import logging
import os
import secrets
import sys
import time
from datetime import timedelta
from functools import wraps
from urllib.parse import urlencode

import bcrypt
import requests
import yaml
from flask import (Flask, Response, abort, g, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from audit import AuditLog
from gateway import Gateway
from webhooks import FORWARD_HEADERS, WebhookRegistry, verify_github_signature

GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
GITHUB_API = "https://api.github.com"

SESSION_MAX_AGE_SECONDS = 24 * 3600
MAX_WEBHOOK_BODY = 1 * 1024 * 1024  # 1 MiB cap on incoming webhook bodies

# Disallow every crawler we can name, then a catch-all wildcard. Some bots
# only honour their own explicit name in robots.txt so the named entries
# matter; the final "User-agent: *" covers everything else.
ROBOTS_TXT = """\
User-agent: GPTBot
Disallow: /
User-agent: ChatGPT-User
Disallow: /
User-agent: OAI-SearchBot
Disallow: /
User-agent: anthropic-ai
Disallow: /
User-agent: ClaudeBot
Disallow: /
User-agent: Claude-Web
Disallow: /
User-agent: Google-Extended
Disallow: /
User-agent: Googlebot
Disallow: /
User-agent: Bingbot
Disallow: /
User-agent: CCBot
Disallow: /
User-agent: PerplexityBot
Disallow: /
User-agent: Bytespider
Disallow: /
User-agent: Amazonbot
Disallow: /
User-agent: Applebot
Disallow: /
User-agent: Applebot-Extended
Disallow: /
User-agent: FacebookBot
Disallow: /
User-agent: Meta-ExternalAgent
Disallow: /
User-agent: cohere-ai
Disallow: /
User-agent: DuckAssistBot
Disallow: /
User-agent: YandexBot
Disallow: /
User-agent: Omgili
Disallow: /
User-agent: Omgilibot
Disallow: /
User-agent: ImagesiftBot
Disallow: /
User-agent: Diffbot
Disallow: /
User-agent: Timpibot
Disallow: /
User-agent: PanguBot
Disallow: /

User-agent: *
Disallow: /
"""


def _safe_next(target: str | None) -> str | None:
    """Return target if it's a local path, else None. Blocks open redirects
    to attacker-controlled hosts via `?next=https://evil.com/...`."""
    if not target:
        return None
    # Reject anything with a scheme/host, and protocol-relative paths like
    # "//evil.com/x" and "/\\evil.com/x" which browsers treat as absolute.
    if not target.startswith("/"):
        return None
    if target.startswith("//") or target.startswith("/\\"):
        return None
    from urllib.parse import urlparse
    p = urlparse(target)
    if p.scheme or p.netloc:
        return None
    return target


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def create_app(config: dict) -> Flask:
    app = Flask(__name__)
    app.secret_key = config["secret_key"]
    # Lax (not Strict) so the session cookie survives OAuth return redirects.
    # Lax still blocks cross-site POSTs, which is what CSRF actually needs.
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SECURE"] = config.get("session_cookie_secure", False)
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=SESSION_MAX_AGE_SECONDS)
    # __Host- prefix binds the cookie to our exact hostname: no Domain
    # attribute, Secure required, Path=/. Blocks a sibling/parent-domain
    # cookie named "session" from shadowing ours. Only safe to turn on
    # when Secure is set — the prefix rules are browser-enforced, so in
    # dev mode (session_cookie_secure=false) we fall back to the default
    # name or the browser would reject the cookie entirely.
    if app.config["SESSION_COOKIE_SECURE"]:
        app.config["SESSION_COOKIE_NAME"] = "__Host-session"

    if config.get("trust_proxy", False):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Timezone the UI renders human-visible timestamps in. Audit log and
    # persisted times stay in UTC; this only affects display. Controlled by
    # the container's TZ env var (see docker-compose.yml / Dockerfile), so
    # operators can set their own by overriding that one variable.
    display_tz = os.environ.get("TZ") or "UTC"

    @app.context_processor
    def _inject_display_tz():
        return {"display_tz": display_tz}

    # Per-IP rate limiting. Storage is in-process memory, which is fine given
    # gunicorn runs with a single worker (mandated by the stateful gateway).
    limiter = Limiter(
        key_func=get_remote_address,
        storage_uri="memory://",
        default_limits=[],
    )
    limiter.init_app(app)

    users = config.get("users") or {}
    admins = set(config.get("admins") or [])
    github_cfg = (config.get("oauth") or {}).get("github")
    reverify_interval = int((github_cfg or {}).get("reverify_interval", 300))
    audit = AuditLog(config.get("audit_log_path"))
    rotation = config.get("audit_rotation", "weekly")
    if rotation in ("weekly", "daily"):
        audit.start_rotation(weekly=(rotation == "weekly"))

    gateway = Gateway(config, audit=audit)
    gateway.start()
    app.config["gateway"] = gateway
    app.config["audit"] = audit

    from pathlib import Path as _Path
    webhook_registry = WebhookRegistry(
        config.get("webhooks") or [],
        state_path=_Path(config.get("state_dir", "state")) / "webhooks_state.json",
    )
    app.config["webhooks"] = webhook_registry

    def login_required(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if not session.get("user"):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "unauthorized"}), 401
                return redirect(url_for("login", next=request.path))
            return f(*a, **kw)
        return wrapper

    def is_admin_session() -> bool:
        u = session.get("user")
        return bool(u) and (u in admins or session.get("oauth_admin", False))

    def _verify_github_access(access_token: str, username: str) -> tuple[bool, bool, str]:
        """Re-query GitHub to verify the user still has access.

        Returns (allowed, is_admin_via_team, denial_reason). Raises
        requests.RequestException on transient network failure — caller
        should treat that as "don't revoke yet, try again later"."""
        if github_cfg is None:
            return False, False, "github oauth not configured"
        required_org = github_cfg["required_org"]
        required_team = github_cfg.get("required_team")
        admin_team = github_cfg.get("admin_team")

        gh = requests.Session()
        gh.headers.update({
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

        def _team_active(team_slug: str) -> tuple[bool, int]:
            url = f"{GITHUB_API}/orgs/{required_org}/teams/{team_slug}/memberships/{username}"
            r = gh.get(url, timeout=10)
            if r.status_code == 200 and r.json().get("state") == "active":
                return True, 200
            return False, r.status_code

        if required_team:
            ok, status = _team_active(required_team)
            if not ok:
                if status in (401, 403):
                    return False, False, "github token revoked or scope missing"
                return False, False, f"not an active member of {required_org}/{required_team}"
        else:
            r = gh.get(f"{GITHUB_API}/user/memberships/orgs/{required_org}", timeout=10)
            if not (r.status_code == 200 and r.json().get("state") == "active"):
                if r.status_code in (401, 403):
                    return False, False, "github token revoked or scope missing"
                return False, False, f"not an active member of {required_org}"

        is_admin_via_team = False
        if admin_team:
            is_admin_via_team, _ = _team_active(admin_team)
        return True, is_admin_via_team, ""

    @app.before_request
    def _csrf_origin_check():
        """Reject state-changing requests whose Origin doesn't match our host.

        Closes the cross-subdomain CSRF gap: browsers treat siblings under
        the same registered domain (e.g. `editor-bajoir.wepublish.cloud`
        and `gateway.wepublish.cloud`) as same-site, so `SameSite=Lax`
        still permits session cookies on cross-subdomain POST navigations.
        A compromised sibling could otherwise auto-submit forms to our
        /api/admin/* endpoints with the victim's cookies attached.

        We exempt the webhook passthrough: external senders (GitHub,
        GitLab) never send an Origin header that matches our host, and
        the secret path is the auth mechanism there.

        Relies on `trust_proxy: true` + Caddy setting X-Forwarded-Proto
        correctly, so `request.scheme` reflects the browser's view
        (https) rather than the Caddy→Flask hop (http). Without ProxyFix
        the expected origin would be `http://...` while the browser
        sends `https://...`, and every POST would fail.
        """
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return
        if request.path.startswith("/hook/"):
            return
        if request.path == "/csp-report":
            # Browsers POST CSP violation reports with no Origin/Referer
            # header. Rate-limited + body-capped at the endpoint itself.
            return
        expected = f"{request.scheme}://{request.host}"
        origin = request.headers.get("Origin")
        if origin == expected:
            return
        # Fallback: some very old browsers omit Origin on same-origin
        # POSTs. Referrer-Policy: same-origin keeps the Referer on
        # same-origin requests, so this check is viable.
        referer = request.headers.get("Referer")
        if referer and referer.startswith(expected + "/"):
            return
        audit.record("csrf_blocked", ip=request.remote_addr,
                     path=request.path, origin=origin or None)
        abort(403)

    @app.before_request
    def _session_max_age():
        # Absolute 24h cap from login time, regardless of activity. A stolen
        # session cookie expires with the original login, not when the thief
        # stops using it. Also kills sessions whose user was revoked/deleted
        # after they logged in — closes the "delete user, they re-register
        # with the stolen cookie" gap.
        u = session.get("user")
        if not u:
            return
        login_at = session.get("login_at")
        if not login_at:
            audit.record("session_expired", user=u, ip=request.remote_addr)
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "session expired"}), 401
            return redirect(url_for("login"))
        if time.time() - login_at > SESSION_MAX_AGE_SECONDS:
            audit.record("session_expired", user=u, ip=request.remote_addr)
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "session expired"}), 401
            return redirect(url_for("login"))
        if gateway.is_session_stale(u, login_at):
            audit.record("session_invalidated", user=u, ip=request.remote_addr)
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "session invalidated"}), 401
            return redirect(url_for("login"))

    @app.before_request
    def _csp_nonce():
        # Per-request cryptographic nonce; embedded in the CSP header and
        # on every <script>/<style> tag via the `csp_nonce` Jinja variable.
        # Lets us drop 'unsafe-inline' from script-src entirely — an XSS
        # injection without access to this nonce cannot execute scripts.
        g.csp_nonce = secrets.token_urlsafe(18)

    @app.context_processor
    def _inject_csp_nonce():
        return {"csp_nonce": getattr(g, "csp_nonce", "")}

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        # same-origin keeps the Origin header on same-origin POSTs (CSRF
        # check depends on it) and sends nothing cross-origin — external
        # sites never see our hostname. "no-referrer" would be stricter
        # but also breaks the CSRF check: browsers serialize Origin as
        # "null" under it, even for same-origin requests.
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        # Permissions-Policy — deny every powerful feature by default.
        # Expanded list of interfaces a compromised page could otherwise
        # request from users (sensors, hardware, payments, autoplay, etc.).
        resp.headers.setdefault(
            "Permissions-Policy",
            "accelerometer=(), ambient-light-sensor=(), autoplay=(), "
            "battery=(), bluetooth=(), camera=(), "
            "display-capture=(), document-domain=(), "
            "encrypted-media=(), execution-while-not-rendered=(), "
            "execution-while-out-of-viewport=(), fullscreen=(), "
            "geolocation=(), gyroscope=(), hid=(), "
            "identity-credentials-get=(), idle-detection=(), "
            "keyboard-map=(), magnetometer=(), microphone=(), midi=(), "
            "navigation-override=(), otp-credentials=(), payment=(), "
            "picture-in-picture=(), publickey-credentials-create=(), "
            "publickey-credentials-get=(), screen-wake-lock=(), "
            "serial=(), speaker-selection=(), storage-access=(), "
            "sync-xhr=(), usb=(), web-share=(), "
            "window-management=(), xr-spatial-tracking=(), "
            "interest-cohort=()",
        )
        # HSTS with preload + 2-year max-age. `preload` signals that you
        # want to be added to the browsers' baked-in HSTS list (submit
        # via hstspreload.org once your entire `wepublish.cloud` subtree
        # is HTTPS-only — this commits you to that).
        resp.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload",
        )
        # Belt + suspenders against search engines and AI crawlers. Meta
        # tags in templates cover the HTML path; this header covers every
        # response including JSON/SVG/robots.txt itself.
        resp.headers.setdefault(
            "X-Robots-Tag",
            "noindex, nofollow, noarchive, nosnippet, noimageindex",
        )
        # Cross-origin isolation suite — COOP blocks any cross-origin
        # window from holding a `window.opener` reference to our page,
        # defeating all tabnabbing and popup-based cross-origin attacks.
        # CORP blocks other origins from loading our resources via <img>,
        # <script>, <link> etc. COEP requires every subresource to
        # explicitly opt in to cross-origin usage — protects against
        # Spectre-style side-channel leaks of our data into other origins.
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        resp.headers.setdefault("Cross-Origin-Embedder-Policy", "require-corp")
        # Block Adobe Flash / Acrobat crossdomain.xml lookups and similar
        # legacy cross-domain mechanisms that bypass SOP.
        resp.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        # Stop the browser from pre-resolving DNS for arbitrary hrefs on
        # our pages — tiny side-channel / privacy win.
        resp.headers.setdefault("X-DNS-Prefetch-Control", "off")
        # No caching of authenticated content anywhere — not browser cache,
        # bfcache, CDN, corporate proxy, or forensic disk image. Some routes
        # (wg-config download) already set this explicitly; applying as a
        # default here covers every HTML/JSON response.
        resp.headers.setdefault("Cache-Control", "no-store")
        # Suppress default Server/Werkzeug fingerprinting where we can.
        resp.headers.pop("Server", None)
        # Strict CSP: nonce-based scripts + nonce-based styles with no
        # `'unsafe-inline'` anywhere. Every <script> and <style> tag in
        # the templates carries nonce="{{ csp_nonce }}". Every visual
        # style is either in a <style> block or in a CSS class — there
        # are no inline style="" attributes left (we refactored them
        # into utility classes). An XSS injection without the nonce
        # cannot execute script AND cannot inject CSS rules that would
        # otherwise be useful for exfiltration (CSS-based attribute
        # stealing, data-URL tricks, etc.).
        nonce = getattr(g, "csp_nonce", "")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' 'strict-dynamic'; "
            f"style-src 'self' 'nonce-{nonce}'; "
            "img-src 'self'; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'none'; "
            "object-src 'none'; "
            "manifest-src 'self'; "
            "worker-src 'none'; "
            "media-src 'none'; "
            "upgrade-insecure-requests; "
            # Any violation (real attack or accidental bad HTML) is POSTed
            # to /csp-report and lands in the audit log. Lets us see
            # attempts that the policy silently blocked, and catch any
            # drift before it breaks something for real users.
            "report-uri /csp-report",
        )
        return resp

    @app.before_request
    def _oauth_reverify():
        # Only applies to OAuth sessions (password sessions have no token).
        if "oauth_token" not in session:
            return
        # Always let the user reach logout and static assets.
        if request.endpoint in ("logout", "static", "login"):
            return
        last = session.get("oauth_verified_at", 0)
        if time.time() - last < reverify_interval:
            return
        try:
            allowed, oauth_admin, reason = _verify_github_access(
                session["oauth_token"], session["user"])
        except requests.RequestException:
            # Transient network/API error — don't punish the user; try again
            # on the next request that crosses the TTL.
            return
        if not allowed:
            user = session.get("user")
            audit.record("session_revoked", user=user, ip=request.remote_addr,
                         via="github", reason=reason)
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "session revoked"}), 401
            return redirect(url_for("login"))
        session["oauth_admin"] = oauth_admin
        session["oauth_verified_at"] = time.time()

    def admin_required(f):
        @wraps(f)
        def wrapper(*a, **kw):
            u = session.get("user")
            if not u:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "unauthorized"}), 401
                return redirect(url_for("login", next=request.path))
            if not is_admin_session():
                return jsonify({"error": "admin required"}), 403
            return f(*a, **kw)
        return wrapper

    @app.route("/robots.txt")
    def robots_txt():
        return Response(ROBOTS_TXT, mimetype="text/plain")

    @app.route("/csp-report", methods=["POST"])
    @limiter.limit("60 per minute")
    def csp_report():
        """Collect CSP violation reports from browsers.

        Browsers POST a small JSON body describing what was blocked
        (blocked-uri, violated-directive, document-uri, etc.). We log
        each event to the audit log so admins can review: either a
        real attack attempt was blocked, or a legitimate page needs
        fixing because the CSP is too tight. Small body cap + its own
        rate limit — browsers sometimes flood reports.
        """
        body = request.get_data(cache=False)
        if len(body) > 8 * 1024:
            abort(413)
        try:
            payload = request.get_json(silent=True) or {}
        except Exception:
            payload = {}
        report = payload.get("csp-report", payload) if isinstance(payload, dict) else {}
        audit.record(
            "csp_violation",
            ip=request.remote_addr,
            directive=(report.get("violated-directive") or report.get("effective-directive")),
            blocked=report.get("blocked-uri"),
            document=report.get("document-uri"),
            source=report.get("source-file"),
            line=report.get("line-number"),
        )
        return ("", 204)

    @app.route("/hook/<path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    @limiter.limit("120 per minute")
    def webhook_passthrough(path: str):
        """Forward a webhook delivery to an internal target.

        Behaviour:
        - Every rejection returns 404 — unknown path, wrong method,
          bad HMAC, oversized body. All indistinguishable from outside
          so the set of valid paths cannot be enumerated.
        - If the webhook has an HMAC secret configured AND the request
          carries a body (POST/PUT/PATCH), X-Hub-Signature-256 is
          verified before forwarding. Body-less methods (GET, DELETE)
          skip HMAC because there's no payload to sign.
        - Body cap: 1 MiB.
        - Upstream timeout: per-webhook (default 15 s). Unreachable
          upstream → 502 so the sender retries per its standard policy.
          (502 does reveal the path exists, but only at the moment the
          upstream is legitimately down — attacker still needs the
          secret path to reach this state.)
        - Response body + status is proxied back to the caller by default
          (GitHub shows it in the deliveries UI); webhook.return_response
          = false replaces it with a minimal 200.
        - Query-string parameters are forwarded verbatim to the target,
          so GET-style webhooks (ping/trigger URLs) work too.
        """
        # Stealth: every rejection that *could* leak "this path exists"
        # collapses to 404 — identical to the "no such path" response.
        # An attacker cannot distinguish unknown path, wrong method, bad
        # HMAC, or oversized body from outside. Real failures are still
        # recorded in the audit log for admins.
        wh = webhook_registry.find(path)
        if wh is None:
            abort(404)
        src = request.remote_addr
        method = request.method.upper()
        if method not in wh.methods:
            audit.record("webhook_failed", ip=src, webhook=wh.name,
                         reason=f"method {method} not allowed")
            abort(404)
        if not wh.enabled:
            # Admin toggled this webhook off. Acknowledge with 200 so the
            # sender doesn't retry forever; record the attempt so admins
            # notice incoming deliveries to a disabled webhook.
            audit.record("webhook_suppressed", ip=src, webhook=wh.name,
                         method=method)
            return ("", 200)
        body = request.get_data(cache=False)
        if len(body) > MAX_WEBHOOK_BODY:
            webhook_registry.record_failure(wh, "body too large")
            audit.record("webhook_failed", ip=src, webhook=wh.name,
                         reason="body too large")
            abort(404)
        # HMAC protects the body. For body-less methods the signature
        # header wouldn't be meaningful anyway, so skip the check.
        if wh.github_hmac_secret and method in ("POST", "PUT", "PATCH"):
            sig = request.headers.get("X-Hub-Signature-256")
            if not verify_github_signature(sig, body, wh.github_hmac_secret):
                webhook_registry.record_failure(wh, "signature mismatch")
                audit.record("webhook_failed", ip=src, webhook=wh.name,
                             reason="signature mismatch")
                abort(404)
        # request.headers.get() is case-insensitive (Werkzeug), so walk the
        # whitelist and pull values by canonical name — this handles GitHub
        # sending "X-Github-Event" vs our set entry "X-GitHub-Event".
        headers = {}
        for canonical in FORWARD_HEADERS:
            v = request.headers.get(canonical)
            if v is not None:
                headers[canonical] = v
        try:
            upstream = requests.request(
                method=method,
                url=wh.target,
                params=request.args,
                data=body if body else None,
                headers=headers,
                timeout=wh.timeout,
                allow_redirects=False,
            )
        except requests.RequestException as e:
            reason = f"upstream {type(e).__name__}"
            webhook_registry.record_failure(wh, reason)
            audit.record("webhook_failed", ip=src, webhook=wh.name,
                         reason=reason)
            return jsonify({"error": "upstream unreachable"}), 502
        webhook_registry.record_success(wh, upstream.status_code)
        audit.record("webhook_forwarded", ip=src, webhook=wh.name,
                     method=method, status=upstream.status_code,
                     bytes_in=len(body))
        if not wh.return_response:
            return ("", 200)
        content_type = upstream.headers.get("Content-Type", "application/octet-stream")
        return Response(upstream.content, status=upstream.status_code,
                        content_type=content_type)

    @app.route("/api/webhooks")
    @admin_required
    def api_webhooks():
        out = []
        for wh in webhook_registry.all():
            s = wh.stats
            out.append({
                "name": wh.name,
                "path": wh.path,  # full secret — admins only (same as config.yaml)
                "target": wh.target,
                "methods": list(wh.methods),
                "has_hmac": bool(wh.github_hmac_secret),
                "return_response": wh.return_response,
                "enabled": wh.enabled,
                "total": s.total,
                "successes": s.successes,
                "failures": s.failures,
                "last_forwarded_at": s.last_forwarded_at,
                "last_upstream_status": s.last_upstream_status,
                "last_error": s.last_error,
            })
        return jsonify({"webhooks": out})

    @app.route("/api/admin/webhook/<name>/enable", methods=["POST"])
    @admin_required
    def api_webhook_enable(name: str):
        if not webhook_registry.set_enabled(name, True):
            return jsonify({"error": "unknown webhook"}), 404
        audit.record("webhook_enabled", user=session["user"],
                     ip=request.remote_addr, webhook=name)
        return jsonify({"ok": True})

    @app.route("/api/admin/webhook/<name>/disable", methods=["POST"])
    @admin_required
    def api_webhook_disable(name: str):
        if not webhook_registry.set_enabled(name, False):
            return jsonify({"error": "unknown webhook"}), 404
        audit.record("webhook_disabled", user=session["user"],
                     ip=request.remote_addr, webhook=name)
        return jsonify({"ok": True})

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10 per minute; 50 per hour", methods=["POST"])
    def login():
        error = None
        if request.method == "POST":
            if not users:
                # No password users configured — refuse to even process the form.
                return render_template("login.html", error="Password login is disabled.",
                                       github_enabled=github_cfg is not None,
                                       password_enabled=False), 403
            u = request.form.get("username", "")
            p = request.form.get("password", "")
            user = users.get(u)
            if user and bcrypt.checkpw(p.encode(), user["password_hash"].encode()):
                session.permanent = True
                session["user"] = u
                session["login_at"] = time.time()
                session.pop("oauth_admin", None)
                audit.record("login", user=u, ip=request.remote_addr, via="password")
                return redirect(_safe_next(request.args.get("next")) or url_for("dashboard"))
            audit.record("login_failed", user=u or None, ip=request.remote_addr,
                         via="password")
            error = "Invalid username or password"
        return render_template("login.html", error=error,
                               github_enabled=github_cfg is not None,
                               password_enabled=bool(users))

    @app.route("/oauth/github/login")
    @limiter.limit("30 per minute")
    def oauth_github_login():
        if github_cfg is None:
            abort(404)
        state = secrets.token_urlsafe(32)
        session["oauth_state"] = state
        if (nxt := _safe_next(request.args.get("next"))):
            session["oauth_next"] = nxt
        params = {
            "client_id": github_cfg["client_id"],
            "redirect_uri": url_for("oauth_github_callback", _external=True),
            "scope": "read:org",
            "state": state,
            "allow_signup": "false",
        }
        return redirect(f"{GITHUB_AUTHORIZE}?{urlencode(params)}")

    @app.route("/oauth/github/callback")
    @limiter.limit("30 per minute")
    def oauth_github_callback():
        if github_cfg is None:
            abort(404)
        expected_state = session.pop("oauth_state", None)
        next_url = session.pop("oauth_next", None)
        if not expected_state or request.args.get("state") != expected_state:
            return render_template("login.html",
                                   error="OAuth state mismatch — please try again.",
                                   github_enabled=True), 400
        code = request.args.get("code")
        if not code:
            return render_template("login.html",
                                   error="OAuth callback missing `code`.",
                                   github_enabled=True), 400

        try:
            tok = requests.post(
                GITHUB_TOKEN,
                data={
                    "client_id": github_cfg["client_id"],
                    "client_secret": github_cfg["client_secret"],
                    "code": code,
                    "redirect_uri": url_for("oauth_github_callback", _external=True),
                },
                headers={"Accept": "application/json"},
                timeout=10,
            )
            access_token = tok.json().get("access_token")
        except requests.RequestException as e:
            app.logger.warning("github token exchange failed: %s", e)
            return render_template("login.html",
                                   error="GitHub token exchange failed.",
                                   github_enabled=True), 502
        if not access_token:
            return render_template("login.html",
                                   error="GitHub denied the token exchange.",
                                   github_enabled=True), 400

        try:
            user_resp = requests.get(
                f"{GITHUB_API}/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=10,
            )
        except requests.RequestException as e:
            app.logger.warning("github /user fetch failed: %s", e)
            return render_template("login.html",
                                   error="GitHub is currently unreachable. Please try again.",
                                   github_enabled=True), 502
        if user_resp.status_code != 200:
            return render_template("login.html",
                                   error="Could not read your GitHub profile.",
                                   github_enabled=True), 502
        login_name = user_resp.json().get("login")
        if not login_name:
            return render_template("login.html",
                                   error="GitHub did not return a username.",
                                   github_enabled=True), 502

        try:
            allowed, oauth_admin, denial_reason = _verify_github_access(
                access_token, login_name)
        except requests.RequestException as e:
            app.logger.warning("github membership check failed for %s: %s",
                               login_name, e)
            return render_template("login.html",
                                   error="GitHub is currently unreachable. Please try again.",
                                   github_enabled=True), 502

        if not allowed:
            # denial_reason names the required org/team — keep it in the
            # audit log for admin visibility, but never surface it to an
            # unauthenticated visitor who just failed the membership check.
            audit.record("login_failed", user=login_name, ip=request.remote_addr,
                         via="github", reason=denial_reason)
            app.logger.info("github access denied for %s: %s",
                            login_name, denial_reason)
            return render_template("login.html",
                                   error="Access denied. Contact your administrator if you think this is a mistake.",
                                   github_enabled=True), 403

        session.permanent = True
        session["user"] = login_name
        session["login_at"] = time.time()
        session["oauth_admin"] = oauth_admin
        session["oauth_token"] = access_token
        session["oauth_verified_at"] = time.time()
        audit.record("login", user=login_name, ip=request.remote_addr,
                     via="github", admin_via_team=oauth_admin or None)
        return redirect(_safe_next(next_url) or url_for("dashboard"))

    @app.route("/logout", methods=["POST"])
    def logout():
        user = session.pop("user", None)
        session.pop("oauth_admin", None)
        session.pop("oauth_token", None)
        session.pop("oauth_verified_at", None)
        if user:
            audit.record("logout", user=user, ip=request.remote_addr)
        return redirect(url_for("login"))

    @app.route("/help")
    @login_required
    def help_page():
        return render_template("help.html")

    @app.route("/")
    @login_required
    def dashboard():
        u = session["user"]
        return render_template(
            "dashboard.html",
            user=u,
            wg_ip=gateway.user_ip(u),
            has_config=gateway.user_has_config(u),
            services=list(gateway.services.values()),
            endpoint=gateway.endpoint,
            is_admin=is_admin_session(),
        )

    @app.route("/api/status")
    @login_required
    def api_status():
        u = session["user"]
        user_state = gateway.users.get(u, {})
        user_grants = gateway.status_for_user(u)
        # Only reveal the mesh member list to users who are themselves in
        # the mesh — prevents non-members from enumerating peers.
        user_in_mesh = any(
            gateway.services.get(name) and gateway.services[name].kind == "mesh"
            for name in user_grants
        )
        mesh_peers = gateway.list_mesh_peers() if user_in_mesh else []
        return jsonify({
            "user": u,
            "wg_ip": gateway.user_ip(u),
            "has_config": gateway.user_has_config(u),
            "grants": user_grants,
            "blocked": list(user_state.get("blocked_services", [])),
            "approved": list(user_state.get("approved_services", [])),
            "service_health": gateway.service_health_snapshot(),
            "mesh_peers": mesh_peers,
        })

    @app.route("/wg-config", methods=["POST"])
    @login_required
    def wg_config():
        u = session["user"]
        cfg_text, wg_ip = gateway.register_user(u)
        audit.record("wg_config_generated", user=u, ip=request.remote_addr,
                     wg_ip=wg_ip)
        filename = f"{gateway.config_name}.conf"
        return Response(
            cfg_text,
            mimetype="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store",
            },
        )

    @app.route("/api/activate/<name>", methods=["POST"])
    @login_required
    def api_activate(name: str):
        u = session["user"]
        src = request.remote_addr
        if name not in gateway.services:
            return jsonify({"error": "unknown service"}), 404
        if not gateway.user_has_config(u):
            return jsonify({"error": "generate a WireGuard config first"}), 400
        try:
            exp = gateway.activate(u, name, source_ip=src)
        except PermissionError as e:
            # Safe to echo: these messages describe the user's own state
            # (blocked / requires approval) that they can already see on
            # their dashboard.
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            # Don't echo unexpected exception strings — subprocess errors,
            # iptables failures, etc. can leak internal paths or commands.
            app.logger.warning("activate failed user=%s svc=%s: %s", u, name, e)
            return jsonify({"error": "could not activate this service"}), 500
        audit.record("activate", user=u, ip=src, service=name,
                     expires_at=exp, wg_ip=gateway.user_ip(u))
        return jsonify({"service": name, "expires_at": exp})

    @app.route("/api/extend/<name>", methods=["POST"])
    @login_required
    def api_extend(name: str):
        u = session["user"]
        src = request.remote_addr
        if name not in gateway.services:
            return jsonify({"error": "unknown service"}), 404
        if not gateway.user_has_config(u):
            return jsonify({"error": "generate a WireGuard config first"}), 400
        try:
            exp = gateway.extend(u, name, source_ip=src)
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            app.logger.warning("extend failed user=%s svc=%s: %s", u, name, e)
            return jsonify({"error": "could not extend this service"}), 500
        audit.record("extend", user=u, ip=src, service=name,
                     expires_at=exp, wg_ip=gateway.user_ip(u))
        return jsonify({"service": name, "expires_at": exp})

    @app.route("/api/deactivate/<name>", methods=["POST"])
    @login_required
    def api_deactivate(name: str):
        u = session["user"]
        if name not in gateway.services:
            return jsonify({"error": "unknown service"}), 404
        gateway.deactivate(u, name)
        audit.record("deactivate", user=u, ip=request.remote_addr,
                     service=name, wg_ip=gateway.user_ip(u))
        return jsonify({"service": name})

    @app.route("/api/users")
    @admin_required
    def api_users():
        return jsonify({"users": gateway.list_users()})

    @app.route("/api/revoke/<username>", methods=["POST"])
    @admin_required
    def api_revoke(username: str):
        actor = session["user"]
        if username == actor:
            return jsonify({"error": "cannot revoke your own config; re-download to rotate instead"}), 400
        ok = gateway.revoke_user(username)
        if not ok:
            return jsonify({"error": "user has no active config"}), 404
        audit.record("user_revoked", user=actor, ip=request.remote_addr,
                     target_user=username)
        return jsonify({"ok": True, "revoked": username})

    @app.route("/api/admin/delete/<username>", methods=["POST"])
    @admin_required
    def api_admin_delete(username: str):
        actor = session["user"]
        if username == actor:
            return jsonify({"error": "cannot delete yourself"}), 400
        ok = gateway.delete_user(username)
        if not ok:
            return jsonify({"error": "unknown user"}), 404
        audit.record("user_deleted", user=actor, ip=request.remote_addr,
                     target_user=username)
        return jsonify({"ok": True, "deleted": username})

    @app.route("/api/admin/deactivate/<username>/<name>", methods=["POST"])
    @admin_required
    def api_admin_deactivate(username: str, name: str):
        actor = session["user"]
        if name not in gateway.services:
            return jsonify({"error": "unknown service"}), 404
        if not gateway.user_has_config(username):
            return jsonify({"error": "unknown user"}), 404
        gateway.deactivate(username, name)
        audit.record("admin_deactivate", user=actor, ip=request.remote_addr,
                     target_user=username, service=name)
        return jsonify({"ok": True})

    @app.route("/api/admin/block/<username>/<name>", methods=["POST"])
    @admin_required
    def api_admin_block(username: str, name: str):
        actor = session["user"]
        if name not in gateway.services:
            return jsonify({"error": "unknown service"}), 404
        ok = gateway.block_service(username, name)
        if not ok:
            return jsonify({"error": "unknown user"}), 404
        audit.record("service_blocked", user=actor, ip=request.remote_addr,
                     target_user=username, service=name)
        return jsonify({"ok": True})

    @app.route("/api/admin/unblock/<username>/<name>", methods=["POST"])
    @admin_required
    def api_admin_unblock(username: str, name: str):
        actor = session["user"]
        ok = gateway.unblock_service(username, name)
        if not ok:
            return jsonify({"error": "unknown user"}), 404
        audit.record("service_unblocked", user=actor, ip=request.remote_addr,
                     target_user=username, service=name)
        return jsonify({"ok": True})

    @app.route("/api/admin/approve/<username>/<name>", methods=["POST"])
    @admin_required
    def api_admin_approve(username: str, name: str):
        actor = session["user"]
        if name not in gateway.services:
            return jsonify({"error": "unknown service"}), 404
        ok = gateway.approve_service(username, name)
        if not ok:
            return jsonify({"error": "unknown user"}), 404
        audit.record("service_approved", user=actor, ip=request.remote_addr,
                     target_user=username, service=name)
        return jsonify({"ok": True})

    @app.route("/api/admin/revoke-approval/<username>/<name>", methods=["POST"])
    @admin_required
    def api_admin_revoke_approval(username: str, name: str):
        actor = session["user"]
        ok = gateway.revoke_approval(username, name)
        if not ok:
            return jsonify({"error": "unknown user"}), 404
        audit.record("service_approval_revoked", user=actor, ip=request.remote_addr,
                     target_user=username, service=name)
        return jsonify({"ok": True})

    @app.route("/api/admin/lock/<username>", methods=["POST"])
    @admin_required
    def api_admin_lock(username: str):
        actor = session["user"]
        if username == actor:
            return jsonify({"error": "cannot lock yourself out"}), 400
        ok = gateway.lock_user(username)
        if not ok:
            return jsonify({"error": "unknown user"}), 404
        audit.record("user_locked", user=actor, ip=request.remote_addr,
                     target_user=username)
        return jsonify({"ok": True})

    @app.route("/api/admin/unlock/<username>", methods=["POST"])
    @admin_required
    def api_admin_unlock(username: str):
        actor = session["user"]
        ok = gateway.unlock_user(username)
        if not ok:
            return jsonify({"error": "unknown user"}), 404
        audit.record("user_unlocked", user=actor, ip=request.remote_addr,
                     target_user=username)
        return jsonify({"ok": True})

    @app.route("/api/audit")
    @admin_required
    def api_audit():
        try:
            offset = max(0, int(request.args.get("offset", 0)))
            limit = min(max(1, int(request.args.get("limit", 50))), 500)
        except ValueError:
            return jsonify({"error": "bad offset/limit"}), 400
        return jsonify(audit.query(
            offset=offset,
            limit=limit,
            category=request.args.get("category") or None,
            user=request.args.get("user") or None,
            service=request.args.get("service") or None,
            ip=request.args.get("ip") or None,
        ))

    return app


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config_path = os.environ.get("CONFIG", "config.yaml")
    if not os.path.exists(config_path):
        print(f"Config not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    config = load_config(config_path)
    app = create_app(config)
    web = config.get("web", {})
    app.run(
        host=web.get("host", "0.0.0.0"),
        port=web.get("port", 8080),
        use_reloader=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
