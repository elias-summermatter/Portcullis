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
from flask import (Flask, Response, abort, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from audit import AuditLog
from gateway import Gateway

GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
GITHUB_API = "https://api.github.com"

SESSION_MAX_AGE_SECONDS = 24 * 3600


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

    if config.get("trust_proxy", False):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

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
    def _session_max_age():
        # Absolute 24h cap from login time, regardless of activity. A stolen
        # session cookie expires with the original login, not when the thief
        # stops using it.
        u = session.get("user")
        if not u:
            return
        login_at = session.get("login_at")
        if login_at and time.time() - login_at <= SESSION_MAX_AGE_SECONDS:
            return
        audit.record("session_expired", user=u, ip=request.remote_addr)
        session.clear()
        if request.path.startswith("/api/"):
            return jsonify({"error": "session expired"}), 401
        return redirect(url_for("login"))

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), interest-cohort=()",
        )
        resp.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
        # Templates use inline <script> and <style> blocks, so 'unsafe-inline'
        # is required; default-src 'self' still blocks external resource loads
        # and frame-ancestors 'none' blocks clickjacking.
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'",
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
            return render_template("login.html",
                                   error=f"GitHub API error: {e}",
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
            return render_template("login.html",
                                   error=f"GitHub membership check failed: {e}",
                                   github_enabled=True), 502

        if not allowed:
            audit.record("login_failed", user=login_name, ip=request.remote_addr,
                         via="github", reason=denial_reason)
            return render_template("login.html",
                                   error=f"Access denied: {denial_reason}.",
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
        return jsonify({
            "user": u,
            "wg_ip": gateway.user_ip(u),
            "has_config": gateway.user_has_config(u),
            "grants": gateway.status_for_user(u),
            "blocked": list(user_state.get("blocked_services", [])),
            "approved": list(user_state.get("approved_services", [])),
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
            return jsonify({"error": str(e)}), 403
        except Exception as e:
            return jsonify({"error": str(e)}), 400
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
            return jsonify({"error": str(e)}), 400
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
