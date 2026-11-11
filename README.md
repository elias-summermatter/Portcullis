# Portcullis

A small self-hosted WireGuard access gateway with a web UI. Users sign in
(password, GitHub OAuth, or Zitadel OIDC), download a WireGuard config, and activate
per-service access for short sessions. Only the IPs of services they've
activated are routed through the tunnel; everything else stays on their
normal connection. Services behind the gateway are completely unreachable
from the public internet.

Built with Flask + a thin wrapper around `wg`/`iptables`/`conntrack`.
Runs as a single Docker container. Roughly 1500 lines of Python + HTML.

---

## Why

You have a handful of internal services (Postgres, SSH bastion, OpenShift
console, Grafana, ...) that you'd rather not expose directly to the
internet. You still want engineers to reach them from their laptops with
normal clients — `psql`, `ssh`, a browser — with certificates that
validate cleanly against the real hostnames.

This tool lets you hand out a WireGuard config, then gate *which*
destinations that config can actually reach from a web dashboard, per
user, per service, with a time limit.

---

## How it works

1. Admin defines services in `config.yaml` — each with a hostname and
   optionally a port.
2. User logs in to the web UI (password, GitHub OAuth, or Zitadel
   OIDC — your choice)
   and downloads a personal WireGuard config. It includes every
   configured service's resolved IP in `AllowedIPs`, plus the gateway's
   own WG network.
3. User imports the config into their WireGuard client. Only traffic to
   those specific IPs is routed through the tunnel; everything else goes
   out their normal connection.
4. Before actually reaching a service, the user clicks **Activate** on
   the dashboard. The gateway installs a per-(user, service) iptables
   ACCEPT rule with a 1-hour expiry. The user can extend up to 8 hours
   of remaining time per service, and can keep re-extending forever.
5. When an activation expires (or is deactivated), the gateway removes
   the rule *and* kills in-flight `conntrack` flows, so open SSH / psql
   sessions drop within a second.

The WireGuard handshake uses a per-user preshared key on top of the
X25519 keypair, for post-quantum hedging.

---

## Features

- Per-user WireGuard identity (X25519 + 32-byte preshared key)
- Per-service activation with configurable expiry (default 1h, cap 8h)
- Automatic teardown on expiry; existing flows killed via `conntrack -D`
- Password login + GitHub OAuth (require org and/or team membership,
  optional admin team) + Zitadel OIDC with PKCE (require a project
  role, optional admin role, optional org pinning)
- OAuth membership / roles are re-checked on an interval so removing a
  user from the team or role kicks their session out
- Admin dashboard:
  - See every user's WG IP, active grants with live countdowns, per-user
    approvals, and blocked services
  - Revoke individual grants (kick)
  - Permanently block a service for a user
  - Approve a per-user, off-by-default service (`requires_approval`)
    and revoke that approval again
  - One-click **Lock out** to block every service for a user at once
  - **Revoke** a user's WG config (keys invalidated, grants dropped —
    approvals, blocks, and IP stay, so a re-download reinstates the
    same identity with the same policy)
  - **Delete** a user entirely when they leave (IP released, all admin
    policy erased)
- Audit log in JSON Lines, with filter + pagination in the UI; rotated
  weekly and gzipped, archives kept for compliance
- Config-download confirmation dialog requires acknowledging a "do not
  share" clause before the private key is revealed

---

## Prerequisites

- **A Linux host.** Kernel 5.6 or newer (Ubuntu 22.04+, Debian 12+,
  Fedora 36+, or Arch). WireGuard is built into the kernel — no module
  install needed.
- **Docker** and the `compose` plugin (for the recommended deployment).
- **A public UDP port.** The VM must be reachable on `51820/udp` (or
  whatever you set `wg_listen_port` to) from every user's network.
- **A DNS name** pointing at the VM for production (Caddy uses it to
  fetch a Let's Encrypt certificate). Not required for a local test.
- **Outbound network access** from the gateway to the real services —
  the gateway resolves the configured hostnames via its own DNS and
  connects to them directly.

## Deploying it

One Linux VM (1 CPU, 512 MB RAM is plenty), kernel 5.6+:

```bash
# 1. Install Docker + the compose plugin.
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER && newgrp docker

# 2. Firewall: let in SSH, HTTP/S (for the web UI + TLS), and WireGuard.
sudo ufw allow 22/tcp
sudo ufw allow 80,443/tcp
sudo ufw allow 51820/udp
sudo ufw enable

# 3. Clone this repo onto the VM and create a config file.
git clone <this-repo> portcullis && cd portcullis
cp config.example.yaml config.yaml
#   Fill in at minimum:
#     - secret_key   (python -c 'import secrets; print(secrets.token_hex(32))')
#     - session_cookie_secure: true
#     - trust_proxy: true
#     - wg_endpoint: gateway.yourdomain.tld:51820
#     - users and/or oauth.github and/or oauth.zitadel
#     - services (your real internal hostnames)

# 4. Point a DNS A record at the VM and set the hostname in the Caddyfile.

# 5. Start everything.
docker compose up -d --build
```

Caddy fetches a Let's Encrypt cert automatically on first start and
reverse-proxies the web UI over HTTPS. WireGuard listens on a separate
UDP port and isn't proxied.

**Back up `./state/`.** It holds the server's WireGuard private key and
every user's peer assignment — losing it invalidates every config
you've handed out.

### Using the prebuilt image

Instead of building locally, you can pull the image CI publishes on
every push to `main` and every night:

```yaml
# docker-compose.yml — replace the `build: .` line with:
services:
  gateway:
    image: seccomch/portcullis:latest                        # Docker Hub
    # or: ghcr.io/elias-summermatter/portcullis:latest       # GHCR
    # ...everything else unchanged
```

Both registries receive the same bit-for-bit image on every publish.
GHCR has no anonymous pull-rate limit; Docker Hub caps anonymous pulls
at 100 per 6h per IP (`docker login` once on the VM to lift it).

Available tags:
- `latest` — most recent publish (either a push to `main` or a nightly rebuild)
- `<short-sha>` — pin to a specific commit, e.g. `a1cf099`
- `<YYYYMMDD>` — pin to a specific build date (useful after a nightly CVE rebuild)

Then update with `docker compose pull && docker compose up -d`. No
local build toolchain needed on the VM.

## Running without Docker (dev mode)

For UI tweaks on your own machine you can skip the container:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml
#   Set  enable_netfilter: false  to skip the root-only ip/wg/iptables calls.
python app.py
```

The web UI will run but "Activate" is a no-op (no routing happens) —
useful for front-end work, not for real access.

---

## Configuration

See [config.example.yaml](config.example.yaml) — every field is
documented inline. Highlights:

| Field                         | What it does                                                       |
|-------------------------------|--------------------------------------------------------------------|
| `secret_key`                  | Flask session signing key. Random 256-bit recommended.             |
| `session_cookie_secure`       | Restrict the cookie to HTTPS. Must be `true` in prod.              |
| `trust_proxy`                 | Honor `X-Forwarded-For` from a reverse proxy.                      |
| `audit_log_path`              | Path to the JSON Lines audit log.                                  |
| `audit_rotation`              | `weekly` / `daily` / `off`. Archives are gzipped and kept forever. |
| `wg_endpoint`                 | `host:port` the client's `[Peer]` section will dial.               |
| `wg_network`                  | WG subnet — gateway takes `.1`, peers get the rest.                |
| `wg_config_name`              | Basename of downloaded configs (<=15 chars).                       |
| `enable_netfilter`            | Set `false` locally to skip root-only commands and just run the UI.|
| `users`                       | Map of username -> bcrypt password hash.                           |
| `admins`                      | Usernames with admin privileges.                                   |
| `oauth.github`                | See section below.                                                 |
| `oauth.zitadel`               | See section below.                                                 |
| `services[].hostname`         | Service hostname — resolved at startup + every 5 min.              |
| `services[].port`             | Optional port restriction. Omit for any TCP port.                  |
| `services[].cidrs`            | Optional explicit IP/CIDR list, merged with DNS results.           |
| `services[].requires_approval`| If `true`, users cannot activate the service until an admin approves them for it. Block still overrides. |

### GitHub OAuth setup

1. Register an OAuth App at
   https://github.com/organizations/<your-org>/settings/applications
   (org-owned) or https://github.com/settings/developers (personal).
2. Set the callback URL to
   `https://<your-gateway-hostname>/oauth/github/callback`.
3. Copy the client ID and generate a client secret.
4. Fill in `config.yaml`:

   ```yaml
   oauth:
     github:
       client_id: "Iv1...."
       client_secret: "..."
       required_org: "your-org"
       required_team: "infra"        # optional — org-only if omitted
       admin_team: "infra-admins"    # optional — these users get admin
       reverify_interval: 300        # seconds
   ```

5. If your org enforces *Third-party Application Access Policy*, an org
   owner has to approve the app once. Org-owned OAuth Apps skip this.

The app only requests the `read:org` scope.

### Zitadel (OIDC) setup

Uses the authorization-code flow with PKCE, so the Zitadel app is a
public client — there is no client secret to store on the gateway.

1. In the Zitadel console, open (or create) a **project** and add the
   role keys you want to use, e.g. `gateway-user` and `gateway-admin`.
2. In the project's settings, enable **Check authorization on
   Authentication** (optional but recommended — Zitadel itself then
   refuses users without any role on the project).
3. Add an **application** to the project: type **Web**, authentication
   method **PKCE**. Redirect URI:
   `https://<your-gateway-hostname>/oauth/zitadel/callback`.
   For a plain-http local test, also add
   `http://localhost:8080/oauth/zitadel/callback` and enable
   **Development Mode** on the app. Copy the **Client ID**.
4. Under the project's **Authorizations**, grant `gateway-user` (and
   `gateway-admin` for admins) to the people who need access.
5. Fill in `config.yaml`:

   ```yaml
   oauth:
     zitadel:
       issuer: "https://auth.example.com"   # your Zitadel instance
       client_id: "123456789012345678"
       required_role: "gateway-user"        # mandatory
       admin_role: "gateway-admin"          # optional
       required_org_id: "123456789"         # optional, see below
       display_name: "Zitadel"              # button label
       reverify_interval: 300               # seconds
   ```

Notes:

- **Username** = Zitadel's `preferred_username` (the login name, e.g.
  `jane@example.com`). Only `A-Z a-z 0-9 . _ @ + -` are accepted; other
  names are denied at login. Usernames share one namespace with
  password and GitHub users, so the same name from two sources maps to
  the same WireGuard identity.
- **Re-checks** call Zitadel's userinfo endpoint with the user's access
  token. A deactivated user, a revoked token, or a removed role ends the
  session on the next check; an unreachable Zitadel does not.
- **Session length** is capped by Zitadel's access-token lifetime
  (default 12h, instance setting). After that the user signs in again,
  which is a silent redirect while their Zitadel SSO session lasts.
  Active service grants are unaffected.
- **`required_org_id`** pins roles to one organization (its ID is shown
  in the org's settings). Recommended when the instance hosts several
  orgs: if the project is ever granted to another org, that org's admins
  could otherwise hand out the same role keys. It also asks Zitadel to
  only allow members of that org to log in.
- Requested scopes: `openid profile` plus
  `urn:zitadel:iam:org:project:role:<key>` for `required_role` and
  `admin_role` (+ `urn:zitadel:iam:org:id:<id>` when `required_org_id`
  is set). Asking for the roles by key makes Zitadel return them in
  userinfo regardless of the project's **Assert Roles on
  Authentication** setting, so that setting can stay off. Role keys
  must not contain spaces.

### No password users?

Leave `users: {}` and `admins: []` — the login form will hide the
password fields automatically, leaving just the OAuth button(s).

---

## Shared network (opt-in peer-to-peer)

By default the gateway enforces **strict peer isolation**: two WG clients
cannot reach each other, even though both sit on the same tunnel. Every
peer-to-peer packet is caught by the `SIG_FORWARD` chain's default DROP.

For cases where team members genuinely need to talk to each other — copy
a file to a colleague, share a scratch HTTP server, screen-share an SSH
session — the gateway ships a synthetic service called `shared-network`.
It appears in the dashboard like any other service and uses the exact
same grant mechanics (1h default, extend +1h, 8h cap, auto-expire).

**Flow:**

1. User clicks Activate on `shared-network`. A warning dialog explains
   the trade-off: their machine will be reachable from every other
   currently-active member for the duration of the grant.
2. On accept, the gateway adds their WG IP to the active mesh set and
   rebuilds a dedicated `SIG_MESH` iptables sub-chain with pair-wise
   ACCEPT rules between every active member.
3. While active, the user sees a *Shared network peers* table listing
   every other member with their username, WG IP, and grant countdown.
4. When the grant expires (or is deactivated / revoked / blocked), the
   member drops out, pair-wise rules are rebuilt without them, and
   in-flight connections to their former peers are torn down via
   `conntrack -D`.

**Security model:**

- **Traffic is confidential and integrity-protected** — it stays inside
  the WireGuard tunnel (X25519 + per-user PSK) between the two members.
  The gateway never NATs or re-encrypts; packets go direct inside the
  encrypted transport. Non-members cannot see or reach this traffic.
- **But your machine IS exposed to the other active members.** If you
  run services that listen on `10.77.0.X`, every peer can try them.
  Bind sensitive things to `127.0.0.1` or firewall your WG interface.
- **Admin controls apply** — block, approve (if `requires_approval`),
  lock, revoke, delete. Leaving the mesh via any of these tears down
  the pair-wise rules and kills in-flight flows immediately.
- **Opt-in, time-limited.** A forgotten membership auto-expires. A
  compromised laptop's window of exposure is bounded by the grant.

**Disabling:**

Set `shared_network.enabled: false` in `config.yaml` to remove the
service entirely. Existing grants tear down on next restart. You can
also set `requires_approval: true` to gate it per user via the existing
admin approval flow.

## Webhook passthrough

Some integrations need the public internet to reach internal services —
the canonical example being "a Git host (GitHub, GitLab, etc.) pushes a
webhook to a CI/CD or deploy system so it knows when to sync." You'd
rather not expose that internal system to the internet just for one
POST endpoint.

The gateway can forward HTTP requests (POST by default; GET/PUT/PATCH/
DELETE on request) from `/hook/<secret-path>` to an internal target, so
the Git host (or any other caller) talks to `gateway.example.com` —
the only public hostname you expose — and the gateway relays the
request to `ci.internal.example.com/api/webhook`.

**How it works:**

1. Add a webhook entry to `config.yaml` with a long random `path` and
   the internal `target` URL.
2. Configure the webhook in GitHub/GitLab pointing at
   `https://<your-gateway>/hook/<that-path>`.
3. Incoming POSTs are matched against configured paths in constant time
   (so valid paths can't be enumerated by timing) and forwarded with a
   tight header whitelist (no Authorization / cookies propagate).
4. Optionally, set `github_hmac_secret` on the webhook to have the
   gateway verify GitHub's `X-Hub-Signature-256` before forwarding —
   only useful when the target cannot validate signatures itself.
   **Leave it unset** when the target already validates (most mature
   CI/CD systems do, when you configure a webhook secret in their UI).
   This is slightly *more* secure: a gateway compromise cannot steal
   and forge an HMAC secret that isn't stored there in the first place,
   so forged deliveries would still fail the target's own check.

**Security properties:**

- Body capped at 1 MiB, upstream timeout 15 s.
- Rate limiter sits in front (120 deliveries/min/IP).
- If upstream is unreachable, returns 502 so the sender retries per its
  normal backoff (GitHub does this automatically).
- `return_response: false` on a webhook returns a minimal 200 to the
  caller regardless of what the upstream said — hides target details
  from GitHub's deliveries page if that matters to you. Default is to
  pass the real response through for debuggability.
- **Non-enumerable.** Every rejection (unknown path, wrong method, bad
  HMAC, oversized body) returns an identical 404. An attacker probing
  `/hook/<guess>` cannot distinguish "this path doesn't exist" from
  "this path exists but my request was rejected" — so valid paths
  can't be discovered by response-code differences. Combined with
  constant-time path matching, the 64-hex-char path space is
  effectively impossible to brute-force.
- **Multi-method.** `methods: ["POST"]` by default; configure `["GET"]`,
  `["POST", "PUT"]`, etc. for targets that expect other verbs. GET-style
  ping/trigger webhooks forward query strings verbatim. HMAC verification
  only runs on body-carrying methods (POST/PUT/PATCH).
- **Header whitelist with per-webhook opt-ins.** A safe-by-default set of
  headers (`Content-Type`, `User-Agent`, `X-GitHub-*`, `X-Hub-Signature-*`,
  `X-GitLab-*`) is forwarded to every target. Cookies, session headers,
  and `Authorization` are stripped by default to prevent caller
  credentials leaking into internal services. If a specific target
  needs additional headers (e.g. an internal API that authenticates
  with a Bearer token sent by the caller), list them under the webhook's
  `forward_headers:` entry — only that webhook gets the extension; the
  global default stays tight.
- Every delivery is audited: `webhook_forwarded` on success,
  `webhook_failed` on errors, `webhook_suppressed` when the admin has
  disabled the webhook.

**Admin controls:**

The dashboard's Webhooks panel (admin-only) shows each configured
webhook with:

- Name, target URL, HMAC-verified indicator
- Delivery counters (total / ok / fail)
- Last-forwarded timestamp (in your configured timezone)
- Last upstream status + error message, if any
- **Disable/Enable button** — stops forwarding without editing
  `config.yaml`. Disabled webhooks acknowledge deliveries with 200
  (so senders don't retry forever) but drop the payload.
- **Copy URL button** — copies the full `https://...<path>` to your
  clipboard for pasting into GitHub.

The enable/disable state persists across restarts via
`state/webhooks_state.json`. A restart does NOT silently re-enable
something an admin deliberately turned off.

## Service health chips

Every service row on the dashboard now carries two coloured tags driven
by background probes:

- **Local (every 5 min, always on):** TCP-connect from the gateway to
  the service. Shows *reachable* (green) when the service answers,
  *unreachable* (gray) when the gateway can't open a socket, or *check
  failed* (amber) on a transient local error. A chronically unreachable
  service means the tunnel route will break too — investigate.
- **Public (every 6 h, opt-in):** POST to `portchecker.io` asking
  whether the service's hostname + port answer from the open internet.
  Shows *not public* (green) when it doesn't, *publicly exposed* (red
  bold) when it does — which means the gateway is being bypassed and
  whatever is exposed should be firewalled off immediately. A failed
  probe (API outage, etc.) is shown as *public check failed* (amber),
  distinct from either outcome — an outage never masquerades as green.

Both checks are fully fail-safe: any exception is caught, logged, and
surfaced as an amber "check failed" chip. The app never breaks because
of a probe.

Transitions are written to the audit log as `service_health_fail` /
`service_health_ok`, one event per incident (debounced — flapping
between `unreachable` and `check_error` does not re-log). The event
includes `probe=local|public`, the precise `state`, and a `reason`
string.

Enable the public probe with `service_health.public_check_enabled:
true` in `config.yaml`. The local probe is always on; tune its cadence
with `service_health.local_interval`.

## Day-to-day operations

### Add a password user

```bash
# On the VM (or locally, if you have bcrypt installed in a venv):
docker compose run --rm --no-deps \
  --entrypoint python gateway hash_password.py
# Prompts for a password, prints a bcrypt hash.
```

Paste the hash into `config.yaml`:

```yaml
users:
  alice:
    password_hash: "$2b$12$..."
```

Then `docker compose restart gateway`.

### Grant a user admin rights

Either add their username to the `admins:` list in `config.yaml` (and
restart), or — if you're using GitHub OAuth — add them to the
`admin_team` in GitHub, or — with Zitadel — grant them the
`admin_role` on the project. Teams and roles are re-checked
periodically without a restart.

### Add a new service

Append to `services:` in `config.yaml`:

```yaml
services:
  - name: grafana
    hostname: "grafana.internal.example.com"
    port: 443
```

Restart the gateway: `docker compose restart gateway`.
The hostname is resolved at startup and every 5 minutes thereafter.

**Existing users have to re-download their WG config** so the new
service's IP lands in their `AllowedIPs`. The dashboard shows a
*Rotate & download config* button for this (rotating their key, so
previous configs are invalidated instantly).

### Revoke vs Delete a user

Two distinct admin actions handle different scenarios:

- **Revoke config** — kills the user's WireGuard keys and drops any
  active grants, but **keeps the user record**: their allocated WG IP,
  all approvals, and all blocks survive. When the user later clicks
  *Generate & download config* again, they get the same IP and admin
  policy automatically reapplies. Use for: lost device, key rotation,
  suspected key leak.
- **Delete** — fully forgets the user: IP is released back to the
  pool, approvals and blocks are erased, and the entry disappears from
  the Users table. Use for: the person left the company / should have
  no future access.

Before this split existed, Revoke silently wiped admin policy too, so
a block set weeks ago could quietly disappear during a key rotation.
That's fixed; admin decisions now persist until you explicitly choose
to erase them with Delete.

Both actions are audited (`user_revoked`, `user_deleted`).

### Approve a user for a gated service

Services marked `requires_approval: true` in `config.yaml` are off by
default — users see them on the dashboard as *awaiting admin approval*
and cannot click **Activate**. To let a specific user in:

1. Open the admin dashboard → **Users** table.
2. In the *Approved services* cell for that user, pick the service from
   the *+ approve service…* dropdown.
3. The user can now activate it normally.

To take access away, click the `×` on the mauve approval chip — any
active grant for that service is torn down immediately, and the user
goes back to *awaiting approval*.

Blocks still override approvals: a blocked-and-approved user is
blocked. Use this for services that should never have blanket access
(prod databases, on-call-only admin consoles, etc.).

### Remove a service

Delete the entry from `config.yaml` and restart. Any active grants for
that service are dropped. Users will still have the (now-unused) IP in
their existing `AllowedIPs` — harmless, but they can re-download to
clean it up.

### View logs

```bash
# Application + request logs from the container:
docker compose logs -f gateway

# The audit log on disk — structured JSON per line:
tail -f logs/audit.log

# Read an archived (gzipped) week:
zcat logs/audit-2026-04-13.log.gz | jq .
```

The admin UI has a paginated, filterable view across the live file and
every archive.

### Update the gateway

```bash
cd portcullis
git pull
docker compose up -d --build
```


State (`state/`, `logs/`) survives because both directories are
bind-mounted from the host. WireGuard peers and user assignments are
preserved across upgrades.

### Restart cleanly

```bash
docker compose restart gateway
```

This brings `wg0` down and back up. Active clients reconnect
automatically within a few seconds.

### Back up state

```bash
tar czf portcullis-backup-$(date +%F).tar.gz config.yaml state/
```

`state/` holds the server's WG private key and every user's peer
assignment. Keep it safe.

### Verify it's working

From the VM:

```bash
docker compose exec gateway wg show
# Shows listening port + one entry per peer once they handshake.
```

From a client with the config imported and active:

```bash
sudo wg show
# Look for "latest handshake: N seconds ago" and non-zero transfer.

ping 10.77.0.1
# The gateway's WG IP; should reply as soon as the tunnel is up.
```

The built-in `/help` page (linked from the dashboard) contains a
Troubleshooting section covering handshake failures, DNS issues, and
why a specific service might not be reachable.

---

## User guide

There's a built-in `/help` page linked from every dashboard. It walks
through:

- installing WireGuard on Windows, macOS, Linux (with both GUI and CLI
  paths for Linux),
- importing the `.conf`,
- activating / extending / deactivating services,
- common troubleshooting (no handshake, can't reach service, etc.).

Nothing in that guide is admin-specific — it's aimed at the engineers
who'll actually use the gateway.

---

## Admin guide

Admins see two extra sections on the dashboard:

**Users table** — every account that has downloaded a WG config:

| Column            | Content                                                                       |
|-------------------|-------------------------------------------------------------------------------|
| Username          | The username / GitHub login.                                                  |
| WG IP             | Their assigned private IP on the WG network.                                  |
| Active grants     | Green chip per active service with live countdown + `x` to kick.              |
| Approved services | Mauve chip per approved `requires_approval` service + `x` to revoke approval. Dropdown lets you approve. |
| Blocked services  | Red chip per blocked service + `x` to unblock. Dropdown below lets you block. |
| Registered        | When they first downloaded a config.                                          |
| Actions           | **Lock out** (block all services), **Revoke config** (drop keys, keep policy), **Delete** (forget entirely). |

**Audit log** — chronologically ordered, server-side filterable by
event category, service, user, and IP; paginated; reads both the live
file and every gzipped weekly archive so you can go back arbitrarily
far.

Admin endpoints:

| Route                                    | Purpose                             |
|------------------------------------------|-------------------------------------|
| `POST /api/revoke/<user>`                | Drop peer + invalidate keys. IP + approvals + blocks survive. |
| `POST /api/admin/delete/<user>`          | Fully forget a user: release IP, erase all policy.            |
| `POST /api/admin/deactivate/<u>/<svc>`   | Kick a single active grant         |
| `POST /api/admin/block/<u>/<svc>`        | Permanently block a service        |
| `POST /api/admin/unblock/<u>/<svc>`      | Undo a block                        |
| `POST /api/admin/approve/<u>/<svc>`      | Approve a user for a `requires_approval` service |
| `POST /api/admin/revoke-approval/<u>/<svc>` | Revoke that approval + drop any active grant |
| `POST /api/admin/lock/<u>`               | Block every service in one click    |
| `POST /api/admin/unlock/<u>`             | Clear all blocks                    |
| `GET /api/webhooks`                      | List configured webhooks + stats (full secret paths; admins only). |
| `POST /api/admin/webhook/<name>/enable`  | Resume forwarding deliveries for a webhook. |
| `POST /api/admin/webhook/<name>/disable` | Silently drop deliveries (200 to sender, no forward). Persists across restart. |
| `GET /api/audit?...`                     | Filter + paginate the audit log    |
| `GET /api/users`                         | Admin dashboard data feed           |

All admin POSTs are 403-gated for non-admins; all of them are audited
with the actor, target, IP, and reason.

### Audit log format

JSON Lines at `logs/audit.log`, one event per line:

```json
{"ts":"2026-04-20T09:12:33Z","event":"activate","user":"alice","ip":"203.0.113.7","service":"postgres01","expires_at":1745147553.4,"wg_ip":"10.77.0.3"}
```

Events you'll see: `login`, `login_failed`, `logout`, `session_revoked`,
`session_expired`, `session_invalidated`, `wg_config_generated`, `activate`, `extend`,
`deactivate`, `grant_expired`, `user_revoked`, `admin_deactivate`,
`service_blocked`, `service_unblocked`, `service_approved`,
`service_approval_revoked`, `user_locked`, `user_unlocked`,
`user_deleted`, `service_health_ok`, `service_health_fail`,
`webhook_forwarded`, `webhook_failed`, `webhook_suppressed`,
`webhook_enabled`, `webhook_disabled`.

Rotation: every Monday 00:00 UTC (configurable) the live file is renamed
to `audit-YYYY-MM-DD.log.gz`, gzipped, and a new live file starts.
Archives are kept forever so compliance queries can reach back as far
as needed. Pagination in the dashboard reads across all archives.

---

## Architecture

```
+-------------------+            +------------------------------+
|  User's laptop    |            |   Gateway VM (Linux)         |
|                   |            |                              |
|  WireGuard client |  UDP 51820 |   wg0  <-----> gateway.py    |
|   (AllowedIPs =   | <--------> |                  |           |
|   service IPs)    |            |                  v           |
|                   |            |   iptables SIG_FORWARD chain |
|   Browser         |  HTTPS     |                  |           |
|   (dashboard)     | <--------> |   Flask  <-> gateway.py      |
+-------------------+            |      (app.py)                |
                                 |                  |           |
                                 |   conntrack      v           |
                                 |   <-> audit.py -> logs/      |
                                 |                              |
                                 |   Egress: MASQUERADE ---> internet -> real services
                                 +------------------------------+
```

**Process model:** one Docker container, one Python process. The web UI
and the WG/iptables control code share a common `Gateway` object
protected by a lock. Background threads handle expiry (`reaper`),
periodic re-resolution of service hostnames (`resolver`), audit-log
rotation, and the OAuth re-verify hook runs once per request above the
TTL.

**Why iptables, not a TCP proxy?** Direct routing is the only way to
preserve TLS certificate validation against the real hostnames. A
userspace proxy would break the chain of trust.

---

## Security model & caveats

**Strong:**

- The services behind the gateway are never reachable from the public
  internet. WireGuard's UDP port silently drops unauthenticated packets,
  so port scanners can't distinguish it from a closed port.
- Stealing one credential isn't enough: an attacker needs the login
  (password, GitHub, or Zitadel), an active WG config, and an active per-service
  grant in the last hour. Every piece is revocable from the dashboard.
- Per-user preshared keys hedge the WG handshake against future
  quantum decryption of recorded traffic.
- `conntrack` teardown on expiry means "access expired" actually cuts
  the wire, not just future connections.

**Browser-facing hardening (full high-security stance):**

- **CSP with per-request nonces** on every `<script>` **and every
  `<style>`** tag. `'unsafe-inline'` is forbidden on both; `strict-dynamic`
  is set on script-src so an XSS injection that doesn't possess the
  per-request nonce cannot execute — and also cannot inject CSS that
  would enable CSS-based data exfiltration (selector-based attribute
  stealing, etc.). Every visual style lives either in a nonced `<style>`
  block or in a CSS class; there are zero inline `style=""` attributes
  in any template.
- **Cross-Origin-Opener-Policy: same-origin** — severs `window.opener`
  relationships with every cross-origin window, defeating all tabnabbing
  and popup-based cross-origin attacks.
- **Cross-Origin-Resource-Policy: same-origin** — no other origin can
  load our resources via `<img>`, `<script>`, `<link>`, etc.
- **Cross-Origin-Embedder-Policy: require-corp** — enables cross-origin
  isolation, protecting against Spectre-style side-channel leaks and
  forcing every subresource to explicitly opt into cross-origin use.
- **`__Host-` session cookie prefix** — browser-enforced binding to
  the exact hostname; a parent or sibling subdomain cannot shadow our
  session cookie even if compromised.
- **Origin/Referer check on all state-changing POSTs** — closes the
  cross-subdomain CSRF gap left open by `SameSite=Lax` (which treats
  siblings under the same registered domain as same-site). A
  compromised sibling subdomain (e.g. `editor.example.com`) cannot CSRF us.
- **`X-Frame-Options: DENY` + `frame-ancestors 'none'`** — clickjacking
  closed two ways.
- **HSTS with `preload` + 2-year max-age + `includeSubDomains`**.
- **Expanded Permissions-Policy** denies every powerful browser
  feature (camera, mic, geolocation, USB, HID, Bluetooth, serial,
  payment, WebAuthn-create, etc.) by default.
- **`X-Permitted-Cross-Domain-Policies: none`** blocks legacy Flash /
  Acrobat cross-domain exfiltration. **`X-DNS-Prefetch-Control: off`**
  removes a minor side-channel.
- **`Cache-Control: no-store`** on every response. Authenticated pages
  are never kept in browser / proxy / CDN caches or in `bfcache`.
- **CSP violation reporting** at `/csp-report`. Any blocked script,
  style, or resource load generates a `csp_violation` audit event,
  so drift or attempted attacks show up in the admin panel.

**Supply chain & ops:**

- **Dependabot** (`.github/dependabot.yml`) opens PRs when any
  pip/docker/github-actions dependency has a new version, with
  security updates filed immediately regardless of schedule.
  **Patch + minor bumps auto-merge** once the security scanners pass
  (via `.github/workflows/dependabot-auto-merge.yml`); major bumps
  stay open for manual review because they can introduce breaking
  API changes a scanner won't catch. Requires branch protection with
  required status checks and "Allow auto-merge" enabled in repo
  settings — see the comment block in that workflow file.
- **Nightly image rebuild** (`.github/workflows/build.yml`) runs every
  night at 03:00 UTC and on every push to `main`. Publishes bit-for-bit
  identical images to both `seccomch/portcullis` on Docker Hub and
  `ghcr.io/elias-summermatter/portcullis` on GHCR, tagged `latest` (moves
  on every publish), the short commit SHA, and the build date. Nightly
  runs exist specifically to rebase on fresh DHI base layers — Docker
  Hardened Images get rebuilt upstream whenever a CVE is fixed, and
  nightly re-pull is what actually gets those fixes into your running
  container. SBOM and build provenance attestations are attached to
  every image.
- **Static security analysis in CI** (`.github/workflows/security.yml`)
  runs on every push and weekly:
  - **Bandit** — Python security linter
  - **Semgrep** — OWASP/Flask/Python/Dockerfile rulepacks
  - **CodeQL** — GitHub's dataflow analysis
  - **pip-audit** — cross-check against PyPA advisory DB
  - **Trivy** — Docker image CVE scan
  - **Gitleaks** — commit-history secret scanning
  - **Hadolint** — Dockerfile lint
- **`SECURITY.md`** publishes a responsible-disclosure policy so
  researchers have a private reporting path.

**The tradeoffs you're making:**

- The gateway becomes a concentrated target. Patch it, rotate
  `secret_key` and OAuth secrets on some cadence, back up `state/`,
  and watch the audit log.
- Admins can do a lot. Pick them carefully, and don't conflate admin
  access to the gateway with admin access to the systems behind it.
- This replaces "exposed services" with "one exposed admin panel." If
  the panel is compromised everything behind it is at risk, so don't
  treat this as an excuse to weaken auth on the services themselves.

---

## File layout

```
app.py                 # Flask app, routes, OAuth, auth decorators
gateway.py             # WireGuard + iptables + conntrack + grants
wg.py                  # X25519 keypair + preshared key + client config
audit.py               # JSON Lines log + weekly gzip rotation
hash_password.py       # One-off bcrypt hasher for config.yaml
entrypoint.sh          # Sets ip_forward, execs python
Dockerfile             # Python 3.12-slim + wireguard-tools + iptables
docker-compose.yml     # Gateway + Caddy (auto-TLS reverse proxy)
Caddyfile              # One-line reverse proxy with auto-TLS
config.example.yaml    # Annotated template — copy to config.yaml
templates/
  login.html           # Sign-in page
  dashboard.html       # Services + (admin) Users + Audit panels
  help.html            # End-user setup guide (per-OS tabs)
```

---

## License

See [LICENSE](LICENSE).
