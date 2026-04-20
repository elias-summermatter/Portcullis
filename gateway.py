"""Secure Infrastructure Gateway: WireGuard + iptables per-service access control.

State model:
- one WireGuard interface (wg0) with a server keypair persisted to disk
- each user gets a fixed IP on the WG network + a peer entry on wg0
- "activating" a service installs an iptables FORWARD ACCEPT rule scoped to
  (that user's WG IP, that service's IPs, that service's port)
- a background reaper tears down expired grants so the config goes dead when
  the timer runs out, even if nothing else touches it
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from wg import Keypair, generate_keypair, generate_preshared_key, render_client_config

log = logging.getLogger(__name__)

DEFAULT_DURATION = 3600
MAX_DURATION = 8 * 3600
EXTEND_STEP = 3600
IPTABLES_CHAIN = "SIG_FORWARD"
RESOLVE_INTERVAL = 300  # re-resolve service hostnames every 5min
REAP_INTERVAL = 10


def _run(cmd: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    log.debug("run: %s", " ".join(cmd))
    return subprocess.run(cmd, check=check, text=True,
                          capture_output=capture)


def _derive_config_name(endpoint: str) -> str:
    """First label of the WG endpoint hostname (or "gateway" if it's an IP).
    Used as the filename prefix and, via wg-quick, the network interface
    name on the client — so must stay short and [a-z0-9-]."""
    import re
    host = endpoint.split(":", 1)[0]
    try:
        ipaddress.ip_address(host)
        return "gateway"
    except ValueError:
        first = host.split(".", 1)[0].lower()
        sanitized = re.sub(r"[^a-z0-9-]", "-", first).strip("-")
        return sanitized or "gateway"


@dataclass
class Service:
    name: str
    hostname: Optional[str] = None
    cidrs: list[str] = field(default_factory=list)
    port: Optional[int] = None
    protocol: str = "tcp"
    resolved: list[str] = field(default_factory=list)  # list of /32 or CIDRs
    # If True the service is off-by-default: a user cannot activate it until
    # an admin has explicitly called approve_service for them. Block still
    # takes precedence over approval.
    requires_approval: bool = False


@dataclass
class Grant:
    user: str
    service: str
    user_ip: str          # the user's WG /32 (gateway-side identity)
    source_ip: Optional[str]  # client's real IP at activation time (for audit)
    expires_at: float
    rules: list[list[str]] = field(default_factory=list)  # iptables rule specs installed


class Gateway:
    def __init__(self, config: dict, audit):
        self.audit = audit
        self.iface = config.get("wg_interface", "wg0")
        self.network = ipaddress.ip_network(config.get("wg_network", "10.77.0.0/24"))
        self.listen_port = int(config.get("wg_listen_port", 51820))
        self.endpoint = config["wg_endpoint"]  # "gateway.example.com:51820"
        self.config_name = config.get("wg_config_name") or _derive_config_name(self.endpoint)
        self.egress_iface = config.get("egress_interface", "eth0")
        self.client_dns = config.get("wg_client_dns")  # optional
        self.state_dir = Path(config.get("state_dir", "state"))
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.enable_netfilter = bool(config.get("enable_netfilter", True))

        self.services: dict[str, Service] = {}
        for s in config.get("services", []):
            svc = Service(
                name=s["name"],
                hostname=s.get("hostname"),
                cidrs=list(s.get("cidrs", [])),
                port=s.get("port"),
                protocol=s.get("protocol", "tcp"),
                requires_approval=bool(s.get("requires_approval", False)),
            )
            self.services[svc.name] = svc

        # users: username -> {"public_key": str, "ip": str, "created_at": float}
        self.users: dict[str, dict] = {}
        # grants keyed by (user, service_name)
        self.grants: dict[tuple[str, str], Grant] = {}
        self._lock = threading.Lock()

        self.server_keys = self._load_or_create_server_keys()
        self._load_users()

    # --- persistent state -------------------------------------------------

    def _load_or_create_server_keys(self) -> Keypair:
        priv_path = self.state_dir / "server.key"
        pub_path = self.state_dir / "server.pub"
        if priv_path.exists() and pub_path.exists():
            return Keypair(
                private_key_b64=priv_path.read_text().strip(),
                public_key_b64=pub_path.read_text().strip(),
            )
        kp = generate_keypair()
        priv_path.write_text(kp.private_key_b64 + "\n")
        priv_path.chmod(0o600)
        pub_path.write_text(kp.public_key_b64 + "\n")
        log.info("generated server WireGuard keypair at %s", priv_path)
        return kp

    def _users_path(self) -> Path:
        return self.state_dir / "users.json"

    def _load_users(self) -> None:
        p = self._users_path()
        if p.exists():
            try:
                self.users = json.loads(p.read_text())
            except Exception as e:
                log.warning("could not load users.json: %s", e)
                self.users = {}

    def _save_users(self) -> None:
        p = self._users_path()
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.users, indent=2))
        tmp.replace(p)

    # --- lifecycle --------------------------------------------------------

    def start(self) -> None:
        if self.enable_netfilter:
            self._setup_interface()
            self._setup_base_firewall()
            for username, u in self.users.items():
                try:
                    self._wg_add_peer(u["public_key"], u["ip"],
                                      preshared_key_b64=u.get("preshared_key"))
                except Exception as e:
                    log.warning("failed to re-add peer %s: %s", username, e)
        self._resolve_all_services()
        threading.Thread(target=self._resolver_loop, daemon=True, name="resolver").start()
        threading.Thread(target=self._reaper_loop, daemon=True, name="reaper").start()

    # --- WG / iptables setup ---------------------------------------------

    def _setup_interface(self) -> None:
        # idempotent: tear down if it exists so we start clean on restart
        try:
            _run(["ip", "link", "del", self.iface], check=False, capture=True)
        except Exception:
            pass
        _run(["ip", "link", "add", "dev", self.iface, "type", "wireguard"])
        gateway_ip = next(self.network.hosts())  # .1
        _run(["ip", "address", "add", f"{gateway_ip}/{self.network.prefixlen}",
              "dev", self.iface])

        priv_file = self.state_dir / "server.key"
        _run(["wg", "set", self.iface,
              "listen-port", str(self.listen_port),
              "private-key", str(priv_file)])
        _run(["ip", "link", "set", "up", "dev", self.iface])
        log.info("WireGuard interface %s up on %s/%d, listen :%d",
                 self.iface, gateway_ip, self.network.prefixlen, self.listen_port)

    def _setup_base_firewall(self) -> None:
        # Custom chain so we can flush ours without trashing the rest of FORWARD.
        _run(["iptables", "-N", IPTABLES_CHAIN], check=False, capture=True)
        _run(["iptables", "-F", IPTABLES_CHAIN])

        # Jump into our chain for both directions of WG traffic:
        #   -i wg0 = new connections from clients going out to targets
        #   -o wg0 = return traffic from targets back into the tunnel
        # Both directions are needed so conntrack ESTABLISHED,RELATED
        # (first rule in the chain) accepts return packets.
        for args in (["-i", self.iface], ["-o", self.iface]):
            _run(["iptables", "-D", "FORWARD", *args, "-j", IPTABLES_CHAIN],
                 check=False, capture=True)
            _run(["iptables", "-I", "FORWARD", "1", *args, "-j", IPTABLES_CHAIN])

        _run(["iptables", "-A", IPTABLES_CHAIN,
              "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        # Final deny — per-grant ACCEPTs get inserted above this.
        _run(["iptables", "-A", IPTABLES_CHAIN, "-j", "DROP"])

        # NAT egress
        _run(["iptables", "-t", "nat", "-D", "POSTROUTING",
              "-s", str(self.network), "-o", self.egress_iface, "-j", "MASQUERADE"],
             check=False, capture=True)
        _run(["iptables", "-t", "nat", "-A", "POSTROUTING",
              "-s", str(self.network), "-o", self.egress_iface, "-j", "MASQUERADE"])
        log.info("base firewall rules installed (chain=%s, egress=%s)",
                 IPTABLES_CHAIN, self.egress_iface)

    # --- peer management --------------------------------------------------

    def _wg_add_peer(self, public_key: str, ip: str,
                     preshared_key_b64: Optional[str] = None) -> None:
        if not self.enable_netfilter:
            return
        args = ["wg", "set", self.iface, "peer", public_key,
                "allowed-ips", f"{ip}/32"]
        tmp_path: Optional[str] = None
        if preshared_key_b64:
            # `wg set ... preshared-key <file>` reads from disk. Write a
            # 0600 tempfile just for the call and delete it afterward.
            fd, tmp_path = tempfile.mkstemp(prefix="wg-psk-", dir=str(self.state_dir))
            try:
                os.write(fd, preshared_key_b64.encode() + b"\n")
                os.close(fd)
                os.chmod(tmp_path, 0o600)
                args += ["preshared-key", tmp_path]
                _run(args)
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        else:
            _run(args)

    def _wg_remove_peer(self, public_key: str) -> None:
        if not self.enable_netfilter:
            return
        _run(["wg", "set", self.iface, "peer", public_key, "remove"],
             check=False, capture=True)

    def _allocate_ip(self) -> str:
        used = {u["ip"] for u in self.users.values()}
        gateway_ip = next(self.network.hosts())
        for host in self.network.hosts():
            if host == gateway_ip:
                continue
            if str(host) not in used:
                return str(host)
        raise RuntimeError("WireGuard network exhausted")

    def register_user(self, username: str) -> tuple[str, str]:
        """Generate a keypair, register a peer, persist, return (config_text, ip).

        The private key is returned once and not stored by the gateway."""
        with self._lock:
            if username in self.users:
                old = self.users[username]
                try:
                    self._wg_remove_peer(old["public_key"])
                except Exception:
                    pass
                ip = old["ip"]
            else:
                ip = self._allocate_ip()
            kp = generate_keypair()
            psk = generate_preshared_key()
            self.users[username] = {
                "public_key": kp.public_key_b64,
                "preshared_key": psk,
                "ip": ip,
                "created_at": time.time(),
            }
            self._save_users()
            self._wg_add_peer(kp.public_key_b64, ip, preshared_key_b64=psk)

        allowed_ips = [str(self.network)]
        for svc in self.services.values():
            allowed_ips.extend(svc.resolved or svc.cidrs)

        cfg = render_client_config(
            client_private_key_b64=kp.private_key_b64,
            client_address=f"{ip}/32",
            server_public_key_b64=self.server_keys.public_key_b64,
            endpoint=self.endpoint,
            allowed_ips=allowed_ips,
            preshared_key_b64=psk,
            dns=self.client_dns,
        )
        return cfg, ip

    def user_ip(self, username: str) -> Optional[str]:
        u = self.users.get(username)
        return u["ip"] if u else None

    def user_has_config(self, username: str) -> bool:
        return username in self.users

    def list_users(self) -> list[dict]:
        now = time.time()
        with self._lock:
            out = []
            for username, u in self.users.items():
                active = [
                    {"service": svc_name, "expires_at": g.expires_at}
                    for (uname, svc_name), g in self.grants.items()
                    if uname == username and g.expires_at > now
                ]
                out.append({
                    "username": username,
                    "wg_ip": u.get("ip"),
                    "created_at": u.get("created_at"),
                    "active": active,
                    "blocked": list(u.get("blocked_services", [])),
                    "approved": list(u.get("approved_services", [])),
                })
            return out

    def is_blocked(self, username: str, service_name: str) -> bool:
        u = self.users.get(username)
        if not u:
            return False
        return service_name in u.get("blocked_services", [])

    def is_approved(self, username: str, service_name: str) -> bool:
        u = self.users.get(username)
        if not u:
            return False
        return service_name in u.get("approved_services", [])

    def block_service(self, username: str, service_name: str) -> bool:
        """Permanently block a service for a user + revoke any active grant.
        Returns True if the block was applied (even if already blocked)."""
        with self._lock:
            u = self.users.get(username)
            if not u:
                return False
            blocked = set(u.get("blocked_services", []))
            blocked.add(service_name)
            u["blocked_services"] = sorted(blocked)
            self._save_users()
            g = self.grants.pop((username, service_name), None)
            if g is not None:
                self._apply_rules(g.rules, delete=True)
                svc = self.services.get(service_name)
                if svc is not None:
                    self._drop_conntrack(g.user_ip, svc)
        return True

    def unblock_service(self, username: str, service_name: str) -> bool:
        with self._lock:
            u = self.users.get(username)
            if not u:
                return False
            blocked = set(u.get("blocked_services", []))
            blocked.discard(service_name)
            u["blocked_services"] = sorted(blocked)
            self._save_users()
        return True

    def approve_service(self, username: str, service_name: str) -> bool:
        """Grant an approval-gated service to a user. Does nothing if the
        service is not marked requires_approval (no effect, returns True so
        the admin UI stays idempotent). Returns False only if the user is
        unknown."""
        with self._lock:
            u = self.users.get(username)
            if not u:
                return False
            approved = set(u.get("approved_services", []))
            approved.add(service_name)
            u["approved_services"] = sorted(approved)
            self._save_users()
        return True

    def revoke_approval(self, username: str, service_name: str) -> bool:
        """Remove a previously-granted approval AND tear down any active grant
        for that service. Returns False only if the user is unknown."""
        with self._lock:
            u = self.users.get(username)
            if not u:
                return False
            approved = set(u.get("approved_services", []))
            approved.discard(service_name)
            u["approved_services"] = sorted(approved)
            self._save_users()
            g = self.grants.pop((username, service_name), None)
            if g is not None:
                self._apply_rules(g.rules, delete=True)
                svc = self.services.get(service_name)
                if svc is not None:
                    self._drop_conntrack(g.user_ip, svc)
        return True

    def lock_user(self, username: str) -> bool:
        """Block every configured service for a user AND revoke all their
        active grants. The WG peer stays (so the tunnel still handshakes)
        but no FORWARD rule matches — effectively a full access freeze."""
        with self._lock:
            u = self.users.get(username)
            if not u:
                return False
            u["blocked_services"] = sorted(self.services.keys())
            self._save_users()
            for key in [k for k in self.grants if k[0] == username]:
                g = self.grants.pop(key)
                self._apply_rules(g.rules, delete=True)
                svc = self.services.get(key[1])
                if svc is not None:
                    self._drop_conntrack(g.user_ip, svc)
        return True

    def unlock_user(self, username: str) -> bool:
        with self._lock:
            u = self.users.get(username)
            if not u:
                return False
            u["blocked_services"] = []
            self._save_users()
        return True

    def revoke_user(self, username: str) -> bool:
        """Kill all grants + drop the WG peer + forget the user's assignment.
        Returns True if the user had a config; False otherwise."""
        with self._lock:
            u = self.users.pop(username, None)
            if u is None:
                return False
            for key in [k for k in self.grants if k[0] == username]:
                g = self.grants.pop(key)
                self._apply_rules(g.rules, delete=True)
                svc = self.services.get(key[1])
                if svc is not None:
                    self._drop_conntrack(g.user_ip, svc)
            try:
                self._wg_remove_peer(u["public_key"])
            except Exception as e:
                log.warning("wg peer remove failed for %s: %s", username, e)
            self._save_users()
        log.info("revoked user=%s ip=%s", username, u.get("ip"))
        return True

    # --- service resolution ----------------------------------------------

    def _resolve_service(self, svc: Service) -> list[str]:
        cidrs = list(svc.cidrs)
        if svc.hostname:
            try:
                # IPv4 only for now (iptables rules); extend if needed.
                infos = socket.getaddrinfo(svc.hostname, None, family=socket.AF_INET,
                                           type=socket.SOCK_STREAM)
                ips = sorted({info[4][0] for info in infos})
                cidrs.extend(f"{ip}/32" for ip in ips)
            except socket.gaierror as e:
                log.warning("resolve %s failed: %s", svc.hostname, e)
        # de-dupe, preserve order
        seen: set[str] = set()
        out = []
        for c in cidrs:
            if c not in seen:
                seen.add(c)
                out.append(c)
        return out

    def _resolve_all_services(self) -> None:
        for svc in self.services.values():
            new = self._resolve_service(svc)
            if new != svc.resolved:
                log.info("service %s resolved: %s", svc.name, new)
                svc.resolved = new

    def _resolver_loop(self) -> None:
        while True:
            time.sleep(RESOLVE_INTERVAL)
            try:
                self._resolve_all_services()
            except Exception as e:
                log.warning("resolver pass failed: %s", e)

    # --- grants (activation) ---------------------------------------------

    def _build_rules(self, user_ip: str, svc: Service) -> list[list[str]]:
        rules: list[list[str]] = []
        targets = svc.resolved or svc.cidrs
        for dest in targets:
            rule = ["-s", f"{user_ip}/32", "-d", dest,
                    "-p", svc.protocol]
            if svc.port:
                rule += ["--dport", str(svc.port)]
            rule += ["-j", "ACCEPT"]
            rules.append(rule)
        return rules

    def _apply_rules(self, rules: list[list[str]], *, delete: bool = False) -> None:
        if not self.enable_netfilter:
            return
        op = "-D" if delete else "-I"
        for r in rules:
            # -I inserts at top so rule is evaluated before the chain's DROP
            cmd = ["iptables", op, IPTABLES_CHAIN] + (["1"] if op == "-I" else []) + r
            _run(cmd, check=not delete, capture=delete)

    def _drop_conntrack(self, user_ip: str, svc: Service) -> None:
        """Tear down in-flight flows so expiry/deactivation cuts the SSH or
        psql session the user already had open, not just new connections."""
        if not self.enable_netfilter:
            return
        targets = svc.resolved or svc.cidrs
        for dest in targets:
            dest_ip = dest.split("/", 1)[0]
            cmd = ["conntrack", "-D",
                   "-s", user_ip,
                   "-d", dest_ip,
                   "-p", svc.protocol]
            if svc.port:
                cmd += ["--dport", str(svc.port)]
            # conntrack -D exits 0 if entries were deleted, 1 if none matched.
            _run(cmd, check=False, capture=True)

    def activate(self, user: str, service_name: str,
                 source_ip: Optional[str] = None) -> float:
        svc = self.services.get(service_name)
        if svc is None:
            raise KeyError(service_name)
        u = self.users.get(user)
        if u is None:
            raise RuntimeError("user has no WG config; generate one first")
        if service_name in u.get("blocked_services", []):
            raise PermissionError(f"service {service_name!r} is blocked for this user")
        if svc.requires_approval and service_name not in u.get("approved_services", []):
            raise PermissionError(f"service {service_name!r} requires admin approval")
        user_ip = u["ip"]
        now = time.time()
        expires = now + DEFAULT_DURATION

        key = (user, service_name)
        with self._lock:
            existing = self.grants.get(key)
            if existing:
                self._apply_rules(existing.rules, delete=True)
            rules = self._build_rules(user_ip, svc)
            self._apply_rules(rules)
            self.grants[key] = Grant(user=user, service=service_name,
                                     user_ip=user_ip, source_ip=source_ip,
                                     expires_at=expires, rules=rules)
        return expires

    def extend(self, user: str, service_name: str,
               source_ip: Optional[str] = None) -> float:
        u = self.users.get(user)
        if u is None:
            raise RuntimeError("user has no WG config; generate one first")
        if service_name in u.get("blocked_services", []):
            raise PermissionError(f"service {service_name!r} is blocked for this user")
        svc = self.services.get(service_name)
        if svc is None:
            raise KeyError(service_name)
        if svc.requires_approval and service_name not in u.get("approved_services", []):
            raise PermissionError(f"service {service_name!r} requires admin approval")
        now = time.time()
        key = (user, service_name)
        with self._lock:
            g = self.grants.get(key)
            current = g.expires_at if (g and g.expires_at > now) else now
            expires = min(current + EXTEND_STEP, now + MAX_DURATION)
            if g is None or g.expires_at <= now:
                if g:
                    self._apply_rules(g.rules, delete=True)
                rules = self._build_rules(u["ip"], svc)
                self._apply_rules(rules)
                self.grants[key] = Grant(user=user, service=service_name,
                                         user_ip=u["ip"], source_ip=source_ip,
                                         expires_at=expires, rules=rules)
            else:
                g.expires_at = expires
                if source_ip:
                    g.source_ip = source_ip
        return expires

    def deactivate(self, user: str, service_name: str) -> None:
        key = (user, service_name)
        with self._lock:
            g = self.grants.pop(key, None)
            if g is not None:
                self._apply_rules(g.rules, delete=True)
                svc = self.services.get(service_name)
                if svc is not None:
                    self._drop_conntrack(g.user_ip, svc)

    def status_for_user(self, user: str) -> dict[str, float]:
        now = time.time()
        out: dict[str, float] = {}
        with self._lock:
            for (u, svc), g in self.grants.items():
                if u == user and g.expires_at > now:
                    out[svc] = g.expires_at
        return out

    # --- reaper -----------------------------------------------------------

    def _reaper_loop(self) -> None:
        while True:
            time.sleep(REAP_INTERVAL)
            try:
                self._reap_expired()
            except Exception as e:
                log.warning("reaper pass failed: %s", e)

    def _reap_expired(self) -> None:
        now = time.time()
        expired: list[tuple[tuple[str, str], Grant]] = []
        with self._lock:
            for key, g in list(self.grants.items()):
                if g.expires_at <= now:
                    expired.append((key, g))
                    del self.grants[key]
            for (_, service_name), g in expired:
                self._apply_rules(g.rules, delete=True)
                svc = self.services.get(service_name)
                if svc is not None:
                    self._drop_conntrack(g.user_ip, svc)
        for (user, service), g in expired:
            log.info("reaped grant user=%s service=%s", user, service)
            self.audit.record("grant_expired", user=user, service=service,
                              ip=g.source_ip, wg_ip=g.user_ip)
