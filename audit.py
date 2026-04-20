import gzip
import json
import logging
import shutil
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)


CATEGORY = {
    "login": "auth", "login_failed": "auth", "logout": "auth",
    "session_revoked": "auth",
    "activate": "grant", "extend": "grant", "deactivate": "grant",
    "grant_expired": "grant", "wg_config_generated": "grant",
    "user_revoked": "admin", "user_deleted": "admin", "admin_deactivate": "admin",
    "service_blocked": "admin", "service_unblocked": "admin",
    "service_approved": "admin", "service_approval_revoked": "admin",
    "user_locked": "admin", "user_unlocked": "admin",
}


def _categories(event: str) -> list[str]:
    cats = [CATEGORY.get(event, "other")]
    if event == "login_failed":
        cats.append("error")
    return cats


def _actor(entry: dict) -> Optional[str]:
    return entry.get("user")


def _matches(
    entry: dict,
    category: Optional[str],
    user: Optional[str],
    service: Optional[str],
    ip: Optional[str],
) -> bool:
    if category and category not in _categories(entry.get("event", "")):
        return False
    if service and entry.get("service") != service:
        return False
    if user:
        actor = (_actor(entry) or "").lower()
        if user.lower() not in actor:
            return False
    if ip and ip.lower() not in (entry.get("ip") or "").lower():
        return False
    return True


class AuditLog:
    def __init__(self, path: Optional[str] = None, memory_size: int = 500):
        self.path = Path(path) if path else None
        self._buffer: deque[dict] = deque(maxlen=memory_size)
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._load_tail()

    def _load_tail(self) -> None:
        assert self.path is not None
        if not self.path.exists():
            return
        try:
            with self.path.open() as f:
                lines = f.readlines()
            tail = lines[-(self._buffer.maxlen or 0):] if self._buffer.maxlen else lines
            for line in tail:
                line = line.strip()
                if not line:
                    continue
                try:
                    self._buffer.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except OSError as e:
            log.warning("audit: could not read %s: %s", self.path, e)

    def record(
        self,
        event: str,
        *,
        user: Optional[str] = None,
        ip: Optional[str] = None,
        service: Optional[str] = None,
        **extra: Any,
    ) -> None:
        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event": event,
        }
        if user is not None:
            entry["user"] = user
        if ip is not None:
            entry["ip"] = ip
        if service is not None:
            entry["service"] = service
        for k, v in extra.items():
            if v is not None:
                entry[k] = v

        line = json.dumps(entry, separators=(",", ":"))
        with self._lock:
            self._buffer.append(entry)
            if self.path:
                try:
                    with self.path.open("a") as f:
                        f.write(line + "\n")
                except OSError as e:
                    log.warning("audit: could not write %s: %s", self.path, e)
        log.info("audit %s", line)

    # --- querying ---------------------------------------------------------

    def _archive_paths(self) -> list[Path]:
        if not self.path:
            return []
        pattern = f"{self.path.stem}-*.log.gz"
        return sorted(self.path.parent.glob(pattern))

    def _read_file(self, path: Path, *, gzipped: bool = False) -> list[dict]:
        events: list[dict] = []
        opener = gzip.open if gzipped else open
        try:
            with opener(path, "rt") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError as e:
            log.warning("audit: could not read %s: %s", path, e)
        return events

    def _read_all_newest_first(self) -> list[dict]:
        """Read live file + gzipped archives, return all events newest-first."""
        if not self.path:
            with self._lock:
                return list(reversed(self._buffer))

        all_events: list[dict] = []
        with self._lock:
            if self.path.exists():
                all_events.extend(self._read_file(self.path))
        for archive in self._archive_paths():
            all_events.extend(self._read_file(archive, gzipped=True))
        all_events.sort(key=lambda e: e.get("ts", ""), reverse=True)
        return all_events

    def query(
        self,
        offset: int = 0,
        limit: int = 100,
        category: Optional[str] = None,
        user: Optional[str] = None,
        service: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> dict:
        all_events = self._read_all_newest_first()
        if any((category, user, service, ip)):
            filtered = [e for e in all_events if _matches(e, category, user, service, ip)]
        else:
            filtered = all_events
        total = len(filtered)
        offset = max(0, offset)
        limit = max(1, min(limit, 500))
        page = filtered[offset:offset + limit]
        return {
            "total": total,
            "total_unfiltered": len(all_events),
            "offset": offset,
            "limit": limit,
            "events": page,
        }

    def recent(self, limit: int = 100) -> list[dict]:
        with self._lock:
            items = list(self._buffer)
        return list(reversed(items[-limit:]))

    # --- rotation ---------------------------------------------------------

    def rotate(self) -> Optional[Path]:
        """Rename audit.log to audit-YYYY-MM-DD.log.gz; start a fresh file.
        Archives are kept forever for compliance. Returns the archive path."""
        if not self.path or not self.path.exists():
            return None

        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        archive = self.path.parent / f"{self.path.stem}-{date_str}.log.gz"
        # Multiple rotations on the same day get a counter suffix.
        i = 2
        while archive.exists():
            archive = self.path.parent / f"{self.path.stem}-{date_str}.{i}.log.gz"
            i += 1

        staging = self.path.with_name(self.path.name + ".rotating")
        with self._lock:
            try:
                self.path.rename(staging)
            except FileNotFoundError:
                return None

        # Compression happens outside the lock so writers aren't blocked.
        try:
            with staging.open("rb") as src, gzip.open(archive, "wb") as dst:
                shutil.copyfileobj(src, dst)
            staging.unlink()
        except OSError as e:
            log.error("audit: rotation compression failed: %s", e)
            try:
                staging.rename(archive.with_suffix(".log"))
            except OSError:
                pass
            return None
        log.info("audit: rotated to %s", archive)
        return archive

    @staticmethod
    def _seconds_until_next_monday(now: datetime) -> float:
        # weekday(): Monday=0 ... Sunday=6. Next Monday 00:00 UTC.
        days_ahead = (7 - now.weekday()) % 7 or 7
        target = (now + timedelta(days=days_ahead)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        return max(1.0, (target - now).total_seconds())

    def start_rotation(self, *, weekly: bool = True) -> None:
        """Rotate audit.log every Monday 00:00 UTC (or every 24h if weekly=False)."""
        if not self.path:
            return

        def loop() -> None:
            while True:
                now = datetime.now(timezone.utc)
                if weekly:
                    sleep_s = self._seconds_until_next_monday(now)
                else:
                    nxt = (now + timedelta(days=1)).replace(
                        hour=0, minute=0, second=0, microsecond=0
                    )
                    sleep_s = max(1.0, (nxt - now).total_seconds())
                time.sleep(sleep_s)
                try:
                    self.rotate()
                except Exception as e:
                    log.warning("audit: rotation failed: %s", e)

        t = threading.Thread(target=loop, daemon=True, name="audit-rotate")
        t.start()
