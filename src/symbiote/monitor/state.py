"""Monitor state on disk (``spec/monitoring.md`` §2 step 6).

Layout under ``state_dir``::

    state.json                         per-agent scheduling state (atomic writes)
    monitor.lock                       exclusive lock held by one tick at a time (fcntl.flock)
    cache/                             advisor response cache
    agents/<slug>/history.jsonl        one cycle record per line
    agents/<slug>/last.agentbom.json   the previous cycle's companion, for drift diffs
    agents/<slug>/chain/               the target's own snapshot chain store (anti-rollback)

The lock is advisory between cooperating ``symbiote monitor`` processes and is an ``fcntl.flock`` (POSIX): the
kernel drops it when the holder exits, so an abandoned lock is never "broken" by a racing process.
``stale_after`` is accepted for compatibility and no longer used.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import secrets
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from symbiote.monitor.risk import RiskTier

if TYPE_CHECKING:
    from symbiote.model.document import AgentBOM

__all__ = [
    "STATE_VERSION",
    "AgentState",
    "StateError",
    "StateLockedError",
    "StateStore",
    "agent_slug",
]

STATE_VERSION = 1
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_COMPANION_BYTES = 64 * 1024 * 1024
MAX_HISTORY_BYTES = 8 * 1024 * 1024
#: Finding fingerprints kept per agent (bounds state.json).
MAX_FINGERPRINTS = 5000

_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]")


class StateError(RuntimeError):
    """``state.json`` is unreadable or malformed (the monitor refuses to guess)."""


class StateLockedError(RuntimeError):
    """Another tick holds the monitor lock."""


def agent_slug(name: str) -> str:
    slug = _SLUG_RE.sub("_", name)[:128].strip(".") or "agent"
    return slug


def _dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    # A hand-edited timestamp without an offset is read as UTC (never compared naive against aware).
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


@dataclass(slots=True)
class AgentState:
    name: str
    last_run_at: datetime | None = None
    next_due_at: datetime | None = None
    tier: RiskTier | None = None
    escalated: bool = False
    clean_streak: int = 0
    consecutive_errors: int = 0
    last_snapshot_digest: str | None = None
    last_serial: int | None = None
    #: Fingerprints (``check_id`` + sorted subjects) of the failing findings of the last successful cycle.
    findings: list[str] = field(default_factory=list)
    last_status: str | None = None
    last_error: str | None = None
    #: Counts from the last cycle, for ``monitor status``.
    last_summary: dict[str, int] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "lastRunAt": _iso(self.last_run_at),
            "nextDueAt": _iso(self.next_due_at),
            "tier": self.tier.value if self.tier else None,
            "escalated": self.escalated,
            "cleanStreak": self.clean_streak,
            "consecutiveErrors": self.consecutive_errors,
            "lastSnapshotDigest": self.last_snapshot_digest,
            "lastSerial": self.last_serial,
            "findings": sorted(self.findings)[:MAX_FINGERPRINTS],
            "lastStatus": self.last_status,
            "lastError": self.last_error,
            "lastSummary": dict(sorted(self.last_summary.items())),
        }

    @classmethod
    def from_json(cls, name: str, data: Any) -> AgentState:
        if not isinstance(data, dict):
            raise StateError(f"state for {name!r} is not an object")
        tier_raw = data.get("tier")
        try:
            tier = RiskTier(tier_raw) if isinstance(tier_raw, str) else None
        except ValueError:
            tier = None
        findings_raw = data.get("findings")
        findings = [f for f in findings_raw if isinstance(f, str)] if isinstance(findings_raw, list) else []
        summary_raw = data.get("lastSummary")
        summary = (
            {k: v for k, v in summary_raw.items() if isinstance(k, str) and isinstance(v, int)}
            if isinstance(summary_raw, dict)
            else {}
        )

        def _int(key: str) -> int:
            v = data.get(key)
            return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0

        serial = data.get("lastSerial")
        digest = data.get("lastSnapshotDigest")
        status = data.get("lastStatus")
        error = data.get("lastError")
        return cls(
            name=name,
            last_run_at=_dt(data.get("lastRunAt")),
            next_due_at=_dt(data.get("nextDueAt")),
            tier=tier,
            escalated=data.get("escalated") is True,
            clean_streak=_int("cleanStreak"),
            consecutive_errors=_int("consecutiveErrors"),
            last_snapshot_digest=digest if isinstance(digest, str) else None,
            last_serial=serial if isinstance(serial, int) and not isinstance(serial, bool) else None,
            findings=findings[:MAX_FINGERPRINTS],
            last_status=status if isinstance(status, str) else None,
            last_error=error if isinstance(error, str) else None,
            last_summary=summary,
        )


class StateStore:
    """All monitor state for one ``state_dir``. Thread-safe within a process; locked across processes."""

    def __init__(
        self,
        state_dir: Path,
        *,
        lock_timeout: float = 30.0,
        stale_after: float = 3600.0,
    ) -> None:
        self.root = Path(state_dir)
        self.path = self.root / "state.json"
        self.lock_path = self.root / "monitor.lock"
        self.chain_dir = self.root / "chain"
        self.cache_dir = self.root / "cache"
        self.lock_timeout = lock_timeout
        self.stale_after = stale_after
        self._mutex = threading.RLock()
        self._agents: dict[str, AgentState] | None = None
        self._lock_token: str | None = None
        self._lock_fd: int | None = None

    # ------------------------------------------------------------------ cross-process lock

    def acquire(self, *, timeout: float | None = None) -> None:
        """Take the exclusive lock, waiting up to ``timeout`` seconds.

        Mutual exclusion is ``fcntl.flock`` on ``monitor.lock``: the kernel releases it when the holder exits, so
        an abandoned lock never needs to be broken by another process (and no breaker can race a fresh holder).
        After locking, the descriptor's inode is compared with the path's: a holder that released (and unlinked)
        the file in between leaves us locking an orphaned inode, so we retry on the current file.
        """
        if self._lock_fd is not None:
            raise StateLockedError(f"{self.lock_path} is already held by this store")
        self.root.mkdir(parents=True, exist_ok=True)
        wait = self.lock_timeout if timeout is None else timeout
        deadline = time.monotonic() + max(0.0, wait)
        token = secrets.token_hex(16)
        while True:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                if time.monotonic() >= deadline:
                    raise StateLockedError(
                        f"another `symbiote monitor` holds {self.lock_path} (waited {wait:.0f}s)"
                    ) from None
                time.sleep(0.05)
                continue
            except BaseException:
                os.close(fd)
                raise
            try:
                current = os.stat(self.lock_path)
            except FileNotFoundError:
                current = None
            if current is None or current.st_ino != os.fstat(fd).st_ino:
                os.close(fd)  # we locked a file that was released and unlinked meanwhile: retry
                continue
            try:
                payload = {"pid": os.getpid(), "token": token, "acquiredAt": time.time()}
                os.ftruncate(fd, 0)
                os.write(fd, json.dumps(payload).encode("utf-8"))
            except OSError:
                os.close(fd)
                raise
            self._lock_fd = fd
            self._lock_token = token
            return

    def heartbeat(self) -> None:
        """Refresh the lock's mtime (diagnostics only: liveness is the kernel-held ``flock``)."""
        if self._lock_fd is not None:
            with contextlib.suppress(OSError):
                os.utime(self._lock_fd)

    def release(self) -> None:
        fd = self._lock_fd
        self._lock_fd = None
        self._lock_token = None
        if fd is None:
            return
        try:
            # Unlink while still holding the lock; waiters re-check the inode after locking (see acquire).
            with contextlib.suppress(OSError):
                current = os.stat(self.lock_path)
                if current.st_ino == os.fstat(fd).st_ino:
                    self.lock_path.unlink()
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def locked(self, *, timeout: float | None = None) -> Iterator[StateStore]:
        self.acquire(timeout=timeout)
        try:
            yield self
        finally:
            self.release()

    @property
    def holds_lock(self) -> bool:
        return self._lock_token is not None

    # ------------------------------------------------------------------ state.json

    def _read(self) -> dict[str, AgentState]:
        try:
            with self.path.open("rb") as fh:
                raw = fh.read(MAX_STATE_BYTES + 1)
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise StateError(f"{self.path}: {exc.strerror or exc}") from None
        if len(raw) > MAX_STATE_BYTES:
            raise StateError(f"{self.path}: larger than {MAX_STATE_BYTES} bytes")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise StateError(f"{self.path}: not valid JSON ({exc})") from None
        if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
            raise StateError(f"{self.path}: unsupported state version")
        agents = data.get("agents")
        if not isinstance(agents, dict):
            raise StateError(f"{self.path}: 'agents' is not an object")
        return {str(k): AgentState.from_json(str(k), v) for k, v in agents.items()}

    def load(self, *, refresh: bool = False) -> dict[str, AgentState]:
        """Every agent's state (a copy; mutate via :meth:`put`)."""
        with self._mutex:
            if self._agents is None or refresh:
                self._agents = self._read()
            return {k: AgentState.from_json(k, v.to_json()) for k, v in self._agents.items()}

    def get(self, name: str) -> AgentState:
        with self._mutex:
            current = self.load().get(name)
            return current if current is not None else AgentState(name=name)

    def put(self, state: AgentState) -> None:
        """Record one agent's state and write ``state.json`` atomically."""
        with self._mutex:
            if self._agents is None:
                self._agents = self._read()
            self._agents[state.name] = AgentState.from_json(state.name, state.to_json())
            payload = {
                "version": STATE_VERSION,
                "agents": {k: v.to_json() for k, v in sorted(self._agents.items())},
            }
            _atomic_write(self.path, (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"))

    # ------------------------------------------------------------------ per-agent files

    def agent_dir(self, name: str) -> Path:
        return self.root / "agents" / agent_slug(name)

    def chain_dir_for(self, name: str) -> Path:
        """The snapshot chain store of one monitored target.

        Each target has its own chain: two targets that declare the same agent identity (the same agent in
        production and staging) must not share serials, heads or anti-rollback state.
        """
        return self.agent_dir(name) / "chain"

    def history_path(self, name: str) -> Path:
        return self.agent_dir(name) / "history.jsonl"

    def previous_companion_path(self, name: str) -> Path:
        return self.agent_dir(name) / "last.agentbom.json"

    def append_history(self, name: str, record: dict[str, Any]) -> None:
        path = self.history_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str) + "\n"
        with self._mutex:
            try:
                if path.stat().st_size + len(line) > MAX_HISTORY_BYTES:
                    os.replace(path, path.with_name("history.1.jsonl"))
            except FileNotFoundError:
                pass
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line)

    def read_history(self, name: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """The last ``limit`` records (newest last); malformed lines are skipped."""
        path = self.history_path(name)
        try:
            with path.open("rb") as fh:
                size = fh.seek(0, os.SEEK_END)
                fh.seek(max(0, size - MAX_HISTORY_BYTES))
                raw = fh.read(MAX_HISTORY_BYTES)
        except FileNotFoundError:
            return []
        out: list[dict[str, Any]] = []
        for line in raw.decode("utf-8", errors="replace").splitlines()[-limit:]:
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict):
                out.append(item)
        return out

    def load_previous(self, name: str) -> AgentBOM | None:
        """The previous cycle's companion, or ``None`` when there is none (first cycle)."""
        from symbiote.export.companion import load_companion

        path = self.previous_companion_path(name)
        try:
            with path.open("rb") as fh:
                raw = fh.read(MAX_COMPANION_BYTES + 1)
        except FileNotFoundError:
            return None
        if len(raw) > MAX_COMPANION_BYTES:
            raise StateError(f"{path}: larger than {MAX_COMPANION_BYTES} bytes")
        return load_companion(raw)

    def save_previous(self, name: str, companion: bytes) -> None:
        _atomic_write(self.previous_companion_path(name), companion)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with tmp.open("wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
