"""Anti-rollback chain state for snapshot serials (``spec/agentbom-profile.md §2.1``, SYM-SNAP-00x).

The store records, per ``(agent_ref, kind)``, the highest serial seen and its digest, forming the
hash chain that ``prev`` must extend. It backs three stable checks (``spec/checks.md §2``):

* ``SYM-SNAP-001`` serial regression (critical) — a new snapshot whose serial is not greater than
  the recorded head, or a *fork* (same serial, different digest).
* ``SYM-SNAP-002`` snapshot expired (high) — evaluated against a supplied clock, never wall time.
* ``SYM-SNAP-003`` chain gap (medium) — ``prev`` does not equal the recorded head digest, or
  serials were skipped.

Storage is a single JSON file under the store directory, written atomically
(temp file + ``os.replace``) behind an exclusive lock file. The store assumes cooperating local
writers (the CLI); it is not a distributed lock service.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from symbiote.model.enums import Severity, SnapshotKind
from symbiote.model.snapshot import Snapshot

if TYPE_CHECKING:
    from symbiote.model.document import AgentBOM

STATE_VERSION = 1
_HISTORY_LIMIT = 50


class StoreLockedError(RuntimeError):
    """The chain-state lock could not be acquired in time."""


class ChainConflictError(RuntimeError):
    """Committing the snapshot would violate anti-rollback (exit code 7, ``spec/cli.md``)."""

    def __init__(self, issues: list[ChainIssue]) -> None:
        super().__init__("; ".join(i.message for i in issues) or "chain conflict")
        self.issues = issues


@dataclass(frozen=True)
class ChainIssue:
    """A chain-state verdict, aligned 1:1 with the ``SYM-SNAP-*`` checks."""

    check_id: str
    severity: Severity
    message: str
    subject: str


@dataclass(frozen=True)
class ChainHead:
    agent_ref: str
    kind: str
    serial: int
    digest: str
    produced_at: str


def _key(agent_ref: str, kind: SnapshotKind | str) -> str:
    kind_value = kind.value if isinstance(kind, SnapshotKind) else kind
    return f"{kind_value}|{agent_ref}"


class ChainStore:
    """File-backed serial/digest chain per ``(agent_ref, snapshot kind)``."""

    def __init__(self, root: Path | str, *, lock_timeout: float = 5.0) -> None:
        self.root = Path(root)
        self.path = self.root / "chains.json"
        self._lock_path = self.root / "chains.lock"
        self._lock_timeout = lock_timeout
        self._lock_fd: int | None = None

    # ------------------------------------------------------------------ io

    def _read(self) -> dict[str, dict[str, object]]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"chain state at {self.path} is unreadable: {exc}") from exc
        if not isinstance(raw, dict) or raw.get("version") != STATE_VERSION:
            raise RuntimeError(f"chain state at {self.path} has an unsupported version")
        chains = raw.get("chains", {})
        return chains if isinstance(chains, dict) else {}

    def _write(self, chains: dict[str, dict[str, object]]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        payload = {"version": STATE_VERSION, "chains": dict(sorted(chains.items()))}
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)

    def _acquire_lock(self) -> None:
        """Take an exclusive kernel lock on a persistent lock file.

        ``flock`` is released by the kernel when the holder exits or crashes, so
        there is no staleness heuristic and no way for a second writer to
        "steal" a live holder's lock (the old mtime-based steal allowed two
        writers into the critical section and a silent chain fork). The lock
        file is never unlinked: unlinking would let a later opener lock a fresh
        inode while an earlier holder still holds the old one.
        """
        self.root.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._lock_path, os.O_CREAT | os.O_WRONLY, 0o600)
        deadline = time.monotonic() + self._lock_timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise StoreLockedError(
                        f"could not lock {self._lock_path} within {self._lock_timeout}s"
                    ) from None
                time.sleep(0.05)
                continue
            self._lock_fd = fd
            return

    def _release_lock(self) -> None:
        fd = self._lock_fd
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
            self._lock_fd = None

    # ------------------------------------------------------------------ queries

    def peek(self, agent_ref: str, kind: SnapshotKind | str) -> ChainHead | None:
        entry = self._read().get(_key(agent_ref, kind))
        if not isinstance(entry, dict):
            return None
        serial = entry.get("serial")
        digest = entry.get("digest")
        if not isinstance(serial, int) or not isinstance(digest, str):
            raise RuntimeError(f"chain state at {self.path} holds a malformed head for {agent_ref}")
        produced_at = entry.get("producedAt")
        return ChainHead(
            agent_ref=agent_ref,
            kind=kind.value if isinstance(kind, SnapshotKind) else kind,
            serial=serial,
            digest=digest,
            produced_at=produced_at if isinstance(produced_at, str) else "",
        )

    def allocate(self, agent_ref: str, kind: SnapshotKind | str) -> tuple[int, str | None]:
        """Next ``(serial, prev_digest)`` for a new snapshot. Pure read; nothing is reserved."""
        head = self.peek(agent_ref, kind)
        if head is None:
            return 1, None
        return head.serial + 1, head.digest

    # ------------------------------------------------------------------ verdicts

    def check(self, snapshot: Snapshot) -> list[ChainIssue]:
        """Anti-rollback verdicts for ``snapshot`` against the recorded head (no writes)."""
        issues: list[ChainIssue] = []
        head = self.peek(snapshot.agent_ref, snapshot.kind)
        subject = snapshot.id
        if head is None:
            if snapshot.prev is not None:
                issues.append(
                    ChainIssue(
                        "SYM-SNAP-003",
                        Severity.MEDIUM,
                        f"{subject}: prev={snapshot.prev} but no chain head is recorded",
                        subject,
                    )
                )
            return issues
        if snapshot.serial == head.serial and snapshot.digest == head.digest:
            return issues  # idempotent re-commit of the recorded head
        if snapshot.serial <= head.serial:
            kind_word = "fork of" if snapshot.serial == head.serial else "regression below"
            issues.append(
                ChainIssue(
                    "SYM-SNAP-001",
                    Severity.CRITICAL,
                    f"{subject}: serial {snapshot.serial} is a {kind_word} recorded head "
                    f"serial {head.serial} ({head.digest})",
                    subject,
                )
            )
            return issues
        if snapshot.prev != head.digest:
            issues.append(
                ChainIssue(
                    "SYM-SNAP-003",
                    Severity.MEDIUM,
                    f"{subject}: prev={snapshot.prev} does not extend recorded head {head.digest}",
                    subject,
                )
            )
        if snapshot.serial > head.serial + 1:
            issues.append(
                ChainIssue(
                    "SYM-SNAP-003",
                    Severity.MEDIUM,
                    f"{subject}: serials {head.serial + 1}..{snapshot.serial - 1} were skipped",
                    subject,
                )
            )
        return issues

    @staticmethod
    def expiry_issues(snapshot: Snapshot, *, now: datetime) -> list[ChainIssue]:
        """``SYM-SNAP-002`` against an explicit clock (callers decide what "now" means)."""
        not_after = snapshot.validity.not_after
        if not_after is None:
            return []
        reference = now if now.tzinfo is not None else now.replace(tzinfo=UTC)
        if reference >= not_after:
            return [
                ChainIssue(
                    "SYM-SNAP-002",
                    Severity.HIGH,
                    f"{snapshot.id}: expired at {not_after.isoformat()}",
                    snapshot.id,
                )
            ]
        return []

    # ------------------------------------------------------------------ commit

    def commit(self, snapshot: Snapshot, *, force: bool = False) -> list[ChainIssue]:
        """Record ``snapshot`` as the chain head.

        Critical issues (``SYM-SNAP-001``) raise :class:`ChainConflictError` unless ``force`` is
        true; non-critical issues are returned and the commit proceeds. The caller surfaces them.
        """
        self._acquire_lock()
        try:
            issues = self.check(snapshot)
            critical = [i for i in issues if i.severity is Severity.CRITICAL]
            if critical and not force:
                raise ChainConflictError(critical)
            chains = self._read()
            key = _key(snapshot.agent_ref, snapshot.kind)
            entry = chains.get(key)
            history_raw = entry.get("history") if isinstance(entry, dict) else None
            history: list[object] = list(history_raw) if isinstance(history_raw, list) else []
            history.append(
                {
                    "serial": snapshot.serial,
                    "digest": snapshot.digest,
                    "producedAt": snapshot.produced_at.isoformat(),
                }
            )
            chains[key] = {
                "agentRef": snapshot.agent_ref,
                "kind": snapshot.kind.value,
                "serial": snapshot.serial,
                "digest": snapshot.digest,
                "producedAt": snapshot.produced_at.isoformat(),
                "history": history[-_HISTORY_LIMIT:],
            }
            self._write(chains)
            return issues
        finally:
            self._release_lock()


def seal_with_chain(
    bom: AgentBOM,
    store: ChainStore,
    *,
    nonce: bytes | None = None,
    prev: str | None = None,
    include_nonce: bool = True,
    force: bool = False,
) -> tuple[AgentBOM, list[ChainIssue]]:
    """Allocate serial/prev from the chain, :func:`~symbiote.snapshot.commit.finalize`, and commit.

    The document's collections and header fields are kept as-is except ``serial``/``prev``
    (chain-allocated unless ``prev`` is given) and the digest-bearing fields, which
    ``finalize`` recomputes. Critical anti-rollback verdicts raise
    :class:`ChainConflictError` (CLI exit code 7) unless ``force``; non-critical issues are
    returned alongside the sealed document.
    """
    from symbiote.model.ids import snapshot_id
    from symbiote.snapshot.commit import PLACEHOLDER_DIGEST, finalize

    if bom.redacted:
        raise ValueError(
            "refusing to seal a redacted view: its withheld leaves cannot be recommitted; "
            "seal from the undisclosed source document instead"
        )
    serial, allocated_prev = store.allocate(bom.snapshot.agent_ref, bom.snapshot.kind)
    working = bom
    if bom.snapshot.serial != serial or bom.merkle is not None:
        header = bom.snapshot.replace(
            serial=serial,
            digest=PLACEHOLDER_DIGEST,
            id=snapshot_id(serial, PLACEHOLDER_DIGEST),
        )
        working = bom.replace(snapshot=header.model_dump(mode="python"), merkle=None)
    sealed = finalize(
        working,
        nonce=nonce,
        prev=prev if prev is not None else allocated_prev,
        include_nonce=include_nonce,
    )
    issues = store.commit(sealed.snapshot, force=force)
    return sealed, issues


__all__ = [
    "STATE_VERSION",
    "ChainConflictError",
    "ChainHead",
    "ChainIssue",
    "ChainStore",
    "StoreLockedError",
    "seal_with_chain",
]
