"""ChainStore anti-rollback semantics (SYM-SNAP-001/002/003, spec/cli.md exit code 7)."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from symbiote.model import Snapshot
from symbiote.model import enums as E
from symbiote.model.common import Validity
from symbiote.snapshot import ChainConflictError, ChainStore, StoreLockedError

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def _snap(serial: int, digest_byte: str, prev: str | None = None, **kw) -> Snapshot:
    digest = "sha256:" + digest_byte * 64
    return Snapshot(
        id=f"snap:{serial}:{digest[7:19]}",
        kind=E.SnapshotKind.DECLARED,
        digest=digest,
        serial=serial,
        prev=prev,
        agent_ref="agent:triager",
        produced_at=NOW,
        **kw,
    )


def test_allocate_on_empty_store(tmp_path) -> None:
    assert ChainStore(tmp_path).allocate("agent:triager", E.SnapshotKind.DECLARED) == (1, None)


def test_commit_peek_allocate_roundtrip(tmp_path) -> None:
    store = ChainStore(tmp_path)
    s1 = _snap(1, "a")
    assert store.commit(s1) == []
    head = store.peek("agent:triager", E.SnapshotKind.DECLARED)
    assert head is not None and head.serial == 1 and head.digest == s1.digest
    assert store.allocate("agent:triager", E.SnapshotKind.DECLARED) == (2, s1.digest)
    # kinds are independent chains
    assert store.allocate("agent:triager", E.SnapshotKind.OBSERVED) == (1, None)


def test_serial_regression_and_fork_are_critical(tmp_path) -> None:
    store = ChainStore(tmp_path)
    store.commit(_snap(2, "a"))
    with pytest.raises(ChainConflictError) as exc:
        store.commit(_snap(1, "b"))
    assert exc.value.issues[0].check_id == "SYM-SNAP-001"
    with pytest.raises(ChainConflictError):  # fork: same serial, different digest
        store.commit(_snap(2, "c"))
    issues = store.commit(_snap(2, "c"), force=True)  # forced fork records the issue
    assert [i.check_id for i in issues] == ["SYM-SNAP-001"]


def test_idempotent_recommit_of_head(tmp_path) -> None:
    store = ChainStore(tmp_path)
    store.commit(_snap(1, "a"))
    assert store.commit(_snap(1, "a")) == []


def test_chain_gap_is_medium_and_commit_proceeds(tmp_path) -> None:
    store = ChainStore(tmp_path)
    s1 = _snap(1, "a")
    store.commit(s1)
    issues = store.commit(_snap(3, "b", prev="sha256:" + "d" * 64))
    ids = sorted(i.check_id for i in issues)
    assert ids == ["SYM-SNAP-003", "SYM-SNAP-003"]  # wrong prev + skipped serial 2
    head = store.peek("agent:triager", E.SnapshotKind.DECLARED)
    assert head is not None and head.serial == 3


def test_prev_without_head_is_a_gap(tmp_path) -> None:
    store = ChainStore(tmp_path)
    issues = store.check(_snap(1, "a", prev="sha256:" + "e" * 64))
    assert [i.check_id for i in issues] == ["SYM-SNAP-003"]


def test_expiry_issue(tmp_path) -> None:
    snap = _snap(1, "a", validity=Validity(not_after=datetime(2026, 1, 1, tzinfo=UTC)))
    issues = ChainStore(tmp_path).expiry_issues(snap, now=NOW)
    assert [i.check_id for i in issues] == ["SYM-SNAP-002"]
    assert ChainStore(tmp_path).expiry_issues(_snap(1, "a"), now=NOW) == []


def test_lock_contention_and_stale_steal(tmp_path) -> None:
    store = ChainStore(tmp_path, lock_timeout=0.2)
    store.root.mkdir(parents=True, exist_ok=True)
    lock = store.root / "chains.lock"
    lock.write_text("1")
    with pytest.raises(StoreLockedError):
        store.commit(_snap(1, "a"))
    old = NOW.timestamp() - 3600
    os.utime(lock, (old, old))  # stale lock is stolen
    assert store.commit(_snap(1, "a")) == []
