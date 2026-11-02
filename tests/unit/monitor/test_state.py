"""Monitor state: atomic state.json, the exclusive lock, stale-lock recovery, history (spec/monitoring.md §2)."""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from symbiote.monitor import (
    AgentState,
    MonitorConfig,
    RiskTier,
    StateError,
    StateLockedError,
    StateStore,
    tick,
)

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def test_round_trip(tmp_path: Path) -> None:
    store = StateStore(tmp_path)
    st = AgentState(
        name="a",
        last_run_at=NOW,
        next_due_at=NOW,
        tier=RiskTier.HIGH,
        escalated=True,
        clean_streak=2,
        consecutive_errors=1,
        last_snapshot_digest="sha256:" + "0" * 64,
        findings=["SYM-X|b", "SYM-X|a"],
        last_status="findings",
    )
    store.put(st)
    data = json.loads((tmp_path / "state.json").read_text())
    assert data["version"] == 1 and data["agents"]["a"]["findings"] == ["SYM-X|a", "SYM-X|b"]
    again = StateStore(tmp_path).get("a")
    assert again.tier is RiskTier.HIGH and again.escalated and again.next_due_at == NOW
    assert StateStore(tmp_path).get("unknown") == AgentState(name="unknown")
    assert not list(tmp_path.glob(".*.tmp"))  # atomic write leaves no temp files


def test_corrupt_state_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "state.json").write_text("{not json")
    with pytest.raises(StateError):
        StateStore(tmp_path).load()
    (tmp_path / "state.json").write_text('{"version": 99, "agents": {}}')
    with pytest.raises(StateError, match="version"):
        StateStore(tmp_path).load()


def test_lock_is_exclusive_and_second_waits(tmp_path: Path) -> None:
    first = StateStore(tmp_path)
    second = StateStore(tmp_path)
    first.acquire()
    with pytest.raises(StateLockedError):
        second.acquire(timeout=0.2)
    acquired = threading.Event()

    def waiter() -> None:
        second.acquire(timeout=5)
        acquired.set()

    t = threading.Thread(target=waiter)
    t.start()
    time.sleep(0.2)
    assert not acquired.is_set()
    first.release()
    t.join(5)
    assert acquired.is_set()
    second.release()
    assert not (tmp_path / "monitor.lock").exists()


def test_abandoned_lock_file_is_reusable_and_held_lock_is_respected(tmp_path: Path) -> None:
    # A lock file left behind by a dead process holds no flock: it is simply taken over (no breaking needed).
    lock = tmp_path / "monitor.lock"
    lock.write_text('{"pid": 1, "token": "dead"}')
    store = StateStore(tmp_path)
    store.acquire(timeout=0.5)
    assert json.loads(lock.read_text())["token"] != "dead"
    store.release()
    # A lock held by another holder is respected, however old its mtime is.
    holder = StateStore(tmp_path)
    holder.acquire()
    old = time.time() - 7200
    os.utime(lock, (old, old))
    with pytest.raises(StateLockedError):
        StateStore(tmp_path, stale_after=1).acquire(timeout=0.2)
    # Releasing a lock we do not hold never removes someone else's.
    StateStore(tmp_path).release()
    assert lock.exists()
    holder.release()


def test_lock_handover_never_yields_two_holders(tmp_path: Path) -> None:
    """Regression: breaking a "stale" lock could restore it over a third process's fresh lock (two holders)."""
    a, b, c = StateStore(tmp_path), StateStore(tmp_path), StateStore(tmp_path)
    a.acquire()
    got_b = threading.Event()

    def take_b() -> None:
        b.acquire(timeout=5)
        got_b.set()

    t = threading.Thread(target=take_b)
    t.start()
    time.sleep(0.1)
    a.release()  # unlinks the file while still locked; B must re-lock the current file, not the orphan
    t.join(5)
    assert got_b.is_set() and b.holds_lock
    with pytest.raises(StateLockedError):
        c.acquire(timeout=0.2)
    token = json.loads((tmp_path / "monitor.lock").read_text())["token"]
    assert token == b._lock_token
    b.release()
    c.acquire(timeout=1)
    c.release()


def test_naive_timestamps_in_state_are_utc(tmp_path: Path) -> None:
    (tmp_path / "state.json").write_text(
        json.dumps({"version": 1, "agents": {"a": {"nextDueAt": "2026-11-01T13:00:00"}}})
    )
    st = StateStore(tmp_path).get("a")
    assert st.next_due_at is not None and st.next_due_at.tzinfo is not None
    assert st.next_due_at > NOW


def test_two_concurrent_ticks(make_config: Callable[..., MonitorConfig]) -> None:
    cfg = make_config("lock_timeout: 1s\n")
    holder = StateStore(cfg.state_dir)
    holder.acquire()
    try:
        with pytest.raises(StateLockedError):
            tick(cfg, now=NOW)
    finally:
        holder.release()
    report = tick(cfg, now=NOW)
    assert [r.agent for r in report.records] == ["triage-agent"]


def test_history_append_and_read(tmp_path: Path) -> None:
    store = StateStore(tmp_path)
    for i in range(5):
        store.append_history("my agent/../x", {"i": i})
    path = store.history_path("my agent/../x")
    assert path.parent.parent == tmp_path / "agents"  # the slug cannot escape the state directory
    with path.open("a") as fh:
        fh.write("garbage\n")
    assert [r["i"] for r in store.read_history("my agent/../x", limit=3)] == [3, 4]
    assert store.read_history("nobody") == []
