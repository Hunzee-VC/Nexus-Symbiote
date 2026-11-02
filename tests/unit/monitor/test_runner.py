"""Monitoring cycles end to end on a temporary copy of examples/triage-agent (spec/monitoring.md §2)."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import symbiote.advisories as advisories
from symbiote.advisories.types import DependencyIntel, DependencyRef, ReleaseInfo, Signal, SignalKind
from symbiote.export.companion import companion_bytes
from symbiote.monitor import MonitorConfig, RiskTier, StateStore, plan, run_cycle, tick
from symbiote.monitor import runner as runner_mod

from .conftest import NOW


def _edit_mcp(agent_dir: Path) -> None:
    p = agent_dir / ".mcp.json"
    p.write_text(p.read_text().replace("triage-mcp-tools==1.4.2", "triage-mcp-tools==1.5.0"))


def test_full_cycle_produces_findings(make_config: Callable[..., MonitorConfig]) -> None:
    cfg = make_config()
    store = StateStore(cfg.state_dir)
    record = run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW)
    assert record.status == "findings"
    assert record.errors == []
    assert record.snapshot is not None and record.snapshot["serial"] == 1
    assert record.new_findings and record.failing == len({f["fingerprint"] for f in record.new_findings})
    assert any(f["check"] == "SYM-MCP-002" and f["severity"] == "high" for f in record.new_findings)
    assert record.steps["drift"] == "not-attempted"  # first cycle
    assert record.steps["dependencies"] == "not-attempted"  # advisories: false
    assert record.dependency_coverage == "not-attempted"
    checks = {v["check"]: v["status"] for v in record.verification}
    assert checks == {
        "chain": "pass",
        "SYM-SNAP-002": "pass",
        "SYM-TOOL-002": "not-attempted",
        "attestation": "not-attempted",
    }
    # A production agent with a failing high finding is `high`; the first cycle sets the baseline, no escalation.
    assert (record.tier, record.escalated) == ("high", False)
    due = datetime.fromisoformat(record.next_due_at or "")
    assert NOW + timedelta(hours=1) <= due < NOW + timedelta(hours=1, minutes=6)
    assert record.exit_code() == 1
    # Persisted: state, history, previous companion.
    st = store.get("triage-agent")
    assert st.last_status == "findings" and st.tier is RiskTier.HIGH and len(st.findings) == record.failing
    history = store.read_history("triage-agent")
    assert history[-1]["status"] == "findings" and history[-1]["agent"] == "triage-agent"
    assert store.previous_companion_path("triage-agent").exists()
    json.dumps(record.to_json())


def test_unchanged_second_cycle_is_quiet(make_config: Callable[..., MonitorConfig]) -> None:
    cfg = make_config()
    store = StateStore(cfg.state_dir)
    run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW)
    second = run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW + timedelta(hours=2))
    assert second.status == "ok" and second.exit_code() == 0
    assert second.new_findings == [] and second.resolved_findings == [] and second.drift == []
    assert second.snapshot is not None and second.snapshot["serial"] == 2
    assert second.steps["drift"] == "ok"
    assert second.clean_streak == 2


def test_drift_between_cycles_escalates(make_config: Callable[..., MonitorConfig], agent_dir: Path) -> None:
    cfg = make_config()
    store = StateStore(cfg.state_dir)
    run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW)
    _edit_mcp(agent_dir)
    rec = run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW + timedelta(hours=2))
    events = [(d["against"], d["type"], d["subject"]) for d in rec.drift]
    assert ("previous", "server-identity-changed", "server:claude-code-triage-tools") in events
    assert rec.status == "findings" and rec.exit_code() == 1
    assert (rec.escalated, rec.escalation, rec.tier, rec.base_tier) == (True, "escalated", "critical", "high")
    assert any(r.startswith("drift: server-identity-changed") for r in rec.escalation_reasons)
    due = datetime.fromisoformat(rec.next_due_at or "")
    assert due - (NOW + timedelta(hours=2)) < timedelta(minutes=11)  # critical cadence
    # Three clean cycles de-escalate.
    t = NOW + timedelta(hours=3)
    changes = []
    for _ in range(3):
        r = run_cycle(cfg.agents[0], config=cfg, state=store, now=t)
        changes.append((r.escalated, r.escalation))
        t += timedelta(minutes=15)
    assert changes == [(True, None), (True, None), (False, "deescalated")]
    assert store.get("triage-agent").escalated is False


def test_baseline_drift_and_served_vs_approved(
    make_config: Callable[..., MonitorConfig], agent_dir: Path, tmp_path: Path
) -> None:
    from symbiote.scan import scan

    approved = tmp_path / "approved.agentbom.json"
    approved.write_bytes(companion_bytes(scan(agent_dir, now=NOW, deterministic=True).bom))
    _edit_mcp(agent_dir)
    cfg = make_config(agent_extra=f"    baseline: {approved}\n")
    rec = run_cycle(cfg.agents[0], config=cfg, state=StateStore(cfg.state_dir), now=NOW)
    assert any(d["against"] == "baseline" and d["type"] == "server-identity-changed" for d in rec.drift)
    served = [v for v in rec.verification if v["check"] == "SYM-TOOL-002"]
    assert served and all(v["status"] in ("pass", "fail", "not-attempted") for v in served)
    assert rec.steps["baseline"] == "ok"


def test_missing_baseline_is_an_error_not_clean(make_config: Callable[..., MonitorConfig]) -> None:
    cfg = make_config(agent_extra="    baseline: approved/missing.agentbom.json\n")
    rec = run_cycle(cfg.agents[0], config=cfg, state=StateStore(cfg.state_dir), now=NOW)
    assert rec.status == "error"
    assert any("baseline" in e for e in rec.errors)
    assert {
        "check": "SYM-TOOL-002",
        "status": "error",
        "severity": "high",
        "message": "baseline unreadable",
    } in rec.verification


def test_error_backoff(make_config: Callable[..., MonitorConfig], agent_dir: Path) -> None:
    cfg = make_config()
    store = StateStore(cfg.state_dir)
    run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW)
    known = store.get("triage-agent").findings
    shutil.rmtree(agent_dir)
    t = NOW + timedelta(hours=2)
    delays = []
    for _ in range(4):
        rec = run_cycle(cfg.agents[0], config=cfg, state=store, now=t)
        assert rec.status == "error" and rec.exit_code() == 6
        assert rec.resolved_findings == []  # an error never resolves anything
        delays.append(datetime.fromisoformat(rec.next_due_at or "") - t)
    assert delays == [timedelta(minutes=m) for m in (1, 2, 4, 8)]
    st = store.get("triage-agent")
    assert st.consecutive_errors == 4 and st.last_status == "error" and st.findings == known
    # The cap is the tier interval.
    for _ in range(10):
        rec = run_cycle(cfg.agents[0], config=cfg, state=store, now=t)
    assert datetime.fromisoformat(rec.next_due_at or "") - t == timedelta(hours=1)


def _fake_check(signals: Sequence[Signal], coverage: str = "queried") -> Callable[..., list[DependencyIntel]]:
    def check(
        refs: Sequence[DependencyRef], *, client: Any, now: datetime, policy: Any = None
    ) -> list[DependencyIntel]:
        assert client.cache_dir is not None  # cached under state_dir
        out = []
        for ref in refs:
            intel = DependencyIntel(ref=ref, checked_at=now, coverage=coverage)  # type: ignore[arg-type]
            if ref.name == "triage-mcp-tools":
                intel.current = ReleaseInfo(version="1.4.2")
                intel.signals = list(signals)
            out.append(intel)
        return out

    return check


def test_vulnerable_dependency_escalates(
    make_config: Callable[..., MonitorConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    signal = Signal(
        kind=SignalKind.VULNERABLE, severity="high", detail="GHSA-xxxx affects 1.4.2", reference="GHSA-xxxx"
    )
    monkeypatch.setattr(advisories, "check_dependencies", _fake_check([signal]))
    cfg = make_config(advisories=True)
    rec = run_cycle(cfg.agents[0], config=cfg, state=StateStore(cfg.state_dir), now=NOW)
    assert rec.dependency_coverage == "queried"
    dep = next(d for d in rec.dependencies if d["name"] == "triage-mcp-tools")
    assert dep["signals"][0]["kind"] == "vulnerable"
    assert rec.escalated and "vulnerable dependency triage-mcp-tools" in rec.escalation_reasons
    assert rec.exit_code() == 1


def test_unreachable_advisories_are_not_clean(
    make_config: Callable[..., MonitorConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(advisories, "check_dependencies", _fake_check([], coverage="unreachable"))
    cfg = make_config(advisories=True)
    rec = run_cycle(cfg.agents[0], config=cfg, state=StateStore(cfg.state_dir), now=NOW)
    assert rec.dependency_coverage == "unreachable"

    def boom(*_a: Any, **_k: Any) -> list[DependencyIntel]:
        raise OSError("network down")

    monkeypatch.setattr(advisories, "check_dependencies", boom)
    rec = run_cycle(cfg.agents[0], config=cfg, state=StateStore(cfg.state_dir), now=NOW + timedelta(hours=2))
    assert rec.dependency_coverage == "unreachable" and rec.status == "error"


def test_tick_runs_only_due_agents(make_config: Callable[..., MonitorConfig]) -> None:
    cfg = make_config()
    first = tick(cfg, now=NOW)
    assert [r.agent for r in first.records] == ["triage-agent"] and first.exit_code == 1
    assert first.next_wake_at is not None
    soon = tick(cfg, now=NOW + timedelta(minutes=5))
    assert soon.records == [] and "triage-agent" in soon.not_due and soon.exit_code == 0
    later = tick(cfg, now=datetime.fromisoformat(first.next_wake_at))
    assert [r.agent for r in later.records] == ["triage-agent"] and later.exit_code == 0
    rows = plan(cfg, now=NOW + timedelta(minutes=5))
    assert rows[0]["tier"] == "high" and rows[0]["due"] is False


def test_budget_exhaustion_is_an_error(
    make_config: Callable[..., MonitorConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = make_config()

    class Expired(runner_mod._Clock):
        def remaining(self) -> float:
            return -1.0

    monkeypatch.setattr(runner_mod, "_Clock", Expired)
    rec = run_cycle(cfg.agents[0], config=cfg, state=StateStore(cfg.state_dir), now=NOW)
    assert rec.status == "error" and any("budget" in e for e in rec.errors)


def test_run_forever_stops(make_config: Callable[..., MonitorConfig]) -> None:
    import threading

    from symbiote.monitor import run_forever

    cfg = make_config()
    stop = threading.Event()
    reports: list[Any] = []

    def on_tick(report: Any) -> None:
        reports.append(report)
        stop.set()

    run_forever(cfg, stop=stop, on_tick=on_tick)
    assert len(reports) == 1 and reports[0].records[0].agent == "triage-agent"


def test_critical_finding_tier(make_config: Callable[..., MonitorConfig], agent_dir: Path) -> None:
    """With the example's unsafe model present, a production agent is critical (10 minute cadence)."""
    shutil.copytree(
        Path(__file__).resolve().parents[3] / "examples" / "triage-agent" / "models", agent_dir / "models"
    )
    cfg = make_config()
    record = run_cycle(cfg.agents[0], config=cfg, state=StateStore(cfg.state_dir), now=NOW)
    assert any(f["check"] == "SYM-MODEL-002" and f["severity"] == "critical" for f in record.new_findings)
    assert record.tier == "critical"
    due = datetime.fromisoformat(record.next_due_at or "")
    assert NOW + timedelta(minutes=10) <= due < NOW + timedelta(minutes=11)
