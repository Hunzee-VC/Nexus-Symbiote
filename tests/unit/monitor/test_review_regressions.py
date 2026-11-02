"""Regressions for the adversarial review of the monitor (incomplete cycles, attestation, baselines, scheduling)."""

from __future__ import annotations

import json
import os
import shutil
import threading
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import symbiote.advisories as advisories
from symbiote.advisories.types import DependencyIntel, DependencyRef
from symbiote.export.companion import companion_bytes
from symbiote.model.enums import SignatureOutcome
from symbiote.monitor import (
    ConfigError,
    MonitorConfig,
    StateStore,
    load_config,
    plan,
    run_cycle,
    run_forever,
    tick,
)

from .conftest import NOW, TRIAGE
from .test_cli import _app

REPO = Path(__file__).resolve().parents[3]


def _fake_check(coverage: str, errors: Sequence[str] = ()) -> Callable[..., list[DependencyIntel]]:
    def check(
        refs: Sequence[DependencyRef], *, client: Any, now: datetime, policy: Any = None
    ) -> list[DependencyIntel]:
        out = []
        for ref in refs:
            intel = DependencyIntel(ref=ref, checked_at=now, coverage=coverage)  # type: ignore[arg-type]
            intel.errors = list(errors)
            out.append(intel)
        return out

    return check


def _edit_mcp(agent_dir: Path) -> None:
    p = agent_dir / ".mcp.json"
    p.write_text(p.read_text().replace("triage-mcp-tools==1.4.2", "triage-mcp-tools==1.5.0"))


# ------------------------------------------------------------------ finding 1: unreachable advisories


def test_unreachable_dependencies_make_the_cycle_incomplete_and_never_deescalate(
    make_config: Callable[..., MonitorConfig], agent_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(advisories, "check_dependencies", _fake_check("queried"))
    cfg = make_config(advisories=True)
    store = StateStore(cfg.state_dir)
    run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW)
    _edit_mcp(agent_dir)
    rec = run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW + timedelta(hours=1))
    assert rec.escalated
    monkeypatch.setattr(
        advisories, "check_dependencies", _fake_check("unreachable", ["registry lookup failed"])
    )
    t = NOW + timedelta(hours=2)
    for _ in range(5):
        rec = run_cycle(cfg.agents[0], config=cfg, state=store, now=t)
        assert rec.dependency_coverage == "unreachable"
        assert rec.status == "incomplete" and rec.exit_code() == 6
        assert rec.incomplete and rec.incomplete[0].startswith("dependencies:")
        assert rec.escalated and rec.escalation is None and rec.clean_streak == 0
        assert rec.consecutive_errors == 0  # not an error: no backoff
        t += timedelta(minutes=15)
    assert store.get("triage-agent").escalated


def test_structural_partial_and_no_advisor_are_not_incomplete(
    make_config: Callable[..., MonitorConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = make_config(advisories=True)
    store = StateStore(cfg.state_dir)
    run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW)
    monkeypatch.setattr(
        advisories, "check_dependencies", _fake_check("not-attempted", ["no advisor for OCI images yet"])
    )
    rec = run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW + timedelta(hours=2))
    assert rec.dependency_coverage == "not-attempted" and rec.status == "ok" and rec.incomplete == []
    monkeypatch.setattr(
        advisories,
        "check_dependencies",
        _fake_check("partial", ["no vulnerability advisor for nuget packages"]),
    )
    rec = run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW + timedelta(hours=4))
    assert rec.dependency_coverage == "partial" and rec.status == "ok"
    monkeypatch.setattr(
        advisories, "check_dependencies", _fake_check("partial", ["OSV lookup for 1.4.2 failed: timeout"])
    )
    rec = run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW + timedelta(hours=6))
    assert rec.status == "incomplete" and rec.exit_code() == 6


# ------------------------------------------------------------------ findings 2 and 4: attestation, baselines


def _approve(agent_dir: Path, tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    from symbiote.scan import scan

    approved = tmp_path / "approved.agentbom.json"
    data = companion_bytes(scan(agent_dir, now=NOW, deterministic=True).bom)
    approved.write_bytes(data)
    return approved, json.loads(data)


def test_attestation_without_sigstore_is_incomplete(
    make_config: Callable[..., MonitorConfig],
    agent_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from symbiote.attest import sigstore_backend as sb

    monkeypatch.setattr(sb, "HAVE_SIGSTORE", False)
    approved, _ = _approve(agent_dir, tmp_path)
    cfg = make_config(
        agent_extra=f"    baseline: {approved}\n    attestation: {{bundle: b.json, policy: p.yaml}}\n"
    )
    store = StateStore(cfg.state_dir)
    run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW)
    rec = run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW + timedelta(hours=2))
    att = next(v for v in rec.verification if v["check"] == "attestation")
    assert att["status"] == "not-attempted"
    assert rec.status == "incomplete" and rec.exit_code() == 6 and rec.clean_streak == 0


def test_attestation_with_missing_policy_is_incomplete(
    make_config: Callable[..., MonitorConfig],
    agent_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from symbiote.attest import sigstore_backend as sb

    monkeypatch.setattr(sb, "HAVE_SIGSTORE", True)
    approved, _ = _approve(agent_dir, tmp_path)
    cfg = make_config(
        agent_extra=f"    baseline: {approved}\n    attestation: {{bundle: missing.json, policy: missing.yaml}}\n"
    )
    store = StateStore(cfg.state_dir)
    run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW)
    rec = run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW + timedelta(hours=2))
    att = next(v for v in rec.verification if v["check"] == "attestation")
    assert att["status"] == "error"
    assert rec.status == "incomplete" and rec.exit_code() == 6 and rec.clean_streak == 0


def _fake_verify(digest: str, outcome: SignatureOutcome, seen: list[Any]) -> Callable[..., Any]:
    from symbiote.attest import sigstore_backend as sb

    def verify(bundle: Any, spec: Any, *, expected_predicate_types: Any = ()) -> Any:
        seen.append(tuple(expected_predicate_types))
        stmt = {"subject": [{"name": "snapshot", "digest": {"sha256": digest.split(":", 1)[-1]}}]}
        return sb.SigstoreVerification(
            outcome=outcome, payload=json.dumps(stmt).encode(), identity="release@example.com"
        )

    return verify


@pytest.mark.parametrize(
    ("outcome", "status", "cycle"),
    [
        (SignatureOutcome.VERIFIED, "pass", "ok"),
        (SignatureOutcome.SIGNATURE_VALID_UNCONSTRAINED, "unconstrained", "incomplete"),
    ],
)
def test_attestation_binding(
    make_config: Callable[..., MonitorConfig],
    agent_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: SignatureOutcome,
    status: str,
    cycle: str,
) -> None:
    from symbiote.attest import sigstore_backend as sb
    from symbiote.attest.statements import predicate_type

    approved, data = _approve(agent_dir, tmp_path)
    (tmp_path / "p.yaml").write_text("identities: []\n")
    seen: list[Any] = []
    monkeypatch.setattr(sb, "HAVE_SIGSTORE", True)
    monkeypatch.setattr(sb, "verify_bundle", _fake_verify(data["snapshot"]["digest"], outcome, seen))
    cfg = make_config(
        agent_extra=f"    baseline: {approved}\n    attestation: {{bundle: b.json, policy: p.yaml}}\n"
    )
    store = StateStore(cfg.state_dir)
    run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW)
    rec = run_cycle(cfg.agents[0], config=cfg, state=store, now=NOW + timedelta(hours=2))
    att = next(v for v in rec.verification if v["check"] == "attestation")
    assert att["status"] == status
    assert seen[-1] == (predicate_type("agentbom-snapshot"),)
    assert rec.status == cycle


def test_tampered_baseline_fails_verification(
    make_config: Callable[..., MonitorConfig],
    agent_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from symbiote.attest import sigstore_backend as sb

    approved, data = _approve(agent_dir, tmp_path)
    original_digest = data["snapshot"]["digest"]
    data["toolServers"][0]["name"] = "renamed-after-approval"  # snapshot.digest left as it was
    approved.write_text(json.dumps(data))
    (tmp_path / "p.yaml").write_text("identities: []\n")
    monkeypatch.setattr(sb, "HAVE_SIGSTORE", True)
    monkeypatch.setattr(sb, "verify_bundle", _fake_verify(original_digest, SignatureOutcome.VERIFIED, []))
    cfg = make_config(
        agent_extra=f"    baseline: {approved}\n    attestation: {{bundle: b.json, policy: p.yaml}}\n"
    )
    rec = run_cycle(cfg.agents[0], config=cfg, state=StateStore(cfg.state_dir), now=NOW)
    checks = {v["check"]: v for v in rec.verification}
    assert checks["baseline-commitment"]["status"] == "fail"
    assert checks["baseline-commitment"]["severity"] == "critical"
    assert checks["attestation"]["status"] != "pass"
    assert checks["SYM-TOOL-002"]["status"] == "error"
    assert not any(d["against"] == "baseline" for d in rec.drift)  # the tampered file drives nothing
    assert rec.steps["baseline"] == "fail"
    assert rec.exceeds_fail_on and rec.exit_code() == 1
    assert "verification failed: baseline-commitment" in rec.escalation_reasons


# ------------------------------------------------------------------ finding 3: SYM-TOOL-002 without served tools


def test_served_vs_approved_without_served_tools_is_not_a_pass(
    make_config: Callable[..., MonitorConfig], agent_dir: Path, tmp_path: Path
) -> None:
    approved, _ = _approve(agent_dir, tmp_path)
    cfg = make_config(agent_extra=f"    baseline: {approved}\n")
    rec = run_cycle(cfg.agents[0], config=cfg, state=StateStore(cfg.state_dir), now=NOW)
    served = [v for v in rec.verification if v["check"] == "SYM-TOOL-002"]
    assert served == [
        {
            "check": "SYM-TOOL-002",
            "status": "not-attempted",
            "severity": "high",
            "message": "no served tools observed (live collection not enabled)",
        }
    ]


# ------------------------------------------------------------------ finding 5: one chain per target


def test_targets_with_the_same_agent_identity_have_separate_chains(tmp_path: Path) -> None:
    for name in ("prod", "staging"):
        shutil.copytree(TRIAGE, tmp_path / name)
    conf = tmp_path / "m.yaml"
    conf.write_text(
        "state_dir: state\nadvisories: false\nconcurrency: 4\nagents:\n"
        "  - {name: triage-prod, path: prod, environment: production, risk: critical}\n"
        "  - {name: triage-staging, path: staging, environment: production, risk: critical}\n"
    )
    cfg = load_config(conf)
    serials: dict[str, list[int]] = {"triage-prod": [], "triage-staging": []}
    t = NOW
    for _ in range(4):
        report = tick(cfg, now=t)
        assert {r.agent for r in report.records} == set(serials)
        for r in report.records:
            assert not r.chain_conflict and r.exit_code() != 7, r.errors
            assert r.snapshot is not None
            serials[r.agent].append(r.snapshot["serial"])
        t += timedelta(hours=1)
    assert serials == {"triage-prod": [1, 2, 3, 4], "triage-staging": [1, 2, 3, 4]}


# ------------------------------------------------------------------ finding 6: rescheduling on config change


def test_config_change_reschedules_an_agent(tmp_path: Path, agent_dir: Path) -> None:
    conf = tmp_path / "m.yaml"
    head = "state_dir: state\nadvisories: false\nagents:\n  - name: triage-agent\n    path: agents/triage-agent\n"
    conf.write_text(head + "    environment: development\n    interval: 2w\n")
    first = tick(load_config(conf), now=NOW)
    assert [r.agent for r in first.records] == ["triage-agent"]
    conf.write_text(head + "    environment: development\n    risk: critical\n")
    cfg = load_config(conf)
    rows = plan(cfg, now=NOW + timedelta(minutes=15))
    assert rows[0]["tier"] == "critical" and rows[0]["interval"] == "0:10:00" and rows[0]["due"] is True
    later = tick(cfg, now=NOW + timedelta(minutes=15))
    assert [r.agent for r in later.records] == ["triage-agent"]
    assert later.records[0].tier == "critical"


# ------------------------------------------------------------------ finding 7: unknown collectors


def test_unknown_collector_is_a_config_error(make_config: Callable[..., MonitorConfig]) -> None:
    with pytest.raises(ConfigError, match="unknown or unavailable collector"):
        make_config(agent_extra="    collectors: [mcp_config]\n")
    cfg = make_config(agent_extra="    collectors: [mcp-config]\n")
    assert cfg.agents[0].collectors == ("mcp-config",)


# ------------------------------------------------------------------ finding 8: naive datetimes


def test_naive_now_and_naive_state(make_config: Callable[..., MonitorConfig]) -> None:
    cfg = make_config()
    naive = NOW.replace(tzinfo=None)
    report = tick(cfg, now=naive)
    assert [r.agent for r in report.records] == ["triage-agent"]
    assert plan(cfg, now=naive + timedelta(minutes=5))[0]["due"] is False
    state = cfg.state_dir / "state.json"
    data = json.loads(state.read_text())
    data["agents"]["triage-agent"]["nextDueAt"] = "2026-11-01T13:00:00"
    state.write_text(json.dumps(data))
    app = _app()

    result = CliRunner().invoke(app, ["monitor", "tick", "--config", str(cfg.config_path), "--json"])
    assert result.exit_code == 0, result.output


def test_unexpected_exception_in_tick_exits_6(
    make_config: Callable[..., MonitorConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    import symbiote.monitor.runner as runner_mod

    app = _app()

    def boom(*_a: Any, **_k: Any) -> Any:
        raise TypeError("internal defect")

    monkeypatch.setattr(runner_mod, "tick", boom)
    cfg = make_config()
    result = CliRunner().invoke(app, ["monitor", "tick", "--config", str(cfg.config_path)])
    assert result.exit_code == 6


# ------------------------------------------------------------------ findings 10, 11, 12: examples, init, clock


def test_crontab_exports_the_environment_file() -> None:
    line = next(
        ln
        for ln in (REPO / "examples" / "monitor" / "crontab.txt").read_text().splitlines()
        if ln and not ln.startswith("#")
    )
    assert "set -a && . /etc/symbiote/monitor.env && set +a" in line


@pytest.mark.parametrize(
    ("args", "name", "path_tail", "environment"),
    [
        (["--path", "null"], "null", "null", "development"),
        (["--path", "agents/x", "--name", "123"], "123", "x", "development"),
        (["--path", "agents/x", "--environment", "yes"], "x", "x", "yes"),
        (["--path", "on"], "on", "on", "development"),
    ],
)
def test_init_quotes_yaml_scalars(
    tmp_path: Path, args: list[str], name: str, path_tail: str, environment: str
) -> None:
    app = _app()

    target = tmp_path / "symbiote-monitor.yaml"
    result = CliRunner().invoke(app, ["monitor", "init", "--config", str(target), *args])
    assert result.exit_code == 0, result.output
    cfg = load_config(target)
    agent = cfg.agents[0]
    assert (agent.name, agent.path.name, agent.environment) == (name, path_tail, environment)


def test_init_never_leaves_an_invalid_file(tmp_path: Path) -> None:
    app = _app()

    target = tmp_path / "symbiote-monitor.yaml"
    result = CliRunner().invoke(app, ["monitor", "init", "--config", str(target), "--name", "a" * 200])
    assert result.exit_code == 2
    assert not target.exists()
    assert [p.name for p in tmp_path.iterdir()] == []


def test_run_forever_clock_drives_the_tick(make_config: Callable[..., MonitorConfig]) -> None:
    cfg = make_config()
    fixed = datetime(2030, 1, 1, 9, 0, tzinfo=UTC)
    stop = threading.Event()
    reports: list[Any] = []

    def on_tick(report: Any) -> None:
        reports.append(report)
        stop.set()

    run_forever(cfg, stop=stop, on_tick=on_tick, clock=lambda: fixed)
    assert reports[0].started_at == fixed.isoformat()
    assert reports[0].records[0].started_at == fixed.isoformat()


def test_lock_file_mode(make_config: Callable[..., MonitorConfig]) -> None:
    cfg = make_config()
    store = StateStore(cfg.state_dir)
    with store.locked():
        assert os.stat(store.lock_path).st_mode & 0o077 == 0
