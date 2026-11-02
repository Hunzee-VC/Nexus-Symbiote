"""``symbiote monitor`` commands and exit codes (spec/monitoring.md §6)."""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from symbiote.cli.monitor_cmd import register
from symbiote.monitor import MonitorConfig, StateStore


def _app() -> typer.Typer:
    app = typer.Typer()

    @app.callback()
    def main() -> None:
        pass

    register(app)
    return app


def _invoke(*args: str) -> tuple[int, str]:
    result = CliRunner().invoke(_app(), list(args))
    return result.exit_code, result.stdout


def test_tick_plan_status(make_config: Callable[..., MonitorConfig], agent_dir: Path) -> None:
    cfg = make_config()
    assert cfg.config_path is not None
    conf = str(cfg.config_path)
    code, out = _invoke("monitor", "plan", "--config", conf, "--json")
    assert code == 0 and json.loads(out)["agents"][0]["due"] is True
    code, out = _invoke("monitor", "status", "--config", conf, "--json")
    assert code == 0 and json.loads(out)["agents"][0]["lastStatus"] is None

    code, out = _invoke("monitor", "tick", "--config", conf, "--json")
    report = json.loads(out)
    assert code == 1 and report["exitCode"] == 1 and report["ran"] == ["triage-agent"]
    assert report["records"][0]["status"] == "findings"

    code, out = _invoke("monitor", "tick", "--config", conf, "--json")  # nothing due
    assert code == 0 and json.loads(out)["ran"] == []

    code, out = _invoke("monitor", "status", "--config", conf, "--json")
    row = json.loads(out)["agents"][0]
    assert (
        code == 0 and row["lastStatus"] == "findings" and row["tier"] == "high" and row["failingFindings"] > 0
    )
    code, out = _invoke("monitor", "plan", "--config", conf, "--json")
    assert code == 0 and json.loads(out)["agents"][0]["due"] is False

    # A cycle that cannot run exits 6.
    shutil.rmtree(agent_dir)
    state = StateStore(cfg.state_dir)
    st = state.get("triage-agent")
    st.next_due_at = None
    state.put(st)
    code, out = _invoke("monitor", "tick", "--config", conf, "--json")
    assert code == 6 and json.loads(out)["records"][0]["status"] == "error"


def test_lock_busy_exits_6(make_config: Callable[..., MonitorConfig]) -> None:
    cfg = make_config("lock_timeout: 1s\n")
    holder = StateStore(cfg.state_dir)
    holder.acquire()
    try:
        code, _ = _invoke("monitor", "tick", "--config", str(cfg.config_path))
    finally:
        holder.release()
    assert code == 6


def test_chain_conflict_exits_7(
    make_config: Callable[..., MonitorConfig], monkeypatch: pytest.MonkeyPatch
) -> None:
    import symbiote.scan
    from symbiote.model.enums import Severity
    from symbiote.snapshot import ChainConflictError, ChainIssue

    def conflicting(*_a: Any, **_k: Any) -> Any:
        issue = ChainIssue(
            "SYM-SNAP-001", Severity.CRITICAL, "serial 1 is a regression below head 5", "snap:1"
        )
        raise ChainConflictError([issue])

    monkeypatch.setattr(symbiote.scan, "scan", conflicting)
    cfg = make_config()
    code, out = _invoke("monitor", "tick", "--config", str(cfg.config_path), "--json")
    rec = json.loads(out)["records"][0]
    assert code == 7 and rec["chainConflict"] is True and rec["status"] == "error"
    assert any(v["check"] == "SYM-SNAP-001" and v["status"] == "fail" for v in rec["verification"])
    assert rec["escalated"] is True  # a verification failure escalates


def test_bad_config_exits_2(tmp_path: Path) -> None:
    bad = tmp_path / "m.yaml"
    bad.write_text("agents: [{name: a, path: ., interval: 30s}]\n")
    assert _invoke("monitor", "tick", "--config", str(bad))[0] == 2
    assert _invoke("monitor", "plan", "--config", str(tmp_path / "missing.yaml"))[0] == 2


def test_init(tmp_path: Path) -> None:
    target = tmp_path / "symbiote-monitor.yaml"
    code, _ = _invoke(
        "monitor", "init", "--config", str(target), "--path", "agents/x", "--environment", "staging"
    )
    assert code == 0
    text = target.read_text()
    assert "url_env: SYMBIOTE_WEBHOOK_URL" in text and 'name: "x"' in text
    assert _invoke("monitor", "init", "--config", str(target))[0] == 2  # refuses to overwrite
    assert os.path.getsize(target) == len(text.encode())
