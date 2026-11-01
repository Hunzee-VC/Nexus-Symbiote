from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from symbiote.cli import app

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "triage-agent"
pytestmark = pytest.mark.skipif(not EXAMPLE.exists(), reason="example fixture missing")


def _scan(tmp_path: Path, runner: CliRunner, *extra: str) -> dict:
    r = runner.invoke(app, ["scan", str(EXAMPLE), "-o", str(tmp_path), "--deterministic", "--json", *extra])
    assert r.exit_code == 0, r.output
    return json.loads(r.stdout)


def test_scan_runs_policy_and_populates_derived(tmp_path: Path) -> None:
    runner = CliRunner()
    summary = _scan(tmp_path, runner)
    assert summary["findings"] is not None
    bom = json.loads((tmp_path / "agentbom.json").read_text())
    assert bom["derived"]["flags"], "flags must be computed during scan"
    # a floating npx launcher in the example must surface as an unpinned-tool flag or SYM-MCP-002 finding
    text = json.dumps(bom["derived"])
    assert "unpinned-tool" in text or "SYM-MCP-002" in text


def test_policy_check_conformance_score(tmp_path: Path) -> None:
    runner = CliRunner()
    _scan(tmp_path, runner)
    companion = tmp_path / "agentbom.json"
    r = runner.invoke(
        app,
        [
            "policy",
            "check",
            str(companion),
            "--json",
            "--sarif",
            str(tmp_path / "out.sarif"),
            "--fail-on",
            "critical",
        ],
    )
    data = json.loads(r.stdout)
    assert data["checksRun"] and (tmp_path / "out.sarif").exists()
    sarif = json.loads((tmp_path / "out.sarif").read_text())
    assert sarif["version"] == "2.1.0"
    r = runner.invoke(app, ["policy", "list", "--json"])
    assert r.exit_code == 0 and any(row["id"].startswith("SYM-") for row in json.loads(r.stdout))
    r = runner.invoke(app, ["conformance", str(companion), "--level", "minimal", "--json"])
    report = json.loads(r.stdout)
    assert report["requested"] == "minimal" and report["requirements"]
    assert r.exit_code in (0, 1, 5)
    r = runner.invoke(app, ["score", str(companion), "--json"])
    assert r.exit_code == 0 and 0 <= json.loads(r.stdout)["score"] <= 100


def test_diff_and_chain_store(tmp_path: Path) -> None:
    runner = CliRunner()
    store = tmp_path / "store"
    a = tmp_path / "a"
    b = tmp_path / "b"
    s1 = _scan(a, runner, "--store", str(store))
    s2 = _scan(b, runner, "--store", str(store))
    assert s1["serial"] == 1 and s2["serial"] == 2
    bom_b = json.loads((b / "agentbom.json").read_text())
    assert bom_b["snapshot"]["prev"] == s1["snapshot"]
    r = runner.invoke(app, ["diff", str(a / "agentbom.json"), str(b / "agentbom.json"), "--json"])
    assert r.exit_code == 0, r.output
    delta = json.loads(r.stdout)
    assert delta["fromSnapshot"] == s1["snapshot"] and delta["toSnapshot"] == s2["snapshot"]
    # changing a tool server in b and diffing must produce an event
    mutated = json.loads((b / "agentbom.json").read_text())
    mutated["toolServers"] = mutated["toolServers"][:-1]
    removed_id = bom_b["toolServers"][-1]["id"]
    mutated["edges"] = [e for e in mutated["edges"] if removed_id not in (e["from"], e["to"])]
    (tmp_path / "mutated.json").write_text(json.dumps(mutated))
    r = runner.invoke(
        app,
        [
            "diff",
            str(b / "agentbom.json"),
            str(tmp_path / "mutated.json"),
            "--json",
            "--fail-on-change",
            "server-removed",
        ],
    )
    assert r.exit_code == 1, r.output
    assert any(e["type"] == "server-removed" for e in json.loads(r.stdout)["events"])
