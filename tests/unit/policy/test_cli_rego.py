"""CLI: ``policy export-rego``, ``policy check --rego`` and the stable exit codes for bad inputs (spec/cli.md)."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from symbiote.cli import exit_codes
from symbiote.cli.app import app
from symbiote.export.companion import companion_bytes
from symbiote.model.document import AgentBOM
from symbiote.policy import REGO_RULES, run_policy
from symbiote.policy import rego as rego_module

runner = CliRunner()


@pytest.fixture
def companion(risky_bom: AgentBOM, tmp_path: Path) -> Path:
    path = tmp_path / "agentbom.json"
    path.write_bytes(companion_bytes(risky_bom))
    return path


def _fake_opa(tmp_path: Path, payload: object) -> Path:
    """A stand-in ``opa`` that prints a fixed evaluation result (the real binary is exercised in test_rego.py)."""
    (tmp_path / "payload.json").write_text(json.dumps(payload), encoding="utf-8")
    fake = tmp_path / "opa"
    fake.write_text(f"#!/bin/sh\ncat '{tmp_path / 'payload.json'}'\n", encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    return fake


def test_export_rego(tmp_path: Path) -> None:
    r = runner.invoke(app, ["policy", "export-rego", str(tmp_path / "rego"), "--json"])
    assert r.exit_code == exit_codes.OK, r.output
    manifest = json.loads(r.stdout)
    assert manifest["rego"] == sorted(REGO_RULES)
    assert (tmp_path / "rego" / "agentbom.rego").is_file()
    assert (tmp_path / "rego" / "manifest.json").is_file()


def test_list_marks_rego_checks() -> None:
    rows = json.loads(runner.invoke(app, ["policy", "list", "--json"]).stdout)
    assert {r["id"] for r in rows if r["rego"]} == set(REGO_RULES)


def test_rego_without_opa_is_an_io_error(
    companion: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rego_module.shutil, "which", lambda _name: None)
    r = runner.invoke(app, ["policy", "check", str(companion), "--rego", str(tmp_path)])
    assert r.exit_code == exit_codes.IO


def test_rego_findings_merge_without_duplicates(
    companion: Path, risky_bom: AgentBOM, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builtin = run_policy(risky_bom).findings
    dup = next(f for f in builtin if f.check_id == "SYM-MCP-002")
    payload = {
        "result": [
            {
                "expressions": [
                    {
                        "value": [
                            {
                                "checkId": "ORG-001",
                                "severity": "critical",
                                "subjectRefs": [risky_bom.subject],
                                "message": "Org rule: no agent may reach production databases.",
                            },
                            {
                                "checkId": dup.check_id,
                                "severity": dup.severity.value,
                                "subjectRefs": list(reversed(dup.subject_refs)),
                                "message": "same finding from the exported Rego",
                            },
                            {"checkId": "ORG-002", "severity": "apocalyptic", "subjectRefs": []},
                        ]
                    }
                ]
            }
        ]
    }
    fake = _fake_opa(tmp_path, payload)
    monkeypatch.setattr(rego_module.shutil, "which", lambda _name: str(fake))
    policies = tmp_path / "policies"
    policies.mkdir()
    r = runner.invoke(app, ["policy", "check", str(companion), "--rego", str(policies), "--json"])
    assert r.exit_code == exit_codes.FINDINGS, r.output
    data = json.loads(r.stdout)
    ids = [f["checkId"] for f in data["findings"]]
    assert "ORG-001" in ids and "ORG-002" not in ids
    assert ids.count("SYM-MCP-002") == sum(1 for f in builtin if f.check_id == "SYM-MCP-002")
    assert any("malformed Rego finding" in e for e in data["errors"])
    sarif = tmp_path / "out.sarif"
    runner.invoke(app, ["policy", "check", str(companion), "--rego", str(policies), "--sarif", str(sarif)])
    rules = {r["ruleId"] for r in json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"]}
    assert "ORG-001" in rules


def test_rego_evaluation_failure_is_an_io_error(
    companion: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = tmp_path / "opa"
    fake.write_text("#!/bin/sh\necho 'rego_parse_error: unexpected token' >&2\nexit 1\n", encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(rego_module.shutil, "which", lambda _name: str(fake))
    r = runner.invoke(app, ["policy", "check", str(companion), "--rego", str(tmp_path)])
    assert r.exit_code == exit_codes.IO


def test_input_errors_use_stable_exit_codes(companion: Path, tmp_path: Path) -> None:
    assert runner.invoke(app, ["policy", "check", str(tmp_path / "missing.json")]).exit_code == exit_codes.IO
    bad = tmp_path / "bad.json"
    bad.write_text('{"specVersion": "0.1"}', encoding="utf-8")
    assert runner.invoke(app, ["policy", "check", str(bad)]).exit_code == exit_codes.SCHEMA
    bad.write_text("{not json", encoding="utf-8")
    assert runner.invoke(app, ["score", str(bad)]).exit_code == exit_codes.SCHEMA
    assert runner.invoke(app, ["conformance", str(bad)]).exit_code == exit_codes.SCHEMA
    assert (
        runner.invoke(app, ["policy", "check", str(companion), "--fail-on", "nope"]).exit_code
        == exit_codes.USAGE
    )
    assert runner.invoke(app, ["policy", "explain", "SYM-NOPE-999"]).exit_code == exit_codes.USAGE
    r = runner.invoke(app, ["policy", "explain", "sym-tool-002", "--json"])
    assert r.exit_code == exit_codes.OK and json.loads(r.stdout)["rego"] is False
