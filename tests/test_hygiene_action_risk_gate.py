"""The Action's risk gate reconciles and uses the signer policy whether or not validate runs.

With `validate: 'false'` the runner called `risk` without `--project` and without the
signer policy, so a discovery report that the caller's policy verifies was treated as
unsigned and failed the gate; the only way through was `allow-unsigned-discovery`. A
scanner subset was refused only while validate was on, although the risk gate fails on
partial coverage too.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.support import ROOT, load_script

runner = load_script("run_action")
SUBSET = "scanners subset requires validate and risk-check to be false"


def _stub(calls: list[list[str]]) -> Any:
    def command(args: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}", encoding="utf-8")
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[0] == "risk":
            return subprocess.CompletedProcess(args, 0, '{"overall_score": 0}', "")
        return subprocess.CompletedProcess(args, 0, '{"passed": true}', "")

    return command


def _policy(tmp_path: Path) -> Path:
    policy = tmp_path / "caller" / "signers.json"
    policy.parent.mkdir()
    policy.write_text('{"version": 1, "artifacts": []}', encoding="utf-8")
    return policy


@pytest.mark.parametrize("validate", ["true", "false"])
def test_risk_gets_the_project_and_the_policy_snapshot_whatever_validate_is(tmp_path, validate):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = runner.Config.from_env(
        {
            "GITHUB_WORKSPACE": str(workspace),
            "SYMBIOTE_VALIDATE": validate,
            "SYMBIOTE_SIGNATURE_POLICY": str(_policy(tmp_path)),
        }
    )
    calls: list[list[str]] = []
    assert runner.run(config, command=_stub(calls)) == 0
    assert [args[0] for args in calls] == (
        ["scan", "validate", "risk"] if validate == "true" else ["scan", "risk"]
    )
    scan, risk = calls[0], calls[-1]
    assert risk[risk.index("--project") + 1] == str(workspace)
    snapshot = scan[scan.index("--signature-policy") + 1]
    assert risk.count("--signature-policy") == 1
    assert risk[risk.index("--signature-policy") + 1] == snapshot


def test_risk_reconciles_against_the_project_without_a_policy_or_validation(tmp_path):
    config = runner.Config.from_env(
        {"GITHUB_WORKSPACE": str(tmp_path), "SYMBIOTE_VALIDATE": "false"}
    )
    calls: list[list[str]] = []
    assert runner.run(config, command=_stub(calls)) == 0
    _, risk = calls
    assert risk[risk.index("--project") + 1] == str(tmp_path)
    assert "--signature-policy" not in risk


@pytest.mark.parametrize(
    ("validate", "risk_check", "refused"),
    [
        ("true", "true", True),
        ("true", "false", True),
        ("false", "true", True),
        ("false", "false", False),
    ],
)
def test_a_scanner_subset_is_refused_while_either_gate_is_on(
    tmp_path, validate, risk_check, refused
):
    env = {
        "GITHUB_WORKSPACE": str(tmp_path),
        "SYMBIOTE_SCANNERS": "mcp,model",
        "SYMBIOTE_VALIDATE": validate,
        "SYMBIOTE_RISK_CHECK": risk_check,
    }
    if refused:
        with pytest.raises(runner.InputError, match=SUBSET):
            runner.Config.from_env(env)
    else:
        assert runner.Config.from_env(env).scanners == ("mcp", "model")


def test_every_scanner_named_is_not_a_subset(tmp_path):
    names = ",".join(sorted(runner.SCANNERS))
    config = runner.Config.from_env({"GITHUB_WORKSPACE": str(tmp_path), "SYMBIOTE_SCANNERS": names})
    assert set(config.scanners) == runner.SCANNERS


def test_the_inputs_describe_both_gates():
    inputs = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))["inputs"]
    scanners = " ".join(inputs["scanners"]["description"].split())
    assert "the validate and risk-check gates fail whenever they are on" in scanners
    assert "the Action refuses such a list unless both are 'false'" in scanners
    unsigned = " ".join(inputs["allow-unsigned-discovery"]["description"].split())
    assert "unless signature-policy names the report and verifies its producer" in unsigned
    assert "validate is 'true' and signature-policy" not in unsigned


def test_the_real_entry_point_passes_the_risk_gate_without_validation(tmp_path):
    workspace = tmp_path / "workspace"
    project = workspace / "agent"
    project.mkdir(parents=True)
    (project / "CLAUDE.md").write_text("Review issues with read-only tools.\n", encoding="utf-8")
    outputs = tmp_path / "outputs"
    keep = {"PATH", "LANG", "LC_ALL", "SYSTEMROOT", "TMPDIR", "VIRTUAL_ENV"}
    env = {key: value for key, value in os.environ.items() if key in keep}
    env.update(
        {
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_OUTPUT": str(outputs),
            "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
            "SYMBIOTE_SCAN_PATH": "agent",
            "SYMBIOTE_OUTPUT_FILE": "result.json",
            "SYMBIOTE_VALIDATE": "false",
        }
    )
    result = subprocess.run(  # noqa: S603 -- the reviewed entry point under this interpreter
        [sys.executable, "-I", str(ROOT / "scripts" / "run_action.py")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr
    values = dict(line.split("=", 1) for line in outputs.read_text().splitlines())
    assert json.loads(values["gates"]) == {
        "collection": "passed",
        "completeness": "skipped",
        "integrity": "skipped",
        "risk": "passed",
        "drift": "skipped",
    }
    assert values["validation_passed"] == "skipped" and values["passed"] == "true"
