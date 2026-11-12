"""The Action records unsigned ShadowScan discovery in CI as a failed gate, never a crash."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "action_unsigned_runner", ROOT / "scripts" / "run_action.py"
)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)

REPORT = ROOT / "tests" / "fixtures" / "shadowscan" / "code-report-0.1.4.json"
UNSIGNED = "Unsigned ShadowScan discovery evidence in CI"
CI_VARIABLES = (
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "CIRCLECI",
    "TF_BUILD",
    "JENKINS_URL",
    "BUILDKITE",
    "DRONE",
    "TRAVIS",
)
REASON = (
    "Unsigned ShadowScan discovery evidence in CI; pass --allow-unsigned-discovery to "
    "accept it explicitly.\n::warning::forged"
)
PARTIAL = {
    "assessment_basis": "unsigned-discovery-evidence",
    "overall_score": None,
    "risk_level": "unknown",
    "coverage_status": "unreconciled",
    "gate_reasons": [REASON],
}
FULL = {
    "overall_score": None,
    "risk_level": "unknown",
    "findings": [],
    "passed": False,
    "assessment_basis": "unsigned-discovery-evidence",
    "coverage_status": "unreconciled",
    "gate_reasons": [REASON],
}


def configuration(workspace: Path, **inputs: str) -> Any:
    return runner.Config.from_env({"GITHUB_WORKSPACE": str(workspace), **inputs})


def published(outputs: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in outputs.read_text().splitlines())


def stub(calls: list[list[str]], risk: tuple[int, str]) -> Any:
    def command(args: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[0] == "risk":
            return subprocess.CompletedProcess(args, risk[0], risk[1], "::warning::from risk")
        return subprocess.CompletedProcess(args, 0, '{"passed": true}', "")

    return command


def test_allow_unsigned_discovery_is_a_strict_boolean_input(tmp_path: Path) -> None:
    assert configuration(tmp_path).allow_unsigned_discovery is False
    allowed = configuration(tmp_path, SYMBIOTE_ALLOW_UNSIGNED_DISCOVERY="true")
    assert allowed.allow_unsigned_discovery is True
    for value in ("yes", "True", "1", "true\n", ""):
        with pytest.raises(runner.InputError, match="allow-unsigned-discovery"):
            configuration(tmp_path, SYMBIOTE_ALLOW_UNSIGNED_DISCOVERY=value)


def test_action_yml_declares_and_passes_the_input_as_data() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    assert action["inputs"]["allow-unsigned-discovery"]["default"] == "false"
    scan = next(step for step in action["runs"]["steps"] if step.get("id") == "scan")
    assert (
        scan["env"]["SYMBIOTE_ALLOW_UNSIGNED_DISCOVERY"] == "${{ inputs.allow-unsigned-discovery }}"
    )


@pytest.mark.parametrize("allow", [False, True])
def test_flag_reaches_validate_and_risk_only_when_set(tmp_path: Path, allow: bool) -> None:
    config = configuration(tmp_path, SYMBIOTE_ALLOW_UNSIGNED_DISCOVERY=str(allow).lower())
    calls: list[list[str]] = []
    command = stub(calls, (0, '{"overall_score": 0, "passed": true}'))
    assert runner.run(config, command=command) == 0
    scan, validate, risk = calls
    assert "--allow-unsigned-discovery" not in scan
    assert ("--allow-unsigned-discovery" in validate) is allow
    assert ("--allow-unsigned-discovery" in risk) is allow


def test_risk_reconciles_against_the_project_with_the_validation_signers(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    policy = tmp_path / "caller" / "signers.json"
    policy.parent.mkdir()
    policy.write_text('{"version": 1, "artifacts": []}')
    config = runner.Config.from_env(
        {"GITHUB_WORKSPACE": str(workspace), "SYMBIOTE_SIGNATURE_POLICY": str(policy)}
    )
    calls: list[list[str]] = []
    assert runner.run(config, command=stub(calls, (0, '{"overall_score": 0}'))) == 0
    _, validate, risk = calls
    assert risk[risk.index("--project") + 1] == str(workspace)
    snapshot = validate[validate.index("--signature-policy") + 1]
    assert risk[risk.index("--signature-policy") + 1] == snapshot


@pytest.mark.parametrize("document", [PARTIAL, FULL], ids=["partial", "full"])
def test_unscored_risk_failure_is_a_recorded_gate_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], document: dict[str, Any]
) -> None:
    outputs, summary = tmp_path / "outputs", tmp_path / "summary.md"
    config = configuration(tmp_path, SYMBIOTE_VALIDATE="false")
    calls: list[list[str]] = []
    command = stub(calls, (1, json.dumps(document)))
    assert runner.run(config, command=command, outputs=outputs, summary=summary) == 1
    values = published(outputs)
    assert json.loads(values["gates"])["risk"] == "failed"
    assert values["passed"] == "false" and values["risk_score"] == ""
    assert values["result"] == "failed"
    log = capsys.readouterr().err
    assert "action failed" not in log
    assert "\n::warning::" not in log and not log.startswith("::warning::")
    assert UNSIGNED in log
    assert "Risk score: not computed" in summary.read_text()
    assert "Risk gate reason: Unsigned ShadowScan" in summary.read_text()


@pytest.mark.parametrize("stdout", ["", "not json", '{"overall_score": null, "passed": true}'])
def test_unscored_risk_without_reasons_still_fails_the_gate(tmp_path: Path, stdout: str) -> None:
    outputs = tmp_path / "outputs"
    config = configuration(tmp_path, SYMBIOTE_VALIDATE="false")
    assert runner.run(config, command=stub([], (1, stdout)), outputs=outputs) == 1
    values = published(outputs)
    assert json.loads(values["gates"])["risk"] == "failed" and values["passed"] == "false"


def test_a_passing_exit_without_a_score_is_still_an_error(tmp_path: Path) -> None:
    config = configuration(tmp_path, SYMBIOTE_VALIDATE="false")
    with pytest.raises(runner.ActionError, match="no finite numeric score"):
        runner.run(config, command=stub([], (0, '{"overall_score": null}')))


def _entry_point(
    tmp_path: Path, allow: str | None
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    workspace = tmp_path / "workspace"
    project = workspace / "agent"
    (project / ".shadowscan").mkdir(parents=True)
    shutil.copy(REPORT, project / ".shadowscan" / "report.json")
    (project / "CLAUDE.md").write_text("Review issues with read-only tools.\n")
    outputs = tmp_path / "outputs"
    env = {k: v for k, v in os.environ.items() if k not in CI_VARIABLES}
    env.update(
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_OUTPUT": str(outputs),
            "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
            "SYMBIOTE_SCAN_PATH": "agent",
            "SYMBIOTE_OUTPUT_FILE": "result.json",
            "SYMBIOTE_SCANNERS": "",
        }
    )
    if allow is not None:
        env["SYMBIOTE_ALLOW_UNSIGNED_DISCOVERY"] = allow
    result = subprocess.run(  # noqa: S603 -- the reviewed entry point under this interpreter
        [sys.executable, "-I", str(ROOT / "scripts" / "run_action.py")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    return result, published(outputs)


def test_entry_point_in_ci_fails_the_gate_on_unsigned_discovery_by_default(
    tmp_path: Path,
) -> None:
    result, values = _entry_point(tmp_path, None)
    assert result.returncode == 1, result.stderr
    assert "Traceback" not in result.stderr
    assert "action failed" not in result.stderr
    gates = json.loads(values["gates"])
    assert gates["collection"] == "passed"
    assert gates["completeness"] == "failed" and values["validation_passed"] == "false"
    assert gates["risk"] == "failed" and values["passed"] == "false"
    assert values["result"] == "failed"
    assert UNSIGNED in result.stderr
    summary = (tmp_path / "summary.md").read_text()
    assert "Risk gate reason: Unsigned ShadowScan discovery evidence in CI" in summary
    assert not re.search(
        r"^::(?!stop-commands|[0-9a-f]{32}::|warning title=|notice title=)", result.stderr, re.M
    )


def test_entry_point_in_ci_accepts_unsigned_discovery_when_allowed(tmp_path: Path) -> None:
    result, values = _entry_point(tmp_path, "true")
    assert "Traceback" not in result.stderr
    assert "action failed" not in result.stderr
    assert UNSIGNED not in result.stderr
    assert "ShadowScan discovery evidence is UNVERIFIED" in result.stderr
    gates = json.loads(values["gates"])
    assert gates["collection"] == "passed"
    assert values["risk_score"] != ""
    assert "allow-unsigned-discovery is 'true'" in result.stderr
    assert result.returncode == 0, result.stderr
    assert values["result"] == "passed" and values["passed"] == "true"
    assert values["validation_passed"] == "true"
    summary = (tmp_path / "summary.md").read_text()
    assert "Unsigned ShadowScan" not in summary
