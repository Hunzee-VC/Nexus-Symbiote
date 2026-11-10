"""The Action's log, outputs and gates: no command from the checkout, nothing ambiguous."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "action_output_runner", ROOT / "scripts" / "run_action.py"
)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)

DECLARED = (
    "aibom_path",
    "sarif_path",
    "risk_score",
    "passed",
    "validation_passed",
    "drift_passed",
    "drift_alerts",
    "gates",
    "result",
    "signature_policy_digest",
)
LOG_COMMAND = re.compile(r"##[A-Za-z]*\[")
OWN_COMMAND = re.compile(
    r"::(?:stop-commands::[0-9a-f]{32}|[0-9a-f]{32}::"
    r"|(?:warning|notice) title=Nexus SymBiote::.*)"
)
HOSTILE = (
    "::set-output name=aibom_path::/etc/passwd\n"
    "x ##[set-output name=sarif_path]/home/runner/work/_temp/**/*%0A\n"
    "::warning::forged\x1b[2J\n"
    "::add-mask::CRITICAL"
)


def configuration(workspace: Path, **inputs: str) -> Any:
    return runner.Config.from_env({"GITHUB_WORKSPACE": str(workspace), **inputs})


def published(outputs: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in outputs.read_text().splitlines())


Command = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def stub(
    calls: list[list[str]],
    *,
    native: str = "{}",
    scan: tuple[int, str] = (0, ""),
    validate: tuple[int, dict[str, Any]] = (0, {"passed": True}),
    risk: tuple[int, dict[str, Any]] = (0, {"overall_score": 0, "passed": True}),
    diff: tuple[int, dict[str, Any]] = (0, {"has_changes": False, "security_alerts": []}),
) -> Command:
    def command(args: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text(native)
            return subprocess.CompletedProcess(args, scan[0], HOSTILE, scan[1])
        code, document = {"validate": validate, "risk": risk, "diff": diff}[args[0]]
        return subprocess.CompletedProcess(args, code, json.dumps(document), HOSTILE)

    return command


def unbracketed(log: str) -> list[str]:
    """Lines the runner would act on: outside a stop-commands block, and not our own."""
    problems: list[str] = []
    token: str | None = None
    tokens: set[str] = set()
    for line in log.splitlines():
        if token is not None:
            if line == f"::{token}::":
                token = None
            elif not line.startswith(runner.RELAY_PREFIX) or LOG_COMMAND.search(line):
                problems.append(line)
            continue
        opened = re.fullmatch(r"::stop-commands::([0-9a-f]{32})", line)
        if opened:
            token = opened.group(1)
            if token in tokens:
                problems.append("reused token " + token)
            tokens.add(token)
        elif (line.lstrip().startswith("::") and not OWN_COMMAND.fullmatch(line)) or (
            LOG_COMMAND.search(line)
        ):
            problems.append(line)
    if token is not None:
        problems.append("unterminated stop-commands block")
    return problems


def test_relayed_output_is_bracketed_neutralized_and_prefixed(tmp_path, capsys):
    calls: list[list[str]] = []
    config = configuration(tmp_path, SYMBIOTE_RISK_THRESHOLD="0", SYMBIOTE_VALIDATE="false")
    assert runner.run(config, command=stub(calls), outputs=tmp_path / "out") == 0
    log = capsys.readouterr().err
    assert unbracketed(log) == []
    assert log.count("::stop-commands::") == 2
    assert "| ::set-output name=aibom_path::/etc/passwd" in log.splitlines()
    assert "| x ##\ufffd[set-output name=sarif_path]/home/runner/work/_temp/**/*%0A" in log
    assert "\x1b" not in log


def test_every_declared_output_is_written_before_collection(tmp_path, capsys):
    calls: list[list[str]] = []
    outputs = tmp_path / "out"
    config = configuration(tmp_path)
    assert runner.run(config, command=stub(calls, scan=(1, HOSTILE)), outputs=outputs) == 1
    lines = outputs.read_text().splitlines()
    assert [line.split("=", 1)[0] for line in lines[: len(DECLARED)]] == list(DECLARED)
    values = published(outputs)
    assert values["aibom_path"] == values["sarif_path"] == values["risk_score"] == ""
    assert values["passed"] == values["validation_passed"] == values["drift_passed"] == "not-run"
    assert values["result"] == "failed"
    assert json.loads(values["gates"])["collection"] == "failed"
    assert [call[0] for call in calls] == ["scan"]
    assert unbracketed(capsys.readouterr().err) == []


def test_action_yml_maps_exactly_the_outputs_the_runner_writes():
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    mapped = {
        re.fullmatch(r"\$\{\{ steps\.scan\.outputs\.(\w+) \}\}", output["value"]).group(1)
        for output in action["outputs"].values()
    }
    assert mapped <= set(DECLARED)
    steps = action["runs"]["steps"]
    uploads = [step for step in steps if "upload" in step.get("uses", "")]
    for step in uploads:
        for name in re.findall(r"steps\.scan\.outputs\.(\w+)", json.dumps(step)):
            assert name in DECLARED
    source = (ROOT / "scripts" / "run_action.py").read_text()
    scan = next(step for step in steps if step.get("id") == "scan")
    for name in scan["env"]:
        if name.startswith("SYMBIOTE_") and name not in {"SYMBIOTE_ACTION_PATH"}:
            assert f'"{name}"' in source or name == "SYMBIOTE_ACTION_PYTHON", name


def test_the_action_keeps_its_interpreter_off_the_callers_path():
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    steps = action["runs"]["steps"]
    setup = next(step for step in steps if "setup-python" in step.get("uses", ""))
    assert setup["with"]["update-environment"] is False
    for step in steps:
        assert "GITHUB_PATH" not in step.get("run", "")
        assert "GITHUB_ENV" not in step.get("run", "")
    install = next(step for step in steps if step.get("id") == "install")
    assert install["env"]["SYMBIOTE_BASE_PYTHON"] == "${{ steps.python.outputs.python-path }}"
    assert 'echo "python=$action_venv/bin/python" >> "$GITHUB_OUTPUT"' in install["run"]
    scan = next(step for step in steps if step.get("id") == "scan")
    assert scan["env"]["SYMBIOTE_ACTION_PYTHON"] == "${{ steps.install.outputs.python }}"


@pytest.mark.parametrize("value", ["-0", "1e-400", "0_0", " 5", "inf", "5.", ".5", "100.5", "007"])
def test_threshold_accepts_only_plain_decimals_from_0_to_100(tmp_path, value):
    with pytest.raises(ValueError, match="risk-threshold"):
        configuration(tmp_path, SYMBIOTE_RISK_THRESHOLD=value)


@pytest.mark.parametrize("value,expected", [("0", 0.0), ("50", 50.0), ("37.5", 37.5)])
def test_threshold_accepts_plain_decimals(tmp_path, value, expected):
    assert configuration(tmp_path, SYMBIOTE_RISK_THRESHOLD=value).threshold == expected


def test_threshold_zero_removes_only_the_score_threshold(tmp_path, capsys):
    calls: list[list[str]] = []
    failing = {
        "overall_score": 17.0,
        "passed": False,
        "gate_reasons": ["finding at or above critical"],
        "findings": [],
    }
    outputs = tmp_path / "out"
    config = configuration(tmp_path, SYMBIOTE_RISK_THRESHOLD="0")
    command = stub(calls, risk=(1, failing))
    assert runner.run(config, command=command, outputs=outputs) == 1
    risk = next(call for call in calls if call[0] == "risk")
    assert "--no-score-threshold" in risk and "--threshold" not in risk
    values = published(outputs)
    assert values["passed"] == "false" and values["risk_score"] == "17.0"
    assert values["result"] == "failed"
    log = capsys.readouterr().err
    assert "::notice title=Nexus SymBiote::risk-threshold is 0: the aggregate score" in log
    assert "|   - finding at or above critical" in log.splitlines()


def test_disabled_gates_are_printed_and_reported_as_skipped(tmp_path, capsys):
    calls: list[list[str]] = []
    outputs = tmp_path / "out"
    config = configuration(tmp_path, SYMBIOTE_VALIDATE="false", SYMBIOTE_RISK_CHECK="false")
    assert runner.run(config, command=stub(calls), outputs=outputs) == 0
    assert [call[0] for call in calls] == ["scan"]
    values = published(outputs)
    assert values["validation_passed"] == "skipped" and values["passed"] == "skipped"
    assert json.loads(values["gates"]) == {
        "collection": "passed",
        "completeness": "skipped",
        "integrity": "skipped",
        "risk": "skipped",
        "drift": "skipped",
    }
    log = capsys.readouterr().err
    assert "::warning title=Nexus SymBiote::validate is 'false'" in log
    assert "::warning title=Nexus SymBiote::risk-check is 'false'" in log


def test_completeness_without_integrity_is_a_visible_choice(tmp_path, capsys):
    calls: list[list[str]] = []
    outputs = tmp_path / "out"
    document = {"passed": True, "completeness": {"status": "pass"}}
    config = configuration(tmp_path, SYMBIOTE_VALIDATE_INTEGRITY="false")
    assert runner.run(config, command=stub(calls, validate=(0, document)), outputs=outputs) == 0
    validate = next(call for call in calls if call[0] == "validate")
    assert validate[-1] == "--skip-integrity" and "--json-output" in validate
    gates = json.loads(published(outputs)["gates"])
    assert gates["completeness"] == "passed" and gates["integrity"] == "skipped"
    assert (
        "::warning title=Nexus SymBiote::validate-integrity is 'false'" in capsys.readouterr().err
    )


def test_a_failed_validation_never_reads_as_skipped(tmp_path):
    calls: list[list[str]] = []
    outputs = tmp_path / "out"
    document = {
        "passed": False,
        "completeness": {"status": "pass"},
        "integrity": {"status": "unknown"},
    }
    config = configuration(tmp_path)
    assert runner.run(config, command=stub(calls, validate=(1, document)), outputs=outputs) == 1
    values = published(outputs)
    assert values["validation_passed"] == "false" and values["passed"] == "true"
    gates = json.loads(values["gates"])
    assert gates["integrity"] == "failed" and values["result"] == "failed"


SHADOWSCAN = json.dumps(
    {
        "metadata": {
            "completeness": {
                "scope": "repository+shadowscan",
                "source_report_digest": "sha256:" + "0" * 64,
            }
        }
    }
)


def test_imported_discovery_never_reaches_sarif(tmp_path, capsys):
    calls: list[list[str]] = []
    exports: list[str] = []
    outputs = tmp_path / "out"
    config = configuration(tmp_path, SYMBIOTE_SARIF="true")
    result = runner.run(
        config,
        command=stub(calls, native=SHADOWSCAN),
        export=lambda native, output, fmt: exports.append(fmt),
        outputs=outputs,
    )
    assert result == 0 and exports == ["json"]
    assert published(outputs)["sarif_path"] == ""
    assert "::warning title=Nexus SymBiote::SARIF upload skipped" in capsys.readouterr().err
    refused = configuration(tmp_path, SYMBIOTE_FORMAT="sarif")
    exports.clear()
    assert (
        runner.run(
            refused,
            command=stub([], native=SHADOWSCAN),
            export=lambda native, output, fmt: exports.append(fmt),
            outputs=tmp_path / "refused",
        )
        == 1
    )
    assert exports == [] and published(tmp_path / "refused")["aibom_path"] == ""


def _baseline(tmp_path: Path) -> Path:
    path = tmp_path / "caller" / "reviewed.json"
    path.parent.mkdir()
    path.write_text('{"components": []}')
    return path


def test_reviewed_baseline_runs_the_drift_gate_on_a_snapshot(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    baseline = _baseline(tmp_path)
    calls: list[list[str]] = []
    outputs = tmp_path / "out"
    alerts = {"has_changes": True, "security_alerts": [{"severity": "high", "alert": "x"}]}
    config = configuration(workspace, SYMBIOTE_REVIEWED_BASELINE=str(baseline))
    assert runner.run(config, command=stub(calls, diff=(1, alerts)), outputs=outputs) == 1
    diff = next(call for call in calls if call[0] == "diff")
    assert diff[3:] == ["--fail-on-alert", "--json-output"]
    snapshot = Path(diff[1])
    assert snapshot != baseline and not snapshot.is_relative_to(workspace)
    values = published(outputs)
    assert values["drift_passed"] == "false" and values["drift_alerts"] == "1"
    assert json.loads(values["gates"])["drift"] == "failed"


def test_reviewed_baseline_must_be_caller_owned(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "reviewed.json").write_text("{}")
    with pytest.raises(ValueError, match="reviewed-baseline must be an absolute path outside"):
        configuration(workspace, SYMBIOTE_REVIEWED_BASELINE=str(workspace / "reviewed.json"))
    link = tmp_path / "link.json"
    link.symlink_to(_baseline(tmp_path))
    with pytest.raises(ValueError, match="regular file reached without symlinks"):
        configuration(workspace, SYMBIOTE_REVIEWED_BASELINE=str(link))


def test_limits_come_only_from_the_input(tmp_path, monkeypatch):
    monkeypatch.setenv(runner.LIMITS_ENV, "max_entries=1")
    seen: list[str | None] = []

    def invoke(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.append(kwargs["env"].get(runner.LIMITS_ENV))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(runner.subprocess, "run", invoke)
    runner._run(["scan"], private=tmp_path)
    runner._run(["scan"], private=tmp_path, limits="max_entries=50000")
    assert seen == [None, "max_entries=50000"]
    with pytest.raises(ValueError, match="limits"):
        configuration(tmp_path, SYMBIOTE_LIMITS="max_entries=1\nSYMBIOTE_VALIDATE=false")


def test_scan_path_through_a_symlink_in_the_workspace_is_refused(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "agents").mkdir()
    (tmp_path / "agents" / "bot").symlink_to(tmp_path / "real", target_is_directory=True)
    with pytest.raises(ValueError, match="scan-path must not pass through a symbolic link"):
        configuration(tmp_path, SYMBIOTE_SCAN_PATH="agents/bot")


def test_output_paths_outside_the_workspace_are_never_emitted(tmp_path):
    outputs = runner._Outputs(tmp_path / "out", tmp_path / "workspace")
    with pytest.raises(ValueError, match="within GITHUB_WORKSPACE"):
        outputs.emit_path("sarif_path", tmp_path / "elsewhere.sarif")
    assert not (tmp_path / "out").exists()


def test_error_text_from_inventory_never_reaches_the_log(tmp_path, monkeypatch, capsys):
    calls: list[list[str]] = []
    monkeypatch.setattr(runner, "_run", lambda args, **kwargs: stub(calls)(args))
    from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator

    def invalid(self: object, bom: object) -> str:
        raise ValueError("invalid cyclonedx export: '##[set-output name=aibom_path]canary'")

    monkeypatch.setattr(CycloneDXGenerator, "generate_json", invalid)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("SYMBIOTE_FORMAT", "cyclonedx")
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out"))
    assert runner.main() == 1
    log = capsys.readouterr().err
    assert "the cyclonedx export failed its schema or consistency checks" in log
    assert "canary" not in log and unbracketed(log) == []

    def unexpected(*args: object, **kwargs: object) -> None:
        raise KeyError("canary ##[error]x")

    monkeypatch.setattr(runner, "run", unexpected)
    assert runner.main() == 1
    log = capsys.readouterr().err
    assert "Nexus SymBiote action failed: unexpected KeyError" in log and "canary" not in log


def test_step_summary_lists_each_gate_and_escapes_reasons(tmp_path):
    calls: list[list[str]] = []
    summary = tmp_path / "summary.md"
    failing = {
        "overall_score": 60.0,
        "passed": False,
        "gate_reasons": ["aggregate score <img src=x> [x](https://e.example)"],
    }
    config = configuration(tmp_path)
    assert runner.run(config, command=stub(calls, risk=(1, failing)), summary=summary) == 1
    text = summary.read_text()
    assert "| risk | failed |" in text and "| collection | passed |" in text
    # GitHub renders the summary as Markdown; every punctuation mark in a reason is escaped.
    assert "aggregate score \\<img src\\=x\\> \\[x\\]\\(https\\:\\/\\/e\\.example\\)" in text
    assert not re.search(r"(?<!\\)[<\[\]()]", text.split("Risk gate reason: ", 1)[1])
    assert "Risk score: 60.0" in text


def test_hostile_project_through_the_real_entry_point(tmp_path):
    workspace = tmp_path / "workspace"
    project = workspace / "agent"
    hidden = project / "##[set-output name=sarif_path]x%0A"
    hidden.mkdir(parents=True)
    (hidden / "s.py").write_text("from mcp.server import Server\n")
    (project / "models").mkdir()
    (project / "models" / "::warning::injected.pkl").write_bytes(b"unsafe")
    (project / "models" / "##[warning]injected.pkl").write_bytes(b"unsafe")
    (project / "CLAUDE.md").write_text("Use the configured tools.\n")
    outputs = tmp_path / "outputs"
    env = {
        **os.environ,
        "GITHUB_WORKSPACE": str(workspace),
        "GITHUB_OUTPUT": str(outputs),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
        "SYMBIOTE_SCAN_PATH": "agent",
        "SYMBIOTE_OUTPUT_FILE": "result.json",
        "SYMBIOTE_SCANNERS": "",
    }
    result = subprocess.run(  # noqa: S603 -- the reviewed entry point under this interpreter
        [sys.executable, "-I", str(ROOT / "scripts" / "run_action.py")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert result.returncode == 1, result.stderr
    assert result.stdout == ""
    assert unbracketed(result.stderr) == []
    assert "injected.pkl" in result.stderr
    lines = outputs.read_text().splitlines()
    assert "sarif_path=" in lines and not any(
        line.startswith("sarif_path=") and line != "sarif_path=" for line in lines
    )
    values = published(outputs)
    assert values["aibom_path"] == str(workspace / "result.json")
    assert values["result"] == "failed"


def test_ci_runs_the_composite_action_end_to_end():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    jobs = workflow["jobs"]
    steps = jobs["action"]["steps"]
    local = [step for step in steps if step.get("uses") == "./"]
    assert {step["id"] for step in local} == {"passing", "failing", "threshold", "hostile"}
    assert all(step.get("continue-on-error") is True for step in local if step["id"] != "passing")
    assert jobs["action"]["strategy"]["matrix"]["python"] == ["3.11", "3.12", "3.13", "3.14"]
    assert jobs["action-annotations"]["needs"] == "action"
    assert {"action", "action-annotations"} <= set(jobs["verified"]["needs"])
