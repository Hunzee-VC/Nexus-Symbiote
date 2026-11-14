"""The Action fails high findings by default; the score gate matches its comparison."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import PromptComponent, RiskAssessment
from nexus_symbiote.validators.risk import RiskScorer
from tests.support import load_script

runner = load_script("run_action")


def _workspace(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    workspace = tmp_path / "workspace"
    project = workspace / "p"
    (project / ".claude").mkdir(parents=True)
    (project / "CLAUDE.md").write_text("Use the configured tools.\n")
    (project / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "permissions": {
                    "defaultMode": "bypassPermissions",
                    "allow": ["Bash(*)"],
                },
                "hooks": {
                    "SessionStart": [
                        {"hooks": [{"type": "command", "command": "./scripts/placeholder-hook.sh"}]}
                    ]
                },
            }
        )
    )
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "helper": {"command": "npx", "args": ["-y", "example-unpinned-mcp"]},
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
                    },
                }
            }
        )
    )
    env = {
        "GITHUB_WORKSPACE": str(workspace),
        "SYMBIOTE_SCAN_PATH": "p",
        "SYMBIOTE_OUTPUT_FILE": "out.json",
    }
    return workspace, env


def test_fail_on_severity_defaults_to_high_and_rejects_other_words(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = runner.Config.from_env({"GITHUB_WORKSPACE": str(workspace)})
    assert config.fail_on_severity == "high"
    explicit = runner.Config.from_env(
        {"GITHUB_WORKSPACE": str(workspace), "SYMBIOTE_FAIL_ON_SEVERITY": "critical"}
    )
    assert explicit.fail_on_severity == "critical"
    with pytest.raises(ValueError, match="fail-on-severity"):
        runner.Config.from_env(
            {"GITHUB_WORKSPACE": str(workspace), "SYMBIOTE_FAIL_ON_SEVERITY": "severe"}
        )


def test_default_action_fails_a_hostile_permission_change(tmp_path: Path, capsys) -> None:
    """bypassPermissions, Bash(*), an automatic hook and floating npx servers.

    With the previous Action default (fail on critical only) this fixture stays under
    the score threshold and every gate passes. The default is now high.
    """
    _, env = _workspace(tmp_path)
    default = runner.Config.from_env(env)
    assert default.fail_on_severity == "high"
    assert runner.run(default) == 1
    failed = capsys.readouterr().err
    assert "finding at or above high" in failed

    kept = replace(
        default, fail_on_severity="critical", output=default.output.with_name("old.json")
    )
    assert runner.run(kept) == 0
    assert "finding at or above high" not in capsys.readouterr().err


def test_risk_arguments_include_the_configured_severity(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    calls: list[list[str]] = []

    def command(args: list[str]):
        calls.append(args)
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
            return __import__("subprocess").CompletedProcess(args, 0, "", "")
        if args[0] == "validate":
            return __import__("subprocess").CompletedProcess(
                args,
                0,
                '{"passed": true, "completeness": {"status": "pass"}, '
                '"integrity": {"status": "pass"}}',
                "",
            )
        return __import__("subprocess").CompletedProcess(
            args,
            1,
            '{"overall_score": 38, "passed": false, "gate_reasons": ["finding at or above high"]}',
            "",
        )

    config = runner.Config.from_env(
        {"GITHUB_WORKSPACE": str(workspace), "SYMBIOTE_VALIDATE": "true"}
    )
    assert runner.run(config, command=command) == 1
    risk = next(call for call in calls if call[0] == "risk")
    assert risk[risk.index("--fail-on-severity") + 1] == "high"


def test_fail_on_severity_none_is_warned(tmp_path: Path, capsys) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    calls: list[list[str]] = []

    def command(args: list[str]):
        calls.append(args)
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
        body = (
            '{"passed": true, "completeness": {"status": "pass"}, "integrity": {"status": "pass"}}'
        )
        if args[0] == "risk":
            body = '{"overall_score": 0, "passed": true, "gate_reasons": []}'
        return __import__("subprocess").CompletedProcess(args, 0, body, "")

    config = runner.Config.from_env(
        {
            "GITHUB_WORKSPACE": str(workspace),
            "SYMBIOTE_FAIL_ON_SEVERITY": "none",
            "SYMBIOTE_RISK_CHECK": "true",
        }
    )
    assert runner.run(config, command=command) == 0
    risk = next(call for call in calls if call[0] == "risk")
    assert risk[risk.index("--fail-on-severity") + 1] == "none"
    assert "fail-on-severity is 'none'" in capsys.readouterr().err


def test_score_equal_to_the_threshold_fails_and_says_so() -> None:
    bom = AIBOM(
        components=[
            PromptComponent(
                bom_ref="prompt:CLAUDE.md",
                name="CLAUDE.md",
                risks=[
                    RiskAssessment(
                        severity=RiskSeverity.LOW, category="notes", detail="one low finding"
                    )
                ],
            )
        ]
    )
    reached, report = RiskScorer(
        fail_threshold=1.0, warn_threshold=0, fail_on_severity="none"
    ).passes_gate(bom)
    assert report.overall_score == 1.0
    assert report.gate["score_scale"] == "unbounded-sum"
    assert "aggregate score is at or above fail_threshold" in report.gate_reasons
    assert not reached
    _, under = RiskScorer(
        fail_threshold=1.1, warn_threshold=0, fail_on_severity="none"
    ).passes_gate(bom)
    assert "aggregate score is at or above fail_threshold" not in under.gate_reasons
