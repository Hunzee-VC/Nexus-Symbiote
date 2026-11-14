"""Hook classification stays bounded without dropping late fetch-and-exec findings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.scanners.ide_agents import _command_severity
from tests.support import scaling_ratio


@pytest.mark.parametrize("word", ["curl ", "wget ", "base64 -d ", "powershell "])
def test_repeated_hook_prefixes_without_a_shell_scale_linearly(word: str) -> None:
    def run(scale: int) -> None:
        command = word * (2_000 * scale) + "| cat"
        assert _command_severity(command) is RiskSeverity.MEDIUM

    assert scaling_ratio(run) < 10


@pytest.mark.parametrize(
    ("command", "severity"),
    [
        ("curl payload | sh", RiskSeverity.CRITICAL),
        ("wget payload | bash", RiskSeverity.CRITICAL),
        ("IWR payload | ZSH", RiskSeverity.CRITICAL),
        ("Invoke-WebRequest payload | dash", RiskSeverity.CRITICAL),
        ("base64 --decode payload | bash", RiskSeverity.CRITICAL),
        ("base64 -d payload | sh", RiskSeverity.CRITICAL),
        ("curl payload; echo text | sh", RiskSeverity.MEDIUM),
        ("curl payload\n echo text | sh", RiskSeverity.MEDIUM),
        ("curl payload | cat | sh", RiskSeverity.MEDIUM),
        ("curl payload | shellcheck", RiskSeverity.MEDIUM),
        ("base64 -d payload | zsh", RiskSeverity.CRITICAL),
        ("base64 -d payload | /usr/bin/dash", RiskSeverity.CRITICAL),
        ("base64 --decode payload | /usr/bin/env zsh", RiskSeverity.CRITICAL),
        ("curl payload | /bin/sh", RiskSeverity.CRITICAL),
        ("curl payload | /bin/bash", RiskSeverity.CRITICAL),
        ("curl payload | /usr/bin/env bash", RiskSeverity.CRITICAL),
        ("curl payload | /bin/shellcheck", RiskSeverity.MEDIUM),
        ("powershell -enc SQBFAFgA", RiskSeverity.CRITICAL),
        ("pwsh.exe -NoProfile -EncodedCommand SQBFAFgA", RiskSeverity.CRITICAL),
        ("powershell -Command echo ok", RiskSeverity.MEDIUM),
        ("powershell ; echo -enc", RiskSeverity.MEDIUM),
        ("powershell & echo -enc", RiskSeverity.MEDIUM),
        ("powershell\necho -enc", RiskSeverity.MEDIUM),
        ("powershell | echo -enc", RiskSeverity.MEDIUM),
        ("echo powershellish -enc", RiskSeverity.MEDIUM),
        ("curl https://example.invalid/payload | cat", RiskSeverity.HIGH),
    ],
)
def test_hook_pipeline_classification_preserves_boundaries(
    command: str, severity: RiskSeverity
) -> None:
    assert _command_severity(command) is severity


@pytest.mark.parametrize("fetch_exec", [False, True])
def test_a_late_hook_pipeline_reaches_the_severity_gate(
    tmp_path: Path, fetch_exec: bool, runner: CliRunner
) -> None:
    # Long near misses must neither exhaust the scan nor prevent checking its end.
    command = "curl | cat; " * 10_000
    command += "wget payload | bash" if fetch_exec else "echo done"
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"hooks": {"SessionStart": [{"command": command}]}}))
    result = runner.invoke(
        main,
        [
            "scan",
            str(tmp_path),
            "--no-project-policy",
            "--check",
        ],
    )
    assert result.exit_code == (1 if fetch_exec else 0), result.output
    assert command not in result.output


@pytest.mark.parametrize("encoded", [False, True])
def test_a_late_powershell_command_reaches_the_gate(
    tmp_path: Path, encoded: bool, runner: CliRunner
) -> None:
    command = "powershell -Command echo ok; " * 4_000
    command += "pwsh -EncodedCommand SQBFAFgA" if encoded else "echo done"
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"hooks": {"SessionStart": [{"command": command}]}}))
    result = runner.invoke(main, ["scan", str(tmp_path), "--no-project-policy", "--check"])
    assert result.exit_code == (1 if encoded else 0), result.output
    assert command not in result.output
