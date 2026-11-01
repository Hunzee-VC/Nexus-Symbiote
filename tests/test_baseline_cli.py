"""Tests for the drift baseline workflow and CLI command contract."""

from __future__ import annotations

import json
import re
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main


def _make_project(root: Path) -> None:
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github@1.2.0"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (root / "requirements.txt").write_text("mcp\n", encoding="utf-8")


def test_baseline_create_and_diff_cycle(tmp_path: Path) -> None:
    """Baseline -> approve a new server -> drift must be detected by diff."""
    runner = CliRunner()
    project = tmp_path / "proj"
    project.mkdir()
    _make_project(project)

    result = runner.invoke(main, ["baseline", str(project), "-o", str(tmp_path / "baseline.json")])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "baseline.json").exists()

    # Change the supply chain: a new server appears.
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github@1.2.0"],
                    },
                    "search": {
                        "command": "npx",
                        "args": ["-y", "@new/search-mcp"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(main, ["scan", str(project), "-o", str(tmp_path / "current.json")])
    assert result.exit_code == 0, result.output

    result = runner.invoke(
        main,
        [
            "diff",
            str(tmp_path / "baseline.json"),
            str(tmp_path / "current.json"),
        ],
    )
    assert result.exit_code == 0
    assert "search" in result.output


README_COMMANDS = [
    "init",
    "scan",
    "validate",
    "risk",
    "diff",
    "summary",
    "baseline",
    "verify-live",
    "vex",
    "advisories",
    "import-shadowscan",
]


def test_every_readme_command_exists() -> None:
    """Guard against the 2a800b5 class of regression: a commit that drops
    documented commands while the README, hooks, and CI still reference them."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0

    documented = set(re.findall(r"^  (\S+)", result.output, re.MULTILINE))
    for command in README_COMMANDS:
        assert command in documented, f"README documents '{command}' but the CLI lost it"


def test_scan_still_works_after_new_commands(tmp_path: Path) -> None:
    runner = CliRunner()
    project = tmp_path / "proj"
    project.mkdir()
    _make_project(project)

    result = runner.invoke(main, ["scan", str(project), "-o", str(tmp_path / "aibom.json")])
    assert result.exit_code == 0
    assert (tmp_path / "aibom.json").exists()
