"""An inventory describes the project, not the directory it was checked out into."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main

DEMO = Path(__file__).resolve().parents[1] / "examples" / "demo-agent"


def _scan(project: Path, output: Path) -> dict:
    result = CliRunner().invoke(main, ["scan", str(project), "--report-only", "-o", str(output)])
    assert result.exit_code == 0, result.output
    return json.loads(output.read_text())


def _checkouts(tmp_path: Path, second: str) -> tuple[Path, Path]:
    first = tmp_path / "laptop" / "demo-agent"
    other = tmp_path / "runner" / "work" / second
    shutil.copytree(DEMO, first)
    shutil.copytree(DEMO, other)
    return first, other


def test_inventory_records_no_checkout_path(tmp_path):
    project, _ = _checkouts(tmp_path, "demo-agent")
    output = tmp_path / "bom.json"
    bom = _scan(project, output)
    assert str(tmp_path) not in output.read_text()
    sources = {c["source_path"] for c in bom["components"] if c.get("source_path")}
    assert ".mcp.json" in sources
    assert all(not Path(source).is_absolute() for source in sources if "://" not in source)


def test_same_project_in_another_directory_is_not_drift(tmp_path):
    first, other = _checkouts(tmp_path, "demo-agent")
    _scan(first, tmp_path / "baseline.json")
    _scan(other, tmp_path / "current.json")
    result = CliRunner().invoke(
        main,
        [
            "diff",
            str(tmp_path / "baseline.json"),
            str(tmp_path / "current.json"),
            "--fail-on-alert",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "No changes detected" in result.output


def test_renamed_checkout_is_not_drift(tmp_path):
    first, other = _checkouts(tmp_path, "renamed")
    _scan(first, tmp_path / "baseline.json")
    _scan(other, tmp_path / "current.json")
    result = CliRunner().invoke(
        main,
        [
            "diff",
            str(tmp_path / "baseline.json"),
            str(tmp_path / "current.json"),
            "--fail-on-alert",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "No changes detected" in result.output


def test_baseline_reconciles_with_another_checkout(tmp_path):
    first, other = _checkouts(tmp_path, "renamed")
    _scan(first, tmp_path / "bom.json")
    result = CliRunner().invoke(
        main, ["validate", str(tmp_path / "bom.json"), "--project", str(other)]
    )
    completeness = result.output.split("Completeness check", 1)[1].split("Integrity check", 1)[0]
    assert "Status: PASS" in completeness, result.output
    assert "Hashes verified: 4, failed: 0" in result.output
