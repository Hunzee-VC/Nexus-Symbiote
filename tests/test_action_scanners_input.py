"""The Action's scanners input says what naming collectors does to the default gates, and
the commands the Action runs behave as it says."""

from __future__ import annotations

from pathlib import Path

import yaml

from nexus_symbiote.cli import main
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "demo-agent"


def test_the_scanners_input_says_that_a_partial_list_fails_the_gates():
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    scanners = action["inputs"]["scanners"]
    description = " ".join(scanners["description"].split())
    assert scanners["default"] == ""
    assert "empty means all" in description
    assert "A list that leaves any collector out makes coverage partial" in description
    assert "the validate and risk-check gates fail whenever they are on" in description


def _gates(runner, tmp_path: Path, names: list[str]) -> tuple[int, int]:
    """The exit codes of validate and risk, as the Action runs them, for a scan with names."""
    inventory = tmp_path / f"{len(names)}.json"
    chosen = [argument for name in names for argument in ("--scanner", name)]
    scan = ["scan", str(DEMO), "--no-project-policy", "--report-only", *chosen]
    assert runner.invoke(main, [*scan, "-o", str(inventory)]).exit_code == 0
    validate = runner.invoke(
        main,
        ["validate", "--no-project-policy", "--skip-integrity", str(inventory)]
        + ["--project", str(DEMO)],
    )
    risk = runner.invoke(main, ["risk", "--no-project-policy", str(inventory)])
    return validate.exit_code, risk.exit_code


def test_leaving_a_collector_out_fails_validate_and_risk(runner, tmp_path):
    assert _gates(runner, tmp_path, ["prompt", "mcp"]) == (1, 1)
    every = sorted(BUILTIN_SCANNER_NAMES)
    assert _gates(runner, tmp_path, every[1:]) == (1, 1)
    assert _gates(runner, tmp_path, every) == (0, 0)
