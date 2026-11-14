"""The demo results quoted in the README and the examples walkthrough match a real scan."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV

ROOT = Path(__file__).resolve().parents[1]
WORDS = [
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
]


def _demo(tmp_path: Path, monkeypatch) -> tuple[dict, dict]:
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    runner = CliRunner()
    output = tmp_path / "demo.aibom.json"
    scanned = runner.invoke(
        main, ["scan", str(ROOT / "examples" / "demo-agent"), "-o", str(output)]
    )
    assert scanned.exit_code == 0, scanned.output
    scored = runner.invoke(main, ["risk", str(output), "--no-project-policy", "--json-output"])
    return json.loads(output.read_text()), json.loads(scored.stdout)


def test_readme_demo_numbers(tmp_path, monkeypatch):
    bom, report = _demo(tmp_path, monkeypatch)
    quoted = re.search(
        r"records (\d+) components across (\d+) types and (\w+) findings \(risk score (\d+),",
        (ROOT / "README.md").read_text(encoding="utf-8"),
    )
    assert quoted, "the README no longer states the demo result in the expected sentence"
    components, types, findings, score = quoted.groups()
    assert int(components) == len(bom["components"])
    assert int(types) == len({c["component_type"] for c in bom["components"]})
    assert findings == WORDS[len(report["findings"])]
    assert float(score) == report["overall_score"]


def test_examples_walkthrough_numbers(tmp_path, monkeypatch):
    bom, report = _demo(tmp_path, monkeypatch)
    text = (ROOT / "examples" / "README.md").read_text(encoding="utf-8")
    quoted = re.search(
        r"record (\d+) components across (\d+) types\..{0,120}?score (\d+),.{0,80}?"
        r"from (\w+) high, (\w+) medium and (\w+) low findings:",
        text,
        re.S,
    )
    assert quoted, "the walkthrough no longer states the demo result in the expected sentence"
    components, types, score, high, medium, low = quoted.groups()
    severities = Counter(finding["severity"] for finding in report["findings"])
    assert int(components) == len(bom["components"])
    assert int(types) == len({c["component_type"] for c in bom["components"]})
    assert float(score) == report["overall_score"]
    assert [high, medium, low] == [WORDS[severities[name]] for name in ("high", "medium", "low")]
