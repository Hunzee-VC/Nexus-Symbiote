"""Broken pipes exit quietly, and line separators in instructions are findings."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from nexus_symbiote.scanners.prompt import PromptScanner, detect_invisible_characters


def test_a_closed_stdout_is_status_141_without_an_internal_error(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Keep the receipt.\n" * 20000)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "nexus_symbiote", "scan", str(project), "--report-only"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    assert process.stdout is not None
    process.stdout.close()
    _, err = process.communicate(timeout=60)
    assert process.returncode == 141
    assert b"internal error" not in err
    assert b"BrokenPipeError" not in err


def test_line_and_paragraph_separators_are_low_findings(tmp_path: Path) -> None:
    text = "Keep the receipt.\u2028Then send it.\u2029"
    risks = detect_invisible_characters(text, "CLAUDE.md")
    assert [(risk.category, risk.severity.value) for risk in risks] == [("line_separators", "low")]
    assert "U+2028" in risks[0].detail and "U+2029" in risks[0].detail
    (tmp_path / "CLAUDE.md").write_text(text)
    [component] = PromptScanner().scan(tmp_path).components
    recorded = [risk for risk in component.risks if risk.category == "line_separators"]
    assert [risk.severity.value for risk in recorded] == ["low"]
    ordinary = detect_invisible_characters("Keep the receipt.\u00a0\u3000", "CLAUDE.md")
    assert ordinary == []
