"""A failed gate says why, on the terminal, without the reader opening the inventory."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import PromptComponent, RiskAssessment
from nexus_symbiote.scanners.base import Scanner, ScanResult


def _scanner(result: ScanResult) -> dict[str, type[Scanner]]:
    class Fixed(Scanner):
        name = "fixed"

        def scan(self, project_root: Path) -> ScanResult:
            return result

    return {"fixed": Fixed}


def _prompt(*risks: RiskAssessment) -> PromptComponent:
    return PromptComponent(
        bom_ref="prompt:a", name="a", content_hash="sha256:" + "0" * 64, risks=list(risks)
    )


def _run(tmp_path, monkeypatch, result: ScanResult, *extra: str):
    monkeypatch.setattr("nexus_symbiote.cli._get_scanners", lambda: _scanner(result))
    output = tmp_path / "bom.json"
    args = ["scan", str(tmp_path), "--no-project-policy", "--scanner", "fixed", "-o", str(output)]
    return CliRunner().invoke(main, [*args, *extra]), output


def test_scan_names_the_collection_failure_that_failed_the_gate(tmp_path, monkeypatch):
    result = ScanResult(
        scanner_name="fixed", components=[_prompt()], scan_failures=["notes.md: invalid UTF-8"]
    )
    run, _ = _run(tmp_path, monkeypatch, result)
    assert run.exit_code == 1
    assert "Scan gate failed" in run.output
    assert "collection: notes.md: invalid UTF-8" in run.output


def test_scan_names_the_risk_reason_that_failed_the_gate(tmp_path, monkeypatch):
    risk = RiskAssessment(
        severity=RiskSeverity.CRITICAL, category="prompt_integrity", detail="hidden text"
    )
    run, _ = _run(
        tmp_path, monkeypatch, ScanResult(scanner_name="fixed", components=[_prompt(risk)])
    )
    assert run.exit_code == 1
    assert "critical" in run.output.split("Scan gate failed", 1)[1].lower()


def test_report_only_shows_the_same_reasons_and_exits_zero(tmp_path, monkeypatch):
    result = ScanResult(
        scanner_name="fixed", components=[_prompt()], scan_failures=["notes.md: invalid UTF-8"]
    )
    run, _ = _run(tmp_path, monkeypatch, result, "--report-only")
    assert run.exit_code == 0
    assert "collection: notes.md: invalid UTF-8" in run.output


def test_long_failure_lists_are_summarized(tmp_path, monkeypatch):
    failures = [f"file_{index}.md: invalid UTF-8" for index in range(25)]
    result = ScanResult(scanner_name="fixed", components=[_prompt()], scan_failures=failures)
    run, _ = _run(tmp_path, monkeypatch, result)
    assert "file_19.md" in run.output
    assert "file_20.md" not in run.output
    assert "5 more in metadata.completeness.scan_failures" in run.output


def test_reasons_are_neutralized_for_the_terminal(tmp_path, monkeypatch):
    hostile = "evil\x1b[2J[bold]name.md: invalid UTF-8"
    result = ScanResult(scanner_name="fixed", components=[_prompt()], scan_failures=[hostile])
    run, _ = _run(tmp_path, monkeypatch, result)
    assert run.exit_code == 1
    assert "\x1b" not in run.output
    assert "[bold]name.md: invalid UTF-8" in run.output


def test_risk_command_names_the_reasons(tmp_path, monkeypatch):
    result = ScanResult(
        scanner_name="fixed", components=[_prompt()], scan_failures=["notes.md: invalid UTF-8"]
    )
    _, output = _run(tmp_path, monkeypatch, result, "--report-only")
    run = CliRunner().invoke(main, ["risk", str(output)])
    assert run.exit_code == 1
    assert "collection: notes.md: invalid UTF-8" in run.output


def test_one_gate_report_lists_each_collection_failure_once(tmp_path, monkeypatch):
    # scan, risk and baseline share reporting.gate_reason_lines: the failure is a
    # "collection:" line naming its collector in scan, and risk does not repeat it
    # among the coverage gaps that restate the inventory's failures.
    result = ScanResult(
        scanner_name="fixed", components=[_prompt()], scan_failures=["notes.md: invalid UTF-8"]
    )
    scanned, output = _run(tmp_path, monkeypatch, result, "--report-only")
    assert "  - collection: notes.md: invalid UTF-8 (from fixed)" in scanned.stderr.splitlines()
    run = CliRunner().invoke(main, ["risk", str(output)])
    assert run.exit_code == 1
    assert run.stdout.count("notes.md: invalid UTF-8") == 1
    assert "  - collection: notes.md: invalid UTF-8" in run.stdout.splitlines()
