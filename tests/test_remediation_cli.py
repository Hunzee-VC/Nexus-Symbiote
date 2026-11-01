"""CLI tests for the remediation: exit codes, policy handling, gates, and import safety."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import cli as cli_module
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import CompletenessClaim, MCPServerComponent
from nexus_symbiote.core.vocab import REQUIRED_SCANNERS
from nexus_symbiote.scanners.base import ScanResult
from tests.test_cli import _create_test_project, _make_fixture_bom


def _complete_fixture(tmp_path: Path, *, with_risks: bool = False) -> Path:
    path = _make_fixture_bom(tmp_path, with_risks=with_risks)
    bom = AIBOM.load(path)
    bom.metadata.completeness = CompletenessClaim(
        scope="full-agent",
        surfaces_scanned=["mcp-config", "prompts"],
        scanner_status=dict.fromkeys(REQUIRED_SCANNERS, "complete"),
        assurance_level=AssuranceLevel.OBSERVED,
    )
    bom.save(path)
    return path


class TestImportShadowScan:
    def test_native_report_imports_to_valid_aibom(self, tmp_path: Path) -> None:
        report = tmp_path / "report.json"
        report.write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "id": "f1",
                            "kind": "mcp-server",
                            "title": "srv",
                            "resource": "https://user:pw@example.com/mcp?token=abc",
                            "risk": {"level": "high", "score": 80},
                        },
                        {"id": "f2", "kind": "agent", "title": "helper"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        out = tmp_path / "aibom.json"
        result = CliRunner().invoke(main, ["import-shadowscan", str(report), "-o", str(out)])
        assert result.exit_code == 0, result.output
        bom = AIBOM.load(out)
        assert len(bom.components) == 2
        text = out.read_text(encoding="utf-8")
        assert "shadowscan:raw" not in text
        assert "token=abc" not in text
        assert "user:pw" not in text
        assert "unassessed-discovery" in text

    def test_symlinked_report_is_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "real.json"
        real.write_text('{"findings": []}', encoding="utf-8")
        link = tmp_path / "link.json"
        link.symlink_to(real)
        out = tmp_path / "aibom.json"
        result = CliRunner().invoke(main, ["import-shadowscan", str(link), "-o", str(out)])
        assert result.exit_code == 2
        assert not out.exists()


class TestExitCodes:
    def test_validate_missing_input_is_usage_error(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(main, ["validate", str(tmp_path / "missing.json")])
        assert result.exit_code == 2

    def test_risk_on_non_aibom_is_usage_error(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("[1, 2, 3]", encoding="utf-8")
        result = CliRunner().invoke(main, ["risk", str(bad)])
        assert result.exit_code == 2

    def test_unexpected_error_exits_three(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("NEXUS_SYMBIOTE_DEBUG", raising=False)
        bom_path = _make_fixture_bom(tmp_path)

        def boom(path: Path) -> AIBOM:
            raise RuntimeError("boom")

        monkeypatch.setattr(cli_module, "_load_aibom", boom)
        result = CliRunner().invoke(main, ["risk", str(bom_path)])
        assert result.exit_code == 3

    def test_diff_invalid_fail_on_is_usage_error(self, tmp_path: Path) -> None:
        path = _make_fixture_bom(tmp_path)
        result = CliRunner().invoke(main, ["diff", str(path), str(path), "--fail-on", "severe"])
        assert result.exit_code == 2

    def test_init_force_overwrites_with_exit_zero(self, tmp_path: Path) -> None:
        (tmp_path / ".nexus-symbiote.yaml").write_text("existing", encoding="utf-8")
        result = CliRunner().invoke(main, ["init", "--path", str(tmp_path), "--force"])
        assert result.exit_code == 0
        assert "version" in (tmp_path / ".nexus-symbiote.yaml").read_text(encoding="utf-8")


class TestRiskPolicyHandling:
    def test_risk_does_not_discover_policy(self, tmp_path: Path) -> None:
        bom_path = _complete_fixture(tmp_path)
        (tmp_path / ".nexus-symbiote.yaml").write_text(
            "risk:\n  fail_threshold: 90.0\n", encoding="utf-8"
        )
        result = CliRunner().invoke(main, ["risk", str(bom_path), "--json-output"])
        assert json.loads(result.output)["policy"] is None

    def test_symlinked_policy_is_usage_error(self, tmp_path: Path) -> None:
        bom_path = _complete_fixture(tmp_path)
        real = tmp_path / "real-policy.yaml"
        real.write_text("risk:\n  fail_threshold: 90.0\n", encoding="utf-8")
        link = tmp_path / "link-policy.yaml"
        link.symlink_to(real)
        result = CliRunner().invoke(main, ["risk", str(bom_path), "--policy", str(link)])
        assert result.exit_code == 2

    def test_out_of_range_policy_value_is_rejected_without_echo(self, tmp_path: Path) -> None:
        bom_path = _complete_fixture(tmp_path)
        policy = tmp_path / "bad.yaml"
        policy.write_text("risk:\n  fail_threshold: 987.25\n", encoding="utf-8")
        result = CliRunner().invoke(main, ["risk", str(bom_path), "--policy", str(policy)])
        assert result.exit_code == 2
        assert "987" not in result.output
        assert "fail_threshold" in result.output

    def test_ignored_category_never_hides_critical_finding(self, tmp_path: Path) -> None:
        bom_path = _complete_fixture(tmp_path, with_risks=True)
        policy = tmp_path / "ignore.yaml"
        policy.write_text(
            'risk:\n  fail_threshold: 100.0\n  ignore_categories: ["serialization_format"]\n',
            encoding="utf-8",
        )
        result = CliRunner().invoke(
            main, ["risk", str(bom_path), "--policy", str(policy), "--json-output"]
        )
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["suppressed"] == 0
        assert any(f["severity"] == "critical" for f in data["findings"])

    def test_complete_fixture_passes_gate(self, tmp_path: Path) -> None:
        bom_path = _complete_fixture(tmp_path)
        result = CliRunner().invoke(main, ["risk", str(bom_path), "--json-output"])
        assert result.exit_code == 0
        assert json.loads(result.output)["coverage_status"] == "complete"


class TestScanCoverageThroughCli:
    def test_repository_without_optional_surfaces_is_complete_and_passes(
        self, tmp_path: Path
    ) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        out = tmp_path / "empty-aibom.json"
        runner = CliRunner()
        scan = runner.invoke(main, ["scan", str(empty), "--policy", "none", "-o", str(out)])
        assert scan.exit_code == 0, scan.output
        status = json.loads(out.read_text(encoding="utf-8"))["metadata"]["completeness"]
        assert status["scanner_status"]["mcp"] == "complete"
        gate = runner.invoke(main, ["risk", str(out), "--json-output"])
        assert gate.exit_code == 0
        assert json.loads(gate.output)["coverage_status"] == "complete"

    def test_excluded_path_makes_scanner_partial(self, tmp_path: Path) -> None:
        project = _create_test_project(tmp_path)
        policy = tmp_path / "exclude.yaml"
        policy.write_text(
            'scan:\n  exclude_paths: ["models", "node_modules", ".git", "__pycache__", ".venv"]\n',
            encoding="utf-8",
        )
        out = tmp_path / "partial.json"
        result = CliRunner().invoke(
            main, ["scan", str(project), "--policy", str(policy), "-o", str(out)]
        )
        assert result.exit_code == 0, result.output
        claim = json.loads(out.read_text(encoding="utf-8"))["metadata"]["completeness"]
        assert claim["scanner_status"]["model"] == "partial"
        assert claim["surfaces_excluded"]

    def test_dropped_file_records_failure_and_fails_gate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _DroppingScanner:
            def scan(self, project_root: Path) -> ScanResult:
                result = ScanResult(scanner_name="mcp")
                result.record_failure("mcp: dropped mcp.json during read")
                return result

        monkeypatch.setattr(
            cli_module,
            "_build_scanner",
            lambda name, cls, policy, shadow_report: _DroppingScanner(),
        )
        project = _create_test_project(tmp_path)
        out = tmp_path / "failed.json"
        runner = CliRunner()
        scan = runner.invoke(main, ["scan", str(project), "--scanner", "mcp", "-o", str(out)])
        assert scan.exit_code == 1
        claim = json.loads(out.read_text(encoding="utf-8"))["metadata"]["completeness"]
        assert claim["scanner_status"]["mcp"] == "failed"
        gate = runner.invoke(main, ["risk", str(out), "--json-output"])
        assert gate.exit_code == 1
        assert json.loads(gate.output)["coverage_status"] == "failed"


class TestDiffFailOn:
    def _removed_tool_pair(self, tmp_path: Path) -> tuple[Path, Path]:
        old = _make_fixture_bom(tmp_path, filename="old.json")
        bom = AIBOM.load(old)
        bom.components = [c for c in bom.components if c.bom_ref != "tool-read"]
        new = tmp_path / "new.json"
        bom.save(new)
        return old, new

    def test_high_change_fails_default_gate(self, tmp_path: Path) -> None:
        old, new = self._removed_tool_pair(tmp_path)
        result = CliRunner().invoke(main, ["diff", str(old), str(new)])
        assert result.exit_code == 1

    def test_high_change_passes_critical_gate(self, tmp_path: Path) -> None:
        old, new = self._removed_tool_pair(tmp_path)
        result = CliRunner().invoke(main, ["diff", str(old), str(new), "--fail-on", "critical"])
        assert result.exit_code == 0

    def test_fail_on_none_never_fails(self, tmp_path: Path) -> None:
        old, new = self._removed_tool_pair(tmp_path)
        result = CliRunner().invoke(main, ["diff", str(old), str(new), "--fail-on", "none"])
        assert result.exit_code == 0

    def test_medium_change_respects_threshold(self, tmp_path: Path) -> None:
        old = _make_fixture_bom(tmp_path, filename="old.json")
        bom = AIBOM.load(old)
        bom.add_component(MCPServerComponent(bom_ref="mcp-extra", name="extra"))
        new = tmp_path / "new.json"
        bom.save(new)
        runner = CliRunner()
        assert runner.invoke(main, ["diff", str(old), str(new)]).exit_code == 0
        assert runner.invoke(main, ["diff", str(old), str(new), "--fail-on", "medium"]).exit_code == 1

    def test_json_output_with_failing_gate_is_still_parseable(self, tmp_path: Path) -> None:
        old, new = self._removed_tool_pair(tmp_path)
        result = CliRunner().invoke(main, ["diff", str(old), str(new), "--json-output"])
        assert result.exit_code == 1
        assert json.loads(result.output)["has_changes"] is True
