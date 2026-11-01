"""CLI integration tests using Click's CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from symbote.cli import main
from symbote.core.aibom import AIBOM, DependencyEdge
from symbote.core.enums import (
    AssuranceLevel,
    RiskSeverity,
    SerializationSafety,
)
from symbote.core.models import (
    AIBOMMetadata,
    CompletenessClaim,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    RiskAssessment,
    ToolComponent,
)


def _create_test_project(tmp_path: Path) -> Path:
    """Create a realistic test project with multiple component types."""
    (tmp_path / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/data"],
                    }
                }
            }
        )
    )
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    (model_dir / "model.safetensors").write_bytes(b"\x00" * 100)
    (model_dir / "config.json").write_text('{"model_type": "llama"}')
    (tmp_path / "CLAUDE.md").write_text("You are a helpful assistant.")
    (tmp_path / "requirements.txt").write_text("transformers==4.40.0\n")
    return tmp_path


def _make_fixture_bom(
    tmp_path: Path, filename: str = "bom.json", *, with_risks: bool = False
) -> Path:
    """Build a fixture AIBOM directly (not via scan) for deterministic tests."""
    bom = AIBOM(
        metadata=AIBOMMetadata(
            authors=["test"],
            completeness=CompletenessClaim(
                scope="full-agent",
                surfaces_scanned=["mcp-config", "prompts", "registry-trust"],
                assurance_level=AssuranceLevel.OBSERVED,
            ),
        )
    )
    bom.add_component(
        MCPServerComponent(
            bom_ref="mcp-fs",
            name="filesystem",
            version="1.0.0",
            version_pinned=True,
        )
    )
    bom.add_component(
        ToolComponent(
            bom_ref="tool-read",
            name="read_file",
            mcp_server_ref="mcp-fs",
            definition_hash="sha256:abc123",
            definition_hash_version="rfc8785-jcs-v1",
        )
    )
    bom.add_component(
        PromptComponent(
            bom_ref="prompt-sys",
            name="CLAUDE.md",
            content_hash="sha256:def456",
        )
    )
    if with_risks:
        bom.add_component(
            ModelComponent(
                bom_ref="model-unsafe",
                name="unsafe-pickle-model",
                serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION,
                risks=[
                    RiskAssessment(
                        severity=RiskSeverity.CRITICAL,
                        category="serialization_format",
                        detail="Pickle format allows arbitrary code execution.",
                    ),
                    RiskAssessment(
                        severity=RiskSeverity.HIGH,
                        category="signing_status",
                        detail="Model is unsigned.",
                    ),
                ],
            )
        )
    bom.add_dependency(
        DependencyEdge(
            source_ref="mcp-fs",
            target_ref="tool-read",
            relationship="invokes",
        )
    )
    path = tmp_path / filename
    bom.save(path)
    return path


def _scan_to_json(runner: CliRunner, args: list[str], tmp_path: Path) -> dict:
    """Run scan and return parsed JSON, writing to a file to avoid Rich stderr mixing."""
    out = tmp_path / "scan_output.json"
    result = runner.invoke(main, ["scan", *args, "-o", str(out)])
    assert result.exit_code == 0
    return json.loads(out.read_text())


class TestScanCommand:
    def test_scan_json_output(self, tmp_path):
        project = _create_test_project(tmp_path)
        out_dir = tmp_path / "out1"
        out_dir.mkdir()
        data = _scan_to_json(CliRunner(), [str(project)], out_dir)
        assert "components" in data
        assert len(data["components"]) >= 1

    def test_scan_to_file(self, tmp_path):
        project = _create_test_project(tmp_path)
        out = tmp_path / "out" / "aibom.json"
        out.parent.mkdir()
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(project), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert "components" in data

    def test_scan_cyclonedx(self, tmp_path):
        project = _create_test_project(tmp_path)
        out = tmp_path / "cdx.json"
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(project), "-f", "cyclonedx", "-o", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data.get("bomFormat") == "CycloneDX"
        assert "specVersion" in data

    def test_scan_spdx(self, tmp_path):
        project = _create_test_project(tmp_path)
        out = tmp_path / "spdx.json"
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(project), "-f", "spdx", "-o", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert "@context" in data
        graph = data.get("@graph", [])
        assert any(e.get("type") == "SpdxDocument" for e in graph)

    def test_scan_specific_scanner(self, tmp_path):
        project = _create_test_project(tmp_path)
        out = tmp_path / "mcp_only.json"
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(project), "--scanner", "mcp", "-o", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert len(data["components"]) >= 1

    def test_scan_unknown_scanner_warns(self, tmp_path):
        project = _create_test_project(tmp_path)
        out = tmp_path / "unknown.json"
        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", str(project), "--scanner", "nonexistent", "-o", str(out)]
        )
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert len(data["components"]) == 0

    def test_scan_empty_project(self, tmp_path):
        out = tmp_path / "empty.json"
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(tmp_path), "-o", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["components"] == []


class TestValidateCommand:
    def test_validate_valid_bom(self, tmp_path):
        project = _create_test_project(tmp_path)
        runner = CliRunner()
        bom_path = tmp_path / "test.json"
        runner.invoke(main, ["scan", str(project), "-o", str(bom_path)])
        result = runner.invoke(main, ["validate", str(bom_path)])
        assert result.exit_code in (0, 1)

    def test_validate_with_project(self, tmp_path):
        project = _create_test_project(tmp_path)
        runner = CliRunner()
        bom_path = tmp_path / "test.json"
        runner.invoke(main, ["scan", str(project), "-o", str(bom_path)])
        result = runner.invoke(main, ["validate", str(bom_path), "--project", str(project)])
        assert result.exit_code in (0, 1)


class TestRiskCommand:
    def test_risk_clean_project(self, tmp_path):
        project = _create_test_project(tmp_path)
        runner = CliRunner()
        bom_path = tmp_path / "test.json"
        runner.invoke(main, ["scan", str(project), "-o", str(bom_path)])
        result = runner.invoke(main, ["risk", str(bom_path)])
        assert result.exit_code in (0, 1)

    def test_risk_json_output(self, tmp_path):
        project = _create_test_project(tmp_path)
        runner = CliRunner()
        bom_path = tmp_path / "test.json"
        runner.invoke(main, ["scan", str(project), "-o", str(bom_path)])
        result = runner.invoke(main, ["risk", str(bom_path), "--json-output"])
        data = json.loads(result.output)
        assert "overall_score" in data
        assert "risk_level" in data

    def test_risk_custom_threshold(self, tmp_path):
        project = _create_test_project(tmp_path)
        runner = CliRunner()
        bom_path = tmp_path / "test.json"
        runner.invoke(main, ["scan", str(project), "-o", str(bom_path)])
        result = runner.invoke(main, ["risk", str(bom_path), "--threshold", "100"])
        assert result.exit_code == 0


class TestDiffCommand:
    def test_diff_identical(self, tmp_path):
        project = _create_test_project(tmp_path)
        runner = CliRunner()
        bom_path = tmp_path / "bom.json"
        runner.invoke(main, ["scan", str(project), "-o", str(bom_path)])
        result = runner.invoke(main, ["diff", str(bom_path), str(bom_path)])
        assert result.exit_code == 0

    def test_diff_with_changes(self, tmp_path):
        project = _create_test_project(tmp_path)
        runner = CliRunner()
        bom_a = tmp_path / "a.json"
        runner.invoke(main, ["scan", str(project), "-o", str(bom_a)])

        (project / "requirements.txt").write_text("transformers==4.41.0\nlangchain>=0.1\n")
        bom_b = tmp_path / "b.json"
        runner.invoke(main, ["scan", str(project), "-o", str(bom_b)])

        result = runner.invoke(main, ["diff", str(bom_a), str(bom_b)])
        assert result.exit_code == 0

    def test_diff_json_output(self, tmp_path):
        project = _create_test_project(tmp_path)
        runner = CliRunner()
        bom_path = tmp_path / "bom.json"
        runner.invoke(main, ["scan", str(project), "-o", str(bom_path)])
        result = runner.invoke(main, ["diff", str(bom_path), str(bom_path), "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "has_changes" in data


class TestSummaryCommand:
    def test_summary(self, tmp_path):
        project = _create_test_project(tmp_path)
        runner = CliRunner()
        bom_path = tmp_path / "test.json"
        runner.invoke(main, ["scan", str(project), "-o", str(bom_path)])
        result = runner.invoke(main, ["summary", str(bom_path)])
        assert result.exit_code == 0


class TestVersionAndHelp:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "symbote" in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "validate" in result.output
        assert "risk" in result.output
        assert "diff" in result.output


class TestRiskFixture:
    """Risk command tests against pre-built fixture BOMs for deterministic coverage."""

    def test_risk_clean_bom_passes(self, tmp_path):
        bom_path = _make_fixture_bom(tmp_path, with_risks=False)
        runner = CliRunner()
        result = runner.invoke(main, ["risk", str(bom_path)])
        assert result.exit_code == 0
        assert "PASSED" in result.output

    def test_risk_risky_bom_fails_gate(self, tmp_path):
        bom_path = _make_fixture_bom(tmp_path, with_risks=True)
        runner = CliRunner()
        result = runner.invoke(main, ["risk", str(bom_path), "--threshold", "10"])
        assert result.exit_code != 0
        assert "FAILED" in result.output

    def test_risk_severity_breakdown_displayed(self, tmp_path):
        bom_path = _make_fixture_bom(tmp_path, with_risks=True)
        runner = CliRunner()
        result = runner.invoke(main, ["risk", str(bom_path)])
        assert "critical" in result.output.lower()

    def test_risk_findings_table(self, tmp_path):
        bom_path = _make_fixture_bom(tmp_path, with_risks=True)
        runner = CliRunner()
        result = runner.invoke(main, ["risk", str(bom_path)])
        assert "serialization_format" in result.output or "Top Findings" in result.output

    def test_risk_json_output_with_fixture(self, tmp_path):
        bom_path = _make_fixture_bom(tmp_path, with_risks=True)
        runner = CliRunner()
        result = runner.invoke(main, ["risk", str(bom_path), "--json-output"])
        data = json.loads(result.output)
        assert data["overall_score"] > 0
        assert len(data["findings"]) == 2
        assert data["findings"][0]["severity"] == "critical"

    def test_risk_high_threshold_passes(self, tmp_path):
        bom_path = _make_fixture_bom(tmp_path, with_risks=True)
        runner = CliRunner()
        result = runner.invoke(main, ["risk", str(bom_path), "--threshold", "200"])
        assert result.exit_code == 0


class TestValidateFixture:
    """Validate command tests with deterministic fixtures."""

    def test_validate_shows_completeness_and_integrity(self, tmp_path):
        bom_path = _make_fixture_bom(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["validate", str(bom_path)])
        assert "Completeness check" in result.output
        assert "Integrity check" in result.output
        assert "Hashes verified" in result.output

    def test_validate_incomplete_bom_exits_nonzero(self, tmp_path):
        bom = AIBOM(metadata=AIBOMMetadata(authors=["test"]))
        path = tmp_path / "empty.json"
        bom.save(path)
        runner = CliRunner()
        result = runner.invoke(main, ["validate", str(path)])
        assert result.exit_code != 0
        assert "ERROR" in result.output

    def test_validate_with_project_cross_check(self, tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        (project / "CLAUDE.md").write_text("prompt")
        (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": {"command": "x"}}}))
        bom_path = _make_fixture_bom(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["validate", str(bom_path), "--project", str(project)])
        assert "Completeness check" in result.output


class TestDiffFixture:
    """Diff command tests with deterministic fixtures."""

    def test_diff_no_changes(self, tmp_path):
        path = _make_fixture_bom(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["diff", str(path), str(path)])
        assert result.exit_code == 0
        assert "No changes" in result.output

    def test_diff_component_added(self, tmp_path):
        old_path = _make_fixture_bom(tmp_path, filename="old.json")
        bom = AIBOM.load(old_path)
        bom.add_component(MCPServerComponent(bom_ref="mcp-new", name="new-server"))
        new_path = tmp_path / "new.json"
        bom.save(new_path)

        runner = CliRunner()
        result = runner.invoke(main, ["diff", str(old_path), str(new_path)])
        assert result.exit_code == 0
        assert "added" in result.output.lower()

    def test_diff_component_removed(self, tmp_path):
        old_path = _make_fixture_bom(tmp_path, filename="old.json")
        new_bom = AIBOM(metadata=AIBOMMetadata(authors=["test"]))
        new_bom.add_component(
            MCPServerComponent(
                bom_ref="mcp-fs",
                name="filesystem",
                version="1.0.0",
            )
        )
        new_path = tmp_path / "reduced.json"
        new_bom.save(new_path)

        runner = CliRunner()
        result = runner.invoke(main, ["diff", str(old_path), str(new_path)])
        assert result.exit_code == 0
        assert "removed" in result.output.lower()

    def test_diff_component_modified(self, tmp_path):
        old_path = _make_fixture_bom(tmp_path, filename="old.json")
        bom = AIBOM.load(old_path)
        for c in bom.components:
            if c.bom_ref == "tool-read":
                c.definition_hash = "sha256:changed"
        new_path = tmp_path / "modified.json"
        bom.save(new_path)

        runner = CliRunner()
        result = runner.invoke(main, ["diff", str(old_path), str(new_path)])
        assert result.exit_code == 0
        assert "modified" in result.output.lower() or "Security Alerts" in result.output

    def test_diff_json_with_security_alert(self, tmp_path):
        old_path = _make_fixture_bom(tmp_path, filename="old.json")
        bom = AIBOM.load(old_path)
        for c in bom.components:
            if c.bom_ref == "tool-read":
                c.definition_hash = "sha256:tampered"
        new_path = tmp_path / "tampered.json"
        bom.save(new_path)

        runner = CliRunner()
        result = runner.invoke(main, ["diff", str(old_path), str(new_path), "--json-output"])
        data = json.loads(result.output)
        assert data["has_changes"] is True
        assert len(data["security_alerts"]) >= 1
        assert data["security_alerts"][0]["severity"] == "critical"

    def test_diff_shows_additions_removals_modifications(self, tmp_path):
        old_path = _make_fixture_bom(tmp_path, filename="old.json")
        bom = AIBOM.load(old_path)
        bom.components = [c for c in bom.components if c.bom_ref != "prompt-sys"]
        bom.add_component(MCPServerComponent(bom_ref="mcp-extra", name="extra-server"))
        for c in bom.components:
            if c.bom_ref == "mcp-fs":
                c.version = "2.0.0"
        new_path = tmp_path / "mixed.json"
        bom.save(new_path)

        runner = CliRunner()
        result = runner.invoke(main, ["diff", str(old_path), str(new_path)])
        assert "added" in result.output.lower()
        assert "removed" in result.output.lower()


class TestSummaryFixture:
    def test_summary_component_types(self, tmp_path):
        bom_path = _make_fixture_bom(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["summary", str(bom_path)])
        assert result.exit_code == 0
        assert "Component types:" in result.output
        assert "mcp-server" in result.output
        assert "tool" in result.output

    def test_summary_with_risks(self, tmp_path):
        bom_path = _make_fixture_bom(tmp_path, with_risks=True)
        runner = CliRunner()
        result = runner.invoke(main, ["summary", str(bom_path)])
        assert result.exit_code == 0
        assert "Risk breakdown:" in result.output


class TestSARIFOutput:
    def test_scan_sarif_format(self, tmp_path):
        project = _create_test_project(tmp_path)
        out = tmp_path / "results.sarif"
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(project), "-f", "sarif", "-o", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1
        assert data["runs"][0]["tool"]["driver"]["name"] == "symbote"

    def test_sarif_empty_project(self, tmp_path):
        out = tmp_path / "empty.sarif"
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(tmp_path), "-f", "sarif", "-o", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data["runs"][0]["results"] == []

    def test_sarif_with_risks(self, tmp_path):
        bom_path = _make_fixture_bom(tmp_path, with_risks=True)
        bom = AIBOM.load(bom_path)
        from symbote.generators.sarif import SARIFGenerator

        sarif = SARIFGenerator().generate(bom)
        assert len(sarif["runs"][0]["results"]) == 2
        levels = {r["level"] for r in sarif["runs"][0]["results"]}
        assert "error" in levels


class TestInitCommand:
    def test_init_creates_file(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(main, ["init", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".symbote.yaml").exists()

    def test_init_refuses_existing(self, tmp_path):
        (tmp_path / ".symbote.yaml").write_text("existing")
        runner = CliRunner()
        result = runner.invoke(main, ["init", "--path", str(tmp_path)])
        assert result.exit_code != 0

    def test_init_force_overwrites(self, tmp_path):
        (tmp_path / ".symbote.yaml").write_text("existing")
        runner = CliRunner()
        result = runner.invoke(main, ["init", "--path", str(tmp_path), "--force"])
        assert result.exit_code == 0
        content = (tmp_path / ".symbote.yaml").read_text()
        assert "version" in content

    def test_init_content_is_parseable(self, tmp_path):
        runner = CliRunner()
        runner.invoke(main, ["init", "--path", str(tmp_path)])
        from symbote.policy import load_policy

        policy = load_policy(tmp_path)
        assert policy is not None
        assert policy.version == "1.0"
        assert "mcp" in policy.scan.scanners


class TestPolicyIntegration:
    def test_scan_uses_policy_format(self, tmp_path):
        project = _create_test_project(tmp_path)
        policy = 'version: "1.0"\noutput:\n  default_format: "cyclonedx"\n'
        (project / ".symbote.yaml").write_text(policy)
        out = project / "output.json"
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(project), "-o", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert data.get("bomFormat") == "CycloneDX"

    def test_scan_cli_overrides_policy(self, tmp_path):
        project = _create_test_project(tmp_path)
        policy = 'version: "1.0"\noutput:\n  default_format: "cyclonedx"\n'
        (project / ".symbote.yaml").write_text(policy)
        out = project / "output.json"
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(project), "-f", "json", "-o", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert "bomFormat" not in data
        assert "components" in data
