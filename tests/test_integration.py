"""End-to-end integration tests: scan → validate → risk → diff pipeline."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM


def _create_full_project(root: Path) -> Path:
    """Build a project that exercises all scanners."""
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/data"],
                    },
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                        "env": {"GITHUB_TOKEN": "***"},
                    },
                }
            }
        )
    )
    (root / "CLAUDE.md").write_text("You are a helpful assistant that reviews code.")
    (root / ".cursorrules").write_text("Always use TypeScript strict mode.")

    skills = root / ".claude" / "skills"
    skills.mkdir(parents=True)
    (skills / "deploy.md").write_text("Deploy the application")

    (root / "requirements.txt").write_text("transformers==4.40.0\nlangchain>=0.1\nopenai==1.30.0\n")

    model_dir = root / "models"
    model_dir.mkdir()
    (model_dir / "model.safetensors").write_bytes(b"\x00" * 100)
    (model_dir / "config.json").write_text('{"model_type": "llama"}')

    (root / ".env.example").write_text("PINECONE_API_KEY=xxx\nPINECONE_INDEX=my-idx\n")

    return root


class TestFullPipeline:
    def test_scan_validate_risk_cycle(self, tmp_path: Path) -> None:
        """Full scan → validate → risk → summary pipeline."""
        project = tmp_path / "project"
        project.mkdir()
        _create_full_project(project)

        runner = CliRunner()
        bom_path = tmp_path / "aibom.json"

        scan = runner.invoke(main, ["scan", "--report-only", str(project), "-o", str(bom_path)])
        assert scan.exit_code == 0
        assert bom_path.exists()
        data = json.loads(bom_path.read_text())
        assert len(data["components"]) >= 3

        validate = runner.invoke(main, ["validate", str(bom_path)])
        assert "Completeness check" in validate.output
        assert "Integrity check" in validate.output

        risk = runner.invoke(main, ["risk", str(bom_path), "--json-output"])
        risk_data = json.loads(risk.output)
        assert "overall_score" in risk_data
        assert isinstance(risk_data["total_components"], int)

        summary = runner.invoke(main, ["summary", str(bom_path)])
        assert summary.exit_code == 0
        assert "Components:" in summary.output

    def test_diff_after_project_change(self, tmp_path: Path) -> None:
        """Scan, modify project, re-scan, diff the two snapshots."""
        project = tmp_path / "project"
        project.mkdir()
        _create_full_project(project)

        runner = CliRunner()
        bom_v1 = tmp_path / "v1.json"
        scan1 = runner.invoke(main, ["scan", "--report-only", str(project), "-o", str(bom_v1)])
        assert scan1.exit_code == 0

        (project / "requirements.txt").write_text(
            "transformers==4.41.0\nlangchain>=0.2\nopenai==1.31.0\nchromadb>=0.4\n"
        )

        bom_v2 = tmp_path / "v2.json"
        scan2 = runner.invoke(main, ["scan", "--report-only", str(project), "-o", str(bom_v2)])
        assert scan2.exit_code == 0

        diff = runner.invoke(main, ["diff", str(bom_v1), str(bom_v2), "--json-output"])
        assert diff.exit_code == 0
        diff_data = json.loads(diff.output)
        assert "has_changes" in diff_data

    def test_all_output_formats(self, tmp_path: Path) -> None:
        """Verify supported output formats produce valid JSON."""
        project = tmp_path / "project"
        project.mkdir()
        _create_full_project(project)

        runner = CliRunner()

        for fmt, key in [("json", "components"), ("cyclonedx", "bomFormat")]:
            out = tmp_path / f"out-{fmt}.json"
            result = runner.invoke(
                main, ["scan", "--report-only", str(project), "-f", fmt, "-o", str(out)]
            )
            assert result.exit_code == 0, f"{fmt} failed: {result.output}"
            data = json.loads(out.read_text())
            assert key in data, f"{fmt} output missing '{key}'"

    def test_scan_roundtrip_load(self, tmp_path: Path) -> None:
        """Scan output can be loaded back as an AIBOM."""
        project = tmp_path / "project"
        project.mkdir()
        _create_full_project(project)
        runner = CliRunner()
        bom_path = tmp_path / "roundtrip.json"
        runner.invoke(main, ["scan", "--report-only", str(project), "-o", str(bom_path)])
        bom = AIBOM.load(bom_path)
        assert len(bom.components) >= 3
        assert bom.metadata.completeness is not None
        assert bom.metadata.completeness.scope == "repository"

    def test_validate_against_project(self, tmp_path: Path) -> None:
        """Cross-validate a BOM against the project that produced it."""
        project = tmp_path / "project"
        project.mkdir()
        _create_full_project(project)
        runner = CliRunner()
        bom_path = tmp_path / "bom.json"
        runner.invoke(main, ["scan", "--report-only", str(project), "-o", str(bom_path)])
        result = runner.invoke(main, ["validate", str(bom_path), "--project", str(project)])
        assert "Completeness check" in result.output
        assert "Integrity check" in result.output

    def test_risk_gate_with_unsafe_model(self, tmp_path: Path) -> None:
        """A project with a pickle model should produce risk findings."""
        project = tmp_path / "project"
        project.mkdir()
        _create_full_project(project)
        unsafe = project / "models" / "extra.pkl"
        unsafe.write_bytes(b"\x00" * 50)
        runner = CliRunner()
        bom_path = tmp_path / "risky.json"
        runner.invoke(main, ["scan", "--report-only", str(project), "-o", str(bom_path)])
        result = runner.invoke(main, ["risk", str(bom_path), "--json-output"])
        data = json.loads(result.output)
        assert data["overall_score"] > 0
        assert data["components_with_risks"] >= 1
