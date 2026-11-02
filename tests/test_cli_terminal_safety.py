"""Human-readable output prints inventory text literally: no markup, no terminal controls."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import MCPServerComponent, PromptComponent

MARKUP = "[link=https://attacker.example/approve]docs[/link][conceal]"
CONTROLS = "\x1b]8;;https://attacker.example\x07x\x1b]8;;\x07\x1b[1A\x1b[2K\rfake\u202egpj.exe"


def test_hostile_component_names_cannot_hide_a_critical_alert(tmp_path):
    server = MCPServerComponent(
        bom_ref="mcp:pay", name="payments", endpoint_url="https://trusted.example"
    )
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    old.write_text(AIBOM(components=[server]).to_json())
    new.write_text(
        AIBOM(
            components=[
                server.model_copy(update={"endpoint_url": "https://attacker.example"}),
                PromptComponent(bom_ref="prompt:1", name=MARKUP),
                PromptComponent(bom_ref="prompt:2", name=CONTROLS),
            ]
        ).to_json()
    )
    result = CliRunner().invoke(main, ["diff", str(old), str(new)])
    output = result.output
    assert "[CRITICAL] Critical change in 'payments'" in output
    assert MARKUP in output
    for character in ("\x1b", "\x07", "\r", "\u202e"):
        assert character not in output


def test_validate_shows_the_component_each_issue_belongs_to(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps(
            {"mcpServers": {"tickets": {"type": "http", "url": "https://mcp.example.com/mcp"}}}
        )
    )
    bom = tmp_path / "bom.json"
    runner = CliRunner()
    assert (
        runner.invoke(main, ["scan", str(project), "--report-only", "-o", str(bom)]).exit_code == 0
    )
    result = runner.invoke(
        main, ["validate", str(bom), "--project", str(project), "--no-project-policy"]
    )
    assert "[mcp-server:" in result.output, result.output


def test_validate_prints_dangling_graph_references_literally(tmp_path):
    hostile = "tool:" + MARKUP + CONTROLS
    server = MCPServerComponent(bom_ref="mcp:docs", name="docs", tool_refs=[hostile])
    bom = tmp_path / "bom.json"
    bom.write_text(AIBOM(components=[server]).to_json())
    result = CliRunner().invoke(main, ["validate", str(bom), "--no-project-policy"])
    assert "ERROR:" in result.output, result.output
    assert MARKUP in result.output
    for character in ("\x1b", "\x07", "\r", "\u202e"):
        assert character not in result.output


def test_risk_project_failure_reasons_print_without_terminal_controls(tmp_path):
    # File names are project data; reconciliation reasons quote the component ref.
    project = tmp_path / "project"
    (project / "models").mkdir(parents=True)
    hostile = "evil\x1b[1A\x1b[2K\rfake‮gpj"
    sample = Path(__file__).parents[1] / "examples/demo-agent/models/intent-classifier.safetensors"
    (project / "models" / f"{hostile}.safetensors").write_bytes(sample.read_bytes())
    bom = tmp_path / "bom.json"
    bom.write_text(AIBOM(components=[]).to_json())
    result = CliRunner().invoke(
        main, ["risk", str(bom), "--project", str(project), "--no-project-policy"]
    )
    assert result.exit_code == 1, result.output
    assert "Project reconciliation failed." in result.output
    assert "evil" in result.output and "fake" in result.output
    for character in ("\x1b", "\r", "‮"):
        assert character not in result.output
