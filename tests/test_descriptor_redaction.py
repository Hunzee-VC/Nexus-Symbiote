"""A display projection must omit schema instance data and retain the source fingerprint."""

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.core.models import ToolComponent
from nexus_symbiote.live.verify import record_candidate, verify_mcp_servers
from nexus_symbiote.scanners.live_mcp import _tool
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.validators.integrity import IntegrityValidator

SENTINEL = "synthetic-credential-in-schema-literal"


def descriptor():
    return {
        "name": "get_issue",
        "description": "Read https://docs.example.test/reference",
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "default": SENTINEL},
                "mode": {"anyOf": [{"const": SENTINEL}, {"enum": [SENTINEL]}]},
                "default": {"type": "string", "examples": [SENTINEL]},
            },
            "$defs": {"examples": {"type": "object", "default": {"nested": SENTINEL}}},
        },
    }


def write_config(root, tool):
    (root / ".mcp.json").write_text(
        json.dumps(
            {"mcpServers": {"mail": {"command": "npx", "args": ["mail@1.2.3"], "tools": [tool]}}}
        )
    )


def test_redacted_descriptor_validates_against_source_and_rejects_tampering(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    raw = descriptor()
    write_config(project, raw)
    target = tmp_path / "bom.json"
    runner = CliRunner()
    collected = runner.invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(target)]
    )
    assert collected.exit_code == 0, collected.output
    assert SENTINEL not in target.read_text()
    bom = AIBOM.load(target)
    tool = next(component for component in bom.components if isinstance(component, ToolComponent))
    assert tool.description_text == "Read https://docs.example.test"
    assert tool.input_schema["properties"]["default"] == {"type": "string"}
    assert tool.input_schema["$defs"]["examples"] == {"type": "object"}
    assert tool.definition_hash == hash_tool_definition(
        raw["name"], raw["description"], raw["inputSchema"]
    )
    assert tool.definition_hash != tool.redacted_definition_hash
    check = ["validate", str(target), "--no-project-policy", "--project", str(project)]
    assert runner.invoke(main, check).exit_code == 0
    assert IntegrityValidator().validate(bom).status == "unknown"
    assert not IntegrityValidator().validate(bom, project, exclude_paths=[".mcp.json"]).is_valid

    # Replacing the source secret even though both display schemas are identical is drift.
    raw["inputSchema"]["properties"]["api_key"]["default"] += "-changed"
    write_config(project, raw)
    assert runner.invoke(main, check).exit_code == 1
    write_config(project, descriptor())

    # A supplier can recompute a display hash, but cannot substitute it for source evidence.
    tool.description_text = "Altered displayed description"
    tool.redacted_definition_hash = hash_tool_definition(
        tool.name, tool.description_text, tool.input_schema
    )
    bom.save(target)
    assert runner.invoke(main, check).exit_code == 1
    tool.definition_hash = tool.redacted_definition_hash
    tool.redacted_definition_hash = None
    bom.save(target)
    assert runner.invoke(main, check).exit_code == 1


@pytest.mark.parametrize("fmt", ["json", "cyclonedx", "spdx", "sarif"])
def test_cli_exports_omit_credential_schema_literals(tmp_path, fmt):
    project = tmp_path / "project"
    project.mkdir()
    write_config(project, descriptor())
    target = tmp_path / "export.json"
    result = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-f", fmt, "-o", str(target)]
    )
    assert result.exit_code == 0, result.output
    assert SENTINEL not in target.read_text()


def test_live_https_and_recorded_stdio_omit_schema_values(tmp_path, monkeypatch):
    raw = descriptor()
    observed = _tool({**raw, "outputSchema": raw["inputSchema"]}, [])
    assert SENTINEL not in json.dumps(observed.descriptor)
    assert observed.descriptor["inputSchema"] == observed.descriptor["outputSchema"]

    write_config(tmp_path, raw)
    bom = AIBOM(components=MCPScanner().scan(tmp_path).components)
    monkeypatch.setattr(
        "nexus_symbiote.live.verify.fetch_tools_from_config", lambda *a, **kw: ("stdio", [raw])
    )
    report = verify_mcp_servers(bom)
    assert report.complete and not report.has_drift
    record_candidate(bom, report)
    assert SENTINEL not in bom.model_dump_json()
    recorded = next(
        component for component in bom.components if isinstance(component, ToolComponent)
    )
    assert recorded.definition_hash == hash_tool_definition(
        raw["name"], raw["description"], raw["inputSchema"]
    )
    assert recorded.redacted_definition_hash == hash_tool_definition(
        recorded.name, recorded.description_text, recorded.input_schema, recorded.annotations
    )
