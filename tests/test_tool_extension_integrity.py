"""Every displayed MCP descriptor extension must participate in its digest check."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import TOOL_DEFINITION_HASH_VERSION, hash_tool_definition
from nexus_symbiote.core.models import ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.validators.integrity import IntegrityValidator

EXTENSIONS = [
    ("mcp_title", "Changed title"),
    ("title", "Changed title"),
    ("mcp_output_schema", {"type": "string"}),
    ("output_schema", {"type": "string"}),
    ("mcp_meta", {"instruction": "Changed metadata"}),
    ("meta", {"instruction": "Changed metadata"}),
]


def _write_project(root: Path, *, redacted: bool = False, extended: bool = False) -> None:
    descriptor: dict[str, Any] = {
        "name": "lookup",
        "description": "Read a record",
        "inputSchema": {"type": "object"},
    }
    if redacted:
        descriptor["inputSchema"]["properties"] = {
            "mode": {"type": "string", "enum": ["private-mode"]}
        }
    if extended:
        descriptor.update(title="Lookup", outputSchema={"type": "object"}, _meta={"tier": 1})
    (root / "CLAUDE.md").write_text("Use the configured tools.\n", encoding="utf-8")
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "lookup": {
                        "command": "npx",
                        "args": ["-y", "lookup-mcp@1.2.3"],
                        "tools": [descriptor],
                    }
                }
            }
        ),
        encoding="utf-8",
    )


def _collected_tool(root: Path) -> ToolComponent:
    return next(
        comp
        for comp in MCPScanner().scan(root, config_only=True).components
        if isinstance(comp, ToolComponent)
    )


@pytest.mark.parametrize(("key", "value"), EXTENSIONS)
@pytest.mark.parametrize("redacted", [False, True])
@pytest.mark.parametrize("with_project", [False, True])
def test_added_extension_cannot_match_an_extension_free_digest(
    tmp_path: Path, key: str, value: Any, redacted: bool, with_project: bool
) -> None:
    _write_project(tmp_path, redacted=redacted)
    tool = _collected_tool(tmp_path)
    assert (tool.redacted_definition_hash is not None) is redacted
    tool.properties[key] = value

    report = IntegrityValidator().validate(
        AIBOM(components=[tool]), project_root=tmp_path if with_project else None
    )

    assert report.hashes_verified == 0
    assert report.hashes_failed == 1
    assert any(issue.category == "hash_mismatch" for issue in report.issues)


@pytest.mark.parametrize("redacted", [False, True])
@pytest.mark.parametrize("extended", [False, True])
def test_unchanged_static_descriptors_still_reconcile_with_source(
    tmp_path: Path, redacted: bool, extended: bool
) -> None:
    _write_project(tmp_path, redacted=redacted, extended=extended)
    tool = _collected_tool(tmp_path)
    report = IntegrityValidator().validate(AIBOM(components=[tool]), project_root=tmp_path)
    assert report.hashes_verified == 1
    assert report.hashes_failed == 0


@pytest.mark.parametrize("mutation", ["title", "output_schema", "meta"])
def test_legacy_display_hash_cannot_hide_changed_extended_descriptor(mutation: str) -> None:
    extensions: dict[str, Any] = {
        "title": "Lookup",
        "output_schema": {"type": "object"},
        "meta": {"tier": 1},
    }
    fingerprint = hash_tool_definition("lookup", "Read a record", {}, {}, **extensions)
    display = hash_tool_definition("lookup", "Read a record", {}, {})
    tool = ToolComponent(
        bom_ref="tool:legacy",
        name="lookup",
        description_text="Read a record",
        input_schema={},
        definition_hash=fingerprint,
        definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
        redacted_definition_hash=display,
        properties=extensions,
    )
    # The historical pairing remains readable when the complete descriptor
    # matches the original digest; no local evidence means it stays unknown.
    unchanged = IntegrityValidator().validate(AIBOM(components=[tool]))
    assert unchanged.hashes_failed == 0
    assert unchanged.hashes_verified == 0
    assert any(issue.category == "descriptor_source_unavailable" for issue in unchanged.issues)

    tool.properties[mutation] = "Changed" if mutation == "title" else {"changed": True}
    changed = IntegrityValidator().validate(AIBOM(components=[tool]))
    assert changed.hashes_failed == 1
    assert changed.hashes_verified == 0
    assert any(issue.category == "hash_mismatch" for issue in changed.issues)


def test_validate_gate_rejects_added_descriptor_metadata(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write_project(project)
    inventory = tmp_path / "inventory.json"
    runner = CliRunner()
    scan = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(inventory)])
    assert scan.exit_code == 0, scan.output
    bom = AIBOM.load(inventory)
    tool = next(comp for comp in bom.components if isinstance(comp, ToolComponent))
    tool.properties["mcp_meta"] = {"instruction": "Changed metadata"}
    bom.save(inventory)

    result = runner.invoke(
        main,
        [
            "validate",
            str(inventory),
            "--project",
            str(project),
            "--no-project-policy",
            "--json-output",
        ],
    )
    report = json.loads(result.output)
    assert result.exit_code != 0, result.output
    assert report["passed"] is False
    assert report["integrity"]["hashes_failed"] == 1
