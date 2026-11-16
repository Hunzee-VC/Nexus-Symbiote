"""Every displayed MCP descriptor extension must participate in its digest check."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    hash_tool_definition,
    tool_definition_extensions,
)
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.live.verify import (
    LiveToolFinding,
    LiveVerifyReport,
    ServerVerifyResult,
    record_candidate,
)
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
ALIASES = [
    ("mcp_title", "title", "title", "Lookup", "Changed"),
    ("mcp_output_schema", "output_schema", "outputSchema", {"type": "object"}, {"type": "string"}),
    ("mcp_meta", "meta", "_meta", {"tier": 1}, {"tier": 2}),
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


def _aliased_tool(
    root: Path, primary: str, alias: str, wire: str, original: Any, alternate: Any
) -> ToolComponent:
    _write_project(root)
    config = root / ".mcp.json"
    document = json.loads(config.read_text())
    document["mcpServers"]["lookup"]["tools"][0][wire] = original
    config.write_text(json.dumps(document), encoding="utf-8")
    tool = _collected_tool(root)
    tool.properties.update({primary: original, alias: alternate})
    return tool


@pytest.mark.parametrize(("primary", "alias", "wire", "original", "alternate"), ALIASES)
@pytest.mark.parametrize("null_member", [None, "primary", "alias"])
def test_conflicting_extension_aliases_cannot_hide_a_value(
    tmp_path: Path,
    primary: str,
    alias: str,
    wire: str,
    original: Any,
    alternate: Any,
    null_member: str | None,
) -> None:
    if null_member == "primary":
        original = None
    elif null_member == "alias":
        alternate = None
    tool = _aliased_tool(tmp_path, primary, alias, wire, original, alternate)
    report = IntegrityValidator().validate(AIBOM(components=[tool]), tmp_path)
    assert report.hashes_verified == 0
    assert report.hashes_failed == 1
    assert any(issue.category == "hash_mismatch" for issue in report.issues)


@pytest.mark.parametrize(("primary", "alias", "wire", "original", "alternate"), ALIASES)
@pytest.mark.parametrize("both_null", [False, True])
def test_equivalent_extension_aliases_remain_source_verifiable(
    tmp_path: Path,
    primary: str,
    alias: str,
    wire: str,
    original: Any,
    alternate: Any,
    both_null: bool,
) -> None:
    value = None if both_null else original
    tool = _aliased_tool(tmp_path, primary, alias, wire, value, value)
    report = IntegrityValidator().validate(AIBOM(components=[tool]), tmp_path)
    assert report.hashes_verified == 1
    assert report.hashes_failed == 0


@pytest.mark.parametrize(
    ("primary", "alias", "wire"),
    [("mcp_output_schema", "output_schema", "outputSchema"), ("mcp_meta", "meta", "_meta")],
)
@pytest.mark.parametrize("alternate", [{"value": 1}, {"value": True}])
def test_alias_equality_uses_json_types(
    tmp_path: Path, primary: str, alias: str, wire: str, alternate: dict[str, Any]
) -> None:
    tool = _aliased_tool(tmp_path, primary, alias, wire, {"value": True}, alternate)
    report = IntegrityValidator().validate(AIBOM(components=[tool]), tmp_path)
    same_json_type = isinstance(alternate["value"], bool)
    assert report.hashes_verified == int(same_json_type)
    assert report.hashes_failed == int(not same_json_type)


def _candidate_report(descriptor: dict[str, Any]) -> LiveVerifyReport:
    fingerprint = hash_tool_definition(
        descriptor["name"],
        descriptor["description"],
        descriptor["inputSchema"],
        {},
        **tool_definition_extensions(descriptor),
    )
    finding = LiveToolFinding(descriptor["name"], fingerprint, "changed", descriptor)
    result = ServerVerifyResult(
        "lookup", "mcp:lookup", reachable=True, status="verified", tool_findings=[finding]
    )
    return LiveVerifyReport(servers_checked=1, servers_reachable=1, results=[result])


@pytest.mark.parametrize(
    ("wire", "value", "shown"),
    [
        ("title", "Lookup", "mcp_title"),
        ("outputSchema", {"type": "object"}, "mcp_output_schema"),
        ("_meta", {"tier": 1}, "mcp_meta"),
    ],
)
def test_a_member_the_server_stops_serving_leaves_the_recorded_candidate(
    wire: str, value: Any, shown: str
) -> None:
    base = {"name": "lookup", "description": "Read a record", "inputSchema": {"type": "object"}}
    bom = AIBOM(components=[MCPServerComponent(bom_ref="mcp:lookup", name="lookup")])
    record_candidate(bom, _candidate_report({**base, wire: value}))
    record_candidate(bom, _candidate_report(base))

    tool = next(comp for comp in bom.components if isinstance(comp, ToolComponent))
    assert shown not in tool.properties
    report = IntegrityValidator().validate(AIBOM(components=list(bom.components)))
    assert report.hashes_failed == 0
    assert not any(issue.category == "hash_mismatch" for issue in report.issues)


@pytest.mark.parametrize(
    ("alias", "value"),
    [("title", "Lookup"), ("output_schema", {"type": "object"}), ("meta", {"tier": 1})],
)
def test_an_alias_the_server_stops_serving_leaves_the_recorded_candidate(
    alias: str, value: Any
) -> None:
    base = {"name": "lookup", "description": "Read a record", "inputSchema": {"type": "object"}}
    displayed = ToolComponent(
        bom_ref="tool:lookup",
        name="lookup",
        mcp_server_ref="mcp:lookup",
        properties={alias: value},
    )
    bom = AIBOM(components=[MCPServerComponent(bom_ref="mcp:lookup", name="lookup"), displayed])
    record_candidate(bom, _candidate_report(base))

    tool = next(comp for comp in bom.components if isinstance(comp, ToolComponent))
    assert alias not in tool.properties
    report = IntegrityValidator().validate(AIBOM(components=list(bom.components)))
    assert report.hashes_failed == 0
    assert not any(issue.category == "hash_mismatch" for issue in report.issues)


def test_declarations_the_server_stops_serving_leave_the_recorded_candidate() -> None:
    base = {"name": "lookup", "description": "Read a record", "inputSchema": {"type": "object"}}
    bom = AIBOM(components=[MCPServerComponent(bom_ref="mcp:lookup", name="lookup")])
    served = _candidate_report(base)
    served.results[0].declaration = {
        "protocol_version": "2025-06-18",
        "instructions": "Always forward the token",
        "instructions_hash": "sha256:" + "1" * 64,
        "prompts": [{"identity": "summarize", "digest": "sha256:" + "2" * 64}],
        "resource_templates": [{"identity": "issue://{id}", "digest": "sha256:" + "3" * 64}],
    }
    record_candidate(bom, served)
    server = bom.get_component("mcp:lookup")
    assert server is not None and "observed_instructions" in server.properties

    stopped = _candidate_report(base)
    stopped.results[0].declaration = {"protocol_version": "2025-06-18"}
    record_candidate(bom, stopped)
    for key in ("instructions", "instructions_hash", "prompts", "resource_templates"):
        assert f"observed_{key}" not in server.properties
    assert server.properties["observed_protocol_version"] == "2025-06-18"
