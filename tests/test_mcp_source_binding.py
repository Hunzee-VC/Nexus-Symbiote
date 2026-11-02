"""A static MCP baseline must match freshly collected, unredacted source data."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.core.models import ClaimEvidence, MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.validators.completeness import CompletenessValidator


def _baseline(
    tmp_path: Path, *, endpoint: str | None = None, command: str = "npx"
) -> tuple[Path, Path, dict]:
    root = tmp_path / "project"
    root.mkdir()
    config = {
        "mcpServers": {
            "local": {
                "command": command,
                "args": ["trusted-tool@1.2.3"],
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a file",
                        "inputSchema": {"type": "object"},
                        "annotations": {"readOnlyHint": True},
                    }
                ],
            }
        }
    }
    if endpoint:
        config["mcpServers"]["local"]["url"] = endpoint
    (root / ".mcp.json").write_text(json.dumps(config))
    output = tmp_path / "bom.json"
    run = CliRunner().invoke(
        main,
        ["scan", "--no-project-policy", "--report-only", str(root), "-o", str(output)],
    )
    assert run.exit_code == 0, run.output
    # Use exactly the saved collector result: do not forge complete metadata.
    original = _validate(root, output)
    assert original.exit_code == 0, original.output
    return root, output, config


def _validate(root: Path, output: Path):
    return CliRunner().invoke(
        main, ["validate", "--no-project-policy", str(output), "--project", str(root)]
    )


@pytest.mark.parametrize("field", ["description", "inputSchema", "annotations"])
def test_changed_local_descriptor_rejects_unchanged_baseline(tmp_path, field):
    root, output, config = _baseline(tmp_path)
    replacement = {
        "description": "Send private content to an external endpoint",
        "inputSchema": {"type": "object", "required": ["secret"]},
        "annotations": {"destructiveHint": True},
    }
    config["mcpServers"]["local"]["tools"][0][field] = replacement[field]
    (root / ".mcp.json").write_text(json.dumps(config))

    run = _validate(root, output)
    assert run.exit_code == 1, run.output
    assert "Missing or mismatched local component" in run.output


@pytest.mark.parametrize(
    "change", ["package", "argument", "environment", "endpoint-path", "command"]
)
def test_changed_launcher_rejects_unchanged_baseline(tmp_path, change):
    root, output, config = _baseline(
        tmp_path,
        endpoint="https://example.test/original" if change == "endpoint-path" else None,
        command="/usr/bin/trusted-tool" if change == "command" else "npx",
    )
    server = config["mcpServers"]["local"]
    if change == "package":
        server["args"] = ["malicious-tool@1.2.3"]
    elif change == "argument":
        server["args"] = ["trusted-tool@1.2.3", "--allow-unrestricted"]
    elif change == "environment":
        server["env"] = {"NODE_OPTIONS": "--require=/tmp/replacement.js"}
    elif change == "command":
        server["command"] = "/usr/bin/replacement-tool"
    else:
        server["url"] = "https://example.test/replacement"
    (root / ".mcp.json").write_text(json.dumps(config))

    run = _validate(root, output)
    assert run.exit_code == 1, run.output
    assert "Missing or mismatched local component" in run.output


@pytest.mark.parametrize("served_claim", [False, True])
def test_self_consistent_replacement_descriptor_is_not_source_corroboration(tmp_path, served_claim):
    root, output, _ = _baseline(tmp_path)
    bom = AIBOM.load(output)
    tool = next(c for c in bom.components if isinstance(c, ToolComponent))
    tool.description_text = "Replacement descriptor"
    tool.input_schema = {"type": "object", "required": ["credential"]}
    tool.definition_hash = hash_tool_definition(
        tool.name, tool.description_text, tool.input_schema, tool.annotations
    )
    if served_claim:
        tool.claims["tool_definition"] = ClaimEvidence(
            method="operator-pinned-stdio-tools-list", scope="served-descriptor"
        )
    bom.save(output)

    run = _validate(root, output)
    assert run.exit_code == 1, run.output
    assert "Missing or mismatched local component" in run.output
    assert "Integrity check" in run.output


@pytest.mark.parametrize("missing", ["static_config_hash", "static_config_hash_profile", "profile"])
def test_legacy_missing_source_binding_is_unknown_and_requires_recollection(tmp_path, missing):
    root, output, _ = _baseline(tmp_path)
    bom = AIBOM.load(output)
    server = next(c for c in bom.components if isinstance(c, MCPServerComponent))
    if missing == "profile":
        server.properties["static_config_hash_profile"] = "unsupported-legacy-profile"
    else:
        server.properties.pop(missing)

    report = CompletenessValidator().validate_against_project(bom, root)
    assert not report.is_complete
    assert any(i.severity == "unknown" and "re-collect" in i.description for i in report.issues)


def test_static_binding_ignores_json_key_order_and_omits_plaintext_secrets(tmp_path):
    config = {
        "mcpServers": {
            "private": {
                "command": "/secret/private-launcher",
                "args": ["--token", "private-argument-token"],
                "env": {"API_KEY": "private-environment-value"},
                "url": "https://user:private-password@example.test/private-path?key=hidden",
            }
        }
    }
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps(config))
    first = MCPScanner().scan(tmp_path)
    server = next(c for c in first.components if isinstance(c, MCPServerComponent))
    exported = server.model_dump_json()
    for secret in (
        "/secret/private-launcher",
        "private-argument-token",
        "private-environment-value",
        "private-password",
        "private-path",
        "hidden",
    ):
        assert secret not in exported
    assert server.properties["static_config_hash"].startswith("sha256:")
    original = config["mcpServers"]["private"]
    config["mcpServers"]["private"] = dict(reversed(list(original.items())))
    path.write_text(json.dumps(config, indent=4))
    second = MCPScanner().scan(tmp_path)
    reordered = next(c for c in second.components if isinstance(c, MCPServerComponent))
    assert server.properties["static_config_hash"] == reordered.properties["static_config_hash"]
