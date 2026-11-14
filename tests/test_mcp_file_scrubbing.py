"""Token-shaped launcher packages are withheld, and one server's secret values are
scrubbed from every server of the same file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner

# Assembled at run time so the source holds no token-shaped literal. OCI repositories
# are lower-case, so the image case uses a lower-case body.
TOKEN = "".join(("gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"))
LOWER_TOKEN = TOKEN.lower()
DIGEST = "sha256:" + "a" * 64
RUNNERS = {
    "npx": ("npx", ["-y", f"{TOKEN}@1.0.0"]),
    "uvx": ("uvx", ["--from", f"{TOKEN}==1.0", "tool"]),
    "go": ("go", ["run", f"github.com/org/{TOKEN}@v1"]),
    "docker": ("docker", ["run", "-i", "--rm", f"reg.example/{LOWER_TOKEN}@{DIGEST}"]),
}
SECRET = "hunter2xyz"  # noqa: S105 - synthetic fixture


def _scan(root: Path, servers: dict[str, Any]):
    root.mkdir(parents=True, exist_ok=True)
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    return MCPScanner().scan(root)


def _server(result, name: str) -> MCPServerComponent:
    return next(
        c
        for c in result.components
        if isinstance(c, MCPServerComponent) and c.source_path == ".mcp.json" and name in c.name
    )


@pytest.mark.parametrize("runner", sorted(RUNNERS))
def test_token_shaped_package_identity_is_withheld(tmp_path, runner):
    command, args = RUNNERS[runner]
    result = _scan(tmp_path, {"s": {"command": command, "args": args}})
    assert not result.scan_failures, result.scan_failures
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    text = server.model_dump_json()
    assert TOKEN not in text
    assert TOKEN[4:].lower() not in text.lower()
    assert server.launcher_package is None
    assert server.package_url is None
    assert server.version is None
    assert [p["identity"] for p in server.properties["packages"]] == ["[withheld]"]
    assert ".mcp.json: MCP server 's' identity withheld by environment-value redaction" in (
        result.surfaces_excluded
    )
    (gap,) = [
        r for r in server.risks if r.category == "completeness" and r.severity.value == "medium"
    ]
    assert "launcher package" in gap.detail
    assert TOKEN not in json.dumps(result.surfaces_excluded + result.scan_failures)


def test_an_ordinary_package_identity_is_kept(tmp_path):
    result = _scan(
        tmp_path,
        {"s": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@2025.4.8"]}},
    )
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert server.launcher_package == "npm:@modelcontextprotocol/server-github"
    assert server.package_url == "pkg:npm/%40modelcontextprotocol/server-github@2025.4.8"
    assert not [
        r for r in server.risks if r.category == "completeness" and r.severity.value == "medium"
    ]


@pytest.mark.parametrize(
    "holder",
    [
        {"env": {"DB_PASSWORD": SECRET}},
        {"type": "http", "url": "https://a.example/mcp", "headers": {"X-Api-Key": SECRET}},
        {"type": "http", "url": "https://a.example/mcp", "http_headers": {"Authorization": SECRET}},
    ],
)
def test_one_servers_secret_value_is_scrubbed_from_every_server_of_the_file(tmp_path, holder):
    servers = {
        "a": {"command": "node", "args": ["a.js"], **holder},
        f"b-{SECRET}": {
            "command": "node",
            "args": ["b.js"],
            "tools": [
                {
                    "name": f"login-{SECRET}",
                    "description": f"Logs in with {SECRET} and lists tickets.",
                }
            ],
        },
    }
    result = _scan(tmp_path, servers)
    assert not result.scan_failures, result.scan_failures
    server = _server(result, "b-")
    (tool,) = [c for c in result.components if isinstance(c, ToolComponent)]
    for component in (server, tool):
        text = component.model_dump_json()
        assert SECRET not in text
        assert "***" in text
    assert server.name == "b-***"
    assert tool.name == "login-***"
    assert "name" in next(
        r.detail for r in server.risks if r.category == "completeness" and "withheld" in r.detail
    )
    assert SECRET not in json.dumps(result.surfaces_excluded + result.scan_failures)


def test_values_of_another_file_are_not_scrubbed(tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"a": {"command": "node", "env": {"DB_PASSWORD": SECRET}}}})
    )
    (project / ".vscode").mkdir()
    (project / ".vscode" / "mcp.json").write_text(
        json.dumps(
            {
                "servers": {
                    "b": {
                        "command": "node",
                        "tools": [{"name": f"login-{SECRET}", "description": "Logs in."}],
                    }
                }
            }
        )
    )
    result = MCPScanner().scan(project)
    (tool,) = [c for c in result.components if isinstance(c, ToolComponent)]
    assert tool.name == f"login-{SECRET}"


def _credential_servers(count: int, per_server: int) -> dict[str, Any]:
    return {
        f"server{index}": {
            "command": "uvx",
            "args": [f"tool{index}==1.0"],
            "env": {
                f"TOKEN_{entry}": f"credential-{index:03d}-{entry:03d}-value"
                for entry in range(per_server)
            },
        }
        for index in range(count)
    }


def test_a_file_at_the_credential_bound_is_collected(tmp_path):
    from nexus_symbiote.scanners.mcp import MAX_SECRETS_PER_FILE

    result = _scan(tmp_path / "project", _credential_servers(16, MAX_SECRETS_PER_FILE // 16))
    assert not result.scan_failures
    servers = [c for c in result.components if isinstance(c, MCPServerComponent)]
    assert len(servers) == 16


def test_a_file_over_the_credential_bound_is_a_named_failure(tmp_path):
    # Every server's text is scrubbed of every credential in its file, so the work
    # grows with servers times values; past the bound the file is not collected.
    from nexus_symbiote.scanners.mcp import MAX_SECRETS_PER_FILE

    per_server = MAX_SECRETS_PER_FILE // 16
    result = _scan(tmp_path / "project", _credential_servers(17, per_server))
    assert result.scan_failures == [
        f".mcp.json: more than {MAX_SECRETS_PER_FILE} credential values in one file; not collected"
    ]
    assert not [c for c in result.components if isinstance(c, MCPServerComponent)]
