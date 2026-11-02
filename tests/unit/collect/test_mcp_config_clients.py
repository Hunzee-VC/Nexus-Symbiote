"""Long-tail client formats verified on 2026-11-01: globs, list shapes, field aliases and client-wide settings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from symbiote.collect.base import CollectContext, run_collectors
from symbiote.collect.mcp_config import McpConfigCollector
from symbiote.model.entities import ToolDefinition, ToolServer
from symbiote.model.enums import Transport


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.fixture
def scene(tmp_path: Path) -> tuple[Path, Path]:
    repo, home = tmp_path / "repo", tmp_path / "home"
    repo.mkdir()
    _write(
        home / ".config" / "goose" / "config.yaml",
        "GOOSE_MODE: auto\nextensions:\n  developer:\n    type: builtin\n    enabled: true\n"
        "  fetch:\n    type: stdio\n    cmd: uvx\n    args: [mcp-server-fetch]\n    envs: {API_TOKEN: secret-value}\n    enabled: true\n"
        "  remote:\n    type: streamable_http\n    uri: https://mcp.example.com/mcp\n",
    )
    _write(
        repo / "opencode.json",
        json.dumps(
            {
                "permission": "allow",
                "mcp": {
                    "local": {
                        "type": "local",
                        "command": ["npx", "-y", "srv@1.0.0"],
                        "environment": {"KEY": "{env:KEY}"},
                    },
                    "remote": {"type": "remote", "url": "https://x.example/mcp", "enabled": False},
                },
            }
        ),
    )
    _write(
        repo / ".continue" / "mcpServers" / "db.yaml",
        "name: db\nversion: 0.0.1\nmcpServers:\n  - name: sqlite\n    command: uvx\n    args: [mcp-server-sqlite]\n",
    )
    _write(
        home / ".config" / "zed" / "settings.json",
        '{ // zed\n "agent": {"tool_permissions": {"default": "allow"}},\n "context_servers": {"git": {"command": {"path": "uvx", "args": ["mcp-server-git"], "env": {}}}},\n}',
    )
    _write(
        home / ".cline" / "data" / "settings" / "cline_mcp_settings.json",
        json.dumps(
            {
                "mcpServers": {
                    "gh": {"command": "npx", "args": ["-y", "gh-mcp"], "autoApprove": ["list_issues"]}
                }
            }
        ),
    )
    _write(
        repo / ".roo" / "mcp.json",
        json.dumps(
            {"mcpServers": {"fs": {"command": "npx", "args": ["fs-mcp@1.2.3"], "alwaysAllow": ["read_file"]}}}
        ),
    )
    _write(
        repo / ".kiro" / "settings" / "mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "aws": {
                        "command": "uvx",
                        "args": ["aws-mcp==1.0"],
                        "autoApprove": ["describe"],
                        "disabled": True,
                    }
                }
            }
        ),
    )
    _write(
        home / ".aws" / "amazonq" / "cli-agents" / "dev.json",
        json.dumps(
            {"allowedTools": ["@git"], "mcpServers": {"git": {"command": "uvx", "args": ["mcp-server-git"]}}}
        ),
    )
    _write(
        home / ".copilot" / "mcp-config.json",
        json.dumps(
            {"mcpServers": {"web": {"type": "http", "url": "https://api.example.com/mcp", "tools": ["*"]}}}
        ),
    )
    _write(
        home / ".lmstudio" / "mcp.json",
        json.dumps({"mcpServers": {"hf": {"url": "https://huggingface.co/mcp"}}}),
    )
    _write(
        home / ".openclaw" / "openclaw.json",
        '{ "mcp": { "servers": { "notes": { "command": "node", "args": ["notes.js"] } } } }',
    )
    _write(
        repo / ".devcontainer" / "devcontainer.json",
        '{ "customizations": { "vscode": { "mcp": { "servers": { "dc": { "type": "stdio", "command": "npx", "args": ["dc-mcp"] } } } } } }',
    )
    _write(
        home / ".config" / "Code" / "User" / "profiles" / "abc123" / "mcp.json",
        '{ "servers": { "prof": { "type": "sse", "url": "https://p.example/sse" } } }',
    )
    _write(
        home / ".gemini" / "extensions" / "ext1" / "gemini-extension.json",
        json.dumps({"name": "ext1", "mcpServers": {"extsrv": {"command": "node", "args": ["x.js"]}}}),
    )
    _write(
        home / ".cursor" / "plugins" / "local" / "plug" / "mcp.json",
        json.dumps({"mcpServers": {"plugsrv": {"url": "https://plug.example/mcp"}}}),
    )
    _write(
        home / ".codeium" / "mcp_config.json",
        json.dumps({"mcpServers": {"alt": {"serverUrl": "https://alt.example/mcp"}}}),
    )
    return repo, home


def test_long_tail_clients(scene: tuple[Path, Path]) -> None:
    repo, home = scene
    result = run_collectors(CollectContext(root=repo, home=home, platform="linux"), [McpConfigCollector()])[0]
    servers = {e.id: e for e in result.entities if isinstance(e, ToolServer)}
    expected = {
        "server:goose-fetch", "server:goose-remote", "server:opencode-local", "server:opencode-remote",
        "server:continue-sqlite", "server:zed-git", "server:cline-gh", "server:roo-fs", "server:kiro-aws",
        "server:amazon-q-git", "server:github-copilot-cli-web", "server:lm-studio-hf", "server:openclaw-notes",
        "server:vscode-dc", "server:vscode-prof", "server:gemini-cli-extsrv", "server:cursor-plugsrv", "server:windsurf-alt",
    }  # fmt: skip
    assert expected <= set(servers), sorted(expected - set(servers))
    assert "server:goose-developer" not in servers  # builtin extensions are not external servers

    goose = servers["server:goose-fetch"]
    assert goose.transport.value is Transport.STDIO
    assert goose.env_var_names == ["API_TOKEN"]
    assert goose.client_trust_flags["goose.GOOSE_MODE"] == "auto"
    assert servers["server:goose-remote"].transport.value is Transport.STREAMABLE_HTTP

    local = servers["server:opencode-local"]
    assert local.package is not None and local.package.value is not None and not local.package.value.floating
    assert local.env_var_names == ["KEY"]
    assert local.client_trust_flags["opencode.permission"] == "allow"
    assert "disabled" in servers["server:opencode-remote"].tags

    assert servers["server:zed-git"].command == "uvx"
    assert servers["server:zed-git"].client_trust_flags["zed.agent.tool_permissions.default"] == "allow"
    assert servers["server:cline-gh"].client_trust_flags["cline.autoApprove"] == "list_issues"
    assert servers["server:roo-fs"].client_trust_flags["roo.alwaysAllow"] == "read_file"
    assert "disabled" in servers["server:kiro-aws"].tags
    assert servers["server:amazon-q-git"].client_trust_flags["amazon-q.allowedTools"] == "@git"
    assert servers["server:github-copilot-cli-web"].client_trust_flags["github-copilot-cli.tools"] == "*"

    tools = {e.id for e in result.entities if isinstance(e, ToolDefinition)}
    assert {"tool:cline-gh/list_issues", "tool:roo-fs/read_file", "tool:kiro-aws/describe"} <= tools
    blob = json.dumps([e.to_json_dict() for e in result.entities])
    assert "secret-value" not in blob


def test_windows_only_locations(tmp_path: Path) -> None:
    home = tmp_path / "home"
    appdata = home / "AppData" / "Roaming"
    _write(
        appdata / "Zed" / "settings.json", '{"context_servers": {"w": {"command": "node", "args": ["w.js"]}}}'
    )
    _write(
        appdata / "Block" / "goose" / "config" / "config.yaml",
        "extensions:\n  w2:\n    type: stdio\n    cmd: node\n",
    )
    win = run_collectors(
        CollectContext(root=tmp_path / "r", home=home, platform="windows"), [McpConfigCollector()]
    )[0]
    ids = {e.id for e in win.entities if isinstance(e, ToolServer)}
    assert {"server:zed-w", "server:goose-w2"} <= ids
    lin = run_collectors(
        CollectContext(root=tmp_path / "r", home=home, platform="linux"), [McpConfigCollector()]
    )[0]
    assert not {e.id for e in lin.entities if isinstance(e, ToolServer)} & {"server:zed-w", "server:goose-w2"}
