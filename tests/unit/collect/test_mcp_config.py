"""mcp-config collector across clients, scopes, trust settings and credential handling."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from symbiote.collect.base import CollectContext, run_collectors
from symbiote.collect.mcp_config import McpConfigCollector
from symbiote.model.entities import CredentialBinding, Identity, ToolDefinition, ToolServer
from symbiote.model.enums import (
    AuthMode,
    CoverageStatus,
    CredentialKind,
    CredentialStorageKind,
    EdgeType,
    Launcher,
    Surface,
    Transport,
    TrustZone,
    ValueState,
)

GH_PAT = "ghp_" + "Z" * 36


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.fixture
def scene(tmp_path: Path) -> tuple[Path, Path]:
    repo, home = tmp_path / "repo", tmp_path / "home"
    _write(
        repo / ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": GH_PAT},
                    },
                    "linear": {
                        "type": "http",
                        "url": "https://mcp.linear.app/mcp",
                        "headers": {"Authorization": "Bearer ${LINEAR_TOKEN}"},
                    },
                    "fetch": {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]},
                }
            }
        ),
    )
    _write(
        repo / ".claude" / "settings.json",
        json.dumps(
            {
                "permissions": {
                    "allow": ["mcp__github__create_issue", "Bash(ls:*)"],
                    "defaultMode": "acceptEdits",
                },
                "enableAllProjectMcpServers": True,
            }
        ),
    )
    _write(
        repo / ".vscode" / "mcp.json",
        """{
          // VS Code uses "servers" and allows comments
          "inputs": [{"type": "promptString", "id": "pat", "password": true}],
          "servers": {
            "github": {"type": "http", "url": "https://api.githubcopilot.com/mcp/", "headers": {"Authorization": "Bearer ${input:pat}"}},
            "local": {"command": "node", "args": ["./server.js"]},
          },
        }""",
    )
    _write(repo / ".vscode" / "settings.json", '{"chat.tools.autoApprove": true, // yolo\n}')
    _write(
        repo / ".gemini" / "settings.json",
        json.dumps(
            {
                "mcpServers": {
                    "db": {
                        "httpUrl": "http://localhost:8080/mcp",
                        "trust": True,
                        "includeTools": ["query", "schema"],
                    }
                }
            }
        ),
    )
    _write(
        repo / ".codex" / "config.toml",
        'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n\n[mcp_servers.docs]\ncommand = "docker"\n'
        'args = ["run", "-i", "--rm", "--network=host", "ghcr.io/acme/docs-mcp:1.0"]\nenabled_tools = ["search"]\n',
    )
    _write(
        home / ".claude.json",
        json.dumps(
            {
                "mcpServers": {"sentry": {"type": "sse", "url": "https://mcp.sentry.dev/sse"}},
                "projects": {
                    str(repo): {
                        "mcpServers": {
                            "pg": {
                                "command": "npx",
                                "args": ["-y", "@acme/pg-mcp", "postgres://u:pw@db.internal/app"],
                            }
                        }
                    },
                    "/somewhere/else": {"mcpServers": {"private": {"command": "secret-tool"}}},
                },
                "oauthAccount": {"emailAddress": "someone@example.com"},
            }
        ),
    )
    _write(
        home / ".cursor" / "mcp.json",
        json.dumps({"mcpServers": {"bad": "not-an-object", "ok": {"url": "https://x.test/sse"}}}),
    )
    _write(home / ".codeium" / "windsurf" / "mcp_config.json", "{ broken json")
    return repo, home


def _servers(results: list) -> dict[str, ToolServer]:
    return {e.id: e for r in results for e in r.entities if isinstance(e, ToolServer)}


def test_project_and_user_scopes(scene: tuple[Path, Path]) -> None:
    repo, home = scene
    ctx = CollectContext(root=repo, home=home, platform="linux", agent_id="agent:triage")
    results = run_collectors(ctx, [McpConfigCollector()])
    servers = _servers(results)
    assert set(servers) == {
        "server:claude-code-github",
        "server:claude-code-linear",
        "server:claude-code-fetch",
        "server:claude-code-sentry",
        "server:claude-code-pg",
        "server:vscode-github",
        "server:vscode-local",
        "server:gemini-cli-db",
        "server:codex-docs",
        "server:cursor-ok",
    }
    assert "server:claude-code-private" not in servers  # other projects in ~/.claude.json are out of scope

    gh = servers["server:claude-code-github"]
    assert gh.transport.value is Transport.STDIO
    assert gh.trust_zone is TrustZone.LOCAL_PROCESS
    assert gh.package is not None and gh.package.value is not None
    assert gh.package.value.floating and gh.package.value.launcher is Launcher.NPX
    assert gh.package.value.purl == "pkg:npm/%40modelcontextprotocol/server-github"
    assert gh.env_var_names == ["GITHUB_PERSONAL_ACCESS_TOKEN"]
    assert gh.client_trust_flags["claude-code.permissions.allow"] == "create_issue"
    assert gh.client_trust_flags["claude-code.enableAllProjectMcpServers"] == "true"
    assert gh.client_trust_flags["claude-code.defaultMode.project"] == "acceptEdits"
    assert "float:no-version" in gh.tags
    assert gh.digest is not None and gh.digest.startswith("sha256:")
    assert gh.provenance.locator == ".mcp.json#/mcpServers/github"

    fetch = servers["server:claude-code-fetch"]
    assert fetch.package is not None and fetch.package.value is not None and not fetch.package.value.floating

    linear = servers["server:claude-code-linear"]
    assert linear.transport.value is Transport.STREAMABLE_HTTP
    assert linear.endpoint is not None and linear.endpoint.value == "https://mcp.linear.app/mcp"
    assert linear.authentication.value is not None and linear.authentication.value.mode is AuthMode.API_KEY
    assert linear.crosses_trust_boundary.value is True
    assert linear.trust_zone is TrustZone.EXTERNAL

    sentry = servers["server:claude-code-sentry"]
    assert sentry.transport.value is Transport.SSE
    assert sentry.authentication.state is ValueState.UNKNOWN  # OAuth may be negotiated at connect time

    vs = servers["server:vscode-github"]
    assert vs.client_trust_flags["vscode.chat.tools.autoApprove"] == "true"
    assert "local-command" in servers["server:vscode-local"].tags

    db = servers["server:gemini-cli-db"]
    assert db.trust_zone is TrustZone.LOOPBACK and db.crosses_trust_boundary.value is False
    assert db.client_trust_flags["gemini-cli.trust"] == "true"

    docs = servers["server:codex-docs"]
    assert docs.client_trust_flags["codex.approval_policy"] == "never"
    assert docs.client_trust_flags["codex.sandbox_mode"] == "danger-full-access"
    assert docs.client_trust_flags["codex.container-risks"] == "host-network"
    assert (
        docs.package is not None
        and docs.package.value is not None
        and docs.package.value.launcher is Launcher.DOCKER
    )


def test_credentials_names_only_and_bindings(scene: tuple[Path, Path]) -> None:
    repo, home = scene
    results = run_collectors(CollectContext(root=repo, home=home, platform="linux"), [McpConfigCollector()])
    result = results[0]
    dump = json.dumps([e.to_json_dict() for e in result.entities]) + json.dumps(
        [e.to_json_dict() for e in result.edges]
    )
    assert GH_PAT not in dump
    assert "pw@" not in dump and "someone@example.com" not in dump
    bindings = {e.id: e for e in result.entities if isinstance(e, CredentialBinding)}
    inline = bindings["cred:claude-code-github-env-github_personal_access_token"]
    assert inline.credential_kind is CredentialKind.STATIC_LONG_LIVED
    assert inline.storage.kind is CredentialStorageKind.FILE
    assert "inline-secret-in-config" in inline.tags
    header = bindings["cred:claude-code-linear-header-authorization"]
    assert (
        header.credential_kind is CredentialKind.UNKNOWN
    )  # "Bearer ${LINEAR_TOKEN}" references the environment
    assert header.storage.kind is CredentialStorageKind.ENV
    assert "inline-secret-in-config" not in header.tags
    identities = [e for e in result.entities if isinstance(e, Identity)]
    assert all(i.ref.startswith(("env:", "header:")) for i in identities)
    holds = [e for e in result.edges if e.type is EdgeType.HOLDS_CREDENTIAL]
    assert len(holds) == len(bindings)
    assert result.redactions and result.redactions[0].count >= 2


def test_declared_tools_and_edges(scene: tuple[Path, Path]) -> None:
    repo, home = scene
    result = run_collectors(
        CollectContext(root=repo, home=home, platform="linux", agent_id="agent:triage"),
        [McpConfigCollector()],
    )[0]
    tools = {e.id: e for e in result.entities if isinstance(e, ToolDefinition)}
    assert set(tools) == {"tool:gemini-cli-db/query", "tool:gemini-cli-db/schema", "tool:codex-docs/search"}
    query = tools["tool:gemini-cli-db/query"]
    assert not query.digest.ok and query.digest.reason is not None
    assert query.approval_gate.value == "none"  # gemini trust=true bypasses confirmation
    depends = [e for e in result.edges if e.type is EdgeType.DEPENDS_ON]
    assert all(e.from_ref == "agent:triage" for e in depends)
    assert len(depends) == 10


def test_coverage_records_errors_and_scope(scene: tuple[Path, Path]) -> None:
    repo, home = scene
    result = run_collectors(CollectContext(root=repo, home=home, platform="linux"), [McpConfigCollector()])[0]
    cov = result.coverage[Surface.TOOLS]
    failed = [s for s in cov.sources if not s.ok]
    assert any(
        s.error_class == "parse-error" and s.locator == "~/.codeium/windsurf/mcp_config.json" for s in failed
    )
    assert cov.status is CoverageStatus.PARTIAL
    assert any("broken" not in w for w in result.warnings)


def test_repo_only_scan_marks_user_scope_not_attempted(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    result = run_collectors(CollectContext(root=repo, platform="linux"), [McpConfigCollector()])[0]
    servers = _servers([result])
    assert "server:claude-code-sentry" not in servers
    cov = result.coverage[Surface.TOOLS]
    assert any(s.source == "user-scope" and s.error_class == "not-attempted" for s in cov.sources)
    assert cov.status is CoverageStatus.PARTIAL


def test_empty_repo_is_queried_with_zero_items(tmp_path: Path) -> None:
    result = run_collectors(
        CollectContext(root=tmp_path, home=tmp_path / "h", platform="linux"), [McpConfigCollector()]
    )[0]
    cov = result.coverage[Surface.TOOLS]
    assert cov.status is CoverageStatus.QUERIED
    assert cov.items_seen == 0
    assert not result.entities


def test_claude_desktop_per_os(tmp_path: Path) -> None:
    home = tmp_path / "home"
    cfg = {
        "mcpServers": {
            "fs": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/Users/me"],
            }
        }
    }
    _write(
        home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json", json.dumps(cfg)
    )
    _write(home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json", json.dumps(cfg))
    for platform in ("macos", "windows"):
        result = run_collectors(
            CollectContext(root=tmp_path / "r", home=home, platform=platform), [McpConfigCollector()]
        )[0]
        servers = _servers([result])
        assert "server:claude-desktop-fs" in servers
        pkg = servers["server:claude-desktop-fs"].package
        assert pkg is not None and pkg.value is not None and not pkg.value.floating
