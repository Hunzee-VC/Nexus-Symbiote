"""Which launcher, URL and authentication values MCP collection scrubs, and which it keeps."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV, MCPScanner

KEY = "k" * 40
DIGEST = "mcp/x@sha256:" + "a" * 64
PADDED = "c2VjcmV0X2tleV92YWx1ZQ=="


def _scan(root: Path, servers: dict):
    root.mkdir(parents=True, exist_ok=True)
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    result = MCPScanner().scan(root, config_only=True)
    assert not result.scan_failures, result.scan_failures
    return result


def _servers(result) -> dict[str, MCPServerComponent]:
    return {c.name: c for c in result.components if isinstance(c, MCPServerComponent)}


def _check(root: Path) -> int:
    return CliRunner().invoke(main, ["scan", "--no-project-policy", "--check", str(root)]).exit_code


@pytest.mark.parametrize(
    "command,args",
    [
        ("npx", ["-y", "some-mcp@1.0.0", f"--api-key={PADDED}"]),
        ("npx", ["-y", "some-mcp@1.0.0", "--api-key", PADDED]),
        ("docker", ["run", "-i", "--rm", "-e", f"API_KEY={PADDED}", DIGEST]),
        ("sh", ["-c", f'API_TOKEN="Bearer {PADDED}" exec uvx mcp-server-git==0.6.2']),
        ("sh", ["-c", f'API_TOKEN="Bearer {PADDED}" exec uvx mcp-server-git']),
        ("cmd", ["/c", f"set API_TOKEN=Bearer {PADDED}&& npx -y some-mcp@1.0.0"]),
    ],
)
def test_launcher_credentials_are_scrubbed_from_tool_lists(tmp_path, monkeypatch, command, args):
    # Base64 padding ("==") is part of a credential, not a requirement pin, and a
    # credential assigned inside an inline script is one word of that script.
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    servers = {"api": {"command": command, "args": args, "autoApprove": [PADDED, "status"]}}
    result = _scan(tmp_path, servers)
    settings = _servers(result)["api"].properties["client_settings"]
    assert settings["auto_approved_tools"] == {"autoApprove": ["***", "status"]}
    assert PADDED not in json.dumps([c.model_dump(mode="json") for c in result.components])
    assert any("tool list entries withheld by redaction" in g for g in result.surfaces_excluded)


@pytest.mark.parametrize(
    "args",
    [
        ["mcp-server-tokens==10.20.30"],
        ["mcp-server-tokens===10.20.30"],
        ["--with", "mcp-server-tokens>=10.20.30", "mcp-server-git==0.6.2"],
        ["--with", "mcp-server-tokens~=10.20.30", "mcp-server-git==0.6.2"],
        ["--with", "mcp-server-tokens!=10.20.30", "mcp-server-git==0.6.2"],
    ],
)
def test_a_requirement_is_not_a_credential_assignment(tmp_path, monkeypatch, args):
    # "tokens" names a credential, so read as name=value the version would be one, and
    # every specifier holding it would be withheld from the identity.
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    result = _scan(tmp_path, {"git": {"command": "uvx", "args": args}})
    server = _servers(result)["git"]
    assert result.surfaces_excluded == []
    assert all(p["identity"] != "[withheld]" for p in server.properties["packages"])
    assert server.launcher_package is not None


def test_variable_references_are_not_credentials(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    server = {
        "command": "npx",
        "args": ["-y", "some-mcp@1.0.0", "--api-key=${API_KEY}", "--token", "${TOKEN_VALUE}"],
        "autoApprove": ["${API_KEY}", "${TOKEN_VALUE}"],
    }
    result = _scan(tmp_path, {"api": server})
    settings = _servers(result)["api"].properties["client_settings"]
    assert settings["auto_approved_tools"] == {"autoApprove": ["${API_KEY}", "${TOKEN_VALUE}"]}
    assert result.surfaces_excluded == []


@pytest.mark.parametrize(
    "header", [["--header", "Accept: application/json"], ["--header=Accept: application/json"]]
)
def test_a_header_flag_scrubs_only_the_credentials_of_its_header(tmp_path, header):
    # A header line is read by its own name; the flag name "header" marks no credential.
    server = {
        "command": "npx",
        "args": ["-y", "mcp-remote@0.1.0", "https://x.example.test/sse", *header],
        "tools": [{"name": "send", "description": "Sends Accept: application/json requests"}],
    }
    result = _scan(tmp_path, {"remote": server})
    [tool] = [c for c in result.components if isinstance(c, ToolComponent)]
    assert tool.description_text == "Sends Accept: application/json requests"


@pytest.mark.parametrize(
    "server",
    [
        {
            "command": "npx",
            "args": [
                "-y",
                "@modelcontextprotocol/server-postgres@0.6.2",
                "postgresql://postgres@localhost:5432/appdb",
            ],
        },
        {
            "command": "npx",
            "args": [
                "-y",
                "@modelcontextprotocol/server-postgres@0.6.2",
                "postgresql://postgres:postgres@localhost:5432/appdb",
            ],
        },
        {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-postgres@0.6.2"],
            "env": {"DATABASE_URL": "postgresql://postgres:postgres@localhost:5432/appdb"},
        },
    ],
)
def test_a_url_user_name_or_word_password_keeps_the_identity(tmp_path, monkeypatch, server):
    # A user name is not a credential, and the default password "postgres" reads as a
    # word: neither may withhold a server and package that name the same database.
    for key in (None, KEY):
        if key is None:
            monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
        else:
            monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, key)
        root = tmp_path / ("keyed" if key else "keyless")
        result = _scan(root, {"postgres": server})
        component = _servers(result)["postgres"]
        assert result.surfaces_excluded == []
        assert component.launcher_package == "npm:@modelcontextprotocol/server-postgres"
        assert component.version == "0.6.2"
        assert _check(root) == 0


SK_SHAPED = "sk-abcdefghijklmnopqrstuvwx"


@pytest.mark.parametrize(
    "locator,secret",
    [
        ("postgresql://app:Zq8vLm2pXr7tKw4n@db.internal/app", "Zq8vLm2pXr7tKw4n"),
        ("postgresql://app:hunter2hunter@db.internal/app", "hunter2hunter"),
        ("postgresql://app:p%40ssw0rd99@db.internal/app", "p@ssw0rd99"),
        (f"https://{SK_SHAPED}@api.example.test/v1", SK_SHAPED),
        (f"https://{SK_SHAPED.replace('-', '%2D')}@api.example.test/v1", SK_SHAPED),
    ],
)
def test_a_credential_in_url_user_information_is_scrubbed(tmp_path, locator, secret):
    # Tool names keep sk-... forms, so only the scrubbed value can hide the token there.
    servers = {
        "db": {"command": "npx", "args": ["-y", "some-mcp@1.0.0", locator]},
        "other": {"type": "http", "url": "https://mcp.example.test", "autoApprove": [secret]},
    }
    result = _scan(tmp_path, servers)
    settings = _servers(result)["other"].properties["client_settings"]
    assert settings["auto_approved_tools"] == {"autoApprove": ["***"]}
    assert secret not in json.dumps([c.model_dump(mode="json") for c in result.components])


@pytest.mark.parametrize(
    "auth_field,settings",
    [
        ("auth", {"type": "bearer", "value": "Zq8vLm2pXr7tKw4n"}),
        ("oauth", {"client": {"credentials": {"value": "Zq8vLm2pXr7tKw4n"}}}),
        ("oauth", {"clientSecrets": ["Zq8vLm2pXr7tKw4n"]}),
    ],
)
def test_every_authentication_value_is_scrubbed_but_public_parameters(
    tmp_path, auth_field, settings
):
    public = {"clientId": "github-mcp-client", "scopes": ["repository:read"]}
    server = {
        "type": "http",
        "url": "https://mcp.example.test",
        auth_field: {**public, **settings},
        "autoApprove": ["Zq8vLm2pXr7tKw4n", "github-mcp-client", "repository:read"],
    }
    result = _scan(tmp_path, {"api": server})
    approved = _servers(result)["api"].properties["client_settings"]["auto_approved_tools"]
    assert approved == {"autoApprove": ["***", "github-mcp-client", "repository:read"]}


def test_a_credential_anywhere_in_a_large_oauth_object_is_scrubbed(tmp_path):
    oauth = {"clientSecret": "oauthclientsec99", **{f"scope{i}": "x" for i in range(1100)}}
    server = {
        "type": "http",
        "url": "https://mcp.example.com/mcp",
        "oauth": oauth,
        "autoApprove": ["oauthclientsec99", "search"],
    }
    result = _scan(tmp_path, {"r": server})
    approved = _servers(result)["r"].properties["client_settings"]["auto_approved_tools"]
    assert approved == {"autoApprove": ["***", "search"]}


@pytest.mark.parametrize("field", ["oauth", "auth"])
def test_an_authentication_object_past_the_bound_is_refused(tmp_path, field):
    settings = {"clientSecret": "oauthclientsec99", **{f"k{i}": "x" for i in range(20_001)}}
    server = {
        "type": "http",
        "url": "https://mcp.example.com/mcp",
        field: settings,
        "autoApprove": ["oauthclientsec99"],
    }
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"r": server}}))
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert result.scan_failures == [
        ".mcp.json: MCP server authentication settings limit (20000 nodes, 64 levels) exceeded"
    ]
    assert not _servers(result)
    assert "oauthclientsec99" not in json.dumps(
        [c.model_dump(mode="json") for c in result.components]
    )


def test_a_tool_name_holding_a_scrubbed_value_is_a_coverage_gap(tmp_path, monkeypatch):
    server = {
        "command": "uvx",
        "args": ["mcp-server-git==0.6.2"],
        "env": {"API_TOKEN": "secret_admin_tool"},
        "tools": [{"name": "secret_admin_tool", "description": "x"}],
    }
    for key in (None, KEY):
        if key is None:
            monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
        else:
            monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, key)
        root = tmp_path / ("keyed" if key else "keyless")
        result = _scan(root, {"git": server})
        [tool] = [c for c in result.components if isinstance(c, ToolComponent)]
        assert tool.name == "***"
        assert result.surfaces_excluded == [
            ".mcp.json: MCP server 'git' tool name withheld by environment-value redaction"
        ]
        assert _check(root) == 1


def test_a_redacted_tool_list_entry_is_a_keyless_diff_alert_on_its_own(tmp_path, monkeypatch):
    # A bare origin and no arguments leave nothing else unbound: only the redacted
    # entries tell diff that the two inventories may differ.
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    boms = []
    for item in ("read_only", "delete_all"):
        root = tmp_path / item
        server = {
            "type": "http",
            "url": "https://mcp.example.com",
            "autoApprove": [f"https://mcp.internal/tools/{item}"],
        }
        _scan(root, {"remote": server})
        bom = tmp_path / f"{item}.json"
        run = CliRunner().invoke(
            main, ["scan", "--no-project-policy", "--report-only", str(root), "-o", str(bom)]
        )
        assert run.exit_code == 0, run.output
        boms.append(str(bom))
    same = CliRunner().invoke(main, ["diff", boms[0], boms[0], "--fail-on-alert"])
    assert same.exit_code == 1, same.output
    assert "unbound" in same.output
    swapped = CliRunner().invoke(main, ["diff", *boms, "--fail-on-alert"])
    assert swapped.exit_code == 1, swapped.output
    assert "unbound" in swapped.output


def test_each_tool_list_entry_is_redacted_once(tmp_path, monkeypatch):
    # Against a file's values a redaction is the costly step of collection.
    calls: list[str] = []
    original = MCPScanner._tool_name

    def counting(name, scrubber):
        calls.append(name)
        return original(name, scrubber)

    monkeypatch.setattr(MCPScanner, "_tool_name", staticmethod(counting))
    fields = ["alwaysAllow", "autoApprove", "includeTools", "excludeTools", "disabledTools"]
    server = {
        "type": "http",
        "url": "https://mcp.example.com",
        "env": {"API_TOKEN": "Zq8vLm2pXr7tKw4n"},
        **{field: [f"{field}_{i}" for i in range(3)] for field in fields},
        "tools": [{"name": "search", "description": "x"}],
    }
    _scan(tmp_path, {"remote": server})
    entries = [f"{field}_{i}" for field in fields for i in range(3)]
    assert sorted(calls) == sorted([*entries, "search", "search"])


@pytest.mark.parametrize(
    "command,args",
    [
        ("env", ["-C", " .", "npx", "-y", "@modelcontextprotocol/server-filesystem@2025.8.21"]),
        ("env", ["--chdir= .", "npx", "-y", "@modelcontextprotocol/server-filesystem@2025.8.21"]),
        ("uv", ["tool", "run", "--directory", " .", "mcp-server-git==0.6.2"]),
        ("wsl", ["--cd", " .", "--exec", "npx", "-y", "some-mcp@1.0.0"]),
    ],
)
def test_padded_dot_launcher_working_directory_relocates_server(tmp_path, command, args):
    subdir = tmp_path / " ."
    subdir.mkdir(exist_ok=True)
    (subdir / ".npmrc").write_text("registry=https://npm.attacker.test/\n")
    result = _scan(tmp_path, {"srv": {"command": command, "args": args}})
    srv = _servers(result)["srv"]
    assert srv.package_url is None
    assert srv.properties.get("launcher_package") is None
    assert srv.properties.get("package_sources") == ["working-directory=[unresolved]"]
    assert any(
        r.category == "package_source" and "working-directory" in r.detail for r in srv.risks
    )


def test_token_shaped_url_username_is_scrubbed_when_password_is_present(tmp_path):
    decoded_pat = "github_pat_1234567890abcdef_1234567890abcdef"
    encoded_pat = "github_pat_1234567890abcdef%5F1234567890abcdef"
    server = {
        "type": "http",
        "url": f"https://{encoded_pat}:x-oauth-basic@registry.example/mcp",
        "autoApprove": [decoded_pat, "search"],
    }
    result = _scan(tmp_path, {"srv": server})
    dumped = json.dumps([c.model_dump(mode="json") for c in result.components])
    assert decoded_pat not in dumped
    assert _servers(result)["srv"].properties["client_settings"]["auto_approved_tools"] == {
        "autoApprove": ["***", "search"]
    }
