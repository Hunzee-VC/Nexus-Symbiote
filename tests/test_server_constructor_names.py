"""A source MCP server is named by the literal name its constructor declares.

`new McpServer({ name: "analytics-mcp", version: "1.0.0" })` and
`FastMCP("analytics-mcp")` were inventoried as the variable the server was bound to.
The literal is the name a client sees; the variable stays as evidence, and a name
computed at run time keeps the variable as the name.
"""

from __future__ import annotations

import gc
import json
import random
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.base import (
    MAX_SERVER_NAME_CHARS,
    KnownValues,
    declared_server_name,
)
from nexus_symbiote.scanners.mcp import MAX_SECRETS_PER_FILE, MCPScanner
from nexus_symbiote.utils.secrets import redact_text

TS_IMPORT = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
TS_TOOL = 'server.registerTool("read_note", {}, readNote);\n'
PY_IMPORT = "from mcp.server.fastmcp import FastMCP\n"
PY_TOOL = "@mcp.tool()\ndef read_note() -> str:\n    return ''\n"
LONG = "n" * (MAX_SERVER_NAME_CHARS + 1)
TOKEN = "ghp_" + "SYNTHETICSENTINEL" + "0" * 19
KEY = "sk-ant-api03-" + "A" * 95


def _scan(root: Path, files: dict[str, str | bytes]):
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
    return MCPScanner().scan(root)


def _servers(result) -> list[MCPServerComponent]:
    return [c for c in result.components if isinstance(c, MCPServerComponent)]


def _ts_server(root: Path, options: str) -> MCPServerComponent:
    source = TS_IMPORT + f"const server = new McpServer({options});\n" + TS_TOOL
    result = _scan(root, {"src/server.ts": source})
    assert result.scan_failures == [] and result.surfaces_excluded == []
    (server,) = _servers(result)
    tools = [c for c in result.components if isinstance(c, ToolComponent)]
    assert [t.mcp_server_ref for t in tools] == [server.bom_ref]
    assert server.tool_refs == [f"tool:{server.bom_ref}/read_note"]
    return server


def test_a_typescript_server_is_named_by_its_literal_name(tmp_path):
    server = _ts_server(tmp_path, '{ name: "analytics-mcp", version: "1.0.0" }')
    start = len(TS_IMPORT) + len("const server = ")
    assert server.name == "analytics-mcp"
    assert server.bom_ref == f"mcp-source:src%2Fserver.ts:analytics-mcp:2:{start}"
    assert server.properties["binding"] == "server"
    assert server.properties["declaration_line"] == 2


@pytest.mark.parametrize(
    "options",
    [
        "{ name: 'analytics-mcp' }",
        '{ "name": "analytics-mcp", version: "1" }',
        "{ ['name']: 'analytics-mcp' }",
        "{ name: `analytics-mcp` }",
        '{ name: "an\\u0061lytics-mcp" }',
        '{ n\\u0061me: "analytics-mcp" }',
        '{ name: "draft", name: "analytics-mcp" }',
        '{ ...defaults, name: "analytics-mcp" }',
        '({ name: ((("analytics-mcp"))) } as Implementation)',
        '{ name: "analytics-mcp" as const, version: "1" }',
        '{ name: "analytics-mcp", /* note */ version: "1", title: name }',
        '{ name: "analytics-mcp", version }',
        '{ name: "analytics-mcp", version: "1" }, { name: "other" }',
        '{ title: () => "x", name: "analytics-mcp" }',
        "{ name: 'analytics-mcp', ['version']: '1' }",
        "{ ['version']: '1', name: 'analytics-mcp' }",
        "{ [`name`]: 'analytics-mcp' }",
    ],
    ids=[
        "single-quoted",
        "string-key",
        "computed-literal-key",
        "plain-template",
        "escaped-value",
        "escaped-key",
        "later-entry-wins",
        "spread-before",
        "wrapped",
        "as-const",
        "comment-and-other-entries",
        "shorthand-of-another-key-after",
        "second-argument-with-another-name",
        "arrow-value-of-another-key",
        "literal-computed-key-after",
        "literal-computed-key-before",
        "template-computed-name-key",
    ],
)
def test_every_spelling_of_a_literal_typescript_name_is_read(tmp_path, options):
    server = _ts_server(tmp_path, options)
    assert (server.name, server.properties["binding"]) == ("analytics-mcp", "server")
    assert ":analytics-mcp:2:" in server.bom_ref


@pytest.mark.parametrize(
    "options",
    [
        "{ name: `${prefix}-mcp`, version: '1' }",
        "{ name: prefix, version: '1' }",
        "{ name: 'analytics' + '-mcp' }",
        "{ name: (0, 'analytics-mcp') }",
        "{ name: 'analytics-mcp', ...overrides }",
        "{ name: 'analytics-mcp', [key]: 'other' }",
        "{ name: 'analytics-mcp', name }",
        "{ get name() { return 'analytics-mcp'; } }",
        "{ name: 'analytics-mcp', name() { return 'x'; } }",
        "{ name: 'analytics-mcp', set name(value) {} }",
        "{ toJSON() { return { name: 'other' }; }, name: 'analytics-mcp' }",
        "{ name: 'analytics-mcp', toJSON() { return { name: 'other' }; } }",
        "{ name: 'analytics-mcp', toJSON: () => ({ name: 'other' }) }",
        "{ name: 'analytics-mcp', toJSON: function () { return {}; } }",
        "{ name: 'analytics-mcp', 'toJSON': serialize }",
        "{ name: 'analytics-mcp', ['toJSON']: serialize }",
        "{ name: 'analytics-mcp', toJSON }",
        "{ describe() { return 'x'; }, name: 'analytics-mcp' }",
        "{ async start() {}, name: 'analytics-mcp' }",
        "{ *ids() {}, name: 'analytics-mcp' }",
        "{ get title() { return 'x'; }, name: 'analytics-mcp' }",
        "{ __proto__: serializer, name: 'analytics-mcp' }",
        "{ [key]: serializer, name: 'analytics-mcp' }",
        "{ ['to' + 'JSON']: serializer, name: 'analytics-mcp' }",
        "{ name: 'analytics-mcp', '__proto__': serializer }",
        "{ name: 'analytics-mcp', \"n\\x61me\": other }",
        "{ version: '1' }",
        "{}",
        "options",
        "...args",
        f"{{ name: '{LONG}' }}",
        "{ name: '' }",
        "{ name: 'line\\nbreak' }",
        "{ name: 'trailing ' }",
        "{ name: 'bidi\\u202eevil' }",
        "{ name: 'semi;colon' }",
        "{ name: '..' }",
        "{ name: 'oct\\101al' }",
        f"{{ name: '{TOKEN}' }}",
        f"{{ name: '{KEY}' }}",
    ],
    ids=[
        "template-substitution",
        "variable",
        "concatenation",
        "sequence",
        "spread-after",
        "computed-key-after",
        "shorthand-after",
        "getter",
        "method-after",
        "setter-after",
        "to-json-method-before",
        "to-json-method-after",
        "to-json-arrow",
        "to-json-function",
        "to-json-string-key",
        "to-json-computed-key",
        "to-json-shorthand",
        "method-before",
        "async-method-before",
        "generator-method-before",
        "getter-of-another-key-before",
        "prototype-before",
        "computed-key-before",
        "computed-to-json-before",
        "prototype-string-key-after",
        "escaped-string-key-after",
        "no-name",
        "empty-object",
        "options-variable",
        "spread-argument",
        "oversized",
        "empty",
        "newline",
        "trailing-space",
        "bidi-override",
        "punctuation",
        "punctuation-only",
        "legacy-octal-escape",
        "token-shaped",
        "key-shaped",
    ],
)
def test_a_typescript_name_computed_or_outside_the_form_keeps_the_binding(tmp_path, options):
    server = _ts_server(tmp_path, options)
    assert (server.name, server.properties["binding"]) == ("server", "server")
    assert ":server:2:" in server.bom_ref


@pytest.mark.parametrize("relative", ["src/server.js", "src/server.mjs", "src/server.jsx"])
def test_a_javascript_server_is_named_by_its_literal_name(tmp_path, relative):
    source = TS_IMPORT + 'const server = new McpServer({ name: "js-mcp", version: "1" });\n'
    result = _scan(tmp_path, {relative: source + TS_TOOL})
    assert result.scan_failures == [] and result.surfaces_excluded == []
    (server,) = _servers(result)
    assert (server.name, server.properties["binding"]) == ("js-mcp", "server")
    assert server.tool_refs == [f"tool:{server.bom_ref}/read_note"]


def test_two_typescript_constructors_in_one_file_are_two_components(tmp_path):
    source = (
        TS_IMPORT
        + 'const server = new McpServer({ name: "analytics-mcp", version: "1" });\n'
        + "const admin = new McpServer({ name: `admin-${env}` });\n"
        + TS_TOOL
        + 'admin.registerTool("purge", {}, purge);\n'
    )
    result = _scan(tmp_path, {"src/server.ts": source})
    assert result.surfaces_excluded == [] and result.scan_failures == []
    servers = _servers(result)
    assert [
        (s.name, s.properties["binding"], s.properties["declaration_line"]) for s in servers
    ] == [
        ("analytics-mcp", "server", 2),
        ("admin", "admin", 3),
    ]
    assert len({s.bom_ref for s in servers}) == 2
    assert [s.tool_refs for s in servers] == [
        [f"tool:{servers[0].bom_ref}/read_note"],
        [f"tool:{servers[1].bom_ref}/purge"],
    ]


def test_two_typescript_servers_with_one_literal_name_keep_distinct_references(tmp_path):
    source = TS_IMPORT + "".join(
        f'const {name} = new McpServer({{ name: "analytics-mcp" }});\n' for name in ("a", "b")
    )
    servers = _servers(_scan(tmp_path, {"src/server.ts": source}))
    assert [(s.name, s.properties["binding"]) for s in servers] == [
        ("analytics-mcp", "a"),
        ("analytics-mcp", "b"),
    ]
    assert len({s.bom_ref for s in servers}) == 2


def test_a_utf16_typescript_server_is_named_by_its_literal_name(tmp_path):
    source = TS_IMPORT + 'const server = new McpServer({ name: "analytics-mcp" });\n'
    result = _scan(tmp_path, {"src/server.ts": b"\xff\xfe" + source.encode("utf-16-le")})
    assert [s.name for s in _servers(result)] == ["analytics-mcp"]


def test_a_deeply_nested_options_object_still_yields_the_literal_name(tmp_path):
    nested = "{ a: " * 200 + "1" + " }" * 200
    server = _ts_server(tmp_path, f'{{ meta: {nested}, name: "analytics-mcp" }}')
    assert server.name == "analytics-mcp"


def _py_server(root: Path, constructor: str) -> MCPServerComponent:
    result = _scan(root, {"pkg/server.py": PY_IMPORT + f"mcp = {constructor}\n" + PY_TOOL})
    assert result.scan_failures == [] and result.surfaces_excluded == []
    (server,) = _servers(result)
    assert server.bom_ref == "mcp-python:pkg%2Fserver.py:mcp"
    assert server.properties["binding"] == "mcp"
    assert server.properties["declaration_line"] == 2
    assert server.tool_refs == ["tool:mcp-python:pkg%2Fserver.py:mcp/read_note"]
    return server


@pytest.mark.parametrize(
    "constructor",
    [
        "FastMCP('analytics-mcp')",
        "FastMCP(name='analytics-mcp')",
        "FastMCP('analytics-mcp', instructions='Reads notes')",
        "FastMCP('analytics' '-mcp')",
        "FastMCP(instructions='Reads notes', name='analytics-mcp')",
        "FastMCP('analytics-mcp', 'Reads notes')",
    ],
    ids=[
        "positional",
        "keyword",
        "with-instructions",
        "implicit-concatenation",
        "keyword-last",
        "positional-instructions",
    ],
)
def test_a_python_server_is_named_by_its_literal_name(tmp_path, constructor):
    assert _py_server(tmp_path, constructor).name == "analytics-mcp"


@pytest.mark.parametrize(
    "constructor",
    [
        "FastMCP(f'{prefix}-mcp')",
        "FastMCP(prefix)",
        "FastMCP('analytics' + '-mcp')",
        "FastMCP(name=prefix)",
        "FastMCP('analytics-mcp', name='other')",
        "FastMCP(b'analytics-mcp')",
        "FastMCP(None)",
        "FastMCP(name=None)",
        "FastMCP()",
        "FastMCP(instructions='Reads notes')",
        f"FastMCP('{LONG}')",
        "FastMCP('')",
        "FastMCP('line\\nbreak')",
        "FastMCP('bidi\\u202eevil')",
        f"FastMCP('{TOKEN}')",
        f"FastMCP('{KEY}')",
    ],
    ids=[
        "f-string",
        "variable",
        "concatenation",
        "keyword-variable",
        "positional-and-keyword",
        "bytes",
        "none",
        "keyword-none",
        "no-name",
        "instructions-only",
        "oversized",
        "empty",
        "newline",
        "bidi-override",
        "token-shaped",
        "key-shaped",
    ],
)
def test_a_python_name_computed_or_outside_the_form_keeps_the_binding(tmp_path, constructor):
    assert _py_server(tmp_path, constructor).name == "mcp"


def test_two_python_servers_with_one_literal_name_keep_distinct_references(tmp_path):
    source = (
        PY_IMPORT
        + "mcp = FastMCP('analytics-mcp')\n"
        + "admin = FastMCP('analytics-mcp')\n"
        + PY_TOOL
        + "@admin.tool()\ndef purge() -> None:\n    pass\n"
    )
    result = _scan(tmp_path, {"pkg/server.py": source})
    assert result.surfaces_excluded == [] and result.scan_failures == []
    servers = _servers(result)
    assert [(s.bom_ref, s.name, s.properties["binding"]) for s in servers] == [
        ("mcp-python:pkg%2Fserver.py:mcp", "analytics-mcp", "mcp"),
        ("mcp-python:pkg%2Fserver.py:admin", "analytics-mcp", "admin"),
    ]
    assert [s.tool_refs for s in servers] == [
        ["tool:mcp-python:pkg%2Fserver.py:mcp/read_note"],
        ["tool:mcp-python:pkg%2Fserver.py:admin/purge"],
    ]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("analytics-mcp", "analytics-mcp"),
        ("Notes Server 2.0", "Notes Server 2.0"),
        ("n" * MAX_SERVER_NAME_CHARS, "n" * MAX_SERVER_NAME_CHARS),
        (LONG, None),
        ("", None),
        ("..", None),
        ("-", None),
        ("_ .", None),
        ("v1", "v1"),
        (" leading", None),
        ("double  space", None),
        ("tab\tname", None),
        ("caf\u00e9", None),
        ("sk-learn-classifier", "sk-learn-classifier"),
        ("notes/mcp", None),
        ("notes%2Fmcp", None),
        (TOKEN, None),
        (KEY, None),
        (b"bytes", None),
        (None, None),
        (7, None),
    ],
)
def test_only_a_bounded_plain_name_is_a_declared_name(value, expected):
    assert declared_server_name(value) == expected


def test_two_scans_of_named_servers_are_byte_identical(tmp_path):
    project = tmp_path / "project"
    _scan(
        project,
        {
            "src/server.ts": TS_IMPORT
            + 'const server = new McpServer({ name: "analytics-mcp", version: "1" });\n'
            + TS_TOOL,
            "pkg/server.py": PY_IMPORT + "mcp = FastMCP(name='notes-mcp')\n" + PY_TOOL,
        },
    )
    runner = CliRunner()
    outputs = []
    for run in ("first", "second"):
        out = tmp_path / f"{run}.json"
        result = runner.invoke(main, ["scan", "--report-only", str(project), "-o", str(out)])
        assert result.exit_code == 0, result.output
        outputs.append(out.read_bytes())
    assert outputs[0] == outputs[1]
    names = {
        component["name"]
        for component in json.loads(outputs[0])["components"]
        if component["component_type"] == "mcp-server"
    }
    assert names == {"analytics-mcp", "notes-mcp"}


def test_a_name_with_spaces_is_percent_encoded_in_the_reference(tmp_path):
    server = _ts_server(tmp_path, '{ name: "Notes Server 2.0", version: "1" }')
    start = len(TS_IMPORT) + len("const server = ")
    assert server.name == "Notes Server 2.0"
    assert server.bom_ref == f"mcp-source:src%2Fserver.ts:Notes%20Server%202.0:2:{start}"
    assert server.tool_refs == [f"tool:{server.bom_ref}/read_note"]


# A credential with no vendor shape: only the configuration file marks it as one.
CONFIGURED = "plainvalue" + "x" * 14
SECRET_SOURCES = {
    "typescript": (
        "src/server.ts",
        lambda name: (
            TS_IMPORT
            + f'const server = new McpServer({{ name: "{name}", version: "1" }});\n'
            + TS_TOOL
        ),
        "server",
    ),
    "python": (
        "src/server.py",
        lambda name: PY_IMPORT + f"mcp = FastMCP('{name}')\n" + PY_TOOL,
        "mcp",
    ),
}


def _configured(path: str = ".mcp.json") -> dict[str, str]:
    server = {"command": "node", "args": ["notes.js"], "env": {"API_TOKEN": CONFIGURED}}
    return {path: json.dumps({"mcpServers": {"notes": server}})}


def _native(tmp_path: Path, files: dict[str, str]) -> tuple[str, list[str]]:
    project = tmp_path / "project"
    for relative, text in files.items():
        path = project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    out = tmp_path / "inventory.json"
    result = CliRunner().invoke(main, ["scan", "--report-only", str(project), "-o", str(out)])
    assert result.exit_code == 0, result.output
    text = out.read_text()
    names = [
        component["name"]
        for component in json.loads(text)["components"]
        if component["component_type"] == "mcp-server"
    ]
    return text, sorted(names)


@pytest.mark.parametrize("language", sorted(SECRET_SOURCES))
@pytest.mark.parametrize("name", [CONFIGURED, f"notes-{CONFIGURED}"], ids=["whole", "part"])
def test_a_configured_credential_never_becomes_a_server_name(tmp_path, language, name):
    relative, source, binding = SECRET_SOURCES[language]
    text, names = _native(tmp_path, {**_configured(), relative: source(name)})
    assert names == sorted([binding, "notes"])
    assert text.count(CONFIGURED) == 0


@pytest.mark.parametrize("language", sorted(SECRET_SOURCES))
def test_a_credential_of_another_client_file_is_known_too(tmp_path, language):
    relative, source, binding = SECRET_SOURCES[language]
    text, names = _native(
        tmp_path, {**_configured(".cursor/mcp.json"), relative: source(CONFIGURED)}
    )
    assert names == sorted([binding, "notes"])
    assert text.count(CONFIGURED) == 0


@pytest.mark.parametrize("language", sorted(SECRET_SOURCES))
def test_a_plain_name_beside_a_configured_credential_is_kept(tmp_path, language):
    relative, source, _ = SECRET_SOURCES[language]
    text, names = _native(tmp_path, {**_configured(), relative: source("analytics-mcp")})
    assert names == ["analytics-mcp", "notes"]
    assert text.count(CONFIGURED) == 0


def _settings(path: str, env: dict[str, str]) -> dict[str, str]:
    return {path: json.dumps({"env": env})}


def _server_file(server: dict[str, object], path: str = ".mcp.json") -> dict[str, str]:
    return {path: json.dumps({"mcpServers": {"notes": server}})}


# Values the inventory never shows that no server's own parsing reads as a credential.
WITHHELD_ELSEWHERE = {
    "claude-settings-env": _settings(".claude/settings.json", {"API_TOKEN": CONFIGURED}),
    "claude-settings-local-env": _settings(
        ".claude/settings.local.json", {"MY_SERVICE_PASSWORD": CONFIGURED}
    ),
    "nested-claude-settings-env": _settings("pkg/.claude/settings.json", {"HMAC": CONFIGURED}),
    "cursor-settings-env": _settings(".cursor/settings.json", {"API_TOKEN": CONFIGURED}),
    "codex-bearer-token": {
        ".codex/config.toml": "[mcp_servers.notes]\n"
        'url = "https://example.com/mcp"\n'
        f'experimental_bearer_token = "{CONFIGURED}"\n'
    },
    "codex-shell-environment": {
        ".codex/config.toml": f'[shell_environment_policy.set]\nSIGNING = "{CONFIGURED}"\n'
    },
    "server-api-key": _server_file(
        {"type": "http", "url": "https://example.com/mcp", "apiKey": CONFIGURED}
    ),
    "server-token": _server_file({"command": "node", "args": ["n.js"], "token": CONFIGURED}),
    "nested-api-key": _server_file(
        {"command": "node", "args": ["n.js"], "settings": {"apiKey": CONFIGURED}}
    ),
    "env-hmac": _server_file({"command": "node", "args": ["n.js"], "env": {"HMAC": CONFIGURED}}),
    "env-webhook-url": _server_file(
        {"command": "node", "args": ["n.js"], "env": {"WEBHOOK_URL": CONFIGURED}}
    ),
    "header-plain-name": _server_file(
        {"type": "http", "url": "https://example.com/mcp", "headers": {"X-Tenant": CONFIGURED}}
    ),
    "split-flag-argument": _server_file(
        {"command": "node", "args": ["n.js", "--api-key", CONFIGURED]}
    ),
    "server-map-over-the-limit": {
        ".mcp.json": json.dumps(
            {
                "mcpServers": {
                    **{f"s{index}": {"command": "node"} for index in range(1000)},
                    "notes": {"command": "node", "env": {"API_TOKEN": CONFIGURED}},
                }
            }
        )
    },
    "split-flag-in-a-server-map-over-the-limit": {
        ".mcp.json": json.dumps(
            {
                "mcpServers": {
                    **{f"s{index}": {"command": "node"} for index in range(1000)},
                    "notes": {"command": "node", "args": ["n.js", "--api-key", CONFIGURED]},
                }
            }
        )
    },
    "server-map-not-an-object": {
        ".mcp.json": json.dumps({"mcpServers": [{"env": {"API_TOKEN": CONFIGURED}}]})
    },
}


@pytest.mark.parametrize("language", sorted(SECRET_SOURCES))
@pytest.mark.parametrize("files", list(WITHHELD_ELSEWHERE.values()), ids=list(WITHHELD_ELSEWHERE))
def test_a_value_withheld_from_the_inventory_never_becomes_a_server_name(tmp_path, language, files):
    relative, source, binding = SECRET_SOURCES[language]
    text, names = _native(tmp_path, {**files, relative: source(f"notes-{CONFIGURED}")})
    assert binding in names
    assert text.count(CONFIGURED) == 0


@pytest.mark.parametrize("language", sorted(SECRET_SOURCES))
def test_a_short_environment_value_does_not_hide_a_name(tmp_path, language):
    relative, source, _ = SECRET_SOURCES[language]
    server = {"command": "node", "args": ["n.js"], "env": {"NOTES_DIR": "notes", "DEBUG": "1"}}
    _, names = _native(tmp_path, {**_server_file(server), relative: source("notes-mcp-v1")})
    assert "notes-mcp-v1" in names


# A credential that only the launcher analysis of a collected server reads.
LAUNCHER_ONLY = {"command": "node", "args": ["n.js", f"--api-key={CONFIGURED}"]}


def test_a_credential_of_a_file_over_the_value_limit_is_still_known(tmp_path):
    servers: dict[str, object] = {
        f"s{index}": {
            "command": "node",
            "env": {
                f"TOKEN_{field}": f"SyntheticValue{index:03d}{field:03d}" for field in range(250)
            },
        }
        for index in range(MAX_SECRETS_PER_FILE // 250 + 1)
    }
    servers["notes"] = LAUNCHER_ONLY
    project = tmp_path / "project"
    files = {
        ".mcp.json": json.dumps({"mcpServers": servers}),
        "src/server.ts": SECRET_SOURCES["typescript"][1](f"notes-{CONFIGURED}"),
    }
    for relative, text in files.items():
        (project / relative).parent.mkdir(parents=True, exist_ok=True)
        (project / relative).write_text(text)
    out = tmp_path / "inventory.json"
    result = CliRunner().invoke(main, ["scan", "--report-only", str(project), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert f"more than {MAX_SECRETS_PER_FILE} credential values in one file" in result.output
    text = out.read_text()
    assert text.count(CONFIGURED) == 0
    names = [c["name"] for c in json.loads(text)["components"] if c["name"] == "server"]
    assert names == ["server"]


@pytest.mark.parametrize("language", sorted(SECRET_SOURCES))
def test_a_credential_of_a_file_refused_for_its_binding_key_is_still_known(
    tmp_path, monkeypatch, language
):
    monkeypatch.setenv("NEXUS_SYMBIOTE_SOURCE_BINDING_KEY", "short")
    relative, source, binding = SECRET_SOURCES[language]
    result = _scan(
        tmp_path,
        {**_server_file(LAUNCHER_ONLY), relative: source(f"notes-{CONFIGURED}")},
    )
    assert any("NEXUS_SYMBIOTE_SOURCE_BINDING_KEY" in failure for failure in result.scan_failures)
    assert [server.name for server in _servers(result)] == [binding]
    dumped = json.dumps([c.model_dump(mode="json") for c in result.components])
    assert dumped.count(CONFIGURED) == 0


@pytest.mark.parametrize(
    "files",
    [
        {".mcp.json": json.dumps({"mcpServers": {}, "padding": [0] * (1 << 17)})},
        {".claude/settings.json": "{"},
        {".cursor/settings.json": b"\xff\xfe{}"},
    ],
    ids=["client-file-over-the-node-limit", "unparsable-settings", "undecodable-settings"],
)
def test_a_configuration_file_not_read_whole_keeps_every_binding(tmp_path, files):
    project = tmp_path / "project"
    _scan(project, files)
    source = TS_IMPORT + 'const server = new McpServer({ name: "analytics-mcp" });\n'
    python = PY_IMPORT + "mcp = FastMCP('notes-mcp')\n"
    result = _scan(project, {"src/server.ts": source, "src/server.py": python})
    assert sorted(server.name for server in _servers(result)) == ["mcp", "server"]


def test_a_name_is_tested_against_every_known_value_it_holds():
    rng = random.Random(7)  # noqa: S311 - reproducible test inputs
    alphabet = "ab-"
    for _ in range(2000):
        values = ["".join(rng.choices(alphabet, k=rng.randint(1, 6))) for _ in range(5)]
        name = "".join(rng.choices(alphabet, k=rng.randint(1, 12)))
        assert KnownValues(values).held_by(name) == any(value in name for value in values)
    assert not KnownValues(["has/slash", "x" * (MAX_SERVER_NAME_CHARS + 1)]).held_by("has/slash")


def test_testing_a_name_does_not_grow_with_the_known_values():
    names = [f"analytics-mcp-{index:06d}-server" for index in range(2000)]

    def cost(known: KnownValues) -> float:
        timings = []
        for _ in range(5):
            started = time.process_time()
            assert not any(known.held_by(name) for name in names)
            timings.append(time.process_time() - started)
        return min(timings)

    many = KnownValues(f"plainvalue{index:014d}" for index in range(200_000))
    few = KnownValues(f"plainvalue{index:014d}" for index in range(30))
    assert cost(many) < 3 * cost(few) + 0.05


# Synthetic token shapes, assembled so that no vendor detector matches the source.
NAME_SHAPES = [
    TOKEN,
    KEY,
    "glpat-" + "SYNTHETICSENTINEL000",
    "npm_" + "SYNTHETICSENTINEL" + "0" * 19,
    "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJ" + "zdWIiOiJzeW50aGV0aWMifQ" + ".SYNTHETIC0sig",
]


@pytest.mark.parametrize("shape", NAME_SHAPES)
@pytest.mark.parametrize("form", ["{}", "notes-{}", "{}.mcp", "notes {} v1"])
def test_the_identifier_reading_finds_no_shape_the_plain_one_misses(shape, form):
    """Why ``declared_server_name`` reads a literal with the plain rules alone."""
    name = form.format(shape)
    if redact_text(name, identifier=True) != name:
        assert redact_text(name) != name
    assert (declared_server_name(name) is None) == (redact_text(name) != name)


@pytest.mark.parametrize(
    ("variable", "expected"),
    [
        ("notes1", [("medium", "Medium change in 'analytics-mcp': properties.binding changed.")]),
        (
            "srv",
            [
                (
                    "high",
                    "Component 'analytics-mcp' (mcp-server) is no longer in the inventory: "
                    "confirm it was deleted, not moved out of collector scope.",
                ),
                ("high", "High change in 'repository': tool_refs changed."),
                ("medium", "New component 'analytics-mcp' (mcp-server) added to supply chain."),
            ],
        ),
    ],
    ids=["same-length", "constructor-moves"],
)
def test_renaming_the_variable_of_a_literal_named_server(tmp_path, variable, expected):
    """The reference keeps the name only while the constructor stays where it was."""
    inventories = []
    for binding in ("server", variable):
        project = tmp_path / binding / "project"
        source = TS_IMPORT + f'const {binding} = new McpServer({{ name: "analytics-mcp" }});\n'
        _scan(project, {"src/server.ts": source})
        out = tmp_path / f"{binding}.json"
        result = CliRunner().invoke(main, ["scan", "--report-only", str(project), "-o", str(out)])
        assert result.exit_code == 0, result.output
        out.write_text(out.read_text().replace(str(project), "/project"))
        inventories.append(str(out))
    result = CliRunner().invoke(main, ["diff", "--json-output", "--no-fail-on-alert", *inventories])
    alerts = json.loads(result.output)["security_alerts"]
    found = sorted((alert["severity"], alert["alert"]) for alert in alerts)
    assert found == expected


def test_repeated_name_entries_cost_what_one_does(tmp_path):
    """Only the winning entry is read: 1,850 long ones once cost ten times the file."""

    def root(name: str, key: Callable[[int], str]) -> Path:
        body = ", ".join(f'{key(i)}: "{f"n{i:04d}" * 25}abc"' for i in range(1850))
        source = TS_IMPORT + f"const server = new McpServer({{ {body} }});\n"
        _scan(tmp_path / name, {"src/server.ts": source})
        return tmp_path / name

    many = root("many", lambda i: "name")
    one = root("one", lambda i: "name" if i == 1849 else "title")

    def cost(project: Path) -> float:
        timings = []
        for _ in range(5):
            gc.collect()
            started = time.process_time()
            result = MCPScanner().scan(project)
            timings.append(time.process_time() - started)
        assert [s.name for s in _servers(result)] == [f"n{1849:04d}" * 25 + "abc"]
        return min(timings)

    assert cost(many) < 3 * cost(one)


def _main_inventory(tmp_path: Path, files: dict[str, str], rename: tuple[str, str] | None):
    """An inventory as main wrote it: the variable as the name and in a TypeScript reference."""
    project = tmp_path / "project"
    for relative, text in files.items():
        path = project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    out = tmp_path / "current.json"
    result = CliRunner().invoke(main, ["scan", "--report-only", str(project), "-o", str(out)])
    assert result.exit_code == 0, result.output
    text = out.read_text()
    if rename is not None:
        text = text.replace(*rename)
    data = json.loads(text)
    for component in data["components"]:
        if component["component_type"] == "mcp-server":
            component["name"] = component["properties"].pop("binding")
    earlier = tmp_path / "earlier.json"
    earlier.write_text(json.dumps(data))
    return project, out, earlier


@pytest.mark.parametrize(
    ("relative", "source", "local", "rename"),
    [
        (
            "src/server.ts",
            TS_IMPORT + 'const notes = new McpServer({ name: "analytics-mcp" });\n',
            f"mcp-source:src%2Fserver.ts:analytics-mcp:2:{len(TS_IMPORT) + 14}",
            (":analytics-mcp:2:", ":notes:2:"),
        ),
        (
            "src/server.ts",
            TS_IMPORT + "const notes = new McpServer({ name: `${prefix}-mcp` });\n",
            f"mcp-source:src%2Fserver.ts:notes:2:{len(TS_IMPORT) + 14}",
            None,
        ),
        (
            "src/server.py",
            PY_IMPORT + "mcp = FastMCP('analytics-mcp')\n",
            "mcp-python:src%2Fserver.py:mcp",
            None,
        ),
    ],
    ids=["typescript-literal", "typescript-computed", "python"],
)
def test_an_earlier_inventory_of_a_source_server_fails_project_reconciliation(
    tmp_path, relative, source, local, rename
):
    project, current, earlier = _main_inventory(tmp_path, {relative: source}, rename)
    mismatch = f"Missing or mismatched local component from MCP inventory: {local}"
    runner = CliRunner()
    validate = ["validate", "--project", str(project), "--skip-integrity"]
    risk = ["risk", "--project", str(project)]
    for command in (validate, risk):
        assert runner.invoke(main, [*command[:1], str(current), *command[1:]]).exit_code == 0
    validated = runner.invoke(main, [*validate[:1], str(earlier), *validate[1:]])
    assert validated.exit_code == 1
    assert mismatch in validated.output
    assert "Validation: FAILED" in validated.output
    risked = runner.invoke(main, [*risk[:1], str(earlier), *risk[1:]])
    assert risked.exit_code == 1
    assert risked.output.startswith("Risk unknown. Project reconciliation failed.\n")
    assert mismatch in risked.output
