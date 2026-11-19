"""A source MCP server is named by the literal name its constructor declares.

`new McpServer({ name: "analytics-mcp", version: "1.0.0" })` and
`FastMCP("analytics-mcp")` were inventoried as the variable the server was bound to.
The literal is the name a client sees; the variable stays as evidence, and a name
computed at run time keeps the variable as the name.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.base import MAX_SERVER_NAME_CHARS, declared_server_name
from nexus_symbiote.scanners.mcp import MCPScanner

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
    ],
    ids=["positional", "keyword", "with-instructions", "implicit-concatenation", "keyword-last"],
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
