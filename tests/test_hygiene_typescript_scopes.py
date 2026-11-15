"""TypeScript scopes: a shadowing declaration neither hides a server nor borrows one.

A `let` in a loop head or a `const` in a `switch` body was bound in the enclosing scope.
Naming it after an SDK import made that import ambiguous, and every server, tool and
launcher in the file was then dropped with no gap. A `var` in a nested block was bound
in that block rather than in its function, so a later use of the name was resolved to
an outer server.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner
from tests.support import scaling_ratio

IMPORT = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
TRANSPORT = 'import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";\n'
SERVER = "const server = new McpServer({name: 'demo', version: '1'});\n"
REGISTER = 'server.registerTool("read_file", {}, handler);\n'
LAUNCH = "const transport = new StdioClientTransport({command: 'npx', args: ['x']});\n"
REDECLARED = "unsupported MCP server SDK binding"
LAUNCHED = "MCP server launched from application code; launcher not inventoried"


def _scan(root: Path, source: str):
    path = root / "src" / "server.ts"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return MCPScanner().scan(root)


def _tools(result) -> list[str]:
    return [c.name for c in result.components if isinstance(c, ToolComponent)]


def _servers(result) -> list[str]:
    return [c.name for c in result.components if isinstance(c, MCPServerComponent)]


@pytest.mark.parametrize(
    "shadow",
    [
        "for (let McpServer = 0; McpServer < 0; McpServer++) {}\n",
        "for (const McpServer of []) {}\n",
        "for (const McpServer in {}) {}\n",
        "for (const [McpServer] of []) {}\n",
        "switch (0) { case 1: const McpServer = 1; break; }\n",
        "switch (0) { default: let McpServer; }\n",
        "class Holder { static { var McpServer = 1; } }\n",
        "namespace Inner { var McpServer = 1; }\n",
        "for (let server = 0; server < 0; server++) {}\n",
        "switch (0) { case 1: const server = 1; }\n",
    ],
    ids=[
        "for-let",
        "for-of",
        "for-in",
        "for-of-pattern",
        "switch-const",
        "switch-let",
        "static-block-var",
        "namespace-var",
        "for-let-receiver",
        "switch-const-receiver",
    ],
)
def test_a_declaration_in_an_inner_scope_does_not_hide_the_server(tmp_path, shadow):
    result = _scan(tmp_path, IMPORT + shadow + SERVER + REGISTER)
    assert not result.scan_failures
    assert result.surfaces_excluded == []
    assert _servers(result) == ["server"]
    assert _tools(result) == ["read_file"]


@pytest.mark.parametrize(
    "shadow",
    [
        "for (let StdioClientTransport = 0; StdioClientTransport < 0; StdioClientTransport++) {}\n",
        "switch (0) { case 1: const StdioClientTransport = 1; break; }\n",
    ],
    ids=["for-let", "switch-const"],
)
def test_a_declaration_in_an_inner_scope_does_not_hide_a_launcher(tmp_path, shadow):
    result = _scan(tmp_path, TRANSPORT + shadow + LAUNCH)
    assert result.surfaces_excluded == [f"src/server.ts:3 ({LAUNCHED})"]


@pytest.mark.parametrize(
    "redeclaration",
    [
        "var McpServer = fake;\n",
        "if (cond) { var McpServer = fake; }\n",
        "for (var McpServer of fakes) {}\n",
        "for (var McpServer = fake;;) { break; }\n",
        "function McpServer() {}\n",
    ],
    ids=["var", "var-in-block", "for-of-var", "for-var", "function"],
)
def test_a_second_declaration_of_an_sdk_import_in_its_scope_is_a_named_gap(tmp_path, redeclaration):
    result = _scan(tmp_path, IMPORT + redeclaration + SERVER + REGISTER)
    assert _tools(result) == [] and _servers(result) == []
    assert f"src/server.ts:2 ({REDECLARED})" in result.surfaces_excluded


@pytest.mark.parametrize(
    "body",
    [
        'if (cond) { var server: any = fake; } server.tool("spoofed", {}, handler);',
        'for (var server of fakes) {} server.tool("spoofed", {}, handler);',
        '{ { var server = fake; } } server.registerTool("spoofed", {}, handler);',
    ],
    ids=["if-block", "for-of", "nested-blocks"],
)
def test_a_var_in_a_nested_block_belongs_to_its_function(tmp_path, body):
    source = IMPORT + SERVER + f"function later(cond, fake, fakes) {{ {body} }}\n"
    result = _scan(tmp_path, source)
    assert _servers(result) == ["server"]
    assert _tools(result) == []


@pytest.mark.parametrize(
    "loop",
    [
        'for (const server of fakes) { server.tool("spoofed", {}, handler); }\n',
        'for (let server in fakes) { server.tool("spoofed", {}, handler); }\n',
        'for (let server = fake; ; ) { server.tool("spoofed", {}, handler); break; }\n',
    ],
    ids=["for-of", "for-in", "for"],
)
def test_a_loop_variable_is_not_the_server_it_is_named_after(tmp_path, loop):
    result = _scan(tmp_path, IMPORT + SERVER + loop)
    assert _servers(result) == ["server"]
    assert _tools(result) == []


def test_hoisting_out_of_nested_blocks_is_linear_in_their_number(tmp_path):
    roots = {}
    for scale in (1, 4):
        functions = "".join(
            f"function f{index}() {{ {'{ ' * 12}var v{index} = 0;{' }' * 12} }}\n"
            for index in range(80 * scale)
        )
        roots[scale] = tmp_path / f"scale-{scale}"
        _scan(roots[scale], IMPORT + SERVER + REGISTER + functions)
    assert scaling_ratio(lambda scale: MCPScanner().scan(roots[scale])) < 10
    largest = MCPScanner().scan(roots[4])
    assert not largest.scan_failures and _tools(largest) == ["read_file"]
