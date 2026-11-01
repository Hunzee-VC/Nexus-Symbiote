import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner

IMPORT = "from mcp.server.mcpserver import MCPServer as Factory\n"
SERVER = "server = Factory('Demo')\n"


def scan(root: Path, source: str):
    path = root / "pkg" / "server.py"
    path.parent.mkdir(exist_ok=True)
    path.write_text(source)
    result = MCPScanner().scan(root)
    return result, [c for c in result.components if isinstance(c, ToolComponent)]


@pytest.mark.parametrize(
    "module, factory",
    [
        ("mcp.server.mcpserver", "MCPServer"),
        ("mcp.server.fastmcp", "FastMCP"),
        ("fastmcp", "FastMCP"),
    ],
)
def test_collects_source_names_without_running_module_or_claiming_a_descriptor(
    tmp_path, module, factory
):
    marker = tmp_path / "executed"
    result, tools = scan(
        tmp_path,
        f"from {module} import {factory} as Factory\n"
        + SERVER
        + f"open({str(marker)!r}, 'w').close()\n"
        + "@server.tool()\ndef add(a,b): pass\n"
        "@server.tool(name='lookup')\nasync def lookup_impl(): pass\n"
        "@server.resource('x://item')\ndef read(): pass\n"
        "@server.prompt()\ndef greet(): pass\n",
    )
    assert not marker.exists() and not result.scan_failures
    assert [tool.name for tool in tools] == ["add", "lookup"]
    assert all(
        tool.input_schema is None
        and tool.definition_hash is None
        and tool.claims["tool_definition"].unknown_reason
        for tool in tools
    )
    server = next(c for c in result.components if c.component_type.value == "mcp-server")
    assert server.tool_refs == [t.bom_ref for t in tools]
    assert all(t.mcp_server_ref == server.bom_ref for t in tools)


@pytest.mark.parametrize(
    "source",
    [
        IMPORT + SERVER + "server = object()\n@server.tool()\ndef fake(): pass\n",
        IMPORT + "Factory = fake\n" + SERVER + "@server.tool()\ndef fake(): pass\n",
        IMPORT + SERVER + "@server.tool(name=untrusted)\ndef fake(): pass\n",
        IMPORT + SERVER + "server.tool = unrelated\n@server.tool()\ndef fake(): pass\n",
        IMPORT + SERVER + "alias = server\n@alias.tool()\ndef fake(): pass\n",
        IMPORT + SERVER + "if flag:\n @server.tool()\n def fake(): pass\n",
        "from mcp.server import Server\nserver=Server('x', on_list_tools=callback)\n",
    ],
)
def test_unresolved_registration_is_visible_and_emits_no_tool(tmp_path, source):
    result, tools = scan(tmp_path, source)
    assert not tools
    assert any(
        "Python MCP" in gap or "MCP server tool list" in gap for gap in result.surfaces_excluded
    )


def test_duplicate_source_registration_fails_collection(tmp_path):
    result, tools = scan(
        tmp_path,
        IMPORT + SERVER + "@server.tool(name='x')\ndef one(): pass\n"
        "@server.tool(name='x')\ndef two(): pass\n",
    )
    assert [t.name for t in tools] == ["x"]
    assert any("duplicate Python MCP tool" in failure for failure in result.scan_failures)


def test_no_sdk_import_and_scan_cli_confines_python_collection(tmp_path):
    _, tools = scan(tmp_path, "other = Factory()\n@other.tool()\ndef fake(): pass\n")
    assert not tools
    (tmp_path / "pkg" / "server.py").write_text(
        IMPORT + SERVER + "@server.tool()\ndef count(): pass\n"
    )
    out = tmp_path / "inventory.json"
    result = CliRunner().invoke(
        main, ["scan", "--scanner", "mcp", "--report-only", "-o", str(out), str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert [
        c["name"]
        for c in json.loads(out.read_text())["components"]
        if c["component_type"] == "tool"
    ] == ["count"]
