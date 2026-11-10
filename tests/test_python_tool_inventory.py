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


FASTMCP = "from mcp.server.fastmcp import FastMCP\n"


@pytest.mark.parametrize(
    "source",
    [
        FASTMCP + "mcp = FastMCP('x', tools=[export_all])\n",
        FASTMCP + "mcp = FastMCP('x', **options)\n",
        FASTMCP + "mcp = FastMCP('x')\nregister_tools(mcp)\n",
        FASTMCP + "mcp = FastMCP('x')\nmcp._tool_manager.add_tool(export_all)\n",
        FASTMCP + "mcp = FastMCP('x')\nmcp.tool()(export_all)\n",
        FASTMCP + "mcp = FastMCP('x')\nservers = [mcp]\n",
        FASTMCP + "F = FastMCP\nmcp = F('x')\n",
        FASTMCP + "class Server(FastMCP):\n    pass\n",
        FASTMCP + "mcp = FastMCP.from_openapi(spec)\n",
        "from server import mcp\n@mcp.tool()\ndef export_all(): pass\n",
        "import server\n@server.mcp.tool()\ndef export_all(): pass\n",
        "from mcp.server.lowlevel import Server\nserver = Server('x')\n",
    ],
)
def test_registrations_outside_the_supported_forms_are_gaps(tmp_path, source):
    result, tools = scan(tmp_path, source)
    assert not tools
    assert result.surfaces_excluded, source


@pytest.mark.parametrize(
    "module, factory",
    [
        ("mcp.server", "FastMCP"),
        ("mcp.server.fastmcp.server", "FastMCP"),
        ("fastmcp.server", "FastMCP"),
    ],
)
def test_additional_sdk_import_paths_are_collected(tmp_path, module, factory):
    result, tools = scan(
        tmp_path,
        f"from {module} import {factory}\nmcp = {factory}('x')\n@mcp.tool\ndef add(): pass\n"
        "if __name__ == '__main__':\n    mcp.run()\n",
    )
    assert [tool.name for tool in tools] == ["add"]
    assert not result.surfaces_excluded


def test_ordinary_server_use_and_other_frameworks_are_not_gaps(tmp_path):
    result, tools = scan(
        tmp_path,
        FASTMCP + "mcp = FastMCP('x')\n@mcp.tool()\ndef add(): pass\n"
        "app = mcp.streamable_http_app()\nmcp.settings.port = 8000\n",
    )
    assert [tool.name for tool in tools] == ["add"] and not result.surfaces_excluded
    result, tools = scan(
        tmp_path,
        "from pydantic_ai import Agent\nfrom pydantic_ai.mcp import MCPServerStdio\n"
        "agent = Agent('model')\n@agent.tool\ndef lookup(): pass\n",
    )
    assert not tools and not result.surfaces_excluded


def test_references_survive_inserted_lines_and_edits_change_the_digest(tmp_path):
    source = FASTMCP + "mcp = FastMCP('x')\n@mcp.tool()\ndef add(): pass\n"
    result, tools = scan(tmp_path, source)
    server = next(c for c in result.components if c.component_type.value == "mcp-server")
    moved, moved_tools = scan(tmp_path, "# a new comment line\n\n" + source)
    moved_server = next(c for c in moved.components if c.component_type.value == "mcp-server")
    assert moved_server.bom_ref == server.bom_ref == "mcp-python:pkg%2Fserver.py:mcp"
    assert [t.bom_ref for t in moved_tools] == [t.bom_ref for t in tools]
    assert moved_server.properties["declaration_line"] == server.properties["declaration_line"] + 2
    assert server.properties["source_sha256"] != moved_server.properties["source_sha256"]


def test_helpers_of_the_same_file_are_judged_by_what_they_do_with_the_server(tmp_path):
    benign = (
        FASTMCP + "mcp = FastMCP('x')\n@mcp.tool()\ndef add(): pass\n"
        "def build(server: FastMCP, *, host: str) -> object:\n"
        "    return server.streamable_http_app(host=host)\n"
        "app = build(mcp, host='127.0.0.1')\n"
    )
    result, tools = scan(tmp_path, benign)
    assert [tool.name for tool in tools] == ["add"] and not result.surfaces_excluded
    registering = benign.replace(
        "    return server.streamable_http_app(host=host)\n",
        "    server.add_tool(lambda: None)\n    return server.streamable_http_app(host=host)\n",
    )
    result, _ = scan(tmp_path, registering)
    assert result.surfaces_excluded
