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


def test_more_than_50_unrelated_python_files_do_not_trigger_mcp_limit_failure(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    for index in range(55):
        (pkg / f"module_{index:02d}.py").write_text(f"VALUE_{index} = {index}\n")
    (pkg / "z_mcp_server.py").write_text(IMPORT + SERVER + "@server.tool()\ndef ping(): pass\n")
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures
    tools = [c for c in result.components if isinstance(c, ToolComponent)]
    assert [tool.name for tool in tools] == ["ping"]


@pytest.mark.parametrize(
    "import_stmt, decorator_expr, expected_framework, expected_name",
    [
        ("from langchain_core.tools import tool\n", "@tool\n", "langchain", "search_kb"),
        (
            "from langchain.tools import tool\n",
            "@tool('custom_search')\n",
            "langchain",
            "custom_search",
        ),
        (
            "from crewai.tools import tool as crew_tool\n",
            "@crew_tool(name_or_callable='delegate_task')\n",
            "crewai",
            "delegate_task",
        ),
        (
            "from agents import function_tool\n",
            "@function_tool(name_override='fetch_profile')\n",
            "openai-agents",
            "fetch_profile",
        ),
        (
            "from agents.tool import function_tool\n",
            "@function_tool\n",
            "openai-agents",
            "search_kb",
        ),
        (
            "from smolagents import tool\n",
            "@tool\n",
            "smolagents",
            "search_kb",
        ),
        (
            "from smolagents.tools import tool\n",
            "@tool\n",
            "smolagents",
            "search_kb",
        ),
        (
            "from pydantic_ai import Agent\nagent = Agent('openai:gpt-4o')\n",
            "@agent.tool\n",
            "pydantic-ai",
            "search_kb",
        ),
        (
            "from pydantic_ai.agent import Agent\nagent: Agent = Agent('openai:gpt-4o')\n",
            "@agent.tool_plain(name='lookup_docs', retries=2)\n",
            "pydantic-ai",
            "lookup_docs",
        ),
    ],
)
def test_collects_standalone_agent_sdk_tool_decorators(
    tmp_path, import_stmt, decorator_expr, expected_framework, expected_name
):
    marker = tmp_path / "executed_sdk"
    result, tools = scan(
        tmp_path,
        import_stmt
        + f"open({str(marker)!r}, 'w').close()\n"
        + decorator_expr
        + "def search_kb(query: str) -> str:\n    return query\n",
    )
    assert not marker.exists() and not result.scan_failures and not result.surfaces_excluded
    assert [tool.name for tool in tools] == [expected_name]
    assert tools[0].properties["framework"] == expected_framework
    assert tools[0].claims["tool_definition"].unknown_reason


FASTMCP = "from mcp.server.fastmcp import FastMCP\n"


@pytest.mark.parametrize(
    "source",
    [
        "from langchain_core.tools import tool\n@tool(dynamic_name)\ndef f(): pass\n",
        "from langchain_core.tools import tool\nalias = tool\n@alias\ndef f(): pass\n",
        "from langchain_core.tools import tool\nif flag:\n    @tool\n    def f(): pass\n",
        "import langchain_core.tools\n",
        "from pydantic_ai import Agent\nagent = Agent('x')\nalias = agent\n@alias.tool\ndef f(): pass\n",
        "from pydantic_ai import Agent\nagent = Agent('x')\n@agent.tool(name=dynamic_name)\ndef f(): pass\n",
    ],
)
def test_unresolved_sdk_decorator_is_visible_and_emits_no_tool(tmp_path, source):
    result, tools = scan(tmp_path, source)
    assert not tools
    assert any("Python SDK tool" in gap for gap in result.surfaces_excluded)


def test_duplicate_sdk_decorator_name_fails_collection(tmp_path):
    result, tools = scan(
        tmp_path,
        "from langchain_core.tools import tool\n"
        "@tool('dup')\ndef one(): pass\n"
        "@tool('dup')\ndef two(): pass\n",
    )
    assert [t.name for t in tools] == ["dup"]
    assert any("duplicate Python SDK tool" in failure for failure in result.scan_failures)


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
    # An agent framework's tool is an SDK tool, never an MCP registration gap; the
    # only gap is the launcher the file imports and passes on.
    assert [(tool.name, tool.properties["framework"]) for tool in tools] == [
        ("lookup", "pydantic-ai")
    ]
    assert result.surfaces_excluded == [
        "pkg/server.py: MCP launcher imported without a use here; servers started or "
        "reached through it elsewhere not inventoried"
    ]


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


@pytest.mark.parametrize(
    "helper",
    [
        "def build(server):\n    server.add_tool(export_all)\nbuild(mcp)\n"
        "def build(server):\n    return server.sse_app()\n",
        "from elsewhere import register_all\n"
        "def build(server):\n    return server.sse_app()\nbuild = register_all\nbuild(mcp)\n",
        "from elsewhere import registering\n"
        "@registering\ndef build(server):\n    return server.sse_app()\nbuild(mcp)\n",
    ],
)
def test_a_helper_the_call_may_not_reach_is_not_judged_benign(tmp_path, helper):
    result, tools = scan(
        tmp_path, FASTMCP + "mcp = FastMCP('x')\n@mcp.tool()\ndef add(): pass\n" + helper
    )
    assert [tool.name for tool in tools] == ["add"]
    assert "pkg/server.py: unsupported Python MCP binding or dynamic registration" in (
        result.surfaces_excluded
    )


AGENT = "from pydantic_ai import Agent\n"


@pytest.mark.parametrize(
    "source",
    [
        AGENT + "agent = Agent('m', tools=[search])\n",
        AGENT + "agent = Agent('m', toolsets=[toolset])\n",
        AGENT + "agent = Agent('m', **options)\n",
        AGENT + "agent = Agent('m')\nregister(agent)\n",
        AGENT + "agent = Agent('m')\nagents = [agent]\n",
        AGENT + "agent = Agent('m')\ngetattr(agent, 'tool_plain')(search)\n",
    ],
)
def test_agent_tools_outside_the_decorator_form_are_gaps(tmp_path, source):
    result, tools = scan(tmp_path, source)
    assert not tools
    assert result.surfaces_excluded == [
        "pkg/server.py: unsupported Python SDK tool binding or dynamic registration"
    ]


def test_agent_tools_are_named_per_agent(tmp_path):
    result, tools = scan(
        tmp_path,
        AGENT + "a = Agent('m')\nb = Agent('m')\n"
        "@a.tool_plain(name='search')\ndef one(): pass\n"
        "@b.tool_plain(name='search')\ndef two(): pass\n"
        "async def main():\n    async with a:\n        await a.run('q')\n",
    )
    assert not result.scan_failures and not result.surfaces_excluded
    assert [tool.bom_ref for tool in tools] == [
        "tool:python:pkg%2Fserver.py/a/search",
        "tool:python:pkg%2Fserver.py/b/search",
    ]
