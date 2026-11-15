import json
import warnings
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
        + "@server.tool(name='lookup')\nasync def lookup_impl(): pass\n"
        + "@server.resource('x://item')\ndef read(): pass\n"
        + "@server.prompt()\ndef greet(): pass\n",
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
        IMPORT
        + SERVER
        + "@server.tool(name='x')\ndef one(): pass\n"
        + "@server.tool(name='x')\ndef two(): pass\n",
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
        + "@tool('dup')\ndef one(): pass\n"
        + "@tool('dup')\ndef two(): pass\n",
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
        FASTMCP
        + "mcp = FastMCP('x')\n@mcp.tool()\ndef add(): pass\n"
        + "app = mcp.streamable_http_app()\nmcp.settings.port = 8000\n",
    )
    assert [tool.name for tool in tools] == ["add"] and not result.surfaces_excluded
    result, tools = scan(
        tmp_path,
        "from pydantic_ai import Agent\nfrom pydantic_ai.mcp import MCPServerStdio\n"
        + "agent = Agent('model')\n@agent.tool\ndef lookup(): pass\n",
    )
    # An agent framework's tool is an SDK tool, never an MCP registration gap; the
    # only gap is the launcher the file imports and passes on.
    assert [(tool.name, tool.properties["framework"]) for tool in tools] == [
        ("lookup", "pydantic-ai")
    ]
    assert result.surfaces_excluded == [
        "pkg/server.py: MCP launcher imported without a use here; servers started or "
        + "reached through it elsewhere not inventoried"
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
        FASTMCP
        + "mcp = FastMCP('x')\n@mcp.tool()\ndef add(): pass\n"
        + "def build(server: FastMCP, *, host: str) -> object:\n"
        + "    return server.streamable_http_app(host=host)\n"
        + "app = build(mcp, host='127.0.0.1')\n"
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
    "operation",
    [
        "mcp.run.__self__.tool()(delete_all)\n",
        "bound = mcp.run\nbound.__self__.tool()(delete_all)\n",
        "closure = mcp.resource('test://x')\n"
        + "closure.__closure__[0].cell_contents.tool()(delete_all)\n",
        "mcp.resource('test://x').__closure__[0].cell_contents.tool()(delete_all)\n",
        "def build(server):\n    def delayed(): server.run()\n    return delayed\n"
        + "handler = build(mcp)\nhandler.__closure__[0].cell_contents.tool()(delete_all)\n",
        "def build(server):\n    return locals()\n"
        + "items = build(mcp)\nitems['server'].tool()(delete_all)\n",
        "async def build(server): pass\n"
        + "task = build(mcp)\ntask.cr_frame.f_locals['server'].tool()(delete_all)\n",
        "def build(server):\n    yield None\n"
        + "gen = build(mcp)\ngen.gi_frame.f_locals['server'].tool()(delete_all)\n",
        "def build(server): server.run(transport='invalid')\n"
        + "try: build(mcp)\n"
        + "except Exception as error:\n"
        + " error.__traceback__.tb_next.tb_frame.f_locals['server'].tool()(delete_all)\n",
        "try: mcp.run(transport='invalid')\n"
        + "except Exception as error:\n"
        + " error.__traceback__.tb_next.tb_frame.f_locals['self'].tool()(delete_all)\n",
        "def register(server):\n    server.run.__self__.tool()(delete_all)\nregister(mcp)\n",
        "def hidden(value: mcp.tool()(delete_all)): pass\n",
        "def hidden() -> mcp.tool()(delete_all): pass\n",
        "registered: mcp.tool()(delete_all) = None\n",
        "def hidden(value: mcp): pass\nhidden.__annotations__['value'].tool()(delete_all)\n",
        "locals()['mcp'].tool()(delete_all)\n",
        "globals()['mcp'].tool()(delete_all)\n",
        "delete_all.__globals__['mcp'].tool()(delete_all)\n",
        "import builtins\nbuiltins.globals()['mcp'].tool()(delete_all)\n",
        "import sys\nsys.modules[__name__].mcp.tool()(delete_all)\n",
        "import anyio\nanyio.run(mcp.run_stdio_async)\n",
        "decorator = mcp.prompt()\n",
        "def hidden(value: lookup[FastMCP]): pass\n",
        "from typing import Optional\ndef hidden(value: Optional[mcp]): pass\n",
        "def hidden(value: mcp | None): pass\n",
        "vars()['mcp'].tool()(delete_all)\n",
        "for value in list(globals().values()):\n    if hasattr(value, 'tool'):\n"
        + "        value.tool()(delete_all)\n",
        "eval('mcp').tool()(delete_all)\n",
        "exec('mcp.tool()(delete_all)')\n",
        "import sys\ntry:\n    mcp.run()\nexcept Exception:\n    sys.exc_info()[2].tb_frame.f_back\n",
        "from sys import modules\nmodules[__name__].mcp.tool()(delete_all)\n",
        "import sys\ngetattr(sys, 'modules')[__name__].mcp.tool()(delete_all)\n",
        "import importlib\ngetattr(importlib.import_module(__name__), 'mcp').tool()(delete_all)\n",
        "def find(value):\n    return getattr(value, 'tool')\n",
        "__builtins__['globals']()['mcp'].tool()(delete_all)\n",
    ],
)
def test_escaping_bound_methods_and_executable_annotations_are_gaps(tmp_path, operation):
    source = FASTMCP + "mcp = FastMCP('x')\ndef delete_all(): pass\n" + operation
    result, tools = scan(tmp_path, source)
    assert not tools
    assert any("unsupported Python MCP" in gap for gap in result.surfaces_excluded)
    (tmp_path / "CLAUDE.md").write_text("Be helpful.\n")
    checked = CliRunner().invoke(main, ["scan", "--no-project-policy", "--check", str(tmp_path)])
    assert checked.exit_code == 1, checked.output
    assert "collection coverage is unknown or incomplete" in checked.output


def test_simple_server_type_annotation_and_direct_run_are_not_gaps(tmp_path):
    source = (
        FASTMCP + "mcp = FastMCP('x')\ndef takes_type(value: FastMCP) -> None: pass\nmcp.run()\n"
    )
    result, _ = scan(tmp_path, source)
    assert not result.scan_failures and not result.surfaces_excluded


def test_immediately_awaited_server_run_does_not_escape(tmp_path):
    source = FASTMCP + "mcp = FastMCP('x')\nasync def start():\n    await mcp.run_stdio_async()\n"
    result, _ = scan(tmp_path, source)
    assert not result.scan_failures and not result.surfaces_excluded


@pytest.mark.parametrize(
    "operation",
    [
        "app = mcp.streamable_http_app()\n",
        "app = mcp.sse_app()\n",
        "app = mcp.http_app()\n",
        "send_app(mcp.sse_app())\n",
        "import uvicorn\nuvicorn.run(mcp.sse_app())\n",
        "import asyncio\nasyncio.run(mcp.run_stdio_async())\n",
        "async def start():\n    return mcp.run_stdio_async()\n",
        "def build(server):\n    return server.sse_app()\napp = build(mcp)\n",
        "def start(server):\n    server.run()\nstart(mcp)\n",
        "try:\n    mcp.run()\nexcept KeyboardInterrupt:\n    pass\n",
        "print(mcp.name)\n",
        "instructions = mcp.instructions\n",
        "def configure(server: FastMCP | None): ...\n",
        "from typing import Optional\ndef configure(server: Optional[FastMCP]): ...\n",
        "def predict(model, x):\n    model.eval()\n    return model(x)\n",
        "def layers(model):\n    return list(model.modules())\n",
        "def total(df):\n    return df.eval('a + b')\n",
        "real = getattr(7, 'real')\n",
        "import os\nenviron = getattr(os, 'environ')\n",
    ],
)
def test_ordinary_server_use_is_not_a_gap(tmp_path, operation):
    source = FASTMCP + "mcp = FastMCP('x')\n@mcp.tool()\ndef add(): pass\n" + operation
    result, tools = scan(tmp_path, source)
    assert [tool.name for tool in tools] == ["add"]
    assert not result.scan_failures and not result.surfaces_excluded
    (tmp_path / "CLAUDE.md").write_text("Be helpful.\n")
    checked = CliRunner().invoke(main, ["scan", "--no-project-policy", "--check", str(tmp_path)])
    assert checked.exit_code == 0, checked.output


@pytest.mark.parametrize(
    "helper",
    [
        (
            "def build(server):\n    server.add_tool(export_all)\nbuild(mcp)\n"
            + "def build(server):\n    return server.sse_app()\n"
        ),
        (
            "from elsewhere import register_all\n"
            + "def build(server):\n    return server.sse_app()\nbuild = register_all\nbuild(mcp)\n"
        ),
        (
            "from elsewhere import registering\n"
            + "@registering\ndef build(server):\n    return server.sse_app()\nbuild(mcp)\n"
        ),
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
        AGENT + "agent = Agent('m')\nagent.run_sync.__self__.tool_plain(search)\n",
        AGENT + "agent = Agent('m')\nmethod = agent.run_sync\nmethod.__self__.tool_plain(search)\n",
        AGENT + "agent = Agent('m')\nasync def run():\n    async with agent as alias: pass\n",
        AGENT + "agent = Agent('m')\nglobals()['agent'].tool_plain(search)\n",
        AGENT + "agent = Agent('m')\n@agent.toolset\ndef tools(ctx): pass\n",
        AGENT + "agent = Agent('m')\nexecutor.submit(agent.run_sync, 'query')\n",
    ],
)
def test_agent_tools_outside_the_decorator_form_are_gaps(tmp_path, source):
    result, tools = scan(tmp_path, source)
    assert not tools
    assert result.surfaces_excluded == [
        "pkg/server.py: unsupported Python SDK tool binding or dynamic registration"
    ]


@pytest.mark.parametrize(
    "operation",
    [
        "result = agent.run_sync('query')\n",
        "try:\n    agent.run_sync('query')\nexcept Exception as error:\n    pass\n",
        "async def main():\n    result = await agent.run('query')\n    return result.output\n",
        "async def main():\n    async with agent.run_stream('query') as response:\n"
        + "        return await response.get_output()\n",
        "print(agent.name)\n",
        "@agent.system_prompt\ndef prompt() -> str:\n    return 'x'\n",
    ],
)
def test_ordinary_agent_use_is_not_a_gap(tmp_path, operation):
    source = AGENT + "agent = Agent('m')\n@agent.tool_plain\ndef search(): pass\n" + operation
    result, tools = scan(tmp_path, source)
    assert [tool.name for tool in tools] == ["search"]
    assert not result.scan_failures and not result.surfaces_excluded


def test_agent_tools_are_named_per_agent(tmp_path):
    result, tools = scan(
        tmp_path,
        AGENT
        + "a = Agent('m')\nb = Agent('m')\n"
        + "@a.tool_plain(name='search')\ndef one(): pass\n"
        + "@b.tool_plain(name='search')\ndef two(): pass\n"
        + "async def main():\n    async with a:\n        await a.run('q')\n",
    )
    assert not result.scan_failures and not result.surfaces_excluded
    assert [tool.bom_ref for tool in tools] == [
        "tool:python:pkg%2Fserver.py/a/search",
        "tool:python:pkg%2Fserver.py/b/search",
    ]


FASTMCP2 = "from fastmcp import FastMCP\n"
CONTEXT_TOOL = (
    FASTMCP
    + "from mcp.server.fastmcp import Context\nmcp = FastMCP('x')\n"
    + "@mcp.tool()\ndef read_note(ctx: Context):\n"
)


@pytest.mark.parametrize(
    "source",
    [
        FASTMCP
        + "async def startup(app):\n    app.add_tool(delete_all)\n    yield {}\n"
        + "mcp = FastMCP('x', lifespan=startup)\n@mcp.tool()\ndef read_note(): pass\n",
        FASTMCP2
        + "from fastmcp.server.middleware import Middleware\n"
        + "class Inject(Middleware):\n    pass\n"
        + "mcp = FastMCP('x', middleware=[Inject()])\n@mcp.tool\ndef read_note(): pass\n",
        FASTMCP2
        + "mcp = FastMCP('x', tool_transformations={'read_note': rename})\n"
        + "@mcp.tool\ndef read_note(): pass\n",
        FASTMCP2 + "mcp = FastMCP('x', None, None, startup)\n@mcp.tool\ndef read_note(): pass\n",
        FASTMCP
        + "from mcp.server.fastmcp import Context\nmcp = FastMCP('x')\n"
        + "@mcp.tool()\ndef read_note(ctx: Context):\n    ctx.fastmcp.add_tool(delete_all)\n",
        FASTMCP
        + "from mcp.server.fastmcp import Context\nmcp = FastMCP('x')\n"
        + "@mcp.tool()\ndef read_note(ctx: Context):\n"
        + "    ctx.request_context.lifespan_context['server'].add_tool(delete_all)\n",
        "from fastmcp.server.middleware import Middleware\n"
        + "class Inject(Middleware):\n"
        + "    async def on_list_tools(self, context, call_next):\n"
        + "        return context.fastmcp_context.fastmcp\n",
        "def register(ctx):\n    ctx.fastmcp.add_tool(delete_all)\n",
        "from mcp.types import TextContent\n"
        + "def register(ctx):\n    ctx.request_context.request.app\n",
        CONTEXT_TOOL + "    ctx._fastmcp.add_tool(delete_all)\n",
        CONTEXT_TOOL + "    ctx._request_context.lifespan_context\n",
        CONTEXT_TOOL + "    wire(ctx)\n",
        CONTEXT_TOOL + "    hold.append(ctx)\n",
        CONTEXT_TOOL + "    wire(ctx.read_resource)\n",
        CONTEXT_TOOL + "    c = ctx\n",
        CONTEXT_TOOL.replace("ctx: Context", "ctx: 'Context'") + "    wire(ctx)\n",
        CONTEXT_TOOL.replace("ctx: Context", "ctx: Context | None = None")
        + "    wire(ctx or None)\n",
        FASTMCP
        + "from mcp.server.fastmcp import Context as C\nclass Mine(C):\n    pass\n"
        + "mcp = FastMCP('x')\n@mcp.tool()\ndef read_note(ctx: Mine):\n    wire(ctx)\n",
        FASTMCP2
        + "from fastmcp.server.dependencies import get_context\nmcp = FastMCP('x')\n"
        + "@mcp.tool\ndef read_note():\n    c = get_context()\n    wire(c)\n",
        FASTMCP2
        + "from fastmcp.server.dependencies import get_context\nmcp = FastMCP('x')\n"
        + "@mcp.tool\ndef read_note():\n    wire(get_context())\n",
        FASTMCP2
        + "from fastmcp.server.context import _current_context\nmcp = FastMCP('x')\n"
        + "@mcp.tool\ndef read_note():\n    wire(_current_context.get())\n",
    ],
)
def test_servers_reached_through_sdk_handles_are_gaps(tmp_path, source):
    result, tools = scan(tmp_path, source)
    assert result.surfaces_excluded, source
    assert all(tool.name == "read_note" for tool in tools)
    (tmp_path / "CLAUDE.md").write_text("Be helpful.\n")
    checked = CliRunner().invoke(main, ["scan", "--no-project-policy", "--check", str(tmp_path)])
    assert checked.exit_code == 1, checked.output
    assert "collection coverage is unknown or incomplete" in checked.output


@pytest.mark.parametrize(
    "header",
    [
        FASTMCP + "from mcp.server.fastmcp import Context\n",
        FASTMCP2 + "from fastmcp import Context\n",
    ],
)
def test_context_used_for_logging_and_progress_is_not_a_gap(tmp_path, header):
    source = (
        header
        + "mcp = FastMCP('x', instructions='Notes')\n"
        + "@mcp.tool()\nasync def read_note(ctx: Context) -> str:\n"
        + "    await ctx.info('reading')\n    await ctx.report_progress(1, 2)\n"
        + "    return ctx.request_id\n"
        + "if __name__ == '__main__':\n    mcp.run()\n"
    )
    result, tools = scan(tmp_path, source)
    assert [tool.name for tool in tools] == ["read_note"]
    assert not result.scan_failures and not result.surfaces_excluded
    (tmp_path / "CLAUDE.md").write_text("Be helpful.\n")
    checked = CliRunner().invoke(main, ["scan", "--no-project-policy", "--check", str(tmp_path)])
    assert checked.exit_code == 0, checked.output


def test_context_passed_to_an_unread_module_is_a_gap(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "boot.py").write_text(
        "def wire(c):\n    getattr(c, 'fast' 'm' 'cp').add_tool(print)\n"
    )
    result, tools = scan(
        tmp_path,
        CONTEXT_TOOL.replace("Context\n", "Context\nfrom boot import wire\n", 1)
        + "    wire(ctx)\n    return 'note'\n",
    )
    assert [tool.name for tool in tools] == ["read_note"]
    assert result.surfaces_excluded == [
        "pkg/server.py: Python MCP server reachable through a request context"
    ]


@pytest.mark.parametrize(
    "source",
    [
        "import mcp.server.fastmcp.exceptions\n"
        + FASTMCP
        + "server = FastMCP('x')\n@server.tool()\ndef read_note(name: str) -> str:\n"
        + "    if not name:\n        raise mcp.server.fastmcp.exceptions.ToolError('no')\n"
        + "    return name\n",
        FASTMCP + "mcp = FastMCP('x', 'Notes', 'https://example.com')\n"
        "@mcp.tool()\ndef read_note() -> str:\n    return 'x'\n",
        FASTMCP2
        + "from fastmcp import Context\nfrom fastmcp.server.dependencies import get_context\n"
        + "mcp = FastMCP('x')\n@mcp.tool\nasync def read_note(ctx: Context | None = None):\n"
        + "    if ctx is not None and not ctx:\n        return ctx.session_id\n"
        + "    c = get_context()\n    await c.info('x')\n    return get_context().request_id\n",
    ],
)
def test_sdk_module_paths_and_plain_context_use_are_not_gaps(tmp_path, source):
    result, tools = scan(tmp_path, source)
    assert [tool.name for tool in tools] == ["read_note"]
    assert not result.scan_failures and not result.surfaces_excluded


def test_fastmcp_package_positional_limit_still_applies(tmp_path):
    result, tools = scan(
        tmp_path,
        FASTMCP2 + "mcp = FastMCP('x', 'Notes', startup)\n@mcp.tool\ndef read_note(): pass\n",
    )
    assert not tools
    assert result.surfaces_excluded


MCPSERVER = "from mcp.server.mcpserver import Context, MCPServer\nserver = MCPServer('x')\n"
MCPSERVER_TOOL = MCPSERVER + "@server.tool()\ndef read_note(ctx: Context):\n"
FASTMCP2_TOOL = FASTMCP2 + "mcp = FastMCP('x')\n@mcp.tool\n"


@pytest.mark.parametrize(
    "source",
    [
        "from mcp.server.mcpserver import MCPServer\n"
        + "server = MCPServer('x', extensions=[Extra()])\n"
        + "@server.tool()\ndef read_note(): pass\n",
        "from mcp.server.mcpserver import MCPServer\n"
        + "server = MCPServer('x', resources=[extra])\n@server.tool()\ndef read_note(): pass\n",
        FASTMCP2 + "mcp = FastMCP('x', transforms=[Extra()])\n@mcp.tool\ndef read_note(): pass\n",
        "from mcp.server.mcpserver import MCPServer\n"
        + "server = MCPServer('x', 'T', 'D', 'I', 'u', [], '1', provider)\n"
        + "@server.tool()\ndef read_note(): pass\n",
        "from fastmcp.server.dependencies import get_server\n"
        + FASTMCP2_TOOL
        + "def read_note():\n    get_server().add_tool(delete_all)\n",
        "import fastmcp.server.dependencies\n"
        + FASTMCP2_TOOL
        + "def read_note():\n    fastmcp.server.dependencies.get_server().add_tool(delete_all)\n",
        "from fastmcp.dependencies import CurrentFastMCP\n"
        + FASTMCP2_TOOL
        + "def read_note(server=CurrentFastMCP()):\n    server.add_tool(delete_all)\n",
        "from fastmcp.dependencies import CurrentContext\n"
        + FASTMCP2_TOOL
        + "def read_note(ctx=CurrentContext()):\n    wire(ctx)\n",
        "from fastmcp.server import dependencies\n"
        + FASTMCP2_TOOL
        + "def read_note(c=dependencies.OptionalCurrentContext()):\n    wire(c)\n",
        "from fastmcp.server import dependencies\n"
        + FASTMCP2_TOOL
        + "def read_note():\n    wire(dependencies.get_context())\n",
        "from fastmcp.server import dependencies\n"
        + FASTMCP2_TOOL
        + "def read_note():\n    wire(dependencies.get_context().model_copy())\n",
        "import mcp.server.lowlevel.server\n"
        + MCPSERVER
        + "@server.tool()\ndef read_note():\n"
        + "    wire(mcp.server.lowlevel.server.request_ctx.get())\n",
        MCPSERVER_TOOL + "    ctx.mcp_server.add_tool(delete_all)\n",
        MCPSERVER_TOOL + "    wire(ctx.model_copy())\n",
        MCPSERVER_TOOL.replace("server = ", "Ctx = Context\nserver = ").replace(
            "ctx: Context", "ctx: Ctx"
        )
        + "    wire(ctx)\n",
        MCPSERVER_TOOL.replace("server = ", "class Mine(Context):\n    pass\nserver = ")
        + "    pass\n",
        "from mcp.server import mcpserver as F\nfrom mcp.server.mcpserver import MCPServer\n"
        + "server = MCPServer('x')\n@server.tool()\ndef read_note(ctx: F.Context):\n"
        + "    wire(ctx)\n",
        "from fastmcp import Context as Ctx\n" + FASTMCP2_TOOL + "def read_note(): pass\n",
        "from fastmcp.server.dependencies import get_http_request\n"
        + FASTMCP2_TOOL
        + "def read_note():\n"
        + "    get_http_request().app.state.fastmcp_server.add_tool(delete_all)\n",
        "from fastmcp.server.dependencies import CurrentRequest\n"
        + FASTMCP2_TOOL
        + "def read_note(request=CurrentRequest()):\n    wire(request.app)\n",
        "from fastmcp.server.http import _current_http_request\n"
        + FASTMCP2_TOOL
        + "def read_note():\n    wire(_current_http_request.get())\n",
        "from starlette.requests import Request\n"
        + "def register(request: Request):\n"
        + "    request.app.state.fastmcp_server.add_tool(delete_all)\n",
        "from fastmcp.server.extensions import _extension_dispatch_scope\n"
        + FASTMCP2_TOOL
        + "def read_note():\n    _extension_dispatch_scope.get()[0].add_tool(delete_all)\n",
        "from fastmcp.server import extensions as E\n"
        + FASTMCP2_TOOL
        + "def read_note():\n    E._delegated_extension_scope.get()[0].add_tool(delete_all)\n",
        "from fastmcp.server.sessions import _future_server_handle\n"
        + FASTMCP2_TOOL
        + "def read_note():\n    wire(_future_server_handle)\n",
        FASTMCP2
        + "from fastmcp.server.dependencies import get_context\n"
        + "mcp = FastMCP('x')\ncurrent = None\n"
        + "@mcp.tool\nasync def read_note():\n    global current\n"
        + "    current = get_context()\n    await current.info('reading')\n"
        + "def list_notes():\n    wire(current)\n",
        FASTMCP2
        + "from fastmcp.server.dependencies import get_context\nmcp = FastMCP('x')\n"
        + "@mcp.tool\ndef read_note():\n    c = None\n"
        + "    def bind():\n        nonlocal c\n        c = get_context()\n"
        + "    bind()\n    wire(c)\n",
        FASTMCP2
        + "from fastmcp.server import context as C\n"
        + "mcp = FastMCP('x')\n@mcp.tool\n"
        + "async def read_note(ctx: getattr(C, 'Context')):\n    wire(ctx)\n",
        FASTMCP2
        + "from fastmcp.server import context as C\nCtx = getattr(C, 'Context')\n"
        + "mcp = FastMCP('x')\n@mcp.tool\ndef read_note(): pass\n",
        "from fastmcp.server import dependencies as D\n"
        + FASTMCP2_TOOL
        + "def read_note():\n    getattr(D, 'get_server')().add_tool(delete_all)\n",
        "from fastmcp.server import dependencies as D\ndef run():\n    getattr(D, 'get_server')()\n",
        "import fastmcp.dependencies as D\n"
        + FASTMCP2_TOOL
        + "def read_note(s=getattr(D, 'CurrentFastMCP')()):\n    s.add_tool(delete_all)\n",
        "from fastmcp.server import extensions as E\n"
        + FASTMCP2_TOOL
        + "def read_note():\n"
        + "    getattr(E, '_extension_dispatch_scope').get()[0].add_tool(delete_all)\n",
        "from fastmcp.server import dependencies as D\n"
        + FASTMCP2_TOOL
        + "def read_note():\n    getattr(D, 'get_context')()\n",
        "from fastmcp.server import dependencies as D\n"
        + FASTMCP2_TOOL
        + "def read_note():\n    getattr(D, 'get_http_request')()\n",
        "from fastmcp.server import dependencies as D\n"
        + FASTMCP2_TOOL
        + "def read_note():\n    getattr(D, 'get_' + 'server')().add_tool(delete_all)\n",
        "from fastmcp.server import dependencies as D\n"
        + "def run():\n    getattr(D, 'get_' + 'server')()\n",
        "def register(ctx):\n    getattr(ctx, 'fastmcp').add_tool(delete_all)\n",
        "def register(req):\n    getattr(req.app.state, 'fastmcp_server').add_tool(delete_all)\n",
        FASTMCP2
        + "from fastmcp.server.dependencies import get_context\nmcp = FastMCP('x')\n"
        + "class Box:\n    c = get_context()\nwire(Box.c)\n"
        + "@mcp.tool\ndef read_note(): pass\n",
        FASTMCP2
        + "from fastmcp.server.dependencies import get_context\nmcp = FastMCP('x')\n"
        + "@mcp.tool\ndef read_note():\n    class Box:\n        c = get_context()\n"
        + "    wire(Box.c)\n",
        "from fastmcp.server.dependencies import get_context\n"
        + "class Box:\n    c = get_context()\nwire(Box.c)\n",
        "import fastmcp\ndef handler(ctx):\n"
        + "    getattr(locals()['ctx'], 'fast' + 'm' + 'cp').add_tool(delete_all)\n",
        "from fastmcp import Context\ndef handler(ctx):\n"
        + "    getattr(ctx, 'fast' + 'm' + 'cp').add_tool(delete_all)\n",
        "from mcp.types import TextContent\ndef handler(ctx):\n"
        + "    getattr(locals()['ctx'], 'request_' + 'context').lifespan_context\n",
        "from __future__ import annotations\nfrom fastmcp.server import context as c\n"
        + FASTMCP2_TOOL
        + "def read_note(ctx: \"getattr(c, 'Con' + 'text')\") -> None:\n    pass\n",
        "from __future__ import annotations\nfrom fastmcp.server import context as c\n"
        + "def handler(ctx: \"getattr(c, 'Con' + 'text')\") -> None:\n    pass\n",
        "from __future__ import annotations\nfrom fastmcp.server import context as c\n"
        + FASTMCP2_TOOL
        + "def read_note(ctx: \"getattr(c, 'Context')\") -> None:\n    wire(ctx)\n",
        "from __future__ import annotations\nfrom fastmcp.server import context as c\n"
        + "def handler(ctx: \"builtins.getattr(c, 'Context')\") -> None:\n    pass\n",
        "from mcp.types import TextContent\nfrom pkg import kinds\n"
        + "def handler(ctx: getattr(kinds, 'Ctx')):\n    wire(ctx)\n",
        "from __future__ import annotations\n"
        + FASTMCP2_TOOL
        + 'def read_note(x: "mcp.add_tool(delete_all) or str") -> str:\n    return x\n',
        "from __future__ import annotations\n"
        + FASTMCP2_TOOL
        + "def read_note(x: \"FastMCP('shadow') and str\") -> str:\n    return x\n",
        "from __future__ import annotations\n"
        + FASTMCP2_TOOL
        + 'def read_note(x: "'
        + ("str | " * 900)
        + 'str") -> str:\n    return x\n',
    ],
)
def test_server_handles_of_current_sdks_are_gaps(tmp_path, source):
    result, tools = scan(tmp_path, source)
    assert result.surfaces_excluded, source
    assert all(tool.name == "read_note" for tool in tools)
    (tmp_path / "CLAUDE.md").write_text("Be helpful.\n")
    checked = CliRunner().invoke(main, ["scan", "--no-project-policy", "--check", str(tmp_path)])
    assert checked.exit_code == 1, checked.output
    assert "collection coverage is unknown or incomplete" in checked.output


@pytest.mark.parametrize(
    "source",
    [
        MCPSERVER
        + "@server.tool()\nasync def read_note(ctx: Context) -> str:\n"
        + "    user = (ctx.headers or {}).get('x-user', 'anon')\n"
        + "    await ctx.info(user, ctx.protocol_version, ctx.client_capabilities)\n"
        + "    return 'note'\n",
        FASTMCP2
        + "from fastmcp import Context\nmcp = FastMCP('x')\n@mcp.tool\n"
        + "async def read_note(ctx: Context) -> str:\n"
        + "    await ctx.set_state('t', ctx.transport)\n    return ctx.task_id\n",
        "from __future__ import annotations\nfrom typing import Literal\n"
        + FASTMCP2
        + "from fastmcp import Context\nmcp = FastMCP('x')\n"
        + "def _helper(srv: 'FastMCP | None') -> None:\n    pass\n"
        + "@mcp.tool\n"
        + "async def read_note(mode: Literal['not valid python!'], ctx: 'Context | None' = None)"
        + " -> str:\n"
        + "    if ctx is not None:\n        await ctx.info(mode)\n    return 'note'\n",
        "from mcp.server.mcpserver import MCPServer\n"
        + "server = MCPServer('x', 'Notes', 'Reads notes')\n"
        + "@server.tool()\ndef read_note() -> str:\n    return 'note'\n",
        "from fastmcp import __version__\n"
        + FASTMCP2_TOOL
        + "def read_note() -> str:\n    return __version__\n",
        "from langchain_core.tools import tool\n"
        + "class Memory:\n    def __init__(self):\n"
        + "        self.current_context = []\n        self.request_ctx = None\n"
        + "@tool\ndef read_note(query: str) -> str:\n    '''Read a note.'''\n    return query\n",
    ],
)
def test_context_data_and_plain_constructors_are_not_gaps(tmp_path, source):
    result, tools = scan(tmp_path, source)
    assert [tool.name for tool in tools] == ["read_note"]
    assert not result.scan_failures and not result.surfaces_excluded
    (tmp_path / "CLAUDE.md").write_text("Be helpful.\n")
    checked = CliRunner().invoke(main, ["scan", "--no-project-policy", "--check", str(tmp_path)])
    assert checked.exit_code == 0, checked.output


CONTEXT_GAP = "pkg/server.py: Python MCP server reachable through a request context"
BINDING_GAP = "pkg/server.py: unsupported Python MCP binding or dynamic registration"
NESTED_STR = repr(repr(repr(repr(repr("str")))))
LONG_UNION = '"' + "str | " * 600 + 'str"'


def assert_gap_fails_check(root: Path, source: str, gap: str) -> None:
    result, tools = scan(root, source)
    assert gap in result.surfaces_excluded, (source, result.surfaces_excluded)
    assert all(tool.name == "read_note" for tool in tools)
    (root / "CLAUDE.md").write_text("Be helpful.\n")
    checked = CliRunner().invoke(main, ["scan", "--no-project-policy", "--check", str(root)])
    assert checked.exit_code == 1, checked.output


@pytest.mark.parametrize(
    "source",
    [
        "import mcp.types\ndef register(ctx, tool):\n"
        + "    getattr(mcp, 'missing', ctx).fastmcp.add_tool(tool)\n",
        "import fastmcp.exceptions\ndef register(ctx, tool):\n"
        + "    getattr(fastmcp, 'missing', ctx).fastmcp.add_tool(tool)\n",
        "import mcp.types\n"
        + FASTMCP2
        + "server = FastMCP('x')\n@server.custom_route('/health', methods=['GET'])\n"
        + "async def health(request):\n    for route in request.app.routes:\n"
        + "        getattr(mcp, 'missing', route.app).fastmcp.add_tool(delete_all)\n"
        + "@server.tool\ndef read_note() -> str:\n    return 'note'\n",
        "import mcp.types\ndef register(ctx, tool):\n"
        + "    mcp.types.carrier = ctx\n    mcp.types.carrier.fastmcp.add_tool(tool)\n",
        "import mcp.server.fastmcp as fm\ndef register(tool):\n    fm.fastmcp.add_tool(tool)\n",
        "import mcp\ndef register(tool):\n    mcp.server.fastmcp.fastmcp.add_tool(tool)\n",
        "import fastmcp\nfastmcp.FastMCP.__init__ = hidden_init\n",
        "from mcp.server.fastmcp import server as S\ndel S.FastMCP.list_tools\n",
        "from fastmcp.server import dependencies as D\ndef run_note(value):\n    D.carrier = value\n",
        "from fastmcp.server import extensions\next = extensions\n"
        + "def scope():\n    return ext._dispatch_hook_v9.get()\n",
        "from fastmcp.server import extensions\n"
        + "def scope(obj):\n    return getattr(obj, 'missing', extensions)._hook_v9.get()\n",
        "import fastmcp\ngetattr(object, 'missing', fastmcp).FastMCP.__init__ = hidden_init\n",
    ],
)
def test_only_the_sdk_module_path_is_exempt_and_sdk_stores_are_gaps(tmp_path, source):
    assert_gap_fails_check(tmp_path, source, CONTEXT_GAP)


@pytest.mark.parametrize(
    "source",
    [
        FASTMCP2_TOOL
        + "def read_note(x: '*(mcp.add_tool(delete_all) or [str])') -> str:\n    return 'n'\n",
        FASTMCP2_TOOL + "def read_note(x: 'not valid python!') -> str:\n    return 'n'\n",
        "from mcp.types import TextContent\ndef handler(x: 'not valid python!'):\n    pass\n",
        "from langchain_core.tools import tool\nfrom mcp.types import TextContent\n"
        + "@tool\ndef read_note(q: 'not valid python!') -> str:\n    '''Read.'''\n    return q\n",
        "from pkg.kinds import Box\n"
        + FASTMCP2_TOOL
        + "def read_note(x: Box['mcp.add_tool(delete_all) or int']) -> str:\n    return 'n'\n",
        "from pkg.kinds import Box\n"
        + FASTMCP2_TOOL
        + "def read_note(x: Box[*['mcp.add_tool(delete_all) or int']]) -> str:\n"
        + "    return 'n'\n",
        "from typing import Dict as Literal\n"
        + FASTMCP2_TOOL
        + "def read_note(x: Literal[str, 'mcp.add_tool(delete_all) or int']) -> str:\n"
        + "    return 'n'\n",
        "from typing import Dict as Annotated\n"
        + FASTMCP2_TOOL
        + "def read_note(x: Annotated[str, 'mcp.add_tool(delete_all) or int']) -> str:\n"
        + "    return 'n'\n",
        FASTMCP2_TOOL
        + "def read_note(x: f\"{'mcp'}.add_tool(delete_all) or int\") -> str:\n    return 'n'\n",
        "from typing import ForwardRef\n"
        + FASTMCP2_TOOL
        + "def read_note(x: ForwardRef('mcp.add_tool(delete_all) or int')) -> str:\n"
        + "    return 'n'\n",
        FASTMCP2_TOOL
        + "def read_note() -> str:\n    return 'n'\n"
        + "class Args:\n    __annotations__ = {'x': 'mcp.add_tool(delete_all) or int'}\n",
        FASTMCP2_TOOL
        + "def read_note() -> str:\n    return 'n'\n"
        + "class Args:\n    def __annotate__(format):\n"
        + "        return {'x': 'mcp.add_tool(delete_all) or int'}\n",
        FASTMCP2_TOOL + f"def read_note(x: {NESTED_STR}) -> str:\n    return 'n'\n",
        FASTMCP2_TOOL
        + "def read_note("
        + ", ".join(f"{name}: {LONG_UNION}" for name in "abcde")
        + ") -> str:\n    return 'n'\n",
        "from fastmcp.server.dependencies import get_context\npeek = locals\n"
        + "def run_note():\n    ctx = get_context()\n    wire(peek()['ctx'])\n",
        "from mcp.types import TextContent\n"
        + "def run_note(ctx):\n    return __import__('builtins').vars()\n",
        "import fastmcp.server.dependencies as D\n"
        + "def run_note(value):\n    setattr(D, 'carrier', value)\n",
        "from langchain_core.tools import tool\n"
        + "from fastmcp.server.dependencies import get_context\n"
        + "@tool\ndef read_note(q: str) -> str:\n    '''Read.'''\n    return q\n"
        + "def run_note():\n    ctx = get_context()\n"
        + "    getattr(locals()['ctx'], 'fast' + 'm' + 'cp').add_tool(delete_all)\n",
        FASTMCP2_TOOL + "def read_note(x: str, vars=vars) -> str:\n    return vars()['x']\n",
        FASTMCP2_TOOL
        + "def read_note(vars: dict) -> str:\n    class Probe:\n        seen = vars()\n"
        + "    return ''\n",
        FASTMCP2_TOOL
        + "def read_note(vars: dict) -> str:\n    def probe():\n        return vars()\n"
        + "    return ''\n",
        FASTMCP2_TOOL + "def read_note() -> str:\n    return (lambda vars=vars: vars())()\n",
    ],
)
def test_annotation_strings_and_reflective_names_fail_closed(tmp_path, source):
    assert_gap_fails_check(tmp_path, source, BINDING_GAP)


@pytest.mark.parametrize(
    "annotation",
    ["'locals() and str'", "'agent.tool_plain(evil) or str'", "'not valid python!'"],
)
def test_agent_annotation_strings_fail_closed(tmp_path, annotation):
    result, tools = scan(
        tmp_path,
        AGENT + f"agent = Agent('m')\n@agent.tool_plain\ndef search(q: {annotation}): pass\n",
    )
    assert [tool.name for tool in tools] == ["search"]
    assert result.surfaces_excluded == [
        "pkg/server.py: unsupported Python SDK tool binding or dynamic registration"
    ]


def test_annotation_compiler_warnings_neither_print_nor_skip_the_string(tmp_path):
    source = (
        FASTMCP2_TOOL
        + "def read_note(x: \"mcp.add_tool(delete_all) or '\\\\q\x1b' and str\") -> str:\n"
        + "    return 'n'\n"
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        result, _ = scan(tmp_path, source)
    assert BINDING_GAP in result.surfaces_excluded
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result, _ = scan(tmp_path, source)
    assert BINDING_GAP in result.surfaces_excluded
    assert not [warning for warning in caught if "escape" in str(warning.message)]


@pytest.mark.parametrize(
    "source",
    [
        FASTMCP2
        + "mcp = FastMCP('templates')\n@mcp.tool\n"
        + "def read_note(template: str, vars: dict[str, str]) -> str:\n"
        + "    return template.format(**vars)\n",
        FASTMCP2_TOOL
        + "def read_note(name: str, exec: bool = False) -> str:\n"
        + "    return [name for _ in range(1) if exec][0]\n",
        "from typing import Annotated\n"
        + FASTMCP2_TOOL
        + "def read_note(\n    values: Annotated[dict[str, str], 'vars'],\n"
        + "    title: Annotated[str, 'The title, not code!'],\n) -> str:\n"
        + "    return title\n",
        "import typing\n"
        + FASTMCP2_TOOL
        + "def read_note(mode: typing.Literal['exec', 'plan', 'not code!'] = 'plan') -> str:\n"
        + "    return mode\n",
        "from typing import TypeVarTuple\n"
        + FASTMCP2
        + "Ts = TypeVarTuple('Ts')\nmcp = FastMCP('x')\n"
        + "def collect(*args: '*Ts') -> None:\n    pass\n"
        + "@mcp.tool\ndef read_note() -> 'list[str]':\n    return []\n",
        "import mcp.shared.exceptions, mcp.server.fastmcp.exceptions as errors\n"
        + FASTMCP
        + "server = FastMCP('x')\n@server.tool()\ndef read_note(name: str) -> str:\n"
        + "    if not name:\n        raise mcp.server.fastmcp.exceptions.ToolError(errors)\n"
        + "    return name\n",
    ],
)
def test_annotations_and_parameters_that_run_no_code_are_not_gaps(tmp_path, source):
    result, tools = scan(tmp_path, source)
    assert [tool.name for tool in tools] == ["read_note"]
    assert not result.scan_failures and not result.surfaces_excluded
    (tmp_path / "CLAUDE.md").write_text("Be helpful.\n")
    checked = CliRunner().invoke(main, ["scan", "--no-project-policy", "--check", str(tmp_path)])
    assert checked.exit_code == 0, checked.output


@pytest.mark.parametrize(
    "source",
    [
        "from mcp.types import TextContent\ndef to_text(blocks) -> list[str]:\n"
        + "    return [getattr(b, 'text', '') for b in blocks if isinstance(b, TextContent)]\n",
        "from mcp import ClientSession\nasync def titles(session: ClientSession) -> list[str]:\n"
        + "    result = await session.list_tools()\n"
        + "    return [getattr(tool, 'title', None) or tool.name for tool in result.tools]\n",
    ],
)
def test_literal_getattr_in_a_file_without_a_server_is_not_a_gap(tmp_path, source):
    result, tools = scan(tmp_path, source)
    assert not tools
    assert not result.scan_failures and not result.surfaces_excluded
