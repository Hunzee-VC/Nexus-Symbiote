"""Discovery cases for tools: function schemas, decorated functions and MCP tool registrations."""

from __future__ import annotations

from .build import as_json, case, decoy, edge, ex, has, lic, loc, text, ver
from .model import Case


def function_schemas() -> Case:
    tools = [
        {
            "type": "function",
            "function": {
                "name": "lookup_order",
                "description": "Look up an order by its public order number.",
                "parameters": {
                    "type": "object",
                    "properties": {"order_number": {"type": "string"}},
                    "required": ["order_number"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "issue_refund",
                "description": "Issue a refund for a delivered order.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "order_number": {"type": "string"},
                        "amount_cents": {"type": "integer", "minimum": 1},
                    },
                    "required": ["order_number", "amount_cents"],
                },
            },
        },
    ]
    agent = text(
        """
        import json
        from pathlib import Path

        from openai import OpenAI

        TOOLS = json.loads(Path("tools/tools.json").read_text())
        client = OpenAI()


        def answer(question: str) -> object:
            return client.chat.completions.create(
                model="gpt-4.1-mini",
                messages=[{"role": "user", "content": question}],
                tools=TOOLS,
            )
        """
    )
    return case(
        "t01-function-schemas",
        "Function-calling tools declared as JSON schemas",
        {"tools/tools.json": as_json(tools), "src/agent.py": agent},
        [
            ex(
                "t01.lookup",
                "tool",
                "function-tool",
                "lookup_order",
                attrs=[has("description", "public order number"), loc("tools/tools.json")],
            ),
            ex(
                "t01.refund",
                "tool",
                "function-tool",
                "issue_refund",
                attrs=[has("description", "delivered order"), loc("tools/tools.json")],
            ),
        ],
        surface="function tool definitions in JSON",
        sources=("OpenAI function calling", "Cisco", "OWASP Agentic Top 10"),
    )


def decorated_tools() -> Case:
    source = text(
        '''
        from agents import function_tool
        from langchain_core.tools import tool


        @tool
        def search_flights(origin: str, destination: str, date: str) -> list[dict[str, str]]:
            """Search published fares between two airports on a date."""
            return []


        @function_tool
        def book_hotel(city: str, nights: int) -> str:
            """Reserve a refundable hotel room."""
            return "pending"


        def decoy_internal_helper(value: str) -> str:
            return value.strip().lower()
        '''
    )
    return case(
        "t02-decorated-tools",
        "Tools declared with framework decorators in Python",
        {"src/travel_tools.py": source},
        [
            ex(
                "t02.flights",
                "tool",
                "function-tool",
                "search_flights",
                attrs=[has("description", "published fares"), loc("src/travel_tools.py")],
            ),
            ex(
                "t02.hotel",
                "tool",
                "function-tool",
                "book_hotel",
                attrs=[has("description", "refundable hotel room"), loc("src/travel_tools.py")],
            ),
        ],
        decoys=[
            decoy(
                "t02.helper",
                "decoy_internal_helper",
                "t02.flights",
                "an undecorated function is not a tool",
            )
        ],
        surface="LangChain and OpenAI Agents SDK tool decorators",
        sources=("LangChain", "OpenAI Agents SDK", "Cisco"),
    )


def python_mcp_server() -> Case:
    server = text(
        '''
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("weather-desk")


        @mcp.tool()
        def get_forecast(city: str, days: int = 3) -> str:
            """Return the daily forecast for a city."""
            return f"{city}: clear for {days} days"


        @mcp.tool()
        def get_alerts(region: str) -> list[str]:
            """List active weather alerts for a region."""
            return []


        @mcp.resource("stations://{station_id}")
        def station(station_id: str) -> str:
            """Describe one weather station."""
            return station_id


        if __name__ == "__main__":
            mcp.run()
        '''
    )
    project = text(
        """
        [project]
        name = "weather-desk"
        version = "0.3.0"
        requires-python = ">=3.11"
        dependencies = ["mcp==1.2.0"]
        """
    )
    return case(
        "t03-python-mcp-server",
        "MCP server implemented in Python with decorated tools",
        {"server.py": server, "pyproject.toml": project},
        [
            ex("t03.server", "tool", "mcp-server-source", "weather-desk", attrs=[loc("server.py")]),
            ex(
                "t03.forecast",
                "tool",
                "mcp-tool",
                "get_forecast",
                attrs=[has("description", "daily forecast"), loc("server.py")],
            ),
            ex(
                "t03.alerts",
                "tool",
                "mcp-tool",
                "get_alerts",
                attrs=[has("description", "active weather alerts"), loc("server.py")],
            ),
        ],
        edges=[
            edge("t03.server", "t03.forecast", "exposes"),
            edge("t03.server", "t03.alerts", "exposes"),
        ],
        surface="FastMCP tool registrations",
        sources=("MCP Python SDK", "agent-bom", "Cisco"),
    )


def typescript_mcp_server() -> Case:
    server = text(
        """
        import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
        import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
        import { z } from "zod";

        const server = new McpServer({ name: "helpdesk-mcp", version: "1.6.0" });

        server.registerTool(
          "create_ticket",
          {
            title: "Create ticket",
            description: "Open a helpdesk ticket for a customer.",
            inputSchema: { subject: z.string(), body: z.string() },
          },
          async ({ subject }) => ({ content: [{ type: "text", text: `created ${subject}` }] }),
        );

        server.tool(
          "close_ticket",
          "Close a resolved helpdesk ticket.",
          { ticketId: z.string() },
          async ({ ticketId }) => ({ content: [{ type: "text", text: `closed ${ticketId}` }] }),
        );

        await server.connect(new StdioServerTransport());
        """
    )
    package = {
        "name": "helpdesk-mcp",
        "version": "1.6.0",
        "type": "module",
        "dependencies": {"@modelcontextprotocol/sdk": "1.0.3", "zod": "3.23.8"},
    }
    return case(
        "t04-typescript-mcp-server",
        "MCP server implemented in TypeScript with registered tools",
        {"src/index.ts": server, "package.json": as_json(package)},
        [
            ex("t04.server", "tool", "mcp-server-source", "helpdesk-mcp", attrs=[ver("1.6.0")]),
            ex(
                "t04.create",
                "tool",
                "mcp-tool",
                "create_ticket",
                attrs=[has("description", "helpdesk ticket for a customer"), loc("src/index.ts")],
            ),
            ex(
                "t04.close",
                "tool",
                "mcp-tool",
                "close_ticket",
                attrs=[has("description", "resolved helpdesk ticket"), loc("src/index.ts")],
            ),
        ],
        edges=[
            edge("t04.server", "t04.create", "exposes"),
            edge("t04.server", "t04.close", "exposes"),
        ],
        surface="MCP TypeScript SDK tool registrations",
        sources=("MCP TypeScript SDK", "agent-bom", "Cisco"),
    )


def mcp_bundle_manifest() -> Case:
    manifest = {
        "manifest_version": "0.2",
        "name": "ledger-tools",
        "display_name": "Ledger Tools",
        "version": "1.4.2",
        "description": "Query and export ledger data.",
        "author": {"name": "Acme Finance Engineering"},
        "license": "MIT",
        "server": {
            "type": "node",
            "entry_point": "server/index.js",
            "mcp_config": {"command": "node", "args": ["${__dirname}/server/index.js"]},
        },
        "tools": [
            {"name": "query_ledger", "description": "Run a read-only ledger query."},
            {"name": "export_report", "description": "Export a month-end report as CSV."},
        ],
    }
    return case(
        "t05-mcp-bundle-manifest",
        "MCP bundle manifest that lists its tools",
        {
            "extension/manifest.json": as_json(manifest),
            "extension/server/index.js": text('console.error("ledger-tools server starting");'),
        },
        [
            ex(
                "t05.bundle",
                "tool",
                "mcp-bundle",
                "ledger-tools",
                attrs=[ver("1.4.2"), lic("MIT"), loc("extension/manifest.json")],
            ),
            ex(
                "t05.query",
                "tool",
                "mcp-tool",
                "query_ledger",
                attrs=[has("description", "read-only ledger query")],
            ),
            ex(
                "t05.export",
                "tool",
                "mcp-tool",
                "export_report",
                attrs=[has("description", "month-end report")],
            ),
        ],
        edges=[
            edge("t05.bundle", "t05.query", "exposes"),
            edge("t05.bundle", "t05.export", "exposes"),
        ],
        surface="MCP bundle (MCPB) manifest",
        sources=("MCP bundle manifest",),
    )


def cases() -> list[Case]:
    return [
        function_schemas(),
        decorated_tools(),
        python_mcp_server(),
        typescript_mcp_server(),
        mcp_bundle_manifest(),
    ]
