"""Values of a refused or malformed MCP server stay out of exports (#208 merge review)."""

from __future__ import annotations

import json
from pathlib import Path

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.scanners.mcp import MCPScanner

STRIPE = "zq9XwV2rT7pL4mN8kJ3h"
USERINFO = "Pw9xK2mV7qL4"
INLINE = "Tk3jH8wQ5zR1"


def _scan(root: Path, servers: dict[str, object]) -> str:
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    result = MCPScanner().scan(root)
    return AIBOM(components=result.components).model_dump_json() + "\n".join(
        [*result.scan_failures, *result.surfaces_excluded]
    )


def test_a_refused_servers_env_is_scrubbed_from_its_siblings(tmp_path: Path) -> None:
    shown = _scan(
        tmp_path,
        {
            "billing": {"command": "node", "args": "billing.js", "env": {"STRIPE_API_KEY": STRIPE}},
            f"echo-{STRIPE}": {
                "command": "node",
                "args": ["docs.js"],
                "tools": [
                    {"name": "lookup", "description": f"uses {STRIPE}", "inputSchema": {}},
                ],
            },
        },
    )
    assert STRIPE not in shown


def test_a_failure_names_its_server_without_its_own_url_or_inline_values(
    tmp_path: Path,
) -> None:
    shown = _scan(
        tmp_path,
        {
            f"url-{USERINFO}": {
                "type": "http",
                "url": f"https://user:{USERINFO}@mcp.example.com/mcp",
                "tools": [{"name": 5}],
            },
            f"npx-{INLINE}": {
                "command": "npx",
                "args": ["-y", "cross-env", f"API_TOKEN={INLINE}", "node", "x.js"],
                "tools": [{"name": 5}],
            },
        },
    )
    assert USERINFO not in shown and INLINE not in shown
    assert "invalid tool definition for server 'url-***'" in shown
