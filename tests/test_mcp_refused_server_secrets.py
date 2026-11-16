"""Values of a refused or malformed MCP server stay out of exports (#208 merge review)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.scanners.mcp import MCPScanner, _diagnostic_values

STRIPE = "zq9XwV2rT7pL4mN8kJ3h"
USERINFO = "Pw9xK2mV7qL4"
INLINE = "Tk3jH8wQ5zR1"
WORDS = "correcthorsewalrus"


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


def test_a_large_tool_list_does_not_use_up_the_walk_before_the_url(tmp_path: Path) -> None:
    tools: list[object] = [{"name": 5}]
    tools.extend(
        {"name": f"t{index}", "inputSchema": {"properties": {f"p{n}": {} for n in range(20)}}}
        for index in range(300)
    )
    shown = _scan(
        tmp_path,
        {
            f"url-{WORDS}": {
                "type": "http",
                "url": f"https://user:{WORDS}@mcp.example.com/mcp",
                "tools": tools,
            },
        },
    )
    assert WORDS not in shown
    assert "invalid tool definition for server 'url-***'" in shown


def test_a_large_unknown_field_withholds_the_failing_servers_name(tmp_path: Path) -> None:
    shown = _scan(
        tmp_path,
        {
            f"url-{WORDS}": _failing(
                {
                    "type": "http",
                    "url": "https://mcp.example.com/mcp",
                    "metadata": {f"k{index}": "v" for index in range(5000)},
                }
            ),
        },
    )
    assert WORDS not in shown
    assert "invalid tool definition for server '[withheld]'" in shown


def test_launch_fields_too_large_to_walk_are_refused() -> None:
    # The parser's argument limit refuses such a server first; the walk fails closed too.
    assert _diagnostic_values({"args": [f"API_TOKEN={WORDS}", *(["x"] * 5000)]}) is None


def test_a_short_user_name_is_not_scrubbed_from_names_but_a_short_password_is(
    tmp_path: Path,
) -> None:
    shown = _scan(
        tmp_path,
        {
            "git-mirror-hunter2": {
                "type": "http",
                "url": "https://git:hunter2@mcp.example.com/mcp",
                "tools": [{"name": 5}],
            },
        },
    )
    assert "hunter2" not in shown
    assert "invalid tool definition for server 'git-mirror-***'" in shown


def test_a_long_user_name_is_scrubbed_from_a_failing_servers_name(tmp_path: Path) -> None:
    shown = _scan(
        tmp_path,
        {
            f"mirror-{USERINFO}": {
                "type": "http",
                "url": f"https://{USERINFO}@mcp.example.com/mcp",
                "tools": [{"name": 5}],
            },
        },
    )
    assert USERINFO not in shown
    assert "invalid tool definition for server 'mirror-***'" in shown


def _failing(config: dict[str, object]) -> dict[str, object]:
    return {**config, "tools": [{"name": 5}]}


@pytest.mark.parametrize(
    "config",
    [
        {"command": "node", "env": {"DATABASE_URL": f"postgres://svc:{WORDS}@db.example.com/app"}},
        {
            "type": "http",
            "url": "https://mcp.example.com/mcp",
            "headers": {"X-Up": f"https://s:{WORDS}@u.example"},
        },
        {
            "type": "http",
            "url": "https://mcp.example.com/mcp",
            "http_headers": {"X-Up": f"https://s:{WORDS}@u.example"},
        },
        {
            "type": "http",
            "url": "https://mcp.example.com/mcp",
            "auth": {"tokenUrl": f"https://c:{WORDS}@auth.example/t"},
        },
        {"type": "http", "url": "https://mcp.example.com/mcp", "oauth": {"clientSecret": WORDS}},
        {"command": "node", "dev": {"debug": {"url": f"https://d:{WORDS}@dbg.example"}}},
        {
            "command": "npx",
            "args": ["-y", "mcp-remote", f"--url=https://user:{WORDS}@mcp.example.com/mcp"],
        },
        {
            "command": "sh",
            "args": ["-c", f"exec mcp-remote https://user:{WORDS}@mcp.example.com/mcp"],
        },
        {"command": "docker", "args": ["run", f"--env=API_TOKEN={WORDS}", "image"]},
        {"type": "http", "url": f"https://user:{WORDS}@mcp.example.com\\@x.example/mcp"},
        {"type": "http", "url": "https://mcp.example.com/mcp", "proxy": f"https://p:{WORDS}@px"},
    ],
)
def test_a_failing_servers_name_never_shows_a_credential_its_fields_hold(
    tmp_path: Path, config: dict[str, object]
) -> None:
    shown = _scan(tmp_path, {f"srv-{WORDS}": _failing(config)})
    assert WORDS not in shown
    assert "invalid tool definition for server 'srv-***'" in shown


def test_a_percent_encoded_password_is_scrubbed_as_decoded(tmp_path: Path) -> None:
    shown = _scan(
        tmp_path,
        {
            "pe-correct-horse-walrus": _failing(
                {"type": "http", "url": "https://u:correct%2Dhorse%2Dwalrus@mcp.example.com/mcp"}
            ),
        },
    )
    assert "correct-horse-walrus" not in shown
    assert "invalid tool definition for server 'pe-***'" in shown


def test_a_field_too_large_to_walk_withholds_the_failing_servers_name(tmp_path: Path) -> None:
    # `uri` is walked but not validated, so it can hold more than the walk reads.
    shown = _scan(
        tmp_path,
        {
            f"srv-{WORDS}": _failing(
                {"type": "http", "url": "https://mcp.example.com/mcp", "uri": [["x"] * 5000]}
            ),
        },
    )
    assert WORDS not in shown
    assert "invalid tool definition for server '[withheld]'" in shown
