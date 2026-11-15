"""A malformed ``.npmrc`` value is one named failure, not a failure per server.

npm's ini reader decodes a quoted value as JSON. A value nested beyond the parser's
recursion limit must not escape as an exception that the server loop reports as an
invalid tool definition and that makes every later server read the file again.
"""

from __future__ import annotations

import json
from pathlib import Path

from nexus_symbiote.scanners.mcp import MCPScanner, _ini_text


def test_a_deeply_nested_quoted_npmrc_value_is_read_as_text() -> None:
    nested = "[" * 50_000 + "]" * 50_000
    assert _ini_text(f"'{nested}'") == nested


def test_servers_survive_a_deeply_nested_npmrc_value(tmp_path: Path) -> None:
    servers = {
        f"files{index}": {"command": "npx", "args": ["-y", f"@scope/files-mcp{index}@1.0.0"]}
        for index in range(4)
    }
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    nested = "[" * 50_000 + "]" * 50_000
    (tmp_path / ".npmrc").write_text(f"'{nested}'=x\nregistry=https://npm.example/\n")
    result = MCPScanner().scan(tmp_path)
    assert not any("invalid tool definition" in failure for failure in result.scan_failures)
    found = [c for c in result.components if c.component_type.value == "mcp-server"]
    assert len(found) == 4
    assert result.surfaces_scanned.count(".npmrc") == 1
