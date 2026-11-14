"""Merging server references across many nested client files costs linear time.

Each nested ``.mcp.json`` adds its servers to the host's client record. Re-sorting the
whole set once per file would make a checkout of N nested files cost N squared.
"""

from __future__ import annotations

import json
from pathlib import Path

from nexus_symbiote.scanners.mcp import MCPScanner
from tests.support import scaling_ratio


def _nested_configs(root: Path, count: int) -> None:
    for index in range(count):
        directory = root / f"pkg{index:05d}"
        directory.mkdir()
        (directory / ".mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        f"files{index}": {
                            "command": "npx",
                            "args": ["-y", f"@scope/files-mcp{index}@1.0.0"],
                        }
                    }
                }
            )
        )


def test_client_server_refs_merge_in_linear_time(tmp_path: Path) -> None:
    roots = {}
    for scale in (1, 4):
        roots[scale] = tmp_path / f"scale{scale}"
        roots[scale].mkdir()
        _nested_configs(roots[scale], 400 * scale)

    def run(scale: int) -> None:
        result = MCPScanner().scan(roots[scale])
        [client] = [c for c in result.components if c.component_type.value == "mcp-client"]
        assert len(client.server_refs) == 400 * scale

    assert scaling_ratio(run, repeats=1) < 8
