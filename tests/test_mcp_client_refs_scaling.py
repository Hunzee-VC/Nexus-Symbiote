"""Merging server references across many nested client files costs linear time.

Each nested ``.mcp.json`` adds its servers to the host's client record. Re-sorting the
whole set once per file would make a checkout of N nested files cost N squared.
"""

from __future__ import annotations

import builtins
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.scanners import mcp
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


def test_client_server_refs_are_sorted_once_per_host_not_once_per_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The work, counted rather than timed, grows linearly with the number of files.

    Timing cannot see the old merge at a size the suite can afford: sorting the union
    after every file is quadratic, but cheap next to reading the files, so the timed
    test above passes on the old code too (audit 2026-11-14 L12). Counting the items
    the collector hands to ``sorted`` measures the merge itself.
    """
    sorted_items = 0

    def counting_sorted(iterable: Iterable[Any], /, **kwargs: Any) -> list[Any]:
        nonlocal sorted_items
        items = list(iterable)
        sorted_items += len(items)
        return builtins.sorted(items, **kwargs)

    monkeypatch.setattr(mcp, "sorted", counting_sorted, raising=False)
    counts = {}
    for scale in (1, 4):
        root = tmp_path / f"scale{scale}"
        root.mkdir()
        _nested_configs(root, 400 * scale)
        sorted_items = 0
        result = MCPScanner().scan(root)
        [client] = [c for c in result.components if c.component_type.value == "mcp-client"]
        assert len(client.server_refs) == 400 * scale
        counts[scale] = sorted_items
    # Linear work grows about four times; the old per-file merge grew sixteen times.
    assert counts[4] < 8 * counts[1], counts
