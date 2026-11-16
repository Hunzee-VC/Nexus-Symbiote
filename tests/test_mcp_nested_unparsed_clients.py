"""A client file whose MCP declarations are only detected is a gap at any depth
(Audit 2026-11-16, S2-03).

opencode, Zed and Continue read the copy in the directory they are started in, as the
parsed clients do, so a nested copy must leave a gap just as the root copy does.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from nexus_symbiote.scanners.mcp import MCPScanner

GAP = "MCP client configuration not inventoried"
SERVER = {"command": "npx", "args": ["-y", "unpinned-mcp-server"]}
FILES = {
    "opencode.json": {"mcp": {"s": {"type": "local", "command": ["npx", "-y", "x"]}}},
    "opencode.jsonc": {"mcp": {"s": {"type": "local", "command": ["npx", "-y", "x"]}}},
    ".zed/settings.json": {"context_servers": {"s": SERVER}},
}


def _write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


@pytest.mark.parametrize("name", sorted(FILES))
def test_nested_unparsed_client_file_is_a_gap(tmp_path: Path, name: str) -> None:
    _write(tmp_path / "pkg" / name, FILES[name])
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert result.surfaces_excluded == [f"pkg/{name}: {GAP}"]
    assert not result.scan_failures


def test_nested_unparsed_file_without_servers_is_no_gap(tmp_path: Path) -> None:
    _write(tmp_path / "pkg" / ".zed" / "settings.json", {"theme": "One Dark"})
    _write(tmp_path / "pkg" / "opencode.json", {"model": "x"})
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert result.surfaces_excluded == []


def test_nested_continue_server_directory_is_a_gap(tmp_path: Path) -> None:
    server = tmp_path / "pkg" / ".continue" / "mcpServers" / "x.yaml"
    server.parent.mkdir(parents=True)
    server.write_text("name: x\n", encoding="utf-8")
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert result.surfaces_excluded == [f"pkg/.continue/mcpServers: {GAP}"]


def test_root_and_nested_gaps_are_both_reported_once(tmp_path: Path) -> None:
    for base in (tmp_path, tmp_path / "a", tmp_path / "b"):
        _write(base / "opencode.json", FILES["opencode.json"])
        (base / ".continue" / "mcpServers").mkdir(parents=True)
        (base / ".continue" / "mcpServers" / "x.yaml").write_text("name: x\n")
        (base / ".continue" / "mcpServers" / "y.yaml").write_text("name: y\n")
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert result.surfaces_excluded == [
        f"opencode.json: {GAP}",
        f"a/opencode.json: {GAP}",
        f"b/opencode.json: {GAP}",
        f".continue/mcpServers: {GAP}",
        f"a/.continue/mcpServers: {GAP}",
        f"b/.continue/mcpServers: {GAP}",
    ]


@pytest.mark.parametrize(
    "variant", ["pkg/OpenCode.json", "pkg/.Zed/settings.json", "pkg/.zed/Settings.json"]
)
def test_nested_unparsed_case_variant_is_a_failure(tmp_path: Path, variant: str) -> None:
    exact = "pkg/opencode.json" if "pen" in variant.lower() else "pkg/.zed/settings.json"
    data = FILES[exact.removeprefix("pkg/")]
    _write(tmp_path / variant, data)
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert any(f.startswith(f"{variant}: case variant of {exact}") for f in result.scan_failures), (
        result.scan_failures
    )


def test_nested_continue_case_variant_is_a_failure(tmp_path: Path) -> None:
    server = tmp_path / "pkg" / ".Continue" / "mcpServers" / "x.yaml"
    server.parent.mkdir(parents=True)
    server.write_text("name: x\n", encoding="utf-8")
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert any(
        f.startswith("pkg/.Continue/mcpServers: case variant of pkg/.continue/mcpServers")
        for f in result.scan_failures
    ), result.scan_failures


def test_linked_zed_and_continue_directories_are_gaps(tmp_path: Path) -> None:
    _write(tmp_path / "shared" / "zed" / "settings.json", FILES[".zed/settings.json"])
    (tmp_path / "shared" / "cont" / "mcpServers").mkdir(parents=True)
    (tmp_path / "shared" / "cont" / "mcpServers" / "x.yaml").write_text("name: x\n")
    (tmp_path / "pkg").mkdir()
    os.symlink("../shared/zed", tmp_path / "pkg" / ".zed")
    os.symlink("../shared/cont", tmp_path / "pkg" / ".continue")
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert sorted(result.surfaces_excluded) == [
        f"pkg/.continue/mcpServers: {GAP}",
        f"pkg/.zed/settings.json: {GAP}",
    ]
    assert not result.scan_failures
