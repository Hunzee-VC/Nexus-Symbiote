"""A nested copy of a Zed, opencode, Continue or Junie client file is read as that
dialect, as nested copies of the other dialects are (Audit 2026-11-16, S2-03).

opencode, Zed, Continue and Junie read the copy in the directory they are started in,
so a nested copy is inventoried as the root copy is, another spelling of one is a
case-variant failure, and a copy behind a directory symlink is read through it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from nexus_symbiote.core.models import MCPClientComponent, MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner

DIRECTORY_GAP = "file below an MCP server directory that the collector does not read there"
SERVER = {"command": "npx", "args": ["-y", "pinned-mcp-server@1.0.0"]}
BLOCK = "mcpServers:\n  - name: s\n    command: npx\n    args: [-y, pinned-mcp-server@1.0.0]\n"
FILES: dict[str, str] = {
    "opencode.json": json.dumps({"mcp": {"s": {"type": "local", "command": ["npx", "-y", "x"]}}}),
    "opencode.jsonc": json.dumps({"mcp": {"s": {"type": "local", "command": ["npx", "-y", "x"]}}}),
    ".zed/settings.json": json.dumps({"context_servers": {"s": SERVER}}),
    ".continue/config.yaml": BLOCK,
    ".continue/mcpServers/x.yaml": BLOCK,
    ".junie/mcp/mcp.json": json.dumps({"mcpServers": {"s": SERVER}}),
}
HOSTS = {
    "opencode.json": "opencode",
    "opencode.jsonc": "opencode",
    ".zed/settings.json": "zed",
    ".continue/config.yaml": "continue",
    ".continue/mcpServers/x.yaml": "continue",
    ".junie/mcp/mcp.json": "junie",
}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _servers(result) -> dict[str, MCPServerComponent]:
    return {c.source_path: c for c in result.components if isinstance(c, MCPServerComponent)}


def _clients(result) -> dict[str, MCPClientComponent]:
    return {c.host_application: c for c in result.components if isinstance(c, MCPClientComponent)}


@pytest.mark.parametrize("name", sorted(FILES))
def test_nested_client_file_is_read_as_its_dialect(tmp_path: Path, name: str) -> None:
    _write(tmp_path / "pkg" / name, FILES[name])
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert not result.scan_failures and not result.surfaces_excluded
    [server] = _servers(result).values()
    assert server.name == "s" and server.command == "npx"
    assert server.source_path == f"pkg/{name}"
    client = _clients(result)[HOSTS[name]]
    assert client.properties["config_paths"] == [f"pkg/{name}"]
    assert client.server_refs == [server.bom_ref]
    assert result.surfaces_scanned == [f"pkg/{name}"]


def test_nested_file_without_servers_creates_no_client(tmp_path: Path) -> None:
    _write(tmp_path / "pkg" / ".zed" / "settings.json", '{"theme": "One Dark"}')
    _write(tmp_path / "pkg" / "opencode.json", '{"model": "x"}')
    _write(tmp_path / "pkg" / ".continue" / "config.yaml", "models: []\n")
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert not result.components and not result.surfaces_excluded and not result.scan_failures
    assert result.surfaces_scanned == [
        "pkg/.continue/config.yaml",
        "pkg/.zed/settings.json",
        "pkg/opencode.json",
    ]


def test_root_and_nested_copies_are_each_read_once(tmp_path: Path) -> None:
    for base in (tmp_path, tmp_path / "a", tmp_path / "b"):
        _write(base / "opencode.json", FILES["opencode.json"])
        _write(base / ".continue" / "mcpServers" / "x.yaml", BLOCK)
        _write(base / ".continue" / "mcpServers" / "y.yaml", BLOCK.replace("name: s", "name: t"))
        _write(base / ".continue" / "mcpServers" / "deeper" / "z.yaml", BLOCK)
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert not result.scan_failures
    assert result.surfaces_scanned == [
        "opencode.json",
        ".continue/mcpServers/x.yaml",
        ".continue/mcpServers/y.yaml",
        "a/.continue/mcpServers/x.yaml",
        "a/.continue/mcpServers/y.yaml",
        "a/opencode.json",
        "b/.continue/mcpServers/x.yaml",
        "b/.continue/mcpServers/y.yaml",
        "b/opencode.json",
    ]
    assert result.surfaces_excluded == [
        f".continue/mcpServers/deeper/z.yaml: {DIRECTORY_GAP}",
        f"a/.continue/mcpServers/deeper/z.yaml: {DIRECTORY_GAP}",
        f"b/.continue/mcpServers/deeper/z.yaml: {DIRECTORY_GAP}",
    ]
    assert len(_servers(result)) == 9
    assert sorted(_clients(result)["continue"].properties["config_paths"]) == sorted(
        path for path in result.surfaces_scanned if ".continue" in path
    )


@pytest.mark.parametrize(
    ("variant", "exact"),
    [
        ("pkg/OpenCode.json", "pkg/opencode.json"),
        ("pkg/.Zed/settings.json", "pkg/.zed/settings.json"),
        ("pkg/.zed/Settings.json", "pkg/.zed/settings.json"),
        ("pkg/.Continue/mcpServers/x.yaml", "pkg/.continue/mcpServers/x.yaml"),
        ("pkg/.continue/MCPServers/x.yaml", "pkg/.continue/mcpServers/x.yaml"),
        ("pkg/.continue/Config.yaml", "pkg/.continue/config.yaml"),
        ("pkg/.junie/MCP/mcp.json", "pkg/.junie/mcp/mcp.json"),
        (".Junie/mcp/mcp.json", ".junie/mcp/mcp.json"),
    ],
)
def test_nested_case_variant_is_a_failure_not_a_server(
    tmp_path: Path, variant: str, exact: str
) -> None:
    name = exact.removeprefix("pkg/")
    _write(tmp_path / variant, FILES[name])
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert any(f.startswith(f"{variant}: case variant of {exact}") for f in result.scan_failures), (
        result.scan_failures
    )
    assert not result.components and not result.surfaces_excluded


def test_linked_zed_continue_and_junie_directories_are_read(tmp_path: Path) -> None:
    _write(tmp_path / "shared" / "zed" / "settings.json", FILES[".zed/settings.json"])
    _write(tmp_path / "shared" / "cont" / "config.yaml", BLOCK)
    _write(
        tmp_path / "shared" / "cont" / "mcpServers" / "x.yaml", BLOCK.replace("name: s", "name: t")
    )
    _write(tmp_path / "shared" / "cont" / "mcpServers" / "y.json", "{}")
    _write(tmp_path / "shared" / "junie" / "mcp" / "mcp.json", FILES[".junie/mcp/mcp.json"])
    (tmp_path / "pkg").mkdir()
    os.symlink("../shared/zed", tmp_path / "pkg" / ".zed")
    os.symlink("../shared/cont", tmp_path / "pkg" / ".continue")
    os.symlink("../shared/junie", tmp_path / "pkg" / ".junie")
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert not result.scan_failures
    # The target of the Junie link is a configuration name at any depth, so it is also
    # read under its own name, as a nested ``mcp.json`` is; that copy names no client.
    assert set(_servers(result)) == {
        "pkg/.zed/settings.json",
        "pkg/.continue/config.yaml",
        "pkg/.continue/mcpServers/x.yaml",
        "pkg/.junie/mcp/mcp.json",
        "shared/junie/mcp/mcp.json",
    }
    assert result.surfaces_excluded == [f"pkg/.continue/mcpServers/y.json: {DIRECTORY_GAP}"]
    assert {host: c.properties["config_paths"] for host, c in _clients(result).items()} == {
        "zed": ["pkg/.zed/settings.json"],
        "continue": ["pkg/.continue/config.yaml", "pkg/.continue/mcpServers/x.yaml"],
        "junie": ["pkg/.junie/mcp/mcp.json"],
    }


@pytest.mark.parametrize("spelling", ["MCPServers", "mcpservers"])
def test_case_variant_below_linked_continue_directory_is_a_failure(
    tmp_path: Path, spelling: str
) -> None:
    _write(tmp_path / "shared" / "c" / spelling / "x.yaml", BLOCK)
    (tmp_path / "pkg").mkdir()
    os.symlink("../shared/c", tmp_path / "pkg" / ".continue")
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert not result.components and not result.surfaces_excluded
    assert [f for f in result.scan_failures if "case variant" in f] == [
        f"pkg/.continue/{spelling}: case variant of pkg/.continue/mcpServers is the active "
        "file on case-insensitive file systems and is not inventoried"
    ], result.scan_failures


def test_linked_continue_directory_without_servers_is_silent(tmp_path: Path) -> None:
    _write(tmp_path / "shared" / "c" / "rules" / "style.md", "Prefer pnpm.\n")
    (tmp_path / "pkg").mkdir()
    os.symlink("../shared/c", tmp_path / "pkg" / ".continue")
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert not result.components and not result.surfaces_excluded and not result.scan_failures
