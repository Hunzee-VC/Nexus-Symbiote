"""A nested client directory reached through a symlink is read under the link's name
(Audit 2026-11-16, S2-01).

The walk covers a linked directory under its target's name, where ``settings.json`` and
``config.toml`` are not client names, so a host started in ``pkg/`` would start servers
that the inventory never showed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.mcp import MCPScanner

SERVER = {"command": "npx", "args": ["-y", "unpinned-mcp-server"]}
CASES = {
    ".gemini": ("settings.json", json.dumps({"mcpServers": {"s": SERVER}})),
    ".codex": (
        "config.toml",
        '[mcp_servers.s]\ncommand = "npx"\nargs = ["-y", "unpinned-mcp-server"]\n',
    ),
    ".vscode": ("mcp.json", json.dumps({"servers": {"s": SERVER}})),
    ".kiro": ("settings/mcp.json", json.dumps({"mcpServers": {"s": SERVER}})),
}


def _servers(result: ScanResult) -> list[str]:
    return sorted(
        c.source_path or "" for c in result.components if isinstance(c, MCPServerComponent)
    )


def _linked(root: Path, link: str, name: str, text: str) -> None:
    target = root / "shared" / "cfg"
    (target / name).parent.mkdir(parents=True, exist_ok=True)
    (target / name).write_text(text, encoding="utf-8")
    (root / link).parent.mkdir(parents=True, exist_ok=True)
    os.symlink(os.path.relpath(target, (root / link).parent), root / link)


@pytest.mark.parametrize("directory", sorted(CASES))
def test_linked_nested_dialect_directory_is_collected(tmp_path: Path, directory: str) -> None:
    name, text = CASES[directory]
    _linked(tmp_path, f"pkg/{directory}", name, text)
    result = MCPScanner().scan(tmp_path, config_only=True)
    # The walk reads the target under its own name too, as a host started there would.
    assert f"pkg/{directory}/{name}" in _servers(result), result.scan_failures
    assert not result.scan_failures


def test_linked_vscode_directory_keeps_its_dialect_and_client(tmp_path: Path) -> None:
    jsonc = '{"servers": {"s": {"command": "npx", "args": ["-y", "x"]}}} // JSONC comment\n'
    _linked(tmp_path, "pkg/.vscode", "mcp.json", jsonc)
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert "pkg/.vscode/mcp.json" in _servers(result)
    assert not any(f.startswith("pkg/.vscode/") for f in result.scan_failures)
    assert any(c.bom_ref == "mcp-client:vscode" for c in result.components)


def test_linked_kiro_settings_directory_is_collected(tmp_path: Path) -> None:
    _linked(tmp_path, "pkg/.kiro/settings", "mcp.json", json.dumps({"mcpServers": {"s": SERVER}}))
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert "pkg/.kiro/settings/mcp.json" in _servers(result), result.scan_failures


def test_linked_case_variant_dialect_directory_is_a_failure(tmp_path: Path) -> None:
    _linked(tmp_path, "pkg/.Gemini", "settings.json", CASES[".gemini"][1])
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert _servers(result) == []
    assert any(
        f.startswith("pkg/.Gemini/settings.json: case variant") for f in result.scan_failures
    ), result.scan_failures


def test_case_variant_below_a_linked_dialect_directory_is_a_failure(tmp_path: Path) -> None:
    _linked(tmp_path, "pkg/.gemini", "Settings.json", CASES[".gemini"][1])
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert _servers(result) == []
    assert any("Settings.json" in f and "case variant" in f for f in result.scan_failures), (
        result.scan_failures
    )


def test_linked_root_dialect_directory_is_read_once(tmp_path: Path) -> None:
    _linked(tmp_path, ".gemini", "settings.json", CASES[".gemini"][1])
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert _servers(result) == [".gemini/settings.json"]
    assert result.surfaces_scanned.count(".gemini/settings.json") == 1
    assert not result.scan_failures


def test_unrelated_directory_link_adds_nothing(tmp_path: Path) -> None:
    _linked(tmp_path, "pkg/lib", "settings.json", CASES[".gemini"][1])
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert _servers(result) == []
    assert not result.scan_failures
