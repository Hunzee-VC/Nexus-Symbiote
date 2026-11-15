"""Another spelling of an MCP client file the walk reads below the root, such as
pkg/.MCP.json for pkg/.mcp.json or pkg/.VSCode/mcp.json for pkg/.vscode/mcp.json, is a
collection failure: a host started in that directory on a case-insensitive file system
opens it in place of the name it asks for. So is one beside the exact name, because a
case-insensitive checkout holds one file for both."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.mcp import MCP_CONFIG_NAMES, MCP_DIALECTS, MCPScanner
from nexus_symbiote.utils.confined import fold_name

RLO = "\u202e"
OK = {"mcpServers": {"ok": {"command": "node", "args": ["server.js"]}}}
EVIL = {"mcpServers": {"evil": {"command": "npx", "args": ["-y", "evil-pkg"]}}}
EVIL_VSCODE = {"servers": {"evil": {"command": "npx", "args": ["-y", "evil-pkg"]}}}
# Every dialect file the walk reads below the root by its name.
NESTED_DIALECTS = [d.path for d in MCP_DIALECTS if d.path.rsplit("/", 1)[-1] in MCP_CONFIG_NAMES]
NESTED_DIALECT_DIRECTORIES = [path for path in NESTED_DIALECTS if "/" in path]


def _variant(path: str, canonical: str) -> str:
    return (
        f"{path}: case variant of {canonical} is the active file on case-insensitive file "
        "systems and is not inventoried"
    )


def _write(root: Path, files: dict[str, object]) -> Path:
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
    return root


def _case_sensitive(directory: Path) -> bool:
    (directory / "probe").write_text("")
    sensitive = not (directory / "PROBE").exists()
    (directory / "probe").unlink()
    return sensitive


def _servers(result: ScanResult) -> list[tuple[str, str | None]]:
    return sorted(
        (c.name, c.source_path) for c in result.components if isinstance(c, MCPServerComponent)
    )


def _scan(project: Path, output: Path) -> tuple[int, dict, str]:
    result = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(output)]
    )
    return result.exit_code, json.loads(output.read_text()), result.output


@pytest.mark.parametrize(
    "path, canonical",
    [
        ("pkg/.MCP.json", "pkg/.mcp.json"),
        ("pkg/.vscode/MCP.json", "pkg/.vscode/mcp.json"),
        ("pkg2/Mcp.Json", "pkg2/mcp.json"),
    ],
)
def test_a_nested_variant_hiding_a_server_fails_the_gate(tmp_path, path, canonical):
    project = _write(tmp_path / "project", {".mcp.json": OK, path: EVIL})
    code, document, output = _scan(project, tmp_path / "out.json")
    assert code == 1
    assert "Scan gate failed" in output
    completeness = document["metadata"]["completeness"]
    assert completeness["scan_failures"] == [_variant(path, canonical)]
    assert completeness["scanner_status"]["mcp"] == "failed"
    assert "evil" not in {c["name"] for c in document["components"]}
    check = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "--check"])
    assert check.exit_code == 1


@pytest.mark.parametrize(
    "path, canonical",
    [
        ("pkg/.MCP.json", "pkg/.mcp.json"),
        ("pkg/MCP.JSON", "pkg/mcp.json"),
        ("a/b/c/d/e/.Mcp.json", "a/b/c/d/e/.mcp.json"),
        ("pkg/Mcp-Config.json", "pkg/mcp-config.json"),
        ("pkg/MCP_CONFIG.JSON", "pkg/mcp_config.json"),
        ("pkg/Mcp-Servers.json", "pkg/mcp-servers.json"),
        ("pkg/Claude_Desktop_Config.json", "pkg/claude_desktop_config.json"),
        ("tools/Cline_MCP_Settings.json", "tools/cline_mcp_settings.json"),
        ("Mcp-Config.json", "mcp-config.json"),
        ("pkg/.mcp.json.", "pkg/.mcp.json"),
        ("pkg/mcp.json ", "pkg/mcp.json"),
        ("pkg/.mcp.json. .", "pkg/.mcp.json"),
        ("pkg/.mcp\u200c.json", "pkg/.mcp.json"),
        (f"pkg/mcp{RLO}.json", "pkg/mcp.json"),
        ("pkg/\ufeffmcp.json", "pkg/mcp.json"),
        ("pkg/mcp-\u017fervers.json", "pkg/mcp-servers.json"),
        ("pkg/.vscode/MCP.json", "pkg/.vscode/mcp.json"),
        ("pkg/.VSCode/mcp.json", "pkg/.vscode/mcp.json"),
        ("pkg/.Cursor/mcp.json", "pkg/.cursor/mcp.json"),
        ("pkg/.CLAUDE/mcp.json", "pkg/.claude/mcp.json"),
        ("pkg/.vscode./mcp.json", "pkg/.vscode/mcp.json"),
        ("pkg/.kiro/Settings/mcp.json", "pkg/.kiro/settings/mcp.json"),
        ("pkg/.\u212airo/settings/mcp.json", "pkg/.kiro/settings/mcp.json"),
        ("pkg/.Kiro/SETTINGS/MCP.JSON", "pkg/.kiro/settings/mcp.json"),
        ("pkg/.Windsurf/mcp_config.json", "pkg/.windsurf/mcp_config.json"),
        ("pkg/.windsurf/MCP_Config.json", "pkg/.windsurf/mcp_config.json"),
        ("pkg/.Claude/.VSCode/mcp-servers.json", "pkg/.claude/.vscode/mcp-servers.json"),
        ("pkg/.windsurf/.MCP.json", "pkg/.windsurf/.mcp.json"),
    ],
)
def test_every_spelling_of_every_nested_client_file_is_a_failure(tmp_path, path, canonical):
    data = EVIL_VSCODE if ".vscode/" in canonical else EVIL
    root = _write(tmp_path, {path: data})
    result = MCPScanner().scan(root, config_only=True)
    assert result.scan_failures == [_variant(path, canonical)]
    assert _servers(result) == []


@pytest.mark.parametrize("name", sorted(MCP_CONFIG_NAMES))
def test_each_nested_name_in_another_case_is_a_failure(tmp_path, name):
    root = _write(tmp_path, {f"pkg/{name.upper()}": EVIL})
    result = MCPScanner().scan(root, config_only=True)
    assert result.scan_failures == [_variant(f"pkg/{name.upper()}", f"pkg/{name}")]


@pytest.mark.parametrize("dialect", NESTED_DIALECT_DIRECTORIES)
def test_each_nested_dialect_directory_in_another_case_is_a_failure(tmp_path, dialect):
    *directories, name = dialect.split("/")
    spelled = "/".join([*(d.upper() for d in directories), name])
    data = EVIL_VSCODE if dialect.startswith(".vscode") else EVIL
    root = _write(tmp_path, {f"pkg/{spelled}": data})
    result = MCPScanner().scan(root, config_only=True)
    assert result.scan_failures == [_variant(f"pkg/{spelled}", f"pkg/{dialect}")]


def test_each_client_name_is_its_own_folded_spelling():
    assert len({fold_name(name) for name in MCP_CONFIG_NAMES}) == len(MCP_CONFIG_NAMES)
    assert all(fold_name(name) == name for name in MCP_CONFIG_NAMES)


@pytest.mark.parametrize(
    "path",
    [
        "PKG/.mcp.json",
        "Packages/API/mcp-config.json",
        "pkg/.Windsurf/.mcp.json",
        "pkg/.VSCode/.mcp.json",
        "docs/Settings/mcp.json",
        "pkg/.kiro/mcp.json",
        "tools/cline_mcp_settings.json",
        *(f"pkg/{dialect}" for dialect in NESTED_DIALECTS),
        "pkg/.windsurf/mcp_config.json",
        "pkg/.claude/.vscode/mcp-servers.json",
    ],
)
def test_exact_spellings_are_read_and_not_variants(tmp_path, path):
    data = EVIL_VSCODE if path.endswith(".vscode/mcp.json") else EVIL
    root = _write(tmp_path, {path: data})
    result = MCPScanner().scan(root, config_only=True)
    assert result.scan_failures == []
    assert _servers(result) == [("evil", path)]


@pytest.mark.parametrize(
    "path",
    [
        "pkg/mcp.json5",
        "pkg/mcp.jsonc",
        "pkg/my-mcp.json",
        "pkg/MCP.md",
        "pkg/MCP.json.bak",
        "pkg/.MCP.json.orig",
        "pkg/mcpconfig.json",
        "pkg/Mcp-Config.yaml",
        "pkg/mcp.jso\u0301n",
        "pkg/\uff4dcp.json",
        "pkg/.VSCode/settings.json",
        "pkg/.Kiro/settings.json",
        "node_modules/x/.MCP.json",
        "pkg/Node_Modules/x/MCP.json",
        "pkg/.git/MCP.json",
    ],
)
def test_other_names_and_skipped_directories_are_not_variants(tmp_path, path):
    root = _write(tmp_path, {path: EVIL})
    result = MCPScanner().scan(root, config_only=True)
    assert result.scan_failures == []
    assert _servers(result) == []


@pytest.mark.parametrize(
    "exact, variant",
    [
        ("pkg/.mcp.json", "pkg/.MCP.json"),
        ("pkg/mcp.json", "pkg/Mcp.Json"),
        ("pkg/.vscode/mcp.json", "pkg/.VSCode/mcp.json"),
        ("pkg/.vscode/mcp.json", "pkg/.vscode/MCP.json"),
        (".mcp.json", ".MCP.json"),
        (".cursor/mcp.json", ".Cursor/mcp.json"),
        ("mcp-servers.json", "MCP-Servers.json"),
    ],
)
def test_a_variant_beside_the_exact_name_is_a_failure_and_the_exact_name_read(
    tmp_path, exact, variant
):
    # A case-insensitive checkout holds one file for both names, so the exact name being
    # read says nothing about the content a host opens there.
    if not _case_sensitive(tmp_path):
        pytest.skip("needs a case-sensitive file system to hold both spellings")
    ok = {"servers": OK["mcpServers"]} if ".vscode" in exact else OK
    root = _write(tmp_path, {exact: ok, variant: EVIL_VSCODE if ".vscode" in exact else EVIL})
    result = MCPScanner().scan(root, config_only=True)
    assert result.scan_failures == [_variant(variant, exact)]
    assert _servers(result) == [("ok", exact)]


def test_a_root_variant_beside_the_exact_name_fails_the_gate(tmp_path):
    if not _case_sensitive(tmp_path):
        pytest.skip("needs a case-sensitive file system to hold both spellings")
    project = _write(tmp_path / "project", {".mcp.json": OK, ".MCP.json": EVIL})
    code, document, output = _scan(project, tmp_path / "out.json")
    assert code == 1 and "Scan gate failed" in output
    assert document["metadata"]["completeness"]["scan_failures"] == [
        _variant(".MCP.json", ".mcp.json")
    ]


@pytest.mark.parametrize(
    "path, canonical",
    [
        (".MCP.json", ".mcp.json"),
        ("MCP.json", "mcp.json"),
        (".Cursor/mcp.json", ".cursor/mcp.json"),
        (".vscode/MCP.json", ".vscode/mcp.json"),
        (".Kiro/Settings/mcp.json", ".kiro/settings/mcp.json"),
    ],
)
def test_a_root_variant_is_reported_once_and_not_read(tmp_path, path, canonical):
    root = _write(tmp_path, {path: EVIL_VSCODE if ".vscode" in canonical else EVIL})
    result = MCPScanner().scan(root, config_only=True)
    assert result.scan_failures == [_variant(path, canonical)]
    assert _servers(result) == []


def test_variants_in_many_packages_are_each_reported(tmp_path):
    files: dict[str, object] = {".mcp.json": OK}
    files.update({f"packages/p{index}/.MCP.json": EVIL for index in range(3, 0, -1)})
    files["packages/p2/.vscode/MCP.json"] = EVIL_VSCODE
    root = _write(tmp_path, files)
    result = MCPScanner().scan(root, config_only=True)
    assert sorted(result.scan_failures) == sorted(
        [
            *(_variant(f"packages/p{i}/.MCP.json", f"packages/p{i}/.mcp.json") for i in (1, 2, 3)),
            _variant("packages/p2/.vscode/MCP.json", "packages/p2/.vscode/mcp.json"),
        ]
    )
    assert _servers(result) == [("ok", ".mcp.json")]
    assert MCPScanner().scan(root, config_only=True).scan_failures == result.scan_failures


def test_a_symlinked_variant_is_a_failure(tmp_path):
    root = _write(tmp_path, {"shared/servers.json": EVIL})
    (root / "pkg").mkdir()
    os.symlink("../shared/servers.json", root / "pkg" / ".MCP.json")
    result = MCPScanner().scan(root, config_only=True)
    assert result.scan_failures == [_variant("pkg/.MCP.json", "pkg/.mcp.json")]
    assert _servers(result) == []


def test_policy_exclusion_turns_the_failure_into_an_exclusion(tmp_path):
    root = _write(tmp_path, {"pkg/.MCP.json": EVIL})
    scanner = MCPScanner()
    scanner.configure(exclude_paths=["pkg"])
    result = scanner.scan(root, config_only=True)
    assert result.scan_failures == []
    assert result.surfaces_excluded


def test_many_variants_are_listed_within_the_bound_and_counted(tmp_path):
    root = _write(tmp_path, {f"d{index:04d}/MCP.json": EVIL for index in range(1_500)})
    first = MCPScanner().scan(root, config_only=True)
    failures = list(first.scan_failures)
    assert len(failures) <= 1_001
    assert failures[0] == _variant("d0000/MCP.json", "d0000/mcp.json")
    assert failures[-1].endswith("more not listed)")
    assert _servers(first) == []
    assert failures == list(MCPScanner().scan(root, config_only=True).scan_failures)


def test_terminal_output_neutralizes_the_variant_name(tmp_path):
    project = _write(
        tmp_path / "project",
        {f"pkg/.MCP{RLO}.json": EVIL, "::error::x/MCP.json": EVIL},
    )
    code, document, output = _scan(project, tmp_path / "out.json")
    assert code == 1
    assert RLO not in output
    assert not any(line.startswith(("::", "##[")) for line in output.splitlines())
    failures = document["metadata"]["completeness"]["scan_failures"]
    assert _variant("::error::x/MCP.json", "::error::x/mcp.json") in failures
