"""The confined reader follows one in-root symlink lexically and reports case variants."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from nexus_symbiote.scanners.base import parse_python
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.utils.confined import ConfinedCollection, fold_name


def _collect(root: Path) -> tuple[list[Path], list[str]]:
    failures: list[str] = []
    with ConfinedCollection(root, failures) as files:
        walked = list(files.iter_files())
    return walked, failures


def test_walk_yields_file_links_and_skips_directory_links_inside_the_root(tmp_path):
    (tmp_path / "docs" / "v2").mkdir(parents=True)
    (tmp_path / "docs" / "v2" / "guide.md").write_text("guide")
    (tmp_path / "AGENTS.md").write_text("agents")
    (tmp_path / "CLAUDE.md").symlink_to("AGENTS.md")
    (tmp_path / "docs" / "latest").symlink_to("v2", target_is_directory=True)
    (tmp_path / "docs" / "v2" / "home").symlink_to("../../AGENTS.md")
    (tmp_path / "self").symlink_to(".", target_is_directory=True)
    walked, failures = _collect(tmp_path)
    assert failures == []
    assert [path.as_posix() for path in walked] == [
        "AGENTS.md",
        "CLAUDE.md",
        "docs/v2/guide.md",
        "docs/v2/home",
    ]


@pytest.mark.parametrize(
    ("make", "reason"),
    [
        (lambda root, out: (root / "x").symlink_to(out), "symlink target is absolute"),
        (lambda root, out: (root / "x").symlink_to("../outside"), "symlink target is outside"),
        (lambda root, out: (root / "x").symlink_to("missing"), "symlink target is unavailable"),
        (lambda root, out: (root / "x").symlink_to("chain"), "symlink target is another symlink"),
        (
            lambda root, out: (root / "x").symlink_to("node_modules/pkg.json"),
            "symlink target is excluded from collection",
        ),
        (lambda root, out: (root / "x").symlink_to("fifo"), "not a regular file or directory"),
        (lambda root, out: (root / "x").symlink_to("d/../a"), "not a plain relative path"),
    ],
)
def test_other_symlinks_in_a_walk_are_failures(tmp_path, make, reason):
    root = tmp_path / "root"
    (root / "node_modules").mkdir(parents=True)
    (root / "node_modules" / "pkg.json").write_text("{}")
    (root / "d").mkdir()
    (root / "a").write_text("a")
    (root / "chain").symlink_to("a")
    os.mkfifo(root / "fifo")
    (tmp_path / "outside").write_text("CANARY")
    make(root, tmp_path / "outside")
    _, failures = _collect(root)
    assert any(failure.startswith("x: ") and reason in failure for failure in failures)


def test_fixed_read_follows_one_in_root_link_and_names_its_target(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "mcp.json").write_text('{"mcpServers": {}}')
    (tmp_path / ".mcp.json").symlink_to("config/mcp.json")
    (tmp_path / ".claude").symlink_to("config", target_is_directory=True)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_json(".mcp.json") == {"mcpServers": {}}
        assert files.link_target(".mcp.json") == "config/mcp.json"
        assert files.read_json(".claude/mcp.json") == {"mcpServers": {}}
        assert files.link_target(".claude/mcp.json") == "config/mcp.json"
        assert files.in_root_target(".mcp.json") == Path("config/mcp.json")
        assert files.is_directory(".claude")
        assert [path.as_posix() for path in files.iter_files(".claude")] == ["config/mcp.json"]
    assert failures == []


def test_read_through_a_link_into_a_further_link_is_refused(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "f.json").write_text("{}")
    (tmp_path / "hop").symlink_to("real", target_is_directory=True)
    (tmp_path / "entry.json").symlink_to("hop/f.json")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_json("entry.json") is None
        assert files.in_root_target("entry.json") is None
    assert failures == ["entry.json: symlink target is or passes through another symlink"]


def test_missing_fixed_path_reports_its_case_variants(tmp_path):
    (tmp_path / ".Claude").mkdir()
    (tmp_path / ".Claude" / "Settings.json").write_text("{}")
    (tmp_path / "Agents.md").write_text("x")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_json(".claude/settings.json", missing_ok=True) is None
        assert files.read_text("AGENTS.md", missing_ok=True, variants_read={"Agents.md"}) is None
        assert files.read_text("README.md", missing_ok=True) is None
        assert files.case_variants("agents.md") == [Path("Agents.md")]
    assert failures == [
        ".Claude/Settings.json: case variant of .claude/settings.json is the active file on "
        "case-insensitive file systems and is not inventoried"
    ]


def test_missing_directory_reports_its_case_variants(tmp_path):
    (tmp_path / ".cursor" / "Rules").mkdir(parents=True)
    (tmp_path / ".cursor" / "Rules" / "a.mdc").write_text("x")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert list(files.iter_files(".cursor/rules")) == []
    assert [failure.split(":")[0] for failure in failures] == [".cursor/Rules"]


def test_exact_name_is_read_without_a_variant_report(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("upper")
    (tmp_path / "claude.md").write_text("lower")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_text("CLAUDE.md", missing_ok=True) == "upper"
    assert failures == []


def test_names_fold_as_case_insensitive_file_systems_compare_them():
    assert fold_name("CLAUDE.md") == fold_name("claude.md")
    assert fold_name("caf\u00e9.md") == fold_name("cafe\u0301.md")
    assert fold_name("agent.json.") == fold_name("agent.json")
    assert fold_name("a\u200db") == fold_name("ab")
    assert fold_name("agent.json") != fold_name("agent-card.json")


@pytest.mark.parametrize(
    "source", ["x = " + "-" * 100_000 + "1\n", "if a:\n    pass\n" + "elif a:\n    pass\n" * 20_000]
)
def test_parser_resource_failures_become_value_errors(source):
    with pytest.raises((ValueError, SyntaxError)):
        parse_python(source)


def test_byte_order_mark_is_accepted_like_cpython():
    assert parse_python("\ufeffimport chromadb\n").body


def test_deeply_nested_source_does_not_discard_other_collector_results(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"notes": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}})
    )
    (tmp_path / "x.py").write_text("# mcp\nx = " + "-" * 100_000 + "1\n")
    mcp = MCPScanner().scan(tmp_path)
    assert any(component.name == "notes" for component in mcp.components)
    assert any("x.py" in failure for failure in mcp.scan_failures)


def test_missing_file_below_a_linked_directory_is_absent_not_a_failure(tmp_path):
    (tmp_path / "shared").mkdir()
    (tmp_path / ".claude").symlink_to("shared", target_is_directory=True)
    (tmp_path / ".cursor").symlink_to("gone", target_is_directory=True)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_json(".claude/settings.local.json", missing_ok=True) is None
        assert list(files.iter_files(".claude/commands")) == []
        assert files.read_json(".cursor/mcp.json", missing_ok=True) is None
    assert failures == [".cursor/mcp.json: symlink target is unavailable"]
