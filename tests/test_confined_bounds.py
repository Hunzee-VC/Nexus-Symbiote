"""The confined reader's bounds: named failures, shared budgets, odd names and operator paths."""

from __future__ import annotations

import errno
import os
import time
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import open_regular_file, pathname_identity
from nexus_symbiote.limits import Bound
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.scanners.prompt import PromptScanner
from nexus_symbiote.scanners.rag import RAGScanner
from nexus_symbiote.utils.confined import ConfinedCollection


def _undecodable(directory: Path, raw: bytes, content: bytes = b"x = 1\n") -> Path:
    path = directory / os.fsdecode(raw)
    try:
        path.write_bytes(content)
    except (OSError, UnicodeEncodeError):
        pytest.skip("file system rejects names that are not UTF-8")
    return path


def test_depth_limit_is_a_named_failure(tmp_path):
    deep = tmp_path.joinpath(*(f"d{level}" for level in range(5)))
    deep.mkdir(parents=True)
    (deep / "hidden.txt").write_text("deep")
    (tmp_path / "top.txt").write_text("top")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_depth=3) as files:
        assert list(files.iter_files()) == [Path("top.txt")]
    assert failures == [
        "d0/d1/d2/d3: depth limit of 3 exceeded; this limit is fixed for this input"
    ]
    failures = []
    with (
        limits.applied(replace(limits.DEFAULTS, depth=3)),
        ConfinedCollection(tmp_path, failures) as files,
    ):
        list(files.iter_files())
    assert failures == ["d0/d1/d2/d3: depth limit of 3 exceeded; raise it with --limit depth=N"]


def test_entry_budget_is_shared_by_every_listing_of_one_collection(tmp_path):
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        for index in range(3):
            (tmp_path / name / f"{index}.txt").write_text("")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=5) as files:
        assert len(list(files.iter_files("a"))) == 3
        assert list(files.iter_files("b")) == []
    assert failures == ["b: entries limit of 5 exceeded; this limit is fixed for this input"]


def test_an_exhausted_entry_budget_is_reported_once(tmp_path):
    for name in ("a", "b", "c", "d"):
        (tmp_path / name).mkdir()
        for index in range(3):
            (tmp_path / name / f"{index}.txt").write_text("")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=8) as files:
        found = list(files.iter_files())
        assert files.root_entries() == []
    assert found == [Path("a/0.txt"), Path("a/1.txt"), Path("a/2.txt")]
    assert failures == ["b: entries limit of 8 exceeded; this limit is fixed for this input"]


def test_root_listing_is_charged_to_the_entry_budget(tmp_path):
    for index in range(5):
        (tmp_path / f"{index}.txt").write_text("")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=4) as files:
        assert files.root_entries() == []
    assert failures == [".: entries limit of 4 exceeded; this limit is fixed for this input"]
    with ConfinedCollection(tmp_path, [], max_entries=5) as files:
        assert files.root_entries() == [f"{index}.txt" for index in range(5)]
        assert list(files.iter_files()) == []


def test_size_failures_name_the_limit_and_never_quote_content(tmp_path):
    (tmp_path / "big.json").write_text('{"token": "CANARY-SECRET-0123456789"}')
    (tmp_path / "small.txt").write_text("1234")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_file_bytes=16, max_total_bytes=6) as files:
        assert files.read_json("big.json") is None
        assert files.read_text("small.txt") == "1234"
        assert files.hash_file("small.txt") is None
    assert failures == [
        "big.json: file-bytes limit of 16 bytes exceeded; this limit is fixed for this input",
        "small.txt: total-bytes limit of 6 bytes exceeded; this limit is fixed for this input",
    ]
    failures = []
    configured = replace(limits.DEFAULTS, file_bytes=16)
    with limits.applied(configured), ConfinedCollection(tmp_path, failures) as files:
        assert files.read_bytes("big.json") is None
        with pytest.raises(OSError), files.open_regular("big.json"):
            pass
    assert failures == [
        "big.json: file-bytes limit of 16 bytes exceeded; raise it with --limit file-bytes=N"
    ]
    assert "CANARY" not in repr(failures)


def test_stream_budget_names_the_bound_that_stopped_it(tmp_path):
    (tmp_path / "a.bin").write_bytes(b"x" * 64)
    failures: list[str] = []
    budget = Bound(32, "model-total-bytes")
    with (
        ConfinedCollection(tmp_path, failures, max_total_bytes=budget) as files,
        pytest.raises(ValueError),
        files.open_regular("a.bin", max_bytes=128) as stream,
    ):
        while stream.read(16):
            pass
    assert failures == [
        "a.bin: model-total-bytes limit of 32 bytes exceeded; "
        "raise it with --limit model-total-bytes=N"
    ]


def test_a_separate_budget_leaves_the_collection_budget_untouched(tmp_path):
    (tmp_path / "a").write_bytes(b"1234")
    (tmp_path / "b").write_bytes(b"5678")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_total_bytes=4) as files:
        with files.separate_budget(Bound(4, "source-scan-bytes")) as budget:
            assert files.read_bytes("a") == b"1234"
            assert files.read_bytes("b") is None
            assert budget.exhausted
        assert files.read_bytes("b") == b"5678"
    assert failures == [
        "b: source-scan-bytes limit of 4 bytes exceeded; raise it with --limit source-scan-bytes=N"
    ]


def test_overflowing_json_numbers_are_invalid_json(tmp_path):
    (tmp_path / "x.json").write_text('{"maximum": 1e400}')
    (tmp_path / "y.json").write_text('{"minimum": -1E999, "ok": 1e-400}')
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        assert files.read_json("x.json") is None
        assert files.read_json("y.json") is None
    assert failures == [
        "x.json: invalid JSON or duplicate keys",
        "y.json: invalid JSON or duplicate keys",
    ]
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"s": {"tools": [{"name": "t", "inputSchema": {"maximum": 1e400}}]}}}'
    )
    assert MCPScanner().scan(tmp_path).scan_failures == [
        ".mcp.json: invalid JSON or duplicate keys"
    ]


def test_policy_exclusion_checks_do_not_grow_with_the_number_of_entries(tmp_path):
    for index in range(300):
        (tmp_path / f"f{index}.py").write_text("")
    (tmp_path / "x000123").mkdir()
    (tmp_path / "x000123" / "hidden.py").write_text("")
    exclusions = [f"x{index:06d}" for index in range(20_000)]
    started = time.monotonic()
    surfaces: list[str] = []
    with ConfinedCollection(tmp_path, [], surfaces, exclude_paths=exclusions) as files:
        found = list(files.iter_files())
    assert time.monotonic() - started < 5
    assert len(found) == 300
    assert surfaces == ["x000123: excluded by collection policy"]


def test_a_walk_records_tens_of_thousands_of_messages_in_linear_time(tmp_path):
    # Checking each new message against the list made 95,000 symlinks a 70 s walk.
    count = 50_000
    (tmp_path / "target").write_text("x")
    names = [f"l{index:05d}" for index in range(count)]
    for name in names:
        os.symlink("target", tmp_path / name)
    failures: list[str] = []
    started = time.monotonic()
    with ConfinedCollection(tmp_path, failures) as files:
        assert list(files.iter_files()) == [Path("target")]
    assert time.monotonic() - started < 8
    assert len(failures) == count
    exclusions: list[str] = []
    started = time.monotonic()
    with ConfinedCollection(tmp_path, [], exclusions, exclude_paths=names) as files:
        assert list(files.iter_files()) == [Path("target")]
    assert time.monotonic() - started < 8
    assert len(exclusions) == count


def test_messages_are_recorded_once_even_when_the_caller_appends_too(tmp_path):
    failures = ["missing: file unavailable during collection"]
    with ConfinedCollection(tmp_path, failures) as files:
        failures.append("later: file unavailable during collection")
        assert files.read_bytes("missing") is None
        assert files.read_bytes("later") is None
        assert files.read_bytes("other") is None
        assert files.read_bytes("other") is None
    assert failures == [
        "missing: file unavailable during collection",
        "later: file unavailable during collection",
        "other: file unavailable during collection",
    ]


def test_a_failed_stream_read_is_recorded(tmp_path, monkeypatch):
    (tmp_path / "a.bin").write_bytes(b"x" * 10)
    failures: list[str] = []
    read = os.read
    with ConfinedCollection(tmp_path, failures) as files, files.open_regular("a.bin") as stream:
        broken = stream.fileno()

        def failing(fd: int, size: int) -> bytes:
            if fd == broken:
                raise OSError(errno.EIO, "I/O error")
            return read(fd, size)

        monkeypatch.setattr(os, "read", failing)
        with pytest.raises(OSError):
            stream.read(4)
    assert failures == ["a.bin: stream read failed (I/O error)"]


def test_an_undecodable_name_is_a_failure_and_the_inventory_still_loads(tmp_path):
    project = tmp_path / "project"
    (project / "models").mkdir(parents=True)
    (project / ".claude" / "skills").mkdir(parents=True)
    (project / "AGENTS.md").write_text("Keep receipts.")
    _undecodable(project, b"tool\xff.py", b"import chromadb\n")
    _undecodable(project / "models", b"m\xff.pkl")
    _undecodable(project / ".claude" / "skills", b"s\xfe.md", b"skill")
    expected = {
        "tool\\xff.py: name is not valid UTF-8; not collected",
        "models/m\\xff.pkl: name is not valid UTF-8; not collected",
        ".claude/skills/s\\xfe.md: name is not valid UTF-8; not collected",
    }
    for scanner in (RAGScanner, ModelScanner, MCPScanner):
        result = scanner().scan(project)
        assert set(result.scan_failures) == expected
        assert not any("\\udc" in repr(component) for component in result.components)
    assert PromptScanner().scan(project).scan_failures == [
        ".claude/skills/s\\xfe.md: name is not valid UTF-8; not collected"
    ]
    output = tmp_path / "out.json"
    runner = CliRunner()
    scan = ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    assert runner.invoke(main, scan).exit_code == 0
    bom = AIBOM.load(output)
    assert "tool\\xff.py: name is not valid UTF-8; not collected" in (
        bom.metadata.completeness.scan_failures if bom.metadata.completeness else []
    )
    result = runner.invoke(main, ["validate", str(output)])
    assert "not a valid native AIBOM file" not in result.output


def test_operator_roots_walk_dot_dot_through_the_real_parent(tmp_path):
    real = tmp_path / "real"
    (real / "project").mkdir(parents=True)
    (real / "project" / "file.txt").write_text("inside")
    (tmp_path / "other").mkdir()
    (tmp_path / "project").mkdir()
    (tmp_path / "project" / "file.txt").write_text("lexical twin")
    (tmp_path / "link").symlink_to(tmp_path / "other", target_is_directory=True)
    failures: list[str] = []
    with ConfinedCollection(tmp_path / "link" / ".." / "project", failures) as files:
        assert files.read_text("file.txt") is None
    assert ".: root unavailable or contains a symlink" in failures
    with ConfinedCollection(real / "project" / ".." / "project", []) as files:
        assert files.read_text("file.txt") == "inside"
    assert pathname_identity(tmp_path / "link" / ".." / "project" / "file.txt") is None
    with pytest.raises(OSError):
        open_regular_file(tmp_path / "link" / ".." / "project" / "file.txt")
    with open_regular_file(real / "project" / ".." / "project" / "file.txt") as stream:
        assert stream.read() == b"inside"


def test_project_paths_with_a_symlinked_component_are_resolved_like_scan(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "model.bin").write_bytes(b"data")
    (tmp_path / "alias").symlink_to(project, target_is_directory=True)
    import hashlib

    digest = "sha256:" + hashlib.sha256(b"data").hexdigest()
    result = CliRunner().invoke(
        main,
        ["verify-artifact", "model.bin", "--project", str(tmp_path / "alias"), "--sha256", digest],
    )
    assert result.exit_code == 0, result.output
