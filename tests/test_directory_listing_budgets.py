"""Directory-name checks must not do unbounded work before a bounded walk."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.policy import PolicyError, find_policy_path
from nexus_symbiote.utils.confined import ConfinedCollection


def _count_entries(monkeypatch, *, repetitions=1, fail_after=None):
    scanned: list[str] = []
    real_scandir = os.scandir

    class Counted:
        def __init__(self, path):
            self.stream = real_scandir(path)

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def __iter__(self):
            yielded = 0
            for entry in self.stream:
                for _ in range(repetitions):
                    if yielded == fail_after:
                        raise OSError(5, "directory I/O failed")
                    scanned.append(entry.name)
                    yielded += 1
                    yield entry

    monkeypatch.setattr(os, "scandir", Counted)
    return scanned


def _colliding_names(directory: Path, *, directories: bool = False) -> None:
    directory.mkdir(exist_ok=True)
    exact, variant = directory / "CLAUDE.md", directory / "claude.MD"
    if directories:
        exact.mkdir()
        if not variant.exists():
            variant.mkdir()
    else:
        exact.write_text("reviewed instructions")
        if not variant.exists():
            variant.write_text("different spelling")


@pytest.mark.parametrize("method", ["read_bytes", "hash_file", "regular_file", "path_identity"])
def test_exact_name_checks_stop_at_the_entry_budget(tmp_path, monkeypatch, method):
    _colliding_names(tmp_path)
    for index in range(256):
        (tmp_path / f"sibling{index:04d}").touch()
    scanned = _count_entries(monkeypatch)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=3) as files:
        assert getattr(files, method)("CLAUDE.md") is None
        assert getattr(files, method)("CLAUDE.md") is None
        assert files.root_entries() == []
    assert len(scanned) == 4  # One lookahead detects that the complete listing will not fit.
    assert any("entries limit of 3 exceeded" in failure for failure in failures)


def test_directory_exact_name_checks_record_budget_refusal(tmp_path, monkeypatch):
    _colliding_names(tmp_path, directories=True)
    for index in range(8):
        (tmp_path / f"sibling{index}").touch()
    scanned = _count_entries(monkeypatch)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=3) as files:
        assert files.is_directory("CLAUDE.md") is False
        assert files.is_directory("CLAUDE.md") is False
    assert len(scanned) == 4
    assert any("entries limit of 3 exceeded" in failure for failure in failures)


def test_repeated_names_in_a_changed_directory_still_spend_the_budget(tmp_path, monkeypatch):
    _colliding_names(tmp_path)
    scanned = _count_entries(monkeypatch, repetitions=256)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=3) as files:
        assert files.read_bytes("CLAUDE.md") is None
    assert len(scanned) == 4
    assert any("entries limit of 3 exceeded" in failure for failure in failures)


@pytest.mark.parametrize("operation", ["path_identity", "root_entries", "iter_files"])
def test_failed_partial_listings_still_spend_the_shared_budget(tmp_path, monkeypatch, operation):
    _colliding_names(tmp_path)
    for index in range(8):
        (tmp_path / f"sibling{index}").touch()
    scanned = _count_entries(monkeypatch, fail_after=2)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=3) as files:
        for _ in range(3):
            if operation == "path_identity":
                assert files.path_identity("CLAUDE.md") is None
            elif operation == "root_entries":
                assert files.root_entries() == []
            else:
                assert list(files.iter_files()) == []
    assert len(scanned) == 4
    assert any("entries limit of 3 exceeded" in failure for failure in failures)


def test_exact_name_indexes_share_the_walk_budget_and_reuse_complete_reads(tmp_path, monkeypatch):
    _colliding_names(tmp_path / "a")
    _colliding_names(tmp_path / "b")
    case_folds = (tmp_path / "A").exists()
    if case_folds:
        (tmp_path / "a" / "filler").touch()
        (tmp_path / "b" / "filler").touch()
    bound = 5 if case_folds else 3
    scanned = _count_entries(monkeypatch)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=bound) as files:
        assert files.read_text("a/CLAUDE.md") == "reviewed instructions"
        first_listing = len(scanned)
        assert files.read_text("a/CLAUDE.md") == "reviewed instructions"
        assert len(scanned) == first_listing
        assert files.read_text("b/CLAUDE.md") is None
        assert list(files.iter_files()) == []
    assert len(scanned) <= bound + 1
    assert any(f"entries limit of {bound} exceeded" in failure for failure in failures)


def test_an_ascii_read_uses_a_shortcut_or_a_bounded_listing(tmp_path, monkeypatch):
    (tmp_path / "CLAUDE.md").write_text("reviewed instructions")
    for index in range(8):
        (tmp_path / f"sibling{index}").touch()
    case_folds = (tmp_path / "claude.MD").exists()
    scanned = _count_entries(monkeypatch)
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=1) as files:
        result = files.read_text("CLAUDE.md")
    if case_folds:
        assert result is None
        assert len(scanned) == 2
        assert any("entries limit of 1 exceeded" in failure for failure in failures)
    else:
        assert result == "reviewed instructions"
        assert scanned == []
        assert failures == []


@pytest.mark.parametrize("policy_exists", [False, True])
def test_policy_discovery_refuses_an_incomplete_listing(tmp_path, monkeypatch, policy_exists):
    if policy_exists:
        (tmp_path / ".nexus-symbiote.yaml").write_text("version: '1.0'\n")
    for index in range(256):
        (tmp_path / f"sibling{index:04d}").touch()
    scanned = _count_entries(monkeypatch)
    with (
        limits.applied(replace(limits.DEFAULTS, entries=3)),
        pytest.raises(PolicyError, match=r"entries limit of 3 exceeded.*--limit entries=N"),
    ):
        find_policy_path(tmp_path)
    assert len(scanned) == 4


def test_policy_discovery_accepts_a_complete_listing_at_the_bound(tmp_path):
    policy = tmp_path / ".nexus-symbiote.yaml"
    policy.write_text("version: '1.0'\n")
    (tmp_path / "other").touch()
    with limits.applied(replace(limits.DEFAULTS, entries=2)):
        assert find_policy_path(tmp_path) == policy


def test_policy_discovery_budget_cannot_fall_back_to_default_policy(tmp_path):
    (tmp_path / ".nexus-symbiote.yaml").write_text("version: '1.0'\n")
    for index in range(8):
        (tmp_path / f"sibling{index}").touch()
    output = tmp_path / "inventory.json"
    result = CliRunner().invoke(
        main, ["--limit", "entries=3", "scan", str(tmp_path), "-o", str(output)]
    )
    assert result.exit_code == 1
    assert "entries limit of 3 exceeded" in result.output
    assert not output.exists()
