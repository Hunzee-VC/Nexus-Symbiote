"""Exact-spelling fallback listings share the collection's entry budget."""

import os
from pathlib import Path

import pytest

from nexus_symbiote.utils.confined import ConfinedCollection


def _tree(root, count=20):
    (root / "CLAUDE.md").write_text("instructions")
    (root / "claude.MD").write_text("variant")
    for index in range(count):
        (root / f"filler-{index}").touch()


@pytest.mark.parametrize("operation", ["read", "metadata", "directory"])
def test_exact_spelling_fails_closed_before_caching_an_oversized_directory(tmp_path, operation):
    _tree(tmp_path)
    (tmp_path / "123").mkdir()
    failures = []
    with ConfinedCollection(tmp_path, failures, max_entries=10) as files:
        if operation == "read":
            assert files.read_text("CLAUDE.md") is None
        elif operation == "metadata":
            assert files.regular_file("CLAUDE.md") is None
        else:
            assert not files.is_directory("123")
        assert not files._exact_names
        assert files.root_entries() == []
        assert list(files.iter_files()) == []
    assert any("entries limit of 10 exceeded" in failure for failure in failures)


def test_cached_exact_names_are_not_charged_again(tmp_path):
    _tree(tmp_path, count=1)
    failures = []
    with ConfinedCollection(tmp_path, failures, max_entries=3) as files:
        assert files.read_text("CLAUDE.md") == "instructions"
        assert files.read_text("CLAUDE.md") == "instructions"
        assert files._entry_budget == [0]
        assert len(next(iter(files._exact_names.values()))[1]) == 3
    assert not failures


def test_exact_name_listing_and_walk_spend_the_same_budget(tmp_path):
    _tree(tmp_path, count=1)
    failures = []
    with ConfinedCollection(tmp_path, failures, max_entries=5) as files:
        assert files.read_text("CLAUDE.md") == "instructions"
        assert list(files.iter_files()) == []
    assert any("entries limit of 5 exceeded" in failure for failure in failures)


def test_changed_directory_cannot_reuse_or_replace_its_bounded_cache(tmp_path):
    _tree(tmp_path, count=1)
    failures = []
    with ConfinedCollection(tmp_path, failures, max_entries=5) as files:
        assert files.read_text("CLAUDE.md") == "instructions"
        (tmp_path / "new-a").mkdir()
        for name in ("new-b", "new-c"):
            (tmp_path / name).touch()
        assert files.read_text("CLAUDE.md") is None
        assert all(len(names) <= 3 for _, names in files._exact_names.values())
    assert any("entries limit of 5 exceeded" in failure for failure in failures)


@pytest.mark.parametrize("changed_field", ["st_size", "st_nlink"])
def test_same_tick_size_or_nlink_change_invalidates_exact_name_cache(
    tmp_path, monkeypatch, changed_field
):
    _tree(tmp_path, count=1)
    failures = []
    real_fstat = os.fstat
    root_identity = (tmp_path.stat().st_dev, tmp_path.stat().st_ino)
    frozen_root_stat = None
    mutate_field = False

    def fake_fstat(fd: int) -> os.stat_result:
        nonlocal frozen_root_stat
        info = real_fstat(fd)
        if (info.st_dev, info.st_ino) != root_identity:
            return info
        if frozen_root_stat is None:
            frozen_root_stat = info
            return info
        if not mutate_field:
            return frozen_root_stat
        values = list(frozen_root_stat)
        if changed_field == "st_size":
            values[6] = frozen_root_stat.st_size + 39
        else:
            values[3] = frozen_root_stat.st_nlink + 1
        return os.stat_result(
            values,
            {
                "st_atime_ns": frozen_root_stat.st_atime_ns,
                "st_mtime_ns": frozen_root_stat.st_mtime_ns,
                "st_ctime_ns": frozen_root_stat.st_ctime_ns,
            },
        )

    monkeypatch.setattr(os, "fstat", fake_fstat)
    with ConfinedCollection(tmp_path, failures, max_entries=5) as files:
        assert files.read_text("CLAUDE.md") == "instructions"
        for name in ("new-a", "new-b", "new-c"):
            (tmp_path / name).touch()
        mutate_field = True
        assert files.read_text("CLAUDE.md") is None
        assert all(len(names) <= 3 for _, names in files._exact_names.values())
    assert any("entries limit of 5 exceeded" in failure for failure in failures)


def test_non_ascii_exact_name_is_also_bounded(tmp_path):
    _tree(tmp_path)
    (tmp_path / "café").write_text("instructions")
    failures = []
    with ConfinedCollection(tmp_path, failures, max_entries=10) as files:
        assert files.read_text(Path("café")) is None
        assert not files._exact_names
    assert any("entries limit of 10 exceeded" in failure for failure in failures)
