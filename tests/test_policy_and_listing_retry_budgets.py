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


def _count_entries(monkeypatch, *, fail_after=None):
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
            for yielded, entry in enumerate(self.stream):
                if yielded == fail_after:
                    raise OSError(5, "directory I/O failed")
                scanned.append(entry.name)
                yield entry

    monkeypatch.setattr(os, "scandir", Counted)
    return scanned


def _colliding_names(directory: Path) -> None:
    directory.mkdir(exist_ok=True)
    exact, variant = directory / "CLAUDE.md", directory / "claude.MD"
    exact.write_text("reviewed instructions")
    if not variant.exists():
        variant.write_text("different spelling")


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
