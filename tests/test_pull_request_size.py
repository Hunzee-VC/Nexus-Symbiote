"""The pull-request size cap counts product changes and ignores the test trees."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.support import load_script

checker = load_script("check_pull_request_size")


def test_tests_and_binaries_are_not_counted() -> None:
    listing = "\n".join(
        [
            "10\t2\tsrc/nexus_symbiote/cli.py",
            "1000\t0\ttests/test_cli.py",
            "3\t1\tbenchmarks/case.json",
            "-\t-\tdocs/assets/banner.jpg",
            "-\t-\ttests/fixtures/model.bin",
            "4\t0\tREADME.md",
        ]
    )
    assert checker.changed_lines(listing) == 16


def test_the_command_fails_above_the_limit(tmp_path: Path, capsys) -> None:
    listing = tmp_path / "numstat.txt"
    listing.write_text("1600\t0\tsrc/nexus_symbiote/cli.py\n")
    assert checker.main(["--numstat-file", str(listing), "--limit", "1500"]) == 1
    assert "1600" in capsys.readouterr().out


def test_a_binary_change_outside_the_expected_trees_cannot_be_measured(
    tmp_path: Path, capsys
) -> None:
    listing = tmp_path / "numstat.txt"
    listing.write_text("-\t-\tsrc/nexus_symbiote/cli.py\n")
    assert checker.main(["--numstat-file", str(listing)]) == 1
    assert "cannot be measured" in capsys.readouterr().out


def _git(root: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", "-C", str(root), *args],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
        env={
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "PATH": "/usr/bin:/bin",
        },
    ).stdout


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@example.invalid")
    _git(root, "config", "user.name", "t")
    (root / "src").mkdir()
    (root / "tests").mkdir()
    (root / "src" / "a.py").write_text("x = 1\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    return root


def test_a_pull_requests_own_gitattributes_cannot_hide_its_changes(
    repository: Path, monkeypatch, capsys
) -> None:
    # `src/** -diff` would report every source change as binary, and so as zero lines.
    base = _git(repository, "rev-parse", "HEAD").strip()
    (repository / ".gitattributes").write_text("src/** -diff\n")
    (repository / "src" / "a.py").write_text("".join(f"x{i} = {i}\n" for i in range(40)))
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "change")
    monkeypatch.chdir(repository)
    assert checker.main(["--base", base, "--limit", "20"]) == 1
    assert "42 lines" in capsys.readouterr().out


def test_a_move_out_of_tests_counts_at_its_destination(
    repository: Path, monkeypatch, capsys
) -> None:
    (repository / "tests" / "big.py").write_text("".join(f"y{i} = {i}\n" for i in range(40)))
    _git(repository, "add", "-A")
    _git(repository, "commit", "-q", "-m", "tests")
    base = _git(repository, "rev-parse", "HEAD").strip()
    _git(repository, "mv", "tests/big.py", "src/big.py")
    _git(repository, "commit", "-q", "-m", "move")
    monkeypatch.chdir(repository)
    assert checker.main(["--base", base, "--limit", "20"]) == 1
    assert "40 lines" in capsys.readouterr().out
