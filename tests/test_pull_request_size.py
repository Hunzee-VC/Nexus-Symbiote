"""The cap measures an immutable PR pair, including adversarial Git path records."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from tests.support import ROOT, load_script

checker = load_script("check_pull_request_size")
workflows = load_script("check_workflows")


def git(*args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


@pytest.fixture
def history(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    git("init", "-b", "main")
    git("config", "user.name", "Size test")
    git("config", "user.email", "size@example.invalid")
    (tmp_path / "README.md").write_text("base\n")
    git("add", ".")
    git("commit", "-m", "base")
    return tmp_path, git("rev-parse", "HEAD")


def commit(path: Path, content: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    git("add", ".")
    git("commit", "-m", "fixture")
    return git("rev-parse", "HEAD")


def test_test_trees_and_reviewed_binary_assets_are_not_counted():
    listing = (
        b"10\t2\tsrc/nexus_symbiote/cli.py\0"
        b"1000\t0\ttests/test_cli.py\0"
        b"3\t1\tbenchmarks/case.json\0"
        b"-\t-\tdocs/assets/banner.jpg\0"
        b"4\t0\tREADME.md\0"
    )
    assert checker.changed_lines(listing) == 16


@pytest.mark.parametrize(
    "listing",
    [
        b"-\t-\tsrc/large.py\0",
        b"-\t-\tscripts/check.py\0",
        b"-\t-\tdocs/assets/code.py\0",
        b"1\t0\tsource.py",
        b"-\t1\tsource.py\0",
        b"-1\t0\tsource.py\0",
        b"1\t0\t\0old.py\0",
    ],
)
def test_unexpected_binary_or_malformed_records_fail_closed(listing):
    with pytest.raises(ValueError):
        checker.changed_lines(listing)


def test_nul_rename_records_classify_both_paths():
    assert checker.changed_lines(b"1\t2\t\0tests/old.py\0tests/new.py\0") == 0
    assert checker.changed_lines(b"1\t2\t\0src/old.py\0src/new.py\0") == 3


@pytest.mark.parametrize(
    "listing",
    [b"0\t0\t\0src/old.py\0tests/new.py\0", b"1\t2\t\0tests/old.py\0src/new.py\0"],
)
def test_saved_cross_boundary_renames_refuse_unavailable_whole_file_sizes(listing):
    with pytest.raises(ValueError, match="rename"):
        checker.changed_lines(listing)


@pytest.mark.parametrize(
    "old,new", [("tests/large.py", "src/large.py"), ("src/large.py", "tests/large.py")]
)
def test_a_whole_file_moved_across_an_excluded_boundary_counts_its_lines(history, old, new):
    root, _ = history
    base = commit(root / old, "value = 1\n" * 1601)
    (root / new).parent.mkdir(parents=True, exist_ok=True)
    git("mv", old, new)
    git("commit", "-m", "move a whole file")
    head = git("rev-parse", "HEAD")
    assert checker.changed_lines(checker._from_git(base, head)) == 1601
    assert checker.main(["--base", base, "--head", head]) == 1


def test_the_command_fails_above_the_limit(tmp_path, capsys):
    listing = tmp_path / "numstat.bin"
    listing.write_bytes(b"1600\t0\tsrc/nexus_symbiote/cli.py\0")
    assert checker.main(["--numstat-file", str(listing), "--limit", "1500"]) == 1
    assert "1600" in capsys.readouterr().out


def test_a_moving_base_and_merge_checkout_do_not_change_the_pr_pair(history):
    root, base = history
    git("switch", "-c", "feature")
    head = commit(root / "feature.py", "feature = 1\n")
    git("switch", "main")
    commit(root / "unrelated.py", "unrelated = 1\n" * 1601)
    git("merge", "--no-edit", "feature")
    assert checker.main(["--base", base, "--head", head]) == 0
    assert checker.changed_lines(checker._from_git(base, head)) == 1


@pytest.mark.parametrize(
    "name", ["tests/test_unicode_é.py", "tests/tab\tname.py", "tests/line\nname.py"]
)
def test_git_paths_are_not_c_quoted_before_test_tree_classification(history, name):
    root, base = history
    head = commit(root / name, "case = 1\n" * 1601)
    assert checker.main(["--base", base, "--head", head]) == 0


def test_a_binary_attribute_cannot_hide_large_source(history, capsys):
    root, base = history
    (root / ".gitattributes").write_text("large.py binary\n")
    head = commit(root / "large.py", "value = 1\n" * 1601)
    assert checker.main(["--base", base, "--head", head]) == 1
    assert "binary" in capsys.readouterr().err.lower()


@pytest.mark.parametrize("base,head", [("main", "a" * 40), ("a" * 40, "HEAD"), ("-x", "b" * 40)])
def test_mutable_or_option_like_refs_are_rejected(base, head):
    with pytest.raises(ValueError, match="commit"):
        checker._from_git(base, head)


@pytest.mark.parametrize("change", ["remove", "skip", "continue", "base", "head", "limit", "fetch"])
def test_ci_cannot_silently_disable_or_change_the_pr_size_contract(tmp_path, change):
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["quality"]["steps"]
    step = next(s for s in steps if "scripts/check_pull_request_size.py" in s.get("run", ""))
    if change == "remove":
        steps.remove(step)
    elif change == "skip":
        step["if"] = "false"
    elif change == "continue":
        step["continue-on-error"] = True
    elif change in {"base", "head"}:
        step["env"]["PR_" + change.upper()] = "${{ github.base_ref }}"
    elif change == "limit":
        step["run"] += " --limit 999999\n"
    elif change == "fetch":
        step["run"] = "\n".join(
            line for line in step["run"].splitlines() if not line.strip().startswith("git fetch")
        )
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow))
    assert any(
        "pull request size" in error or "check_pull_request_size.py" in error
        for error in workflows.check(path)
    )
