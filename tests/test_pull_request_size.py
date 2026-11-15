"""The cap measures an immutable PR pair, including adversarial Git path records."""

from __future__ import annotations

import copy
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.support import ROOT, load_script

checker = load_script("check_pull_request_size")
workflows = load_script("check_workflows")

GIT = shutil.which("git")
assert GIT is not None


def git(*args: str) -> str:
    return subprocess.run(  # noqa: S603 - resolved git executable in isolated test repository
        [GIT, *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


@pytest.fixture
def history(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, str]:
    monkeypatch.chdir(tmp_path)
    git("init", "-b", "main")
    git("config", "user.name", "Size test")
    git("config", "user.email", "size@example.invalid")
    (tmp_path / "README.md").write_text("base\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-m", "base")
    return tmp_path, git("rev-parse", "HEAD")


def commit(path: Path, content: str | bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    git("add", ".")
    git("commit", "-m", "fixture")
    return git("rev-parse", "HEAD")


def test_test_trees_and_reviewed_binary_assets_are_not_counted() -> None:
    listing = (
        b"10\t2\tsrc/nexus_symbiote/cli.py\0"
        b"1000\t0\ttests/test_cli.py\0"
        b"3\t1\tbenchmarks/case.json\0"
        b"-\t-\tdocs/assets/banner.jpg\0"
        b"4\t0\tREADME.md\0"
    )
    assert checker.changed_lines(listing) == 16
    assert checker.changed_lines(b"") == 0


@pytest.mark.parametrize(
    "listing",
    [
        b"-\t-\tsrc/large.py\0",
        b"-\t-\tscripts/check.py\0",
        b"-\t-\t.github/workflows/ci.yml\0",
        b"-\t-\tdocs/assets/code.py\0",
        b"-\t-\tdocs/assets/../../src/evil.png\0",
        b"2000\t0\ttests/../src/evil.py\0",
        b"1\t0\t/tests/test_cli.py\0",
        b"1\t0\ttests//test_cli.py\0",
        b"1\t0\t./tests/test_cli.py\0",
        b"1\t0\tsource.py",
        b"-\t1\tsource.py\0",
        b"-1\t0\tsource.py\0",
        b"1\t0\t\0old.py\0",
        b"1\t0\t\0\0new.py\0",
        b"bad-record\0",
    ],
)
def test_unexpected_binary_or_malformed_records_fail_closed(listing: bytes) -> None:
    with pytest.raises(ValueError):
        checker.changed_lines(listing)


def test_nul_rename_records_classify_both_paths() -> None:
    assert checker.changed_lines(b"1\t2\t\0tests/old.py\0tests/new.py\0") == 0
    assert checker.changed_lines(b"1\t2\t\0benchmarks/old.py\0tests/new.py\0") == 0
    assert checker.changed_lines(b"1\t2\t\0src/old.py\0src/new.py\0") == 3


@pytest.mark.parametrize(
    "listing",
    [
        b"0\t0\t\0src/old.py\0tests/new.py\0",
        b"1\t2\t\0tests/old.py\0src/new.py\0",
        b"0\t0\t\0benchmarks/old.py\0src/new.py\0",
        b"0\t0\t\0src/old.py\0benchmarks/new.py\0",
    ],
)
def test_saved_cross_boundary_renames_refuse_unavailable_whole_file_sizes(
    listing: bytes,
) -> None:
    with pytest.raises(ValueError, match="rename"):
        checker.changed_lines(listing)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("tests/large.py", "src/large.py"),
        ("src/large.py", "tests/large.py"),
        ("benchmarks/large.py", "src/large.py"),
        ("src/large.py", "benchmarks/large.py"),
    ],
)
def test_a_whole_file_moved_across_an_excluded_boundary_counts_its_lines(
    history: tuple[Path, str], old: str, new: str
) -> None:
    root, _ = history
    base = commit(root / old, "value = 1\n" * 1601)
    (root / new).parent.mkdir(parents=True, exist_ok=True)
    git("mv", old, new)
    git("commit", "-m", "move a whole file")
    head = git("rev-parse", "HEAD")
    assert checker.changed_lines(checker._from_git(base, head)) == 1601
    assert checker.main(["--base", base, "--head", head]) == 1


def test_copy_from_tests_into_source_with_diff_renames_copies_counts_all_lines(
    history: tuple[Path, str],
) -> None:
    root, _ = history
    git("config", "diff.renames", "copies")
    base = commit(root / "tests/large.py", "value = 1\n" * 1601)
    head = commit(root / "src/copied.py", "value = 1\n" * 1601)
    assert checker.changed_lines(checker._from_git(base, head)) == 1601
    assert checker.main(["--base", base, "--head", head]) == 1


def test_diff_relative_in_subdirectory_cannot_spoof_test_tree_prefix(
    history: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, base = history
    git("config", "diff.relative", "true")
    head = commit(root / "pkg/tests/not_excluded.py", "value = 1\n" * 1601)
    subdir = root / "pkg"
    monkeypatch.chdir(subdir)
    assert checker.changed_lines(checker._from_git(base, head)) == 1601
    assert checker.main(["--base", base, "--head", head]) == 1


def test_the_command_fails_above_the_limit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listing = tmp_path / "numstat.bin"
    listing.write_bytes(b"1600\t0\tsrc/nexus_symbiote/cli.py\0")
    assert checker.main(["--numstat-file", str(listing), "--limit", "1500"]) == 1
    assert "1600" in capsys.readouterr().out


def test_a_moving_base_and_merge_checkout_do_not_change_the_pr_pair(
    history: tuple[Path, str],
) -> None:
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
def test_git_paths_are_not_c_quoted_before_test_tree_classification(
    history: tuple[Path, str], name: str
) -> None:
    root, base = history
    head = commit(root / name, "case = 1\n" * 1601)
    assert checker.main(["--base", base, "--head", head]) == 0


def test_a_binary_attribute_cannot_hide_large_source(
    history: tuple[Path, str], capsys: pytest.CaptureFixture[str]
) -> None:
    root, base = history
    (root / ".gitattributes").write_text("large.py binary\n", encoding="utf-8")
    head = commit(root / "large.py", "value = 1\n" * 1601)
    assert checker.main(["--base", base, "--head", head]) == 1
    assert "binary" in capsys.readouterr().err.lower()


@pytest.mark.parametrize("target", ["scripts/payload.bin", ".github/workflows/payload.bin"])
def test_real_binary_files_in_gate_paths_fail_closed(
    history: tuple[Path, str], target: str, capsys: pytest.CaptureFixture[str]
) -> None:
    root, base = history
    head = commit(root / target, b"\x00\x01\x02binary-payload\x00" * 64)
    assert checker.main(["--base", base, "--head", head]) == 1
    assert "binary" in capsys.readouterr().err.lower()


def test_symlink_and_mode_changes_are_counted_safely(history: tuple[Path, str]) -> None:
    root, base = history
    script = root / "scripts/tool.py"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("x = 1\n", encoding="utf-8")
    link = root / "src/link.py"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to("../README.md")
    git("add", ".")
    git("commit", "-m", "add script and symlink")
    mid = git("rev-parse", "HEAD")
    assert checker.main(["--base", base, "--head", mid]) == 0

    script.chmod(0o755)
    link.unlink()
    link.write_text("line = 1\n" * 1601, encoding="utf-8")
    git("add", ".")
    git("commit", "-m", "chmod and replace symlink with large file")
    head = git("rev-parse", "HEAD")
    assert checker.changed_lines(checker._from_git(mid, head)) == 1602
    assert checker.main(["--base", mid, "--head", head]) == 1


@pytest.mark.parametrize(
    ("base", "head"),
    [
        ("main", "a" * 40),
        ("a" * 40, "HEAD"),
        ("-x", "b" * 40),
        ("A" * 40, "b" * 40),
        ("a" * 39, "b" * 40),
    ],
)
def test_mutable_or_option_like_refs_are_rejected(base: str, head: str) -> None:
    with pytest.raises(ValueError, match="commit"):
        checker._from_git(base, head)


@pytest.mark.parametrize(
    "change",
    [
        "remove",
        "skip",
        "no-condition",
        "continue",
        "decoy-duplicate",
        "base",
        "head",
        "extra-env",
        "limit",
        "fetch",
        "working-directory",
    ],
)
def test_ci_cannot_silently_disable_or_change_the_pr_size_contract(
    tmp_path: Path, change: str
) -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["quality"]["steps"]
    step = next(s for s in steps if "scripts/check_pull_request_size.py" in s.get("run", ""))
    if change == "remove":
        steps.remove(step)
    elif change == "skip":
        step["if"] = "false"
    elif change == "no-condition":
        step.pop("if", None)
    elif change == "continue":
        step["continue-on-error"] = True
    elif change == "decoy-duplicate":
        step["continue-on-error"] = True
        decoy = copy.deepcopy(step)
        decoy.pop("id", None)
        decoy.pop("continue-on-error", None)
        decoy["if"] = "steps.pr-size.outcome == 'success' || github.event_name == 'pull_request'"
        decoy["run"] = "python scripts/check_pull_request_size.py --base $PR_HEAD --head $PR_HEAD"
        steps.append(decoy)
    elif change in {"base", "head"}:
        step["env"]["PR_" + change.upper()] = "${{ github.base_ref }}"
    elif change == "extra-env":
        step["env"]["GIT_EXTERNAL_DIFF"] = "/bin/true"
    elif change == "limit":
        step["run"] += " --limit 999999\n"
    elif change == "fetch":
        step["run"] = "\n".join(
            line for line in step["run"].splitlines() if not line.strip().startswith("git fetch")
        )
    elif change == "working-directory":
        step["working-directory"] = "tests"
    path = tmp_path / "ci.yml"
    path.write_text(yaml.safe_dump(workflow), encoding="utf-8")
    assert any(
        "pull request size" in error or "check_pull_request_size.py" in error
        for error in workflows.check(path)
    )


def test_cli_argument_and_runtime_error_branches(
    history: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, base = history
    listing = tmp_path / "numstat.bin"
    listing.write_bytes(b"1\t0\tREADME.md\0")

    for bad_args in (
        ["--numstat-file", str(listing), "--limit", "-1"],
        ["--numstat-file", str(listing), "--base", base],
        ["--base", base],
    ):
        with pytest.raises(SystemExit) as exc:
            checker.main(bad_args)
        assert exc.value.code == 2

    assert checker.main(["--base", base, "--head", "f" * 40]) == 1

    monkeypatch.setattr(checker, "MAX_NUMSTAT_BYTES", 4)
    assert checker.main(["--numstat-file", str(listing)]) == 1

    monkeypatch.setattr(checker.shutil, "which", lambda _name: None)
    assert checker.main(["--base", base, "--head", base]) == 1
