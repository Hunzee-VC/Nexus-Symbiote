from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from symbiote.advisories.types import DependencyKind, DependencyRef, Signal, SignalKind
from symbiote.update import (
    PullRequestError,
    UpdateProposal,
    branch_name,
    locate_edits,
    open_pull_request,
    render_pr_body,
)
from symbiote.update.pr import _scrub

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

CONFIG = '{\n  "mcpServers": {\n    "srv": {"command": "npx", "args": ["-y", "server-pkg"]}\n  }\n}\n'
FAKE_GH = """#!/bin/sh
if [ "$1" = "pr" ] && [ "$2" = "list" ]; then
  printf '%s\\n' "$@" >> "$FAKE_GH_LOG.list"
  if [ -f "$FAKE_GH_STATE" ]; then cat "$FAKE_GH_STATE"; else echo '[]'; fi
  exit 0
fi
if [ -n "$FAKE_GH_FAIL" ]; then echo "gh: HTTP 502" >&2; exit 1; fi
printf '%s\\n' "$@" > "$FAKE_GH_LOG"
cat > "$FAKE_GH_BODY"
echo '[{"url":"https://github.example/acme/agent/pull/7","state":"OPEN"}]' > "$FAKE_GH_STATE"
echo "https://github.example/acme/agent/pull/7"
"""


def make_proposal() -> UpdateProposal:
    ref = DependencyRef(
        kind=DependencyKind.MCP_SERVER_PACKAGE,
        ecosystem="npm",
        name="server-pkg",
        version=None,
        locators=(".mcp.json#/mcpServers/srv",),
    )
    return UpdateProposal(
        kind="pin",
        dependency=ref,
        current="(floating)",
        proposed="1.4.2",
        title="Pin server-pkg to 1.4.2",
        rationale="floating reference; contact @attacker <script>",
        signals=[
            Signal(SignalKind.FLOATING, "medium", "npx -y resolves latest"),
            Signal(SignalKind.VULNERABLE, "high", "old advisory", "GHSA-1234-5678-9abc"),
        ],
        review_notes=["Re-capture the served tool definitions and re-approve the toolset digest."],
        severity="medium",
    )


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    gitconfig = tmp_path / "gitconfig"
    gitconfig.write_text(
        "[user]\n\tname = Test\n\temail = test@example.invalid\n[commit]\n\tgpgsign = false\n"
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    gh = bindir / "gh"
    gh.write_text(FAKE_GH)
    gh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{Path(shutil.which('git') or '/usr/bin/git').parent}")
    monkeypatch.setenv("FAKE_GH_LOG", str(tmp_path / "gh-args.txt"))
    monkeypatch.setenv("FAKE_GH_BODY", str(tmp_path / "gh-body.md"))
    monkeypatch.setenv("FAKE_GH_STATE", str(tmp_path / "gh-state.json"))
    monkeypatch.delenv("FAKE_GH_FAIL", raising=False)
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", "-q", "-b", "main", str(remote)], check=True)
    work = tmp_path / "work"
    work.mkdir()
    git(work, "init", "-q", "-b", "main")
    (work / ".mcp.json").write_text(CONFIG)
    (work / "README.md").write_text("agent\n")
    git(work, "add", ".")
    git(work, "commit", "-q", "-m", "init")
    git(work, "remote", "add", "origin", str(remote))
    git(work, "push", "-q", "-u", "origin", "main")
    git(work, "remote", "set-head", "origin", "main")
    return work


def test_branch_name_and_body() -> None:
    p = make_proposal()
    assert branch_name([p]) == "symbiote/deps/server-pkg-1.4.2"
    q = make_proposal()
    q.proposed = "sha256:" + "ab" * 32
    q.dependency = DependencyRef(DependencyKind.MCP_SERVER_PACKAGE, "oci", "ghcr.io/Acme/MCP", None)
    assert branch_name([q]) == "symbiote/deps/ghcr.io-acme-mcp-sha256-abababababab"
    assert branch_name([p, q]).startswith("symbiote/deps/batch-")
    body = render_pr_body([p])
    assert "GHSA-1234-5678-9abc" in body
    assert "- [ ] Re-capture the served tool definitions" in body
    assert "@attacker" not in body and "<script>" not in body  # untrusted text cannot mention or inject HTML


def test_code_spans_cannot_break_out() -> None:
    p = make_proposal()
    p.signals = [
        Signal(
            SignalKind.VULNERABLE,
            "high",
            "x",
            "GHSA-1\n\n@acme/security-team <img src=https://evil.example/x.png>",
        )
    ]
    p.dependency = DependencyRef(DependencyKind.MCP_SERVER_PACKAGE, "npm", "pkg\r\n\n# heading\t`x`", None)
    body = render_pr_body([p])
    for line in body.splitlines():
        if "@acme" in line or "<img" in line or "heading" in line:
            # only ever inside a single-line code span
            assert line.count("`") >= 2
            start, end = line.index("`"), line.rindex("`")
            for needle in ("@acme", "<img", "# heading"):
                if needle in line:
                    assert start < line.index(needle) < end
    assert "\n\n@acme" not in body and "\n# heading" not in body


def test_dry_run_lists_commands_without_side_effects(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(CONFIG)
    p = make_proposal()
    p.edits = locate_edits(tmp_path, p)
    out = open_pull_request(tmp_path, [p], base="main", dry_run=True)
    assert "git checkout -b symbiote/deps/server-pkg-1.4.2 main" in out
    assert (
        "git push --set-upstream origin symbiote/deps/server-pkg-1.4.2:symbiote/deps/server-pkg-1.4.2" in out
    )
    assert "gh pr create --draft --base main --head symbiote/deps/server-pkg-1.4.2" in out
    assert "--force" not in out and "merge" not in out
    assert (tmp_path / ".mcp.json").read_text() == CONFIG


def test_requires_edits() -> None:
    with pytest.raises(PullRequestError, match="no proposal has a file edit"):
        open_pull_request(Path("."), [make_proposal()], dry_run=True)


def test_opens_draft_pr_in_temporary_repository(repo: Path, tmp_path: Path) -> None:
    (repo / "untracked-notes.txt").write_text("not mine to commit\n")
    p = make_proposal()
    p.edits = locate_edits(repo, p)
    url = open_pull_request(repo, [p])
    assert url == "https://github.example/acme/agent/pull/7"
    branch = "symbiote/deps/server-pkg-1.4.2"
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == branch
    assert git(repo, "show", "--name-only", "--format=", "HEAD") == ".mcp.json"
    assert '"server-pkg@1.4.2"' in (repo / ".mcp.json").read_text()
    message = git(repo, "log", "-1", "--format=%B")
    assert "[pin/medium] server-pkg: (floating) -> 1.4.2" in message
    remote_branches = git(tmp_path / "remote.git", "branch", "--list")
    assert branch in remote_branches
    assert git(tmp_path / "remote.git", "rev-parse", "main") == git(repo, "rev-parse", "main")
    args = (tmp_path / "gh-args.txt").read_text().splitlines()
    assert args[:3] == ["pr", "create", "--draft"]
    assert args[args.index("--base") + 1] == "main"
    assert args[args.index("--head") + 1] == branch
    body = (tmp_path / "gh-body.md").read_text()
    assert "re-approve the toolset digest" in body
    assert (repo / "untracked-notes.txt").exists()
    assert "untracked-notes.txt" in git(repo, "status", "--porcelain")
    # a second run finds the open pull request and changes nothing
    git(repo, "checkout", "-q", "main")
    head = git(repo, "rev-parse", "HEAD")
    q = make_proposal()
    q.edits = locate_edits(repo, q)
    assert open_pull_request(repo, [q]) == "https://github.example/acme/agent/pull/7"
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert git(repo, "rev-parse", "HEAD") == head


def test_rerun_from_fresh_clone_is_a_no_op(repo: Path, tmp_path: Path) -> None:
    # Finding: day 2 runs in a fresh CI clone (no local branch) while day 1's PR is still open.
    p = make_proposal()
    p.edits = locate_edits(repo, p)
    open_pull_request(repo, [p])
    remote_head = git(tmp_path / "remote.git", "rev-parse", "symbiote/deps/server-pkg-1.4.2")
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(tmp_path / "remote.git"), str(clone)], check=True)
    q = make_proposal()
    q.edits = locate_edits(clone, q)
    assert open_pull_request(clone, [q]) == "https://github.example/acme/agent/pull/7"
    assert git(clone, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert git(clone, "branch", "--list", "symbiote/*") == ""
    assert git(tmp_path / "remote.git", "rev-parse", "symbiote/deps/server-pkg-1.4.2") == remote_head


def test_remote_branch_without_pr_is_refused_before_any_change(repo: Path, tmp_path: Path) -> None:
    git(repo, "push", "-q", "origin", "main:symbiote/deps/server-pkg-1.4.2")
    p = make_proposal()
    p.edits = locate_edits(repo, p)
    with pytest.raises(PullRequestError, match="without a pull request"):
        open_pull_request(repo, [p])
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert (repo / ".mcp.json").read_text() == CONFIG


def test_failure_after_checkout_restores_branch_and_cleans_up(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_GH_FAIL", "1")
    p = make_proposal()
    p.edits = locate_edits(repo, p)
    with pytest.raises(PullRequestError, match="failed"):
        open_pull_request(repo, [p])
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert git(repo, "branch", "--list", "symbiote/*") == ""
    assert (repo / ".mcp.json").read_text() == CONFIG
    assert git(repo, "status", "--porcelain", "--untracked-files=no") == ""
    # the just-pushed branch was removed from the remote, so the next run starts clean
    assert git(tmp_path / "remote.git", "branch", "--list", "symbiote/*") == ""


def test_refuses_dirty_working_tree(repo: Path) -> None:
    (repo / "README.md").write_text("changed\n")
    p = make_proposal()
    p.edits = locate_edits(repo, p)
    with pytest.raises(PullRequestError, match="uncommitted changes"):
        open_pull_request(repo, [p])
    assert git(repo, "branch", "--list", "symbiote/*") == ""
    assert (repo / ".mcp.json").read_text() == CONFIG


def test_scrub_removes_tokens() -> None:
    text = "fatal: https://x-access-token:ghs_abcdefghijklmnopqrstuvwxyz0123@github.com/a/b ghp_" + "A" * 36
    scrubbed = _scrub(text)
    assert "ghs_" not in scrubbed and "ghp_" not in scrubbed
    assert "<redacted>" in scrubbed
