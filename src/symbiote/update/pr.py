"""Open a pull request for update proposals with ``git`` and the ``gh`` CLI (``spec/monitoring.md`` §4).

The flow is deliberately boring and reviewable:

1. require a clean working tree (nothing of the user's is ever swept into the commit);
2. create ``symbiote/deps/<dependency>-<version>`` from ``base`` (default: the current branch);
3. apply the edits (:func:`symbiote.update.patch.apply_proposals`) and commit *only* the edited files;
4. ``git push --set-upstream origin <branch>`` — never ``--force``, never the default branch;
5. ``gh pr create --draft`` with a body rendering every proposal (signals, advisories, review notes).

It never merges. Every subprocess runs a fixed argv list (no shell) with an explicit ``cwd`` and a timeout;
credentials stay with ``git``/``gh`` (their own config or ``GH_TOKEN``) and are never printed: process output
included in errors is scrubbed of token-shaped strings first.
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

from symbiote.advisories.types import SignalKind
from symbiote.update.patch import PatchError, _changes, apply_proposals
from symbiote.update.types import UpdateProposal

__all__ = ["PullRequestError", "branch_name", "open_pull_request", "render_pr_body"]

BRANCH_PREFIX: Final = "symbiote/deps/"
REMOTE: Final = "origin"
_GIT_TIMEOUT: Final = 60.0
_NET_TIMEOUT: Final = 180.0
_MAX_OUTPUT: Final = 64 * 1024
_SECRETS: Final = re.compile(
    r"(gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|"
    r"(?<=://)[^/\s:@]{1,256}:[^/\s@]{1,256}(?=@)|(?i:bearer)\s+[A-Za-z0-9._~+/=-]{8,512})"
)
_CONTROL: Final = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class PullRequestError(RuntimeError):
    """The pull request could not be prepared or opened; the message never contains credentials."""


def _scrub(text: str) -> str:
    return _SECRETS.sub("<redacted>", text[:_MAX_OUTPUT])


def _slug(text: str, limit: int = 60) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", text.lower()).strip("-.")
    slug = re.sub(r"\.{2,}", ".", slug)
    return slug[:limit].strip("-.") or "dependency"


def _version_slug(version: str) -> str:
    if version.startswith("sha256:"):
        return "sha256-" + _slug(version[7:], 12)
    return _slug(version, 40)


def branch_name(proposals: Sequence[UpdateProposal]) -> str:
    """``symbiote/deps/<dependency>-<version>``; several proposals get a stable ``batch-<hash>`` name."""
    if len(proposals) == 1:
        p = proposals[0]
        return f"{BRANCH_PREFIX}{_slug(p.dependency.name)}-{_version_slug(p.proposed)}"
    material = "\n".join(sorted(f"{p.dependency.name}@{p.proposed}" for p in proposals))
    return f"{BRANCH_PREFIX}batch-{hashlib.sha256(material.encode()).hexdigest()[:12]}"


def _md(text: str, limit: int = 600) -> str:
    """Untrusted text (registry and advisory data) rendered inert: no HTML, no @-mentions, one line."""
    clean = _CONTROL.sub(" ", text).replace("\r", " ").replace("\n", " ")
    clean = clean.replace("<", "&lt;").replace(">", "&gt;")
    clean = re.sub(r"@(?=[A-Za-z0-9])", "@\u200b", clean)
    return clean[:limit] + ("…" if len(clean) > limit else "")


def _code(text: str) -> str:
    return "`" + _CONTROL.sub(" ", text).replace("`", "'")[:200] + "`"


def _commit_message(proposals: Sequence[UpdateProposal]) -> str:
    if len(proposals) == 1:
        subject = f"deps(agent): {proposals[0].title}"
    else:
        subject = f"deps(agent): update {len(proposals)} agent dependencies"
    lines = [_CONTROL.sub(" ", subject)[:120], ""]
    for p in proposals:
        lines.append(f"- [{p.kind}/{p.severity}] {p.dependency.name}: {p.current} -> {p.proposed}")
    lines += ["", "Proposed by `symbiote update`; review notes are in the pull request description."]
    return "\n".join(_CONTROL.sub(" ", line) for line in lines) + "\n"


def render_pr_body(proposals: Sequence[UpdateProposal]) -> str:
    """Markdown body: every proposal with its rationale, signals, advisories, edits and review notes."""
    out = [
        "## SymBiote agent dependency updates",
        "",
        "Proposed by `symbiote update` (AgentBOM dependency bot). This pull request is a **draft**: "
        "nothing is merged automatically. Work through the review notes before marking it ready.",
        "",
    ]
    for p in proposals:
        out += [
            f"### {_md(p.title, 200)}",
            "",
            f"- **Kind:** {p.kind}  **Severity:** {p.severity}",
            f"- **Dependency:** {_code(p.dependency.name)} ({p.dependency.ecosystem}, {p.dependency.kind.value})",
            f"- **Change:** {_code(p.current)} → {_code(p.proposed)}",
            "",
            _md(p.rationale, 2000),
            "",
        ]
        if p.signals:
            out.append("**Signals**")
            out.append("")
            for s in p.signals:
                ref = f" — {_code(s.reference)}" if s.reference else ""
                out.append(f"- `{s.kind.value}` ({s.severity}){ref}: {_md(s.detail)}")
            out.append("")
        advisories = sorted(
            {
                s.reference
                for s in p.signals
                if s.reference and s.kind in (SignalKind.VULNERABLE, SignalKind.MALICIOUS)
            }
        )
        if advisories:
            out.append("**Advisories:** " + ", ".join(_code(a) for a in advisories))
            out.append("")
        if p.edits:
            out.append("**Edits**")
            out.append("")
            for e in p.edits:
                out.append(f"- {_code(e.locator)}: {_code(e.before)} → {_code(e.after)}")
            out.append("")
        if p.review_notes:
            out.append("**Review checklist**")
            out.append("")
            out.extend(f"- [ ] {_md(n)}" for n in p.review_notes)
            out.append("")
    return "\n".join(out).rstrip() + "\n"


def _tool(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise PullRequestError(f"`{name}` was not found on PATH")
    return found


def _env() -> dict[str, str]:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"  # fail instead of prompting for credentials
    env["GH_PROMPT_DISABLED"] = "1"
    env["GIT_EDITOR"] = "true"
    return env


def _run(
    argv: Sequence[str],
    cwd: Path,
    *,
    timeout: float = _GIT_TIMEOUT,
    stdin: str | None = None,
    env: Mapping[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv list, no shell, explicit cwd
            list(argv),
            cwd=cwd,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=dict(env) if env is not None else _env(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise PullRequestError(
            f"`{Path(argv[0]).name} {argv[1] if len(argv) > 1 else ''}` timed out"
        ) from None
    except OSError as exc:
        raise PullRequestError(f"cannot run {Path(argv[0]).name}: {exc.strerror or exc}") from None
    if check and proc.returncode != 0:
        detail = _scrub((proc.stderr or proc.stdout or "").strip())
        raise PullRequestError(
            f"`{Path(argv[0]).name} {' '.join(argv[1:3])}` failed (exit {proc.returncode}): {detail[:800]}"
        )
    return proc


def _current_branch(git: str, root: Path) -> str:
    proc = _run([git, "symbolic-ref", "--quiet", "--short", "HEAD"], root, check=False)
    branch = proc.stdout.strip()
    if proc.returncode != 0 or not branch:
        raise PullRequestError("HEAD is detached; pass --base explicitly")
    return branch


def _default_branch(git: str, root: Path) -> str | None:
    proc = _run([git, "symbolic-ref", "--quiet", "--short", f"refs/remotes/{REMOTE}/HEAD"], root, check=False)
    ref = proc.stdout.strip()
    if proc.returncode == 0 and ref.startswith(f"{REMOTE}/"):
        return ref[len(REMOTE) + 1 :]
    return None


def _show(argv: Sequence[str]) -> str:
    return "$ " + shlex.join([Path(argv[0]).name, *argv[1:]])


def open_pull_request(
    root: Path,
    proposals: Sequence[UpdateProposal],
    *,
    base: str | None = None,
    draft: bool = True,
    dry_run: bool = False,
) -> str:
    """Create a branch, commit the edits, push and open a pull request; returns the PR URL.

    With ``dry_run`` nothing is changed or run (apart from read-only ``git`` queries when ``git`` is
    available) and the commands that would run are returned instead, one per line.
    """
    root = Path(root).resolve()
    with_edits = [p for p in proposals if p.edits]
    if not with_edits:
        raise PullRequestError("no proposal has a file edit; nothing to commit")
    try:
        changes = _changes(root, with_edits)
    except PatchError as exc:
        raise PullRequestError(f"the edits cannot be applied safely: {exc}") from None
    files = sorted(changes)
    if not files:
        raise PullRequestError("the edits change no file")
    branch = branch_name(with_edits)
    title = with_edits[0].title if len(with_edits) == 1 else f"Update {len(with_edits)} agent dependencies"
    title = _CONTROL.sub(" ", title)[:200]
    message = _commit_message(with_edits)
    body = render_pr_body(with_edits)

    git = shutil.which("git") or "git"
    gh = shutil.which("gh") or "gh"
    if dry_run:
        try:
            base_ref = base or _current_branch(git, root)
        except PullRequestError:
            base_ref = base or "<current branch>"
    else:
        git = _tool("git")
        gh = _tool("gh")
        base_ref = base or _current_branch(git, root)
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", base_ref) and base_ref != "<current branch>":
        raise PullRequestError(f"invalid base branch {base_ref!r}")

    commands: list[list[str]] = [
        [git, "status", "--porcelain", "--untracked-files=no"],
        [git, "checkout", "-b", branch, base_ref],
        [git, "add", "--", *files],
        [git, "commit", "--file=-", "--", *files],
        [git, "push", "--set-upstream", REMOTE, f"{branch}:{branch}"],
        [
            gh,
            "pr",
            "create",
            *(["--draft"] if draft else []),
            "--base",
            base_ref,
            "--head",
            branch,
            "--title",
            title,
            "--body-file",
            "-",
        ],
    ]
    if dry_run:
        lines = [_show(c) for c in commands]
        lines.insert(2, f"# apply edits to: {', '.join(files)}")
        return "\n".join(lines) + "\n"

    status = _run(commands[0], root)
    if status.stdout.strip():
        raise PullRequestError("the working tree has uncommitted changes; commit or stash them first")
    default = _default_branch(git, root)
    if (
        branch == base_ref
        or (default is not None and branch == default)
        or not branch.startswith(BRANCH_PREFIX)
    ):
        raise PullRequestError("refusing to push to the base or default branch")
    exists = _run([git, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"], root, check=False)
    if exists.returncode == 0:
        raise PullRequestError(f"branch {branch} already exists; delete it or merge the open pull request")
    _run(commands[1], root)
    try:
        written = apply_proposals(root, with_edits)
    except (PatchError, OSError) as exc:
        raise PullRequestError(f"applying the edits failed on branch {branch}: {exc}") from None
    if sorted(written) != files:
        raise PullRequestError("the edited files differ from the planned files")
    _run(commands[2], root)
    _run(commands[3], root, stdin=message)
    _run(commands[4], root, timeout=_NET_TIMEOUT)
    proc = _run(commands[5], root, timeout=_NET_TIMEOUT, stdin=body)
    url = next((ln.strip() for ln in reversed(proc.stdout.splitlines()) if ln.strip()), "")
    return _scrub(url)
