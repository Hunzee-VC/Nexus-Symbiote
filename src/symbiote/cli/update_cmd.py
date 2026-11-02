"""``symbiote update``: dependency proposals for one agent (``spec/monitoring.md`` §4, §6).

Scan the agent (or load a companion), check its dependencies with the advisors, plan proposals, then list
them, show a unified diff, write the edits, or open a draft pull request.

Exit codes: 0 nothing at or above ``high`` is pending; 1 a proposal at or above ``high`` is pending; 6 an I/O
or network failure left required lookups unreachable (or the scan, write or pull request failed). A known
high-severity proposal (1) takes precedence over incomplete coverage (6).
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer

from symbiote.cli import exit_codes

__all__ = ["register", "update"]

#: Cache directory for advisor responses, relative to the working directory.
CACHE_DIR = Path(".symbiote") / "cache"
_PENDING = frozenset({"critical", "high"})


def _proposal_json(p: Any) -> dict[str, Any]:
    return {
        "kind": p.kind,
        "severity": p.severity,
        "dependency": {
            "kind": p.dependency.kind.value,
            "ecosystem": p.dependency.ecosystem,
            "name": p.dependency.name,
            "version": p.dependency.version,
            "subjects": list(p.dependency.subjects),
            "locators": list(p.dependency.locators),
            "purl": p.dependency.purl,
        },
        "current": p.current,
        "proposed": p.proposed,
        "title": p.title,
        "rationale": p.rationale,
        "signals": [
            {"kind": s.kind.value, "severity": s.severity, "detail": s.detail, "reference": s.reference}
            for s in p.signals
        ],
        "edits": [
            {"path": e.path, "locator": e.locator, "before": e.before, "after": e.after} for e in p.edits
        ],
        "reviewNotes": list(p.review_notes),
    }


def update(
    path: Annotated[Path, typer.Argument(help="Agent directory (also the root that edits apply to).")] = Path(
        "."
    ),
    companion: Annotated[
        Path | None,
        typer.Option("--companion", help="Use this AgentBOM companion instead of scanning PATH."),
    ] = None,
    offline: Annotated[
        bool, typer.Option("--offline", help="No network: answer from the local cache only.")
    ] = False,
    cooldown_days: Annotated[
        int | None,
        typer.Option("--cooldown-days", min=0, help="Never propose releases younger than this (default 7)."),
    ] = None,
    allow_major: Annotated[bool, typer.Option("--allow-major", help="Allow major-version updates.")] = False,
    diff: Annotated[bool, typer.Option("--diff", help="Print the edits as a unified diff.")] = False,
    write: Annotated[bool, typer.Option("--write", help="Apply the edits to the files.")] = False,
    open_pr: Annotated[
        bool, typer.Option("--open-pr", help="Commit the edits on a new branch and open a draft PR with gh.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable JSON on stdout.")] = False,
) -> None:
    """Propose safe updates for the agent's MCP servers, A2A peers, skills, tools and models (Dependabot for agents)."""
    from symbiote.advisories import engine, http, inventory
    from symbiote.cli.app import console, emit, load_companion_or_exit
    from symbiote.update import (
        PatchError,
        PullRequestError,
        UpdatePolicy,
        apply_proposals,
        locate_edits,
        open_pull_request,
        plan_updates,
        render_diff,
    )

    root = path
    if companion is not None:
        bom = load_companion_or_exit(companion)
    else:
        from symbiote.scan import scan as run_scan

        try:
            bom = run_scan(path, policy=False).bom
        except (OSError, ValueError) as exc:
            console.print(f"[red]cannot scan {path}[/red]: {str(exc)[:300]}")
            raise typer.Exit(exit_codes.IO) from None

    defaults = UpdatePolicy()
    policy = UpdatePolicy(
        cooldown_days=defaults.cooldown_days if cooldown_days is None else cooldown_days,
        security_cooldown_days=defaults.security_cooldown_days,
        require_provenance_continuity=defaults.require_provenance_continuity,
        block_new_install_scripts=defaults.block_new_install_scripts,
        pin_floating=defaults.pin_floating,
        allow_major=allow_major,
    )
    refs = inventory.dependencies_from_bom(bom)
    try:
        client = http.HttpClient(CACHE_DIR, offline=offline)
        intel = engine.check_dependencies(refs, client=client, now=datetime.now(UTC), policy=policy)
    except OSError as exc:
        console.print(f"[red]dependency lookups failed[/red]: {type(exc).__name__}")
        raise typer.Exit(exit_codes.IO) from None

    proposals = plan_updates(intel, policy)
    for p in proposals:
        p.edits = locate_edits(root, p)
    unreachable = [i for i in intel if i.coverage == "unreachable"]
    not_attempted = [i for i in intel if i.coverage == "not-attempted"]

    status = exit_codes.OK
    diff_text: str | None = None
    written: list[str] = []
    pr_url: str | None = None
    try:
        if diff:
            diff_text = render_diff(root, proposals)
        if open_pr and any(p.edits for p in proposals):
            pr_url = open_pull_request(root, proposals)
        elif write:
            written = apply_proposals(root, proposals)
    except (PatchError, PullRequestError, OSError) as exc:
        console.print(f"[red]update failed[/red]: {exc}")
        status = exit_codes.IO

    data = {
        "root": str(root),
        "dependencies": len(refs),
        "proposals": [_proposal_json(p) for p in proposals],
        "unreachable": [{"name": i.ref.name, "errors": list(i.errors)[:5]} for i in unreachable],
        "notAttempted": [i.ref.name for i in not_attempted],
        "diff": diff_text,
        "written": written,
        "pullRequest": pr_url,
    }
    if as_json:
        emit(data, True)
    else:
        lines = [f"{len(refs)} dependencies checked, {len(proposals)} proposal(s)"]
        for p in proposals:
            colour = "red" if p.severity in _PENDING else "yellow" if p.severity == "medium" else "cyan"
            lines.append(
                f"[{colour}]{p.severity:8s}[/{colour}] {p.kind:12s} {p.dependency.name}  {p.current} -> {p.proposed}"
                f"  ({len(p.edits)} edit(s))"
            )
            lines.extend(f"           - {n}" for n in p.review_notes[:4])
        for i in unreachable:
            lines.append(f"[yellow]unreachable[/yellow] {i.ref.name}: lookups failed; no conclusion drawn")
        if not_attempted:
            lines.append(f"not attempted: {', '.join(i.ref.name for i in not_attempted[:10])}")
        lines.extend(f"written: {w}" for w in written)
        if pr_url:
            lines.append(f"pull request: {pr_url}")
        console.print("\n".join(lines))
        if diff_text:
            sys.stdout.write(diff_text)
    if status != exit_codes.OK:
        raise typer.Exit(status)
    if any(p.severity in _PENDING for p in proposals):
        raise typer.Exit(exit_codes.FINDINGS)
    if unreachable:
        raise typer.Exit(exit_codes.IO)


def register(app: typer.Typer) -> None:
    """Add the ``update`` command to ``app``."""
    app.command("update")(update)
