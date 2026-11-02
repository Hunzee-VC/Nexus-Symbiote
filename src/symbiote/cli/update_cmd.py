"""``symbiote update``: dependency proposals for one agent (``spec/monitoring.md`` §4, §6).

Scan the agent (or load a companion), check its dependencies with the advisors, plan proposals, then list
them, show a unified diff, write the edits, or open a draft pull request.

Exit codes: 0 nothing at or above ``--fail-on`` (default ``high``) is pending and every lookup that was attempted
succeeded; 1 a proposal, or an unresolved risk signal (vulnerable, malicious, floating, deprecated, yanked,
definition drift, retiring model) on a dependency without a proposal, is at or above ``--fail-on``; 6 a lookup
failed (coverage ``unreachable``, or ``partial`` because a source did not answer), or the scan, write or pull
request failed, or an unexpected error occurred. A pending finding (1) takes precedence over incomplete coverage
(6); a failed write or pull request (6) takes precedence over both. Every dependency whose coverage is not
``queried`` is listed with its coverage and errors: what could not be checked is never reported as clean.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Final

import click
import typer

from symbiote.cli import exit_codes

__all__ = ["register", "update"]

#: Cache directory for advisor responses, relative to the working directory.
CACHE_DIR = Path(".symbiote") / "cache"
_SEVERITIES: Final[tuple[str, ...]] = ("critical", "high", "medium", "low", "info")
#: Errors that state a known gap (no advisor exists) rather than a failed lookup.
_NO_ADVISOR: Final[tuple[str, ...]] = ("no vulnerability advisor", "no advisor")
#: Signal kinds that are a risk in themselves (not facts about a candidate release).
_RISK_SIGNALS: Final = frozenset(
    {"vulnerable", "malicious", "floating", "deprecated", "yanked", "definition-drift", "retiring-model"}
)


class FailOn(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


def _at_or_above(severity: str, threshold: str) -> bool:
    return severity in _SEVERITIES and _SEVERITIES.index(severity) <= _SEVERITIES.index(threshold)


def _lookup_failed(intel: Any) -> bool:
    """A source that should have answered did not (as opposed to a dependency no advisor covers)."""
    if intel.coverage == "unreachable":
        return True
    if intel.coverage == "partial":
        return not intel.errors or any(not str(e).startswith(_NO_ADVISOR) for e in intel.errors)
    return False


def _signal_json(s: Any) -> dict[str, Any]:
    return {"kind": s.kind.value, "severity": s.severity, "detail": s.detail, "reference": s.reference}


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
        "signals": [_signal_json(s) for s in p.signals],
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
    fail_on: Annotated[
        FailOn,
        typer.Option(
            "--fail-on", help="Exit 1 when a proposal or unresolved risk is at or above this severity."
        ),
    ] = FailOn.HIGH,
    diff: Annotated[bool, typer.Option("--diff", help="Print the edits as a unified diff.")] = False,
    write: Annotated[bool, typer.Option("--write", help="Apply the edits to the files.")] = False,
    open_pr: Annotated[
        bool, typer.Option("--open-pr", help="Commit the edits on a new branch and open a draft PR with gh.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable JSON on stdout.")] = False,
) -> None:
    """Propose safe updates for the agent's MCP servers, A2A peers, skills, tools and models (Dependabot for agents)."""
    from symbiote.cli.app import console

    try:
        _update(
            path, companion, offline, cooldown_days, allow_major, str(fail_on), diff, write, open_pr, as_json
        )
    except (typer.Exit, typer.Abort, click.exceptions.Exit, click.exceptions.Abort, click.ClickException):
        raise
    except Exception as exc:
        console.print(f"[red]symbiote update failed unexpectedly[/red]: {type(exc).__name__}", markup=True)
        raise typer.Exit(exit_codes.IO) from None


def _update(
    path: Path,
    companion: Path | None,
    offline: bool,
    cooldown_days: int | None,
    allow_major: bool,
    fail_on: str,
    diff: bool,
    write: bool,
    open_pr: bool,
    as_json: bool,
) -> None:
    from rich.markup import escape

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
            console.print(f"[red]cannot scan {escape(str(path))}[/red]: {escape(str(exc)[:300])}")
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
    incomplete = [i for i in intel if i.coverage != "queried"]
    failed = [i for i in intel if _lookup_failed(i)]
    proposed_refs = {
        (p.dependency.kind, p.dependency.ecosystem, p.dependency.name, p.dependency.version)
        for p in proposals
    }
    unresolved = [
        (i, s)
        for i in intel
        if (i.ref.kind, i.ref.ecosystem, i.ref.name, i.ref.version) not in proposed_refs
        for s in i.signals
        if s.kind.value in _RISK_SIGNALS
    ]

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
        console.print(f"[red]update failed[/red]: {escape(str(exc))}")
        status = exit_codes.IO

    data = {
        "root": str(root),
        "dependencies": len(refs),
        "failOn": fail_on,
        "proposals": [_proposal_json(p) for p in proposals],
        "coverage": [
            {
                "name": i.ref.name,
                "kind": i.ref.kind.value,
                "ecosystem": i.ref.ecosystem,
                "version": i.ref.version,
                "coverage": i.coverage,
                "lookupFailed": _lookup_failed(i),
                "errors": [str(e)[:500] for e in i.errors[:10]],
                "signals": [_signal_json(s) for s in i.signals],
            }
            for i in incomplete
        ],
        "unresolvedSignals": [{"name": i.ref.name, **_signal_json(s)} for i, s in unresolved],
        "lookupFailures": len(failed),
        "unreachable": [{"name": i.ref.name, "errors": list(i.errors)[:5]} for i in unreachable],
        "notAttempted": [i.ref.name for i in not_attempted],
        "diff": diff_text,
        "written": written,
        "pullRequest": pr_url,
    }
    if as_json:
        emit(data, True)
    else:
        summary = f"{len(refs)} dependencies checked, {len(proposals)} proposal(s)"
        if incomplete:
            summary += f"; {len(incomplete)} not fully checked ({len(failed)} lookup failure(s))"
        lines = [summary]
        for p in proposals:
            colour = (
                "red" if _at_or_above(p.severity, "high") else "yellow" if p.severity == "medium" else "cyan"
            )
            lines.append(
                f"[{colour}]{p.severity:8s}[/{colour}] {p.kind:12s} {escape(p.dependency.name)}  "
                f"{escape(p.current)} -> {escape(p.proposed)}  ({len(p.edits)} edit(s))"
            )
            lines.extend(f"           - {escape(n)}" for n in p.review_notes[:4])
        for i in incomplete:
            colour = "red" if _lookup_failed(i) else "yellow"
            lines.append(
                f"[{colour}]{i.coverage}[/{colour}] {escape(i.ref.name)}: no clean conclusion drawn"
                + ("" if i.coverage != "unreachable" else " (lookups failed)")
            )
            lines.extend(f"           ! {escape(str(e)[:300])}" for e in i.errors[:5])
        for i, sig in unresolved:
            lines.append(
                f"unresolved {sig.severity} {sig.kind.value}: {escape(i.ref.name)}: {escape(sig.detail)}"
            )
        lines.extend(f"written: {escape(w)}" for w in written)
        if pr_url:
            lines.append(f"pull request: {escape(pr_url)}")
        console.print("\n".join(lines))
        if diff_text:
            sys.stdout.write(diff_text)
    if status != exit_codes.OK:
        raise typer.Exit(status)
    if any(_at_or_above(p.severity, fail_on) for p in proposals) or any(
        _at_or_above(sig.severity, fail_on) for _, sig in unresolved
    ):
        raise typer.Exit(exit_codes.FINDINGS)
    if failed:
        raise typer.Exit(exit_codes.IO)


def register(app: typer.Typer) -> None:
    """Add the ``update`` command to ``app``."""
    app.command("update")(update)
