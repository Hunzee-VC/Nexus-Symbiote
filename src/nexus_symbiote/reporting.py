"""Human-readable reports in which no inventory text can act as markup or a command.

A report is a list of (text, style) lines. Every line that carries inventory or checkout
text is built by safe_line(): neutralized as a whole, behind a fixed prefix, and printed
as plain text, never through a markup parser, highlighter or line wrapper. The Action
runner renders the CLI's JSON documents with the same functions, so both read alike.
"""

from __future__ import annotations

import math
import os
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import click

from nexus_symbiote.utils.terminal import neutralize, safe_line

ReportLine = tuple[str, str | None]

LISTED = 10
"""How many findings, collection failures or excluded surfaces a gate failure lists."""
TOP_FINDINGS = 15
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _style(text: str, style: str | None) -> str:
    if style is None:
        return text
    if style == "bold":
        return click.style(text, bold=True)
    return click.style(text, fg=style)


def print_lines(lines: Iterable[ReportLine], *, err: bool = False) -> None:
    """Print report lines; styles are dropped off a terminal and under NO_COLOR."""
    color = False if os.environ.get("NO_COLOR") else None
    for text, style in lines:
        click.echo(_style(text, style), err=err, color=color)


def _at_or_above(severity: object, cutoff: object) -> bool:
    if severity not in SEVERITY_ORDER or cutoff not in SEVERITY_ORDER:
        return False
    return SEVERITY_ORDER.index(str(severity)) <= SEVERITY_ORDER.index(str(cutoff))


def _finding_line(prefix: str, finding: Mapping[str, Any]) -> str:
    return safe_line(
        prefix,
        finding.get("severity"),
        " ",
        finding.get("component_name"),
        " [",
        finding.get("category"),
        "] ",
        finding.get("detail"),
    )


def _number(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return math.nan
    return float(value)


def _shown(value: object, spec: str = ".0f") -> str:
    """A number from a report, or "?" when the report carries none."""
    number = _number(value)
    return "?" if not math.isfinite(number) else format(number, spec)


def gate_reason_lines(document: Mapping[str, Any]) -> list[ReportLine]:
    """Why a risk gate failed: its reasons, the findings that tripped it and the score."""
    lines: list[ReportLine] = []
    reasons = [str(reason) for reason in document.get("gate_reasons") or []]
    lines.extend((safe_line("  reason: ", reason), None) for reason in reasons)
    cutoff = document.get("fail_on_severity")
    if any(reason.startswith("finding at or above") for reason in reasons):
        tripped = [
            finding
            for finding in document.get("findings") or []
            if isinstance(finding, Mapping) and _at_or_above(finding.get("severity"), cutoff)
        ]
        lines.extend((_finding_line("  finding: ", finding), None) for finding in tripped[:LISTED])
        if len(tripped) > LISTED:
            lines.append((f"  ... and {len(tripped) - LISTED} more such findings", None))
    if math.isfinite(_number(document.get("overall_score"))) and "score_threshold" in document:
        threshold = document["score_threshold"]
        limit = (
            "no aggregate score threshold"
            if threshold is None
            else f"fail threshold {_shown(threshold, 'g')}"
        )
        lines.append((f"  score: {_shown(document['overall_score'], '.1f')} ({limit})", None))
    return lines


def risk_report_lines(document: Mapping[str, Any]) -> list[ReportLine]:
    """The human-readable form of a `risk --json-output` document."""
    lines: list[ReportLine] = []
    passed = document.get("passed") is True
    if document.get("assessment_basis") == "project-reconciliation-failed":
        lines.append(("Risk unknown. Project reconciliation failed.", "yellow"))
    else:
        level = neutralize(document.get("risk_level", "unknown"))
        color = {"critical": "red", "high": "red", "moderate": "yellow", "clean": "green"}
        score = _shown(document.get("overall_score"), ".1f")
        lines.append((f"Risk Score: {score} ({level})", color.get(level, "yellow")))
        basis = document.get("assessment_basis", "unknown")
        lines.append((safe_line("  Assessment basis: ", basis), None))
        lines.append((safe_line("  Coverage: ", document.get("coverage_status", "unknown")), None))
        total = _shown(document.get("total_components"))
        risky = _shown(document.get("components_with_risks"))
        lines.append((f"  Components: {total} total, {risky} with risks", None))
        counts = document.get("severity_counts") or {}
        if counts:
            lines.append(("  Severity breakdown:", None))
            for severity, count in sorted(counts.items()):
                lines.append((safe_line("    - ", severity, ": ", count), None))
        findings = [f for f in document.get("findings") or [] if isinstance(f, Mapping)]
        if findings:
            heading = "Top findings:"
            if len(findings) > TOP_FINDINGS:
                heading = (
                    f"Top findings ({TOP_FINDINGS} of {len(findings)}; --json-output lists all):"
                )
            lines.append((heading, "bold"))
            lines.extend((_finding_line("  - ", f), None) for f in findings[:TOP_FINDINGS])
    lines.append(("Gate: PASSED", "green") if passed else ("Gate: FAILED", "red"))
    lines.extend(gate_reason_lines(document))
    gaps = [str(gap) for gap in document.get("coverage_gaps") or []]
    lines.extend((safe_line("  coverage gap: ", gap), None) for gap in gaps[:LISTED])
    if len(gaps) > LISTED:
        lines.append((f"  ... and {len(gaps) - LISTED} more coverage gaps", None))
    suppressed = document.get("suppressed_findings") or []
    if suppressed:
        lines.append(
            (f"  suppressed by policy: {len(suppressed)} findings (see --json-output)", "yellow")
        )
    return lines


def _omitted(section: Mapping[str, Any]) -> list[ReportLine]:
    count = _number(section.get("issues_omitted"))
    if not math.isfinite(count) or count <= 0:
        return []
    return [(f"  ... and {count:.0f} more issues, counted in --json-output", None)]


def validation_report_lines(
    document: Mapping[str, Any], *, project: object = None
) -> list[ReportLine]:
    """The human-readable form of a `validate --json-output` document."""
    status_color = {"PASS": "green", "FAIL": "red", "UNKNOWN": "yellow"}
    lines: list[ReportLine] = [(safe_line("Policy: ", document.get("policy_source")), None)]
    if document.get("assessment_basis") == "project-reconciled":
        lines.append(
            (
                safe_line(
                    "Assessment basis: project-reconciled: the inventory was compared with a "
                    "fresh local collection of ",
                    project if project is not None else "the project",
                ),
                None,
            )
        )
    else:
        lines.append(
            (
                "Assessment basis: supplied-bom: only the inventory's own claims were checked; "
                "nothing was compared with a project. Pass --project to reconcile it.",
                "yellow",
            )
        )

    def issues(section: Mapping[str, Any], ref: str, text: str) -> None:
        for issue in section.get("issues") or []:
            if isinstance(issue, Mapping):
                severity = neutralize(issue.get("severity", "")).upper()
                lines.append(
                    (safe_line(f"  {severity} [", issue.get(ref), "] ", issue.get(text)), None)
                )

    completeness = document.get("completeness") or {}
    lines.append(("Completeness check", "bold"))
    if completeness.get("status") == "skipped":
        lines.append(("  SKIPPED by explicit policy", "yellow"))
    else:
        status = neutralize(completeness.get("status", "unknown")).upper()
        lines.append((f"  Status: {status}", status_color.get(status)))
        lines.append((f"  Components: {_shown(completeness.get('total_components'))}", None))
        issues(completeness, "surface", "description")
        lines.extend(_omitted(completeness))
    integrity = document.get("integrity") or {}
    lines.append(("Integrity check", "bold"))
    if integrity.get("status") == "skipped":
        if integrity.get("skipped_by") == "--skip-integrity":
            lines.append(
                ("  SKIPPED by --skip-integrity: no hash or signature was checked", "yellow")
            )
        else:
            lines.append(("  SKIPPED by explicit policy", "yellow"))
    else:
        status = neutralize(integrity.get("status", "unknown")).upper()
        lines.append((f"  Status: {status}", status_color.get(status)))
        verified = _shown(integrity.get("hashes_verified"))
        failed = _shown(integrity.get("hashes_failed"))
        lines.append((f"  Hashes verified: {verified}, failed: {failed}", None))
        issues(integrity, "component_ref", "detail")
        lines.extend(_omitted(integrity))
        explained = any(
            isinstance(issue, Mapping) and issue.get("severity") in {"unknown", "error", "critical"}
            for issue in integrity.get("issues") or []
        )
        if status == "UNKNOWN" and not explained:
            lines.append(("  UNKNOWN: no hash or signature could be verified", None))
    discovery = document.get("discovery_producer")
    if isinstance(discovery, Mapping):
        problems = discovery.get("problems") or []
        lines.append(("Discovery producer check", "bold"))
        lines.append(("  Status: FAIL", "red") if problems else ("  Status: PASS", "green"))
        lines.extend((safe_line("  ERROR [shadowscan] ", p), None) for p in problems)
    for error in document.get("assurance_errors") or []:
        lines.append((safe_line("  ERROR: ", error), None))
    for issue in document.get("graph_issues") or []:
        lines.append((safe_line("  ERROR: ", issue), None))
    passed = document.get("passed") is True
    lines.append(("Validation: PASSED", "green") if passed else ("Validation: FAILED", "red"))
    return lines


def diff_report_lines(document: Mapping[str, Any]) -> list[ReportLine]:
    """The human-readable form of a `diff --json-output` document."""
    if not document.get("has_changes"):
        return [("No changes detected.", "green")]
    lines: list[ReportLine] = [
        (f"{_shown(document.get('total_changes'))} changes detected", "bold")
    ]
    alerts = [a for a in document.get("security_alerts") or [] if isinstance(a, Mapping)]
    if alerts:
        lines += [("", None), ("Security Alerts:", "red")]
        for alert in alerts:
            severity = neutralize(alert.get("severity", "")).upper()
            lines.append((safe_line("  [", severity, "] ", alert.get("alert")), None))
    notes = [
        change
        for change in document.get("metadata_changes") or []
        if isinstance(change, Mapping) and change.get("severity") == "info"
    ]
    if notes:
        lines += [("", None), ("Notes:", "bold")]
        lines.extend((safe_line("  [INFO] ", change.get("detail")), None) for change in notes)
    for key, mark, label, color in (
        ("components_added", "+", "added", "green"),
        ("components_removed", "-", "removed", "red"),
        ("components_modified", "~", "modified", "yellow"),
    ):
        changes = [c for c in document.get(key) or [] if isinstance(c, Mapping)]
        if not changes:
            continue
        lines += [("", None), (f"{mark}{len(changes)} {label}", color)]
        for change in changes:
            if mark == "~":
                details = "; ".join(map(str, change.get("details") or []))
                lines.append((safe_line("  ~ ", change.get("name"), ": ", details), None))
            else:
                line = safe_line(f"  {mark} ", change.get("name"), " (", change.get("type"), ")")
                lines.append((line, None))
    for key, mark, label, color in (
        ("dependencies_added", "+", "relationships added", "green"),
        ("dependencies_removed", "-", "relationships removed", "red"),
    ):
        edges = [e for e in document.get(key) or [] if isinstance(e, Mapping)]
        if not edges:
            continue
        lines += [("", None), (f"{mark}{len(edges)} {label}", color)]
        for edge in edges:
            condition = edge.get("conditions")
            lines.append(
                (
                    safe_line(
                        f"  {mark} ",
                        edge.get("source"),
                        " -",
                        edge.get("relationship"),
                        "-> ",
                        edge.get("target"),
                        f" (when {condition})" if condition else "",
                    ),
                    None,
                )
            )
    return lines


def scan_gate_lines(
    document: Mapping[str, Any],
    failures: Mapping[str, Sequence[str]],
    excluded: Mapping[str, Sequence[str]],
    not_collected: Sequence[str],
) -> list[ReportLine]:
    lines = gate_reason_lines(document)
    if not_collected:
        names = ", ".join(not_collected)
        lines.append(
            (safe_line("  not collected: ", names, " (coverage needs every collector)"), None)
        )
    gaps = [
        (kind, name, message)
        for kind, records in (("collection failure", failures), ("excluded surface", excluded))
        for name, messages in records.items()
        for message in messages
    ]
    for kind, name, message in gaps[:LISTED]:
        lines.append((safe_line(f"  {kind} (", name, "): ", message), None))
    if len(gaps) > LISTED:
        lines.append(
            (
                f"  ... and {len(gaps) - LISTED} more collection failures or excluded surfaces, "
                "recorded under metadata.completeness in the inventory",
                None,
            )
        )
    return lines
