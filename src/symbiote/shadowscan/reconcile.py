"""Reconcile a declared or approved AgentBOM with a ShadowScan report (``spec/shadowscan-mapping.md §5``).

ShadowScan answers "is this discovered thing in the inventory?"; Symbiote answers the converse too: "is
everything the AgentBOM declares actually there, and does the declared autonomy hold?" The comparison is done on
the observed snapshot the report imports to (same id scheme as the ``mcp-config`` collector, so tool servers
match by id first), and the verdicts are ordinary policy findings (``SYM-SS-*``) so they flow into SARIF, exit
codes and the conformance report like any other check.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from symbiote.model import enums as E
from symbiote.model.document import AgentBOM
from symbiote.model.entities import Finding, ToolServer
from symbiote.policy.spec import SEVERITY_ORDER
from symbiote.shadowscan.autonomy import from_iso
from symbiote.shadowscan.mapping import import_report
from symbiote.shadowscan.report import ShadowScanReport


@dataclass(slots=True)
class ServerMatch:
    declared_id: str
    observed_id: str
    how: str


@dataclass(slots=True)
class AutonomyComparison:
    declared_iso: str | None
    declared_level: int | None
    floor: int | None
    ceiling: int | None
    oversight: str | None
    initiation: str | None
    verdict: str  # consistent | understated | above-ceiling | undeclared | unassessed


@dataclass(slots=True)
class Reconciliation:
    subject: str
    report_version: str
    report_complete: bool
    scan_root: str | None
    observed: AgentBOM
    matched: list[ServerMatch] = field(default_factory=list)
    observed_not_declared: list[str] = field(default_factory=list)
    declared_not_observed: list[str] = field(default_factory=list)
    declared_not_observed_state: str = "unknown"
    autonomy: AutonomyComparison | None = None
    shadow_findings: list[dict[str, Any]] = field(default_factory=list)
    registered: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def failing(self, fail_on: E.Severity = E.Severity.HIGH) -> list[Finding]:
        threshold = SEVERITY_ORDER.index(fail_on)
        return [
            f
            for f in self.findings
            if f.state is E.FindingState.FAIL and SEVERITY_ORDER.index(f.severity) <= threshold
        ]

    def summary(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "shadowscanVersion": self.report_version,
            "reportComplete": self.report_complete,
            "scanRoot": self.scan_root,
            "toolServers": {
                "matched": [asdict(m) for m in self.matched],
                "observedNotDeclared": self.observed_not_declared,
                "declaredNotObserved": self.declared_not_observed,
                "declaredNotObservedState": self.declared_not_observed_state,
            },
            "autonomy": asdict(self.autonomy) if self.autonomy else None,
            "shadowFindings": self.shadow_findings,
            "registered": self.registered,
            "findings": [f.to_json_dict() for f in self.findings],
            "counts": {
                "fail": sum(1 for f in self.findings if f.state is E.FindingState.FAIL),
                "indeterminate": sum(1 for f in self.findings if f.state is E.FindingState.INDETERMINATE),
            },
        }


def _server_key(server: ToolServer) -> tuple[str, str]:
    endpoint = server.endpoint.value if server.endpoint is not None and server.endpoint.value else ""
    return ((server.name or "").lower(), (server.command or endpoint or "").lower())


def reconcile(
    bom: AgentBOM,
    report: ShadowScanReport,
    *,
    now: datetime | None = None,
    scan_root: str | None = None,
    deterministic: bool = False,
) -> Reconciliation:
    """Compare ``bom`` (declared/approved) with what ShadowScan observed about the same agent."""
    now = now or (datetime(2000, 1, 1, tzinfo=UTC) if deterministic else datetime.now(UTC))
    root = bom.root_agent
    observed = import_report(
        report,
        agent_name=root.name or root.id.split(":", 1)[1],
        now=now,
        deterministic=deterministic,
        scope="root",
        scan_root=scan_root,
        policy=False,
    )
    rec = Reconciliation(
        subject=bom.subject,
        report_version=report.version,
        report_complete=report.complete,
        scan_root=scan_root or (report.scan_roots[0] if report.scan_roots else None),
        observed=observed,
    )
    declared = {s.id: s for s in bom.tool_servers}
    observed_servers = {s.id: s for s in observed.tool_servers if "implemented-server" not in s.tags}
    by_key = {_server_key(s): s.id for s in bom.tool_servers}
    seen_declared: set[str] = set()
    for oid, server in sorted(observed_servers.items()):
        if oid in declared:
            rec.matched.append(ServerMatch(declared_id=oid, observed_id=oid, how="id"))
            seen_declared.add(oid)
            continue
        key = _server_key(server)
        did = by_key.get(key)
        if did is not None and did not in seen_declared:
            rec.matched.append(ServerMatch(declared_id=did, observed_id=oid, how="name+launch"))
            seen_declared.add(did)
            continue
        rec.observed_not_declared.append(oid)
    code_covered = any(s.surface == "code" for s in report.stats) and report.complete
    rec.declared_not_observed = sorted(set(declared) - seen_declared)
    rec.declared_not_observed_state = "fail" if code_covered and observed_servers else "unknown"
    declared_iso = (
        root.automation_level.value.value
        if root.automation_level is not None and root.automation_level.value is not None
        else None
    )
    declared_level = from_iso(declared_iso)[0] if declared_iso else None
    assessed = observed.root_agent.autonomy_assessment
    if assessed is None:
        verdict = "unassessed"
    elif declared_level is None:
        verdict = "undeclared"
    elif declared_level < assessed.floor:
        verdict = "understated"
    elif declared_level > assessed.ceiling:
        verdict = "above-ceiling"
    else:
        verdict = "consistent"
    rec.autonomy = AutonomyComparison(
        declared_iso=declared_iso,
        declared_level=declared_level,
        floor=assessed.floor if assessed else None,
        ceiling=assessed.ceiling if assessed else None,
        oversight=assessed.oversight.value if assessed else None,
        initiation=assessed.initiation.value if assessed else None,
        verdict=verdict,
    )
    slugs = {a.id.split(":", 1)[1] for a in bom.agents}
    for f in report.findings:
        if f.shadow is True:
            rec.shadow_findings.append(
                {"id": f.id, "kind": f.kind, "title": f.title, "risk": f.risk.level, "resource": f.resource}
            )
        if f.registry_match:
            rec.registered.append(
                {
                    "id": f.id,
                    "kind": f.kind,
                    "registryMatch": f.registry_match,
                    "inAgentBom": f.registry_match in slugs,
                }
            )
    rec.findings = _findings(rec, bom, declared_level)
    return rec


def _findings(rec: Reconciliation, bom: AgentBOM, declared_level: int | None) -> list[Finding]:
    from symbiote.policy.checks import shadowscan as checks

    out: list[Finding] = []
    specs = checks.specs()
    root = bom.subject
    for oid in rec.observed_not_declared:
        server = next(s for s in rec.observed.tool_servers if s.id == oid)
        out.append(
            checks.finding_plain(
                specs["SYM-SS-002"],
                subjects=[root],
                inputs=[oid],
                message=f"ShadowScan observed tool server {server.name!r} (client {server.client or 'unknown'}) that the AgentBOM does not declare.",
                locator=server.provenance.locator,
            )
        )
    for did in rec.declared_not_observed:
        server = next(s for s in bom.tool_servers if s.id == did)
        state = (
            E.FindingState.FAIL if rec.declared_not_observed_state == "fail" else E.FindingState.INDETERMINATE
        )
        out.append(
            checks.finding_plain(
                specs["SYM-SS-003"],
                subjects=[did],
                inputs=[root],
                state=state,
                message=(
                    f"Declared tool server {server.name!r} was not observed by ShadowScan"
                    + (
                        " in a complete code scan of the same root."
                        if state is E.FindingState.FAIL
                        else "; the report is incomplete or did not cover the repository, so absence is unknown."
                    )
                ),
                locator=server.provenance.locator,
            )
        )
    auto = rec.autonomy
    if auto and auto.verdict == "understated":
        out.append(
            checks.finding_plain(
                specs["SYM-SS-004"],
                subjects=[root],
                message=f"Declared automation level {auto.declared_iso} (L{auto.declared_level}) is below the observed autonomy floor L{auto.floor} (ceiling L{auto.ceiling}).",
            )
        )
    if auto and auto.verdict == "above-ceiling":
        out.append(
            checks.finding_plain(
                specs["SYM-SS-005"],
                subjects=[root],
                severity=E.Severity.INFO,
                message=f"Declared automation level {auto.declared_iso} (L{auto.declared_level}) exceeds the observed ceiling L{auto.ceiling}: configuration evidence rules it out.",
            )
        )
    if auto and auto.oversight == "bypassed":
        out.append(
            checks.finding_plain(
                specs["SYM-SS-006"],
                subjects=[root],
                message="ShadowScan found approval-bypass evidence: side-effecting actions run without a person approving them.",
            )
        )
    for sf in rec.shadow_findings:
        severity = E.Severity.HIGH if sf["risk"] in ("critical", "high") else E.Severity.MEDIUM
        out.append(
            checks.finding_plain(
                specs["SYM-SS-001"],
                subjects=[root],
                severity=severity,
                message=f"Shadow {sf['kind']}: {sf['title']} ({sf['risk']} heuristic risk) is not claimed by the inventory supplied to ShadowScan.",
                locator=sf["resource"],
            )
        )
    if not rec.report_complete:
        out.append(
            checks.finding_plain(
                specs["SYM-SS-007"],
                subjects=[root],
                state=E.FindingState.INDETERMINATE,
                message="The ShadowScan report is incomplete: a connector failed, was skipped or stopped early, so nothing can be concluded from absence.",
            )
        )
    return out


__all__ = ["AutonomyComparison", "Reconciliation", "ServerMatch", "reconcile"]
