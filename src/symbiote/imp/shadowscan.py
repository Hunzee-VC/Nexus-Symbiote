"""Import a Nexus-ShadowScan JSON report as observed evidence for one agent.

ShadowScan scans an estate and emits findings; SymBiote documents one agent.
This importer therefore takes a ``selector`` over findings (default: all) and
maps what the scan *observed* onto AgentBOM entities, with honest assurance:

* ``mcp-server`` / ``mcp-config`` findings → observed :class:`ToolServer`
  stubs (identity facts the scan could not establish stay ``unknown``);
* a finding's ``models`` → hosted :class:`Model` stubs with the resolved
  revision explicitly unknown (a scan sees names, not snapshots);
* the autonomy **interval** (``metadata.autonomy``, floor/ceiling) → the
  highest observed floor as an ``automationLevel`` claim on the ISO ladder,
  with the full interval preserved — the ceiling is never silently dropped,
  because a scan can rarely prove a capability absent;
* surfaces that produced findings → :class:`SurfaceCoverage` fragments where
  ShadowScan's surface has a SymBiote equivalent; the rest are reported in
  ``warnings`` instead of being force-fitted (unknown ≠ absent, I2);
* ``shadow`` / ``risk`` / ``surface`` per finding → ``ForeignProperty``
  passthrough (dialect ``shadowscan``), and the whole report is pinned by a
  ``scan-report`` :class:`Evidence` digest.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from symbiote.digest import jsondoc_digest
from symbiote.model.common import Claim
from symbiote.model.entities import (
    Evidence,
    ForeignProperty,
    HostedIdentity,
    Model,
    SourceRun,
    SurfaceCoverage,
    ToolServer,
)
from symbiote.model.enums import (
    AliasPinning,
    ClaimMethod,
    CoverageStatus,
    EvidenceKind,
    IsoAutomationLevel,
    ModelKind,
    Surface,
    ToolServerKind,
    UnknownReason,
)
from symbiote.model.ids import evidence_id, make_id

DIALECT = "shadowscan"
COLLECTOR_REF = "collector:shadowscan-import@0.1.0"

#: ShadowScan L0-L5 floor → ISO/IEC 22989 ladder (inverse of the exporter table).
ISO_FROM_LEVEL: dict[int, IsoAutomationLevel] = {
    0: IsoAutomationLevel.NOT_AUTOMATED,
    1: IsoAutomationLevel.ASSISTIVE_AUTOMATION,
    2: IsoAutomationLevel.PARTIAL_AUTOMATION,
    3: IsoAutomationLevel.CONDITIONAL_AUTOMATION,
    4: IsoAutomationLevel.HIGH_AUTOMATION,
    5: IsoAutomationLevel.FULL_AUTOMATION,
}

#: ShadowScan surfaces with a faithful SymBiote surface; others go to warnings.
SURFACE_MAP: dict[str, Surface] = {
    "code": Surface.CODE,
    "identity": Surface.IDENTITY,
    "gateway": Surface.MODEL_GATEWAY,
    "network": Surface.NETWORK,
    "runtime": Surface.RUNTIME,
    "endpoint": Surface.RUNTIME,
}

_MCP_KINDS = frozenset({"mcp-server", "mcp-config"})


class ShadowScanImportError(ValueError):
    """The input is not a ShadowScan JSON report this importer understands."""


@dataclass(slots=True)
class AutonomyInterval:
    floor: int
    ceiling: int
    floor_label: str | None = None
    ceiling_label: str | None = None
    oversight: str | None = None


@dataclass(slots=True)
class ShadowScanImport:
    """What one report contributes, with assurance already mapped."""

    tool_servers: list[ToolServer] = field(default_factory=list)
    models: list[Model] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    foreign_properties: list[ForeignProperty] = field(default_factory=list)
    coverage: dict[Surface, SurfaceCoverage] = field(default_factory=dict)
    automation_level: Claim[IsoAutomationLevel] | None = None
    autonomy_interval: AutonomyInterval | None = None
    warnings: list[str] = field(default_factory=list)
    report_version: str | None = None


def _autonomy(finding: Mapping[str, Any]) -> Mapping[str, Any] | None:
    metadata = finding.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    autonomy = metadata.get("autonomy")
    return autonomy if isinstance(autonomy, Mapping) else None


def import_shadowscan(
    report: Mapping[str, Any],
    *,
    agent_id: str = "agent:imported",
    selector: Callable[[Mapping[str, Any]], bool] | None = None,
    now: datetime | None = None,
) -> ShadowScanImport:
    """Map the selected findings of one report onto AgentBOM entities."""
    now = now or datetime.now(UTC)
    findings = report.get("findings")
    if not isinstance(findings, list) or "version" not in report:
        raise ShadowScanImportError("expected a ShadowScan JSON report (version + findings)")
    selected = [f for f in findings if isinstance(f, Mapping) and (selector is None or selector(f))]
    result = ShadowScanImport(report_version=str(report.get("version")))

    digest = jsondoc_digest("application/vnd.shadowscan.report+json", dict(report))
    evidence_ref = None
    if digest.ok and digest.value:
        evidence = Evidence(
            id=evidence_id(digest.value),
            evidence_kind=EvidenceKind.SCAN_REPORT,
            media_type="application/vnd.shadowscan.report+json",
            digest=digest.value,
            created=now,
        )
        result.evidence.append(evidence)
        from symbiote.model.common import EvidenceRef

        evidence_ref = EvidenceRef(digest=digest.value, media_type=evidence.media_type)
    else:
        result.warnings.append(f"report not digestable: {digest.reason}")

    def observed(value: Any, locator: str) -> Claim[Any]:
        return Claim.observed(
            value,
            method=ClaimMethod.HEURISTIC,
            collector=COLLECTOR_REF,
            locator=locator,
            observed_at=now,
            evidence=[evidence_ref] if evidence_ref is not None else [],
        )

    best: AutonomyInterval | None = None
    surface_counts: dict[str, int] = {}
    unmapped: dict[str, int] = {}
    for index, finding in enumerate(selected):
        finding_id = str(finding.get("id") or f"finding-{index}")
        resource = str(finding.get("resource") or finding_id)
        surface = str(finding.get("surface") or "")
        surface_counts[surface] = surface_counts.get(surface, 0) + 1
        kind = str(finding.get("kind") or "")

        if kind in _MCP_KINDS:
            server = ToolServer(
                id=make_id("server", resource, collision_seed=finding_id),
                name=str(finding.get("title") or resource),
                server_kind=ToolServerKind.MCP,
                transport=Claim.unknown(UnknownReason.NOT_COLLECTED, locator=resource),
                authentication=Claim.unknown(UnknownReason.NOT_COLLECTED, locator=resource),
                crosses_trust_boundary=Claim.unknown(UnknownReason.NOT_COLLECTED, locator=resource),
            )
            result.tool_servers.append(server)
            element_id = server.id
        else:
            element_id = make_id("sw", resource, collision_seed=finding_id)

        providers = finding.get("model_providers") or ["unknown"]
        for model_name in finding.get("models") or []:
            if not isinstance(model_name, str) or not model_name:
                continue
            result.models.append(
                Model(
                    id=make_id("model", model_name, collision_seed=finding_id),
                    name=model_name,
                    model_kind=ModelKind.HOSTED,
                    hosted=observed(
                        HostedIdentity(
                            provider=str(providers[0]),
                            requested_ref=model_name,
                            resolved_ref=Claim.unknown(UnknownReason.PROVIDER_UNDISCLOSED),
                            alias_pinning=AliasPinning.UNKNOWN,
                        ),
                        resource,
                    ),
                )
            )

        for key in ("shadow", "risk", "surface", "kind"):
            if finding.get(key) is not None:
                result.foreign_properties.append(
                    ForeignProperty(dialect=DIALECT, element_id=element_id, name=key, value=str(finding[key]))
                )

        autonomy = _autonomy(finding)
        if autonomy is not None:
            floor = autonomy.get("floor")
            ceiling = autonomy.get("ceiling")
            if isinstance(floor, int) and 0 <= floor <= 5 and (best is None or floor > best.floor):
                best = AutonomyInterval(
                    floor=floor,
                    ceiling=ceiling if isinstance(ceiling, int) else 5,
                    floor_label=autonomy.get("floor_label"),
                    ceiling_label=autonomy.get("ceiling_label"),
                    oversight=autonomy.get("oversight"),
                )

    if best is not None:
        result.autonomy_interval = best
        result.automation_level = observed(ISO_FROM_LEVEL[best.floor], f"{agent_id}:autonomy.floor")
        if best.ceiling > best.floor:
            result.warnings.append(
                f"autonomy ceiling L{best.ceiling} exceeds the imported floor L{best.floor}; "
                "a scan can rarely prove a capability absent — keep the interval"
            )

    for surface, count in sorted(surface_counts.items()):
        mapped = SURFACE_MAP.get(surface)
        if mapped is None:
            unmapped[surface] = count
            continue
        current = result.coverage.get(mapped, SurfaceCoverage())
        result.coverage[mapped] = current.model_copy(
            update={
                "status": CoverageStatus.QUERIED,
                "sources": [
                    *current.sources,
                    SourceRun(source=f"shadowscan:{surface}", ok=True, items=count),
                ],
                "items_seen": current.items_seen + count,
            }
        )
    if unmapped:
        listed = ", ".join(f"{name} ({count})" for name, count in sorted(unmapped.items()))
        result.warnings.append(f"ShadowScan surfaces without a SymBiote equivalent were not mapped: {listed}")
    scope = report.get("collection_scope")
    if isinstance(scope, Mapping) and scope.get("comparable") is False:
        result.warnings.append(
            f"collection scope not comparable across runs: {scope.get('reason', 'unspecified')}"
        )
    return result


__all__ = [
    "COLLECTOR_REF",
    "DIALECT",
    "ISO_FROM_LEVEL",
    "SURFACE_MAP",
    "AutonomyInterval",
    "ShadowScanImport",
    "ShadowScanImportError",
    "import_shadowscan",
]
