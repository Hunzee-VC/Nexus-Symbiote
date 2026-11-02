"""Compatibility façade: ShadowScan report import (``symbiote.shadowscan`` is the implementation).

:func:`import_shadowscan` keeps the original signature (a parsed report dict, an ``agent_id`` and a finding
``selector``) and returns the flat :class:`ShadowScanImport` summary. New code should use
:func:`symbiote.shadowscan.read_report` + :func:`symbiote.shadowscan.import_report` (a complete observed
snapshot) or :func:`symbiote.shadowscan.map_report` (entities for a collector), which also handle the
CycloneDX dialect, every ShadowScan kind, coverage from connector stats and the reconcile checks.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from symbiote.model.common import Claim
from symbiote.model.entities import Agent, Evidence, ForeignProperty, Model, SurfaceCoverage, ToolServer
from symbiote.model.enums import AgentRole, IsoAutomationLevel, Surface
from symbiote.shadowscan.autonomy import to_iso
from symbiote.shadowscan.mapping import DIALECT, map_report
from symbiote.shadowscan.report import ReportError, load_report

COLLECTOR_REF = "collector:shadowscan-report@0.1.0"
#: ShadowScan L0-L5 floor → ISO/IEC 22989 ladder.
ISO_FROM_LEVEL: dict[int, IsoAutomationLevel] = {n: to_iso(n) for n in range(6)}


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
    """What one report contributes, with assurance already mapped (flat view)."""

    tool_servers: list[ToolServer] = field(default_factory=list)
    models: list[Model] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    foreign_properties: list[ForeignProperty] = field(default_factory=list)
    coverage: dict[Surface, SurfaceCoverage] = field(default_factory=dict)
    automation_level: Claim[IsoAutomationLevel] | None = None
    autonomy_interval: AutonomyInterval | None = None
    warnings: list[str] = field(default_factory=list)
    report_version: str | None = None
    #: the full mapping result (agents, identities, grants, edges, flags …)
    detail: Any = None


def import_shadowscan(
    report: Mapping[str, Any],
    *,
    agent_id: str = "agent:imported",
    selector: Callable[[Mapping[str, Any]], bool] | None = None,
    now: datetime | None = None,
) -> ShadowScanImport:
    """Map the selected findings of one parsed report onto AgentBOM entities for ``agent_id``."""
    now = now or datetime.now(UTC)
    if not isinstance(report, Mapping) or "findings" not in report or "version" not in report:
        raise ShadowScanImportError("expected a ShadowScan JSON report (version + findings)")
    if selector is not None:
        report = {
            **report,
            "findings": [f for f in report["findings"] if isinstance(f, Mapping) and selector(f)],
        }
    try:
        parsed = load_report(report)
    except ReportError as exc:
        raise ShadowScanImportError(str(exc)) from exc
    root = Agent(id=agent_id, name=agent_id.split(":", 1)[-1], version="0.0.0", role=AgentRole.ROOT)
    mapped = map_report(parsed, root=root, now=now, scope="estate")
    result = ShadowScanImport(
        tool_servers=list(mapped.tool_servers),
        models=list(mapped.models),
        evidence=list(mapped.evidence),
        coverage={s: c for s, c in mapped.coverage.items() if c.sources or c.status.value != "not-attempted"},
        automation_level=mapped.root.automation_level,
        warnings=list(mapped.warnings),
        report_version=parsed.version or None,
        detail=mapped,
    )
    assessed = mapped.root.autonomy_assessment
    if assessed is not None:
        result.autonomy_interval = AutonomyInterval(
            floor=assessed.floor,
            ceiling=assessed.ceiling,
            floor_label=f"L{assessed.floor}",
            ceiling_label=f"L{assessed.ceiling}",
            oversight=assessed.oversight.value,
        )
        result.warnings.append(
            f"autonomy interval preserved: floor L{assessed.floor}, ceiling L{assessed.ceiling} "
            "(a ceiling of L5 means 'not ruled out', never a level)"
        )
    for f in parsed.findings:
        element = mapped.derived_from.get(f.id, [f"shadowscan:finding:{f.id}"])[0]
        result.foreign_properties.extend(
            ForeignProperty(dialect=DIALECT, element_id=element, name=name, value=value)
            for name, value in (
                ("shadow", "unknown" if f.shadow is None else str(f.shadow).lower()),
                ("risk", f.risk.level),
                ("surface", f.surface),
                ("kind", f.kind),
            )
        )
    return result


__all__ = [
    "COLLECTOR_REF",
    "ISO_FROM_LEVEL",
    "AutonomyInterval",
    "ShadowScanImport",
    "ShadowScanImportError",
    "import_shadowscan",
]
