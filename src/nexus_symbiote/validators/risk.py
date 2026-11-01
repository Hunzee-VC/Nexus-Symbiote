"""Risk scoring engine — aggregates per-component risks into an overall score."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity

# The complete built-in collection scope; do not infer completeness from a
# caller-provided subset. Update alongside the CLI scanner registry.
REQUIRED_SCANNERS = frozenset({"mcp", "model", "prompt", "rag", "registry"})

SEVERITY_WEIGHTS: dict[RiskSeverity, float] = {
    RiskSeverity.CRITICAL: 10.0,
    RiskSeverity.HIGH: 7.0,
    RiskSeverity.MEDIUM: 4.0,
    RiskSeverity.LOW: 1.0,
    RiskSeverity.INFO: 0.0,
}


@dataclass
class RiskFinding:
    component_ref: str
    component_name: str
    severity: RiskSeverity
    category: str
    detail: str
    recommendation: str | None = None
    references: list[str] = field(default_factory=list)
    score: float = 0.0


@dataclass
class RiskReport:
    overall_score: float = 0.0
    risk_level: str = "unknown"
    findings: list[RiskFinding] = field(default_factory=list)
    category_scores: dict[str, float] = field(default_factory=dict)
    severity_counts: dict[str, int] = field(default_factory=dict)
    total_components: int = 0
    components_with_risks: int = 0
    coverage_status: str = "unknown"
    gate_reason: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_score": round(self.overall_score, 2),
            "risk_level": self.risk_level,
            "total_components": self.total_components,
            "components_with_risks": self.components_with_risks,
            "coverage_status": self.coverage_status,
            "gate_reason": self.gate_reason,
            "severity_counts": self.severity_counts,
            "category_scores": {k: round(v, 2) for k, v in self.category_scores.items()},
            "findings": [
                {
                    "component_ref": f.component_ref,
                    "component_name": f.component_name,
                    "severity": f.severity.value,
                    "category": f.category,
                    "detail": f.detail,
                    "recommendation": f.recommendation,
                    "score": round(f.score, 2),
                }
                for f in self.findings
            ],
        }


class RiskScorer:
    """Aggregates component-level risks into a scored report."""

    def __init__(
        self,
        severity_weights: dict[RiskSeverity, float] | None = None,
        fail_threshold: float = 50.0,
        warn_threshold: float = 20.0,
        ignore_categories: set[str] | None = None,
    ) -> None:
        self.weights = severity_weights or SEVERITY_WEIGHTS
        self.fail_threshold = fail_threshold
        self.warn_threshold = warn_threshold
        # Categories suppressed by policy (NS-06: risk.ignore_categories is now enforced).
        self.ignore_categories = {c.lower() for c in (ignore_categories or set())}

    def score(self, bom: AIBOM) -> RiskReport:
        report = RiskReport()
        report.total_components = len(bom.components)
        report.coverage_status = self._coverage_status(bom.metadata.completeness)
        components_with_risks: set[str] = set()
        category_scores: dict[str, float] = {}

        for comp in bom.components:
            risks = getattr(comp, "risks", [])
            if not risks:
                continue
            components_with_risks.add(comp.bom_ref)

            for risk in risks:
                if risk.category.lower() in self.ignore_categories:
                    continue
                sev = risk.severity
                weight = self.weights.get(sev, 0.0)

                finding = RiskFinding(
                    component_ref=comp.bom_ref,
                    component_name=comp.name,
                    severity=sev,
                    category=risk.category,
                    detail=risk.detail,
                    recommendation=risk.recommendation,
                    references=list(risk.references),
                    score=weight,
                )
                report.findings.append(finding)

                sev_key = sev.value
                report.severity_counts[sev_key] = report.severity_counts.get(sev_key, 0) + 1
                category_scores[risk.category] = category_scores.get(risk.category, 0.0) + weight

        report.components_with_risks = len(components_with_risks)
        report.category_scores = category_scores
        report.overall_score = sum(f.score for f in report.findings)
        if report.severity_counts.get("critical", 0):
            report.risk_level = "critical"
        elif not report.findings and report.coverage_status != "reported":
            report.risk_level = "unknown"
        else:
            report.risk_level = self._classify(report.overall_score)
        report.findings.sort(key=lambda f: self.weights.get(f.severity, 0.0), reverse=True)

        return report

    def _classify(self, score: float) -> str:
        if score >= self.fail_threshold:
            return "critical"
        if score >= self.warn_threshold:
            return "high"
        if score > 0:
            return "moderate"
        return "clean"

    @staticmethod
    def _coverage_status(coverage: Any) -> str:
        """Classify collection coverage.

        A scanner that ran and found nothing is COMPLETE coverage of an absent
        surface, not partial — so a clean full scan can legitimately reach
        'reported'. Coverage is 'partial' only when a required scanner is
        missing or a scanner actually failed, and 'unknown' when no per-scanner
        status was recorded. This makes the gate reachable while staying
        fail-closed on real failures. (NS-02)
        """
        if coverage is None:
            return "unknown"
        if coverage.scan_failures:
            return "partial"
        statuses = getattr(coverage, "scanner_status", None) or {}
        if not statuses:
            # Legacy/imported claim without per-scanner status: an explicit
            # exclusion still means coverage is incomplete; otherwise unknown.
            return "partial" if coverage.surfaces_excluded else "unknown"
        required_present = REQUIRED_SCANNERS.issubset(statuses)
        all_complete = all(state == "complete" for state in statuses.values())
        if not required_present or not all_complete:
            return "partial"
        return "reported"

    def passes_gate(self, bom: AIBOM, require_coverage: bool = True) -> tuple[bool, RiskReport]:
        """Evaluate the CI gate.

        Fails on any critical finding, on overall_score >= fail_threshold, and
        (unless require_coverage is False) on coverage that is not 'reported'.
        The distinct reasons are recorded in report.gate_reason so CI can tell
        'risk too high' apart from 'coverage incomplete'. (NS-02/NS-03)
        """
        report = self.score(bom)
        reasons: list[str] = []
        if report.severity_counts.get("critical", 0):
            reasons.append("critical-findings")
        if report.overall_score >= self.fail_threshold:
            reasons.append(f"score>={self.fail_threshold:g}")
        if require_coverage and report.coverage_status != "reported":
            reasons.append(f"coverage={report.coverage_status}")
        report.gate_reason = "; ".join(reasons) if reasons else "pass"
        return (not reasons), report
