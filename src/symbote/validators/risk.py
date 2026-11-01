"""Risk scoring engine — aggregates per-component risks into an overall score."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from symbote.core.aibom import AIBOM
from symbote.core.enums import RiskSeverity

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_score": round(self.overall_score, 2),
            "risk_level": self.risk_level,
            "total_components": self.total_components,
            "components_with_risks": self.components_with_risks,
            "coverage_status": self.coverage_status,
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
    ) -> None:
        self.weights = severity_weights or SEVERITY_WEIGHTS
        self.fail_threshold = fail_threshold
        self.warn_threshold = warn_threshold

    def score(self, bom: AIBOM) -> RiskReport:
        report = RiskReport()
        report.total_components = len(bom.components)
        coverage = bom.metadata.completeness
        if coverage is not None and coverage.scan_failures:
            report.coverage_status = "partial"
        elif coverage is not None and coverage.surfaces_scanned and bom.components:
            # This reflects reported collection, not independent verification of completeness.
            report.coverage_status = "reported"
        components_with_risks: set[str] = set()
        category_scores: dict[str, float] = {}

        for comp in bom.components:
            risks = getattr(comp, "risks", [])
            if not risks:
                continue
            components_with_risks.add(comp.bom_ref)

            for risk in risks:
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

    def passes_gate(self, bom: AIBOM) -> tuple[bool, RiskReport]:
        report = self.score(bom)
        passed = (
            report.overall_score < self.fail_threshold
            and not report.severity_counts.get("critical", 0)
            and report.coverage_status == "reported"
        )
        return passed, report
