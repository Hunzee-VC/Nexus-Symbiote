"""Risk scoring engine — aggregates per-component risks into an overall score."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.vocab import REQUIRED_SCANNERS
from nexus_symbiote.validators.coverage import COVERAGE_COMPLETE, assess_coverage

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
    coverage_reasons: list[str] = field(default_factory=list)
    suppressed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_score": round(self.overall_score, 2),
            "risk_level": self.risk_level,
            "total_components": self.total_components,
            "components_with_risks": self.components_with_risks,
            "coverage_status": self.coverage_status,
            "coverage_reasons": list(self.coverage_reasons),
            "suppressed": self.suppressed,
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
        warn_threshold: float = 25.0,
        ignore_categories: Iterable[str] = (),
    ) -> None:
        for name, value in (("fail_threshold", fail_threshold), ("warn_threshold", warn_threshold)):
            if not 0.0 <= value <= 100.0:
                raise ValueError(f"{name} must be between 0 and 100")
        self.weights = severity_weights or SEVERITY_WEIGHTS
        self.fail_threshold = fail_threshold
        self.warn_threshold = warn_threshold
        self.ignore_categories = frozenset(ignore_categories)

    def score(self, bom: AIBOM) -> RiskReport:
        report = RiskReport()
        report.total_components = len(bom.components)
        assessment = assess_coverage(bom.metadata.completeness, REQUIRED_SCANNERS)
        report.coverage_status = assessment.state
        report.coverage_reasons = list(assessment.reasons)

        components_with_risks: set[str] = set()
        category_scores: dict[str, float] = {}
        seen: set[tuple[str, str, str]] = set()

        for comp in bom.components:
            for risk in getattr(comp, "risks", []):
                key = (comp.bom_ref, risk.category, risk.detail)
                if key in seen:
                    continue
                seen.add(key)

                sev = risk.severity
                if risk.category in self.ignore_categories and sev != RiskSeverity.CRITICAL:
                    report.suppressed += 1
                    continue

                weight = self.weights.get(sev, 0.0)
                report.findings.append(
                    RiskFinding(
                        component_ref=comp.bom_ref,
                        component_name=comp.name,
                        severity=sev,
                        category=risk.category,
                        detail=risk.detail,
                        recommendation=risk.recommendation,
                        references=list(risk.references),
                        score=weight,
                    )
                )
                components_with_risks.add(comp.bom_ref)

                sev_key = sev.value
                report.severity_counts[sev_key] = report.severity_counts.get(sev_key, 0) + 1
                category_scores[risk.category] = category_scores.get(risk.category, 0.0) + weight

        report.components_with_risks = len(components_with_risks)
        report.category_scores = category_scores
        report.overall_score = sum(f.score for f in report.findings)
        if report.severity_counts.get("critical", 0):
            report.risk_level = "critical"
        elif not report.findings and report.coverage_status != COVERAGE_COMPLETE:
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
            and report.coverage_status == COVERAGE_COMPLETE
        )
        return passed, report
