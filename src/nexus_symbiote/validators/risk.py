"""Risk scoring engine — aggregates per-component risks into an overall score."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.core.models import AgentComponent, ModelComponent, RiskAssessment
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES

REQUIRED_SCANNERS = BUILTIN_SCANNER_NAMES

SEVERITY_WEIGHTS: dict[RiskSeverity, float] = {
    RiskSeverity.CRITICAL: 10.0,
    RiskSeverity.HIGH: 7.0,
    RiskSeverity.MEDIUM: 4.0,
    RiskSeverity.LOW: 1.0,
    RiskSeverity.INFO: 0.0,
}


def _intrinsic_model_risks(component: ModelComponent) -> list[RiskAssessment]:
    """Derive risk from declared security facts even if findings were removed."""
    risks = list(component.risks)
    checks = (
        (
            component.serialization_safety
            in {
                SerializationSafety.UNSAFE_CODE_EXECUTION,
                SerializationSafety.UNSAFE_TEMPLATE_INJECTION,
            },
            RiskSeverity.CRITICAL,
            "serialization_format",
            "The declared model serialization or loader permits unsafe execution.",
        ),
        (
            component.trust_remote_code is True,
            RiskSeverity.CRITICAL,
            "code_execution",
            "The model configuration enables repository code execution.",
        ),
        (
            component.serialization_format in {"safetensors", "safe-tensors"}
            and component.serialization_safety == SerializationSafety.UNKNOWN,
            RiskSeverity.HIGH,
            "invalid_safetensors",
            "The declared SafeTensors artifact has no corroborated structural safety.",
        ),
    )
    for applies, severity, category, detail in checks:
        if applies and not any(r.category == category and r.severity == severity for r in risks):
            risks.append(RiskAssessment(severity=severity, category=category, detail=detail))
    return risks


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
    gate_reasons: list[str] = field(default_factory=list)
    ignored_findings: int = 0
    warning_threshold_exceeded: bool = False
    coverage_status: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_score": round(self.overall_score, 2),
            "risk_level": self.risk_level,
            "coverage_status": self.coverage_status,
            "gate_reasons": self.gate_reasons,
            "ignored_findings": self.ignored_findings,
            "warning_threshold_exceeded": self.warning_threshold_exceeded,
            "total_components": self.total_components,
            "components_with_risks": self.components_with_risks,
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
        ignore_categories: list[str] | None = None,
        fail_on_severity: str = "critical",
    ) -> None:
        if not math.isfinite(fail_threshold) or fail_threshold <= 0:
            raise ValueError("fail_threshold must be positive and finite")
        if not math.isfinite(warn_threshold) or warn_threshold < 0:
            raise ValueError("warn_threshold must be finite and nonnegative")
        self.weights = severity_weights or SEVERITY_WEIGHTS
        self.fail_threshold = fail_threshold
        self.warn_threshold = warn_threshold
        self.ignore_categories = set(ignore_categories or [])
        if fail_on_severity not in (*[s.value for s in RiskSeverity], "none"):
            raise ValueError("unknown fail_on_severity")
        self.fail_on_severity = fail_on_severity

    def score(self, bom: AIBOM) -> RiskReport:
        report = RiskReport()
        report.total_components = len(bom.components)
        coverage = bom.metadata.completeness
        if coverage is not None and (coverage.scan_failures or coverage.surfaces_excluded):
            report.coverage_status = "partial"
        elif coverage is not None:
            statuses = coverage.scanner_status
            if statuses and (
                not REQUIRED_SCANNERS.issubset(statuses)
                or any(state != "complete" for state in statuses.values())
            ):
                report.coverage_status = "partial"
            elif statuses and coverage.surfaces_scanned and bom.components:
                report.coverage_status = "reported"
        components_with_risks: set[str] = set()
        category_scores: dict[str, float] = {}

        for comp in bom.components:
            risks = (
                _intrinsic_model_risks(comp)
                if isinstance(comp, ModelComponent)
                else getattr(comp, "risks", [])
            )
            if not risks:
                continue
            for risk in risks:
                if risk.category in self.ignore_categories:
                    report.ignored_findings += 1
                    continue
                components_with_risks.add(comp.bom_ref)
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
        report.risk_level = (
            "unknown"
            if not report.findings and report.coverage_status != "reported"
            else self._classify(report.overall_score)
        )
        if report.severity_counts.get("critical", 0):
            report.risk_level = "critical"
        report.warning_threshold_exceeded = report.overall_score >= self.warn_threshold
        order = list(RiskSeverity)
        if self.fail_on_severity != "none":
            cutoff = order.index(RiskSeverity(self.fail_on_severity))
            if any(order.index(f.severity) <= cutoff for f in report.findings):
                report.gate_reasons.append(f"finding at or above {self.fail_on_severity}")
                if self.fail_on_severity == "critical":
                    report.risk_level = "critical"
        if report.overall_score >= self.fail_threshold:
            report.gate_reasons.append("aggregate score exceeds fail_threshold")
        if "invalid_safetensors" in category_scores:
            report.gate_reasons.append("SafeTensors structural safety is unverified")
        if report.coverage_status != "reported":
            report.gate_reasons.append("collection coverage is unknown or incomplete")
        if (
            coverage is not None
            and coverage.scope in {"repository", "repository+shadowscan"}
            and not any(
                c.properties.get("collection_mode") != "imported-unverified-report"
                and not (
                    isinstance(c, AgentComponent)
                    and c.properties.get("identity_source") == "repository-path"
                )
                for c in bom.components
            )
        ):
            report.gate_reasons.append(
                "no agent manifest or supported local inventory evidence was found"
            )
            if not report.findings:
                report.risk_level = "unknown"
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
        passed = not report.gate_reasons
        return passed, report
