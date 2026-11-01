"""SARIF 2.1.0 output generator for GitHub Security tab integration."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from nexus_symbiote import __version__
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import CompletenessClaim
from nexus_symbiote.core.redact import redact_url
from nexus_symbiote.core.vocab import SCANNER_FAILED
from nexus_symbiote.generators.base import Generator

SEVERITY_TO_SARIF = {
    RiskSeverity.CRITICAL: "error",
    RiskSeverity.HIGH: "error",
    RiskSeverity.MEDIUM: "warning",
    RiskSeverity.LOW: "note",
    RiskSeverity.INFO: "note",
}

# GitHub code scanning reads security-severity from the rule, so each rule takes the highest
# severity of its results.
SECURITY_SEVERITY = {
    RiskSeverity.CRITICAL: "9.5",
    RiskSeverity.HIGH: "8.0",
    RiskSeverity.MEDIUM: "5.5",
    RiskSeverity.LOW: "3.0",
    RiskSeverity.INFO: "0.0",
}

_SEVERITY_RANK = {
    RiskSeverity.CRITICAL: 4,
    RiskSeverity.HIGH: 3,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.LOW: 1,
    RiskSeverity.INFO: 0,
}

# POSIX absolute, UNC, or Windows drive-letter paths.
_ABSOLUTE_PATH = re.compile(r"^(?:/|\\\\|[A-Za-z]:[\\/])")
_NO_RECOMMENDATION = "No recommendation is recorded for this rule. Review each result's message."


def _artifact_uri(source_path: str) -> str:
    """Project-relative location. Absolute paths keep only the file name; URLs are redacted."""
    if "://" in source_path:
        return redact_url(source_path)
    if _ABSOLUTE_PATH.match(source_path):
        return re.split(r"[\\/]", source_path)[-1]
    return source_path


def _execution_status(claim: CompletenessClaim | None) -> tuple[bool, str]:
    """Whether the scan ran without failures, and the reason when it did not."""
    if claim is None:
        return True, "no completeness claim recorded"
    reasons = [f"scan failure: {failure}" for failure in claim.scan_failures]
    reasons.extend(
        f"scanner failed: {name}"
        for name, status in sorted(claim.scanner_status.items())
        if status == SCANNER_FAILED
    )
    if reasons:
        return False, "; ".join(reasons)
    return True, "no scan failures or failed scanners recorded"


class SARIFGenerator(Generator):
    format_name = "sarif"

    def generate(self, bom: AIBOM) -> dict[str, Any]:
        rules: dict[str, dict[str, Any]] = {}
        rule_severity: dict[str, RiskSeverity] = {}
        rule_help: dict[str, str] = {}
        results: list[dict[str, Any]] = []

        for comp in bom.components:
            for risk in comp.risks:
                rule_id = f"nexus-symbiote/{risk.category}"
                if rule_id not in rules:
                    rules[rule_id] = {
                        "id": rule_id,
                        "shortDescription": {"text": risk.category.replace("_", " ").title()},
                        "helpUri": (
                            risk.references[0]
                            if risk.references
                            else "https://github.com/aisecnomad/nexus-symbiote"
                        ),
                    }
                    rule_severity[rule_id] = risk.severity
                elif _SEVERITY_RANK[risk.severity] > _SEVERITY_RANK[rule_severity[rule_id]]:
                    rule_severity[rule_id] = risk.severity
                if risk.recommendation:
                    rule_help.setdefault(rule_id, risk.recommendation)

                fingerprint = hashlib.sha256(
                    f"{rule_id}|{comp.bom_ref}|{risk.detail}".encode()
                ).hexdigest()
                result: dict[str, Any] = {
                    "ruleId": rule_id,
                    "level": SEVERITY_TO_SARIF.get(risk.severity, "note"),
                    "message": {"text": risk.detail},
                    "partialFingerprints": {"nexusSymbiote/v1": fingerprint},
                    "properties": {
                        "component_ref": comp.bom_ref,
                        "trust_tier": comp.trust_tier.value if comp.trust_tier else "unknown",
                    },
                }

                if risk.recommendation:
                    result["properties"]["recommendation"] = risk.recommendation

                if comp.source_path:
                    result["locations"] = [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": _artifact_uri(comp.source_path)},
                            }
                        }
                    ]

                results.append(result)

        for rule_id, rule in rules.items():
            rule["help"] = {"text": rule_help.get(rule_id, _NO_RECOMMENDATION)}
            rule["properties"] = {"security-severity": SECURITY_SEVERITY[rule_severity[rule_id]]}

        succeeded, reason = _execution_status(bom.metadata.completeness)
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "nexus-symbiote",
                            "version": __version__,
                            "informationUri": "https://github.com/aisecnomad/nexus-symbiote",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": succeeded,
                            "endTimeUtc": datetime.now(UTC).isoformat(),
                            "properties": {"nexus-symbiote:executionSuccessfulReason": reason},
                        }
                    ],
                }
            ],
        }
