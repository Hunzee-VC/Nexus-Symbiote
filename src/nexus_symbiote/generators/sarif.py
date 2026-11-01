"""SARIF 2.1.0 output generator for GitHub Security tab integration."""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from typing import Any

from nexus_symbiote import __version__
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.generators.base import Generator

SEVERITY_TO_SARIF = {
    RiskSeverity.CRITICAL: "error",
    RiskSeverity.HIGH: "error",
    RiskSeverity.MEDIUM: "warning",
    RiskSeverity.LOW: "note",
    RiskSeverity.INFO: "note",
}

# GitHub code scanning reads a numeric "security-severity" (CVSS-like 0-10) to
# rank alerts; without it every alert defaults to the same bucket. (NS-09)
SECURITY_SEVERITY = {
    RiskSeverity.CRITICAL: "9.5",
    RiskSeverity.HIGH: "8.0",
    RiskSeverity.MEDIUM: "5.0",
    RiskSeverity.LOW: "3.0",
    RiskSeverity.INFO: "0.0",
}

# A result with no physical location is dropped or mis-attributed by GitHub
# code scanning. Components discovered without a file (imported/remote) fall
# back to the BOM artifact so the finding is never silently lost. (NS-09)
_FALLBACK_URI = "nexus-symbiote-aibom.json"


def _fingerprint(*parts: str) -> str:
    """Stable fingerprint so GitHub correlates the same alert across runs (NS-09)."""
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:32]


def _end_time() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    when = datetime.fromtimestamp(int(epoch), tz=UTC) if epoch else datetime.now(UTC)
    return when.isoformat()


class SARIFGenerator(Generator):
    format_name = "sarif"

    def generate(self, bom: AIBOM) -> dict[str, Any]:
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for comp in bom.components:
            for index, risk in enumerate(comp.risks):
                rule_id = f"nexus-symbiote/{risk.category}"
                severity = SEVERITY_TO_SARIF.get(risk.severity, "note")
                security_severity = SECURITY_SEVERITY.get(risk.severity, "0.0")

                if rule_id not in rules:
                    rule_entry: dict[str, Any] = {
                        "id": rule_id,
                        "name": risk.category.replace("_", " ").title().replace(" ", ""),
                        "shortDescription": {"text": risk.category.replace("_", " ").title()},
                        "helpUri": (
                            risk.references[0]
                            if risk.references
                            else "https://github.com/aisecnomad/nexus-symbiote"
                        ),
                        "defaultConfiguration": {"level": severity},
                        "properties": {
                            "security-severity": security_severity,
                            "tags": ["supply-chain", "ai-security"],
                        },
                    }
                    if risk.recommendation:
                        rule_entry["help"] = {"text": risk.recommendation}
                    rules[rule_id] = rule_entry

                uri = comp.source_path or _FALLBACK_URI
                result: dict[str, Any] = {
                    "ruleId": rule_id,
                    "level": severity,
                    "message": {"text": risk.detail},
                    "locations": [
                        {
                            "physicalLocation": {"artifactLocation": {"uri": uri}},
                            "logicalLocations": [
                                {"fullyQualifiedName": comp.bom_ref, "kind": "resource"}
                            ],
                        }
                    ],
                    # Stable across runs so GitHub de-duplicates rather than
                    # re-opening the same alert each scan. (NS-09)
                    "partialFingerprints": {
                        "nexusSymbioteComponentRisk/v1": _fingerprint(
                            rule_id, comp.bom_ref, str(index)
                        )
                    },
                    "properties": {
                        "component_ref": comp.bom_ref,
                        "trust_tier": comp.trust_tier.value if comp.trust_tier else "unknown",
                        "security-severity": security_severity,
                    },
                }
                if risk.recommendation:
                    result["properties"]["recommendation"] = risk.recommendation

                results.append(result)

        return {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
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
                            "executionSuccessful": True,
                            "endTimeUtc": _end_time(),
                        }
                    ],
                }
            ],
        }
