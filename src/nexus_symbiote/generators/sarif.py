"""SARIF 2.1.0 output generator for GitHub Security tab integration."""

from __future__ import annotations

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


class SARIFGenerator(Generator):
    format_name = "sarif"

    def generate(self, bom: AIBOM) -> dict[str, Any]:
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for comp in bom.components:
            for risk in comp.risks:
                rule_id = f"nexus-symbiote/{risk.category}"
                if rule_id not in rules:
                    rule_entry: dict[str, Any] = {
                        "id": rule_id,
                        "shortDescription": {"text": risk.category.replace("_", " ").title()},
                        "helpUri": (
                            risk.references[0]
                            if risk.references
                            else "https://github.com/aisecnomad/nexus-symbiote"
                        ),
                    }
                    if risk.recommendation:
                        rule_entry["help"] = {"text": risk.recommendation}
                    rules[rule_id] = rule_entry

                result: dict[str, Any] = {
                    "ruleId": rule_id,
                    "level": SEVERITY_TO_SARIF.get(risk.severity, "note"),
                    "message": {"text": risk.detail},
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
                                "artifactLocation": {"uri": comp.source_path},
                            }
                        }
                    ]

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
                            "endTimeUtc": datetime.now(UTC).isoformat(),
                        }
                    ],
                }
            ],
        }
