"""SARIF 2.1.0 output generator for GitHub Security tab integration."""

from __future__ import annotations

from datetime import UTC
from pathlib import Path
from typing import Any
from urllib.parse import quote

from nexus_symbiote import __version__
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.generators._common import content_digest, prepare
from nexus_symbiote.generators.base import Generator

SEVERITY_TO_SARIF = {
    RiskSeverity.CRITICAL: "error",
    RiskSeverity.HIGH: "error",
    RiskSeverity.MEDIUM: "warning",
    RiskSeverity.LOW: "note",
    RiskSeverity.INFO: "note",
}
SECURITY_SEVERITY = {
    RiskSeverity.CRITICAL: "9.5",
    RiskSeverity.HIGH: "8.0",
    RiskSeverity.MEDIUM: "5.0",
    RiskSeverity.LOW: "2.0",
    RiskSeverity.INFO: "0.0",
}


class SARIFGenerator(Generator):
    format_name = "sarif"

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or Path.cwd()).resolve()

    def _location(self, source: str | None) -> str | None:
        if not source:
            return None
        path = Path(source)
        if path.is_absolute():
            try:
                path = path.relative_to(self.root)
            except ValueError:
                return None
        if ".." in path.parts:
            return None
        return quote(path.as_posix(), safe="/")

    def generate(self, bom: AIBOM) -> dict[str, Any]:
        prepare(bom)
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for comp in sorted(bom.components, key=lambda c: c.bom_ref):
            for risk in sorted(comp.risks, key=lambda r: (r.category, r.detail)):
                rule_id = f"nexus_symbiote/{risk.category}"
                if rule_id not in rules:
                    rule_entry: dict[str, Any] = {
                        "id": rule_id,
                        "shortDescription": {"text": risk.category.replace("_", " ").title()},
                        "helpUri": (
                            risk.references[0]
                            if risk.references
                            else "https://github.com/aisecnomad/nexus-symbiote"
                        ),
                        "properties": {"security-severity": SECURITY_SEVERITY[risk.severity]},
                    }
                    if risk.recommendation:
                        rule_entry["help"] = {"text": risk.recommendation}
                    rules[rule_id] = rule_entry
                scores = rules[rule_id]["properties"]
                if float(SECURITY_SEVERITY[risk.severity]) > float(scores["security-severity"]):
                    scores["security-severity"] = SECURITY_SEVERITY[risk.severity]

                result: dict[str, Any] = {
                    "ruleId": rule_id,
                    "level": SEVERITY_TO_SARIF.get(risk.severity, "note"),
                    "message": {"text": risk.detail},
                    "partialFingerprints": {
                        "nexus_symbiote/v1": content_digest(
                            {
                                "rule": rule_id,
                                "component": comp.bom_ref,
                                "detail": risk.detail,
                            }
                        ).split(":", 1)[1]
                    },
                    "properties": {
                        "component_ref": comp.bom_ref,
                        "trust_tier": comp.trust_tier.value if comp.trust_tier else "unknown",
                    },
                }

                if risk.recommendation:
                    result["properties"]["recommendation"] = risk.recommendation

                location = self._location(comp.source_path)
                if location:
                    result["locations"] = [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": location, "uriBaseId": "%SRCROOT%"},
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
                            "endTimeUtc": bom.metadata.timestamp.astimezone(UTC)
                            .isoformat()
                            .replace("+00:00", "Z")
                            if bom.metadata.timestamp
                            else None,
                        }
                    ],
                }
            ],
        }
