"""CycloneDX VEX output generator for AI supply-chain findings.

Traditional VEX answers "is this package affected by this CVE?" AI systems
need the same question asked about behavior: "is this model affected by this
safety finding, at this exact weight revision, including every fine-tune,
LoRA adapter, and quantization applied since?"

Statements are keyed to:
- the component's bom-ref,
- the exact artifact digests recorded in the BOM (whole-file, tensor
  inventory, safetensors header), and
- the adaptation lineage (derivation type, quantization, base model).

The output is a CycloneDX VEX document; agent-specific provenance is carried
in the ``nexus-symbiote:`` property namespace.
"""

from __future__ import annotations

import json
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import ModelComponent
from nexus_symbiote.generators.base import Generator

SEVERITY_TO_VEX: dict[RiskSeverity, str] = {
    RiskSeverity.CRITICAL: "critical",
    RiskSeverity.HIGH: "high",
    RiskSeverity.MEDIUM: "medium",
    RiskSeverity.LOW: "low",
    RiskSeverity.INFO: "info",
}


class VEXGenerator(Generator):
    """Emit a VEX document from AIBOM risk findings."""

    format_name = "cyclonedx-vex-1.0"

    def generate(self, aibom: AIBOM) -> dict[str, Any]:
        aibom.finalize()
        statements: list[dict[str, Any]] = []
        refs: set[str] = set()

        for comp in aibom.components:
            risks = getattr(comp, "risks", None) or []
            if not risks:
                continue
            refs.add(comp.bom_ref)
            for risk in risks:
                statements.append(self._statement(comp, risk))

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "version": aibom.metadata.version,
            "serialNumber": aibom.metadata.serial_number,
            "metadata": self._metadata(aibom),
            "vulnerabilities": [
                {
                    "bom-ref": f"vuln:symbiote:{s['id']}",
                    "id": s["id"],
                    "source": {
                        "name": "SymBiote AIBOM",
                        "url": "https://github.com/aisecnomad/SymBiote",
                    },
                    "description": s["description"],
                    "ratings": [{"severity": s["severity"]}],
                    "analysis": s["analysis"],
                    "affects": [{"ref": ref} for ref in s["affects"]],
                    "properties": s["properties"],
                }
                for s in statements
            ],
            "components": [
                {"bom-ref": c.bom_ref, "type": "application", "name": c.name}
                for c in aibom.components
                if c.bom_ref in refs
            ],
        }

    def _metadata(self, aibom: AIBOM) -> dict[str, Any]:
        return {
            "timestamp": aibom.metadata.timestamp.isoformat() if aibom.metadata.timestamp else None,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": aibom.metadata.tool_name,
                        "version": aibom.metadata.tool_version or "unknown",
                        "publisher": aibom.metadata.tool_vendor,
                    }
                ]
            },
        }

    def _statement(self, comp: Any, risk: Any) -> dict[str, Any]:
        """Build one VEX vulnerability entry from a risk finding."""
        vuln_id = self._vulnerability_id(comp, risk)
        description = risk.detail
        if risk.recommendation:
            description = f"{description} Recommendation: {risk.recommendation}"

        analysis: dict[str, str] = {
            "state": "affected",
            "justification": "observed in the agent supply chain at the recorded revision",
        }

        props: dict[str, str] = {
            "nexus-symbiote:category": risk.category,
        }

        if isinstance(comp, ModelComponent):
            props["nexus-symbiote:artifact"] = "model-weights"
            if comp.hashes.get("sha256"):
                props["nexus-symbiote:weightDigest"] = comp.hashes["sha256"]
            tensor_digest = comp.tensor_inventory_hash or comp.hashes.get("tensor_inventory_sha256")
            if tensor_digest:
                props["nexus-symbiote:tensorInventoryDigest"] = tensor_digest
            if comp.derivation_type:
                props["nexus-symbiote:adaptationEvent"] = comp.derivation_type
            if comp.quantization_method:
                props["nexus-symbiote:quantization"] = comp.quantization_method
            if comp.base_model_ref:
                props["nexus-symbiote:baseModelRef"] = comp.base_model_ref
            if comp.serialization_safety is not None:
                props["nexus-symbiote:serializationSafety"] = comp.serialization_safety.value
        else:
            props["nexus-symbiote:artifact"] = comp.component_type.value
            if comp.hashes.get("sha256"):
                props["nexus-symbiote:artifactDigest"] = comp.hashes["sha256"]

        if risk.references:
            props["nexus-symbiote:references"] = json.dumps(risk.references)

        return {
            "id": vuln_id,
            "description": description,
            "severity": SEVERITY_TO_VEX.get(risk.severity, "unknown"),
            "analysis": analysis,
            "affects": [comp.bom_ref],
            "properties": [{"name": k, "value": v} for k, v in props.items()],
        }

    @staticmethod
    def _vulnerability_id(comp: Any, risk: Any) -> str:
        digest = comp.hashes.get("sha256") or "no-digest"
        short = digest.split(":")[-1][:12]
        return f"SYM-{risk.category.upper().replace('_', '-')}-{short}"
