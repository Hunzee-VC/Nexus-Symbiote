"""CycloneDX 1.7 findings in triage, retaining declared model-revision evidence."""

from __future__ import annotations

from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_canonical
from nexus_symbiote.core.models import ModelComponent
from nexus_symbiote.generators.base import Generator
from nexus_symbiote.generators.validation import require_valid


class VEXGenerator(Generator):
    """Project inventory findings without treating risk heuristics as vulnerabilities."""

    format_name = "vex-cyclonedx-1.7"

    def generate(self, bom: AIBOM) -> dict[str, Any]:
        bom.finalize()
        vulnerabilities: list[dict[str, Any]] = []
        components: list[dict[str, Any]] = []
        seen: set[str] = set()
        for comp in sorted(bom.components, key=lambda c: c.bom_ref):
            if not comp.risks:
                continue
            components.append({"type": "application", "bom-ref": comp.bom_ref, "name": comp.name})
            for risk in comp.risks:
                identifier = (
                    "NEXUS-"
                    + hash_canonical(
                        {
                            "ref": comp.bom_ref,
                            "risk": risk.model_dump(mode="json"),
                            "hashes": comp.hashes,
                        }
                    ).split(":", 1)[1]
                )
                if identifier in seen:
                    continue
                seen.add(identifier)
                props = {
                    "nexus-symbiote:category": risk.category,
                    "nexus-symbiote:assurance": "declared-inventory-finding",
                }
                if comp.hashes.get("sha256"):
                    props["nexus-symbiote:artifactDigest"] = comp.hashes["sha256"]
                if isinstance(comp, ModelComponent):
                    for key, value in {
                        "weightDigest": comp.hashes.get("sha256"),
                        "tensorMetadataDigest": comp.tensor_inventory_hash,
                        "adaptationEvent": comp.derivation_type,
                        "quantization": comp.quantization_method,
                        "baseModelRef": comp.base_model_ref,
                    }.items():
                        if value:
                            props["nexus-symbiote:" + key] = value
                vulnerabilities.append(
                    {
                        "bom-ref": "vulnerability:" + identifier,
                        "id": identifier,
                        "source": {"name": "Nexus SymBiote inventory findings"},
                        "description": risk.detail,
                        "ratings": [{"severity": risk.severity.value}],
                        "analysis": {
                            "state": "in_triage",
                            "detail": "Inventory risk finding; exploitability and deployment impact are unverified. "
                            + (risk.recommendation or ""),
                        },
                        "affects": [{"ref": comp.bom_ref}],
                        "properties": [{"name": k, "value": v} for k, v in sorted(props.items())],
                    }
                )
        document: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "version": bom.metadata.version,
            "serialNumber": bom.metadata.serial_number,
            "components": components,
            "vulnerabilities": vulnerabilities,
        }
        require_valid(document, "cyclonedx")
        return document
