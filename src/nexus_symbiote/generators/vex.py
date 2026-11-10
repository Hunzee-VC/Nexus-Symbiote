"""CycloneDX 1.7 findings in triage, retaining declared model-revision evidence.

The document has its own identity: a serial number derived from the inventory's,
the inventory's version, a timestamp and the producing tool. It names the inventory
it describes with a BOM-Link external reference, and its components carry the same
types, versions, package URLs and digests as the CycloneDX inventory export.

Every statement is ``in_triage``. The command takes no triage decisions, so the
document cannot state ``not_affected``, ``exploitable`` or ``resolved``, and its
``NEXUS-`` identifiers match no public vulnerability database.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import ModelComponent
from nexus_symbiote.generators._common import (
    NAMESPACE,
    OMITTED_IMPORTED_FINDINGS,
    content_digest,
    imported_discovery_component,
)
from nexus_symbiote.generators.base import Generator
from nexus_symbiote.generators.cyclonedx import standard_component
from nexus_symbiote.generators.sarif import SEVERITY_ORDER, plain_text
from nexus_symbiote.generators.validation import require_valid

_SERIAL = re.compile(r"urn:uuid:([0-9a-fA-F-]{36})")


def finding_id(component_ref: str, category: str, detail: str) -> str:
    """Stable per component, category and finding text; equal to the SARIF fingerprint."""
    digest = content_digest(
        {"rule": f"nexus_symbiote/{category}", "component": component_ref, "detail": detail}
    )
    return "NEXUS-" + digest.split(":", 1)[1]


class VEXGenerator(Generator):
    """Project inventory findings without treating risk heuristics as vulnerabilities."""

    format_name = "vex-cyclonedx-1.7"

    def generate(self, bom: AIBOM) -> dict[str, Any]:
        bom.finalize()
        serial = str(bom.metadata.serial_number)
        stamp = bom.metadata.timestamp
        timestamp = stamp.isoformat() if stamp is not None and stamp.tzinfo is not None else None
        vulnerabilities: list[dict[str, Any]] = []
        components: list[dict[str, Any]] = []
        seen: set[str] = set()
        omitted = 0
        for comp in sorted(bom.components, key=lambda c: c.bom_ref):
            risks = getattr(comp, "risks", [])
            if imported_discovery_component(comp):
                omitted += len(risks)
                continue
            if not risks:
                continue
            components.append(standard_component(comp))
            for risk in sorted(risks, key=lambda r: (SEVERITY_ORDER[r.severity], r.category)):
                identifier = finding_id(comp.bom_ref, risk.category, risk.detail)
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
                analysis: dict[str, Any] = {
                    "state": "in_triage",
                    "detail": "Inventory risk finding; exploitability and deployment impact "
                    "are unverified. " + plain_text(risk.recommendation or ""),
                }
                if timestamp:
                    analysis["lastUpdated"] = timestamp
                vulnerabilities.append(
                    {
                        "bom-ref": "vulnerability:" + identifier,
                        "id": identifier,
                        "source": {"name": "Nexus SymBiote inventory findings"},
                        "description": plain_text(risk.detail),
                        "ratings": [{"severity": risk.severity.value}],
                        "analysis": analysis,
                        "affects": [{"ref": comp.bom_ref}],
                        "properties": [{"name": k, "value": v} for k, v in sorted(props.items())],
                    }
                )
        document: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "version": bom.metadata.version,
            "serialNumber": "urn:uuid:"
            + str(uuid.uuid5(NAMESPACE, "nexus-symbiote-vex:" + serial)),
            "metadata": {
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": bom.metadata.tool_name,
                            "version": bom.metadata.tool_version or "unknown",
                            "publisher": bom.metadata.tool_vendor,
                        }
                    ]
                },
            },
            "components": components,
            "vulnerabilities": vulnerabilities,
        }
        if timestamp:
            document["metadata"]["timestamp"] = timestamp
        if omitted:
            document["metadata"]["properties"] = [
                {"name": OMITTED_IMPORTED_FINDINGS, "value": str(omitted)}
            ]
        inventory = _SERIAL.fullmatch(serial)
        if inventory is not None:
            document["externalReferences"] = [
                {
                    "type": "bom",
                    "url": f"urn:cdx:{inventory[1].lower()}/{bom.metadata.version}",
                    "comment": "The inventory whose findings this document lists",
                }
            ]
        require_valid(document, "cyclonedx")
        return document
