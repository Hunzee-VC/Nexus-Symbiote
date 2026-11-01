"""SPDX 3.0 output generator.

Maps AgentBOM components to SPDX 3.0 JSON-LD, using the AI and dataset
profiles alongside agent-specific extensions under the symbote namespace.
"""

from __future__ import annotations

import uuid
from typing import Any

from symbote.core.aibom import AIBOM, DependencyEdge
from symbote.core.enums import ComponentType
from symbote.core.models import (
    AgentComponent,
    AnyComponent,
    ModelComponent,
    RAGSourceComponent,
    ToolComponent,
)
from symbote.generators.base import Generator

SPDX_TYPE_MAP: dict[ComponentType, str] = {
    ComponentType.AGENT: "ai_AIPackage",
    ComponentType.MODEL: "ai_AIPackage",
    ComponentType.TOOL: "software_Package",
    ComponentType.MCP_SERVER: "software_Package",
    ComponentType.PROMPT_TEMPLATE: "software_Snippet",
    ComponentType.GUARDRAIL_POLICY: "software_Package",
    ComponentType.MEMORY_STORE: "dataset_Dataset",
    ComponentType.RAG_SOURCE: "dataset_Dataset",
    ComponentType.DATA_SOURCE: "dataset_Dataset",
    ComponentType.REGISTRY_ENTRY: "software_Package",
    ComponentType.SKILL_PACKAGE: "software_Package",
}


class SPDXGenerator(Generator):
    format_name = "spdx-3.0"

    def __init__(self, namespace: str = "https://spdx.org/spdxdocs/symbote") -> None:
        self._namespace = namespace

    def generate(self, aibom: AIBOM) -> dict[str, Any]:
        aibom.finalize()
        doc_id = f"urn:spdx:document:{uuid.uuid4()}"

        elements: list[dict[str, Any]] = []
        for comp in aibom.components:
            elements.append(self._element(comp))
        for dep in aibom.dependencies:
            elements.append(self._relationship(dep))

        return {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [
                {
                    "type": "SpdxDocument",
                    "spdxId": doc_id,
                    "name": f"symbote-aibom-{aibom.metadata.serial_number or 'unknown'}",
                    "specVersion": "3.0.1",
                    "creationInfo": self._creation_info(aibom),
                    "element": [e["spdxId"] for e in elements],
                    "rootElement": [
                        e["spdxId"]
                        for e in elements
                        if e.get("type") in ("ai_AIPackage", "software_Package")
                    ][:1],
                },
                *elements,
            ],
        }

    def _creation_info(self, aibom: AIBOM) -> dict[str, Any]:
        return {
            "specVersion": "3.0.1",
            "created": (
                aibom.metadata.timestamp.isoformat()
                if aibom.metadata.timestamp
                else "1970-01-01T00:00:00Z"
            ),
            "createdBy": [f"urn:spdx:agent:{aibom.metadata.tool_name}"],
            "createdUsing": [
                f"urn:spdx:tool:{aibom.metadata.tool_name}-{aibom.metadata.tool_version or 'unknown'}"
            ],
        }

    def _element(self, comp: AnyComponent) -> dict[str, Any]:
        spdx_type = SPDX_TYPE_MAP.get(comp.component_type, "software_Package")
        spdx_id = f"urn:spdx:{comp.bom_ref.replace(':', '-')}"

        element: dict[str, Any] = {
            "type": spdx_type,
            "spdxId": spdx_id,
            "name": comp.name,
        }
        if comp.version:
            element["packageVersion"] = comp.version
        if comp.supplier:
            element["suppliedBy"] = f"urn:spdx:agent:{comp.supplier}"
        if comp.description:
            element["description"] = comp.description
        if comp.hashes:
            element["verifiedUsing"] = [
                {
                    "type": "Hash",
                    "algorithm": alg,
                    "hashValue": val.split(":", 1)[-1] if ":" in val else val,
                }
                for alg, val in comp.hashes.items()
                if val
            ]

        ext = self._extensions(comp)
        if ext:
            element["extension"] = ext
        return element

    def _extensions(self, comp: AnyComponent) -> list[dict[str, Any]]:
        props: dict[str, Any] = {
            "symbote:componentType": comp.component_type.value,
            "symbote:trustTier": comp.trust_tier.value,
            "symbote:assuranceLevel": comp.assurance_level.value,
        }

        if isinstance(comp, AgentComponent):
            props["symbote:autonomyLevel"] = comp.autonomy_level.value
            if comp.framework:
                props["symbote:framework"] = comp.framework
        elif isinstance(comp, ModelComponent):
            if comp.serialization_format:
                props["symbote:serializationFormat"] = comp.serialization_format
            if comp.signing_status:
                props["symbote:signingStatus"] = comp.signing_status
        elif isinstance(comp, ToolComponent):
            if comp.definition_hash:
                props["symbote:definitionHash"] = comp.definition_hash
        elif isinstance(comp, RAGSourceComponent):
            if comp.corpus_type:
                props["symbote:corpusType"] = comp.corpus_type

        return [
            {
                "type": "Extension",
                "specVersion": "symbote-1.0.0",
                "properties": props,
            }
        ]

    def _relationship(self, edge: DependencyEdge) -> dict[str, Any]:
        rel_map = {
            "invokes": "DEPENDS_ON",
            "delegates-to": "DEPENDS_ON",
            "retrieves-from": "DEPENDS_ON",
            "trained-on": "TRAINED_ON",
            "fine-tuned-from": "DERIVED_FROM",
            "quantized-from": "DERIVED_FROM",
            "merged-from": "DERIVED_FROM",
            "depends-on": "DEPENDS_ON",
        }
        return {
            "type": "Relationship",
            "spdxId": f"urn:spdx:rel:{uuid.uuid4()}",
            "relationshipType": rel_map.get(edge.relationship, "OTHER"),
            "from": f"urn:spdx:{edge.source_ref.replace(':', '-')}",
            "to": [f"urn:spdx:{edge.target_ref.replace(':', '-')}"],
            "extension": [
                {
                    "type": "Extension",
                    "specVersion": "symbote-1.0.0",
                    "properties": {"symbote:relationship": edge.relationship},
                }
            ],
        }
