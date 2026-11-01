"""SPDX 3.0 output generator.

Maps AgentBOM components to SPDX 3.0 JSON-LD, using the AI and dataset
profiles alongside agent-specific extensions under the nexus-symbiote namespace.
"""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import quote

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.models import (
    AgentComponent,
    AnyComponent,
    ModelComponent,
    RAGSourceComponent,
    ToolComponent,
)
from nexus_symbiote.generators.base import Generator

# Every ComponentType has an SPDX 3.0 class. Types with no dedicated class are software packages.
SPDX_TYPE_MAP: dict[ComponentType, str] = {
    ComponentType.AGENT: "ai_AIPackage",
    ComponentType.MODEL: "ai_AIPackage",
    ComponentType.TOOL: "software_Package",
    ComponentType.MCP_SERVER: "software_Package",
    ComponentType.MCP_CLIENT: "software_Package",
    ComponentType.PROMPT_TEMPLATE: "software_Snippet",
    ComponentType.GUARDRAIL_POLICY: "software_Package",
    ComponentType.MEMORY_STORE: "dataset_Dataset",
    ComponentType.RAG_SOURCE: "dataset_Dataset",
    ComponentType.DATA_SOURCE: "dataset_Dataset",
    ComponentType.REGISTRY_ENTRY: "software_Package",
    ComponentType.SKILL_PACKAGE: "software_Package",
    ComponentType.A2A_CLIENT: "software_Package",
    ComponentType.A2A_SERVER: "software_Package",
    ComponentType.IDE_AGENT: "software_Package",
    ComponentType.VERIFIED_EXTENSION: "software_Package",
}

# SPDX 3.0 RelationshipType values. Edge types not listed here become "other". The original
# type is kept in the nexus-symbiote:relationship property.
SPDX_RELATIONSHIP_MAP: dict[str, str] = {
    "depends-on": "dependsOn",
    "invokes": "dependsOn",
    "delegates-to": "dependsOn",
    "retrieves-from": "dependsOn",
    "trained-on": "trainedOn",
    "fine-tuned-from": "derivedFrom",
    "quantized-from": "derivedFrom",
    "merged-from": "derivedFrom",
}

_SPEC_VERSION = "3.0.1"
_CREATION_INFO_ID = "_:creationinfo"
_PROFILES = ("core", "software", "ai", "dataset")


def _component_iri(bom_ref: str) -> str:
    # Quoting encodes every colon, so these IRIs never match the prefixed IRIs below.
    return "urn:spdx:" + quote(bom_ref, safe="")


def _agent_iri(name: str) -> str:
    return "urn:spdx:agent:" + quote(name, safe="")


def _tool_iri(label: str) -> str:
    return "urn:spdx:tool:" + quote(label, safe="")


def _org_iri(name: str) -> str:
    return "urn:spdx:org:" + quote(name, safe="")


class SPDXGenerator(Generator):
    format_name = "spdx-3.0"

    def __init__(self, namespace: str = "https://spdx.org/spdxdocs/nexus-symbiote") -> None:
        self._namespace = namespace

    def generate(self, aibom: AIBOM) -> dict[str, Any]:
        aibom.finalize()
        timestamp = aibom.metadata.timestamp
        serial = aibom.metadata.serial_number
        if timestamp is None or serial is None:
            raise ValueError("finalize() did not set the AIBOM timestamp and serial number")

        tool_name = aibom.metadata.tool_name
        tool_label = f"{tool_name}-{aibom.metadata.tool_version or 'unknown'}"
        agent_id = _agent_iri(tool_name)
        tool_id = _tool_iri(tool_label)
        creation_info: dict[str, Any] = {
            "type": "CreationInfo",
            "@id": _CREATION_INFO_ID,
            "specVersion": _SPEC_VERSION,
            "created": timestamp.isoformat(),
            "createdBy": [agent_id],
            "createdUsing": [tool_id],
        }

        nodes: list[dict[str, Any]] = [
            {"type": "SoftwareAgent", "spdxId": agent_id, "name": tool_name},
            {"type": "Tool", "spdxId": tool_id, "name": tool_label},
        ]
        suppliers = sorted({c.supplier for c in aibom.components if c.supplier})
        nodes.extend(
            {"type": "Organization", "spdxId": _org_iri(name), "name": name} for name in suppliers
        )
        nodes.extend(self._element(c) for c in aibom.components)

        refs = {c.bom_ref for c in aibom.components}
        seen: set[tuple[str, str, str]] = set()
        for edge in aibom.dependencies:
            key = (edge.source_ref, edge.relationship, edge.target_ref)
            if edge.source_ref not in refs or edge.target_ref not in refs or key in seen:
                continue
            seen.add(key)
            nodes.append(self._relationship(edge))

        for node in nodes:
            node["creationInfo"] = _CREATION_INFO_ID

        root = next(
            (c for c in aibom.components if c.component_type == ComponentType.AGENT),
            aibom.components[0] if aibom.components else None,
        )
        document: dict[str, Any] = {
            "type": "SpdxDocument",
            "spdxId": f"urn:spdx:document:{uuid.uuid5(uuid.NAMESPACE_URL, serial)}",
            "name": f"nexus-symbiote-aibom-{serial}",
            "specVersion": _SPEC_VERSION,
            "creationInfo": _CREATION_INFO_ID,
            "profileConformance": list(_PROFILES),
            "element": [node["spdxId"] for node in nodes],
            "rootElement": [_component_iri(root.bom_ref)] if root is not None else [],
        }

        return {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [document, creation_info, *nodes],
        }

    def _element(self, comp: AnyComponent) -> dict[str, Any]:
        spdx_type = SPDX_TYPE_MAP.get(comp.component_type, "software_Package")

        element: dict[str, Any] = {
            "type": spdx_type,
            "spdxId": _component_iri(comp.bom_ref),
            "name": comp.name,
        }
        if comp.version:
            element["packageVersion"] = comp.version
        if comp.supplier:
            element["suppliedBy"] = _org_iri(comp.supplier)
        if comp.description:
            element["description"] = comp.description
        if comp.hashes:
            element["verifiedUsing"] = [
                {
                    "type": "Hash",
                    "algorithm": alg.lower(),
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
            "nexus-symbiote:componentType": comp.component_type.value,
            "nexus-symbiote:trustTier": comp.trust_tier.value,
            "nexus-symbiote:assuranceLevel": comp.assurance_level.value,
        }

        if isinstance(comp, AgentComponent):
            props["nexus-symbiote:autonomyLevel"] = comp.autonomy_level.value
            if comp.framework:
                props["nexus-symbiote:framework"] = comp.framework
        elif isinstance(comp, ModelComponent):
            if comp.serialization_format:
                props["nexus-symbiote:serializationFormat"] = comp.serialization_format
            if comp.signing_status:
                props["nexus-symbiote:signingStatus"] = comp.signing_status
        elif isinstance(comp, ToolComponent):
            if comp.definition_hash:
                props["nexus-symbiote:definitionHash"] = comp.definition_hash
        elif isinstance(comp, RAGSourceComponent):
            if comp.corpus_type:
                props["nexus-symbiote:corpusType"] = comp.corpus_type

        return [
            {
                "type": "Extension",
                "specVersion": "nexus-symbiote-1.0.0",
                "properties": props,
            }
        ]

    def _relationship(self, edge: DependencyEdge) -> dict[str, Any]:
        # Deterministic: the same edge always gets the same id, and no random ids are used.
        key = f"{edge.source_ref}|{edge.relationship}|{edge.target_ref}"
        return {
            "type": "Relationship",
            "spdxId": f"urn:spdx:rel:{uuid.uuid5(uuid.NAMESPACE_URL, key)}",
            "relationshipType": SPDX_RELATIONSHIP_MAP.get(edge.relationship, "other"),
            "from": _component_iri(edge.source_ref),
            "to": [_component_iri(edge.target_ref)],
            "extension": [
                {
                    "type": "Extension",
                    "specVersion": "nexus-symbiote-1.0.0",
                    "properties": {"nexus-symbiote:relationship": edge.relationship},
                }
            ],
        }
