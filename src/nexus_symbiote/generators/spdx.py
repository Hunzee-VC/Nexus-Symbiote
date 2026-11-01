"""Validated SPDX 3.0.1 projection with a digest-bound native document extension."""

from __future__ import annotations

import uuid
from datetime import UTC
from typing import Any

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.models import AnyComponent, ModelComponent
from nexus_symbiote.generators._common import (
    NAMESPACE,
    claim_properties,
    component_property,
    content_digest,
    document_properties,
    json_text,
    normalize_hash,
    prepare,
    recover_document,
)
from nexus_symbiote.generators.base import Generator
from nexus_symbiote.generators.validation import require_valid

SPDX_TYPE_MAP = {
    ComponentType.AGENT: "ai_AIPackage",
    ComponentType.MODEL: "ai_AIPackage",
    ComponentType.PROMPT_TEMPLATE: "software_File",
    ComponentType.MEMORY_STORE: "dataset_DatasetPackage",
    ComponentType.RAG_SOURCE: "dataset_DatasetPackage",
    ComponentType.DATA_SOURCE: "dataset_DatasetPackage",
}


NO_ASSERTION_LICENSE = "https://spdx.org/rdf/3.0.1/terms/Licensing/NoAssertion"


def _extension(properties: list[dict[str, str]]) -> list[dict[str, Any]]:
    return [
        {
            "type": "extension_CdxPropertiesExtension",
            "extension_cdxProperty": [
                {
                    "type": "extension_CdxPropertyEntry",
                    "extension_cdxPropName": prop["name"],
                    "extension_cdxPropValue": prop["value"],
                }
                for prop in properties
            ],
        }
    ]


class SPDXGenerator(Generator):
    format_name = "spdx-3.0.1"

    def __init__(self, namespace: str = "https://spdx.org/spdxdocs/nexus_symbiote") -> None:
        self._namespace = namespace.rstrip("/")

    def _id(self, kind: str, key: str) -> str:
        return self._namespace + "/" + kind + "/" + str(uuid.uuid5(NAMESPACE, kind + ":" + key))

    def generate(self, aibom: AIBOM) -> dict[str, Any]:
        prepare(aibom)
        ci = "_:creation"
        producer_id = self._id("producer", aibom.metadata.tool_name)
        tool_id = self._id("generator", aibom.metadata.tool_name)
        creator = {
            "type": "SoftwareAgent",
            "spdxId": producer_id,
            "creationInfo": ci,
            "name": aibom.metadata.tool_name,
        }
        generator = {
            "type": "Tool",
            "spdxId": tool_id,
            "creationInfo": ci,
            "name": aibom.metadata.tool_name,
            "summary": aibom.metadata.tool_version,
        }
        assert aibom.metadata.timestamp is not None
        creation = {
            "type": "CreationInfo",
            "@id": ci,
            "specVersion": "3.0.1",
            "created": aibom.metadata.timestamp.astimezone(UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "createdBy": [producer_id],
            "createdUsing": [tool_id],
        }
        suppliers = {comp.supplier for comp in aibom.components if comp.supplier}
        parties = [
            {
                "type": "Organization",
                "spdxId": self._id("supplier", name),
                "creationInfo": ci,
                "name": name,
            }
            for name in sorted(suppliers)
        ]
        components = [
            self._element(comp) for comp in sorted(aibom.components, key=lambda c: c.bom_ref)
        ]
        edge_values = {
            json_text(edge.model_dump(mode="json", exclude_none=True)): edge
            for edge in aibom.dependencies
        }
        relationships = [self._relationship(edge_values[key]) for key in sorted(edge_values)]
        license_relationships = [
            {
                "type": "Relationship",
                "spdxId": self._id("license-relationship", component["spdxId"] + ":" + kind),
                "creationInfo": ci,
                "relationshipType": kind,
                "from": component["spdxId"],
                "to": [NO_ASSERTION_LICENSE],
            }
            for component in components
            if component["type"] in {"ai_AIPackage", "dataset_DatasetPackage"}
            for kind in ("hasDeclaredLicense", "hasConcludedLicense")
        ]
        elements: list[dict[str, Any]] = [
            creator,
            generator,
            *parties,
            *components,
            *relationships,
            *license_relationships,
        ]
        doc = {
            "type": "SpdxDocument",
            "spdxId": self._id("document", str(aibom.metadata.serial_number)),
            "creationInfo": ci,
            "name": "Nexus SymBiote AgentBOM " + str(aibom.metadata.serial_number),
            "element": [element["spdxId"] for element in elements],
            "rootElement": [
                self._id("component", comp.bom_ref)
                for comp in sorted(aibom.components, key=lambda c: c.bom_ref)
                if comp.component_type == ComponentType.AGENT
            ],
            # The inventory does not collect all AI/Dataset-profile conformance evidence.
            "profileConformance": ["core", "software", "extension"],
            "extension": _extension(document_properties(aibom, self.format_name)),
        }
        result = {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [doc, *elements, creation],
        }
        require_valid(result, "spdx")
        return result

    def _element(self, comp: AnyComponent) -> dict[str, Any]:
        typ = SPDX_TYPE_MAP.get(comp.component_type, "software_Package")
        element: dict[str, Any] = {
            "type": typ,
            "spdxId": self._id("component", comp.bom_ref),
            "creationInfo": "_:creation",
            "name": comp.name,
            "extension": _extension([component_property(comp), *claim_properties(comp)]),
        }
        if comp.version and typ != "software_File":
            element["software_packageVersion"] = comp.version
        if comp.supplier:
            element["suppliedBy"] = self._id("supplier", comp.supplier)
        if comp.description:
            element["description"] = comp.description
        if typ != "software_File":
            element["software_downloadLocation"] = "NOASSERTION"
        if typ == "ai_AIPackage":
            element.update(
                {
                    "software_primaryPurpose": "model"
                    if isinstance(comp, ModelComponent)
                    else "application",
                    "ai_autonomyType": "noAssertion",
                    "ai_informationAboutTraining": "Not supplied by the inventory producer.",
                    "ai_informationAboutApplication": comp.description
                    or "Not supplied by the inventory producer.",
                    "ai_limitation": "Inventory assertions do not establish model safety or authorization.",
                    "ai_useSensitivePersonalInformation": "noAssertion",
                }
            )
            if isinstance(comp, ModelComponent) and comp.model_type:
                element["ai_typeOfModel"] = [comp.model_type]
        elif typ == "dataset_DatasetPackage":
            element.update(
                {
                    "software_primaryPurpose": "data",
                    "dataset_datasetType": ["noAssertion"],
                    "dataset_hasSensitivePersonalInformation": "noAssertion",
                    "dataset_dataCollectionProcess": "Not supplied by the inventory producer.",
                    "dataset_intendedUse": "Not supplied by the inventory producer.",
                }
            )
        elif comp.component_type in {
            ComponentType.MCP_CLIENT,
            ComponentType.MCP_SERVER,
            ComponentType.A2A_CLIENT,
            ComponentType.A2A_SERVER,
            ComponentType.IDE_AGENT,
        }:
            element["software_primaryPurpose"] = "application"
        elif comp.component_type == ComponentType.VERIFIED_EXTENSION:
            element["software_primaryPurpose"] = "library"
        if comp.hashes:
            hashes = []
            for algorithm, value in sorted(comp.hashes.items()):
                name, digest = normalize_hash(algorithm, value)
                spdx_algorithm = (
                    name.lower().replace("-", "_")
                    if name.startswith("SHA3-")
                    else name.lower().replace("-", "")
                )
                hashes.append({"type": "Hash", "algorithm": spdx_algorithm, "hashValue": digest})
            element["verifiedUsing"] = hashes
        return element

    def _relationship(self, edge: DependencyEdge) -> dict[str, Any]:
        mapping = {
            "invokes": "usesTool",
            "trained-on": "trainedOn",
            "depends-on": "dependsOn",
            "fine-tuned-from": "descendantOf",
            "quantized-from": "descendantOf",
            "merged-from": "descendantOf",
        }
        body = edge.model_dump(mode="json", exclude_none=True)
        return {
            "type": "Relationship",
            "spdxId": self._id("relationship", content_digest(body)),
            "creationInfo": "_:creation",
            "relationshipType": mapping.get(edge.relationship, "other"),
            "from": self._id("component", edge.source_ref),
            "to": [self._id("component", edge.target_ref)],
            "extension": _extension(
                [{"name": "nexus-symbiote:relationship", "value": json_text(body)}]
            ),
        }

    @staticmethod
    def recover(document: dict[str, Any]) -> AIBOM:
        require_valid(document, "spdx")
        docs = [node for node in document["@graph"] if node["type"] == "SpdxDocument"]
        if len(docs) != 1:
            raise ValueError("expected exactly one SPDX document")
        entries = docs[0]["extension"][0]["extension_cdxProperty"]
        return recover_document(
            [
                {"name": prop["extension_cdxPropName"], "value": prop["extension_cdxPropValue"]}
                for prop in entries
            ]
        )
