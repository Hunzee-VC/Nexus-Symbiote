"""Validated SPDX 3.0.1 projection with a digest-bound native document extension."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
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
    coverage_aggregate,
    document_properties,
    json_text,
    native_document,
    normalize_hash,
    prepare,
    recover_document,
    unordered_projection,
)
from nexus_symbiote.generators.base import Generator
from nexus_symbiote.generators.package_identifiers import (
    package_identifier,
    package_identifier_properties,
)
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
MAX_CONDITION_COMMENT = 1024
COVERAGE_COMMENTS = {
    "incomplete": (
        "Collection coverage is incomplete: collectors were scoped or failed, surfaces "
        "were excluded, or discovery was imported. This document does not assert "
        "complete collection."
    ),
    "unknown": (
        "Collection coverage is unknown: static collection does not observe runtime, "
        "network or live tool surfaces. This document does not assert complete collection."
    ),
}


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


@dataclass(frozen=True)
class _DocumentIds:
    document: str

    @property
    def creation(self) -> str:
        return self.document + "#creation"

    def element(self, kind: str, key: str) -> str:
        return f"{self.document}#{kind}-{uuid.uuid5(NAMESPACE, key)}"


class SPDXGenerator(Generator):
    format_name = "spdx-3.0.1"

    def __init__(self, namespace: str = "https://spdx.org/spdxdocs/nexus_symbiote") -> None:
        self._namespace = namespace.rstrip("/")

    def generate(self, aibom: AIBOM) -> dict[str, Any]:
        document = self._projection(aibom)
        require_valid(document, "spdx")
        return document

    def _projection(self, aibom: AIBOM) -> dict[str, Any]:
        prepare(aibom)
        # Native refs are BOM-local, and producers can reuse serial numbers across revisions.
        revision = content_digest(native_document(aibom)).removeprefix("sha256:")
        ids = _DocumentIds(f"{self._namespace}/document/{revision}")
        ci = ids.creation
        producer_id = ids.element("producer", aibom.metadata.tool_name)
        tool_id = ids.element("generator", aibom.metadata.tool_name)
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
                "spdxId": ids.element("supplier", name),
                "creationInfo": ci,
                "name": name,
            }
            for name in sorted(suppliers)
        ]
        components = [
            self._element(comp, ids) for comp in sorted(aibom.components, key=lambda c: c.bom_ref)
        ]
        edge_values = {
            json_text(edge.model_dump(mode="json", exclude_none=True)): edge
            for edge in aibom.dependencies
        }
        coverage = coverage_aggregate(aibom.metadata.completeness)
        relationships = [
            self._relationship(
                edge_values[key], ids, "incomplete" if coverage == "incomplete" else "noAssertion"
            )
            for key in sorted(edge_values)
        ]
        license_relationships = [
            {
                "type": "Relationship",
                "spdxId": ids.element("license-relationship", component["spdxId"] + ":" + kind),
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
            "spdxId": ids.document,
            "creationInfo": ci,
            "name": "Nexus SymBiote AgentBOM " + str(aibom.metadata.serial_number),
            "element": [element["spdxId"] for element in elements],
            "rootElement": [
                ids.element("component", comp.bom_ref)
                for comp in sorted(aibom.components, key=lambda c: c.bom_ref)
                if comp.component_type == ComponentType.AGENT
            ],
            # The inventory does not collect all AI/Dataset-profile conformance evidence.
            "profileConformance": ["core", "software", "extension"],
            "comment": COVERAGE_COMMENTS[coverage],
            "extension": _extension(document_properties(aibom, self.format_name)),
        }
        return {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [doc, *elements, creation],
        }

    @staticmethod
    def _element(comp: AnyComponent, ids: _DocumentIds) -> dict[str, Any]:
        typ = SPDX_TYPE_MAP.get(comp.component_type, "software_Package")
        element: dict[str, Any] = {
            "type": typ,
            "spdxId": ids.element("component", comp.bom_ref),
            "creationInfo": ids.creation,
            "name": comp.name,
            "extension": _extension(
                [
                    component_property(comp),
                    *claim_properties(comp),
                    *package_identifier_properties(comp),
                ]
            ),
        }
        package = package_identifier(comp)
        if package.value is not None:
            element["externalIdentifier"] = [
                {
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "packageUrl",
                    "identifier": package.value,
                    "comment": "Declared package identity; not authenticated by the exporter.",
                }
            ]
            if typ != "software_File":
                element["software_packageUrl"] = package.value
        if typ != "software_File" and (package.version or comp.version):
            element["software_packageVersion"] = package.version or comp.version
        if comp.supplier:
            element["suppliedBy"] = ids.element("supplier", comp.supplier)
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

    @staticmethod
    def _relationship(edge: DependencyEdge, ids: _DocumentIds, completeness: str) -> dict[str, Any]:
        mapping = {
            "invokes": "usesTool",
            "trained-on": "trainedOn",
            "depends-on": "dependsOn",
            "fine-tuned-from": "descendantOf",
            "quantized-from": "descendantOf",
            "merged-from": "descendantOf",
        }
        body = edge.model_dump(mode="json", exclude_none=True)
        typed = mapping.get(edge.relationship)
        relationship = {
            "type": "Relationship",
            "spdxId": ids.element("relationship", content_digest(body)),
            "creationInfo": ids.creation,
            # A typed SPDX relationship is unconditional; standard-only consumers
            # never see the native condition, so match the CycloneDX graph rule.
            "relationshipType": "other" if edge.conditions or typed is None else typed,
            "from": ids.element("component", edge.source_ref),
            "to": [ids.element("component", edge.target_ref)],
            "completeness": completeness,
            "extension": _extension(
                [{"name": "nexus-symbiote:relationship", "value": json_text(body)}]
            ),
        }
        if edge.conditions:
            conditions = edge.conditions
            if len(conditions) > MAX_CONDITION_COMMENT:
                conditions = conditions[:MAX_CONDITION_COMMENT] + " [truncated]"
            relationship["comment"] = (
                f"Conditional native relationship '{edge.relationship}' (conditions: "
                f"{conditions}). Not an unconditional {typed or 'relationship'} assertion."
            )
        return relationship

    @staticmethod
    def recover(document: dict[str, Any]) -> AIBOM:
        require_valid(document, "spdx")
        docs = [node for node in document["@graph"] if node["type"] == "SpdxDocument"]
        if len(docs) != 1:
            raise ValueError("expected exactly one SPDX document")
        doc = docs[0]
        namespace, separator, _revision = doc["spdxId"].rpartition("/document/")
        if not namespace or not separator:
            raise ValueError("unrecognized SPDX export document identifier")
        properties = [
            {"name": prop["extension_cdxPropName"], "value": prop.get("extension_cdxPropValue", "")}
            for extension in doc.get("extension", [])
            if isinstance(extension, dict)
            and extension.get("type") == "extension_CdxPropertiesExtension"
            for prop in extension.get("extension_cdxProperty", [])
            if isinstance(prop, dict) and "extension_cdxPropName" in prop
        ]
        recovered = recover_document(properties)
        expected = SPDXGenerator(namespace)._projection(recovered)
        # A conforming JSON-LD consumer can omit an empty root element set.
        actual = {
            **document,
            "@graph": [
                {**node, "rootElement": node.get("rootElement", [])} if node is doc else node
                for node in document["@graph"]
            ],
        }
        if unordered_projection(actual) != unordered_projection(expected):
            raise ValueError("SPDX projection conflicts with the embedded native document")
        return recovered
