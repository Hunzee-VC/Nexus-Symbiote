"""Project AgentBOM components and qualified edges into SPDX 3.0.1 JSON-LD."""

from __future__ import annotations

from datetime import UTC
from typing import Any
from urllib.parse import quote

from symbiote.core.aibom import AIBOM
from symbiote.core.enums import ComponentType
from symbiote.generators.base import Generator, validate_references, wire_hashes
from symbiote.generators.cyclonedx import CycloneDXGenerator

SPDX_TYPE_MAP = {
    ComponentType.AGENT: "ai_AIPackage",
    ComponentType.MODEL: "ai_AIPackage",
    ComponentType.PROMPT_TEMPLATE: "software_File",
    ComponentType.MEMORY_STORE: "dataset_DatasetPackage",
    ComponentType.RAG_SOURCE: "dataset_DatasetPackage",
    ComponentType.DATA_SOURCE: "dataset_DatasetPackage",
}
RELATIONSHIP_TYPES = {
    "invokes": "usesTool",
    "depends-on": "dependsOn",
    "retrieves-from": "dependsOn",
    "trained-on": "trainedOn",
    "fine-tuned-from": "descendantOf",
    "quantized-from": "descendantOf",
    "merged-from": "descendantOf",
}

# Standard SPDX individual indicating that no license determination is made.
NO_ASSERTION_LICENSE = "https://spdx.org/rdf/3.0.1/terms/Licensing/NoAssertion"


def _properties_extension(props: list[dict[str, str]]) -> list[dict[str, Any]]:
    return [
        {
            "type": "extension_CdxPropertiesExtension",
            "extension_cdxProperty": [
                {
                    "type": "extension_CdxPropertyEntry",
                    "extension_cdxPropName": prop["name"],
                    "extension_cdxPropValue": prop["value"],
                }
                for prop in props
            ],
        }
    ]


class SPDXGenerator(Generator):
    format_name = "spdx-3.0"

    def __init__(self, namespace: str = "https://spdx.org/spdxdocs/symbiote") -> None:
        self._namespace = namespace.rstrip("/")

    def generate(self, aibom: AIBOM) -> dict[str, Any]:
        aibom.finalize()
        validate_references(aibom)
        meta = aibom.metadata
        if meta.serial_number is None or meta.timestamp is None:
            raise ValueError("SPDX export requires a serial number and timestamp")
        base = f"{self._namespace}/{quote(meta.serial_number, safe='')}/{meta.version}/"
        producer_id = base + "producer"
        creation: dict[str, Any] = {
            "@id": "_:creation",
            "type": "CreationInfo",
            "specVersion": "3.0.1",
            "created": meta.timestamp.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "createdBy": [producer_id],
        }
        elements: list[dict[str, Any]] = [
            {"type": "SoftwareAgent", "spdxId": producer_id, "name": meta.tool_name}
        ]
        suppliers = {
            name: base + "supplier/" + quote(name, safe="")
            for name in sorted({c.supplier for c in aibom.components if c.supplier})
        }
        for name, identifier in suppliers.items():
            elements.append({"type": "Organization", "spdxId": identifier, "name": name})

        ids = {c.bom_ref: base + "component/" + quote(c.bom_ref, safe="") for c in aibom.components}
        for comp in aibom.components:
            spdx_type = SPDX_TYPE_MAP.get(comp.component_type, "software_Package")
            props = CycloneDXGenerator.component_properties(comp)
            element: dict[str, Any] = {
                "type": spdx_type,
                "spdxId": ids[comp.bom_ref],
                "name": comp.name,
            }
            if spdx_type == "dataset_DatasetPackage":
                element["dataset_datasetType"] = ["noAssertion"]
            if comp.version:
                if spdx_type == "software_File":
                    props.append({"name": "symbiote:version", "value": comp.version})
                else:
                    element["software_packageVersion"] = comp.version
            if comp.supplier:
                element["suppliedBy"] = suppliers[comp.supplier]
            if comp.description:
                element["description"] = comp.description
            if comp.hashes:
                element["verifiedUsing"] = [
                    {"type": "Hash", "algorithm": alg, "hashValue": digest}
                    for alg, digest in wire_hashes(comp.hashes, spdx=True)
                ]
            element["extension"] = _properties_extension(props)
            elements.append(element)

            # AI and Dataset profiles require exactly one declared and one
            # concluded license relationship for each package. NoAssertion is
            # deliberate: discovery does not determine licensing terms.
            if spdx_type in ("ai_AIPackage", "dataset_DatasetPackage"):
                for relationship in ("hasDeclaredLicense", "hasConcludedLicense"):
                    elements.append(
                        {
                            "type": "Relationship",
                            "spdxId": base
                            + "license/"
                            + quote(comp.bom_ref, safe="")
                            + "/"
                            + relationship,
                            "relationshipType": relationship,
                            "from": ids[comp.bom_ref],
                            "to": [NO_ASSERTION_LICENSE],
                        }
                    )

        for index, edge in enumerate(aibom.dependencies):
            elements.append(
                {
                    "type": "Relationship",
                    "spdxId": base + f"relationship/{index}",
                    "relationshipType": RELATIONSHIP_TYPES.get(edge.relationship, "other"),
                    "from": ids[edge.source_ref],
                    "to": [ids[edge.target_ref]],
                    "extension": _properties_extension(
                        [
                            {
                                "name": "symbiote:relationship",
                                "value": edge.model_dump_json(exclude_none=True),
                            }
                        ]
                    ),
                }
            )
        for element in elements:
            element["creationInfo"] = creation["@id"]
        document = {
            "type": "SpdxDocument",
            "spdxId": base + "document",
            "creationInfo": creation["@id"],
            "name": f"symbiote-aibom-{meta.serial_number}",
            "profileConformance": [
                "core",
                "software",
                "ai",
                "dataset",
                "extension",
                "simpleLicensing",
                "expandedLicensing",
            ],
            "element": [element["spdxId"] for element in elements],
            "rootElement": [
                ids[c.bom_ref] for c in aibom.components if c.component_type == ComponentType.AGENT
            ],
        }
        return {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [document, creation, *elements],
        }
