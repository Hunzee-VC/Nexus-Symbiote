"""Validated SPDX 3.0.1 projection with a digest-bound native document extension.

Profile conformance lists core, software and extension, plus expandedLicensing when
the document references SPDX's NoAssertionLicense individual. Models, agents and
data use the AI and Dataset classes, but the AI and Dataset profiles also require
properties an inventory does not collect (supplier, release time, version and
download location), so those profiles are not claimed. Unknown optional fields are
omitted rather than filled with placeholders.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote, urlsplit

from referencing.exceptions import Unresolvable

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge, native_document, prepare
from nexus_symbiote.core.canonical import NAMESPACE, content_digest, json_text
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.models import AgentComponent, AnyComponent, ModelComponent
from nexus_symbiote.generators import _legacy
from nexus_symbiote.generators._common import (
    PROJECTION_PROPERTY,
    claim_properties,
    component_property,
    coverage_aggregate,
    declared_projection,
    document_properties,
    native_components,
    recover_native,
    repository_scan,
    repository_subject,
    standard_hashes,
    standard_version,
    unordered_projection,
)
from nexus_symbiote.generators.base import Generator
from nexus_symbiote.generators.package_identifiers import (
    package_identifier,
    package_identifier_properties,
)
from nexus_symbiote.generators.validation import (
    _IRI_EXCLUDED,
    SPDX_COLLECTIONS,
    require_valid,
    spdx_errors,
)

PROJECTION = "spdx-3.0.1/2"
SPDX_TYPE_MAP = {
    ComponentType.AGENT: "ai_AIPackage",
    ComponentType.MODEL: "ai_AIPackage",
    ComponentType.PROMPT_TEMPLATE: "software_File",
    ComponentType.MEMORY_STORE: "dataset_DatasetPackage",
    ComponentType.RAG_SOURCE: "dataset_DatasetPackage",
    ComponentType.DATA_SOURCE: "dataset_DatasetPackage",
}


# SPDX 3.0.1 defines this named individual for "no assertion" about a license.
NO_ASSERTION_LICENSE = "expandedlicensing_NoAssertionLicense"
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
_NAMESPACE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[^\s#?<>\"{}|\\^`]+")
_DEFAULT_DOCUMENT = re.compile(
    r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


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


def _validated_namespace(namespace: str) -> str:
    value = namespace.rstrip("/")
    invalid = "SPDX namespace must be an absolute IRI without a query or fragment"
    if len(value) > 2048 or _NAMESPACE.fullmatch(value) is None or _IRI_EXCLUDED.search(value):
        raise ValueError(invalid)
    # "spdx.org.", "spdx%2Eorg" and IDNA spellings such as "spdx\u3002org" name the
    # same host as "spdx.org".
    host = unquote(urlsplit(value).hostname or "")
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError(invalid) from exc
    host = host.lower().rstrip(".")
    if host == "spdx.org" or host.endswith(".spdx.org"):
        raise ValueError("SPDX namespace must be one the document creator controls")
    return value


def _document_namespace(spdx_id: str) -> str | None:
    """The namespace an export was written with, or None for the default identifier."""
    namespace, separator, revision = spdx_id.rpartition("/document/")
    if namespace and separator and revision:
        return namespace
    if _DEFAULT_DOCUMENT.fullmatch(spdx_id):
        return None
    raise ValueError("unrecognized SPDX export document identifier")


def _without_created(value: Any) -> Any:
    """Recursively drop ``created`` from SPDX ``CreationInfo`` elements only.

    When the embedded native document has no timestamp, ``CreationInfo.created``
    is render-time metadata, so it is the one value allowed to differ between an
    export and its recovery. A ``created`` key on any other element is content.
    """
    if isinstance(value, dict):
        creation_info = value.get("type") == "CreationInfo"
        return {
            key: _without_created(item)
            for key, item in value.items()
            if not (creation_info and key == "created")
        }
    if isinstance(value, list):
        return [_without_created(item) for item in value]
    return value


@dataclass(frozen=True)
class _DocumentIds:
    document: str

    @property
    def creation(self) -> str:
        return self.document + "#creation"

    def element(self, kind: str, key: str) -> str:
        return f"{self.document}#{kind}-{uuid.uuid5(NAMESPACE, key)}"


class SPDXGenerator(Generator):
    """SPDX 3.0.1 JSON-LD export.

    Element identifiers are scoped to one inventory revision. Pass ``namespace``, an
    absolute IRI the operator controls, to mint them under ``<namespace>/document/``;
    by default the document identifier is a ``urn:uuid`` derived from the revision.
    """

    format_name = "spdx-3.0.1"

    def __init__(self, namespace: str | None = None) -> None:
        self._namespace = None if namespace is None else _validated_namespace(namespace)

    def generate(self, aibom: AIBOM) -> dict[str, Any]:
        document = self._projection(aibom)
        require_valid(document, "spdx")
        return document

    def _ids(self, revision: str) -> _DocumentIds:
        if self._namespace is None:
            return _DocumentIds(
                "urn:uuid:" + str(uuid.uuid5(NAMESPACE, "spdx-document:" + revision))
            )
        return _DocumentIds(f"{self._namespace}/document/{revision}")

    def _projection(self, aibom: AIBOM, native: dict[str, Any] | None = None) -> dict[str, Any]:
        prepare(aibom)
        native = native_document(aibom) if native is None else native
        # Native refs are BOM-local, and producers can reuse serial numbers across revisions.
        ids = self._ids(content_digest(native).removeprefix("sha256:"))
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
        # SPDX 3.0.1 requires CreationInfo.created. The native BOM carries no
        # wall-clock timestamp by default, so fall back to the export time.
        # This is the only wall-clock field in SPDX output: two exports of
        # the same inventory differ only here.
        created_at = aibom.metadata.timestamp or datetime.now(UTC)
        creation = {
            "type": "CreationInfo",
            "@id": ci,
            "specVersion": "3.0.1",
            "created": created_at.astimezone(UTC)
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
        native_by_ref = native_components(native)
        ordered = sorted(aibom.components, key=lambda c: c.bom_ref)
        components = [self._element(comp, ids, native_by_ref[comp.bom_ref]) for comp in ordered]
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
        subject = repository_subject(aibom)
        members: list[dict[str, Any]] = [
            *parties,
            *components,
            *relationships,
            *license_relationships,
        ]
        sbom: dict[str, Any] = {
            "type": "software_Sbom",
            "spdxId": ids.element("sbom", "inventory"),
            "creationInfo": ci,
            "element": [member["spdxId"] for member in members],
            "rootElement": [
                ids.element("component", comp.bom_ref)
                for comp in ([subject] if subject is not None else ordered)
                if comp.component_type == ComponentType.AGENT
            ],
        }
        if repository_scan(aibom):
            sbom["software_sbomType"] = ["source"]
        elements: list[dict[str, Any]] = [creator, generator, *members, sbom]
        doc = {
            "type": "SpdxDocument",
            "spdxId": ids.document,
            "creationInfo": ci,
            "name": "Nexus SymBiote AgentBOM " + str(aibom.metadata.serial_number),
            "element": [element["spdxId"] for element in elements],
            "rootElement": [sbom["spdxId"]],
            "profileConformance": [
                "core",
                "software",
                *(["expandedLicensing"] if license_relationships else []),
                "extension",
            ],
            "comment": COVERAGE_COMMENTS[coverage],
            "extension": _extension(
                [
                    *document_properties(aibom, self.format_name, native),
                    {"name": PROJECTION_PROPERTY, "value": PROJECTION},
                ]
            ),
        }
        return {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [doc, *elements, creation],
        }

    @staticmethod
    def _element(comp: AnyComponent, ids: _DocumentIds, native: dict[str, Any]) -> dict[str, Any]:
        typ = SPDX_TYPE_MAP.get(comp.component_type, "software_Package")
        element: dict[str, Any] = {
            "type": typ,
            "spdxId": ids.element("component", comp.bom_ref),
            "creationInfo": ids.creation,
            "name": comp.name,
            "extension": _extension(
                [
                    component_property(comp, native),
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
        version = standard_version(comp)
        if typ != "software_File" and version:
            element["software_packageVersion"] = version
        if comp.supplier:
            element["suppliedBy"] = ids.element("supplier", comp.supplier)
        if comp.description:
            element["description"] = comp.description
        if typ == "ai_AIPackage":
            element["software_primaryPurpose"] = (
                "model" if isinstance(comp, ModelComponent) else "application"
            )
            if isinstance(comp, ModelComponent) and comp.model_type:
                element["ai_typeOfModel"] = [comp.model_type]
            if isinstance(comp, AgentComponent) and comp.description:
                element["ai_informationAboutApplication"] = comp.description
        elif typ == "dataset_DatasetPackage":
            element["software_primaryPurpose"] = "data"
            # The only property the Dataset class requires; the inventory has no type.
            element["dataset_datasetType"] = ["noAssertion"]
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
        hashes = standard_hashes(comp)
        if hashes:
            element["verifiedUsing"] = [
                {"type": "Hash", "algorithm": _spdx_algorithm(name), "hashValue": digest}
                for name, digest in hashes
            ]
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
        elif typed is None:
            relationship["comment"] = f"Native relationship '{edge.relationship}'."
        return relationship

    @staticmethod
    def recover(document: dict[str, Any]) -> AIBOM:
        """Require agreement with the embedded inventory under the declared projection.

        A document without a projection marker was written by 0.1.0 and must match that
        projection. Malformed input raises ValueError.
        """
        try:
            return SPDXGenerator._recover(document)
        except (RecursionError, Unresolvable, KeyError, TypeError, AttributeError) as exc:
            raise ValueError("SPDX document cannot be recovered") from exc

    @staticmethod
    def _recover(document: dict[str, Any]) -> AIBOM:
        graph = document.get("@graph")
        docs = [
            node
            for node in (graph if isinstance(graph, list) else [])
            if isinstance(node, dict) and node.get("type") == "SpdxDocument"
        ]
        if len(docs) != 1:
            raise ValueError("expected exactly one SPDX document")
        doc = docs[0]
        properties = [
            {"name": prop["extension_cdxPropName"], "value": prop.get("extension_cdxPropValue", "")}
            for extension in doc.get("extension", [])
            if isinstance(extension, dict)
            and extension.get("type") == "extension_CdxPropertiesExtension"
            for prop in extension.get("extension_cdxProperty", [])
            if isinstance(prop, dict) and "extension_cdxPropName" in prop
        ]
        projection = declared_projection(properties)
        namespace = _document_namespace(doc["spdxId"])
        recovered, native = recover_native(properties)
        if projection == PROJECTION:
            expected = SPDXGenerator(namespace)._projection(recovered, native)
        elif projection is None and namespace is not None:
            expected = _legacy.spdx_projection(recovered, namespace, native)
        else:
            raise ValueError("unsupported SPDX projection version")
        # Without a native timestamp, CreationInfo.created is render-time
        # metadata and a re-projection at recovery time legitimately differs
        # only there. With one, the export must carry exactly that timestamp.
        actual, wanted = _public_view(document), _public_view(expected)
        if recovered.metadata.timestamp is None:
            actual, wanted = _without_created(actual), _without_created(wanted)
        if unordered_projection(actual) != unordered_projection(wanted):
            raise ValueError("SPDX projection conflicts with the embedded native document")
        # Only the flat reference topology emitted by a supported projection may
        # reach schema validation. Inline reference objects can make the general
        # SPDX schema revisit a tiny nested input an enormous number of times.
        errors = spdx_errors(
            document,
            legacy_license=_legacy.NO_ASSERTION_LICENSE if projection is None else None,
        )
        if errors:
            raise ValueError("invalid spdx export: " + "; ".join(errors[:10]))
        return recovered


def _public_view(document: dict[str, Any]) -> dict[str, Any]:
    # A conforming JSON-LD consumer can omit an empty root element set.
    return {
        **document,
        "@graph": [
            {**node, "rootElement": node.get("rootElement", [])}
            if isinstance(node, dict) and node.get("type") in SPDX_COLLECTIONS
            else node
            for node in document["@graph"]
        ],
    }


def _spdx_algorithm(name: str) -> str:
    """SPDX spells SHA3 digests with an underscore and the others without separators."""
    return (
        name.lower().replace("-", "_")
        if name.startswith("SHA3-")
        else name.lower().replace("-", "")
    )
