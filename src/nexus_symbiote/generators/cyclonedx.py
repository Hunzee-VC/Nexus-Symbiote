"""CycloneDX 1.7 output generator.

Maps AgentBOM components to CycloneDX 1.7 JSON, extending the standard
with agent-specific property taxonomies under the nexus-symbiote: namespace.
docs/standard-exports.md describes the mapping and the property names.
"""

from __future__ import annotations

from typing import Any

from referencing.exceptions import Unresolvable

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.models import (
    AgentComponent,
    AnyComponent,
    GuardrailComponent,
    MCPServerComponent,
    MemoryStoreComponent,
    ModelComponent,
    PromptComponent,
    RAGSourceComponent,
    RegistryEntryComponent,
    SkillPackageComponent,
    ToolComponent,
)
from nexus_symbiote.generators import _legacy
from nexus_symbiote.generators._common import (
    PROJECTION_PROPERTY,
    claim_properties,
    component_property,
    coverage_aggregate,
    declared_projection,
    document_properties,
    json_text,
    native_components,
    native_document,
    prepare,
    recover_native,
    repository_scan,
    repository_subject,
    requested_version,
    standard_hashes,
    standard_version,
    unordered_projection,
)
from nexus_symbiote.generators.base import Generator
from nexus_symbiote.generators.package_identifiers import (
    package_identifier,
    package_identifier_properties,
)
from nexus_symbiote.generators.validation import require_valid

PROJECTION = "cyclonedx-1.7/2"
COMPONENT_TYPE_MAP: dict[ComponentType, str] = {
    ComponentType.AGENT: "application",
    ComponentType.MODEL: "machine-learning-model",
    ComponentType.TOOL: "library",
    ComponentType.MCP_SERVER: "application",
    ComponentType.MCP_CLIENT: "application",
    ComponentType.A2A_CLIENT: "application",
    ComponentType.A2A_SERVER: "application",
    ComponentType.IDE_AGENT: "application",
    ComponentType.VERIFIED_EXTENSION: "library",
    ComponentType.PROMPT_TEMPLATE: "data",
    ComponentType.GUARDRAIL_POLICY: "library",
    ComponentType.MEMORY_STORE: "data",
    ComponentType.RAG_SOURCE: "data",
    ComponentType.DATA_SOURCE: "data",
    ComponentType.REGISTRY_ENTRY: "library",
    ComponentType.SKILL_PACKAGE: "library",
}
# Package registries hold libraries; image registries hold containers. Any other
# registry keeps the neutral "library" type.
REGISTRY_COMPONENT_TYPES = {"docker-hub": "container", "docker": "container", "oci": "container"}


def component_type(comp: AnyComponent) -> str:
    if isinstance(comp, RegistryEntryComponent):
        return REGISTRY_COMPONENT_TYPES.get((comp.registry_type or "").lower(), "library")
    return COMPONENT_TYPE_MAP.get(comp.component_type, "library")


def property_value(value: Any) -> str:
    """JSON spelling for non-string values: ``true``, ``3``, ``{"a":1}``."""
    return value if isinstance(value, str) else json_text(value)


def standard_component(comp: AnyComponent) -> dict[str, Any]:
    """The standard fields of a component, shared with the VEX projection."""
    result: dict[str, Any] = {
        "type": component_type(comp),
        "bom-ref": comp.bom_ref,
        "name": comp.name,
    }
    version = standard_version(comp)
    if version:
        result["version"] = version
    package = package_identifier(comp)
    if package.value is not None:
        result["purl"] = package.value
    hashes = standard_hashes(comp)
    if hashes:
        result["hashes"] = [{"alg": name, "content": digest} for name, digest in hashes]
    return result


class CycloneDXGenerator(Generator):
    format_name = "cyclonedx-1.7"

    def generate(self, aibom: AIBOM) -> dict[str, Any]:
        document = self._projection(aibom)
        require_valid(document, "cyclonedx")
        return document

    def _projection(self, aibom: AIBOM, native: dict[str, Any] | None = None) -> dict[str, Any]:
        prepare(aibom)
        native = native_document(aibom) if native is None else native
        components = native_components(native)
        subject = repository_subject(aibom)
        composition: dict[str, Any] = {"aggregate": coverage_aggregate(aibom.metadata.completeness)}
        if subject is not None:
            composition |= {"assemblies": [subject.bom_ref], "dependencies": [subject.bom_ref]}
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "version": aibom.metadata.version,
            "serialNumber": aibom.metadata.serial_number,
            "metadata": self._metadata(aibom, native, subject),
            "components": [
                self._component(c, components[c.bom_ref])
                for c in sorted(aibom.components, key=lambda c: c.bom_ref)
                if c is not subject
            ],
            "dependencies": self._dependencies(aibom),
            "compositions": [composition],
        }

    @staticmethod
    def _dependencies(aibom: AIBOM) -> list[dict[str, Any]]:
        """Only unconditional edges with dependency meaning enter the standard graph.

        ``depends-on`` keeps its direction. A tool requires the server that provides
        it, so ``provides-tool`` is the tool's dependency on its server. Conditions,
        invocation, lineage and authority stay in the extension.
        """
        adjacency: dict[str, set[str]] = {}
        for edge in aibom.dependencies:
            if edge.conditions:
                continue
            if edge.relationship == "depends-on":
                adjacency.setdefault(edge.source_ref, set()).add(edge.target_ref)
            elif edge.relationship == "provides-tool":
                adjacency.setdefault(edge.target_ref, set()).add(edge.source_ref)
        return [
            {"ref": ref, "dependsOn": sorted(targets)} for ref, targets in sorted(adjacency.items())
        ]

    @staticmethod
    def _public_view(document: dict[str, Any]) -> dict[str, Any]:
        view = dict(document)
        # The upstream SDK supplies the schema hint and an extra ref-only row
        # for known components without emitted edges. Never discard targets.
        if view.get("$schema") == "http://cyclonedx.org/schema/bom-1.7.schema.json":
            del view["$schema"]
        view.setdefault("components", [])
        view["dependencies"] = [
            edge for edge in view.get("dependencies", []) if set(edge) != {"ref"}
        ]
        return view

    @classmethod
    def _expected_view(cls, candidate: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
        view = cls._public_view(candidate)
        # Readers such as the upstream SDK drop the compositions array. Without one a
        # consumer sees no completeness assertion, which equals "unknown". Dropping
        # "incomplete" loses the public coverage warning, and any composition that
        # is present must match exactly, so both still conflict.
        if "compositions" not in document and [
            composition.get("aggregate") for composition in view.get("compositions", [])
        ] == ["unknown"]:
            del view["compositions"]
        return view

    @classmethod
    def recover(
        cls, document: dict[str, Any], *, allow_legacy_relationships: bool = False
    ) -> AIBOM:
        """Require agreement with the embedded inventory under the declared projection.

        A document without a projection marker was written by 0.1.0 and must match that
        projection. Legacy mode also accepts, for such a document only, the exact edge
        projection of the historical exporter as a whole: every edge in ``dependsOn``
        and no conditional flag. A mixture is rejected. Malformed input raises
        ValueError.
        """
        try:
            return cls._recover(document, allow_legacy_relationships)
        except (RecursionError, Unresolvable, KeyError, TypeError, AttributeError) as exc:
            raise ValueError("CycloneDX document cannot be recovered") from exc

    @classmethod
    def _recover(cls, document: dict[str, Any], allow_legacy_relationships: bool) -> AIBOM:
        require_valid(document, "cyclonedx")
        properties = document.get("metadata", {}).get("properties", [])
        recovered, native = recover_native(properties)
        projection = declared_projection(properties)
        if projection == PROJECTION:
            candidates = [cls()._projection(recovered, native)]
        elif projection is None:
            candidates = [
                _legacy.cyclonedx_projection(recovered, native, historical=historical)
                for historical in ((False, True) if allow_legacy_relationships else (False,))
            ]
        else:
            raise ValueError("unsupported CycloneDX projection version")
        actual = unordered_projection(cls._public_view(document))
        if not any(
            actual == unordered_projection(cls._expected_view(candidate, document))
            for candidate in candidates
        ):
            raise ValueError("CycloneDX projection conflicts with the embedded native document")
        return recovered

    def _metadata(
        self, aibom: AIBOM, native: dict[str, Any], subject: AnyComponent | None
    ) -> dict[str, Any]:
        # The native BOM carries no wall-clock timestamp by default; omit
        # the field rather than emitting null, which the CycloneDX schema
        # rejects. An explicitly set observation timestamp is preserved.
        meta: dict[str, Any] = {}
        if aibom.metadata.timestamp is not None:
            meta["timestamp"] = aibom.metadata.timestamp.isoformat()
        meta["tools"] = {
            "components": [
                {
                    "type": "application",
                    "name": aibom.metadata.tool_name,
                    "version": aibom.metadata.tool_version or "unknown",
                    "publisher": aibom.metadata.tool_vendor,
                }
            ]
        }
        if aibom.metadata.authors:
            meta["authors"] = [{"name": a} for a in aibom.metadata.authors]
        if repository_scan(aibom):
            # Configuration read from a repository describes what is planned to run.
            meta["lifecycles"] = [{"phase": "pre-build"}]
        if subject is not None:
            meta["component"] = self._component(subject, native_components(native)[subject.bom_ref])
        edges = sorted(
            {
                json_text(
                    {"from": edge.source_ref, "to": edge.target_ref, "type": edge.relationship}
                    | ({"conditional": True} if edge.conditions else {})
                )
                for edge in aibom.dependencies
            }
        )
        meta["properties"] = [
            *({"name": "nexus-symbiote:dependency:relationship", "value": edge} for edge in edges),
            *document_properties(aibom, self.format_name, native),
            {"name": PROJECTION_PROPERTY, "value": PROJECTION},
        ]
        claim = aibom.metadata.completeness
        if claim and claim.source_report_digest:
            meta["properties"].extend(
                [
                    {
                        "name": "nexus-symbiote:discovery:reportSha256",
                        "value": claim.source_report_digest,
                    },
                    {
                        "name": "nexus-symbiote:discovery:sourceFormat",
                        "value": claim.source_report_format or "unknown",
                    },
                    {
                        "name": "nexus-symbiote:discovery:sourceStatus",
                        "value": claim.source_report_status or "unknown",
                    },
                    {
                        "name": "nexus-symbiote:discovery:unmappedCount",
                        "value": str(claim.source_unmapped_count),
                    },
                ]
            )
        return meta

    def _component(self, comp: AnyComponent, native: dict[str, Any]) -> dict[str, Any]:
        result = standard_component(comp)
        if comp.supplier:
            result["supplier"] = {"name": comp.supplier}
        if comp.description:
            result["description"] = comp.description
        if comp.source_path:
            result["evidence"] = {"occurrences": [{"location": comp.source_path}]}
        props = self._extension_properties(comp, native)
        if props:
            result["properties"] = props
        return result

    def _extension_properties(
        self, comp: AnyComponent, native: dict[str, Any]
    ) -> list[dict[str, str]]:
        props: list[dict[str, str]] = []

        def _add(name: str, value: Any) -> None:
            if value is not None and value != "":
                props.append({"name": f"nexus-symbiote:{name}", "value": property_value(value)})

        _add("componentType", comp.component_type.value)
        _add("trustTier", comp.trust_tier.value)
        _add("assuranceLevel", comp.assurance_level.value)
        _add("requestedVersion", requested_version(comp))

        if isinstance(comp, AgentComponent):
            _add(
                "autonomyLevel",
                comp.autonomy_level.value if comp.autonomy_level is not None else "unknown",
            )
            _add("framework", comp.framework)
            for ref in comp.model_refs:
                _add("modelRef", ref)
            for ref in comp.tool_refs:
                _add("toolRef", ref)
        elif isinstance(comp, ModelComponent):
            _add("modelType", comp.model_type)
            _add("provider", comp.provider)
            _add("serializationFormat", comp.serialization_format)
            _add("serializationSafety", comp.serialization_safety.value)
            _add("signingStatus", comp.signing_status)
            _add("trustRemoteCode", comp.trust_remote_code)
        elif isinstance(comp, ToolComponent):
            _add("definitionHash", comp.definition_hash)
            _add("definitionHashVersion", comp.definition_hash_version)
            for k, v in comp.annotations.items():
                _add(f"annotation.{k}", v)
        elif isinstance(comp, MCPServerComponent):
            _add("transport", comp.transport)
            # The native default of 0 also means "not observed"; only a count is exported.
            _add("toolCount", comp.tool_count or None)
            _add("versionPinned", comp.version_pinned)
            _add("schemaHash", comp.schema_hash)
        elif isinstance(comp, PromptComponent):
            _add("promptType", comp.prompt_type)
            _add("contentHash", comp.content_hash)
        elif isinstance(comp, GuardrailComponent):
            _add("guardrailType", comp.guardrail_type)
        elif isinstance(comp, MemoryStoreComponent):
            _add("storeType", comp.store_type)
            _add("tenantIsolated", comp.tenant_isolated)
            _add("encryptionAtRest", comp.encryption_at_rest)
        elif isinstance(comp, RAGSourceComponent):
            _add("corpusType", comp.corpus_type)
            _add("embeddingModel", comp.embedding_model_name)
        elif isinstance(comp, RegistryEntryComponent):
            _add("registryType", comp.registry_type)
            _add("publisherVerified", comp.publisher_verified)
        elif isinstance(comp, SkillPackageComponent):
            _add("skillType", comp.skill_type)

        props.append(component_property(comp, native))
        props.extend(claim_properties(comp))
        props.extend(package_identifier_properties(comp))

        return props
