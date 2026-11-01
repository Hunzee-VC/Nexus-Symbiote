"""CycloneDX 1.7 output generator.

Maps AgentBOM components to CycloneDX 1.7 JSON, extending the standard
with agent-specific property taxonomies under the nexus-symbiote: namespace.
"""

from __future__ import annotations

import json
from typing import Any

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
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
from nexus_symbiote.generators.base import Generator
from nexus_symbiote.validators.coverage import assess_coverage

# Every ComponentType maps to a CycloneDX 1.7 component.type value. The original type is kept
# in the nexus-symbiote:componentType property.
COMPONENT_TYPE_MAP: dict[ComponentType, str] = {
    ComponentType.AGENT: "application",
    ComponentType.MODEL: "machine-learning-model",
    ComponentType.TOOL: "application",
    ComponentType.MCP_SERVER: "application",
    ComponentType.MCP_CLIENT: "application",
    ComponentType.PROMPT_TEMPLATE: "file",
    ComponentType.GUARDRAIL_POLICY: "file",
    ComponentType.MEMORY_STORE: "data",
    ComponentType.RAG_SOURCE: "data",
    ComponentType.DATA_SOURCE: "data",
    ComponentType.REGISTRY_ENTRY: "application",
    ComponentType.SKILL_PACKAGE: "application",
    ComponentType.A2A_CLIENT: "application",
    ComponentType.A2A_SERVER: "application",
    ComponentType.IDE_AGENT: "application",
    ComponentType.VERIFIED_EXTENSION: "application",
}

_HASH_ALGORITHMS: dict[str, str] = {
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
}


def _property_value(value: Any) -> str:
    """Property values are strings. Booleans become true or false, containers become JSON."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple, dict)):
        return json.dumps(value, sort_keys=True, default=str)
    return str(value)


def _property(name: str, value: Any) -> dict[str, str]:
    return {"name": name, "value": _property_value(value)}


def _hash_algorithm(alg: str) -> str:
    return _HASH_ALGORITHMS.get(alg.lower(), alg.upper().replace("SHA", "SHA-"))


class CycloneDXGenerator(Generator):
    format_name = "cyclonedx-1.7"

    def generate(self, aibom: AIBOM) -> dict[str, Any]:
        aibom.finalize()
        refs = {component.bom_ref for component in aibom.components}
        # An edge is kept only when both of its ends are components. The rest are counted.
        edges = [e for e in aibom.dependencies if e.source_ref in refs and e.target_ref in refs]
        grouped: dict[str, set[str]] = {}
        for edge in edges:
            grouped.setdefault(edge.source_ref, set()).add(edge.target_ref)

        metadata = self._metadata(aibom)
        # CycloneDX dependency objects do not carry typed edge semantics.
        # Keep the original edges as documented metadata properties.
        metadata["properties"] = [
            {
                "name": "nexus-symbiote:dependency:relationship",
                "value": json.dumps(
                    {"from": edge.source_ref, "to": edge.target_ref, "type": edge.relationship},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            }
            for edge in edges
        ]
        metadata["properties"].extend(self._completeness_properties(aibom))
        metadata["properties"].append(
            _property("nexus-symbiote:dependency:dropped", len(aibom.dependencies) - len(edges))
        )
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "version": aibom.metadata.version,
            "serialNumber": aibom.metadata.serial_number,
            "metadata": metadata,
            "components": [self._component(c) for c in aibom.components],
            "dependencies": [
                {"ref": ref, "dependsOn": sorted(grouped.get(ref, set()))}
                for ref in sorted(refs)
            ],
        }

    def _metadata(self, aibom: AIBOM) -> dict[str, Any]:
        meta: dict[str, Any] = {
            "timestamp": (
                aibom.metadata.timestamp.isoformat() if aibom.metadata.timestamp else None
            ),
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
        if aibom.metadata.authors:
            meta["authors"] = [{"name": a} for a in aibom.metadata.authors]
        return meta

    def _completeness_properties(self, aibom: AIBOM) -> list[dict[str, str]]:
        claim = aibom.metadata.completeness
        assessment = assess_coverage(claim)
        props = [
            _property("nexus-symbiote:coverage", assessment.state),
            _property("nexus-symbiote:coverage-reasons", list(assessment.reasons)),
        ]
        if claim is not None:
            props.append(_property("nexus-symbiote:scope", claim.scope))
            props.append(_property("nexus-symbiote:scanner-status", claim.scanner_status))
        return props

    def _component(self, comp: AnyComponent) -> dict[str, Any]:
        cdx_type = COMPONENT_TYPE_MAP.get(comp.component_type, "application")
        result: dict[str, Any] = {
            "type": cdx_type,
            "bom-ref": comp.bom_ref,
            "name": comp.name,
        }
        if comp.version:
            result["version"] = comp.version
        if comp.supplier:
            result["supplier"] = {"name": comp.supplier}
        if comp.description:
            result["description"] = comp.description
        hashes = self._hashes(comp)
        if hashes:
            result["hashes"] = hashes

        props = self._extension_properties(comp)
        if props:
            result["properties"] = props

        return result

    def _hashes(self, comp: AnyComponent) -> list[dict[str, str]]:
        hashes = [
            {"alg": _hash_algorithm(alg), "content": val.split(":", 1)[-1]}
            for alg, val in comp.hashes.items()
            if val
        ]
        if isinstance(comp, PromptComponent) and comp.content_hash:
            algorithm, _, digest = comp.content_hash.partition(":")
            already_listed = any(h["alg"] == "SHA-256" for h in hashes)
            if algorithm.lower() == "sha256" and digest and not already_listed:
                hashes.append({"alg": "SHA-256", "content": digest})
        return hashes

    def _extension_properties(self, comp: AnyComponent) -> list[dict[str, str]]:
        props: list[dict[str, str]] = []

        def _add(name: str, value: Any) -> None:
            if value is not None and value != "":
                props.append(_property(f"nexus-symbiote:{name}", value))

        _add("componentType", comp.component_type.value)
        _add("trustTier", comp.trust_tier.value)
        _add("assuranceLevel", comp.assurance_level.value)

        if isinstance(comp, AgentComponent):
            _add("autonomyLevel", comp.autonomy_level.value)
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
            if comp.annotations:
                for k, v in comp.annotations.items():
                    _add(f"annotation.{k}", v)
        elif isinstance(comp, MCPServerComponent):
            _add("transport", comp.transport)
            _add("toolCount", comp.tool_count)
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

        for risk in comp.risks:
            props.append(
                _property(
                    "nexus-symbiote:risk",
                    f"{risk.severity.value} {risk.category}: {risk.detail}",
                )
            )

        return props

    def _dependency(self, edge: DependencyEdge) -> dict[str, Any]:
        return {
            "ref": edge.source_ref,
            "dependsOn": [edge.target_ref],
        }
