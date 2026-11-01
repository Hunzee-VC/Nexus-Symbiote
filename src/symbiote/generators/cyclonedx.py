"""CycloneDX 1.7 output generator.

Maps AgentBOM components to CycloneDX 1.7 JSON, extending the standard
with agent-specific property taxonomies under the symbiote: namespace.
"""

from __future__ import annotations

import json
from typing import Any

from symbiote.core.aibom import AIBOM, DependencyEdge
from symbiote.core.enums import ComponentType
from symbiote.core.models import (
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
from symbiote.generators.base import Generator

COMPONENT_TYPE_MAP: dict[ComponentType, str] = {
    ComponentType.AGENT: "application",
    ComponentType.MODEL: "machine-learning-model",
    ComponentType.TOOL: "library",
    ComponentType.MCP_SERVER: "application",
    ComponentType.PROMPT_TEMPLATE: "data",
    ComponentType.GUARDRAIL_POLICY: "library",
    ComponentType.MEMORY_STORE: "data",
    ComponentType.RAG_SOURCE: "data",
    ComponentType.DATA_SOURCE: "data",
    ComponentType.REGISTRY_ENTRY: "platform",
    ComponentType.SKILL_PACKAGE: "library",
}


class CycloneDXGenerator(Generator):
    format_name = "cyclonedx-1.7"

    def generate(self, aibom: AIBOM) -> dict[str, Any]:
        aibom.finalize()
        metadata = self._metadata(aibom)
        # CycloneDX dependency objects do not carry typed edge semantics.
        # Keep the original edges as documented metadata properties.
        if aibom.dependencies:
            metadata["properties"] = [
                {
                    "name": "symbiote:dependency:relationship",
                    "value": json.dumps(
                        {"from": edge.source_ref, "to": edge.target_ref, "type": edge.relationship},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                }
                for edge in aibom.dependencies
            ]
        grouped: dict[str, set[str]] = {}
        for edge in aibom.dependencies:
            grouped.setdefault(edge.source_ref, set()).add(edge.target_ref)
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "version": aibom.metadata.version,
            "serialNumber": aibom.metadata.serial_number,
            "metadata": metadata,
            "components": [self._component(c) for c in aibom.components],
            "dependencies": [
                {"ref": ref, "dependsOn": sorted(targets)}
                for ref, targets in sorted(grouped.items())
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

    def _component(self, comp: AnyComponent) -> dict[str, Any]:
        cdx_type = COMPONENT_TYPE_MAP.get(comp.component_type, "library")
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
        if comp.hashes:
            result["hashes"] = [
                {"alg": alg.upper().replace("SHA", "SHA-"), "content": val.split(":", 1)[-1]}
                for alg, val in comp.hashes.items()
                if val
            ]

        props = self._extension_properties(comp)
        if props:
            result["properties"] = props

        return result

    def _extension_properties(self, comp: AnyComponent) -> list[dict[str, str]]:
        props: list[dict[str, str]] = []

        def _add(name: str, value: Any) -> None:
            if value is not None and value != "":
                props.append({"name": f"symbiote:{name}", "value": str(value)})

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

        return props

    def _dependency(self, edge: DependencyEdge) -> dict[str, Any]:
        return {
            "ref": edge.source_ref,
            "dependsOn": [edge.target_ref],
        }
