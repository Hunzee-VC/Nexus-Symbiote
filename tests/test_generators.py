"""Tests for CycloneDX and SPDX generators."""

from __future__ import annotations

import json

import pytest

from symbiote.core.aibom import AIBOM, DependencyEdge
from symbiote.core.enums import SerializationSafety
from symbiote.core.models import (
    AgentComponent,
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
from symbiote.generators.cyclonedx import CycloneDXGenerator
from symbiote.generators.spdx import SPDXExportUnavailableError, SPDXGenerator


def _sample_aibom() -> AIBOM:
    bom = AIBOM()
    bom.add_component(
        AgentComponent(
            bom_ref="agent:main",
            name="my-agent",
            framework="langchain",
            model_refs=["model:gpt-4o"],
            tool_refs=["tool:read_file"],
        )
    )
    bom.add_component(
        ModelComponent(
            bom_ref="model:gpt-4o",
            name="gpt-4o",
            provider="openai",
            serialization_format="api",
            signing_status="n/a",
        )
    )
    bom.add_component(
        ToolComponent(
            bom_ref="tool:read_file",
            name="read_file",
            description_text="Reads a file",
            definition_hash="sha256:abc123",
        )
    )
    bom.add_component(
        MCPServerComponent(
            bom_ref="mcp:fs",
            name="@modelcontextprotocol/server-filesystem",
            transport="stdio",
            tool_count=3,
            version_pinned=True,
        )
    )
    bom.add_dependency(
        DependencyEdge(
            source_ref="agent:main",
            target_ref="tool:read_file",
            relationship="invokes",
        )
    )
    return bom


class TestCycloneDXGenerator:
    def test_generate_structure(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_sample_aibom())
        assert result["bomFormat"] == "CycloneDX"
        assert result["specVersion"] == "1.7"
        assert "serialNumber" in result
        assert len(result["components"]) == 4
        assert len(result["dependencies"]) == 1

    def test_component_types_mapped(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_sample_aibom())
        types = {c["name"]: c["type"] for c in result["components"]}
        assert types["gpt-4o"] == "machine-learning-model"
        assert types["read_file"] == "library"
        assert types["@modelcontextprotocol/server-filesystem"] == "application"

    def test_extension_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_sample_aibom())
        agent_comp = next(c for c in result["components"] if c["name"] == "my-agent")
        prop_names = {p["name"] for p in agent_comp.get("properties", [])}
        assert "symbiote:componentType" in prop_names
        assert "symbiote:autonomyLevel" in prop_names

    def test_model_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_sample_aibom())
        model_comp = next(c for c in result["components"] if c["name"] == "gpt-4o")
        props = {p["name"]: p["value"] for p in model_comp.get("properties", [])}
        assert props.get("symbiote:provider") == "openai"

    def test_dependency_mapping(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_sample_aibom())
        dep = result["dependencies"][0]
        assert dep["ref"] == "agent:main"
        assert "tool:read_file" in dep["dependsOn"]

    def test_generate_json_valid(self):
        gen = CycloneDXGenerator()
        json_str = gen.generate_json(_sample_aibom())
        data = json.loads(json_str)
        assert data["bomFormat"] == "CycloneDX"

    def test_metadata_tools(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_sample_aibom())
        tools = result["metadata"]["tools"]["components"]
        assert len(tools) == 1
        assert tools[0]["name"] == "symbiote"


def test_spdx_export_fails_closed():
    with pytest.raises(SPDXExportUnavailableError, match="SPDX export is unavailable"):
        SPDXGenerator().generate(_sample_aibom())


def _full_component_aibom() -> AIBOM:
    bom = AIBOM()
    bom.add_component(
        AgentComponent(
            bom_ref="agent:main",
            name="my-agent",
            framework="crewai",
            model_refs=["model:gpt-4o"],
            tool_refs=["tool:read_file"],
        )
    )
    bom.add_component(
        ModelComponent(
            bom_ref="model:gpt-4o",
            name="gpt-4o",
            provider="openai",
            model_type="foundation",
            serialization_format="safetensors",
            serialization_safety=SerializationSafety.SAFE,
            signing_status="sigstore-signed",
            trust_remote_code=True,
            version="4.0",
            supplier="OpenAI",
            description="Large language model",
            hashes={"sha256": "sha256:abc"},
        )
    )
    bom.add_component(
        ToolComponent(
            bom_ref="tool:read_file",
            name="read_file",
            description_text="Reads a file",
            definition_hash="sha256:abc123",
            annotations={"readOnlyHint": True, "openWorldHint": False},
        )
    )
    bom.add_component(
        MCPServerComponent(
            bom_ref="mcp:fs",
            name="filesystem",
            transport="stdio",
            tool_count=3,
            version_pinned=True,
            schema_hash="sha256:sch123",
        )
    )
    bom.add_component(
        PromptComponent(
            bom_ref="prompt:sys",
            name="system-prompt",
            prompt_type="system-prompt",
            content_hash="sha256:ppp",
        )
    )
    bom.add_component(
        GuardrailComponent(
            bom_ref="guard:filter",
            name="content-filter",
            guardrail_type="output-filter",
        )
    )
    bom.add_component(
        MemoryStoreComponent(
            bom_ref="mem:conv",
            name="conversation-store",
            store_type="conversation",
            tenant_isolated=True,
            encryption_at_rest=True,
        )
    )
    bom.add_component(
        RAGSourceComponent(
            bom_ref="rag:docs",
            name="docs-index",
            corpus_type="vector-store",
            embedding_model_name="text-embedding-3-small",
        )
    )
    bom.add_component(
        RegistryEntryComponent(
            bom_ref="reg:npm",
            name="npm-registry",
            registry_type="npm",
            publisher_verified=True,
        )
    )
    bom.add_component(
        SkillPackageComponent(
            bom_ref="skill:deploy",
            name="deploy-skill",
            skill_type="skill",
        )
    )
    bom.add_dependency(
        DependencyEdge(
            source_ref="agent:main",
            target_ref="model:gpt-4o",
            relationship="trained-on",
        )
    )
    bom.add_dependency(
        DependencyEdge(
            source_ref="agent:main",
            target_ref="tool:read_file",
            relationship="invokes",
        )
    )
    return bom


class TestCycloneDXGeneratorFull:
    def test_all_component_types_present(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        assert len(result["components"]) == 10

    def test_model_all_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        model_comp = next(c for c in result["components"] if c["name"] == "gpt-4o")
        props = {p["name"]: p["value"] for p in model_comp.get("properties", [])}
        assert props["symbiote:modelType"] == "foundation"
        assert props["symbiote:serializationFormat"] == "safetensors"
        assert props["symbiote:serializationSafety"] == "safe"
        assert props["symbiote:signingStatus"] == "sigstore-signed"
        assert props["symbiote:trustRemoteCode"] == "True"

    def test_model_version_and_supplier(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        model_comp = next(c for c in result["components"] if c["name"] == "gpt-4o")
        assert model_comp["version"] == "4.0"
        assert model_comp["supplier"]["name"] == "OpenAI"

    def test_model_hashes(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        model_comp = next(c for c in result["components"] if c["name"] == "gpt-4o")
        assert len(model_comp.get("hashes", [])) >= 1

    def test_agent_refs(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        agent_comp = next(c for c in result["components"] if c["name"] == "my-agent")
        props = {p["name"]: p["value"] for p in agent_comp.get("properties", [])}
        assert "symbiote:modelRef" in props
        assert "symbiote:toolRef" in props
        assert props["symbiote:framework"] == "crewai"

    def test_tool_annotation_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        tool_comp = next(c for c in result["components"] if c["name"] == "read_file")
        props = {p["name"]: p["value"] for p in tool_comp.get("properties", [])}
        assert "symbiote:annotation.readOnlyHint" in props

    def test_mcp_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        mcp_comp = next(c for c in result["components"] if c["name"] == "filesystem")
        props = {p["name"]: p["value"] for p in mcp_comp.get("properties", [])}
        assert props["symbiote:transport"] == "stdio"
        assert props["symbiote:toolCount"] == "3"
        assert props["symbiote:schemaHash"] == "sha256:sch123"

    def test_prompt_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        p = next(c for c in result["components"] if c["name"] == "system-prompt")
        props = {p["name"]: p["value"] for p in p.get("properties", [])}
        assert props["symbiote:promptType"] == "system-prompt"
        assert props["symbiote:contentHash"] == "sha256:ppp"

    def test_guardrail_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        g = next(c for c in result["components"] if c["name"] == "content-filter")
        props = {p["name"]: p["value"] for p in g.get("properties", [])}
        assert props["symbiote:guardrailType"] == "output-filter"

    def test_memory_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        m = next(c for c in result["components"] if c["name"] == "conversation-store")
        props = {p["name"]: p["value"] for p in m.get("properties", [])}
        assert props["symbiote:storeType"] == "conversation"
        assert props["symbiote:tenantIsolated"] == "True"
        assert props["symbiote:encryptionAtRest"] == "True"

    def test_rag_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        r = next(c for c in result["components"] if c["name"] == "docs-index")
        props = {p["name"]: p["value"] for p in r.get("properties", [])}
        assert props["symbiote:corpusType"] == "vector-store"
        assert props["symbiote:embeddingModel"] == "text-embedding-3-small"

    def test_registry_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        r = next(c for c in result["components"] if c["name"] == "npm-registry")
        props = {p["name"]: p["value"] for p in r.get("properties", [])}
        assert props["symbiote:registryType"] == "npm"
        assert props["symbiote:publisherVerified"] == "True"

    def test_skill_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        s = next(c for c in result["components"] if c["name"] == "deploy-skill")
        props = {p["name"]: p["value"] for p in s.get("properties", [])}
        assert props["symbiote:skillType"] == "skill"

    def test_multiple_dependency_types(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_full_component_aibom())
        deps = result["dependencies"]
        assert all(set(d) == {"ref", "dependsOn"} for d in deps)
        rels = {json.loads(p["value"])["type"] for p in result["metadata"]["properties"]}
        assert "trained-on" in rels
        assert "invokes" in rels

    def test_authors_in_metadata(self):
        bom = _full_component_aibom()
        bom.metadata.authors = ["Alice", "Bob"]
        gen = CycloneDXGenerator()
        result = gen.generate(bom)
        authors = result["metadata"]["authors"]
        assert len(authors) == 2
        assert authors[0]["name"] == "Alice"
