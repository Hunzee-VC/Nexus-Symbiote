"""Tests for CycloneDX and SPDX generators."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, Draft202012Validator
from referencing import Registry, Resource

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
from symbiote.generators.spdx import SPDXGenerator


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


def _extension_properties(element):
    return {
        prop["extension_cdxPropName"]: prop["extension_cdxPropValue"]
        for prop in element["extension"][0]["extension_cdxProperty"]
    }


class TestSPDXGenerator:
    def test_generate_structure(self):
        gen = SPDXGenerator()
        result = gen.generate(_sample_aibom())
        assert result["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
        graph = result["@graph"]
        doc = graph[0]
        assert doc["type"] == "SpdxDocument"
        assert graph[1]["specVersion"] == "3.0.1"
        assert doc["creationInfo"] == graph[1]["@id"]

    def test_element_types(self):
        gen = SPDXGenerator()
        result = gen.generate(_sample_aibom())
        elements = result["@graph"][1:]
        types = {e["name"]: e["type"] for e in elements if "name" in e}
        assert types.get("gpt-4o") == "ai_AIPackage"
        assert types.get("read_file") == "software_Package"

    def test_spdx_ids_unique(self):
        gen = SPDXGenerator()
        result = gen.generate(_sample_aibom())
        ids = [e["spdxId"] for e in result["@graph"] if "spdxId" in e]
        assert len(ids) == len(set(ids))

    def test_extensions_present(self):
        gen = SPDXGenerator()
        result = gen.generate(_sample_aibom())
        elements = [e for e in result["@graph"][1:] if e.get("type") != "Relationship"]
        for elem in elements:
            if "extension" in elem:
                assert "symbiote:componentType" in _extension_properties(elem)

    def test_relationship_types(self):
        gen = SPDXGenerator()
        result = gen.generate(_sample_aibom())
        rels = [e for e in result["@graph"] if e.get("type") == "Relationship"]
        assert len(rels) == 1
        assert rels[0]["relationshipType"] == "usesTool"

    def test_generate_json_valid(self):
        gen = SPDXGenerator()
        json_str = gen.generate_json(_sample_aibom())
        data = json.loads(json_str)
        assert "@context" in data


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
            hashes={"sha256": "sha256:" + "ab" * 32},
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
        assert deps == [{"ref": "agent:main", "dependsOn": ["model:gpt-4o", "tool:read_file"]}]
        rels = {
            json.loads(p["value"])["type"]
            for p in result["metadata"]["properties"]
            if p["name"] == "symbiote:dependency:relationship"
        }
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


class TestSPDXGeneratorFull:
    def test_all_element_types(self):
        gen = SPDXGenerator()
        result = gen.generate(_full_component_aibom())
        graph = result["@graph"]
        types = {e.get("name"): e["type"] for e in graph if "name" in e}
        assert types["my-agent"] == "ai_AIPackage"
        assert types["conversation-store"] == "dataset_DatasetPackage"
        assert types["docs-index"] == "dataset_DatasetPackage"
        assert types["content-filter"] == "software_Package"

    def test_trained_on_relationship(self):
        gen = SPDXGenerator()
        result = gen.generate(_full_component_aibom())
        rels = [e for e in result["@graph"] if e.get("type") == "Relationship"]
        rel_types = {r["relationshipType"] for r in rels}
        assert "trainedOn" in rel_types
        assert "usesTool" in rel_types

    def test_model_extensions(self):
        gen = SPDXGenerator()
        result = gen.generate(_full_component_aibom())
        model = next(e for e in result["@graph"] if e.get("name") == "gpt-4o")
        props = _extension_properties(model)
        assert props["symbiote:serializationFormat"] == "safetensors"
        assert props["symbiote:signingStatus"] == "sigstore-signed"

    def test_supplier_mapped(self):
        gen = SPDXGenerator()
        result = gen.generate(_full_component_aibom())
        model = next(e for e in result["@graph"] if e.get("name") == "gpt-4o")
        assert "suppliedBy" in model
        assert "OpenAI" in model["suppliedBy"]

    def test_hashes_mapped(self):
        gen = SPDXGenerator()
        result = gen.generate(_full_component_aibom())
        model = next(e for e in result["@graph"] if e.get("name") == "gpt-4o")
        assert "verifiedUsing" in model
        assert model["verifiedUsing"][0]["type"] == "Hash"


@pytest.mark.parametrize("fixture", ["example", "full", "empty"])
def test_portable_formats_validate_offline(fixture):
    directory = Path(__file__).parent
    bom = {
        "example": lambda: AIBOM.load(directory.parent / "examples/customer-support-agent.json"),
        "full": _full_component_aibom,
        "empty": AIBOM,
    }[fixture]()
    schemas = directory / "schemas"
    cdx_schema = json.loads((schemas / "bom-1.7.schema.json").read_text())
    registry = Registry()
    for file in ("jsf-0.82.schema.json", "spdx.schema.json"):
        sub = json.loads((schemas / file).read_text())
        registry = registry.with_resource(
            "http://cyclonedx.org/schema/" + file, Resource.from_contents(sub)
        )
    cdx = CycloneDXGenerator().generate(bom)
    Draft7Validator(
        cdx_schema, registry=registry, format_checker=Draft7Validator.FORMAT_CHECKER
    ).validate(cdx)
    spdx = SPDXGenerator().generate(bom)
    Draft202012Validator(
        json.loads((schemas / "spdx-json-schema-3.0.1.json").read_text()),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(spdx)
    identifiers = {n.get("spdxId", n.get("@id")) for n in spdx["@graph"]}
    for n in spdx["@graph"]:
        if "spdxId" in n:
            assert n["creationInfo"] in identifiers
        for ref in (
            n.get("element", [])
            + n.get("rootElement", [])
            + n.get("to", [])
            + n.get("createdBy", [])
        ):
            assert ref in identifiers
        if "from" in n:
            assert n["from"] in identifiers
        if "suppliedBy" in n:
            assert n["suppliedBy"] in identifiers


@pytest.mark.parametrize("generator", [SPDXGenerator, CycloneDXGenerator])
def test_rejects_invalid_digest_and_dangling_references(generator):
    bom = _sample_aibom()
    bom.components[0].hashes = {"sha256": "sha256:abc"}
    with pytest.raises(ValueError, match="invalid"):
        generator().generate(bom)
    bom.components[0].hashes = {}
    bom.add_dependency(
        DependencyEdge(source_ref="agent:main", target_ref="absent", relationship="invokes")
    )
    with pytest.raises(ValueError, match="unresolved"):
        generator().generate(bom)
