"""Tests for CycloneDX and SPDX generators."""

from __future__ import annotations

import json

from symbote.core.aibom import AIBOM, DependencyEdge
from symbote.core.models import (
    AgentComponent,
    MCPServerComponent,
    ModelComponent,
    ToolComponent,
)
from symbote.generators.cyclonedx import CycloneDXGenerator
from symbote.generators.spdx import SPDXGenerator


def _sample_aibom() -> AIBOM:
    bom = AIBOM()
    bom.add_component(AgentComponent(
        bom_ref="agent:main",
        name="my-agent",
        framework="langchain",
        model_refs=["model:gpt-4o"],
        tool_refs=["tool:read_file"],
    ))
    bom.add_component(ModelComponent(
        bom_ref="model:gpt-4o",
        name="gpt-4o",
        provider="openai",
        serialization_format="api",
        signing_status="n/a",
    ))
    bom.add_component(ToolComponent(
        bom_ref="tool:read_file",
        name="read_file",
        description_text="Reads a file",
        definition_hash="sha256:abc123",
    ))
    bom.add_component(MCPServerComponent(
        bom_ref="mcp:fs",
        name="@modelcontextprotocol/server-filesystem",
        transport="stdio",
        tool_count=3,
        version_pinned=True,
    ))
    bom.add_dependency(DependencyEdge(
        source_ref="agent:main",
        target_ref="tool:read_file",
        relationship="invokes",
    ))
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
        assert "symbote:componentType" in prop_names
        assert "symbote:autonomyLevel" in prop_names

    def test_model_properties(self):
        gen = CycloneDXGenerator()
        result = gen.generate(_sample_aibom())
        model_comp = next(c for c in result["components"] if c["name"] == "gpt-4o")
        props = {p["name"]: p["value"] for p in model_comp.get("properties", [])}
        assert props.get("symbote:provider") == "openai"

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
        assert tools[0]["name"] == "symbote"


class TestSPDXGenerator:
    def test_generate_structure(self):
        gen = SPDXGenerator()
        result = gen.generate(_sample_aibom())
        assert result["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
        graph = result["@graph"]
        doc = graph[0]
        assert doc["type"] == "SpdxDocument"
        assert doc["specVersion"] == "3.0.1"

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
        ids = [e["spdxId"] for e in result["@graph"]]
        assert len(ids) == len(set(ids))

    def test_extensions_present(self):
        gen = SPDXGenerator()
        result = gen.generate(_sample_aibom())
        elements = [e for e in result["@graph"][1:] if e.get("type") != "Relationship"]
        for elem in elements:
            if "extension" in elem:
                ext = elem["extension"][0]
                assert ext["specVersion"] == "symbote-1.0.0"
                assert "symbote:componentType" in ext["properties"]

    def test_relationship_types(self):
        gen = SPDXGenerator()
        result = gen.generate(_sample_aibom())
        rels = [e for e in result["@graph"] if e.get("type") == "Relationship"]
        assert len(rels) == 1
        assert rels[0]["relationshipType"] == "DEPENDS_ON"

    def test_generate_json_valid(self):
        gen = SPDXGenerator()
        json_str = gen.generate_json(_sample_aibom())
        data = json.loads(json_str)
        assert "@context" in data
