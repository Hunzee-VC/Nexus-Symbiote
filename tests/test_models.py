"""Tests for core domain models, enums, hashing, and AIBOM document."""

from __future__ import annotations

import json

from symbote.core.aibom import AIBOM, DependencyEdge
from symbote.core.enums import (
    SERIALIZATION_FORMAT_SAFETY,
    AutonomyLevel,
    CapabilityClass,
    ComponentType,
    RiskSeverity,
    SerializationSafety,
    TrustTier,
)
from symbote.core.hashing import (
    canonical_json,
    extract_version_pin,
    hash_bytes,
    hash_canonical,
    hash_tool_definition,
)
from symbote.core.models import (
    AgentComponent,
    AIBOMMetadata,
    AuthorizationRecord,
    CapabilityDeclaration,
    CompletenessClaim,
    MCPServerComponent,
    ModelComponent,
    RiskAssessment,
    ToolComponent,
)


class TestEnums:
    def test_component_types_complete(self):
        assert len(ComponentType) >= 11

    def test_risk_severity_ordering(self):
        severities = list(RiskSeverity)
        assert RiskSeverity.CRITICAL in severities
        assert RiskSeverity.INFO in severities

    def test_serialization_safety_map(self):
        assert SERIALIZATION_FORMAT_SAFETY["safetensors"] == SerializationSafety.SAFE
        assert SERIALIZATION_FORMAT_SAFETY["pickle"] == SerializationSafety.UNSAFE_CODE_EXECUTION

    def test_trust_tier_values(self):
        assert TrustTier.INTERNAL_VERIFIED.value == "internal-verified"
        assert TrustTier.UNTRUSTED_PUBLIC.value == "untrusted-public"

    def test_autonomy_levels(self):
        assert AutonomyLevel.L0_CHATBOT.value == "L0-chatbot"
        assert AutonomyLevel.L4_FULLY_AUTONOMOUS.value == "L4-fully-autonomous"


class TestModels:
    def test_agent_component_defaults(self):
        agent = AgentComponent(bom_ref="agent:main", name="my-agent")
        assert agent.component_type == ComponentType.AGENT
        assert agent.autonomy_level == AutonomyLevel.L2_AGENT
        assert agent.trust_tier == TrustTier.UNKNOWN

    def test_tool_component(self):
        tool = ToolComponent(
            bom_ref="tool:read_file",
            name="read_file",
            description_text="Reads a file from disk",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
            definition_hash="sha256:abc123",
        )
        assert tool.component_type == ComponentType.TOOL
        assert tool.definition_hash == "sha256:abc123"

    def test_model_component_serialization_safety(self):
        model = ModelComponent(
            bom_ref="model:weights.pt",
            name="weights.pt",
            serialization_format="pytorch",
            serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION,
        )
        assert model.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION

    def test_mcp_server_component(self):
        mcp = MCPServerComponent(
            bom_ref="mcp:filesystem",
            name="@modelcontextprotocol/server-filesystem",
            transport="stdio",
            tool_count=5,
            version_pinned=True,
        )
        assert mcp.transport == "stdio"
        assert mcp.version_pinned is True

    def test_risk_assessment(self):
        risk = RiskAssessment(
            severity=RiskSeverity.CRITICAL,
            category="serialization_format",
            detail="Uses pickle",
            recommendation="Switch to SafeTensors",
        )
        assert risk.severity == RiskSeverity.CRITICAL

    def test_capability_declaration(self):
        cap = CapabilityDeclaration(
            capabilities=[CapabilityClass.FILESYSTEM, CapabilityClass.NETWORK],
            egress_domains=["api.example.com"],
        )
        assert len(cap.capabilities) == 2

    def test_authorization_record(self):
        auth = AuthorizationRecord(
            principal="admin@org.com",
            action="invoke",
            resource_scope="production",
            approval_required=True,
        )
        assert auth.approval_required is True

    def test_completeness_claim(self):
        claim = CompletenessClaim(
            scope="full-agent",
            surfaces_scanned=["mcp", "models"],
            surfaces_excluded=["rag"],
        )
        assert claim.scope == "full-agent"

    def test_metadata_defaults(self):
        meta = AIBOMMetadata()
        assert meta.spec_version == "1.0.0"
        assert meta.tool_name == "symbote"

    def test_model_roundtrip(self):
        agent = AgentComponent(
            bom_ref="agent:test",
            name="test",
            framework="langchain",
            model_refs=["model:gpt-4o"],
            risks=[
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="test",
                    detail="test detail",
                )
            ],
        )
        data = agent.model_dump(mode="json", exclude_none=True)
        restored = AgentComponent.model_validate(data)
        assert restored.bom_ref == "agent:test"
        assert len(restored.risks) == 1


class TestHashing:
    def test_canonical_json_key_ordering(self):
        result = canonical_json({"b": 1, "a": 2})
        assert result == '{"a":2,"b":1}'

    def test_canonical_json_nested(self):
        result = canonical_json({"z": {"b": 1, "a": 2}, "a": "x"})
        assert result == '{"a":"x","z":{"a":2,"b":1}}'

    def test_canonical_json_string_escaping(self):
        result = canonical_json({"k": 'hello\nworld"!'})
        assert '\\n' in result
        assert '\\"' in result

    def test_canonical_json_null_handling(self):
        result = canonical_json({"a": None, "b": 1})
        assert '"a"' not in result

    def test_canonical_json_float(self):
        result = canonical_json({"v": 1.0})
        assert result == '{"v":1}'

    def test_canonical_json_nan(self):
        result = canonical_json({"v": float("nan")})
        assert result == '{"v":null}'

    def test_hash_canonical_deterministic(self):
        h1 = hash_canonical({"b": 1, "a": 2})
        h2 = hash_canonical({"a": 2, "b": 1})
        assert h1 == h2

    def test_hash_canonical_format(self):
        h = hash_canonical({"x": 1})
        assert h.startswith("sha256:")
        assert len(h.split(":")[1]) == 64

    def test_hash_tool_definition(self):
        h = hash_tool_definition("read_file", "Reads a file", {"type": "object"})
        assert h.startswith("sha256:")

    def test_hash_tool_definition_sensitive_to_changes(self):
        h1 = hash_tool_definition("read_file", "Reads a file")
        h2 = hash_tool_definition("read_file", "Reads a file from disk")
        assert h1 != h2

    def test_hash_bytes(self):
        h = hash_bytes(b"hello world")
        assert h.startswith("sha256:")

    def test_extract_version_pin(self):
        assert extract_version_pin("@modelcontextprotocol/server-filesystem@1.2.3") == "1.2.3"
        assert extract_version_pin("package@latest") is None
        assert extract_version_pin("package:latest") is None


class TestAIBOM:
    def test_empty_aibom(self):
        bom = AIBOM()
        assert len(bom.components) == 0
        assert len(bom.dependencies) == 0

    def test_add_component(self):
        bom = AIBOM()
        tool = ToolComponent(bom_ref="tool:test", name="test")
        bom.add_component(tool)
        assert len(bom.components) == 1
        assert bom.get_component("tool:test") is not None

    def test_add_component_replaces_existing(self):
        bom = AIBOM()
        v1 = ToolComponent(bom_ref="tool:test", name="test-v1")
        v2 = ToolComponent(bom_ref="tool:test", name="test-v2")
        bom.add_component(v1)
        bom.add_component(v2)
        assert len(bom.components) == 1
        assert bom.get_component("tool:test").name == "test-v2"

    def test_get_components_by_type(self):
        bom = AIBOM()
        bom.add_component(ToolComponent(bom_ref="tool:a", name="a"))
        bom.add_component(ToolComponent(bom_ref="tool:b", name="b"))
        bom.add_component(ModelComponent(bom_ref="model:c", name="c"))
        tools = bom.get_components_by_type(ComponentType.TOOL)
        assert len(tools) == 2

    def test_add_dependency(self):
        bom = AIBOM()
        edge = DependencyEdge(source_ref="agent:main", target_ref="tool:read", relationship="invokes")
        bom.add_dependency(edge)
        assert len(bom.dependencies) == 1

    def test_get_all_risks(self):
        bom = AIBOM()
        bom.add_component(ToolComponent(
            bom_ref="tool:test",
            name="test",
            risks=[
                RiskAssessment(severity=RiskSeverity.HIGH, category="test", detail="d1"),
                RiskAssessment(severity=RiskSeverity.LOW, category="test", detail="d2"),
            ],
        ))
        risks = bom.get_all_risks()
        assert len(risks) == 2

    def test_finalize_sets_metadata(self):
        bom = AIBOM()
        bom.finalize()
        assert bom.metadata.timestamp is not None
        assert bom.metadata.serial_number is not None
        assert bom.metadata.serial_number.startswith("urn:uuid:")

    def test_to_json_roundtrip(self):
        bom = AIBOM()
        bom.add_component(ToolComponent(bom_ref="tool:x", name="x"))
        json_str = bom.to_json()
        data = json.loads(json_str)
        assert data["metadata"]["tool_name"] == "symbote"
        assert len(data["components"]) == 1

    def test_save_and_load(self, tmp_path):
        bom = AIBOM()
        bom.add_component(ToolComponent(bom_ref="tool:x", name="x"))
        path = tmp_path / "test.aibom.json"
        bom.save(path)
        loaded = AIBOM.load(path)
        assert len(loaded.components) == 1
        assert loaded.get_component("tool:x").name == "x"

    def test_summary(self):
        bom = AIBOM()
        bom.add_component(ToolComponent(
            bom_ref="tool:x",
            name="x",
            risks=[RiskAssessment(severity=RiskSeverity.HIGH, category="test", detail="d")],
        ))
        s = bom.summary()
        assert s["total_components"] == 1
        assert s["total_risks"] == 1
        assert "high" in s["risk_breakdown"]
