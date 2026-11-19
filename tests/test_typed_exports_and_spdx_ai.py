"""Tests for CycloneDX projection 3, SPDX 3.0.1 AI/Dataset projection 4, ISO 22989, and agent.yaml 1.1."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from spdx_python_model import v3_0_1 as spdx

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import AssuranceLevel, AutonomyLevel, TrustTier
from nexus_symbiote.core.models import (
    A2AServerComponent,
    AgentComponent,
    ClaimEvidence,
    CompletenessClaim,
    DataSourceComponent,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    RAGSourceComponent,
    RegistryEntryComponent,
    SkillPackageComponent,
    ToolComponent,
)
from nexus_symbiote.generators.cyclonedx import (
    PROJECTION,
    PROJECTION_V3_16,
    PROJECTION_V3_17,
    CycloneDXGenerator,
)
from nexus_symbiote.generators.spdx import PROJECTION as SPDX_V3
from nexus_symbiote.generators.spdx import PROJECTION_V4, SPDXGenerator
from nexus_symbiote.spdx_profiles import (
    ISO_22989_AUTOMATION_TABLE,
    apply_agent_yaml_declarations,
    resolve_automation_mapping,
)


def _rich_aibom() -> AIBOM:
    ts = datetime(2026, 11, 19, 0, 0, 0, tzinfo=UTC)
    agent = AgentComponent(
        bom_ref="agent:repo",
        name="customer-support-agent",
        version="1.2.0",
        supplier="Acme AI",
        autonomy_level=AutonomyLevel.L2_AGENT,
        source_path="agent.yaml",
        assurance_level=AssuranceLevel.OBSERVED,
        properties={
            "inferred_subject": True,
            "declared_license": "Apache-2.0",
            "declared_release_time": "2026-11-01T00:00:00Z",
            "declared_download_location": "https://example.com/agents/customer-support-1.2.0.tar.gz",
            "declared_domain": "customer-support",
            "declared_compliance": ["ISO/IEC 42001:2023"],
            "source_line": 12,
        },
    )
    base_model = ModelComponent(
        bom_ref="model:base",
        name="llama-3-8b",
        version="3.0.0",
        supplier="Meta",
        model_type="transformer",
        assurance_level=AssuranceLevel.OBSERVED,
        properties={
            "declared_license": "Apache-2.0",
            "declared_release_time": "2026-06-01T00:00:00Z",
            "declared_download_location": "https://huggingface.co/meta-llama/Llama-3-8B",
            "declared_domain": "text-generation",
        },
    )
    tuned_model = ModelComponent(
        bom_ref="model:tuned",
        name="support-llama-8b-ft",
        version="1.0.0",
        supplier="Acme AI",
        model_type="transformer",
        source_path="models/support.safetensors",
        hashes={"sha256": "a" * 64},
        signing_status="sigstore-signed",
        assurance_level=AssuranceLevel.VERIFIED,
        trust_tier=TrustTier.THIRD_PARTY_SIGNED,
        claims={
            "locator": ClaimEvidence(
                assurance=AssuranceLevel.OBSERVED,
                method="model-collector",
                scope="artifact",
                locator="models/support.safetensors:42",
            )
        },
        properties={
            "declared_license": "Apache-2.0",
            "declared_release_time": "2026-10-15T00:00:00Z",
            "declared_download_location": "https://example.com/models/support.safetensors",
            "declared_domain": "customer-support",
            "declared_limitations": "English ticket triage only.",
        },
    )
    dataset = DataSourceComponent(
        bom_ref="dataset:tickets",
        name="support-tickets-2026",
        version="2026.10",
        supplier="Acme Data",
        dataset_type="text",
        source_uri="https://example.com/datasets/support-tickets-2026.parquet",
        collection_date="2026-10-01T00:00:00Z",
        license="CC-BY-4.0",
        assurance_level=AssuranceLevel.DECLARED,
        properties={
            "declared_release_time": "2026-10-01T00:00:00Z",
            "declared_download_location": "https://example.com/datasets/support-tickets-2026.parquet",
            "declared_license": "CC-BY-4.0",
            "declared_availability": "directDownload",
            "declared_sensitive_pii": "no",
        },
    )
    mcp_srv = MCPServerComponent(
        bom_ref="mcp:docs",
        name="docs-mcp",
        version="2.1.0",
        transport="streamable-http",
        endpoint_url="https://mcp.example.com/v1",
        version_pinned=True,
        assurance_level=AssuranceLevel.OBSERVED,
    )
    tool = ToolComponent(
        bom_ref="tool:search_docs",
        name="search_docs",
        version="2.1.0",
        definition_hash="sha256:" + "b" * 64,
        assurance_level=AssuranceLevel.OBSERVED,
    )
    a2a_srv = A2AServerComponent(
        bom_ref="a2a:billing",
        name="billing-specialist",
        version="1.0.0",
        endpoint_url="https://a2a.example.com/billing",
        authentication_required=True,
        assurance_level=AssuranceLevel.OBSERVED,
    )
    rag = RAGSourceComponent(
        bom_ref="rag:kb",
        name="kb-index",
        version="2026.10",
        supplier="Acme Data",
        corpus_type="vector-db",
        assurance_level=AssuranceLevel.OBSERVED,
        properties={
            "declared_release_time": "2026-10-01T00:00:00Z",
            "declared_download_location": "https://example.com/rag/kb-index",
            "declared_license": "CC-BY-4.0",
        },
    )
    skill = SkillPackageComponent(
        bom_ref="skill:triage",
        name="ticket-triage-skill",
        version="0.4.0",
        assurance_level=AssuranceLevel.OBSERVED,
    )
    prompt = PromptComponent(
        bom_ref="prompt:sys",
        name="system-prompt",
        content_hash="sha256:" + "c" * 64,
        assurance_level=AssuranceLevel.OBSERVED,
    )
    pkg = RegistryEntryComponent(
        bom_ref="pkg:openai",
        name="openai",
        version="1.52.0",
        registry_type="pypi",
        package_url="pkg:pypi/openai@1.52.0",
        assurance_level=AssuranceLevel.OBSERVED,
    )

    bom = AIBOM(
        components=[
            agent,
            base_model,
            tuned_model,
            dataset,
            mcp_srv,
            tool,
            a2a_srv,
            rag,
            skill,
            prompt,
            pkg,
        ],
        dependencies=[
            DependencyEdge(
                source_ref="agent:repo", target_ref="model:tuned", relationship="uses-model"
            ),
            DependencyEdge(
                source_ref="agent:repo", target_ref="a2a:billing", relationship="delegates-to"
            ),
            DependencyEdge(
                source_ref="agent:repo", target_ref="rag:kb", relationship="retrieves-from"
            ),
            DependencyEdge(
                source_ref="agent:repo", target_ref="skill:triage", relationship="loads-skill"
            ),
            DependencyEdge(
                source_ref="agent:repo", target_ref="prompt:sys", relationship="configured-with"
            ),
            DependencyEdge(
                source_ref="agent:repo", target_ref="tool:search_docs", relationship="invokes"
            ),
            DependencyEdge(
                source_ref="agent:repo", target_ref="pkg:openai", relationship="depends-on"
            ),
            DependencyEdge(
                source_ref="mcp:docs", target_ref="tool:search_docs", relationship="provides-tool"
            ),
            DependencyEdge(
                source_ref="model:tuned", target_ref="dataset:tickets", relationship="trained-on"
            ),
            DependencyEdge(
                source_ref="model:tuned", target_ref="model:base", relationship="fine-tuned-from"
            ),
        ],
    )
    bom.metadata.timestamp = ts
    bom.metadata.authors = ["Platform Security Team"]
    bom.metadata.completeness = CompletenessClaim(
        scope="repository",
        collectors_requested=["mcp", "model"],
        collectors_completed=["mcp", "model"],
        scanner_status={"mcp": "complete", "model": "complete"},
    )
    return bom


def test_cyclonedx_projection_v3_standard_fields_schema_and_roundtrip() -> None:
    bom = _rich_aibom()
    doc_v2 = CycloneDXGenerator().generate(bom)
    assert any(
        p == {"name": "nexus-symbiote:projection", "value": PROJECTION}
        for p in doc_v2["metadata"]["properties"]
    )
    assert "services" not in doc_v2

    for spec_ver, expected_marker, schema_ver in (
        ("1.7", PROJECTION_V3_17, SchemaVersion.V1_7),
        ("1.6", PROJECTION_V3_16, SchemaVersion.V1_6),
    ):
        gen = CycloneDXGenerator(projection_version=3, spec_version=spec_ver)
        raw_json = gen.generate_json(bom)
        validator = JsonStrictValidator(schema_ver)
        validation_errors = validator.validate_str(raw_json)
        assert validation_errors is None, f"CycloneDX {spec_ver} schema error: {validation_errors}"

        doc = json.loads(raw_json)
        assert any(
            p == {"name": "nexus-symbiote:projection", "value": expected_marker}
            for p in doc["metadata"]["properties"]
        )

        dep_pairs = {
            (row["ref"], target)
            for row in doc["dependencies"]
            for target in row.get("dependsOn", [])
        }
        assert len(dep_pairs) == 10

        service_urls = {ep for svc in doc["services"] for ep in svc["endpoints"]}
        assert "https://mcp.example.com/v1" in service_urls
        assert "https://a2a.example.com/billing" in service_urls

        tuned = next(c for c in doc["components"] if c["bom-ref"] == "model:tuned")
        assert tuned["evidence"]["occurrences"] == [
            {"location": "models/support.safetensors", "line": 42}
        ]
        assert tuned["licenses"] == [{"license": {"name": "Apache-2.0"}}]
        assert tuned["pedigree"]["ancestors"] == [
            {"type": "machine-learning-model", "name": "llama-3-8b", "version": "3.0.0"}
        ]
        assert tuned["modelCard"]["modelParameters"]["datasets"] == [{"ref": "dataset:tickets"}]
        assert tuned["modelCard"]["modelParameters"]["task"] == "customer-support"
        assert tuned["modelCard"]["considerations"]["technicalLimitations"] == [
            "English ticket triage only."
        ]

        recovered = CycloneDXGenerator.recover(doc)
        assert len(recovered.components) == len(bom.components)
        assert len(recovered.dependencies) == len(bom.dependencies)

        tampered = json.loads(raw_json)
        tampered["services"][0]["endpoints"] = ["https://evil.example.com/mcp"]
        with pytest.raises(ValueError, match="conflicts with the embedded native document"):
            CycloneDXGenerator.recover(tampered)


def test_spdx_projection_v4_typed_relationships_profiles_and_deserializer() -> None:
    bom = _rich_aibom()
    doc_v3 = SPDXGenerator(namespace="https://example.com/spdx").generate(bom)
    spdx_doc_v3 = next(item for item in doc_v3["@graph"] if item["type"] == "SpdxDocument")
    v3_props = {
        p["extension_cdxPropName"]: p["extension_cdxPropValue"]
        for p in spdx_doc_v3["extension"][0]["extension_cdxProperty"]
    }
    assert v3_props["nexus-symbiote:projection"] == SPDX_V3

    gen_v4 = SPDXGenerator(namespace="https://example.com/spdx", projection_version=4)
    raw_v4 = gen_v4.generate_json(bom)
    doc_v4 = json.loads(raw_v4)

    spdx_doc = next(item for item in doc_v4["@graph"] if item["type"] == "SpdxDocument")
    v4_props = {
        p["extension_cdxPropName"]: p["extension_cdxPropValue"]
        for p in spdx_doc["extension"][0]["extension_cdxProperty"]
    }
    assert v4_props["nexus-symbiote:projection"] == PROJECTION_V4
    assert "ai" in spdx_doc["profileConformance"]
    assert "dataset" in spdx_doc["profileConformance"]
    assert "simpleLicensing" in spdx_doc["profileConformance"]

    persons = [item for item in doc_v4["@graph"] if item["type"] == "Person"]
    assert len(persons) == 1
    assert persons[0]["name"] == "Platform Security Team"

    rel_types = {
        item["relationshipType"] for item in doc_v4["@graph"] if item["type"] == "Relationship"
    }
    assert {
        "delegatedTo",
        "trainedOn",
        "descendantOf",
        "configures",
        "usesTool",
        "hasProvidedDependency",
        "dependsOn",
    } <= rel_types

    object_set = spdx.SHACLObjectSet()
    deserializer = spdx.JSONLDDeserializer()
    deserializer.read(io.StringIO(raw_v4), object_set)
    ai_pkgs = list(object_set.foreach_type(spdx.ai_AIPackage))
    ds_pkgs = list(object_set.foreach_type(spdx.dataset_DatasetPackage))
    assert len(ai_pkgs) == 3
    assert len(ds_pkgs) == 2

    recovered = SPDXGenerator.recover(doc_v4)
    assert len(recovered.components) == len(bom.components)

    incomplete_bom = _rich_aibom()
    for comp in incomplete_bom.components:
        comp.properties.pop("declared_release_time", None)
    doc_incomplete = gen_v4.generate(incomplete_bom)
    spdx_incomplete = next(
        item for item in doc_incomplete["@graph"] if item["type"] == "SpdxDocument"
    )
    assert "ai" not in spdx_incomplete["profileConformance"]


def test_iso_22989_automation_table_agent_yaml_and_export_standard_cli(tmp_path: Path) -> None:
    assert len(ISO_22989_AUTOMATION_TABLE) == 6
    mapped_l0 = resolve_automation_mapping("L0")
    assert mapped_l0 is not None and mapped_l0.spdx_autonomy_presence == "no"
    mapped_0 = resolve_automation_mapping(0)
    assert mapped_0 is not None and mapped_0.iso_name == "no_automation"
    for level in (1, 2, 3, 4, 5):
        mapped = resolve_automation_mapping(level)
        assert mapped is not None and mapped.spdx_autonomy_presence == "yes"
    for level_str in ("L1", "L2", "L3", "L4"):
        mapped = resolve_automation_mapping(level_str)
        assert mapped is not None and mapped.spdx_autonomy_presence == "yes"

    (tmp_path / "agent.yaml").write_text(
        """
name: customer-support-agent
version: 9.9.9
owner: Different Owner
automation_level: full_automation
licenses:
  - Apache-2.0
data_usage: no-training-on-customer-inputs
compliance:
  - EU-AI-Act-Art-53
allowed_regions:
  - eu-west-1
datasets:
  - name: eval-golden-set
    version: "1.0"
    dataset_type: evaluation
    license: MIT
    download_location: https://example.com/eval.jsonl
    release_time: 2026-11-01
models:
  - name: support-llama-8b-ft
    version: "2.0.0"
    license: MIT
    training:
      description: LoRA fine-tune
      datasets:
        - eval-golden-set
""",
        encoding="utf-8",
    )
    bom = _rich_aibom()
    notices = apply_agent_yaml_declarations(bom, tmp_path)
    assert len(notices) >= 3

    agent = bom.get_component("agent:repo")
    assert agent is not None
    assert agent.version == "1.2.0"
    assert agent.supplier == "Acme AI"
    assert any(r.category == "declaration_conflict" for r in agent.risks)

    eval_ds = next(c for c in bom.components if c.name == "eval-golden-set")
    assert eval_ds.assurance_level == AssuranceLevel.DECLARED
    assert any(
        e.source_ref == "model:tuned"
        and e.target_ref == eval_ds.bom_ref
        and e.relationship == "trained-on"
        for e in bom.dependencies
    )

    bom_path = tmp_path / "aibom.json"
    _rich_aibom().save(bom_path)
    spdx_out = tmp_path / "out.spdx.json"
    res = CliRunner().invoke(
        main,
        [
            "export-standard",
            str(bom_path),
            "-f",
            "spdx",
            "--spdx-projection",
            "4",
            "--spdx-namespace",
            "https://example.com/ns",
            "--author",
            "Jane Doe",
            "--project",
            str(tmp_path),
            "--agent-yaml",
            "agent.yaml",
            "-o",
            str(spdx_out),
        ],
    )
    assert res.exit_code == 0, res.output
    spdx_doc = json.loads(spdx_out.read_text(encoding="utf-8"))
    person_names = {el["name"] for el in spdx_doc["@graph"] if el["type"] == "Person"}
    assert "Jane Doe" in person_names
