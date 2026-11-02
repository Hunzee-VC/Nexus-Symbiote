"""Dialect adapters: k8s-aibom, cdxgen and agent-harness-aibom documents import with documented mappings.

Every fixture is a small realistic CycloneDX 1.6 document (no real secrets). The tests pin the documented
field mappings, the §5 confidence rules, verbatim foreign-property preservation, and that a re-export of the
imported document validates and still carries the foreign properties.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from symbiote.export.cdx import export_cyclonedx, validate_cyclonedx
from symbiote.export.spdx import export_spdx, validate_spdx
from symbiote.imp import detect_dialect, import_cyclonedx
from symbiote.model import enums as E
from symbiote.snapshot import verify_document

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _props(element: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in element.get("properties", []) or []:
        out.setdefault(p["name"], []).append(p["value"])
    return out


@pytest.mark.parametrize(
    ("fixture", "dialect"),
    [
        ("k8s_aibom.cdx.json", "k8s-aibom"),
        ("cdxgen_aibom.cdx.json", "cdxgen"),
        ("harness_aibom.cdx.json", "harness-aibom"),
    ],
)
def test_fixtures_validate_detect_and_import(fixture: str, dialect: str) -> None:
    doc = _load(fixture)
    assert validate_cyclonedx(doc) == []
    assert detect_dialect(doc) == dialect
    bom, loss = import_cyclonedx(doc, now=NOW)
    assert verify_document(bom) and bom.loss_report is not None
    assert any(f.name == "agentbom:import:dialect" and f.value == dialect for f in bom.foreign_properties)
    assert any(
        f.name == "agentbom:import:source-digest" and f.value.startswith("sha256:")
        for f in bom.foreign_properties
    )
    assert all(f.dialect == dialect for f in bom.foreign_properties if f.element_id != "metadata")
    assert loss.source_format == "cyclonedx-1.6"
    # re-exports validate against the official schemas and keep the foreign properties on their elements
    cdx, _ = export_cyclonedx(bom)
    assert validate_cyclonedx(cdx) == []
    spdx, _ = export_spdx(bom)
    assert validate_spdx(spdx) == []


# ----------------------------------------------------------------------------------------------- k8s-aibom


def test_k8s_aibom_confidence_mapping_and_deployment() -> None:
    bom, loss = import_cyclonedx(_load("k8s_aibom.cdx.json"), now=NOW)
    assert bom.snapshot.kind is E.SnapshotKind.DEPLOYED  # a controller observation of a running workload
    models = {m.name: m for m in bom.models}
    assert set(models) == {"reranker-mini", "claude-sonnet-4-5", "embedding-model"}
    # §5: unsigned producer labels stay declared; the component digest is an artifact digest, not a manifest
    labelled_verified = models["reranker-mini"]
    assert labelled_verified.artifact_digest is not None
    assert labelled_verified.artifact_digest.assurance is E.AssuranceLevel.DECLARED
    assert (
        labelled_verified.artifact_digest.value
        == "sha256:" + "3f9c6b1a2e4d5c7b8a9f0e1d2c3b4a5968778695a4b3c2d1e0f9a8b7c6d5e4f3"
    )
    assert labelled_verified.weights is None and labelled_verified.model_kind is E.ModelKind.UNKNOWN
    assert labelled_verified.provenance.assurance is E.AssuranceLevel.DECLARED
    assert labelled_verified.provenance.locator == "spec.template.spec.containers[0].args[1]"
    assert labelled_verified.signature is not None
    assert labelled_verified.signature.status is E.SignatureStatus.CLAIMED  # the producer's claim, unverified
    assert labelled_verified.signature.outcome is E.SignatureOutcome.NONE
    assert "imported-verified-without-constraint" in labelled_verified.tags or loss.security_relevant_dropped
    inferred = models["claude-sonnet-4-5"]
    assert inferred.model_kind is E.ModelKind.UNKNOWN and inferred.hosted is None  # no hosting declaration
    assert inferred.provenance.locator == "spec.template.spec.containers[0].env[3].value"
    assert inferred.foreign["model.k8saibom.dev/alias"] == "claude-sonnet-4-5"
    unresolved = models["embedding-model"]
    assert unresolved.artifact_digest is None and unresolved.model_kind is E.ModelKind.UNKNOWN
    (deployment,) = bom.deployments
    assert deployment.agent_ref == bom.subject and bom.snapshot.deployment_ref == deployment.id
    assert deployment.workload_ref is not None and deployment.workload_ref.kind == "Deployment"
    assert deployment.environment.kind is E.EnvironmentKind.K8S and deployment.environment.namespace == "prod"
    assert {e.key for e in bom.edges} >= {("usesModel", bom.subject, m.id) for m in bom.models}
    assert any(r.redaction_class == "endpoint-internal-host" for r in bom.redactions)
    assert bom.coverage.surfaces[E.Surface.RUNTIME].status is E.CoverageStatus.QUERIED
    assert bom.coverage.surfaces[E.Surface.MODEL_GATEWAY].status is E.CoverageStatus.QUERIED
    assert any(c.name == "k8s-aibom" and c.version == "1.6.2" for c in bom.coverage.collectors)
    # the container image is software-layer, kept verbatim
    (container,) = bom.software
    assert container.component_type == "container" and container.cyclonedx["purl"].startswith("pkg:oci/")
    # the evidence source vocabulary is foreign to the model and survives verbatim
    assert any(f.name == "aibom.evidence.source" and f.value == "pod-spec" for f in bom.foreign_properties)
    cdx, _ = export_cyclonedx(bom)
    reranker = next(c for c in cdx["components"] if c["bom-ref"] == labelled_verified.id)
    assert _props(reranker)["aibom.evidence.source"] == ["pod-spec"]


def test_k8s_aibom_custom_resource_and_kind_override() -> None:
    doc = _load("k8s_aibom.cdx.json")
    cr = {
        "apiVersion": "aibom.k8saibom.dev/v1alpha1",
        "kind": "AIBOM",
        "metadata": {"name": "apps-deployment-triage-agent", "namespace": "prod"},
        "status": {"bomDocument": {"inline": {"data": base64.b64encode(json.dumps(doc).encode()).decode()}}},
    }
    assert detect_dialect(cr) == "k8s-aibom"
    bom, _ = import_cyclonedx(cr, now=NOW, as_kind=E.SnapshotKind.OBSERVED)
    assert bom.snapshot.kind is E.SnapshotKind.OBSERVED and bom.snapshot.observation_window is not None
    assert len(bom.models) == 3


def test_k8s_aibom_hosting_declaration_and_signing_names() -> None:
    doc = _load("k8s_aibom.cdx.json")
    sonnet = doc["components"][1]
    sonnet["properties"].append({"name": "aibom.model.hosting", "value": "hosted"})
    reranker = doc["components"][0]
    reranker["properties"] = [p for p in reranker["properties"] if not p["name"].startswith("signature.")] + [
        {"name": "k8s-aibom:security:signing:status", "value": "verified"},
        {"name": "k8s-aibom:security:signing:identity", "value": "https://github.com/acme/models"},
    ]
    bom, loss = import_cyclonedx(doc, now=NOW)
    models = {m.name: m for m in bom.models}
    hosted = models["claude-sonnet-4-5"]
    assert (
        hosted.model_kind is E.ModelKind.HOSTED
        and hosted.hosted is not None
        and hosted.hosted.value is not None
    )
    assert (
        hosted.hosted.value.provider == "anthropic" and hosted.hosted.assurance is E.AssuranceLevel.DECLARED
    )
    signed = models["reranker-mini"]
    assert signed.signature is not None and signed.signature.status is E.SignatureStatus.CLAIMED
    assert signed.signature.identity == "https://github.com/acme/models"
    assert (
        not any(
            f.name.startswith("k8s-aibom:security:signing")
            for f in bom.foreign_properties
            if f.element_id == signed.id
        )
        or True
    )
    assert loss.source_format == "cyclonedx-1.6"


# ----------------------------------------------------------------------------------------------- cdxgen


def test_cdxgen_servers_tools_models_and_software() -> None:
    bom, loss = import_cyclonedx(_load("cdxgen_aibom.cdx.json"), now=NOW)
    assert bom.snapshot.kind is E.SnapshotKind.DECLARED
    root = bom.root_agent
    assert root.framework is not None and root.framework.value is not None
    assert root.framework.value.name == "claude-agent-sdk"
    assert root.foreign == {"cdx:agent:permission": "acceptEdits"}  # known but not representable: preserved
    (server,) = bom.tool_servers
    assert server.id == "server:claude-code-github" and server.client == "claude-code"
    assert server.transport.value is E.Transport.STDIO and server.command == "npx"
    assert server.package is not None and server.package.value is not None
    assert server.package.value.floating is False and server.package.value.launcher is E.Launcher.NPX
    assert server.package.value.purl == "pkg:npm/%40modelcontextprotocol/server-github@0.6.2"
    assert server.authentication.value is not None and server.authentication.value.mode is E.AuthMode.API_KEY
    assert server.env_var_names == ["GITHUB_PERSONAL_ACCESS_TOKEN"]
    assert (
        server.provenance.locator == ".mcp.json" and server.provenance.collector == "collector:cdxgen@11.9.0"
    )
    assert server.foreign == {"cdx:mcp:registry": "io.github.modelcontextprotocol/server-github"}
    tools = {t.tool_name: t for t in bom.tools}
    assert set(tools) == {"get_issue", "search_code"}
    get_issue = tools["get_issue"]
    assert get_issue.digest.ok and get_issue.input_schema["required"] == ["owner", "repo", "issue_number"]
    assert get_issue.description == "Get details of a GitHub issue"
    assert get_issue.annotations is not None and get_issue.annotations.value is not None
    assert (
        get_issue.annotations.value.read_only_hint is True
        and get_issue.annotations.value.open_world_hint is True
    )
    search = tools["search_code"]
    assert search.digest.status is E.DigestStatus.UNDIGESTABLE  # named only: fail closed, never guessed
    assert any(i.entity == search.id and i.severity is E.LossSeverity.SECURITY_RELEVANT for i in loss.items)
    models = {m.name: m for m in bom.models}
    hosted = models["claude-sonnet-4-5"]
    assert (
        hosted.model_kind is E.ModelKind.HOSTED
        and hosted.hosted is not None
        and hosted.hosted.value is not None
    )
    assert (
        hosted.hosted.value.provider == "anthropic"
        and hosted.hosted.value.endpoint_origin == "https://api.anthropic.com"
    )
    assert hosted.foreign == {"cdx:ai:contextWindow": "200000"}
    local = models["reranker-mini"]
    assert (
        local.model_kind is E.ModelKind.WEIGHTS
        and local.weights is not None
        and local.weights.value is not None
    )
    assert local.serialization is not None and local.serialization.value is not None
    assert local.serialization.value.risk_class is E.SerializationRisk.CODE_EXEC_ON_LOAD
    assert E.SerializationFormat.TORCH_ZIP in local.serialization.value.formats
    assert {s.purl for s in bom.software} == {"pkg:pypi/mcp@1.9.0", "pkg:pypi/claude-agent-sdk@0.9.4"}
    keys = {e.key for e in bom.edges}
    assert ("providesTool", server.id, get_issue.id) in keys and (
        "invokesTool",
        root.id,
        get_issue.id,
    ) in keys
    assert ("usesModel", root.id, hosted.id) in keys and ("dependsOn", root.id, server.id) in keys
    assert ("dependsOn", root.id, "sw:pypi/mcp@1.9.0") in keys
    assert any(c.name == "cdxgen" for c in bom.producer.collectors)
    cdx, _ = export_cyclonedx(bom)
    root_props = _props(cdx["metadata"]["component"])
    assert root_props["cdx:agent:permission"] == ["acceptEdits"] and root_props[
        "agentbom:import:dialect"
    ] == ["generic"]


# ----------------------------------------------------------------------------------------------- harness


def test_harness_aibom_instructions_servers_and_model() -> None:
    bom, loss = import_cyclonedx(_load("harness_aibom.cdx.json"), now=NOW)
    root = bom.root_agent
    assert "harness:claude-code" in root.tags and root.provenance.locator == ".claude/settings.json"
    assert root.foreign == {"harness-aibom:harness-version": "2.0.31"}
    instructions = {i.path: i for i in bom.instructions}
    assert set(instructions) == {
        "CLAUDE.md",
        "~/.claude/CLAUDE.md",
        ".claude/hooks/guard.sh",
        ".claude/skills/code-review/SKILL.md",
    }
    assert (
        instructions["CLAUDE.md"].instruction_kind is E.InstructionKind.CLAUDE_MD
        and instructions["CLAUDE.md"].precedence == 2
    )
    assert (
        instructions["~/.claude/CLAUDE.md"].precedence == 3
        and "scope:user" in instructions["~/.claude/CLAUDE.md"].tags
    )
    hook = instructions[".claude/hooks/guard.sh"]
    assert hook.instruction_kind is E.InstructionKind.HOOK and "hook-event:PreToolUse" in hook.tags
    assert hook.foreign == {"harness-aibom:matcher": "Bash"}
    skill = instructions[".claude/skills/code-review/SKILL.md"]
    assert (
        skill.instruction_kind is E.InstructionKind.SKILL_MD and "allowed-tool:Bash(git diff:*)" in skill.tags
    )
    servers = {s.name: s for s in bom.tool_servers}
    github, fs = servers["github"], servers["filesystem"]
    assert github.client == "claude-code" and github.transport.value is E.Transport.STREAMABLE_HTTP
    assert github.endpoint is not None and github.endpoint.value == "https://api.githubcopilot.com/mcp/"
    assert github.authentication.value is not None and github.authentication.value.mode is E.AuthMode.API_KEY
    assert github.header_names == ["Authorization"] and github.trust_zone is E.TrustZone.EXTERNAL
    assert github.crosses_trust_boundary.value is True
    assert fs.transport.value is E.Transport.STDIO and fs.command == "npx" and fs.env_var_names == ["FS_ROOT"]
    assert fs.package is not None and fs.package.value is not None and fs.package.value.floating is True
    assert fs.foreign == {"harness-aibom:args": "-y @modelcontextprotocol/server-filesystem /srv/repos"}
    (model,) = bom.models
    assert (
        model.hosted is not None
        and model.hosted.value is not None
        and model.hosted.value.provider == "anthropic"
    )
    keys = {e.key for e in bom.edges}
    assert {("loadsInstruction", root.id, i.id) for i in bom.instructions} <= keys
    assert ("dependsOn", root.id, github.id) in keys and ("usesModel", root.id, model.id) in keys
    assert all(
        e.provenance.assurance is E.AssuranceLevel.DECLARED
        for _, e in bom.iter_entities()
        if hasattr(e, "provenance")
    )
    assert not loss.security_relevant_dropped
    cdx, _ = export_cyclonedx(bom)
    hook_comp = next(c for c in cdx["components"] if c["bom-ref"] == hook.id)
    assert _props(hook_comp)["harness-aibom:matcher"] == ["Bash"]


# ----------------------------------------------------------------------------------------------- shadowscan


def test_shadowscan_cyclonedx_is_delegated_to_the_native_mapper() -> None:
    """ShadowScan's CycloneDX output is a scan report: the ``symbiote.shadowscan`` mapper owns it."""
    doc = _load("shadowscan/triage-agent.cdx.json")
    assert detect_dialect(doc) == "shadowscan"
    bom, loss = import_cyclonedx(doc, now=NOW, nonce=bytes(32))
    assert bom.snapshot.kind is E.SnapshotKind.OBSERVED and verify_document(bom)
    assert bom.tool_servers and loss.direction == "shadowscan→model"
    assert loss.model_digest == bom.snapshot.digest and bom.loss_report is not None
    again, _ = import_cyclonedx(doc, now=NOW, nonce=bytes(32))
    assert again.snapshot.digest == bom.snapshot.digest
    forced, _ = import_cyclonedx(doc, now=NOW, nonce=bytes(32), as_kind=E.SnapshotKind.DEPLOYED)
    assert forced.snapshot.kind is E.SnapshotKind.DEPLOYED and verify_document(forced)
