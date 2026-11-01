from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from typer.testing import CliRunner

from symbiote.attest.dsse import KeyRing, generate_signing_key, sign_envelope, verify_envelope
from symbiote.cli import app
from symbiote.collect import CollectContext
from symbiote.collect.mcp_config import McpConfigCollector
from symbiote.model import AgentBOM, Claim
from symbiote.model import enums as E
from symbiote.model.entities import DataSource, SnapshotCommitment, SourceRun, SurfaceCoverage
from symbiote.policy import completeness_score, evaluate_conformance
from symbiote.scan import scan
from symbiote.snapshot import diff, finalize, redact_entities, verify_document


def test_signature_threshold_counts_distinct_trusted_keys() -> None:
    key, other = generate_signing_key("ed25519"), generate_signing_key("ed25519")
    ring = KeyRing.from_public_keys([key.public_key(), other.public_key()])
    single = sign_envelope(b"test", "application/octet-stream", key)
    duplicated = single.replace(signatures=single.signatures * 2)
    with pytest.raises(InvalidSignature):
        verify_envelope(duplicated, ring, threshold=2)
    with pytest.raises(ValueError):
        verify_envelope(single.replace(signatures=[]), ring, threshold=0)
    both = sign_envelope(b"test", single.payload_type, other, duplicated)
    assert len(verify_envelope(both, ring, threshold=2)[1]) == 2


def test_commitment_requires_exact_disclosure(minimal_bom: AgentBOM) -> None:
    bom = finalize(minimal_bom.replace(edges=[]))
    extra = bom.tools[0].replace(id="tool:github/new")
    assert not verify_document(bom.replace(tools=[*bom.tools, extra]))
    assert not verify_document(bom.replace(tools=[]))
    redacted = redact_entities(bom, {bom.tools[0].id}, applied_by="a", redaction_class="tool-text")
    assert verify_document(redacted)
    assert not verify_document(redacted.replace(redacted=[]))
    placeholder = redacted.redacted[0]
    assert not verify_document(
        redacted.replace(redacted=[placeholder.replace(leaf_hash="sha256:" + "0" * 64)])
    )
    assert not verify_document(
        redacted.replace(redacted=[], tools=[bom.tools[0].replace(tool_name="changed")])
    )
    assert (
        redact_entities(redacted, {placeholder.id}, applied_by="b", redaction_class="tool-text") is redacted
    )


def test_data_delta_includes_changes_and_removals(minimal_bom: AgentBOM) -> None:
    source = DataSource(
        id="data:corpus",
        kind=E.DataSourceKind.RAG_INDEX,
        instruction_bearing=Claim.declared(False),
        snapshot=Claim.declared(SnapshotCommitment(commitment="sha256:" + "1" * 64)),
    )
    before = finalize(minimal_bom.replace(data_sources=[source]))
    for updated in (
        source.replace(snapshot=Claim.declared(SnapshotCommitment(commitment="sha256:" + "2" * 64))),
        source.replace(chunking={"size": 256}),
        source.replace(embedding_model_ref="model:new"),
        source.replace(quarantine={"status": "quarantined"}),
    ):
        (event,) = diff(before, finalize(minimal_bom.replace(data_sources=[updated]))).events
        assert event.type is E.DeltaEventType.DATA_SOURCE_CHANGED
        assert event.before and event.after and event.before != event.after
    (event,) = diff(before, finalize(minimal_bom)).events
    assert event.type is E.DeltaEventType.DATA_SOURCE_REMOVED and event.before and event.after is None


def test_unknown_and_evidenced_empty_have_different_denominators(minimal_bom: AgentBOM) -> None:
    bare = minimal_bom.replace(tool_servers=[], tools=[], edges=[])
    score = completeness_score(bare)
    assert score.score < 10
    assert next(a for a in score.areas if a.area == "models").status == "unknown"
    coverage = bare.coverage.replace(
        surfaces={
            E.Surface.MODEL_GATEWAY: SurfaceCoverage(
                status=E.CoverageStatus.QUERIED,
                items_seen=0,
                sources=[SourceRun(source="tenant-models", ok=True, items=0)],
            ),
        }
    )
    updated = completeness_score(bare.replace(coverage=coverage))
    area = next(a for a in updated.areas if a.area == "models")
    assert area.status == "not-applicable" and area.total == 0


@pytest.mark.parametrize("value", ["false", "true", 1, [], False])
def test_external_validation_requires_boolean_true(minimal_bom: AgentBOM, value: object) -> None:
    report = evaluate_conformance(
        minimal_bom,
        "verified",
        evidence={
            "cyclonedx_valid": value,
            "snapshot_attestation_verified": value,
            "toolset_matches_approved": value,
        },
    )
    for requirement in report.requirements:
        if requirement.id in ("AB-MIN-07", "AB-VER-01", "AB-VER-02"):
            assert requirement.status == "fail"


def test_symlinked_scan_inputs_stay_out_of_scope(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    external = tmp_path / "outside"
    external.mkdir()
    (external / "agent.yaml").write_text("name: OUTSIDE-CANARY")
    (repo / "agent.yaml").symlink_to(external / "agent.yaml")
    with pytest.raises(ValueError, match="cannot safely read"):
        scan(repo)
    (repo / "agent.yaml").unlink()
    (external / "mcp.json").write_text(json.dumps({"mcpServers": {"outside-canary": {"command": "canary"}}}))
    (repo / ".cursor").symlink_to(external, target_is_directory=True)
    result = McpConfigCollector().collect(CollectContext(root=repo))
    assert not result.entities
    assert any(not s.ok and s.locator == ".cursor/mcp.json" for s in result.coverage[E.Surface.TOOLS].sources)


def test_cli_scan_does_not_overwrite_link_target(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("canary")
    (repo / "agentbom.json").symlink_to(outside)
    run = CliRunner().invoke(app, ["scan", str(repo), "-o", str(repo), "--format", "companion"])
    assert run.exit_code == 0, run.output
    assert outside.read_text() == "canary"
    assert not (repo / "agentbom.json").is_symlink()
    assert json.loads((repo / "agentbom.json").read_bytes())["subject"] == "agent:repo"


def test_cli_scan_refuses_redirected_output_directory(tmp_path: Path) -> None:
    root = tmp_path / "untrusted"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "out").symlink_to(outside, target_is_directory=True)
    run = CliRunner().invoke(app, ["scan", str(root), "-o", str(root / "out"), "--format", "companion"])
    assert run.exit_code != 0 and not list(outside.iterdir())
