"""Tests for model governance policy (Item 30) and dual-axis completeness scoring (Item 31)."""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote.attestation import build_statement, sign_statement
from nexus_symbiote.cli import main
from nexus_symbiote.completeness_score import score_aibom_completeness
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import AssuranceLevel, SerializationSafety
from nexus_symbiote.core.models import (
    AgentComponent,
    AIBOMMetadata,
    MCPServerComponent,
    ModelComponent,
)
from nexus_symbiote.model_policy import (
    ModelGovernancePolicy,
    ModelPolicyError,
    ModelPolicyWaiver,
    ModelRetirementCatalog,
    ModelRetirementEntry,
    evaluate_model_policy,
    is_pinned_model_identifier,
    load_model_policy,
    load_retirement_catalog,
)


def _write_keypair(directory: Path, name: str) -> tuple[Ed25519PrivateKey, Path]:
    private = Ed25519PrivateKey.generate()
    pub_path = directory / f"{name}.pub.pem"
    pub_path.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return private, pub_path


def _attest(target: Path, private: Ed25519PrivateKey, att_path: Path) -> None:
    raw = target.read_bytes()
    stmt = build_statement(
        raw,
        name=target.name,
        purpose="reviewed",
        signed_at=datetime.now(UTC).replace(microsecond=0),
    )
    env = sign_statement(stmt, [private])
    att_path.write_text(
        json.dumps(env.model_dump(mode="json", by_alias=True), indent=2) + "\n", encoding="utf-8"
    )


def test_pinning_accepts_dated_snapshots_and_digests_but_rejects_floating_aliases():
    """Exact Item 30 Done-when: dated snapshots stay clean; floating aliases fail closed."""
    clean_pinned = [
        "gpt-4o-2024-08-06",
        "o3-mini-2025-01-31",
        "claude-sonnet-4-20250514",
        "claude-3-5-sonnet-20241022",
        "gemini-2.0-flash-001",
        "sha256:" + "a" * 64,
        "org/model@sha256:" + "b" * 64,
        "0123456789abcdef0123456789abcdef01234567",
    ]
    for ident in clean_pinned:
        assert is_pinned_model_identifier(ident) is True, f"expected pinned: {ident}"

    floating = [
        "gpt-4o",
        "gpt-4-turbo",
        "claude-3-5-sonnet-latest",
        "gemini-2.5-pro",
        "llama3:latest",
        "main",
        "latest",
        "gpt-4o-preview",
        "",
        None,
    ]
    for ident in floating:
        assert is_pinned_model_identifier(ident) is False, f"expected floating: {ident}"


def test_model_policy_catches_floating_license_trc_pickle_and_retirement_while_dated_passes(
    tmp_path,
):
    """Positive + benign-twin tests for Item 30 covering all governance rules & AIROM catalog."""
    bom = AIBOM(
        metadata=AIBOMMetadata(timestamp=datetime(2020, 1, 1, tzinfo=UTC)),  # stale BOM timestamp
        components=[
            # Benign twin: dated snapshot, approved license, trust_remote_code=False, safe weights, active in catalog.
            ModelComponent(
                bom_ref="model:clean-dated",
                name="gpt-4o",
                provider="openai",
                requested_alias="gpt-4o",
                resolved_revision="gpt-4o-2024-08-06",
                trust_remote_code=False,
                serialization_format="hosted",
                serialization_safety=SerializationSafety.SAFE,
                properties={"license": "Commercial-OpenAI"},
            ),
            # Positive fixture 1: floating alias + unknown license + retired model in catalog.
            ModelComponent(
                bom_ref="model:bad-floating-retired",
                name="gpt-4-turbo",
                provider="openai",
                requested_alias="gpt-4-turbo",
                trust_remote_code=False,
            ),
            # Positive fixture 2: pinned commit SHA, but disallowed license + trust_remote_code=True + pickle weights + deprecated.
            ModelComponent(
                bom_ref="model:bad-trc-pickle",
                name="legacy-hf-model",
                provider="huggingface",
                resolved_revision="0123456789abcdef0123456789abcdef01234567",
                trust_remote_code=True,
                serialization_format="pickle",
                serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION,
                properties={"license": "GPL-3.0-only"},
            ),
        ],
    )
    policy = ModelGovernancePolicy(
        allowed_licenses=["Apache-2.0", "MIT", "Commercial-OpenAI"],
        denied_licenses=["GPL-3.0-only"],
        retirement_warn_days=90,
        waivers=[
            # Expired waiver MUST NOT suppress finding even though BOM timestamp is 2020-01-01!
            ModelPolicyWaiver(
                rule="model_unpinned_alias",
                model_ref="model:bad-floating-retired",
                owner="sec-team",
                reason="temporary migration",
                expires_at=datetime(2021, 1, 1, tzinfo=UTC),
            ),
        ],
    )
    catalog = ModelRetirementCatalog(
        catalog_version="2026.11",
        models=[
            ModelRetirementEntry(
                model_id="gpt-4o-2024-08-06",
                status="active",
            ),
            ModelRetirementEntry(
                model_id="gpt-4-turbo",
                status="retired",
                sunset_date=datetime(2025, 6, 1, tzinfo=UTC).date(),
                replacement="gpt-4o-2024-08-06",
            ),
            ModelRetirementEntry(
                model_id="legacy-hf-model",
                status="deprecated",
                sunset_date=(datetime.now(UTC) + timedelta(days=30)).date(),
                replacement="safe-hf-model-v2",
            ),
        ],
    )

    # Even with SOURCE_DATE_EPOCH set to 2020, wall-clock UTC governs expiry & retirement!
    old_sde = os.environ.get("SOURCE_DATE_EPOCH")
    os.environ["SOURCE_DATE_EPOCH"] = "1577836800"
    try:
        report = evaluate_model_policy(bom, policy, catalog=catalog)
    finally:
        if old_sde is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = old_sde

    assert report.passed is False
    assert report.models_checked == 3
    assert report.expired_waiver_count == 1
    assert report.waived_count == 0

    # Benign twin dated snapshot has ZERO findings.
    assert not any(f.model_ref == "model:clean-dated" for f in report.findings)

    by_model: dict[str, set[str]] = {}
    for f in report.findings:
        by_model.setdefault(f.model_ref, set()).add(f.rule)

    assert by_model["model:bad-floating-retired"] == {
        "model_unpinned_alias",
        "model_license_unknown",
        "model_retired",
    }
    assert by_model["model:bad-trc-pickle"] == {
        "model_license_disallowed",
        "model_trust_remote_code",
        "model_unsafe_serialization",
        "model_deprecated",
    }

    # Benign-only BOM passes cleanly with exit 0 via CLI with D7 DSSE attestation!
    clean_bom = AIBOM(components=[bom.components[0]])
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    bom_path = repo / "clean-aibom.json"
    clean_bom.save(bom_path)

    op_dir = tmp_path / "operator"
    op_dir.mkdir()
    private, pub_path = _write_keypair(op_dir, "gov")

    pol_path = op_dir / "model-policy.json"
    pol_path.write_text(
        json.dumps(policy.model_dump(mode="json"), indent=2, sort_keys=True), encoding="utf-8"
    )
    pol_att = op_dir / "model-policy.att.json"
    _attest(pol_path, private, pol_att)

    cat_path = op_dir / "airom.json"
    cat_path.write_text(
        json.dumps(catalog.model_dump(mode="json"), indent=2, sort_keys=True), encoding="utf-8"
    )
    cat_att = op_dir / "airom.att.json"
    _attest(cat_path, private, cat_att)

    runner = CliRunner()
    # D7: unsigned policy refused by default!
    res_refused = runner.invoke(main, ["model-policy", str(bom_path), "--policy", str(pol_path)])
    assert res_refused.exit_code != 0
    assert "DSSE attestation" in res_refused.output

    # Attested policy + attested catalog passes cleanly with exit 0!
    res_ok = runner.invoke(
        main,
        [
            "model-policy",
            str(bom_path),
            "--policy",
            str(pol_path),
            "--policy-attestation",
            str(pol_att),
            "--retirement-catalog",
            str(cat_path),
            "--catalog-attestation",
            str(cat_att),
            "--trusted-key",
            str(pub_path),
            "--project-root",
            str(repo),
        ],
    )
    assert res_ok.exit_code == 0, res_ok.output
    data = json.loads(res_ok.output)
    assert data["passed"] is True
    assert data["policy_attested"] is True
    assert data["catalog_attested"] is True


def test_model_policy_refuses_in_repo_files_and_tampered_attestations(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    bom_path = repo / "aibom.json"
    AIBOM().save(bom_path)

    in_repo_pol = repo / "policy.json"
    in_repo_pol.write_text(
        json.dumps(ModelGovernancePolicy().model_dump(mode="json")), encoding="utf-8"
    )
    with pytest.raises(ModelPolicyError, match="outside the scanned project"):
        load_model_policy(in_repo_pol, inventory_path=bom_path, allow_unsigned=True)

    in_repo_cat = repo / "catalog.json"
    in_repo_cat.write_text(
        json.dumps(ModelRetirementCatalog(catalog_version="1.0").model_dump(mode="json")),
        encoding="utf-8",
    )
    with pytest.raises(ModelPolicyError, match="outside the scanned project"):
        load_retirement_catalog(in_repo_cat, inventory_path=bom_path, allow_unsigned=True)

    # Tampered attestation fails closed.
    op_dir = tmp_path / "op"
    op_dir.mkdir()
    private, pub_path = _write_keypair(op_dir, "k")
    pol_path = op_dir / "pol.json"
    pol_path.write_text(
        json.dumps(ModelGovernancePolicy().model_dump(mode="json")), encoding="utf-8"
    )
    att_path = op_dir / "pol.att.json"
    _attest(pol_path, private, att_path)
    pol_path.write_bytes(pol_path.read_bytes() + b"\n")
    with pytest.raises(ModelPolicyError, match="attestation verification failed"):
        load_model_policy(pol_path, attestation_path=att_path, trusted_key_paths=(pub_path,))


def test_completeness_score_distinguishes_valid_undocumented_from_well_documented_model(tmp_path):
    """Exact Item 31 Done-when: schema-valid undocumented model scores high on structure, low on completeness."""
    undoc_bom = AIBOM(
        components=[
            ModelComponent(bom_ref="model:undoc", name="mystery-llm"),
        ]
    )
    undoc_rep = score_aibom_completeness(undoc_bom)
    assert undoc_rep.structure_score == 100.0
    assert undoc_rep.completeness_score <= 25.0
    assert undoc_rep.verdict == "structurally_valid_but_incomplete"
    assert undoc_rep.quality_gap >= 75.0
    assert "pinned_revision" in undoc_rep.components[0].missing_fields
    assert "license" in undoc_rep.components[0].missing_fields
    assert "cryptographic_digest" in undoc_rep.components[0].missing_fields

    # Benign twin: well-documented model scores high on BOTH structure and completeness!
    doc_bom = AIBOM(
        components=[
            ModelComponent(
                bom_ref="model:documented",
                name="llama-3.3-70b",
                provider="meta",
                supplier="Meta",
                model_type="foundation",
                resolved_revision="0123456789abcdef0123456789abcdef01234567",
                hashes={"sha256": "a" * 64},
                serialization_format="safetensors",
                serialization_safety=SerializationSafety.SAFE,
                trust_remote_code=False,
                description="Documented production foundation model.",
                source_path="models/llama/config.json",
                assurance_level=AssuranceLevel.OBSERVED,
                properties={"license": "Llama-3.3-Community"},
            ),
        ]
    )
    doc_rep = score_aibom_completeness(doc_bom)
    assert doc_rep.structure_score == 100.0
    assert doc_rep.completeness_score == 100.0
    assert doc_rep.verdict == "complete"
    assert doc_rep.components[0].missing_fields == ()

    # Broken structural references penalize structure_score deterministically.
    broken_bom = AIBOM(
        components=[
            AgentComponent(
                bom_ref="agent:a1",
                name="a1",
                model_refs=["model:missing-1", "model:missing-2"],
            ),
            MCPServerComponent(bom_ref="mcp:s1", name="s1"),
        ],
        dependencies=[
            DependencyEdge(
                source_ref="agent:a1", target_ref="model:ghost", relationship="uses-model"
            )
        ],
    )
    broken_rep = score_aibom_completeness(broken_bom)
    assert broken_rep.structure_score < 80.0
    assert broken_rep.verdict == "structurally_invalid"
    assert len(broken_rep.dangling_dependency_edges) == 1

    # CLI exit-gate test (--min-completeness fails on undocumented, passes on documented).
    undoc_path = tmp_path / "undoc.json"
    doc_path = tmp_path / "doc.json"
    undoc_bom.save(undoc_path)
    doc_bom.save(doc_path)
    runner = CliRunner()
    res_fail = runner.invoke(
        main,
        [
            "completeness-score",
            str(undoc_path),
            "--min-structure",
            "90",
            "--min-completeness",
            "80",
        ],
    )
    assert res_fail.exit_code == 1
    res_pass = runner.invoke(
        main,
        ["completeness-score", str(doc_path), "--min-structure", "90", "--min-completeness", "80"],
    )
    assert res_pass.exit_code == 0


def test_model_governance_and_completeness_linear_scaling_2000_models():
    """Verify linear O(M) scaling across 2,000 models."""
    models = [
        ModelComponent(
            bom_ref=f"model:m-{i:04d}",
            name="gpt-4o-2024-08-06",
            resolved_revision="gpt-4o-2024-08-06",
            trust_remote_code=False,
            properties={"license": "MIT"},
        )
        for i in range(2_000)
    ]
    bom = AIBOM(components=models)
    policy = ModelGovernancePolicy(allowed_licenses=["MIT"])
    t0 = time.monotonic()
    p_rep = evaluate_model_policy(bom, policy)
    c_rep = score_aibom_completeness(bom)
    elapsed = time.monotonic() - t0
    assert p_rep.passed is True
    assert p_rep.models_checked == 2_000
    assert c_rep.component_count == 2_000
    assert elapsed < 2.0, f"expected linear evaluation (<2s), got {elapsed:.2f}s"
