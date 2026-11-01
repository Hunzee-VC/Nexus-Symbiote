"""Regression tests for evidence and policy assurance boundaries."""

import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety, TrustTier
from nexus_symbiote.core.models import (
    AIBOMMetadata,
    CompletenessClaim,
    ModelComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.utils.crypto import verify_sigstore_bundle
from nexus_symbiote.validators.integrity import IntegrityValidator
from nexus_symbiote.validators.risk import RiskScorer


def test_signature_filename_does_not_promote_trust(tmp_path: Path) -> None:
    (tmp_path / "model.safetensors").write_bytes(b"weight")
    (tmp_path / "model.sig").write_text("not a signature")
    component = ModelScanner().scan(tmp_path).components[0]
    assert component.signing_status == "signature-present-unverified"
    assert component.signing_identity is None
    assert component.trust_tier == TrustTier.UNKNOWN
    assert any(r.category == "signing_status" for r in component.risks)


@pytest.mark.parametrize("identity,issuer", [(None, None), ("a", None), (None, "b")])
def test_verify_requires_both_trust_constraints(
    tmp_path: Path, identity: str | None, issuer: str | None
) -> None:
    result = verify_sigstore_bundle(tmp_path / "artifact", tmp_path / "bundle", identity, issuer)
    assert not result.verified
    assert "identity" in result.error and "issuer" in result.error


def test_sigstore_verifier_applies_identity_and_checks_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import hashlib

    artifact = tmp_path / "model"
    bundle = tmp_path / "bundle"
    artifact.write_bytes(b"artifact")
    bundle.write_bytes(b"bundle")
    expected_digest = hashlib.sha256(b"artifact").digest()
    calls: list[tuple[str, str]] = []

    class Identity:
        def __init__(self, *, identity: str, issuer: str) -> None:
            calls.append((identity, issuer))

    class Hashed:
        def __init__(self, *, algorithm: object, digest: bytes) -> None:
            self.digest = digest

    class HashAlgorithm:
        SHA2_256 = "sha256"

    class Verifier:
        @staticmethod
        def production(offline: bool = False) -> "Verifier":
            return Verifier()

        def verify_artifact(self, hashed: object, _bundle: object, _policy: object) -> None:
            if getattr(hashed, "digest", None) != expected_digest:
                raise ValueError("signature does not match")

    pkg = ModuleType("sigstore")
    models = ModuleType("sigstore.models")
    verify = ModuleType("sigstore.verify")
    verify_policy = ModuleType("sigstore.verify.policy")
    hashes = ModuleType("sigstore.hashes")
    protobuf_common = ModuleType("sigstore_protobuf_specs.dev.sigstore.common.v1")
    models.Bundle = SimpleNamespace(from_json=lambda _: object())
    verify.Verifier = Verifier
    verify_policy.Identity = Identity
    hashes.Hashed = Hashed
    protobuf_common.HashAlgorithm = HashAlgorithm
    monkeypatch.setitem(sys.modules, "sigstore", pkg)
    monkeypatch.setitem(sys.modules, "sigstore.models", models)
    monkeypatch.setitem(sys.modules, "sigstore.verify", verify)
    monkeypatch.setitem(sys.modules, "sigstore.verify.policy", verify_policy)
    monkeypatch.setitem(sys.modules, "sigstore.hashes", hashes)
    monkeypatch.setitem(
        sys.modules, "sigstore_protobuf_specs.dev.sigstore.common.v1", protobuf_common
    )
    result = verify_sigstore_bundle(artifact, bundle, "trusted", "issuer")
    assert result.verified
    assert calls == [("trusted", "issuer")]
    artifact.write_bytes(b"changed")
    assert not verify_sigstore_bundle(artifact, bundle, "trusted", "issuer").verified


def test_critical_unsafe_format_alone_invalidates_integrity() -> None:
    bom = AIBOM()
    bom.add_component(
        ModelComponent(
            bom_ref="model:p",
            name="p",
            serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION,
        )
    )
    report = IntegrityValidator().validate(bom)
    assert not report.is_valid
    assert any(i.category == "unsafe_format" and i.severity == "critical" for i in report.issues)


def test_one_critical_cannot_pass_risk_gate() -> None:
    bom = AIBOM(
        metadata=AIBOMMetadata(
            completeness=CompletenessClaim(scope="test", surfaces_scanned=["model"])
        )
    )
    bom.add_component(
        ModelComponent(
            bom_ref="model:p",
            name="p",
            risks=[
                RiskAssessment(severity=RiskSeverity.CRITICAL, category="test", detail="critical")
            ],
        )
    )
    passed, report = RiskScorer().passes_gate(bom)
    assert not passed
    assert report.risk_level == "critical"
    assert report.overall_score == 10


def test_missing_or_failed_coverage_is_not_clean_or_passing() -> None:
    passed, report = RiskScorer().passes_gate(AIBOM())
    assert not passed
    assert report.risk_level == "unknown"
    assert report.coverage_status == "unknown"
    bom = AIBOM(
        metadata=AIBOMMetadata(
            completeness=CompletenessClaim(
                scope="test", surfaces_scanned=["model"], scan_failures=["mcp failed"]
            )
        )
    )
    bom.add_component(ModelComponent(bom_ref="model:p", name="p"))
    passed, report = RiskScorer().passes_gate(bom)
    assert not passed
    assert report.coverage_status == "partial"
    assert report.risk_level == "unknown"
    bom.metadata.completeness.scan_failures = []
    bom.metadata.completeness.surfaces_excluded = ["runtime: not assessed"]
    passed, report = RiskScorer().passes_gate(bom)
    assert not passed
    assert report.coverage_status == "partial"
    assert report.risk_level == "unknown"


def test_per_scanner_coverage_requires_every_state_to_be_complete() -> None:
    claim = CompletenessClaim(scope="test", surfaces_scanned=["model"])
    bom = AIBOM(metadata=AIBOMMetadata(completeness=claim))
    bom.add_component(ModelComponent(bom_ref="model:p", name="p"))
    # Mirror a claim from the newer schema without coupling this PR to it.
    object.__setattr__(
        bom.metadata.completeness, "scanner_status", {"model": "complete", "mcp": "unknown"}
    )
    passed, report = RiskScorer().passes_gate(bom)
    assert not passed
    assert report.coverage_status == "partial"
    object.__setattr__(bom.metadata.completeness, "scanner_status", {"model": "complete"})
    passed, report = RiskScorer().passes_gate(bom)
    assert not passed
    assert report.coverage_status == "partial"
    object.__setattr__(
        bom.metadata.completeness,
        "scanner_status",
        dict.fromkeys(("mcp", "model", "prompt", "rag", "registry"), "complete"),
    )
    passed, report = RiskScorer().passes_gate(bom)
    assert passed
    assert report.coverage_status == "reported"


def test_removing_tool_hash_is_assurance_regression() -> None:
    old, new = AIBOM(), AIBOM()
    old.add_component(ToolComponent(bom_ref="tool:a", name="a", definition_hash="sha256:aaa"))
    new.add_component(ToolComponent(bom_ref="tool:a", name="a"))
    diff = AIBOMDiffer().diff(old, new)
    assert diff.has_changes
    assert diff.components_modified[0].severity == "high"
    assert "assurance regressed" in diff.components_modified[0].details[0]


def test_installed_sigstore_exposes_supported_api() -> None:
    verify = pytest.importorskip("sigstore.verify")
    assert callable(verify.Verifier.verify_artifact)
