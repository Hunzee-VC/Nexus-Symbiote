"""Regression tests for evidence and policy assurance boundaries."""

import stat
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from nexus_symbiote.core.redact import REDACTED, redact_aibom, redact_string, redact_url
from nexus_symbiote.core.textsafety import find_hidden_characters
from nexus_symbiote.scanners.base import hash_regular_file
from nexus_symbiote.scanners.prompt import PromptScanner
from nexus_symbiote.scanners.rag import RAGScanner
from nexus_symbiote.scanners.shadowscan import ShadowScanImporter
from nexus_symbiote.utils.fsio import MAX_MODEL_BYTES, write_text_safely

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety, TrustTier
from nexus_symbiote.core.models import (
    AIBOMMetadata,
    CompletenessClaim,
    ModelComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.core.vocab import SCANNER_NAMES
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
    assert report.coverage_status == "failed"
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
        dict.fromkeys(SCANNER_NAMES, "complete"),
    )
    passed, report = RiskScorer().passes_gate(bom)
    assert passed
    assert report.coverage_status == "complete"


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


def test_bidi_and_tag_characters_are_flagged() -> None:
    kinds = {(h.codepoint, h.kind) for h in find_hidden_characters("a\u202eb\U000e0041")}
    assert kinds == {("U+202E", "bidi-control"), ("U+E0041", "tag-character")}


def test_joiner_and_variation_selector_are_not_flagged() -> None:
    assert find_hidden_characters("a\u200db\ufe0f") == []


def test_prompt_with_bidi_control_is_high_risk(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("Allow only \u202eread\u202c operations.", encoding="utf-8")
    components = PromptScanner().scan(tmp_path).components
    assert components
    risks = [r for c in components for r in c.risks if r.category == "hidden-characters"]
    assert risks
    assert all(r.severity == RiskSeverity.HIGH for r in risks)


def test_redact_string_removes_credential_shapes() -> None:
    text = (
        "AKIAIOSFODNN7EXAMPLE ghp_" + "a" * 36 + " password=hunter2 "
        "https://user:pw@example.com/mcp?token=abc"
    )
    redacted = redact_string(text)
    for secret in ("AKIAIOSFODNN7EXAMPLE", "ghp_" + "a" * 36, "hunter2", "user:pw", "token=abc"):
        assert secret not in redacted
    assert redact_url("https://user:pw@example.com:8443/mcp?token=abc#frag") == (
        "https://example.com:8443/mcp"
    )
    assert REDACTED in redacted


def test_redact_aibom_leaves_fingerprinted_fields_unchanged() -> None:
    digest = "sha256:" + "b" * 64
    bom = AIBOM()
    bom.add_component(
        ToolComponent(
            bom_ref="tool:t",
            name="t",
            description_text="reads files, password=hunter2",
            definition_hash=digest,
            definition_hash_version="rfc8785-jcs-v1",
            description="token=abcdef123456",
        )
    )
    redact_aibom(bom)
    tool = bom.components[0]
    assert tool.description_text == "reads files, password=hunter2"
    assert tool.definition_hash == digest
    assert tool.description == f"token={REDACTED}"


def test_write_text_safely_refuses_symlink_destination(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("original", encoding="utf-8")
    link = tmp_path / "out.json"
    link.symlink_to(target)
    with pytest.raises(OSError):
        write_text_safely(link, "replacement")
    assert target.read_text(encoding="utf-8") == "original"


def test_write_text_safely_replaces_atomically(tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    out.write_text("old", encoding="utf-8")
    write_text_safely(out, "new")
    assert out.read_text(encoding="utf-8") == "new"
    assert not list(tmp_path.glob(".out.json.*.tmp"))


def test_write_text_safely_creates_owner_only_file(tmp_path: Path) -> None:
    out = tmp_path / "fresh.json"
    write_text_safely(out, "{}")
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_write_text_safely_respects_overwrite_false(tmp_path: Path) -> None:
    out = tmp_path / "keep.json"
    out.write_text("keep", encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_text_safely(out, "new", overwrite=False)
    assert out.read_text(encoding="utf-8") == "keep"


def test_model_size_bound_is_at_least_256_gib() -> None:
    assert MAX_MODEL_BYTES >= 256 * 1024**3


def test_model_file_above_one_gib_is_hashed(tmp_path: Path) -> None:
    weights = tmp_path / "big.safetensors"
    with weights.open("wb") as handle:
        handle.truncate(1024**3 + 1)
    digest = hash_regular_file(weights)
    assert digest.startswith("sha256:")


def test_model_directories_with_same_name_get_distinct_refs(tmp_path: Path) -> None:
    for parent in ("a", "b"):
        model_dir = tmp_path / parent / "model"
        model_dir.mkdir(parents=True)
        (model_dir / "model.safetensors").write_bytes(b"weights")
    refs = [c.bom_ref for c in ModelScanner().scan(tmp_path).components]
    assert len(refs) == 2
    assert len(set(refs)) == 2


def test_env_and_example_naming_same_store_get_distinct_refs(tmp_path: Path) -> None:
    line = "PINECONE_URL=https://example.com\n"
    (tmp_path / ".env").write_text(line, encoding="utf-8")
    (tmp_path / ".env.example").write_text(line, encoding="utf-8")
    refs = [c.bom_ref for c in RAGScanner().scan(tmp_path).components]
    assert len(refs) == len(set(refs)) == 2


def test_symlinked_shadowscan_report_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text('{"findings": []}', encoding="utf-8")
    link = tmp_path / "report.json"
    link.symlink_to(real)
    with pytest.raises(OSError):
        ShadowScanImporter().import_report(link)


def test_shadowscan_raw_fields_are_not_copied(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        '{"findings": [{"id": "f1", "kind": "mcp-server", "title": "srv",'
        ' "secret_note": "token-XYZ-123", "risk": {"level": "high", "score": 80}}]}',
        encoding="utf-8",
    )
    components = ShadowScanImporter().import_report(report)
    assert len(components) == 1
    assert "shadowscan:raw" not in components[0].properties
    assert "token-XYZ-123" not in str(components[0].properties)


def test_shadowscan_record_without_risk_is_unassessed(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text('{"findings": [{"id": "f2", "kind": "agent", "title": "a"}]}', encoding="utf-8")
    components = ShadowScanImporter().import_report(report)
    categories = [r.category for c in components for r in c.risks]
    assert "unassessed-discovery" in categories

