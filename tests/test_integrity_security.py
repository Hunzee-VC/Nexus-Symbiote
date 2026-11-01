"""Security regressions covering real scanner/validator boundaries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_symbiote.core import AIBOM, ModelComponent, PromptComponent, ToolComponent
from nexus_symbiote.core.enums import SerializationSafety, TrustTier
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    hash_file,
    hash_tool_definition,
)
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import MAX_MODEL_HEADER_BYTES, ModelScanner, inspect_model_format
from nexus_symbiote.utils.crypto import SigstoreArtifactPolicy, VerificationResult
from nexus_symbiote.validators.integrity import IntegrityValidator


def write_safetensors(path: Path, header: dict | None = None, data: bytes = b"abcd") -> None:
    if header is None:
        header = {"weight": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}}
    raw = json.dumps(header, separators=(",", ":")).encode()
    raw += b" " * (-len(raw) % 8)
    path.write_bytes(len(raw).to_bytes(8, "little") + raw + data)


def test_signature_filename_and_format_suffix_cannot_establish_trust(tmp_path):
    (tmp_path / "model.safetensors").write_bytes(b"not a tensor container")
    (tmp_path / "model.sigstore").write_text("not a signature")
    comp = ModelScanner().scan(tmp_path).components[0]
    assert comp.signing_status == "signature-present-unverified"
    assert comp.signing_identity is None
    assert comp.trust_tier != TrustTier.THIRD_PARTY_SIGNED
    assert comp.serialization_safety == SerializationSafety.UNKNOWN
    assert {r.category for r in comp.risks} >= {"signing_status", "serialization_format_unknown"}


def test_valid_nonexecuting_tensor_container_has_structural_evidence(tmp_path):
    path = tmp_path / "model.safetensors"
    write_safetensors(path)
    comp = ModelScanner().scan(tmp_path).components[0]
    assert comp.serialization_safety == SerializationSafety.SAFE
    assert "offsets checked" in comp.properties["format_inspection"]
    assert comp.signing_status == "signature-not-found"
    assert comp.trust_tier != TrustTier.THIRD_PARTY_SIGNED


@pytest.mark.parametrize(
    ("header", "data"),
    [
        ({"x": {"dtype": "U8", "shape": [5], "data_offsets": [0, 4]}}, b"abcd"),
        ({"x": {"dtype": "U8", "shape": [3], "data_offsets": [1, 4]}}, b"abcd"),
        ({"x": {"dtype": "UNSUPPORTED", "shape": [4], "data_offsets": [0, 4]}}, b"abcd"),
        ({"__metadata__": {"not_a_string": 1}}, b""),
        ({"x": {"dtype": "U8", "shape": [True], "data_offsets": [0, 1]}}, b"a"),
    ],
)
def test_invalid_tensor_structure_never_becomes_safe(tmp_path, header, data):
    path = tmp_path / "model.safetensors"
    write_safetensors(path, header, data)
    assert inspect_model_format(path)[0] == SerializationSafety.UNKNOWN


def test_oversize_header_and_duplicate_keys_are_rejected(tmp_path):
    path = tmp_path / "model.safetensors"
    path.write_bytes((MAX_MODEL_HEADER_BYTES + 1).to_bytes(8, "little") + b" " * 8)
    assert inspect_model_format(path)[0] == SerializationSafety.UNKNOWN
    duplicate = b'{"__metadata__":{},"__metadata__":{}}'
    path.write_bytes(len(duplicate).to_bytes(8, "little") + duplicate)
    assert inspect_model_format(path)[0] == SerializationSafety.UNKNOWN


@pytest.mark.parametrize("suffix", ["onnx", "ggml", "gguf"])
def test_other_formats_do_not_get_safe_status_from_suffix(tmp_path, suffix):
    path = tmp_path / f"model.{suffix}"
    path.write_bytes(b"GGUF\x00not a verified loader")
    assert (
        ModelScanner().scan(tmp_path).components[0].serialization_safety
        == SerializationSafety.UNKNOWN
    )


def test_unchanged_tool_without_annotations_passes_digest_check(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "test": {
                        "command": "npx",
                        "args": ["test@1.0.0"],
                        "tools": [
                            {
                                "name": "get_issue",
                                "description": "Get an issue",
                                "inputSchema": {"type": "object"},
                            }
                        ],
                    }
                }
            }
        )
    )
    bom = AIBOM(components=MCPScanner().scan(tmp_path).components)
    report = IntegrityValidator().validate(bom)
    assert report.hashes_verified == 1
    assert report.hashes_failed == 0
    assert report.status == "pass"


def test_critical_unsafe_model_fails_without_remote_code_flag():
    model = ModelComponent(
        bom_ref="model:unsafe",
        name="unsafe.pkl",
        serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION,
    )
    report = IntegrityValidator().validate(AIBOM(components=[model]))
    assert report.status == "fail"
    assert not report.is_valid
    assert any(i.severity == "critical" and i.category == "unsafe_format" for i in report.issues)


@pytest.mark.parametrize(
    "component",
    [
        ModelComponent(bom_ref="model:m", name="m", signing_status="sigstore-signed"),
        ToolComponent(bom_ref="tool:t", name="t"),
        PromptComponent(bom_ref="prompt:p", name="p"),
    ],
)
def test_missing_required_evidence_is_unknown_not_pass(component):
    report = IntegrityValidator().validate(AIBOM(components=[component]))
    assert report.status == "unknown"
    assert not report.is_valid
    assert report.signatures_checked == 0


def test_empty_inventory_has_no_verified_integrity():
    assert IntegrityValidator().validate(AIBOM()).status == "unknown"


@pytest.mark.parametrize("digest", ["sha256:bad", "sha1:" + "a" * 40, "sha512:" + "a" * 128])
def test_invalid_or_conflicting_digest_fails_without_throwing(digest):
    model = ModelComponent(bom_ref="model:m", name="m", hashes={"sha256": digest})
    report = IntegrityValidator().validate(AIBOM(components=[model]))
    assert report.status == "fail"
    assert report.hashes_failed >= 1


def test_missing_declared_artifact_and_escaping_path_fail(tmp_path):
    for source in ["missing.safetensors", "../outside.safetensors"]:
        comp = ModelComponent(
            bom_ref="model:m", name="m", source_path=source, hashes={"sha256": "a" * 64}
        )
        report = IntegrityValidator().validate(AIBOM(components=[comp]), tmp_path)
        assert report.status == "fail"
        assert any(i.category == "missing_artifact" for i in report.issues)


def model_and_policy(tmp_path):
    path = tmp_path / "model.safetensors"
    write_safetensors(path)
    comp = ModelScanner().scan(tmp_path).components[0]
    policy = SigstoreArtifactPolicy(
        path, tmp_path / "model.sigstore", "trusted@example.test", "https://issuer.example.test"
    )
    return comp, policy


def test_verified_signature_is_bound_to_explicit_policy_and_bom_bytes(tmp_path, monkeypatch):
    comp, policy = model_and_policy(tmp_path)
    calls = []

    def verify(artifact, bundle, identity, issuer):
        calls.append((artifact, bundle, identity, issuer))
        return VerificationResult(
            True, identity=identity, issuer=issuer, details={"artifact_digest": hash_file(artifact)}
        )

    monkeypatch.setattr("nexus_symbiote.validators.integrity.verify_sigstore_bundle", verify)
    report = IntegrityValidator([policy]).validate(AIBOM(components=[comp]), tmp_path)
    assert report.is_valid
    assert report.signatures_checked == report.signatures_verified == 1
    assert calls == [
        (policy.artifact_path, policy.bundle_path, policy.expected_identity, policy.expected_issuer)
    ]


@pytest.mark.parametrize(
    "result",
    [
        VerificationResult(False, error="untrusted signer"),
        VerificationResult(True, details={"artifact_digest": "sha256:" + "0" * 64}),
    ],
)
def test_bad_signature_or_wrong_subject_fails(tmp_path, monkeypatch, result):
    comp, policy = model_and_policy(tmp_path)
    monkeypatch.setattr(
        "nexus_symbiote.validators.integrity.verify_sigstore_bundle", lambda *args: result
    )
    report = IntegrityValidator([policy]).validate(AIBOM(components=[comp]), tmp_path)
    assert report.status == "fail"
    assert report.signatures_checked == 1
    assert report.signatures_verified == 0


def test_model_scanner_only_upgrades_after_explicit_matching_verification(tmp_path, monkeypatch):
    _, policy = model_and_policy(tmp_path)
    monkeypatch.setattr(
        "nexus_symbiote.scanners.model.verify_sigstore_bundle",
        lambda *args: VerificationResult(
            True,
            identity=policy.expected_identity,
            issuer=policy.expected_issuer,
            details={"artifact_digest": hash_file(policy.artifact_path)},
        ),
    )
    verified = ModelScanner([policy]).scan(tmp_path).components[0]
    assert verified.trust_tier == TrustTier.THIRD_PARTY_SIGNED
    assert verified.signing_identity == policy.expected_identity
    monkeypatch.setattr(
        "nexus_symbiote.scanners.model.verify_sigstore_bundle",
        lambda *args: VerificationResult(
            True,
            details={"artifact_digest": "sha256:" + "0" * 64},
        ),
    )
    wrong = ModelScanner([policy]).scan(tmp_path).components[0]
    assert wrong.trust_tier != TrustTier.THIRD_PARTY_SIGNED
    assert wrong.signing_status == "verification-failed"


def test_model_collection_refuses_symlinked_directories_and_weights(tmp_path):
    external = tmp_path / "external"
    project = tmp_path / "project"
    external.mkdir()
    project.mkdir()
    write_safetensors(external / "model.safetensors")
    (project / "linked-dir").symlink_to(external, target_is_directory=True)
    (project / "linked.safetensors").symlink_to(external / "model.safetensors")
    result = ModelScanner().scan(project)
    assert result.components == []
    assert result.scan_failures


def test_model_config_symlink_is_never_read(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "private.json"
    outside.write_text('{"trust_remote_code":true}')
    write_safetensors(project / "model.safetensors")
    (project / "config.json").symlink_to(outside)
    result = ModelScanner().scan(project)
    assert result.scan_failures
    assert result.components[0].trust_remote_code is None


def test_model_hash_limit_is_explicit_missing_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr("nexus_symbiote.scanners.model.MAX_HASH_SIZE", 8)
    write_safetensors(tmp_path / "model.safetensors")
    result = ModelScanner().scan(tmp_path)
    assert result.scan_failures
    assert result.components[0].hashes == {}
    assert result.components[0].serialization_safety == SerializationSafety.UNKNOWN


def test_model_collection_obeys_exclusions(tmp_path):
    excluded = tmp_path / "excluded"
    excluded.mkdir()
    write_safetensors(excluded / "model.safetensors")
    scanner = ModelScanner()
    scanner.configure(exclude_paths=["excluded"])
    result = scanner.scan(tmp_path)
    assert result.components == []
    assert result.surfaces_excluded


@pytest.mark.parametrize("version", [None, "rfc8785-jcs-v1", "unsupported"])
def test_legacy_tool_fingerprints_require_recollection(version):
    tool = ToolComponent(
        bom_ref="tool:legacy",
        name="legacy",
        description_text="read",
        definition_hash=hash_tool_definition("legacy", "read"),
        definition_hash_version=version,
    )
    report = IntegrityValidator().validate(AIBOM(components=[tool]))
    assert not report.is_valid
    assert report.status == "fail"
    assert report.hashes_verified == 0
    assert any(i.category == "fingerprint_version_unknown" for i in report.issues)


def test_current_version_tool_fingerprint_can_be_verified():
    tool = ToolComponent(
        bom_ref="tool:current",
        name="current",
        description_text="read",
        definition_hash=hash_tool_definition("current", "read"),
        definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
    )
    report = IntegrityValidator().validate(AIBOM(components=[tool]))
    assert report.is_valid
    assert report.hashes_verified == 1
