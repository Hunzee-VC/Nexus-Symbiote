"""Audit PR 3 regression tests for validators, diff, exports, and strict models."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, NativeFormatError
from nexus_symbiote.core.enums import (
    AssuranceLevel,
    RiskSeverity,
    SerializationSafety,
    TrustTier,
)
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    extract_version_pin,
    hash_tool_definition,
    parse_json_strict,
    tool_definition_extensions,
)
from nexus_symbiote.core.models import (
    A2AServerComponent,
    ClaimEvidence,
    CompletenessClaim,
    ModelComponent,
    RegistryEntryComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.generators.package_identifiers import package_identifier
from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.generators.vex import VEXGenerator
from nexus_symbiote.live.inventory import observation_inventory
from nexus_symbiote.live.verify import observed_tool_properties
from nexus_symbiote.scanners.live_mcp import DiscoveryResult, ObservedTool
from nexus_symbiote.utils.crypto import VerificationResult
from nexus_symbiote.validators.integrity import IntegrityValidator
from nexus_symbiote.validators.risk import RiskScorer

FIXTURES = Path(__file__).parent / "fixtures"
SHADOWSCAN_REPORT = FIXTURES / "shadowscan/code-report-0.1.4.json"
SIGNER_IDENTITY = "https://github.com/acme/discovery/.github/workflows/scan.yml@refs/heads/main"
SIGNER_ISSUER = "https://token.actions.githubusercontent.com"


def test_extended_mcp_tool_fields_validate_and_preserve_unredacted_live_inventory() -> None:
    descriptor = {
        "name": "query_ledger",
        "title": "Query Ledger",
        "description": "Read ledger entries.",
        "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
        "outputSchema": {"type": "object", "properties": {"balance": {"type": "number"}}},
        "_meta": {"tier": "finance"},
        "annotations": {"readOnlyHint": True},
    }
    fingerprint = hash_tool_definition(
        "query_ledger",
        "Read ledger entries.",
        descriptor["inputSchema"],
        descriptor["annotations"],
        title="Query Ledger",
        output_schema=descriptor["outputSchema"],
        meta=descriptor["_meta"],
    )
    result = DiscoveryResult(
        endpoint="https://mcp.acme.example/mcp",
        protocol_version="2025-06-18",
        server_info={"name": "ledger", "version": "1.0.0"},
        server_capabilities={"tools": {}},
        observed_at="2026-11-12T12:00:00+00:00",
        completed_at="2026-11-12T12:00:01+00:00",
        declaration_hash="sha256:" + "d" * 64,
        identity_hash="sha256:" + "e" * 64,
        complete=True,
        tools=[
            ObservedTool(
                name="query_ledger",
                descriptor=descriptor,
                fingerprint=fingerprint,
                definition_hash=fingerprint,
            )
        ],
    )
    bom = observation_inventory(result)
    tool = next(c for c in bom.components if isinstance(c, ToolComponent))
    assert tool.redacted_definition_hash is None
    assert tool.properties["mcp_title"] == "Query Ledger"

    # IntegrityValidator recomputes with extended fields and reports self-consistency
    # (unknown without local config), NEVER a false hash_mismatch error.
    report = IntegrityValidator().validate(bom)
    assert report.hashes_failed == 0
    assert all(issue.category != "hash_mismatch" for issue in report.issues)

    # Static-config style properties (title/output_schema/meta) also round-trip cleanly.
    static_tool = ToolComponent(
        bom_ref="tool:static-extended",
        name="query_ledger",
        description_text="Read ledger entries.",
        input_schema=descriptor["inputSchema"],
        annotations=descriptor["annotations"],
        definition_hash=fingerprint,
        definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
        properties={
            "title": "Query Ledger",
            "output_schema": descriptor["outputSchema"],
            "meta": descriptor["_meta"],
        },
    )
    static_report = IntegrityValidator().validate(AIBOM(components=[static_tool]))
    assert static_report.hashes_failed == 0
    assert observed_tool_properties(descriptor, observed_hash=fingerprint)["mcp_meta"] == {
        "tier": "finance"
    }


def test_legacy_observation_tool_with_title_validates_without_hash_mismatch() -> None:
    """Pre-0.2.0 live inventories stored a titled tool's display hash without
    title/outputSchema/_meta while the fingerprint already bound them; the
    validator must accept that legacy pairing, not report a false mismatch."""
    descriptor = {
        "name": "query_ledger",
        "title": "Query Ledger",
        "description": "Read ledger entries.",
        "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
        "outputSchema": {"type": "object", "properties": {"balance": {"type": "number"}}},
        "_meta": {"tier": "finance"},
        "annotations": {"readOnlyHint": True},
    }
    # Exactly what the pre-0.2.0 observation path stored: the live fingerprint
    # (extensions bound) as definition_hash, the extension-free display hash
    # as redacted_definition_hash.
    fingerprint = hash_tool_definition(
        "query_ledger",
        "Read ledger entries.",
        descriptor["inputSchema"],
        descriptor["annotations"],
        **tool_definition_extensions(descriptor),
    )
    display = hash_tool_definition(
        "query_ledger",
        "Read ledger entries.",
        descriptor["inputSchema"],
        descriptor["annotations"],
    )
    assert fingerprint != display
    legacy_tool = ToolComponent(
        bom_ref="tool:legacy-extended",
        name="query_ledger",
        description_text="Read ledger entries.",
        input_schema=descriptor["inputSchema"],
        annotations=descriptor["annotations"],
        definition_hash=fingerprint,
        definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
        redacted_definition_hash=display,
        properties={
            "mcp_title": "Query Ledger",
            "mcp_output_schema": descriptor["outputSchema"],
            "mcp_meta": descriptor["_meta"],
        },
    )
    report = IntegrityValidator().validate(AIBOM(components=[legacy_tool]))
    assert report.hashes_failed == 0
    assert all(issue.category != "hash_mismatch" for issue in report.issues)


def test_signed_discovery_report_satisfies_default_require_integrity_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "proj"
    bom_path = tmp_path / "bom.json"
    (project / ".shadowscan").mkdir(parents=True)
    shutil.copy(SHADOWSCAN_REPORT, project / ".shadowscan/report.json")
    (project / ".shadowscan/report.sigstore.json").write_text("{}")
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "payments": {"command": "npx", "args": ["-y", "@acme/payments-mcp@1.2.3"]}
                }
            }
        )
    )
    monkeypatch.setenv("NEXUS_SYMBIOTE_BINDING_KEY", "test-binding-key-for-pr3")
    scan_res = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(bom_path)]
    )
    assert scan_res.exit_code == 0, scan_res.output

    def fake_verify(artifact: Path, bundle: Path, identity: str, issuer: str) -> VerificationResult:
        digest = "sha256:" + hashlib.sha256(Path(artifact).read_bytes()).hexdigest()
        return VerificationResult(
            verified=True,
            identity=identity,
            issuer=issuer,
            details={"artifact_digest": digest},
        )

    monkeypatch.setattr("nexus_symbiote.utils.crypto.verify_sigstore_bundle", fake_verify)
    signers = tmp_path / "signers.json"
    signers.write_text(
        json.dumps(
            {
                "version": 1,
                "artifacts": [
                    {
                        "artifact_path": ".shadowscan/report.json",
                        "bundle_path": ".shadowscan/report.sigstore.json",
                        "expected_identity": SIGNER_IDENTITY,
                        "expected_issuer": SIGNER_ISSUER,
                    }
                ],
            }
        )
    )
    # Default policy has require_integrity: true AND require_completeness: true!
    res = CliRunner().invoke(
        main,
        [
            "validate",
            str(bom_path),
            "--project",
            str(project),
            "--signature-policy",
            str(signers),
            "--json-output",
        ],
    )
    assert res.exit_code == 0, res.output
    payload = json.loads(res.stdout)
    assert payload["passed"] is True
    assert payload["integrity"]["signatures_verified"] == 1
    assert payload["discovery_producer"]["status"] == "verified"


def test_package_identifier_rejects_unattributed_private_registries_and_injected_versions() -> None:
    # Private registry omitted from PURL -> rejected (prevents dependency-confusion projection)
    private_pypi = RegistryEntryComponent(
        bom_ref="registry:pypi/internal-pkg",
        name="internal-pkg",
        registry_type="pypi",
        version="==1.2.3",
        registry_uri="https://pypi.corp.internal/simple",
        package_url="pkg:pypi/internal-pkg@1.2.3",
    )
    assert package_identifier(private_pypi).status == "unavailable-invalid"

    # Private registry explicitly matching repository_url -> accepted
    attributed_pypi = private_pypi.model_copy(
        update={
            "package_url": "pkg:pypi/internal-pkg@1.2.3?repository_url=https://pypi.corp.internal/simple"
        }
    )
    assert package_identifier(attributed_pypi).status == "declared"

    # Default public PyPI registry without repository_url -> accepted
    public_pypi = RegistryEntryComponent(
        bom_ref="registry:pypi/openai",
        name="openai",
        registry_type="pypi",
        version="==1.2.3",
        registry_uri="https://pypi.org",
        package_url="pkg:pypi/openai@1.2.3",
    )
    assert package_identifier(public_pypi).status == "declared"

    # Unversioned component with version injected in PURL -> rejected
    unversioned_pypi = RegistryEntryComponent(
        bom_ref="registry:pypi/openai",
        name="openai",
        registry_type="pypi",
        version=None,
        package_url="pkg:pypi/openai@1.2.3",
    )
    assert package_identifier(unversioned_pypi).status == "unavailable-invalid"

    unversioned_npm = RegistryEntryComponent(
        bom_ref="registry:npm/openai",
        name="openai",
        registry_type="npm",
        version=None,
        package_url="pkg:npm/openai@1.2.3",
    )
    assert package_identifier(unversioned_npm).status == "unavailable-invalid"

    # OCI PURL omitting repository_url or tag when image carries them -> rejected
    digest = "a" * 64
    oci_missing_repo = RegistryEntryComponent(
        bom_ref="registry:oci/app",
        name=f"ghcr.io/org/app:1.0@sha256:{digest}",
        registry_type="oci",
        package_url=f"pkg:oci/app@sha256:{digest}?tag=1.0",
    )
    assert package_identifier(oci_missing_repo).status == "unavailable-invalid"

    oci_missing_tag = RegistryEntryComponent(
        bom_ref="registry:oci/app",
        name=f"ghcr.io/org/app:1.0@sha256:{digest}",
        registry_type="oci",
        package_url=f"pkg:oci/app@sha256:{digest}?repository_url=ghcr.io/org/app",
    )
    assert package_identifier(oci_missing_tag).status == "unavailable-invalid"


def test_differ_propagates_added_severity_unsafe_serialization_and_status_drops() -> None:
    baseline = AIBOM()
    unsafe_model = ModelComponent(
        bom_ref="model:pickle-weights",
        name="unsafe-weights",
        serialization_format="pickle",
        serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION,
    )
    candidate = AIBOM(components=[unsafe_model])
    report = AIBOMDiffer().diff(baseline, candidate)
    assert report.components_added[0].severity == "critical"
    assert report.security_alerts[0]["severity"] == "critical"

    # Safe -> unsafe_code_execution transition on existing model is critical
    safe_model = ModelComponent(
        bom_ref="model:weights",
        name="weights",
        serialization_format="safetensors",
        serialization_safety=SerializationSafety.SAFE,
    )
    mutated_model = safe_model.model_copy(
        update={
            "serialization_format": "pickle",
            "serialization_safety": SerializationSafety.UNSAFE_CODE_EXECUTION,
        }
    )
    mod_report = AIBOMDiffer().diff(
        AIBOM(components=[safe_model]), AIBOM(components=[mutated_model])
    )
    assert mod_report.components_modified[0].severity == "critical"

    # Stripping source_report_status from complete -> None while report remains imported alerts!
    digest = "sha256:" + "1" * 64
    old_bom = AIBOM()
    old_bom.metadata.completeness = CompletenessClaim(
        scope="repository+shadowscan",
        source_report_digest=digest,
        source_report_content_digest="sha256:" + "2" * 64,
        source_report_content_profile="nexus-symbiote/shadowscan-content/v1",
        source_report_format="shadowscan-json",
        source_report_status="complete",
    )
    new_bom = AIBOM()
    new_bom.metadata.completeness = CompletenessClaim(
        scope="repository+shadowscan",
        source_report_digest=digest,
        source_report_content_digest="sha256:" + "2" * 64,
        source_report_content_profile="nexus-symbiote/shadowscan-content/v1",
        source_report_format=None,
        source_report_status=None,
    )
    status_diff = AIBOMDiffer().diff(old_bom, new_bom)
    fields = {c["field"]: c["severity"] for c in status_diff.metadata_changes}
    assert fields["completeness.source_report_status"] == "high"
    assert fields["completeness.source_report_format"] == "high"


def test_risk_sarif_and_vex_share_intrinsic_model_risks_and_warn_threshold() -> None:
    assert RiskScorer().warn_threshold == 25.0

    # Stripped component.risks + mixed-case SafeTensors with UNKNOWN safety
    stripped_model = ModelComponent(
        bom_ref="model:stripped",
        name="stripped-model",
        serialization_format="SafeTensors",
        serialization_safety=SerializationSafety.UNKNOWN,
        trust_remote_code=True,
        risks=[],
    )
    bom = AIBOM(components=[stripped_model])
    bom.metadata.timestamp = datetime(2026, 11, 12, 12, 0, tzinfo=UTC)
    bom.metadata.serial_number = "urn:uuid:11111111-2222-4333-8444-555555555555"

    scored = RiskScorer().score(bom)
    categories = {f.category for f in scored.findings}
    assert {"invalid_safetensors", "code_execution"} <= categories

    sarif = SARIFGenerator().generate(bom)
    rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert "nexus_symbiote/code_execution/critical" in rule_ids
    assert "nexus_symbiote/invalid_safetensors/high" in rule_ids

    vex = VEXGenerator().generate(bom)
    vex_categories = {
        prop["value"]
        for vuln in vex["vulnerabilities"]
        for prop in vuln["properties"]
        if prop["name"] == "nexus-symbiote:category"
    }
    assert {"invalid_safetensors", "code_execution"} <= vex_categories


def test_extract_version_pin_handles_tag_plus_digest_and_rejects_floating_major_tags() -> None:
    digest = "A" * 64
    expected = "sha256:" + "a" * 64
    assert extract_version_pin(f"ghcr.io/org/image:1.2.3@sha256:{digest}") == expected
    assert extract_version_pin(f"image:sha256:{digest}", ecosystem="oci") == expected
    assert extract_version_pin("repo/image:1") is None
    assert extract_version_pin("repo/image:v1") is None
    assert extract_version_pin("repo/image:20") is None
    assert extract_version_pin("repo/image:1.2") == "1.2"
    assert extract_version_pin("repo/image:1.2.3") == "1.2.3"


def test_strict_i_json_save_load_a2a_bool_and_aware_timestamps(tmp_path: Path) -> None:
    # UTF-8 BOM and UTF-16 bytes rejected by parse_json_strict and AIBOM.load
    with pytest.raises(ValueError, match="Byte-order marks"):
        parse_json_strict(b'\xef\xbb\xbf{"a": 1}')
    with pytest.raises(ValueError, match="Byte-order marks"):
        parse_json_strict('\ufeff{"a": 1}')
    with pytest.raises((UnicodeError, ValueError)):
        parse_json_strict('{"a": 1}'.encode("utf-16-le"))

    bom_file = tmp_path / "bom_with_bom.json"
    bom_file.write_bytes(b'\xef\xbb\xbf{"components": []}')
    with pytest.raises(NativeFormatError):
        AIBOM.load(bom_file)

    # Out-of-range integer in properties refused by to_native_json() so save() never writes unreadable JSON
    bad_bom = AIBOM(
        components=[
            ToolComponent(
                bom_ref="tool:huge-int",
                name="huge",
                trust_tier=TrustTier.UNKNOWN,
                assurance_level=AssuranceLevel.DECLARED,
                properties={"unsafe_int": 2**60},
                risks=[
                    RiskAssessment(
                        severity=RiskSeverity.LOW, category="note", detail="test component"
                    )
                ],
            )
        ]
    )
    # The content-digest serial is derived first and refuses the same value.
    with pytest.raises(ValueError, match="I-JSON"):
        bad_bom.to_native_json()

    # A2AServerComponent.authentication_required rejects string/int coercion
    with pytest.raises(ValidationError):
        A2AServerComponent.model_validate(
            {"bom_ref": "a2a:srv", "name": "srv", "authentication_required": "false"}
        )
    assert (
        A2AServerComponent(
            bom_ref="a2a:srv", name="srv", authentication_required=True
        ).authentication_required
        is True
    )

    # Reading stays as the native format has always been read: a timestamp without an
    # offset is accepted, so inventories written before this change still load.
    naive = ClaimEvidence.model_validate(
        {
            "assurance": "observed",
            "method": "static-config",
            "scope": "repository",
            "observed_at": "2026-11-12T12:00:00",
        }
    )
    assert naive.observed_at is not None and naive.observed_at.tzinfo is None
