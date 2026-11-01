import hashlib
import json
import runpy
from pathlib import Path

import pytest
from click.testing import CliRunner
from pydantic import TypeAdapter, ValidationError

from symbiote.cli import main
from symbiote.core.aibom import AIBOM
from symbiote.core.models import AgentComponent, AnyComponent
from symbiote.scanners.model import ModelScanner
from symbiote.scanners.registry import RegistryScanner
from symbiote.utils.crypto import VerificationResult

ROOT = Path(__file__).resolve().parents[1]


def test_declared_variant_and_published_schema_agree():
    schema = json.loads((ROOT / "schemas/symbiote-aibom-1.0.schema.json").read_text())
    assert schema["$defs"]["ComponentVariants"] == TypeAdapter(AnyComponent).json_schema(
        ref_template="#/$defs/ComponentVariants/$defs/{model}"
    )
    for fields in (
        {"serialization_safety": "safe-ish", "trust_remote_code": True},
        {"signning_status": "verified"},
    ):
        with pytest.raises(ValidationError):
            AIBOM.model_validate(
                {"components": [{"component_type": "model", "bom_ref": "m", "name": "m", **fields}]}
            )
    assert isinstance(
        AIBOM.model_validate(
            {"components": [{"component_type": "agent", "bom_ref": "a", "name": "a"}]}
        ).components[0],
        AgentComponent,
    )


def test_scanned_signature_binds_exact_bytes_and_both_constraints(tmp_path, monkeypatch):
    weight = tmp_path / "weights.bin"
    weight.write_bytes(b"one")
    weight.with_suffix(".bin.sigstore.json").write_text("bundle")
    digest = hashlib.sha256(b"one").hexdigest()

    def verifier(actual, bundle, identity, issuer):
        return VerificationResult(
            (actual, bundle, identity, issuer) == (digest, b"bundle", "alice", "issuer")
        )

    monkeypatch.setattr("symbiote.utils.crypto.verify_sigstore_digest", verifier)

    def scan():
        return ModelScanner("alice", "issuer").scan(tmp_path).components[0]

    assert scan().signing_status == "sigstore-signed"
    weight.write_bytes(b"two")
    assert scan().signing_identity is None
    assert (
        CliRunner().invoke(main, ["scan", "--model-signer", "alice", str(tmp_path)]).exit_code != 0
    )


def test_lockfile_registry_and_privacy(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"^1.0.0"}}')
    assert RegistryScanner().scan(tmp_path).components[0].registry_uri is None
    (tmp_path / "package-lock.json").write_text(
        '{"packages":{"node_modules/openai":{"version":"1.2.3","resolved":"https://u:SECRET@private.test/path/SECRET?token=SECRET"}}}'
    )
    entry = RegistryScanner().scan(tmp_path).components[0]
    assert (entry.version, entry.registry_uri) == ("1.2.3", "https://private.test")
    assert "SECRET" not in entry.model_dump_json()


def test_no_output_write_through_checkout_link(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    canary = tmp_path / "canary"
    canary.write_text("unchanged")
    dest = project / "bom.json"
    dest.symlink_to(canary)
    result = CliRunner().invoke(main, ["scan", str(project), "-o", str(dest)])
    assert result.exit_code == 0, result.output
    assert canary.read_text() == "unchanged"
    assert AIBOM.load(dest).metadata.completeness.assurance_level.value == "declared"


def test_public_regression_corpus():
    report = runpy.run_path(str(ROOT / "benchmarks/run_inventory.py"))["run"]()
    assert report["passed"], report
    assert report["counts"] == {"tp": 17, "fp": 0, "fn": 0, "tn": 5}


def test_shadow_report_is_confined_and_raw_evidence_stays_private(tmp_path):
    from symbiote.scanners.shadowscan import ShadowScanImporter

    report = tmp_path / "private"
    report.write_text(
        json.dumps(
            [{"kind": "mcp", "title": "test", "resource": "https://x/SECRET", "token": "SECRET"}]
        )
    )
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "shadowscan.json").symlink_to(report)
    assert ShadowScanImporter().scan(root).scan_failures
    comp = ShadowScanImporter().import_report(report)[0]
    assert "SECRET" not in comp.model_dump_json()
    assert comp.properties["shadowscan:sourceDigest"].startswith("sha256:")
