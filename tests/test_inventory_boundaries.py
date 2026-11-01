import hashlib
import json
import runpy
from pathlib import Path

import pytest
from click.testing import CliRunner
from pydantic import TypeAdapter, ValidationError

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import AgentComponent, AnyComponent
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.scanners.registry import RegistryScanner
from nexus_symbiote.utils.crypto import VerificationResult

ROOT = Path(__file__).resolve().parents[1]


def test_declared_variant_and_published_schema_agree():
    from jsonschema import Draft202012Validator

    schema = json.loads((ROOT / "schemas/nexus-symbiote-aibom-1.0.schema.json").read_text())
    assert schema["$defs"]["ComponentVariants"] == TypeAdapter(AnyComponent).json_schema(
        ref_template="#/$defs/ComponentVariants/$defs/{model}"
    )
    for fields in (
        {"serialization_safety": "safe-ish", "trust_remote_code": True},
        {"signning_status": "verified"},
    ):
        assert not Draft202012Validator(schema).is_valid(
            {
                "metadata": {"spec_version": "1.0.0"},
                "components": [{"component_type": "model", "bom_ref": "m", "name": "m", **fields}],
            }
        )
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

    monkeypatch.setattr("nexus_symbiote.utils.crypto.verify_sigstore_digest", verifier)

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
    from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

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


def test_benchmark_statement_binds_outputs_and_materials(tmp_path, monkeypatch):
    from nexus_symbiote.utils.crypto import VerificationResult

    monkeypatch.syspath_prepend(str(ROOT / "benchmarks"))
    import evidence

    target = tmp_path / "run"
    evidence.prepare(target)
    statement = (target / "statement.json").read_bytes()
    (target / "statement.sigstore.json").write_bytes(b"test-only")
    expected = hashlib.sha256(statement).hexdigest()

    def check(digest, bundle, identity, issuer):
        return VerificationResult(
            (digest, bundle, identity, issuer) == (expected, b"test-only", "signer", "authority")
        )

    monkeypatch.setattr("nexus_symbiote.utils.crypto.verify_sigstore_digest", check)
    evidence.verify(target, "signer", "authority", compare_installation=True)
    with pytest.raises(ValueError, match="signature"):
        evidence.verify(target, "other", "authority")
    (target / "results.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="bind"):
        evidence.verify(target, "signer", "authority")


def test_security_facts_cannot_be_cleared_by_omitting_findings(tmp_path):
    from nexus_symbiote.core.models import CompletenessClaim, ModelComponent
    from nexus_symbiote.validators.integrity import IntegrityValidator
    from nexus_symbiote.validators.risk import RiskScorer

    for fields in [
        {"serialization_safety": "unsafe-code-execution"},
        {"trust_remote_code": True},
        {"serialization_format": "safe-tensors", "serialization_safety": "unknown"},
    ]:
        bom = AIBOM(components=[ModelComponent(bom_ref="m", name="m", risks=[], **fields)])
        bom.metadata.completeness = CompletenessClaim(
            scope="local-static-project",
            surfaces_scanned=["all"],
            scanner_status=dict.fromkeys(
                ("mcp", "model", "prompt", "rag", "registry", "a2a", "ide_agents", "shadowscan"),
                "complete",
            ),
        )
        ok, report = RiskScorer(fail_threshold=1000).passes_gate(bom)
        assert report.coverage_status == "reported" and not ok
        assert not IntegrityValidator().validate(bom).is_valid


def test_dynamic_mcp_declaration_leaves_coverage_partial(tmp_path):
    from nexus_symbiote.scanners.mcp import MCPScanner

    (tmp_path / "server.ts").write_text(
        'import {McpServer} from "@modelcontextprotocol/server"; const server=new McpServer({}); server.registerTool(runtimeName, {}, fn);'
    )
    result = MCPScanner().scan(tmp_path)
    assert any("unresolved MCP tool name" in item for item in result.surfaces_excluded)


def test_cli_imports_real_shadow_evidence_with_renamed_package(tmp_path):
    report_path = tmp_path / "shadowscan.json"
    report_path.write_text('[{"kind":"model","title":"declaration"}]')
    target = tmp_path / "out.json"
    runner = CliRunner()
    scanned = runner.invoke(main, ["scan", "-o", str(target), "--", str(tmp_path)])
    assert scanned.exit_code == 0, scanned.output
    assert AIBOM.load(target).metadata.completeness.scope == "local-static-project+shadowscan"
    for fmt in ("json", "cyclonedx", "spdx", "sarif"):
        imported = runner.invoke(
            main, ["import-shadowscan", str(report_path), "-f", fmt, "-o", str(target)]
        )
        assert imported.exit_code == 0, imported.output
        assert json.loads(target.read_text())


def test_scan_flags_disguised_pickle_and_ignores_untrusted_project_policy(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".nexus-symbiote.yaml").write_text("unknown_policy_key: true")
    weight = root / "weights.safetensors"
    weight.write_bytes(b"\x80\x04N.")
    out = tmp_path / "bom.json"
    args = ["scan", "--no-project-policy", "--scanner", "model", "-o", str(out), str(root)]
    runner = CliRunner()
    assert runner.invoke(main, args).exit_code == 1
    result = runner.invoke(main, [*args[:1], "--report-only", *args[1:]])
    assert result.exit_code == 0, result.output
    model = next(c for c in AIBOM.load(out).components if c.component_type.value == "model")
    assert model.serialization_format == "pickle"
    assert model.serialization_safety.value == "unsafe-code-execution"
    assert model.hashes == {"sha256": "sha256:" + hashlib.sha256(weight.read_bytes()).hexdigest()}
