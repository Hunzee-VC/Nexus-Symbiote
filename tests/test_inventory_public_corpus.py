"""Pinned public MCP source and signed inventory-regression evidence."""

import importlib.util
import json
import runpy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_public_inventory_corpus_has_honest_denominators():
    report = runpy.run_path(str(ROOT / "benchmarks/inventory/run_inventory.py"))["run"]()
    assert report["passed"], report
    assert report["counts"] == {"tp": 21, "fp": 0, "fn": 0, "tn": 7}
    assert report["denominators"] == {"expected_tools": 21, "explicit_decoys": 7}
    assert report["unknown_negative_labels"] == 5
    assert report["unlabeled_predictions"] == 0
    assert report["label_bounds"]["recall"] == {
        "label_count": 21,
        "observed_count": 21,
        "unknown_count": 0,
        "lower": 1.0,
        "upper": 1.0,
    }
    assert report["label_bounds"]["specificity"] == {
        "label_count": 12,
        "observed_count": 7,
        "unknown_count": 5,
        "lower": 7 / 12,
        "upper": 1.0,
    }


def test_label_bounds_keep_unknowns_and_empty_denominators_visible():
    bounds = runpy.run_path(str(ROOT / "benchmarks/inventory/run_inventory.py"))["label_bounds"]
    scores = {
        "tp": 2,
        "fn": 1,
        "unknown_positive_labels": 2,
        "tn": 1,
        "fp": 1,
        "unknown_negative_labels": 2,
    }
    result = bounds(scores)
    assert result["recall"] == {
        "label_count": 5,
        "observed_count": 3,
        "unknown_count": 2,
        "lower": 0.4,
        "upper": 0.8,
    }
    assert result["specificity"] == {
        "label_count": 4,
        "observed_count": 2,
        "unknown_count": 2,
        "lower": 0.25,
        "upper": 0.75,
    }
    assert bounds(dict.fromkeys(scores, 0))["recall"] == {
        "label_count": 0,
        "observed_count": 0,
        "unknown_count": 0,
        "lower": None,
        "upper": None,
    }


def test_only_adjudicated_negatives_enter_confusion_counts():
    import pytest

    score = runpy.run_path(str(ROOT / "benchmarks/inventory/run_inventory.py"))["score_tools"]
    result = score({"tool", "decoy", "unknown"}, ["tool", "missed"], ["decoy", "negative"])
    assert result == {
        "tp": 1,
        "fp": 1,
        "fn": 1,
        "tn": 1,
        "unknown_positive_labels": 0,
        "unknown_negative_labels": 0,
        "unexpected_unlabeled": ["unknown"],
    }
    incomplete = score(
        {"tool", "decoy"}, ["tool", "missing"], ["decoy", "negative"], collection_incomplete=True
    )
    assert incomplete["tp"] == incomplete["fp"] == 1
    assert incomplete["fn"] == incomplete["tn"] == 0
    assert incomplete["unknown_positive_labels"] == incomplete["unknown_negative_labels"] == 1
    with pytest.raises(ValueError, match="unique and disjoint"):
        score(set(), ["tool"], ["tool"])
    with pytest.raises(ValueError, match="unique and disjoint"):
        score(set(), ["tool", "tool"], [])


# The collector records an absent config as scanned; reported as excluded, it is a gap too.
@pytest.mark.parametrize(
    "reason",
    ["app/mcpserver_quickstart.py: unexpected omission", "mcp-config (no config files found)"],
)
def test_unexpected_exclusion_is_unknown_and_fails_the_case(monkeypatch, reason):
    namespace = runpy.run_path(str(ROOT / "benchmarks/inventory/run_inventory.py"))
    scanner = namespace["MCPScanner"]
    original = scanner.scan

    def incomplete(self, path):
        result = original(self, path)
        if (path / "app/mcpserver_quickstart.py").exists():
            result.surfaces_excluded.append(reason)
        return result

    monkeypatch.setattr(scanner, "scan", incomplete)
    report = namespace["run"]()
    case = next(row for row in report["cases"] if row["case"] == "python-sdk-quickstart")
    assert not case["passed"] and case["coverage_incomplete"]
    assert case["unknown_negative_labels"] == 2
    assert case["relevant_mcp_exclusions"] == [reason]
    assert not report["passed"]


@pytest.mark.parametrize(
    ("forged", "valid"),
    [
        ("digest-pinned", "digest-pinned"),
        ("signature-not-found", "signature-present-unverified"),
    ],
)
def test_server_and_signing_controls_judge_the_component_they_name(monkeypatch, forged, valid):
    """A risk on the other server, a verified status or the other unverified one fails them."""
    namespace = runpy.run_path(str(ROOT / "benchmarks/inventory/run_inventory.py"))
    mcp, model = namespace["MCPScanner"], namespace["ModelScanner"]
    scan_servers, scan_models = mcp.scan, model.scan

    def treated_as_loopback(self, path):
        result = scan_servers(self, path)
        for server in result.components:
            if getattr(server, "endpoint_url", None) == "http://localhost.attacker.invalid":
                server.risks = [r for r in server.risks if r.category != "transport_security"]
        return result

    def misreported(self, path):
        result = scan_models(self, path)
        status = forged if (path / "model.sig").exists() else valid
        result.components = [
            c.model_copy(update={"signing_status": status}) for c in result.components
        ]
        return result

    monkeypatch.setattr(mcp, "scan", treated_as_loopback)
    monkeypatch.setattr(model, "scan", misreported)
    report = namespace["run"]()
    cases = {row["case"]: row for row in report["cases"]}
    assert cases["scoped-servers"]["checks"] == {
        "distinct_scoped_edges": True,
        "origin_only": True,
        "no_secret_in_bom": True,
        "deceptive_localhost_flagged": False,
    }
    assert cases["forged-signer-and-format"]["checks"]["signer_unverified"] is False
    assert cases["valid-safe-tensor"]["checks"] == {"safe_format": True, "unsigned": False}
    assert not any(
        cases[case]["passed"]
        for case in ("scoped-servers", "forged-signer-and-format", "valid-safe-tensor")
    )
    assert not report["passed"]


def test_inventory_statement_binds_results_and_scanner_materials(tmp_path, monkeypatch):
    import hashlib
    import importlib.util

    from nexus_symbiote.utils.crypto import VerificationResult

    monkeypatch.syspath_prepend(str(ROOT / "benchmarks/inventory"))
    spec = importlib.util.spec_from_file_location(
        "inventory_evidence", ROOT / "benchmarks/inventory/evidence.py"
    )
    evidence = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(evidence)
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
    import pytest

    with pytest.raises(ValueError, match="signature"):
        evidence.verify(target, "other", "authority")
    (target / "results.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="bind"):
        evidence.verify(target, "signer", "authority")


def test_every_inventory_control_can_fail(tmp_path):
    """Each check is falsifiable: a broken input turns it false, the real one true."""
    from nexus_symbiote.core.aibom import AIBOM
    from nexus_symbiote.core.enums import RiskSeverity
    from nexus_symbiote.core.models import ModelComponent, RiskAssessment
    from nexus_symbiote.validators.risk import RiskScorer

    harness = runpy.run_path(str(ROOT / "benchmarks/inventory/run_inventory.py"))
    project = tmp_path / "project"
    project.mkdir()
    (project / "weights.safetensors").write_text("invalid")
    # The invalid weights fail the scan gate on their own: without the hostile policy
    # the scan still writes an inventory, so the policy check cannot pass by accident.
    assert harness["policy_rejected"](project, tmp_path) is False
    (project / ".nexus-symbiote.yaml").write_text("scan:\n  scanners: []\n")
    assert harness["policy_rejected"](project, tmp_path) is True

    assert harness["operator_policy_isolated"](project, tmp_path) is True
    (project / "weights.safetensors").unlink()
    assert harness["operator_policy_isolated"](project, tmp_path) is False

    empty = tmp_path / "empty"
    empty.mkdir()
    assert harness["unknown_coverage_gate"](empty, tmp_path) is True
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "AGENTS.md").write_text("Keep receipts.")
    assert harness["unknown_coverage_gate"](evidence, tmp_path) is False

    risky = AIBOM()
    risky.add_component(
        ModelComponent(
            bom_ref="model:m",
            name="m",
            risks=[RiskAssessment(severity=RiskSeverity.CRITICAL, category="x", detail="x")],
        )
    )
    assert harness["critical_gate"](RiskScorer().score(risky)) is True
    # Unknown coverage alone also fails the gate, but must not count as a critical gate.
    assert harness["critical_gate"](RiskScorer().score(AIBOM())) is False


def test_an_attested_release_archive_is_checked_without_a_sigstore_bundle(tmp_path, monkeypatch):
    import pytest

    monkeypatch.syspath_prepend(str(ROOT / "benchmarks/inventory"))
    spec = importlib.util.spec_from_file_location(
        "inventory_evidence_check", ROOT / "benchmarks/inventory/evidence.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    target = tmp_path / "run"
    module.prepare(target)
    statement = json.loads((target / "statement.json").read_text())
    materials = statement["predicate"]["materialsSha256"]
    # Package data such as the vendored schemas is bound, not only Python source.
    assert any(name.endswith(".json") for name in materials if name.startswith("package/"))
    assert "click" in statement["predicate"]["packageVersions"]
    assert not (target / "statement.sigstore.json").exists()
    module.check(target, compare_installation=True)
    monkeypatch.setattr(module, "installed_versions", lambda: {"click": "0"})
    with pytest.raises(ValueError, match="distributions differ"):
        module.check(target, compare_installation=True)
    (target / "results.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="bind"):
        module.check(target)


def test_the_installation_comparison_ignores_what_created_the_environment(tmp_path, monkeypatch):
    from email.message import Message
    from types import SimpleNamespace

    import pytest

    monkeypatch.syspath_prepend(str(ROOT / "benchmarks/inventory"))
    spec = importlib.util.spec_from_file_location(
        "inventory_evidence_bootstrap", ROOT / "benchmarks/inventory/evidence.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def environment(*entries):
        def distributions():
            for name, version in entries:
                metadata = Message()
                metadata["Name"] = name
                yield SimpleNamespace(metadata=metadata, version=version)

        monkeypatch.setattr(module, "distributions", distributions)

    environment(("click", "8.5.0"), ("nexus-symbiote", "0.2.0"), ("pip", "25.3"))
    assert module.installed_versions() == {"click": "8.5.0", "nexus-symbiote": "0.2.0"}
    archive = tmp_path / "archive"
    archive.mkdir()
    results = b'{"passed": true}\n'
    (archive / "results.json").write_bytes(results)
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "results.json", "digest": {"sha256": module.digest(results)}}],
        "predicateType": module.PREDICATE_TYPE,
        "predicate": {
            "materialsSha256": module.materials(),
            "packageVersions": module.installed_versions(),
        },
    }
    (archive / "statement.json").write_text(json.dumps(statement))
    # A uv environment has no pip; another Python patch release seeds other versions.
    for seeded in [(), (("pip", "24.0"), ("setuptools", "80.9.0"), ("wheel", "0.45.1"))]:
        environment(("click", "8.5.0"), ("nexus-symbiote", "0.2.0"), *seeded)
        module.check(archive, compare_installation=True)
    environment(("click", "8.4.0"), ("nexus-symbiote", "0.2.0"))
    with pytest.raises(ValueError, match="distributions differ"):
        module.check(archive, compare_installation=True)
