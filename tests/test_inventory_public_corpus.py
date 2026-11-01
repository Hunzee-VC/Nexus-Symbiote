"""Pinned public MCP source and signed inventory-regression evidence."""

import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_public_inventory_corpus_has_honest_denominators():
    report = runpy.run_path(str(ROOT / "benchmarks/inventory/run_inventory.py"))["run"]()
    assert report["passed"], report
    assert report["counts"] == {"tp": 17, "fp": 0, "fn": 0, "tn": 5}
    assert report["denominators"] == {"expected_tools": 17, "explicit_decoys": 5}


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
