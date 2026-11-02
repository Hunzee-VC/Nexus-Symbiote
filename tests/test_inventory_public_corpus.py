"""Pinned public MCP source and signed inventory-regression evidence."""

import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_public_inventory_corpus_has_honest_denominators():
    report = runpy.run_path(str(ROOT / "benchmarks/inventory/run_inventory.py"))["run"]()
    assert report["passed"], report
    assert report["counts"] == {"tp": 18, "fp": 0, "fn": 0, "tn": 7}
    assert report["denominators"] == {"expected_tools": 18, "explicit_decoys": 7}
    assert report["unlabeled_predictions"] == 0


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
        {"tool", "decoy"}, ["tool", "missing"], ["decoy", "negative"], collection_failed=True
    )
    assert incomplete["tp"] == incomplete["fp"] == 1
    assert incomplete["fn"] == incomplete["tn"] == 0
    assert incomplete["unknown_positive_labels"] == incomplete["unknown_negative_labels"] == 1
    with pytest.raises(ValueError, match="unique and disjoint"):
        score(set(), ["tool"], ["tool"])
    with pytest.raises(ValueError, match="unique and disjoint"):
        score(set(), ["tool", "tool"], [])


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
