"""Pinned public MCP source and signed inventory-regression evidence."""

import runpy
from pathlib import Path

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


def test_unexpected_exclusion_is_unknown_and_fails_the_case(monkeypatch):
    namespace = runpy.run_path(str(ROOT / "benchmarks/inventory/run_inventory.py"))
    scanner = namespace["MCPScanner"]
    original = scanner.scan

    def incomplete(self, path):
        result = original(self, path)
        if (path / "app/mcpserver_quickstart.py").exists():
            result.surfaces_excluded.append("app/mcpserver_quickstart.py: unexpected omission")
        return result

    monkeypatch.setattr(scanner, "scan", incomplete)
    report = namespace["run"]()
    case = next(row for row in report["cases"] if row["case"] == "python-sdk-quickstart")
    assert not case["passed"] and case["coverage_incomplete"]
    assert case["unknown_negative_labels"] == 2
    assert case["relevant_mcp_exclusions"] == ["app/mcpserver_quickstart.py: unexpected omission"]
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
