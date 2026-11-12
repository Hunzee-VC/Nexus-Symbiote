"""Verify corpus integrity, metric denominators, and actual evaluator execution."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import types
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "benchmark_runner", Path(__file__).parents[1] / "scripts" / "benchmark_security.py"
)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


def clone_corpus(tmp_path):
    corpus = tmp_path / "corpus"
    shutil.copytree(Path(__file__).parents[1] / "benchmarks", corpus)
    return corpus / "manifest.json"


# The digest of the committed manifest, labels and fixtures. The gate compares results
# only with the manifest they were produced from, so a label flipped in the same change as
# the detector would pass it; changing any case must also change this line, visibly.
CORPUS_DIGEST = "81143e881262c5cf1b890c18afe3a02cba5357a5716dc13f6f8dfb824d386e1e"


def test_committed_inputs_have_exact_hashes_and_explicit_labels():
    manifest, digest = benchmark.load_manifest(benchmark.DEFAULT_MANIFEST)
    assert digest == CORPUS_DIGEST
    assert len(manifest["cases"]) == 18
    assert sum(c["task"] == "detection" for c in manifest["cases"]) == 16
    assert any(c["truth"] is True for c in manifest["cases"])
    assert any(c["truth"] is False for c in manifest["cases"])
    assert any(c["truth"] is None for c in manifest["cases"])


def test_modified_input_fails_instead_of_changing_denominator(tmp_path):
    path = clone_corpus(tmp_path)
    fixture = path.parent / "fixtures/prompt-ascii/project/CLAUDE.md"
    fixture.write_text(fixture.read_text() + "changed")
    with pytest.raises(ValueError, match="digest mismatch"):
        benchmark.load_manifest(path)


def test_ambiguous_manifest_json_is_rejected(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text('{"schema_version": 1, "schema_version": 1, "cases": []}')
    with pytest.raises(ValueError, match="duplicate JSON key"):
        benchmark.load_manifest(path)


@pytest.mark.parametrize("change", ["extra", "duplicate", "symlink", "escape"])
def test_undeclared_and_ambiguous_corpus_inputs_are_rejected(tmp_path, change):
    path = clone_corpus(tmp_path)
    document = json.loads(path.read_text())
    case = document["cases"][0]
    if change == "extra":
        (path.parent / case["directory"] / "not-in-manifest").write_text("extra")
    elif change == "duplicate":
        document["cases"].append(case)
    elif change == "symlink":
        (path.parent / case["directory"] / "escape").symlink_to(tmp_path)
    else:
        case["references"][0]["path"] = "../escape"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        benchmark.load_manifest(path)


def test_unknown_predictions_and_control_contracts_never_inflate_counts():
    def record(truth, prediction, task="detection"):
        return {"truth": truth, "prediction": prediction, "task": task}

    result = benchmark.metrics(
        [
            record(True, True),
            record(True, False),
            record(False, True),
            record(False, False),
            record(True, None),
            record(False, None),
            record(None, None),
            record(False, False, "control"),
        ]
    )
    assert [result[k] for k in ["tp", "fp", "tn", "fn"]] == [1, 1, 1, 1]
    assert result["detection_cases"] == 7 and result["scored_cases"] == 4
    assert result["unknown_predictions"] == 3
    assert result["unknown_positive_labels"] == result["unknown_negative_labels"] == 1
    assert result["precision"] == result["recall"] == result["f1"] == 0.5
    assert result["precision_denominator"] == result["recall_denominator"] == 2
    assert benchmark.metrics([])["precision"] is None


def test_predictions_do_not_read_labels_and_use_real_scanner():
    manifest, _ = benchmark.load_manifest(benchmark.DEFAULT_MANIFEST)
    case = next(c for c in manifest["cases"] if c["id"] == "prompt-zero-width")
    directory = benchmark.DEFAULT_MANIFEST.parent / case["directory"]
    original = benchmark._evaluate(case, directory)
    contradictory_label = benchmark._evaluate({**case, "truth": False}, directory)
    assert original == contradictory_label
    assert original["prediction"] is True
    assert "invisible_characters" in original["facts"]["risk_categories"]


def test_actual_corpus_run_records_evidence_and_unknown_coverage():
    report = benchmark.run_benchmark()
    assert report["corpus"]["cases"] == 18
    assert report["metrics"]["detection_cases"] == 16
    assert report["measurement"]["elapsed_seconds"] > 0
    assert report["measurement"]["python_traced_peak_bytes"] > 0
    assert len(report["tool"]["source_digest"]) == 64
    assert len(report["runner_sha256"]) == 64
    parse = next(r for r in report["results"] if r["kind"] == "parse_coverage")
    assert parse["prediction"] is None and parse["facts"]["collection_failures"]
    assert parse["control_passed"] is True
    credential = next(r for r in report["results"] if r["kind"] == "credential_export")
    assert credential["facts"]["export_formats_checked"] == ["cyclonedx", "native", "sarif", "spdx"]
    # Do not assert perfect efficacy: the report must retain any actual FP/FN.
    counts = sum(report["metrics"][k] for k in ["tp", "fp", "tn", "fn"])
    assert counts == report["metrics"]["scored_cases"]


def test_benchmark_revision_comes_from_the_workflow_or_a_tracked_checkout(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", "c" * 40)
    identity = benchmark._source_identity()
    assert (identity["git_sha"], identity["revision_source"]) == ("c" * 40, "GITHUB_SHA")
    monkeypatch.delenv("GITHUB_SHA")
    # An installed copy inside an unrelated checkout is not that checkout's revision.
    checkout = tmp_path / "checkout"
    package = checkout / ".venv/lib/site-packages/nexus_symbiote"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (checkout / "README.md").write_text("unrelated")
    git = ["git", "-C", str(checkout), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    for arguments in (["init", "-q"], ["add", "README.md"], ["commit", "-q", "-m", "x"]):
        subprocess.run([*git, *arguments], check=True, capture_output=True, timeout=30)  # noqa: S603
    installed = types.ModuleType("nexus_symbiote")
    installed.__file__ = str(package / "__init__.py")
    installed.__version__ = "0"
    monkeypatch.setattr(benchmark, "nexus_symbiote", installed)
    identity = benchmark._source_identity()
    assert identity["git_sha"] is None and identity["revision_source"] is None
