"""Smoke tests for the cross-tool benchmark's corpus and scoring tables."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks" / "aibom-bench"))

from aibom_bench import corpus, scoring, variants  # noqa: E402


def test_corpus_is_deterministic_and_labels_point_at_files(tmp_path: Path) -> None:
    first, second = corpus.build_base(), corpus.build_base()
    assert variants.corpus_digest(first) == variants.corpus_digest(second)
    project = variants.write(first, tmp_path)
    for item in first.items:
        assert any((project / path).exists() for path in item.paths), item.id
        assert item.kind in scoring.KIND_PATTERNS, item.id


def test_weights_sum_to_one_hundred_and_variants_build() -> None:
    assert sum(weight for *_, weight, _ in scoring.CRITERIA) == 100
    for case in variants.HOSTILE_CASES:
        variants.apply_hostile(corpus.build_base(), case)
    assert len(variants.apply_drift(corpus.build_base())) == 10
