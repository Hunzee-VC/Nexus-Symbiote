"""Keep the seeded hostile corpus's committed results, scorecard and name in step."""

from __future__ import annotations

import functools
import importlib.util
import json
import sys
from types import ModuleType
from typing import Any

from tests.support import ROOT

BENCH = ROOT / "benchmarks" / "seeded-corpus"


@functools.cache
def _score() -> ModuleType:
    name = "seeded_corpus_score"
    spec = importlib.util.spec_from_file_location(name, BENCH / "score.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Dataclasses resolve string annotations through sys.modules.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _results() -> dict[str, Any]:
    value = json.loads((BENCH / "results" / "results.json").read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_committed_scorecard_renders_from_the_committed_results() -> None:
    scorecard = (BENCH / "results" / "scorecard.md").read_text(encoding="utf-8")
    assert _score().scorecard(_results()) == scorecard


def test_results_name_the_generator_label_and_the_moved_positive_control() -> None:
    results = _results()
    generator = (BENCH / "generate.py").read_text(encoding="utf-8")
    assert results["benchmark"] == "seeded-corpus"
    assert '"benchmark": "seeded-corpus",' in generator
    source = results["tools"]["positive-control"]["source"]
    assert source == "benchmarks/seeded-corpus/executor.py"
    assert (ROOT / source).is_file()


def test_only_the_rename_note_uses_the_name_that_belongs_to_another_tree() -> None:
    counts = {
        path.relative_to(BENCH).as_posix(): path.read_text(encoding="utf-8").count("AIBOM-Bench")
        for path in BENCH.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    assert {name: count for name, count in counts.items() if count} == {"README.md": 1}
