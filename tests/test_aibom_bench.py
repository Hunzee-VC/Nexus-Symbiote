"""Validity tests for the cross-tool benchmark.

The scorer is checked against three synthetic tools whose right score is known in advance:
one that reports nothing, one that lists every file without saying what it is, and one that
reports the ground truth exactly. A scorer that pays the first two is paying for nothing.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks" / "aibom-bench"))

from aibom_bench import corpus, extract, runner, scoring, variants  # noqa: E402

VARIANTS = [
    "base",
    "repeat",
    "drift",
    *(f"hostile:{case}" for case in variants.HOSTILE_CASES),
    runner.EGRESS_PROBE,
    runner.EXEC_PROBE,
]


class NoSchemas:
    def cyclonedx(self, outputs: list[Any]) -> dict[str, Any]:
        return {"score": 0.0}

    spdx = sarif = cyclonedx


def _truth() -> dict[str, Any]:
    drifted = corpus.build_base()
    truth = variants.ground_truth(corpus.build_base(), variants.apply_drift(drifted))
    return json.loads(json.dumps(truth))


def _score(
    tmp_path: Path, document: dict[str, Any] | None, fmt: str = "native-json"
) -> dict[str, Any]:
    runs: dict[str, Any] = {}
    for variant in VARIANTS:
        out = tmp_path / "out" / variant.replace(":", "-")
        out.mkdir(parents=True)
        outputs = []
        if document is not None:
            path = out / "inventory.json"
            path.write_text(json.dumps(document, sort_keys=True))
            outputs.append({"path": str(path), "format": fmt})
        runs[variant] = {
            "scans": [
                {
                    "label": "scan",
                    "outputs": outputs,
                    "timed_out": False,
                    "seconds": 1.0,
                    "max_rss_mb": 1.0,
                    "egress_attempts": [],
                }
            ],
            "canaries_tripped": [],
        }
    record = {"tool": "synthetic", "version": "0", "runs": runs}
    return scoring.score_tool(_truth(), record, tmp_path, {}, NoSchemas())


def test_corpus_is_deterministic_and_labels_point_at_files(tmp_path: Path) -> None:
    first, second = corpus.build_base(), corpus.build_base()
    assert variants.corpus_digest(first) == variants.corpus_digest(second)
    project = variants.write(first, tmp_path)
    for item in first.items:
        assert any((project / path).exists() for path in item.paths), item.id
        assert item.kind in scoring.KIND_PATTERNS, item.id


def test_no_key_names_a_different_component() -> None:
    built = corpus.build_base()
    texts = {path: raw.decode("utf-8", "replace").lower() for path, raw in built.files.items()}
    # References to the same component from another file: imports of a package, and the
    # adapter's pointer to its base model. The listing rule in detect_all handles the latter.
    allowed = {"@anthropic-ai/sdk", "@modelcontextprotocol/sdk", "llama-3.1-8b-instruct"}
    for item in built.items:
        own = [path.lower() for path in item.paths]
        for key in item.keys:
            if key.startswith(("=", "pkg:")) or key in allowed:
                continue
            strays = [
                path
                for path, text in texts.items()
                if (key.lower() in text or key.lower() in path.lower())
                and not any(path.lower().startswith(o) or o.startswith(path.lower()) for o in own)
            ]
            assert not strays, f"{item.id}: key {key!r} also appears in {strays}"


def test_weights_sum_to_one_hundred_and_variants_build() -> None:
    assert sum(weight for *_, weight, _ in scoring.CRITERIA) == 100
    for case in variants.HOSTILE_CASES:
        variants.apply_hostile(corpus.build_base(), case)
    assert len(variants.apply_drift(corpus.build_base())) == 10


def test_a_tool_that_reports_nothing_scores_zero(tmp_path: Path) -> None:
    result = scoring.score_tool(
        _truth(), {"tool": "null", "version": "0", "runs": {}}, tmp_path, {}, NoSchemas()
    )
    assert result["total"] == 0, result["points"]


def test_a_file_listing_earns_no_inventory_or_safety_credit(tmp_path: Path) -> None:
    listing = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"type": "file", "name": path, "bom-ref": f"file:{path}"}
            for path in corpus.build_base().files
        ],
    }
    result = _score(tmp_path, listing, "cyclonedx-json")
    groups = result["groups"]
    for group in ("Discovery", "Precision", "Record fidelity", "Risk analysis", "Scanner safety"):
        expected = 1.0 if group == "Scanner safety" else 0.0  # 8.6: it ran offline, no egress
        assert groups[group]["points"] == expected, (group, result["points"])


def test_reporting_the_ground_truth_earns_full_inventory_credit(tmp_path: Path) -> None:
    truth = _truth()
    edges = {edge["source"]: edge["target"] for edge in truth["edges"]}
    by_id = {item["id"]: item for item in truth["items"]}
    components = []
    for item in truth["items"]:
        related = by_id[edges[item["id"]]]["keys"] if item["id"] in edges else []
        components.append(
            {
                "name": item["keys"][0].lstrip("="),
                "kind": item["kind"],
                "aliases": [key.lstrip("=") for key in item["keys"]],
                "facts": [fact["any_of"][0] for fact in item["facts"]],
                "related": [key.lstrip("=") for key in related],
            }
        )
    result = _score(tmp_path, {"components": components})
    assert result["groups"]["Discovery"]["points"] == 30, result["details"]["1.4"]
    assert result["groups"]["Record fidelity"]["points"] == 14, result["points"]
    assert result["details"]["2.1"]["reported_as_components"] == []
    assert result["points"]["5.1"] == 4


def test_details_nested_in_property_bags_count_for_the_owning_record() -> None:
    flat = {"servers": [{"name": "fs", "args": ["server-filesystem@1"]}]}
    nested = {"servers": [{"name": "fs", "metadata": {"args": ["server-filesystem@1"]}}]}
    listing = {"coverage": {"surfaces_scanned": ["server-filesystem.json"], "collector": "mcp"}}
    for document in (flat, nested):
        output = extract.Output("x", "native-json", Path("x"), b"", document)
        assert any("server-filesystem" in record.own for record in extract.records([output]))
    output = extract.Output("x", "native-json", Path("x"), b"", listing)
    assert extract.records([output]) == []


def _echo(type_value: str | None, typed_per_kind: bool = False) -> dict[str, Any]:
    """A degenerate tool: one record per file that lists every token in the file."""
    records = []
    for path, raw in corpus.build_base().files.items():
        tokens = sorted(set(re.findall(r"[A-Za-z0-9_@./:=()*-]+", raw.decode("utf-8", "replace"))))
        kinds = list(scoring.KIND_PATTERNS) if typed_per_kind else [type_value]
        for kind in kinds:
            record: dict[str, Any] = {"name": path, "tokens": tokens}
            if kind:
                record["type"] = kind
            records.append(record)
    return {"records": records}


def test_echoing_every_string_is_not_an_inventory(tmp_path: Path) -> None:
    everything = " ".join(scoring.KIND_PATTERNS)
    cases = {
        "untyped": _echo(None),
        "one catch-all type": _echo(everything),
        "every type for every file": _echo(None, typed_per_kind=True),
    }
    for name, document in cases.items():
        result = _score(tmp_path / name.replace(" ", "-"), document)
        for group in ("Discovery", "Precision", "Record fidelity"):
            assert result["groups"][group]["points"] == 0, (name, group, result["points"])


def test_calling_every_file_a_model_costs_all_precision(tmp_path: Path) -> None:
    """A known limit: a typed echo earns the credit of the one type it guesses.

    A tool that labels every file a model and lists the file's strings is credited with the
    models, because for a small file that output cannot be told from a real finding. It
    earns nothing in the other four pillars and reports every model decoy it faces.
    """
    result = _score(tmp_path, _echo("model"))
    for criterion in ("1.2", "1.3", "1.4", "1.5"):
        assert result["points"][criterion] == 0, criterion
    assert result["groups"]["Precision"]["points"] <= 0.5
    reported = set(result["details"]["2.1"]["reported_as_components"])
    assert {"decoy.fake-gguf", "decoy.printer-model", "decoy.prose-models"} <= reported, reported
    assert result["total"] < 25, result["total"]
