#!/usr/bin/env python3
"""AIBOM-Bench command line: build the corpus, run tools, score, report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from aibom_bench import corpus, report, runner, scoring, variants  # noqa: E402
from aibom_bench.validators import Validators  # noqa: E402

ALL_VARIANTS = ["base", "repeat", "drift", *(f"hostile:{case}" for case in variants.HOSTILE_CASES)]


def _truth() -> dict[str, object]:
    drifted = corpus.build_base()
    return variants.ground_truth(corpus.build_base(), variants.apply_drift(drifted))


def _adapters(names: list[str]) -> list[dict[str, object]]:
    paths = sorted((HERE / "tools").glob("*.json"))
    adapters = [json.loads(path.read_text()) for path in paths]
    return [adapter for adapter in adapters if not names or adapter["tool"] in names]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="write a corpus variant and the ground truth")
    build.add_argument("directory", type=Path)
    build.add_argument("--variant", default="base", choices=ALL_VARIANTS)
    run = commands.add_parser("run", help="run tools against every variant")
    run.add_argument("--tools-root", type=Path, required=True)
    run.add_argument("--work", type=Path, required=True)
    run.add_argument("--tool", action="append", default=[])
    run.add_argument("--variant", action="append", default=[], choices=ALL_VARIANTS)
    score = commands.add_parser("score", help="score recorded runs and write the report")
    score.add_argument("--work", type=Path, required=True)
    score.add_argument("--schemas", type=Path, required=True)
    score.add_argument("--out", type=Path, required=True)
    score.add_argument("--tool", action="append", default=[])
    args = parser.parse_args()

    if args.command == "build":
        built = runner._build(args.variant, corpus.DEFAULT_CANARY_DIR)
        project = variants.write(built, args.directory)
        (args.directory / "ground-truth.json").write_text(json.dumps(_truth(), indent=2) + "\n")
        print(f"{project}\ncorpus digest {variants.corpus_digest(built)}")
        return 0
    if args.command == "run":
        for adapter in _adapters(args.tool):
            record = runner.run_tool(
                adapter, args.tools_root, args.work, args.variant or ALL_VARIANTS
            )
            for variant, result in record["runs"].items():
                scans = result.get("scans", [result])
                summary = ", ".join(
                    f"{scan.get('label', 'diff')}={scan['exit_code']}/{scan['seconds']}s"
                    for scan in scans
                )
                print(f"{adapter['tool']:24} {variant:24} {summary}", flush=True)
        return 0
    truth = _truth()
    validators = Validators(args.schemas)
    results = []
    for adapter in _adapters(args.tool):
        runs = args.work / str(adapter["tool"]) / "runs.json"
        if not runs.is_file():
            print(f"skipping {adapter['tool']}: no recorded runs", file=sys.stderr)
            continue
        path = HERE / "assessments" / f"{adapter['tool']}.json"
        assessment = json.loads(path.read_text()) if path.is_file() else {}
        result = scoring.score_tool(
            truth,
            json.loads(runs.read_text()),
            args.work / str(adapter["tool"]),
            assessment,
            validators,
        )
        result.update(
            {key: adapter.get(key) for key in ("display", "license", "source", "unmeasured")}
        )
        results.append(result)
    results.sort(key=lambda result: -result["total"])
    args.out.mkdir(parents=True, exist_ok=True)
    scoring.dump(results, args.out / "results.json")
    (args.out / "RESULTS.md").write_text(report.render(results, truth, validators.used))
    for result in results:
        print(f"{result['total']:5.1f}  {result['grade']}  {result['display']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
