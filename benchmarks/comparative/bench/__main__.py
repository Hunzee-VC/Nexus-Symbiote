"""Command line: check the corpus, run the tools, score the runs and write the report."""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from pathlib import Path

from . import BENCH_VERSION, baselines, corpus, report, runner, score
from .tools import TOOLS, Tool, by_id


def _tools(names: list[str] | None) -> list[Tool]:
    return [by_id(name) for name in names] if names else list(TOOLS)


def command_check(_: argparse.Namespace) -> int:
    built = corpus.build()
    problems = corpus.check(built)
    for problem in problems:
        print(problem)
    expects = sum(len(case.expects) for case in built.discovery)
    print(
        f"{len(built.discovery)} discovery cases, {expects} expected components, "
        f"{len(built.risk)} risk pairs, {len(built.hostile)} hostile cases, "
        f"{len(built.mutations)} mutations"
    )
    print(f"corpus digest {corpus.digest(built)}")
    return 1 if problems else 0


def command_materialize(args: argparse.Namespace) -> int:
    built = corpus.build()
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        print(f"{out} is not empty", file=sys.stderr)
        return 2
    for case in built.all_cases():
        corpus.materialize(case, out / "cases" / case.id)
    corpus.write_tree(built.outside, out / "outside")
    print(f"wrote {len(built.all_cases())} cases under {out}")
    return 0


def command_run(args: argparse.Namespace) -> int:
    if not runner.sandbox_supported():
        print(
            "Cannot create a network and mount namespace (needs root or CAP_SYS_ADMIN and unshare).",
            file=sys.stderr,
        )
        return 2
    built = corpus.build()
    problems = corpus.check(built)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    selected = [tool for tool in _tools(args.tool) if tool.measured]
    work = Path(args.work)
    started = time.time()
    only = frozenset(args.case) if args.case else None
    records = runner.run_all(
        selected, built, Path(args.tools_root).resolve(), work, args.workers, only
    )
    session = {
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "seconds": round(time.time() - started, 1),
        "runs": len(records),
        "tools": [tool.id for tool in selected],
        "cases": sorted(only) if only else "all",
    }
    environment_path = work / "environment.json"
    previous = json.loads(environment_path.read_text()) if environment_path.is_file() else {}
    sessions = [*previous.get("sessions", []), session]
    environment = {
        "bench_version": BENCH_VERSION,
        "corpus_digest": corpus.digest(built),
        "started_utc": sessions[0]["started_utc"],
        "seconds": round(sum(entry["seconds"] for entry in sessions), 1),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpus": os.cpu_count(),
        "timeout_seconds": runner.TIMEOUT_SECONDS,
        "isolation": "unshare --net --mount, cleared environment, empty home directory",
        "runs": sum(
            1
            for record in (work / "runs").glob("*/*/*/*/record.json")
            if record.parts[-5] not in {baselines.ORACLE.id, baselines.NULL.id}
        ),
        "executed": sum(entry["runs"] for entry in sessions),
        "sessions": sessions,
    }
    (work / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
    print(json.dumps(environment, indent=2))
    return 0


def command_score(args: argparse.Namespace) -> int:
    built = corpus.build()
    work = Path(args.work)
    for calibration in (baselines.ORACLE, baselines.NULL):
        baselines.write(calibration, built, work)
    selected = [tool for tool in _tools(args.tool) if tool.measured]
    scores = []
    for tool in selected:
        if not (work / "runs" / tool.id).is_dir():
            print(f"no runs recorded for {tool.id}", file=sys.stderr)
            return 1
        scores.append(score.Scorer(built, tool, work).all())
    calibration_scores = [
        score.Scorer(built, tool, work).all() for tool in (baselines.ORACLE, baselines.NULL)
    ]
    environment_path = work / "environment.json"
    result = {
        "bench_version": BENCH_VERSION,
        "corpus_digest": corpus.digest(built),
        "weights": score.WEIGHTS,
        "grades": [list(band) for band in score.GRADES],
        "environment": json.loads(environment_path.read_text())
        if environment_path.is_file()
        else {},
        "tools": [
            {
                "id": tool.id,
                "name": tool.name,
                "version": tool.version,
                "license": tool.license,
                "origin": tool.origin,
                "measured": tool.measured,
                "not_measured": tool.not_measured,
                "note": tool.note,
                "commands": {fmt: tool.argv(fmt, "<tools>") for fmt in tool.commands},
                "environment": dict(tool.env),
            }
            for tool in TOOLS
        ],
        "scores": sorted(scores, key=lambda entry: -entry["composite"]),
        "calibration": calibration_scores,
        "sensitivity": score.sensitivity(scores) if scores else {},
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    for entry in result["scores"] + calibration_scores:
        print(f"{entry['tool']:22} {entry['composite']:6.2f} {entry['grade']}")
    return 0


def command_report(args: argparse.Namespace) -> int:
    result = json.loads(Path(args.results).read_text())
    Path(args.out).write_text(report.render(result, corpus.build()))
    print(f"wrote {args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="check the corpus against its ground truth").set_defaults(
        run=command_check
    )
    materialize = commands.add_parser("materialize", help="write every case to a directory")
    materialize.add_argument("--out", required=True)
    materialize.set_defaults(run=command_materialize)
    run = commands.add_parser("run", help="run the tools in the sandbox")
    run.add_argument("--tools-root", required=True)
    run.add_argument("--work", required=True)
    run.add_argument("--tool", action="append")
    run.add_argument("--workers", type=int, default=4)
    run.add_argument("--case", action="append", help="run only this case; repeatable")
    run.set_defaults(run=command_run)
    scoring = commands.add_parser("score", help="score recorded runs")
    scoring.add_argument("--work", required=True)
    scoring.add_argument("--out", required=True)
    scoring.add_argument("--tool", action="append")
    scoring.set_defaults(run=command_score)
    reporting = commands.add_parser("report", help="render the Markdown report")
    reporting.add_argument("--results", required=True)
    reporting.add_argument("--out", required=True)
    reporting.set_defaults(run=command_report)
    args = parser.parse_args(argv)
    return int(args.run(args))


if __name__ == "__main__":
    raise SystemExit(main())
