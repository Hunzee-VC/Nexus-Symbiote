"""Gate the committed security cases while retaining their full, finite-corpus report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmark_security import DEFAULT_MANIFEST, load_manifest, run_benchmark


def regression_failures(report: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    """Require every approved case and its explicit detection/control expectation."""
    expected = {case["id"]: case for case in manifest["cases"]}
    rows = report.get("results")
    if not isinstance(rows, list):
        return ["missing per-case regression results"]
    seen: set[str] = set()
    failures: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            failures.append("invalid per-case regression result")
            continue
        cid = row["id"]
        if cid not in expected or cid in seen:
            failures.append(f"{cid}: unexpected or duplicate case")
            continue
        seen.add(cid)
        case = expected[cid]
        if row.get("task") != case["task"] or row.get("truth") is not case["truth"]:
            failures.append(f"{cid}: task or label differs from committed expectation")
        if row.get("error") is not None or row.get("passed") is not True:
            failures.append(f"{cid}: failed, incomplete, or errored regression")
        if case["task"] == "detection":
            if type(case["truth"]) is not bool or row.get("prediction") is not case["truth"]:
                failures.append(f"{cid}: detection differs from committed expectation")
        elif case["task"] == "control":
            if row.get("control_passed") is not True:
                failures.append(f"{cid}: control contract did not pass")
        else:
            failures.append(f"{cid}: unsupported regression task")
    failures.extend(f"{cid}: missing case" for cid in sorted(expected.keys() - seen))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    manifest, _ = load_manifest(DEFAULT_MANIFEST)
    report = run_benchmark(DEFAULT_MANIFEST)
    failures = regression_failures(report, manifest)
    report["regression_gate"] = {
        "scope": "committed per-case contracts; not a field efficacy estimate",
        "passed": not failures,
        "failures": failures,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    for failure in failures:
        print(failure)
    print(
        f"Security regression contracts: {len(report['results'])} cases; {len(failures)} failures"
    )
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
