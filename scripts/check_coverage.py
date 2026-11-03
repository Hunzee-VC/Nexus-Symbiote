"""Enforce measured statement and branch floors, independently of rounded display values."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

# Last audited baseline (docs/audits/closed-pr-review-2026-11-02.md): 91.56% statements,
# 82.73% branches.
# Keep modest platform headroom; raise these deliberately as missing paths are tested.
MIN_STATEMENT_PERCENT = 90
MIN_BRANCH_PERCENT = 75


def coverage_failures(report: dict[str, Any]) -> list[str]:
    if report.get("meta", {}).get("branch_coverage") is not True:
        return ["branch coverage was not measured"]
    totals = report.get("totals", {})
    failures = []
    for name, covered_key, total_key, floor in (
        ("statement", "covered_lines", "num_statements", MIN_STATEMENT_PERCENT),
        ("branch", "covered_branches", "num_branches", MIN_BRANCH_PERCENT),
    ):
        covered, total = totals.get(covered_key), totals.get(total_key)
        if (
            type(covered) is not int
            or type(total) is not int
            or not 0 <= covered <= total
            or total == 0
        ):
            failures.append(f"{name}: missing or invalid coverage counts")
            continue
        if covered * 100 < total * floor:
            failures.append(f"{name}: {100 * covered / total:.2f}% is below {floor}%")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ValueError("coverage report must be an object")
        failures = coverage_failures(report)
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(f"Coverage gate rejected the report: {exc}")
        return 1
    for failure in failures:
        print(failure)
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
