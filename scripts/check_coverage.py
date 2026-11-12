"""Enforce measured coverage floors, independently of rounded display values.

The package must keep its statement and branch floors, and each security-critical module
must keep its own: a well-tested package average cannot hide an untested module that
confines reads, verifies signatures, gates verdicts or enforces offline mode. The gate
scripts are measured too, and the Action's runner, which decides its gate outcomes, has a
floor of its own. A listed file missing from the report, or a report without the scripts,
fails. The measured figures are printed, and written to the job summary in CI; the floors
only rise, as missing paths gain tests.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

PACKAGE = "nexus_symbiote"
SCRIPTS = "scripts"
MIN_STATEMENT_PERCENT = 91
MIN_BRANCH_PERCENT = 83
# Floors per file, a few points under the coverage measured when they were set; a branch
# floor of None leaves a file with too few branches for a stable percentage unchecked.
MODULE_FLOORS: dict[str, tuple[int, int | None]] = {
    "nexus_symbiote/utils/confined.py": (88, 78),
    "nexus_symbiote/core/hashing.py": (95, 92),
    "nexus_symbiote/utils/crypto.py": (86, 60),
    "nexus_symbiote/signature_policy.py": (95, 88),
    "nexus_symbiote/validators/completeness.py": (92, 88),
    "nexus_symbiote/validators/integrity.py": (92, 88),
    "nexus_symbiote/validators/risk.py": (94, 88),
    "nexus_symbiote/diff/differ.py": (96, 92),
    "nexus_symbiote/modes.py": (85, 75),
    "nexus_symbiote/runtime.py": (91, 82),
    "nexus_symbiote/policy.py": (90, 82),
    "nexus_symbiote/utils/secrets.py": (90, 85),
    "nexus_symbiote/utils/terminal.py": (95, None),
    "nexus_symbiote/attestation.py": (98, 98),
    "nexus_symbiote/attestation_cli.py": (98, 98),
    # Measured at 87% of statements and 86% of branches when scripts/ joined the report.
    "scripts/run_action.py": (75, 65),
    "nexus_symbiote/core/content_digest.py": (98, 98),
    "nexus_symbiote/digest_cli.py": (98, 98),
    "nexus_symbiote/risk_classes.py": (98, 98),
    "nexus_symbiote/graph_view.py": (98, 98),
    "nexus_symbiote/graph_cli.py": (98, 98),
    "nexus_symbiote/crosswalk.py": (98, None),
    "nexus_symbiote/crosswalk_cli.py": (98, 98),
    "nexus_symbiote/otlp.py": (98, 98),
    "nexus_symbiote/trace_evidence.py": (98, 98),
    "nexus_symbiote/trace_cli.py": (98, 98),
}
COUNTS = (
    ("statement", "covered_lines", "num_statements"),
    ("branch", "covered_branches", "num_branches"),
)


def _percent(summary: Any, covered_key: str, total_key: str) -> tuple[int, int] | None:
    covered = summary.get(covered_key) if isinstance(summary, dict) else None
    total = summary.get(total_key) if isinstance(summary, dict) else None
    if type(covered) is not int or type(total) is not int or not 0 <= covered <= total:
        return None
    return covered, total


def _below(label: str, counts: tuple[int, int] | None, floor: int | None) -> list[str]:
    if floor is None:
        return []
    if counts is None or counts[1] == 0:
        return [f"{label}: missing or invalid coverage counts"]
    covered, total = counts
    if covered * 100 < total * floor:
        return [f"{label}: {100 * covered / total:.2f}% is below {floor}%"]
    return []


def _files(report: dict[str, Any]) -> dict[str, Any]:
    files = report.get("files")
    return files if isinstance(files, dict) else {}


def _module(report: dict[str, Any], suffix: str) -> Any:
    matches = [
        entry
        for path, entry in _files(report).items()
        if isinstance(path, str) and ("/" + Path(path).as_posix()).endswith("/" + suffix)
    ]
    return matches[0].get("summary") if len(matches) == 1 and isinstance(matches[0], dict) else None


def _in_scope(path: str, scope: str) -> bool:
    parts = Path(path).parts
    return scope in parts if scope == PACKAGE else bool(parts) and parts[0] == scope


def _aggregate(report: dict[str, Any], scope: str, covered_key: str, total_key: str) -> Any:
    """Summed counts over every measured file in scope; None when any is invalid or absent."""
    covered = total = 0
    found = False
    for path, entry in _files(report).items():
        if not isinstance(path, str) or not _in_scope(path, scope):
            continue
        counts = _percent(
            entry.get("summary") if isinstance(entry, dict) else None, covered_key, total_key
        )
        if counts is None:
            return None
        found = True
        covered += counts[0]
        total += counts[1]
    return (covered, total) if found else None


def coverage_failures(report: dict[str, Any]) -> list[str]:
    if report.get("meta", {}).get("branch_coverage") is not True:
        return ["branch coverage was not measured"]
    failures = []
    for (name, covered_key, total_key), floor in zip(
        COUNTS, (MIN_STATEMENT_PERCENT, MIN_BRANCH_PERCENT), strict=True
    ):
        counts = _aggregate(report, PACKAGE, covered_key, total_key)
        failures.extend(_below(f"package {name}", counts, floor))
    if _aggregate(report, SCRIPTS, *COUNTS[0][1:]) is None:
        failures.append("scripts/: not measured, or measured with invalid counts")
    for module, floors in MODULE_FLOORS.items():
        summary = _module(report, module)
        if summary is None:
            failures.append(f"{module}: not measured, or measured more than once")
            continue
        for (name, covered_key, total_key), module_floor in zip(COUNTS, floors, strict=True):
            failures.extend(
                _below(f"{module} {name}", _percent(summary, covered_key, total_key), module_floor)
            )
    return failures


def measured(report: dict[str, Any]) -> list[str]:
    """The measured figures as Markdown table rows, for the log and the CI job summary."""
    rows = ["| Scope | Statements | Branches | Floors |", "| --- | --- | --- | --- |"]

    def cell(counts: tuple[int, int] | None) -> str:
        return f"{100 * counts[0] / counts[1]:.2f}%" if counts and counts[1] else "n/a"

    for label, scope, floors in (
        ("package", PACKAGE, f"{MIN_STATEMENT_PERCENT}% / {MIN_BRANCH_PERCENT}%"),
        ("scripts", SCRIPTS, "- / -"),
    ):
        rows.append(
            f"| {label} | {cell(_aggregate(report, scope, *COUNTS[0][1:]))} | "
            f"{cell(_aggregate(report, scope, *COUNTS[1][1:]))} | {floors} |"
        )
    for module, (statements, branches) in MODULE_FLOORS.items():
        summary = _module(report, module)
        rows.append(
            f"| {module} | {cell(_percent(summary, *COUNTS[0][1:]))} | "
            f"{cell(_percent(summary, *COUNTS[1][1:]))} | {statements}% / "
            f"{'-' if branches is None else f'{branches}%'} |"
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ValueError("coverage report must be an object")
        failures = coverage_failures(report)
        rows = measured(report)
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(f"Coverage gate rejected the report: {exc}")
        return 1
    print("\n".join(rows))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write("## Coverage\n\n" + "\n".join(rows) + "\n")
    for failure in failures:
        print(failure)
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
