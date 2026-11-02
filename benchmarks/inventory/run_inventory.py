"""Run the versioned, labeled inventory cases locally with the public CLI."""

import hashlib
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import parse_json_strict
from nexus_symbiote.core.models import (
    CompletenessClaim,
    MCPServerComponent,
    ModelComponent,
    ToolComponent,
)
from nexus_symbiote.scanners.base import read_regular_text
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.validators.risk import RiskScorer

DIRECTORY = Path(__file__).resolve().parent


def score_tools(
    predicted: set[str],
    expected: list[str],
    decoys: list[str],
    *,
    collection_incomplete: bool = False,
) -> dict:
    """Score only labeled tools and explicitly labeled non-tools.

    An unexpected, unlabeled name fails the case but does not become a false
    positive in a closed-world confusion matrix without an adjudicated label.
    Missing labels are unknown when collection is incomplete, not false or true negatives.
    """
    if (
        len(set(expected)) != len(expected)
        or len(set(decoys)) != len(decoys)
        or set(expected) & set(decoys)
    ):
        raise ValueError("Tool and decoy labels must be unique and disjoint")
    positives, negatives = set(expected), set(decoys)
    return {
        "tp": len(predicted & positives),
        "fn": 0 if collection_incomplete else len(positives - predicted),
        "fp": len(predicted & negatives),
        "tn": 0 if collection_incomplete else len(negatives - predicted),
        "unknown_positive_labels": len(positives - predicted) if collection_incomplete else 0,
        "unknown_negative_labels": len(negatives - predicted) if collection_incomplete else 0,
        "unexpected_unlabeled": sorted(predicted - positives - negatives),
    }


def relevant_mcp_exclusions(case: dict, exclusions: list[str]) -> list[str]:
    """Only ignore absent config when labels explicitly concern application source."""
    return sorted(
        reason
        for reason in exclusions
        if not (
            case.get("inventory_scope") == "source"
            and reason == "mcp-config (no config files found)"
        )
    )


def label_bounds(scores: dict) -> dict:
    """Bound recall and specificity over explicit labels when collection is incomplete.

    These are deterministic best/worst cases for the unobserved labels, not
    statistical confidence intervals or estimates for unlabeled predictions.
    """

    def interval(success: int, failure: int, unknown: int) -> dict:
        total = success + failure + unknown
        return {
            "label_count": total,
            "observed_count": success + failure,
            "unknown_count": unknown,
            "lower": success / total if total else None,
            "upper": (success + unknown) / total if total else None,
        }

    return {
        "recall": interval(scores["tp"], scores["fn"], scores["unknown_positive_labels"]),
        "specificity": interval(scores["tn"], scores["fp"], scores["unknown_negative_labels"]),
    }


def run() -> dict:
    manifest = parse_json_strict(read_regular_text(DIRECTORY / "manifest.json"))
    rows = []
    totals = Counter()
    for case in manifest["cases"]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "input"
            project.mkdir()
            files = {k: v.encode() for k, v in case.get("files", {}).items()}
            files.update({k: bytes.fromhex(v) for k, v in case.get("hex_files", {}).items()})
            if "fixture" in case:
                relative = Path(case["fixture"])
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("Fixture path must stay in the committed corpus")
                source = read_regular_text(DIRECTORY / "fixtures" / relative).encode("utf-8")
                if hashlib.sha256(source).hexdigest() != case["sha256"]:
                    raise ValueError("Reference source does not match its pinned digest")
                files[case["file"]] = source
            for name, data in files.items():
                relative = Path(name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("Case input paths must be relative and confined")
                path = project / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            bom = AIBOM()
            failures, exclusions = [], []
            mcp_exclusions = []
            statuses = {}
            for scanner in (MCPScanner(), ModelScanner()):
                collected = scanner.scan(project)
                for component in collected.components:
                    try:
                        bom.add_component(component)
                    except ValueError:
                        failures.append("conflicting scanner component identity")
                failures.extend(collected.scan_failures)
                exclusions.extend(collected.surfaces_excluded)
                if scanner.name == "mcp":
                    mcp_exclusions.extend(collected.surfaces_excluded)
                statuses[scanner.name] = (
                    "failed"
                    if collected.scan_failures
                    else "partial"
                    if collected.surfaces_excluded
                    else "complete"
                )
            bom.metadata.completeness = CompletenessClaim(
                scope="inventory-regression",
                scanner_status=statuses,
                scan_failures=failures,
                surfaces_excluded=exclusions,
            )
            output = root / "result.json"
            output.write_text(bom.to_json())
            tools = [c for c in bom.components if isinstance(c, ToolComponent)]
            servers = [c for c in bom.components if isinstance(c, MCPServerComponent)]
            models = [c for c in bom.components if isinstance(c, ModelComponent)]
            predicted = {t.name for t in tools}
            expected = set(case["tools"])
            checks = {}
            for name in case.get("checks", []):
                if name == "distinct_scoped_edges":
                    by_ref = {s.bom_ref: s for s in servers}
                    ok = len(by_ref) == 2 and all(
                        t.mcp_server_ref in by_ref
                        and t.bom_ref in by_ref[t.mcp_server_ref].tool_refs
                        for t in tools
                    )
                elif name == "origin_only":
                    ok = {s.endpoint_url for s in servers} == {
                        "http://localhost.attacker.invalid",
                        "https://trusted.invalid",
                    }
                elif name == "no_secret_in_bom":
                    ok = "SECRET_BENCH_MARKER" not in output.read_text()
                elif name == "deceptive_localhost_flagged":
                    ok = any(r.category == "transport_security" for s in servers for r in s.risks)
                elif name in {"unsafe_format", "safe_format", "unknown_format"}:
                    expected_format = {
                        "unsafe_format": "unsafe-code-execution",
                        "safe_format": "safe",
                        "unknown_format": "unknown",
                    }[name]
                    ok = (
                        len(models) == 1 and models[0].serialization_safety.value == expected_format
                    )
                elif name in {"unsigned", "signer_unverified"}:
                    ok = (
                        len(models) == 1
                        and not models[0].signing_identity
                        and models[0].signing_status != "sigstore-signed"
                        and models[0].assurance_level.value != "verified"
                    )
                elif name in {"critical_gate", "unknown_coverage_gate"}:
                    passed, report = RiskScorer().passes_gate(bom)
                    ok = not passed and (
                        name != "critical_gate" or report.severity_counts.get("critical", 0) > 0
                    )
                elif name == "policy_rejected":
                    ok = CliRunner().invoke(main, ["scan", str(project)]).exit_code != 0
                elif name == "operator_policy_isolated":
                    ok = bool(models)
                else:
                    raise ValueError(f"Unknown benchmark assertion {name}")
                checks[name] = ok
            misses, extras = sorted(expected - predicted), sorted(predicted - expected)
            relevant_exclusions = relevant_mcp_exclusions(case, mcp_exclusions)
            has_tool_labels = bool(case["tools"] or case["decoys"])
            incomplete = bool(failures or (has_tool_labels and relevant_exclusions))
            scores = score_tools(
                predicted, case["tools"], case["decoys"], collection_incomplete=incomplete
            )
            expected_exclusions = sorted(case.get("expected_mcp_exclusions", []))
            exclusions_match = not has_tool_labels or relevant_exclusions == expected_exclusions
            totals.update(
                {
                    k: scores[k]
                    for k in (
                        "tp",
                        "fp",
                        "fn",
                        "tn",
                        "unknown_positive_labels",
                        "unknown_negative_labels",
                    )
                }
            )
            rows.append(
                {
                    "case": case["id"],
                    "tools": sorted(predicted),
                    "missing": misses,
                    "unexpected": extras,
                    "unexpected_unlabeled": scores["unexpected_unlabeled"],
                    "tool_counts": {k: scores[k] for k in ("tp", "fp", "fn", "tn")},
                    "label_bounds": label_bounds(scores),
                    "unknown_positive_labels": scores["unknown_positive_labels"],
                    "unknown_negative_labels": scores["unknown_negative_labels"],
                    "checks": checks,
                    "collection_failures": failures,
                    "collector_status": statuses,
                    "relevant_mcp_exclusions": relevant_exclusions,
                    "coverage_incomplete": incomplete,
                    "coverage_rationale": case.get("coverage_rationale"),
                    "expected_mcp_exclusions": expected_exclusions,
                    "passed": not misses
                    and not extras
                    and not failures
                    and exclusions_match
                    and all(checks.values()),
                }
            )
    return {
        "corpus_version": manifest["version"],
        "counts": {key: totals[key] for key in ("tp", "fp", "fn", "tn")},
        "denominators": {
            "expected_tools": totals["tp"] + totals["fn"],
            "explicit_decoys": totals["tn"] + totals["fp"],
        },
        "unlabeled_predictions": sum(len(row["unexpected_unlabeled"]) for row in rows),
        "unknown_positive_labels": sum(row["unknown_positive_labels"] for row in rows),
        "unknown_negative_labels": sum(row["unknown_negative_labels"] for row in rows),
        "label_bounds": label_bounds(totals),
        "scope": "finite labeled MCP inventory regressions; model and policy checks are separate controls",
        "cases": rows,
        "passed": all(r["passed"] for r in rows),
    }


if __name__ == "__main__":
    report = run()
    print(json.dumps(report, indent=2))
    sys.exit(0 if report["passed"] else 1)
