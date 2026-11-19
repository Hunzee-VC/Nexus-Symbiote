"""Precision and drift-regression gate (`make precision`).

Enforces:
1. Committed per-case security regression contracts (`benchmarks/manifest.json`).
2. `model_drift` and `a2a_scope_drift` drift-detection invariants over `AIBOMDiffer`.
3. Per-class recall floors when an AIBOM-Bench score file (`--scores`) is present or supplied.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_SCRIPTS_DIR = str(Path(__file__).resolve().parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from benchmark_security import DEFAULT_MANIFEST, load_manifest, run_benchmark  # noqa: E402
from check_security_regressions import regression_failures  # noqa: E402

from nexus_symbiote.core.aibom import AIBOM  # noqa: E402
from nexus_symbiote.core.enums import SerializationSafety  # noqa: E402
from nexus_symbiote.core.models import A2AServerComponent, ModelComponent  # noqa: E402
from nexus_symbiote.diff.differ import AIBOMDiffer  # noqa: E402

# Recorded Corpus A / Corpus B per-class recall floors on main before ShadowScan pair merge.
DEFAULT_CLASS_FLOORS: dict[str, float] = {
    "model-file": 0.80,
    "mcp-server": 0.65,
    "tool": 0.65,
    "skill": 1.00,
    "a2a": 1.00,
    "package": 0.60,
    "vector-store": 0.50,
}


def verify_drift_kinds() -> list[str]:
    """Verify `model_drift` and `a2a_scope_drift` fail `AIBOMDiffer` with security alerts."""
    failures: list[str] = []
    differ = AIBOMDiffer()
    old_m = ModelComponent(
        bom_ref="model:weights/model.safetensors",
        name="weights/model.safetensors",
        source_path="weights/model.safetensors",
        hashes={"sha256": "0" * 64},
        serialization_safety=SerializationSafety.SAFE,
    )
    new_m = old_m.model_copy(
        update={
            "hashes": {"sha256": "f" * 64},
            "serialization_safety": SerializationSafety.UNSAFE_CODE_EXECUTION,
        }
    )
    if not differ.diff(AIBOM(components=[old_m]), AIBOM(components=[new_m])).security_alerts:
        failures.append("model_drift: altered model digest and safety raised no security alert")

    old_a = A2AServerComponent(
        bom_ref="a2a-server:partner",
        name="partner",
        endpoint_url="https://agent.example.com",
        authentication_required=True,
        skills_declared=["read-tickets"],
    )
    new_a = old_a.model_copy(
        update={"authentication_required": False, "skills_declared": ["read-tickets", "admin"]}
    )
    if not differ.diff(AIBOM(components=[old_a]), AIBOM(components=[new_a])).security_alerts:
        failures.append("a2a_scope_drift: widened A2A skills/auth raised no security alert")
    return failures


def evaluate_class_floors(
    scores_doc: dict[str, Any], floors: dict[str, float] = DEFAULT_CLASS_FLOORS
) -> list[str]:
    """Check per-class recall in an AIBOM-Bench score document against recorded floors."""
    failures: list[str] = []
    per_class = scores_doc.get("per_class_recall") or scores_doc.get("classes")
    if not isinstance(per_class, dict):
        return ["scores document missing per_class_recall / classes mapping"]
    for cls_name, floor in sorted(floors.items()):
        entry = per_class.get(cls_name)
        if entry is None:
            continue
        recall = entry.get("recall") if isinstance(entry, dict) else entry
        if isinstance(recall, bool) or not isinstance(recall, (int, float)):
            failures.append(f"{cls_name}: invalid recall value")
            continue
        if float(recall) + 1e-9 < floor:
            failures.append(f"{cls_name}: recall {float(recall):.3f} fell below floor {floor:.3f}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scores", type=Path, default=None, help="Optional AIBOM-Bench scores JSON"
    )
    parser.add_argument(
        "--out", type=Path, default=Path("precision-gate.json"), help="Summary output path"
    )
    args = parser.parse_args(argv)

    manifest, _ = load_manifest(DEFAULT_MANIFEST)
    reg_report = run_benchmark(DEFAULT_MANIFEST)
    failures = regression_failures(reg_report, manifest)
    failures.extend(verify_drift_kinds())

    default_bench = Path("benchmarks/aibom-bench/results/scores.json")
    score_path = args.scores or (default_bench if default_bench.is_file() else None)
    bench_status = "not-present"
    if score_path is not None:
        try:
            scores_doc = json.loads(score_path.read_text(encoding="utf-8"))
            if not isinstance(scores_doc, dict):
                raise ValueError("scores root must be an object")
            floor_failures = evaluate_class_floors(scores_doc)
            failures.extend(floor_failures)
            bench_status = "failed" if floor_failures else "passed"
        except (OSError, ValueError) as exc:
            failures.append(f"scores: {type(exc).__name__}")
            bench_status = "failed"

    summary = {
        "passed": not failures,
        "security_cases": len(reg_report.get("results", [])),
        "drift_kinds_checked": ["model_drift", "a2a_scope_drift"],
        "aibom_bench_status": bench_status,
        "failures": failures,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    for item in failures:
        print(item)
    print(f"Precision gate: {'PASSED' if not failures else 'FAILED'} ({len(failures)} failures)")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
