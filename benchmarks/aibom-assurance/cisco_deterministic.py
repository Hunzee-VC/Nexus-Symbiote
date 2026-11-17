#!/usr/bin/env python3
"""Run the Cisco AI BOM deterministic pipeline (tiers 1 and 2) and render its reports.

``cisco-aibom analyze`` refuses to run without an LLM provider, and the benchmark runs
without one. ``cisco-aibom watch`` drives ``ScanPipeline`` without the agentic stage; this
helper calls the same class once, assembles a ``ScanResult`` the way the CLI does, scores it
with the built-in ``RiskScorer`` and renders every reporter the package registers. Results
are labelled "deterministic tiers only" in the benchmark.

Usage: cisco_deterministic.py FIXTURE OUT_DIR
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path


def main() -> int:
    fixture = str(Path(sys.argv[1]).resolve())
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)

    from aibom.finding_annotations import annotate_findings
    from aibom.models import ScanResult, SourceResult
    from aibom.reporters import get_reporter
    from aibom.risk import RiskScorer
    from aibom.scan_pipeline import ScanPipeline

    started = time.time()
    pipeline = ScanPipeline(scan_paths=[fixture], output_format="json")
    result = pipeline.run()
    components, relationships, _ = annotate_findings(
        list(result.components),
        list(result.relationships),
        [],
        include_code_snippets=False,
        allowed_roots=[fixture],
    )
    scan_result = ScanResult(
        metadata={
            "scan_paths": [fixture],
            "pipeline": "deterministic-only (no agentic stage)",
            "agentic_status": result.agentic_status,
            "duration_seconds": round(time.time() - started, 3),
        },
        sources=[SourceResult(path=fixture, components=components, relationships=relationships)],
        cross_repo_links=[],
        errors=[],
    )
    scan_result.risk = RiskScorer().score(scan_result)

    rendered: dict[str, str] = {}
    for fmt, name in [
        ("json", "report.json"),
        ("cyclonedx", "report.cdx.json"),
        ("sarif", "report.sarif"),
        ("spdx", "report.spdx.json"),
    ]:
        reporter = get_reporter(fmt)
        if reporter is None:
            rendered[fmt] = "no reporter registered"
            continue
        try:
            with open(out / name, "w", encoding="utf-8") as handle:
                reporter.render(scan_result, handle)
            rendered[fmt] = name
        except Exception as exc:  # report the failure, keep the other formats
            rendered[fmt] = f"render failed: {type(exc).__name__}: {exc}"
    summary = {
        "components": len(components),
        "relationships": len(relationships),
        "risk_score": scan_result.risk.score,
        "risk_flags": len(scan_result.risk.flags),
        "agentic_status": result.agentic_status,
        "rendered": rendered,
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
