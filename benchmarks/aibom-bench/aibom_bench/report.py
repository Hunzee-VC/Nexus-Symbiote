"""Render scored results as Markdown."""

from __future__ import annotations

from typing import Any

from . import BENCH_VERSION
from .scoring import CRITERIA


def render(results: list[dict[str, Any]], truth: dict[str, Any], schemas: dict[str, str]) -> str:
    groups = list(dict.fromkeys(group for _, group, _, _, _ in CRITERIA))
    lines = [
        "# AIBOM-Bench results",
        "",
        f"Benchmark {BENCH_VERSION}, corpus `{truth['corpus_digest'][:16]}`: "
        f"{len(truth['items'])} components, {len(truth['decoys'])} decoys, "
        f"{len(truth['risks'])} planted risks, {len(truth['changes'])} planted changes, "
        f"{len(truth['hostile_cases'])} hostile-input cases. All runs offline.",
        "",
        "## Scores",
        "",
        "| Tool | Version | Total | Grade | " + " | ".join(groups) + " |",
        "| --- | --- | ---: | :---: | " + " | ".join("---:" for _ in groups) + " |",
    ]
    for result in results:
        cells = [
            f"{result['groups'][g]['points']:.1f}/{result['groups'][g]['of']:.0f}" for g in groups
        ]
        lines.append(
            f"| {result['display']} | {result['version']} | **{result['total']:.1f}** | "
            f"{result['grade']} | " + " | ".join(cells) + " |"
        )
    lines += ["", "## Points by criterion", ""]
    lines.append("| Criterion | Max | " + " | ".join(r["display"] for r in results) + " |")
    lines.append("| --- | ---: | " + " | ".join("---:" for _ in results) + " |")
    for criterion, _, title, weight, method in CRITERIA:
        mark = "" if method == "measured" else " (assessed)"
        cells = " | ".join(f"{r['points'][criterion]:.1f}" for r in results)
        lines.append(f"| {criterion} {title}{mark} | {weight:g} | {cells} |")
    lines += ["", "## Measurements", ""]
    lines.append(
        "| Tool | Component recall | Records emitted | Risks caught | Changes visible | "
        "Hostile cases passed | Canaries tripped | Secrets disclosed | Egress attempts | Scan time |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: |")
    for result in results:
        d = result["details"]
        passed = sum(case["passed"] for case in d["8.5"]["cases"].values())
        lines.append(
            f"| {result['display']} | {result['recall']:.0%} | {result['components_reported']} | "
            f"{len(d['6.1']['caught'])}/{d['6.1']['of']} | {len(d['7.1']['visible'])}/{len(truth['changes'])} | "
            f"{passed}/{len(d['8.5']['cases'])} | {', '.join(d['8.1']['canaries_tripped']) or 'none'} | "
            f"{len(d['8.3']['disclosed'])} | {len(d['8.6']['connection_attempts'])} | {result['seconds']} s |"
        )
    limited = [r for r in results if r.get("unmeasured")]
    if limited:
        lines += ["", "## Scores that are floors, not measurements", ""]
        lines += [f"- **{r['display']}**: {r['unmeasured']}" for r in limited]
    lines += ["", "## Schemas used", ""]
    lines += [f"- `{name}` sha256 `{digest}`" for name, digest in sorted(schemas.items())]
    return "\n".join(lines) + "\n"
