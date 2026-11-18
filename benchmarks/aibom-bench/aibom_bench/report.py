"""Render scored results as Markdown."""

from __future__ import annotations

from typing import Any

from . import BENCH_VERSION
from .scoring import CRITERIA, GROUPS, SENSITIVITY


def _ranks(results: list[dict[str, Any]], scenario: str) -> dict[str, int]:
    ordered = sorted(results, key=lambda result: -result["sensitivity"][scenario])
    return {result["tool"]: position for position, result in enumerate(ordered, 1)}


def render(results: list[dict[str, Any]], truth: dict[str, Any], schemas: dict[str, str]) -> str:
    def name(result: dict[str, Any]) -> str:
        return result["display"] + (" †" if result.get("unmeasured") else "")

    ungraded = [result for result in results if result.get("not_gradable")]
    results = [result for result in results if not result.get("not_gradable")]

    lines = [
        "# AIBOM-Bench results",
        "",
        f"Benchmark {BENCH_VERSION}, corpus {truth['corpus_version']} "
        f"`{truth['corpus_digest'][:16]}`: {len(truth['items'])} components, "
        f"{len(truth['decoys'])} decoys, {len(truth['risks'])} planted risks, "
        f"{len(truth['changes'])} planted changes, {len(truth['hostile_cases'])} hostile-input "
        "cases. Scored scans ran with no network.",
        "",
        "† The score is a floor: the tool could not run as designed here. See the notes below.",
        "",
        "## Scores",
        "",
        "| Tool | Version | Total | Grade | " + " | ".join(GROUPS) + " |",
        "| --- | --- | ---: | :---: | " + " | ".join("---:" for _ in GROUPS) + " |",
    ]
    for result in results:
        cells = [
            f"{result['groups'][g]['points']:.1f}/{result['groups'][g]['of']:.0f}" for g in GROUPS
        ]
        lines.append(
            f"| {name(result)} | {result['version']} | **{result['total']:.1f}** | "
            f"{result['grade']} | " + " | ".join(cells) + " |"
        )
    for result in ungraded:
        lines.append(
            f"| {result['display']} | {result['version']} | not graded | n/a | "
            + " | ".join("n/a" for _ in GROUPS)
            + " |"
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
        "| Tool | Component recall | Risks caught | Changes visible | Decoys reported / faced | "
        "Canaries tripped / faced | Secrets disclosed / faced | Hostile cases passed / faced | "
        "Default-command egress attempts | Scan time |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for result in results:
        d = result["details"]
        cases = d["8.5"]["cases"].values()
        decoys_faced = len(truth["decoys"]) - len(d["2.1"]["not_tested"])
        tripped = sorted({c for names in d["8.1"]["canaries_tripped"].values() for c in names})
        lines.append(
            f"| {name(result)} | {result['recall']:.0%} | "
            f"{len(d['6.1']['caught'])}/{d['6.1']['of']} | "
            f"{len(d['7.1']['visible'])}/{len(truth['changes'])} | "
            f"{len(d['2.1']['reported_as_components'])}/{decoys_faced} | "
            f"{len(tripped)}/{len(d['8.1']['canaries_faced'])} | "
            f"{len(d['8.3']['disclosed'])}/{len(d['8.3']['secrets_faced'])} | "
            f"{sum(c['passed'] for c in cases)}/{sum(c['faced'] for c in cases)} | "
            f"{len(d['8.6']['default_command_connection_attempts'])} | {result['seconds']} s |"
        )
    lines += [
        "",
        "## Sensitivity to the weights",
        "",
        "Each cell is the tool's total out of 100, and its rank, under a different weighting. "
        "A ranking that changes with the weights is a judgement, not a measurement.",
        "",
        "| Tool | " + " | ".join(SENSITIVITY) + " | Rank range |",
        "| --- | " + " | ".join("---:" for _ in SENSITIVITY) + " | :---: |",
    ]
    ranks = {scenario: _ranks(results, scenario) for scenario in SENSITIVITY}
    for result in results:
        cells, seen = [], []
        for scenario in SENSITIVITY:
            rank = ranks[scenario][result["tool"]]
            seen.append(rank)
            cells.append(f"{result['sensitivity'][scenario]:.1f} (#{rank})")
        span = f"{min(seen)}" if min(seen) == max(seen) else f"{min(seen)} to {max(seen)}"
        lines.append(f"| {name(result)} | " + " | ".join(cells) + f" | {span} |")
    limited = [r for r in results if r.get("unmeasured")]
    if limited:
        lines += ["", "## Scores that are floors, not measurements", ""]
        lines += [f"- **{r['display']}**: {r['unmeasured']}" for r in limited]
    observed = [r for r in results if r.get("observed")]
    if observed:
        lines += ["", "## Observed outside the scored run", ""]
        lines += [f"- **{r['display']}**: {r['observed']}" for r in observed]
    if ungraded:
        lines += ["", "## Not graded", ""]
        lines += [f"- **{r['display']}**: {r['not_gradable']}" for r in ungraded]
    lines += ["", "## Schemas used", ""]
    lines += [f"- `{name}` sha256 `{digest}`" for name, digest in sorted(schemas.items())]
    return "\n".join(lines) + "\n"
