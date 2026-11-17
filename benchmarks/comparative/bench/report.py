"""Render the Markdown report from a results document. Every number comes from that document."""

from __future__ import annotations

from typing import Any

from .model import Corpus
from .score import WEIGHTS

Json = dict[str, Any]
PILLARS = {
    "discovery": "Discovery",
    "precision": "Precision",
    "fidelity": "Attributes",
    "relationships": "Relations",
    "conformance": "Conformance",
    "risk": "Risk signal",
    "hostile": "Hostile input",
    "reproducibility": "Reproducible",
    "change": "Change",
}
DOMAIN_TITLES = {
    "model": "Models",
    "data": "Data",
    "tool": "Tools",
    "agent": "Agent components",
    "platform": "Packages and platform",
}


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{round(value * 100)}%"


def _table(header: list[str], rows: list[list[str]], right: int = 0) -> str:
    """A Markdown table; the last ``right`` columns are right-aligned."""
    align = ["---"] * (len(header) - right) + ["---:"] * right
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join(align) + " |"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def _label(entry: Json) -> str:
    return f"{entry['name']} {entry['version']}"


def _scorecard(result: Json) -> str:
    ranges = result["sensitivity"]["range"]
    rows = []
    for rank, entry in enumerate(result["scores"], start=1):
        low, high = ranges[entry["tool"]]
        rows.append(
            [
                str(rank),
                _label(entry),
                f"{entry['composite']:.1f}",
                entry["grade"],
                f"{low}" if low == high else f"{low} to {high}",
                *[_pct(entry["pillars"][name]["score"]) for name in PILLARS],
            ]
        )
    header = ["Rank", "Tool", "Score", "Grade", "Rank under other weightings"]
    header += [f"{title} ({WEIGHTS[name]})" for name, title in PILLARS.items()]
    return _table(header, rows, right=len(PILLARS))


def _discovery(result: Json) -> str:
    rows = []
    for entry in result["scores"]:
        discovery = entry["pillars"]["discovery"]
        cells = [
            f"{discovery['domains'][domain]['found']}/{discovery['domains'][domain]['total']}"
            for domain in DOMAIN_TITLES
        ]
        native = entry["native"]
        rows.append(
            [
                _label(entry),
                *cells,
                f"{discovery['found']}/{discovery['total']}",
                _pct(discovery["score"]),
                _pct(native["score"]) if native else "same document",
            ]
        )
    header = ["Tool", *DOMAIN_TITLES.values(), "All", "Mean of domains", "In its own JSON format"]
    return _table(header, rows, right=3)


def _quality(result: Json) -> str:
    rows = []
    for entry in result["scores"]:
        pillars = entry["pillars"]
        fidelity, conformance = pillars["fidelity"], pillars["conformance"]
        relationships, precision = pillars["relationships"], pillars["precision"]
        rows.append(
            [
                _label(entry),
                f"{fidelity['passed']}/{fidelity['total']}",
                _pct(fidelity["when_found"]),
                f"{relationships['found']}/{relationships['total']}",
                f"{conformance['schema_valid']}/{conformance['schema_checked']}",
                _pct(conformance["purl_valid"]),
                _pct(conformance["typing"]),
                f"{precision['rejected']}/{precision['total']}",
                str(precision["reported"]),
                str(precision["control_files_reported"]),
            ]
        )
    header = [
        "Tool",
        "Attributes present",
        "Attributes when found",
        "Relationships",
        "Schema-valid documents",
        "Valid package URLs",
        "Standard type used",
        "Decoys rejected",
        "Decoys reported",
        "Control files reported",
    ]
    return _table(header, rows, right=9)


def _matrix(result: Json, pillar: str, titles: dict[str, str], cell: Any) -> str:
    tools = result["scores"]
    header = ["Case", *[entry["name"] + " " + entry["version"].split(" ")[0] for entry in tools]]
    rows = []
    for item_id, title in titles.items():
        rows.append([title, *[cell(entry["pillars"][pillar]["items"][item_id]) for entry in tools]])
    return _table(header, rows)


def _risk_cell(item: Json) -> str:
    return {1.0: "yes", 0.5: "console only", 0.0: "no"}[item["credit"]]


def _hostile_cell(item: Json) -> str:
    failed = [name.replace("_", " ") for name, ok in item["checks"].items() if not ok]
    if failed:
        text = "FAIL: " + ", ".join(failed)
        return text if item["engaged"] else f"{text} (not engaged)"
    return "pass" if item["engaged"] else "not engaged"


def _change_cell(item: Json) -> str:
    if not item["engaged"]:
        return "not engaged"
    if not item["stable"]:
        return "unstable"
    return "yes" if item["changed"] else "no"


def _reproducibility(result: Json) -> str:
    rows = []
    for entry in result["scores"]:
        items = list(entry["pillars"]["reproducibility"]["items"].values())
        engaged = [item for item in items if item["engaged"]]

        def count(key: str, value: float, pool: list[Json] = engaged) -> str:
            return str(sum(1 for item in pool if item[key] == value))

        rows.append(
            [
                _label(entry),
                f"{len(engaged)}/{len(items)}",
                count("repeat", 1.0),
                count("repeat", 0.5),
                count("repeat", 0.0),
                count("relocated", 1.0),
                count("relocated", 0.5),
                count("relocated", 0.0),
            ]
        )
    header = [
        "Tool",
        "Cases engaged",
        "Repeat: identical",
        "Repeat: same content",
        "Repeat: differs",
        "Moved: identical",
        "Moved: same content",
        "Moved: differs",
    ]
    return _table(header, rows, right=7)


def _operations(result: Json) -> str:
    rows = []
    for entry in result["scores"]:
        operations = entry["operations"]
        codes = ", ".join(
            f"{code}: {count}" for code, count in sorted(operations["exit_codes"].items())
        )
        rows.append(
            [
                _label(entry),
                str(operations["runs"]),
                f"{operations['median_seconds']:.2f}",
                f"{operations['max_seconds']:.1f}",
                str(operations["peak_rss_mb"]),
                str(operations["timeouts"]),
                str(operations["runs_that_changed_the_project"]),
                codes,
            ]
        )
    header = [
        "Tool",
        "Runs",
        "Median seconds",
        "Slowest seconds",
        "Peak memory (MB)",
        "Timeouts",
        "Runs that changed the scanned project",
        "Exit codes",
    ]
    return _table(header, rows, right=7)


def _sensitivity(result: Json) -> str:
    sensitivity = result["sensitivity"]
    header = ["Weighting", *[_label(entry) for entry in result["scores"]]]
    rows = [
        [scheme, *[str(sensitivity["ranks"][entry["tool"]][scheme]) for entry in result["scores"]]]
        for scheme in sensitivity["schemes"]
    ]
    return _table(header, rows, right=len(result["scores"]))


def _roster(result: Json) -> tuple[str, str]:
    measured, skipped = [], []
    for tool in result["tools"]:
        if tool["measured"]:
            command = " ".join(tool["commands"]["cdx"]).replace("<tools>/", "")
            measured.append([f"{tool['name']} {tool['version']}", tool["origin"], f"`{command}`"])
        else:
            skipped.append([f"{tool['name']} {tool['version']}", tool["not_measured"]])
    return (
        _table(
            ["Tool", "Pinned artifact", "CycloneDX command (run in the project directory)"],
            measured,
        ),
        _table(["Tool", "Why it has no score in this round"], skipped),
    )


def render(result: Json, corpus: Corpus) -> str:
    environment = result["environment"]
    measured, skipped = _roster(result)
    risk_titles = {pair.id: f"{pair.id}: {pair.title}" for pair in corpus.risk}
    hostile_titles = {
        hostile.case.id: f"{hostile.case.id}: {hostile.klass}" for hostile in corpus.hostile
    }
    change_titles = {
        mutation.id: f"{mutation.id}: {mutation.title}" for mutation in corpus.mutations
    }
    calibration = ", ".join(
        f"{entry['name']} {entry['composite']:.1f}" for entry in result["calibration"]
    )
    expects = sum(len(case.expects) for case in corpus.discovery)
    sections = [
        "# Comparative AI-BOM benchmark: results",
        "",
        "Generated by `python -m bench report` from `scorecard.json`; do not edit by hand. "
        "The method, every scoring rule and the limits of these numbers are in "
        "[METHOD.md](../../METHOD.md). Read the limits before quoting a score. Changes made "
        "after the method was registered are in [DEVIATIONS.md](../../DEVIATIONS.md).",
        "",
        f"- Benchmark version {result['bench_version']}, corpus digest `{result['corpus_digest']}`.",
        f"- Run started {environment.get('started_utc', 'unknown')} on "
        f"{environment.get('platform', 'unknown')}, Python {environment.get('python', 'unknown')}, "
        f"{environment.get('runs', 'unknown')} recorded tool runs "
        f"({environment.get('executed', 'unknown')} executed, counting re-runs) in "
        f"{environment.get('seconds', 'unknown')} seconds of run sessions.",
        f"- Isolation: {environment.get('isolation', 'unknown')}; "
        f"{environment.get('timeout_seconds', 'unknown')} second limit per run.",
        f"- Corpus: {len(corpus.discovery)} discovery cases with {expects} labelled components, "
        f"{len(corpus.risk)} risk pairs, {len(corpus.hostile)} hostile cases, "
        f"{len(corpus.mutations)} mutations.",
        f"- Calibration: {calibration} (expected 100 and 0).",
        "",
        "## Scorecard",
        "",
        "Scores are out of 100. The number after each pillar is its weight. "
        "Grades: A from 85, B from 70, C from 55, D from 40, F below 40.",
        "",
        _scorecard(result),
        "",
        "## Tools without a score",
        "",
        skipped,
        "",
        "## How each tool was run",
        "",
        measured,
        "",
        "## Discovery by domain",
        "",
        "Components found in the CycloneDX document, out of those labelled. The last column "
        "repeats the count in the tool's own JSON format, where it has one, to show what its "
        "CycloneDX export leaves out; it is not scored.",
        "",
        _discovery(result),
        "",
        "## Attributes, relationships, conformance and decoys",
        "",
        "`Control files reported` counts elements that mention one of the files with no AI "
        "content that every case holds; it is not scored.",
        "",
        _quality(result),
        "",
        "## Risk signals",
        "",
        "`yes`: a machine-readable output differs between the clean and the risky twin. "
        "`console only`: only the console text or the exit code differs. `no`: nothing differs.",
        "",
        _matrix(result, "risk", risk_titles, _risk_cell),
        "",
        "## Hostile inputs",
        "",
        "`not engaged`: the tool did not report the ordinary component beside the hostile input, "
        "so the case earns nothing and shows nothing about its safety.",
        "",
        _matrix(result, "hostile", hostile_titles, _hostile_cell),
        "",
        "## Reproducibility",
        "",
        "Each engaged case was scanned again in place, and again from a different directory. "
        "`identical`: equal after the serial number and timestamp are removed. `same content`: "
        "equal only after identifiers, times and list order are also removed.",
        "",
        _reproducibility(result),
        "",
        "## Change sensitivity",
        "",
        "`yes`: the document changed when the project did. `unstable`: two scans of the unchanged "
        "project already differ, so a change cannot be attributed.",
        "",
        _matrix(result, "change", change_titles, _change_cell),
        "",
        "## Operations (not scored)",
        "",
        _operations(result),
        "",
        "## Rank under other weightings",
        "",
        "The published weights are a judgment. This table shows each tool's rank when the "
        "weights change or one pillar is left out.",
        "",
        _sensitivity(result),
        "",
    ]
    return "\n".join(sections)
