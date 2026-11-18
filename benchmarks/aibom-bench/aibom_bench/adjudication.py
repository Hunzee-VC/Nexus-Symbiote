"""Build the packet an independent rater uses to judge risk findings without tool names.

Automatic matching of findings to planted risks is fallible, and the benchmark's author
maintains one of the graded tools. So every risk and control verdict is rated twice: once
by the author and once by a rater who sees only anonymized evidence. Disagreements go to a
third rater. This module writes the anonymized evidence; it decides nothing.
"""

from __future__ import annotations

import html
import json
import random
import re
from pathlib import Path
from typing import Any

from . import extract

TOOL_NAMES = re.compile(
    r"nexus[-_ ]?symbiote|agent[-_ ]?bom|agent[-_ ]?scan|ai[-_]bom|trusera|aibom|aisbom|cdxgen"
    r"|cdx-audit|airom|syft|anchore|cisco|snyk|owasp",
    re.I,
)
SCAN_ROOT = re.compile(r"/\S*?acme-support-copilot/", re.I)
# Whatever is left of a host path would show which tool shares the benchmark's repository.
HOST_PATH = re.compile(r"\S*(claude-0|scratchpad|-home-user-|7bf94c7d)\S*", re.I)
FIELD_CHARS = 260
MAX_EVIDENCE = 60
MAX_CHARS = 700
RULE = (
    "A risk counts as reported when the tool states it as a finding, a warning, or an explicit "
    "risk flag attached to the affected component, and the statement is about this risk. A "
    "neutral attribute the reader must interpret (the bare string 'latest', a listed URL, an "
    "echo of file content) does not count. A finding about a different problem on the same "
    "component does not count. For a control (a benign item), answer whether the tool wrongly "
    "reports the named problem on it."
)


def _html_lines(text: str) -> list[str]:
    """The visible text of an HTML report, one block per line."""
    text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", text)
    text = re.sub(
        r"(?i)</?(p|div|tr|li|h[1-6]|details|summary|section|table|br)\b[^>]*>", "\n", text
    )
    return [html.unescape(re.sub(r"<[^>]+>", " ", line)) for line in text.splitlines()]


def _native_statements(node: Any, context: str = "") -> list[tuple[str, str]]:
    """Finding-like objects in arbitrary JSON, reduced to the fields a reader would read."""
    found: list[tuple[str, str]] = []
    if isinstance(node, list):
        for element in node:
            found += _native_statements(element, context)
        return found
    if not isinstance(node, dict):
        return found
    keys = list(node)
    if any(extract.SEVERITY_KEY.search(key) for key in keys) and any(
        extract.MESSAGE_KEY.search(key) for key in keys
    ):
        fields = [
            f"{key}={str(value)[:FIELD_CHARS]}"
            for key, value in node.items()
            if isinstance(value, (str, int, float)) and not isinstance(value, bool) and str(value)
        ]
        where = json.dumps(node)[: extract.FINDING_MAX_CHARS]
        found.append((f"{context} {where}", f"{context} | " + "; ".join(fields)))
    names = " ".join(
        str(value)
        for key, value in node.items()
        if key.lower() in extract.NAME_KEYS and isinstance(value, str)
    )
    for value in node.values():
        found += _native_statements(value, names[:200])
    return found


def _statements(outputs: list[extract.Output]) -> list[tuple[str, str]]:
    """Every finding a tool made, as (where it points, what it says), in a compact form."""
    found: list[tuple[str, str]] = []
    for output in outputs:
        doc = output.doc
        if output.format == "sarif" and isinstance(doc, dict):
            for run in doc.get("runs", []) or []:
                for result in run.get("results", []) or []:
                    where = json.dumps(result.get("locations", []))
                    message = result.get("message", {}).get("text", "")
                    said = f"[{result.get('level', '')}] {result.get('ruleId', '')}: {message}"
                    found.append((f"{where} {said}", said))
        elif output.format == "cyclonedx-json" and isinstance(doc, dict):
            for entry in doc.get("vulnerabilities", []) or []:
                said = f"[vulnerability] {entry.get('id', '')}: {entry.get('description', '')}"
                found.append((json.dumps(entry), said))
        elif output.format == "native-json" and doc is not None:
            found += _native_statements(doc)
        elif output.format in extract.TEXT_FORMATS or output.format.startswith("console-"):
            lines = (
                _html_lines(output.text) if output.format == "html" else output.text.splitlines()
            )
            lines = [line for line in lines if line.strip()]
            for index, line in enumerate(lines):
                found.append((line, " ".join(lines[max(0, index - 1) : index + 3])))
    return found


def _evidence(labelled: dict[str, Any], statements: list[tuple[str, str]]) -> list[str]:
    needles = [text.lower() for text in (*labelled["keys"], *labelled["paths"])]
    kept: list[str] = []
    seen: set[str] = set()
    for where, said in statements:
        if not any(needle in where.lower() for needle in needles):
            continue
        said = SCAN_ROOT.sub("", re.sub(r"\s+", " ", said))
        text = TOOL_NAMES.sub("TOOL", HOST_PATH.sub("<path>", said)).strip()[:MAX_CHARS]
        if text[:140].lower() in seen:
            continue
        seen.add(text[:140].lower())
        kept.append(text)
    return kept[:MAX_EVIDENCE]


def build_packet(truth: dict[str, Any], work: Path, tools: list[str], seed: int) -> dict[str, Any]:
    shuffled = sorted(tools)
    random.Random(seed).shuffle(shuffled)  # noqa: S311 - orders labels, protects nothing
    key = {f"T{index:02d}": tool for index, tool in enumerate(shuffled, 1)}
    labels = [
        {**labelled, "group": group}
        for group in ("risks", "controls")
        for labelled in truth[group]
        if not labelled.get("online")
    ]
    packet: dict[str, Any] = {"rule": RULE, "tools": {}}
    for code, tool in key.items():
        runs = json.loads((work / tool / "runs.json").read_text())["runs"]
        statements = _statements(extract.load_outputs(runs["base"], work / tool / "out" / "base"))
        packet["tools"][code] = [
            {
                "id": labelled["id"],
                "kind": "control (benign item)"
                if labelled["group"] == "controls"
                else "planted risk",
                "statement": labelled["title"],
                "risk_class": labelled["signal"].replace("_", " "),
                "component": labelled["keys"],
                "files": labelled["paths"],
                "evidence": _evidence(labelled, statements),
            }
            for labelled in labels
        ]
    return {"packet": packet, "key": key}


DIFF_RULE = (
    "A change counts as reported when the drift report states that this component was added, "
    "removed or modified, in any words, so that a reader of the report alone would know this "
    "component changed. A count of changes with no component named does not count. A change "
    "to a different component does not count, even in the same file."
)
MAX_DIFF_LINES = 500


def _flatten(node: Any, path: str = "") -> list[str]:
    if isinstance(node, dict):
        return [line for key, value in node.items() for line in _flatten(value, f"{path}.{key}")]
    if isinstance(node, list):
        return [
            line for index, value in enumerate(node) for line in _flatten(value, f"{path}[{index}]")
        ]
    return [f"{path.lstrip('.')} = {node}"]


def build_diff_packet(
    truth: dict[str, Any], work: Path, tools: list[str], seed: int
) -> dict[str, Any]:
    """Each tool's own drift report, anonymized, beside the ten planted changes."""
    shuffled = sorted(tools)
    random.Random(seed).shuffle(shuffled)  # noqa: S311 - orders labels, protects nothing
    key = {f"D{index:02d}": tool for index, tool in enumerate(shuffled, 1)}
    changes = [
        {"id": change["id"], "statement": change["title"], "files": change["paths"]}
        for change in truth["changes"]
    ]
    reports = {}
    for code, tool in key.items():
        lines: list[str] = []
        for path in sorted((work / tool / "out" / "diff").glob("*")):
            if not path.is_file():
                continue
            text = path.read_text(errors="replace")
            try:
                lines += _flatten(json.loads(text))
            except ValueError:
                lines += text.splitlines()
        cleaned = []
        for line in lines:
            line = SCAN_ROOT.sub("", re.sub(r"\s+", " ", line)).strip()
            line = TOOL_NAMES.sub("TOOL", HOST_PATH.sub("<path>", line))[:MAX_CHARS]
            if line and line not in cleaned:
                cleaned.append(line)
        reports[code] = cleaned[:MAX_DIFF_LINES]
    return {"packet": {"rule": DIFF_RULE, "changes": changes, "reports": reports}, "key": key}
