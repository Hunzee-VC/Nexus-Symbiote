"""Score recorded runs. Every rule here is applied to every tool in the same way."""

from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import cdx
from .build import DATA, control_tokens
from .cases_hostile import OUTSIDE_MARKER, TERMINAL_MARKERS, secret_values
from .cases_risk import RISK_WORDS
from .model import DOMAINS, Attr, Case, Corpus, Expect, Hostile
from .tools import OUT_NAMES, Tool

WEIGHTS: dict[str, int] = {
    "discovery": 30,
    "precision": 8,
    "fidelity": 12,
    "relationships": 5,
    "conformance": 8,
    "risk": 12,
    "hostile": 12,
    "reproducibility": 5,
    "change": 8,
}
GRADES: tuple[tuple[float, str], ...] = ((85.0, "A"), (70.0, "B"), (55.0, "C"), (40.0, "D"))
BOUNDED_MEMORY_KB = 2 * 1024 * 1024
READ_LIMIT = 5 * 1024 * 1024
RISKISH = re.compile(
    r"risk|sever|finding|vuln|threat|trust|safe|malic|issue|alert|suspic|danger|verdict|violat"
    r"|polic|poison|inject|warn|flag|secur|pinned|integrity|score|posture|grade|blocked"
    r"|credential|secret|exposure|hidden|unicode|permission",
    re.IGNORECASE,
)
ESCAPE_BEFORE_MARKER = re.compile(rb"\x1b[^\n]{0,24}?(?:" + b"|".join(TERMINAL_MARKERS) + rb")")
Json = dict[str, Any]


def grade(score: float) -> str:
    for floor, letter in GRADES:
        if score >= floor:
            return letter
    return "F"


def wilson(successes: int, total: int) -> tuple[float, float]:
    """95% Wilson score interval for a proportion."""
    if total == 0:
        return (0.0, 0.0)
    z = 1.959964
    share = successes / total
    centre = share + z * z / (2 * total)
    spread = z * math.sqrt(share * (1 - share) / total + z * z / (4 * total * total))
    low = (centre - spread) / (1 + z * z / total)
    high = (centre + spread) / (1 + z * z / total)
    return (round(max(0.0, low), 4), round(min(1.0, high), 4))


@dataclass
class View:
    """Everything one tool wrote for one case and variant."""

    records: dict[str, Json] = field(default_factory=dict)
    documents: dict[str, Json | None] = field(default_factory=dict)
    raw: dict[str, bytes] = field(default_factory=dict)
    stdout: bytes = b""
    stderr: bytes = b""
    elements: list[cdx.Element] = field(default_factory=list)
    links: dict[str, set[str]] = field(default_factory=dict)

    @property
    def bom(self) -> Json | None:
        return self.documents.get("cdx")

    def blobs(self) -> list[bytes]:
        return [*self.raw.values(), self.stdout, self.stderr]


def _read(path: Path) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read(READ_LIMIT)
    except OSError:
        return b""


def load_view(work: Path, tool_id: str, case_id: str, variant: str = "base") -> View:
    view = View()
    base = work / "runs" / tool_id / case_id / variant.replace(":", "_")
    for fmt, name in OUT_NAMES.items():
        directory = base / fmt
        record = directory / "record.json"
        if not record.is_file():
            continue
        view.records[fmt] = json.loads(record.read_text())
        output = directory / "out" / name
        view.raw[fmt] = _read(output)
        view.documents[fmt] = cdx.load(output) if output.is_file() else None
        view.stdout += _read(directory / "stdout.bin")
        view.stderr += _read(directory / "stderr.bin")
    if view.bom is not None:
        view.elements = cdx.elements(view.bom)
        view.links = cdx.links(view.bom)
    return view


def _matches(expect: Expect, element: cdx.Element) -> bool:
    return any(all(token.lower() in element.text for token in group) for group in expect.any_of)


def recognized(expect: Expect, view: View, generic: set[cdx.Signature]) -> list[cdx.Element]:
    """Elements that name the component and are not rendered like an arbitrary file."""
    return [
        element
        for element in view.elements
        if _matches(expect, element) and element.signature not in generic
    ]


def generic_signatures(corpus: Corpus, views: dict[str, View]) -> set[cdx.Signature]:
    """How this tool renders the control files, which hold no AI content."""
    signatures: set[cdx.Signature] = set()
    for case in corpus.all_cases():
        view = views.get(case.id)
        if view is None:
            continue
        tokens = control_tokens(case.id if case in corpus.discovery else _control_key(case))
        for element in view.elements:
            if any(token in element.text for token in tokens):
                signatures.add(element.signature)
    return signatures


def _control_key(case: Case) -> str:
    for path in case.files:
        if path.startswith("docs/ctrl-notes-"):
            return path[len("docs/ctrl-notes-") : -len(".md")]
    return case.id


def _word(token: str, text: str) -> bool:
    pattern = r"(?<![a-z0-9])" + re.escape(token.lower()) + r"(?![a-z0-9])"
    return re.search(pattern, text) is not None


def _version(token: str, text: str) -> bool:
    pattern = r"(?<![a-z0-9.])" + re.escape(token.lower()) + r"(?![a-z0-9])(?!\.\d)"
    return re.search(pattern, text) is not None


def _under_datasets(node: Any, expect: Expect, inside: bool = False) -> bool:
    if isinstance(node, dict):
        return any(
            _under_datasets(value, expect, inside or key == "datasets")
            for key, value in node.items()
        )
    if isinstance(node, list):
        return any(_under_datasets(item, expect, inside) for item in node)
    if inside and isinstance(node, str):
        return any(all(token.lower() in node.lower() for token in group) for group in expect.any_of)
    return False


def attribute_holds(
    attr: Attr, expect: Expect, element: cdx.Element, files: dict[str, bytes]
) -> bool:
    if attr.kind == "version":
        return all(_version(value, element.text) for value in attr.values)
    if attr.kind == "purl":
        wanted = {cdx.normalize_purl(value) for value in attr.values}
        return any(cdx.normalize_purl(value) in wanted for value in cdx.purl_values(element.obj))
    if attr.kind == "sha256":
        return hashlib.sha256(files[attr.values[0]]).hexdigest() in element.text
    if attr.kind == "location":
        return all(value.lower() in element.text for value in attr.values)
    if attr.kind == "type":
        if element.type in attr.values:
            return True
        return DATA in attr.values and _under_datasets(element.obj, expect)
    return all(_word(value, element.text) for value in attr.values)


def connected(sources: list[cdx.Element], targets: list[cdx.Element], view: View) -> bool:
    """True when the document relates the two components in any standard way."""
    for source in sources:
        for target in targets:
            if source.index == target.index:
                return True
            if source.parent == target.index or target.parent == source.index:
                return True
            if source.ref and target.ref:
                if target.ref in view.links.get(source.ref, set()):
                    return True
                if len(target.ref) >= 6 and target.ref.lower() in source.text.replace(
                    source.ref.lower(), ""
                ):
                    return True
                if len(source.ref) >= 6 and source.ref.lower() in target.text.replace(
                    target.ref.lower(), ""
                ):
                    return True
    return False


_VALIDATORS: dict[str, Any] = {}


def schema_valid(raw: bytes, bom: Json) -> bool | None:
    """Strict validation against the official schema of the version the document declares.

    ``None`` when the validator or that schema version is unavailable.
    """
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError:
        return None
    version = str(bom.get("specVersion", ""))
    if version not in _VALIDATORS:
        try:
            _VALIDATORS[version] = JsonStrictValidator(SchemaVersion.from_version(version))
        except (ValueError, KeyError):
            _VALIDATORS[version] = None
    validator = _VALIDATORS[version]
    if validator is None:
        return None
    try:
        return validator.validate_str(raw.decode("utf-8", "replace")) is None
    except Exception:  # noqa: BLE001 - a validator crash is a failed validation, not a harness error
        return False


def _short(value: Any) -> str | None:
    if isinstance(value, bool) or value is None:
        return str(value)
    if not isinstance(value, (str, int, float)):
        return None
    text = cdx.TIMESTAMP.sub("<time>", cdx.UUID.sub("<uuid>", str(value)))
    if len(text) > 160 or cdx.HEXISH.search(text):
        return None
    return text


def _native_signals(node: Any, counter: Counter[tuple[str, ...]], riskish: bool, key: str) -> None:
    if isinstance(node, dict):
        for name, value in node.items():
            _native_signals(value, counter, riskish or bool(RISKISH.search(str(name))), str(name))
    elif isinstance(node, list):
        for item in node:
            _native_signals(item, counter, riskish, key)
    elif riskish:
        value = _short(node)
        if value is not None:
            counter[("native", key, value)] += 1


def signals(view: View) -> Counter[tuple[str, ...]]:
    """Machine-readable risk statements in a tool's output, as comparable keys."""
    counter: Counter[tuple[str, ...]] = Counter()
    sarif = view.documents.get("sarif")
    if sarif:
        for run in sarif.get("runs") or []:
            for result in (run.get("results") or []) if isinstance(run, dict) else []:
                if isinstance(result, dict):
                    counter[
                        ("sarif", str(result.get("ruleId", "")), str(result.get("level", "")))
                    ] += 1
    bom = view.bom
    if bom:
        for vulnerability in bom.get("vulnerabilities") or []:
            if not isinstance(vulnerability, dict):
                continue
            ratings = vulnerability.get("ratings") or [{}]
            severity = ratings[0].get("severity", "") if isinstance(ratings[0], dict) else ""
            counter[("vulnerability", str(vulnerability.get("id", "")), str(severity))] += 1
        for annotation in bom.get("annotations") or []:
            if isinstance(annotation, dict):
                counter[("annotation", _short(annotation.get("text")) or "<long>")] += 1
        for element in view.elements:
            for prop in element.obj.get("properties") or []:
                if not isinstance(prop, dict) or not RISKISH.search(str(prop.get("name", ""))):
                    continue
                value = _short(prop.get("value"))
                if value is not None:
                    counter[("property", str(prop.get("name")), value)] += 1
    native = view.documents.get("native")
    if native:
        _native_signals(native, counter, False, "")
    return counter


def _lexicon(view: View) -> int:
    console = (view.stdout + view.stderr).lower()
    return sum(console.count(word.encode()) for word in RISK_WORDS)


def _exit(view: View) -> int | None:
    record = view.records.get("cdx")
    return None if record is None else record.get("exit_code")


def _completed(view: View) -> bool:
    record = view.records.get("cdx")
    if record is None or view.bom is None:
        return False
    code = record.get("exit_code")
    return (
        not record["timed_out"] and not record["memory_killed"] and code is not None and code >= 0
    )


class Scorer:
    """Scores one tool from the runs recorded in a work directory."""

    def __init__(self, corpus: Corpus, tool: Tool, work: Path) -> None:
        self.corpus = corpus
        self.tool = tool
        self.work = work
        self._views: dict[tuple[str, str], View] = {}
        base_views = {case.id: self.view(case.id) for case in corpus.all_cases()}
        self.generic = generic_signatures(corpus, base_views)

    def view(self, case_id: str, variant: str = "base") -> View:
        key = (case_id, variant)
        if key not in self._views:
            self._views[key] = load_view(self.work, self.tool.id, case_id, variant)
        return self._views[key]

    def found(self, case: Case, variant: str = "base") -> dict[str, list[cdx.Element]]:
        view = self.view(case.id, variant)
        return {expect.id: recognized(expect, view, self.generic) for expect in case.expects}

    def discovery(self) -> Json:
        by_domain = {domain: [0, 0] for domain in DOMAINS}
        items: Json = {}
        for case in self.corpus.discovery:
            hits = self.found(case)
            for expect in case.expects:
                by_domain[expect.domain][1] += 1
                elements = hits[expect.id]
                if elements:
                    by_domain[expect.domain][0] += 1
                items[expect.id] = {
                    "found": bool(elements),
                    "as": _describe(elements[0]) if elements else None,
                }
        domains: dict[str, Json] = {
            domain: {
                "found": found,
                "total": total,
                "recall": round(found / total, 4),
                "interval": wilson(found, total),
            }
            for domain, (found, total) in by_domain.items()
        }
        score = statistics.fmean(entry["recall"] for entry in domains.values())
        total_found = sum(entry["found"] for entry in domains.values())
        total = sum(entry["total"] for entry in domains.values())
        return {
            "score": round(score, 4),
            "found": total_found,
            "total": total,
            "micro_recall": round(total_found / total, 4),
            "domains": domains,
            "items": items,
        }

    def native(self) -> Json | None:
        """Recall in the tool's own JSON format, as a diagnostic of what export drops."""
        if "native" not in self.tool.commands:
            return None
        by_domain = {domain: [0, 0] for domain in DOMAINS}
        for case in self.corpus.discovery:
            document = self.view(case.id).documents.get("native")
            nodes = cdx.bounded_nodes(document) if document else []
            for expect in case.expects:
                by_domain[expect.domain][1] += 1
                if any(
                    all(token.lower() in node for token in group)
                    for node in nodes
                    for group in expect.any_of
                ):
                    by_domain[expect.domain][0] += 1
        recalls = {domain: round(found / total, 4) for domain, (found, total) in by_domain.items()}
        return {"score": round(statistics.fmean(recalls.values()), 4), "domains": recalls}

    def precision(self) -> Json:
        items: Json = {}
        for case in self.corpus.discovery:
            hits = self.found(case)
            view = self.view(case.id)
            for decoy in case.decoys:
                reported = any(
                    all(token.lower() in element.text for token in decoy.tokens)
                    for element in view.elements
                )
                paired = bool(hits[decoy.paired])
                items[decoy.id] = {"reported": reported, "paired_found": paired, "why": decoy.why}
        rejected = sum(
            1 for item in items.values() if item["paired_found"] and not item["reported"]
        )
        reported_count = sum(1 for item in items.values() if item["reported"])
        return {
            "score": round(rejected / len(items), 4),
            "rejected": rejected,
            "reported": reported_count,
            "total": len(items),
            "items": items,
        }

    def fidelity(self) -> Json:
        passed = total = passed_found = total_found = 0
        items: Json = {}
        for case in self.corpus.discovery:
            hits = self.found(case)
            for expect in case.expects:
                if not expect.attrs:
                    continue
                total += len(expect.attrs)
                elements = hits[expect.id]
                best: dict[str, bool] = {attr.label: False for attr in expect.attrs}
                for element in elements:
                    outcome = {
                        attr.label: attribute_holds(attr, expect, element, case.files)
                        for attr in expect.attrs
                    }
                    if sum(outcome.values()) > sum(best.values()):
                        best = outcome
                if elements:
                    total_found += len(expect.attrs)
                    passed_found += sum(best.values())
                passed += sum(best.values())
                items[expect.id] = best
        return {
            "score": round(passed / total, 4),
            "passed": passed,
            "total": total,
            "when_found": round(passed_found / total_found, 4) if total_found else None,
            "items": items,
        }

    def relationships(self) -> Json:
        items: Json = {}
        for case in self.corpus.discovery:
            hits = self.found(case)
            view = self.view(case.id)
            for edge in case.edges:
                sources, targets = hits[edge.source], hits[edge.target]
                items[f"{edge.source} {edge.relation} {edge.target}"] = bool(
                    sources and targets and connected(sources, targets, view)
                )
        return {
            "score": round(sum(items.values()) / len(items), 4),
            "found": sum(items.values()),
            "total": len(items),
            "items": items,
        }

    def conformance(self) -> Json:
        items: Json = {}
        valid = checked = 0
        for case in self.corpus.discovery:
            view = self.view(case.id)
            hits = self.found(case)
            if view.bom is None or not any(hits.values()):
                items[case.id] = None
                continue
            parts: dict[str, float] = {}
            verdict = schema_valid(view.raw["cdx"], view.bom)
            if verdict is not None:
                parts["schema"] = float(verdict)
                checked += 1
                valid += int(verdict)
            purls = [value for element in view.elements for value in cdx.purl_values(element.obj)]
            if purls:
                parts["purl"] = sum(bool(cdx.PURL.match(value)) for value in purls) / len(purls)
            refs = [element.ref for element in view.elements if element.ref]
            if refs:
                parts["refs"] = float(len(refs) == len(set(refs)))
            typed = [
                (expect, attr)
                for expect in case.expects
                for attr in expect.attrs
                if attr.kind == "type" and hits[expect.id]
            ]
            if typed:
                parts["typing"] = sum(
                    any(
                        attribute_holds(attr, expect, element, case.files)
                        for element in hits[expect.id]
                    )
                    for expect, attr in typed
                ) / len(typed)
            parts["case"] = statistics.fmean(parts.values()) if parts else 0.0
            items[case.id] = {name: round(value, 4) for name, value in parts.items()}
        engaged = [item["case"] for item in items.values() if item is not None]

        def mean_of(name: str) -> float | None:
            values = [item[name] for item in items.values() if item is not None and name in item]
            return round(statistics.fmean(values), 4) if values else None

        return {
            "score": round(sum(engaged) / len(items), 4),
            "when_engaged": round(statistics.fmean(engaged), 4) if engaged else None,
            "engaged_cases": len(engaged),
            "total_cases": len(items),
            "schema_valid": valid,
            "schema_checked": checked,
            "purl_valid": mean_of("purl"),
            "typing": mean_of("typing"),
            "items": items,
        }

    def risk(self) -> Json:
        items: Json = {}
        for pair in self.corpus.risk:
            clean, risky = self.view(pair.clean.id), self.view(pair.risky.id)
            extra = signals(risky) - signals(clean)
            console = _lexicon(risky) > _lexicon(clean) or _exit(risky) != _exit(clean)
            credit = 1.0 if extra else 0.5 if console else 0.0
            items[pair.id] = {
                "class": pair.klass,
                "credit": credit,
                "channel": "machine-readable" if extra else "console" if console else None,
                "evidence": [" | ".join(key) for key in sorted(extra)[:3]],
                "exit_codes": [_exit(clean), _exit(risky)],
            }
        return {
            "score": round(statistics.fmean(item["credit"] for item in items.values()), 4),
            "machine_readable": sum(1 for item in items.values() if item["credit"] == 1.0),
            "console_only": sum(1 for item in items.values() if item["credit"] == 0.5),
            "total": len(items),
            "items": items,
        }

    def _hostile_check(self, name: str, hostile: Hostile, view: View) -> bool:
        records = list(view.records.values())
        blobs = view.blobs()
        if name == "completes":
            return _completed(view)
        if name == "no_execution":
            return not any(record["canaries"] for record in records)
        if name == "no_escape":
            needles = [OUTSIDE_MARKER.encode()] + [
                hashlib.sha256(data).hexdigest().encode() for data in self.corpus.outside.values()
            ]
            return not any(needle in blob.lower() for needle in needles for blob in blobs)
        if name == "no_secret_disclosure":
            leaked = any(value.encode() in blob for value in secret_values() for blob in blobs)
            return not leaked and not any(record["secrets_in_state"] for record in records)
        if name == "no_terminal_escape":
            return ESCAPE_BEFORE_MARKER.search(view.stdout + view.stderr) is None
        if name == "bounded_memory":
            return all(
                record["max_rss_kb"] < BOUNDED_MEMORY_KB and not record["memory_killed"]
                for record in records
            )
        if name == "not_steered":
            if hostile.twin is None:
                return True
            lost = {key for key, value in self.found(hostile.twin).items() if value} - {
                key for key, value in self.found(hostile.case).items() if value
            }
            return not lost
        raise ValueError(name)

    def hostile(self) -> Json:
        items: Json = {}
        for hostile in self.corpus.hostile:
            view = self.view(hostile.case.id)
            engaged = any(self.found(hostile.case).values())
            checks = {name: self._hostile_check(name, hostile, view) for name in hostile.checks}
            safety = sum(checks.values()) / len(checks)
            items[hostile.case.id] = {
                "class": hostile.klass,
                "engaged": engaged,
                "checks": checks,
                "credit": round(safety, 4) if engaged else 0.0,
            }
        engaged_items = [item for item in items.values() if item["engaged"]]
        failures = sorted(
            f"{case_id}: {name}"
            for case_id, item in items.items()
            for name, ok in item["checks"].items()
            if not ok
        )
        return {
            "score": round(statistics.fmean(item["credit"] for item in items.values()), 4),
            "engaged": len(engaged_items),
            "total": len(items),
            "when_engaged": (
                round(statistics.fmean(item["credit"] for item in engaged_items), 4)
                if engaged_items
                else None
            ),
            "failed_checks": failures,
            "items": items,
        }

    def _same(self, case_id: str, variant: str) -> float:
        first, second = self.view(case_id).bom, self.view(case_id, variant).bom
        if first is None or second is None:
            return 0.0
        if cdx.strict_form(first) == cdx.strict_form(second):
            return 1.0
        return 0.5 if cdx.semantic_form(first) == cdx.semantic_form(second) else 0.0

    def reproducibility(self) -> Json:
        by_id = {case.id: case for case in self.corpus.discovery}
        items: Json = {}
        for base_id in sorted({mutation.base for mutation in self.corpus.mutations}):
            engaged = any(self.found(by_id[base_id]).values())
            repeat = self._same(base_id, "repeat")
            relocated = self._same(base_id, "relocated")
            items[base_id] = {
                "engaged": engaged,
                "repeat": repeat,
                "relocated": relocated,
                "credit": (repeat + relocated) / 2 if engaged else 0.0,
            }
        engaged_items = [item for item in items.values() if item["engaged"]]
        return {
            "score": round(statistics.fmean(item["credit"] for item in items.values()), 4),
            "engaged": len(engaged_items),
            "total": len(items),
            "when_engaged": (
                round(statistics.fmean(item["credit"] for item in engaged_items), 4)
                if engaged_items
                else None
            ),
            "items": items,
        }

    def change(self) -> Json:
        by_id = {case.id: case for case in self.corpus.discovery}
        items: Json = {}
        for mutation in self.corpus.mutations:
            base = self.view(mutation.base).bom
            engaged = bool(self.found(by_id[mutation.base])[mutation.binds])
            stable = self._same(mutation.base, "repeat") > 0.0
            mutated = self.view(mutation.base, f"mut:{mutation.id}").bom
            changed = (
                base is not None
                and mutated is not None
                and cdx.semantic_form(base) != cdx.semantic_form(mutated)
            )
            items[mutation.id] = {
                "title": mutation.title,
                "engaged": engaged,
                "stable": stable,
                "changed": changed,
                "credit": float(engaged and stable and changed),
            }
        engaged_items = [item for item in items.values() if item["engaged"]]
        return {
            "score": round(statistics.fmean(item["credit"] for item in items.values()), 4),
            "detected": sum(1 for item in items.values() if item["credit"]),
            "engaged": len(engaged_items),
            "total": len(items),
            "when_engaged": (
                round(statistics.fmean(item["credit"] for item in engaged_items), 4)
                if engaged_items
                else None
            ),
            "items": items,
        }

    def operations(self) -> Json:
        """Unscored measurements of every run of this tool."""
        home_scope = {case.id for case in self.corpus.all_cases() if case.home_scope}
        records = [
            json.loads(path.read_text())
            for path in sorted((self.work / "runs" / self.tool.id).glob("*/*/*/record.json"))
        ]
        touched = [
            record
            for record in records
            if record["case"] not in home_scope
            and (record["created"] or record["modified"] or record["deleted"])
        ]
        return {
            "runs": len(records),
            "median_seconds": round(
                statistics.median(record["wall_seconds"] for record in records), 2
            ),
            "max_seconds": max(record["wall_seconds"] for record in records),
            "peak_rss_mb": round(max(record["max_rss_kb"] for record in records) / 1024),
            "timeouts": sum(1 for record in records if record["timed_out"]),
            "exit_codes": dict(Counter(str(record["exit_code"]) for record in records)),
            "runs_that_changed_the_project": len(touched),
            "changed_paths_example": sorted(
                {path for record in touched for path in record["created"]}
            )[:5],
        }

    def all(self) -> Json:
        pillars: Json = {
            "discovery": self.discovery(),
            "precision": self.precision(),
            "fidelity": self.fidelity(),
            "relationships": self.relationships(),
            "conformance": self.conformance(),
            "risk": self.risk(),
            "hostile": self.hostile(),
            "reproducibility": self.reproducibility(),
            "change": self.change(),
        }
        composite = sum(WEIGHTS[name] * pillars[name]["score"] for name in WEIGHTS)
        return {
            "tool": self.tool.id,
            "name": self.tool.name,
            "version": self.tool.version,
            "composite": round(composite, 2),
            "grade": grade(composite),
            "pillars": pillars,
            "native": self.native(),
            "operations": self.operations(),
        }


def _describe(element: cdx.Element) -> str:
    name = str(element.obj.get("name", ""))[:60]
    return f"{element.kind}/{element.type or '-'}: {name}"


def sensitivity(scores: list[Json]) -> Json:
    """Rank of each tool under other weightings, to show how far the order depends on them."""
    schemes: dict[str, dict[str, float]] = {
        "published weights": {name: float(weight) for name, weight in WEIGHTS.items()},
        "equal pillars": dict.fromkeys(WEIGHTS, 1.0),
        "inventory only": {
            name: float(weight)
            if name in {"discovery", "precision", "fidelity", "relationships"}
            else 0.0
            for name, weight in WEIGHTS.items()
        },
        "assurance doubled": {
            name: weight
            * (2.0 if name in {"risk", "hostile", "reproducibility", "change"} else 1.0)
            for name, weight in WEIGHTS.items()
        },
    }
    for name in WEIGHTS:
        schemes[f"without {name}"] = {
            other: (0.0 if other == name else float(weight)) for other, weight in WEIGHTS.items()
        }
    ranks: Json = {score["tool"]: {} for score in scores}
    for scheme, weights in schemes.items():
        total = sum(weights.values())
        ordered = sorted(
            scores,
            key=lambda score: (
                -sum(weights[name] * score["pillars"][name]["score"] for name in weights) / total
            ),
        )
        for rank, score in enumerate(ordered, start=1):
            ranks[score["tool"]][scheme] = rank
    return {
        "schemes": list(schemes),
        "ranks": ranks,
        "range": {tool: [min(by.values()), max(by.values())] for tool, by in ranks.items()},
    }
