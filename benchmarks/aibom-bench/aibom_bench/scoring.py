"""Score one tool's recorded runs against the ground truth.

Ninety of the hundred points are computed here from tool output. The other ten come from
``assessments/<tool>.json``, where each judgement names its evidence and evidence tier.

A check a tool never faced earns nothing. Decoys, clean controls, canaries, secrets and
hostile cases each name the real components that show a tool read the file the check
lives in; a tool that found none of them was not tested and is not credited for passing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import extract
from .extract import Finding, Output, Record
from .runner import EGRESS_PROBE, EXEC_PROBE

# (id, group, title, points, method)
CRITERIA: list[tuple[str, str, str, float, str]] = [
    ("1.1", "Discovery", "Models", 7, "measured"),
    ("1.2", "Discovery", "Data", 6, "measured"),
    ("1.3", "Discovery", "Tools and frameworks", 5, "measured"),
    ("1.4", "Discovery", "Agent components", 9, "measured"),
    ("1.5", "Discovery", "Infrastructure and deployment", 3, "measured"),
    ("2.1", "Precision", "Decoy resistance", 4, "measured"),
    ("3.1", "Record fidelity", "Version and supplier", 4, "measured"),
    ("3.2", "Record fidelity", "Content digests", 3, "measured"),
    ("3.3", "Record fidelity", "Evidence location", 3, "measured"),
    ("3.4", "Record fidelity", "Domain facts and licence", 2, "measured"),
    ("3.5", "Record fidelity", "Relationships", 2, "measured"),
    ("4.1", "Standards", "CycloneDX output validates", 3, "measured"),
    ("4.2", "Standards", "SPDX output validates", 2, "measured"),
    ("4.3", "Standards", "AI vocabulary in CycloneDX", 2, "measured"),
    ("4.4", "Standards", "Package URLs", 1, "measured"),
    ("4.5", "Standards", "SARIF output validates", 1, "measured"),
    ("4.6", "Standards", "Minimum-element or framework reporting", 1, "assessed"),
    ("5.1", "BOM integrity", "Deterministic output", 4, "measured"),
    ("5.2", "BOM integrity", "Signing, attestation and verification", 3, "assessed"),
    ("5.3", "BOM integrity", "Reports what it could not read", 1, "measured"),
    ("5.4", "BOM integrity", "States collection scope and coverage", 1, "assessed"),
    ("5.5", "BOM integrity", "Evidence typing per record", 1, "assessed"),
    ("6.1", "Risk analysis", "Planted-risk recall", 8, "measured"),
    ("6.2", "Risk analysis", "Clean controls not flagged", 2, "measured"),
    ("6.3", "Risk analysis", "Advisory mapping and VEX", 2, "assessed"),
    ("7.1", "Change detection", "Changes visible in the BOM", 3, "measured"),
    ("7.2", "Change detection", "Native drift report", 3, "measured"),
    ("7.3", "Change detection", "CI and policy gate", 1, "assessed"),
    ("7.4", "Change detection", "Runtime reconciliation", 1, "assessed"),
    ("8.1", "Scanner safety", "Executes nothing from the project", 4, "measured"),
    ("8.2", "Scanner safety", "Stays inside the project", 2, "measured"),
    ("8.3", "Scanner safety", "Does not disclose secrets", 2, "measured"),
    ("8.4", "Scanner safety", "Neutralizes hostile names", 1, "measured"),
    ("8.5", "Scanner safety", "Survives hostile input", 2, "measured"),
    ("8.6", "Scanner safety", "Works offline, attempts no egress", 1, "measured"),
]
GROUPS = list(dict.fromkeys(group for _, group, _, _, _ in CRITERIA))
GRADES = [(85, "A"), (70, "B"), (55, "C"), (40, "D"), (25, "E"), (0, "F")]
TIER_FACTOR = {"M": 1.0, "V": 1.0, "S": 1.0, "D": 0.5, "N": 0.0}
FACT_COVERAGE_FLOOR = 8
RETENTION_FLOOR = 0.9
MAX_KINDS = 8
CONTAINER_CHANGES = 3
WALKER_DIRECTORIES = 3
PILLAR_CRITERION = {"models": "1.1", "data": "1.2", "tools": "1.3", "agents": "1.4", "infra": "1.5"}

# Type vocabulary accepted per kind. It is matched against a record's own type fields, never
# against its name or path, and lists generic words only; no tool's product terms.
KIND_PATTERNS = {
    "model": r"machine-learning-model|\bmodel|llm|weights|gguf|safetensors|onnx|aipackage"
    r"|foundation",
    "dataset": r"dataset|\bdata\b|training[-_ ]?(data|set)|corpus",
    "vector_store": r"vector|\brag\b|retriev|embedding|datastore|database|\bdb\b|\bdata\b|index"
    r"|memory|store|knowledge",
    "knowledge_source": r"\brag\b|knowledge|retriev|data[-_ ]?source|dataset|\bdata\b|document"
    r"|corpus|bucket|connector|storage",
    "framework": r"library|framework|package|sdk|pypi|npm|dependenc|pkg:|python|javascript"
    r"|application",
    "tool": r"tool|function|capabilit",
    "mcp_server": r"mcp|server|service",
    # Skills, instruction files, commands and subagent definitions are all natural-language
    # instruction artifacts, and tools draw the lines between them differently. A tool that
    # files AGENTS.md under "skill" has still said what it is.
    "skill": r"skill|instruction",
    "instructions": r"instruction|prompt|rule|memory|guidance|skill",
    "subagent": r"agent|skill|prompt|instruction",
    "prompt": r"prompt|instruction|template|system[-_ ]?message",
    "agent": r"agent|a2a|crew|workflow|assistant",
    "command": r"command|slash|prompt|skill|instruction",
    "hook": r"hook|setting|config|automation|agent",
    "permission": r"permission|setting|polic|allow|config|authorit|agent",
    "plugin": r"plugin|extension|marketplace",
    "guardrail": r"guardrail|rail|polic|safety",
    "container": r"container|image|docker|oci|service|platform|deployment|infra|compose",
    "endpoint": r"endpoint|service|cloud|platform|deployment|\bapi\b|infra|resource|llm",
    "ci_agent": r"action|workflow|\bci\b|pipeline|agent|github",
}
CRASH = re.compile(
    r"Traceback \(most recent call last\)|^panic: |FATAL ERROR|Segmentation fault"
    r"|Maximum call stack|RecursionError|MemoryError",
    re.M,
)
# A record that says the thing is not what its name suggests is not a false claim.
DISCLAIMED = re.compile(
    r"unrecogni[sz]ed|invalid|mismatch|not a valid|malformed|disguised|unknown format|corrupt"
    r"|not a (gguf|model)|bad magic",
)
READ_FAILURE = re.compile(
    r"error|fail|invalid|malformed|pars(e|ing)|could not|cannot|unable|unreadable|skipp"
    r"|truncat|unsupported|corrupt|incomplete|partial|\bgap\b",
)
BROKEN_FILES = ("packages/broken", "skills/broken", "models.broken", "garbage.mdc")
SENSITIVITY = {
    "declared weights": None,
    "equal weight per group": "equal",
    "measured criteria only": "measured",
    "inventory only (groups 1 to 3)": {"Discovery", "Precision", "Record fidelity"},
    "without scanner safety": set(GROUPS) - {"Scanner safety"},
    "without BOM integrity": set(GROUPS) - {"BOM integrity"},
}


def _matches(record: Record, key: str) -> bool:
    key = key.lower()
    return key[1:] in record.names if key.startswith("=") else key in record.own


def _named(record: Record, item: dict[str, Any]) -> bool:
    """Whether the record is named for this component, as opposed to mentioning it."""
    for key in (*item["keys"], *item["weak_keys"]):
        key = key.lower()
        if key[1:] in record.names if key.startswith("=") else key in record.identity:
            return True
    return False


Detected = dict[str, tuple[float, list[Record]]]
_KIND = {kind: re.compile(pattern) for kind, pattern in KIND_PATTERNS.items()}


def detect_all(truth: dict[str, Any], records: list[Record]) -> Detected:
    """Credit each component that some record identifies.

    A record identifies a component when it contains one of the component's keys and its
    own type says what kind of thing it is. Three rules keep a mention from passing as an
    identification:

    - no type, no credit: a record that names a string without classifying it earns nothing;
    - a type that fits more than ``MAX_KINDS`` kinds, on one record or across the records
      sharing one name, is a catch-all and counts as no type;
    - a record that matches several components of one kind is a listing unless it is named
      for one of them, and then it credits only those.
    """
    kinds = [
        frozenset(kind for kind, rx in _KIND.items() if rx.search(record.type_evidence))
        for record in records
    ]
    by_identity: dict[str, set[str]] = {}
    for record, matched in zip(records, kinds, strict=True):
        if record.identity:
            by_identity.setdefault(record.identity, set()).update(matched)

    def typed(index: int, kind: str) -> bool:
        record = records[index]
        if len(kinds[index]) > MAX_KINDS:
            return False
        if len(by_identity.get(record.identity, ())) > MAX_KINDS:
            return False
        return kind in kinds[index]

    candidates: dict[str, list[int]] = {item["id"]: [] for item in truth["items"]}
    claims: dict[tuple[int, str], list[dict[str, Any]]] = {}
    for item in truth["items"]:
        keys = (*item["keys"], *item["weak_keys"])
        for index, record in enumerate(records):
            if typed(index, item["kind"]) and any(_matches(record, key) for key in keys):
                candidates[item["id"]].append(index)
                claims.setdefault((index, item["kind"]), []).append(item)
    for (index, _), items in claims.items():
        if len(items) < 2:
            continue
        named = [item["id"] for item in items if _named(records[index], item)]
        for item in items:
            if item["id"] not in named:
                candidates[item["id"]].remove(index)
    return {
        name: (1.0 if found else 0.0, [records[index] for index in found])
        for name, found in candidates.items()
    }


class Exposure:
    """Whether a tool demonstrably read the file a check lives in.

    A component found in the file shows it. Where no labelled component lives in the file,
    a record or console line that names the file shows it; a bare file listing does not.
    """

    def __init__(
        self,
        truth: dict[str, Any],
        detected: Detected,
        records: list[Record],
        outputs: list[Output],
    ) -> None:
        self.table = truth["exposure"]
        self.detected = detected
        paths = {item["id"]: item["paths"][0] for item in truth["items"]}
        found_in = {
            paths[name].split("/")[0] if "/" in paths[name] else "."
            for name, (credit, _) in detected.items()
            if credit
        }
        # A tool that found components in three or more top-level directories walks the tree.
        self.walker = len(found_in) >= WALKER_DIRECTORIES
        self.text = " ".join(record.own for record in records if not record.is_file)
        self.text += " ".join(o.text.lower() for o in outputs if o.format.startswith("console-"))

    def __call__(self, check: str) -> bool:
        entry = self.table[check]
        if entry.get("walker"):
            return self.walker
        return any(self.detected[item][0] for item in entry["items"]) or any(
            path.lower() in self.text for path in entry["paths"]
        )


def _fact_rates(truth: dict[str, Any], detected: Detected) -> dict[str, Any]:
    groups = {
        "3.1": {"version", "supplier"},
        "3.2": {"digest"},
        "3.3": {"location"},
        "3.4": {"domain", "license"},
    }
    result = {}
    for criterion, classes in groups.items():
        expected = found = applicable = 0
        for item in truth["items"]:
            credit, matched = detected[item["id"]]
            facts = [fact for fact in item["facts"] if fact["cls"] in classes]
            if not credit or not facts:
                continue
            applicable += 1
            # Facts are read from what the records state in short fields, not from file
            # content a tool copied into them.
            text = " ".join(record.described or record.full for record in matched)
            for fact in facts:
                expected += 1
                found += any(option.lower() in text for option in fact["any_of"])
        rate = found / expected if expected else 0.0
        factor = min(1.0, applicable / FACT_COVERAGE_FLOOR)
        result[criterion] = {
            "score": rate * factor,
            "facts_found": found,
            "facts_expected": expected,
            "items_with_fact": applicable,
        }
    return result


def _edges(truth: dict[str, Any], detected: Detected, pairs: set[frozenset[str]]) -> dict[str, Any]:
    items = {item["id"]: item for item in truth["items"]}
    satisfied = []
    for edge in truth["edges"]:
        source, target = detected[edge["source"]][1], detected[edge["target"]][1]
        if not source or not target:
            continue
        target_keys = [k.lower() for k in items[edge["target"]]["keys"] if not k.startswith("=")]
        source_keys = [k.lower() for k in items[edge["source"]]["keys"] if not k.startswith("=")]
        mentioned = any(key in record.full for record in source for key in target_keys) or any(
            key in record.full for record in target for key in source_keys
        )
        linked = any(
            frozenset({a.ref, b.ref}) in pairs for a in source for b in target if a.ref and b.ref
        )
        if mentioned or linked:
            satisfied.append(edge["id"])
    return {"score": len(satisfied) / len(truth["edges"]), "satisfied": satisfied}


def _decoys(truth: dict[str, Any], records: list[Record], exposed: Exposure) -> dict[str, Any]:
    reported, untested = [], []
    for decoy in truth["decoys"]:
        if not exposed(decoy["id"]):
            untested.append(decoy["id"])
            continue
        pattern = re.compile(KIND_PATTERNS[decoy["signal"]])
        for record in records:
            if record.is_file or not any(key.lower() in record.own for key in decoy["keys"]):
                continue
            if pattern.search(record.type_evidence) and not DISCLAIMED.search(record.full):
                reported.append(decoy["id"])
                break
    total = len(truth["decoys"])
    return {
        "score": (total - len(untested) - len(reported)) / total,
        "reported_as_components": reported,
        "not_tested": untested,
    }


def _finding_hit(labelled: dict[str, Any], signal: re.Pattern[str], findings: list[Finding]) -> str:
    keys = [key.lower() for key in labelled["keys"]]
    for finding in findings:
        line, _, window = finding.text.partition("\x00")
        if any(key in line for key in keys) and signal.search(window or line):
            return f"{finding.source}: {finding.text[:400]}"
    return ""


def _risks(
    truth: dict[str, Any], findings: list[Finding], overrides: dict[str, Any]
) -> dict[str, Any]:
    signals = {name: re.compile(pattern, re.I) for name, pattern in truth["signals"].items()}
    verdicts: dict[str, Any] = {}
    for group in ("risks", "controls"):
        for labelled in truth[group]:
            snippet = _finding_hit(labelled, signals[labelled["signal"]], findings)
            verdict = {"auto": bool(snippet), "final": bool(snippet), "snippet": snippet}
            if labelled["id"] in overrides:
                verdict["final"] = bool(overrides[labelled["id"]]["verdict"])
                verdict["adjudication"] = overrides[labelled["id"]]["reason"]
            verdicts[labelled["id"]] = verdict
    offline = [risk for risk in truth["risks"] if not risk["online"]]
    caught = [risk["id"] for risk in offline if verdicts[risk["id"]]["final"]]
    classes_caught = {risk["signal"] for risk in offline if verdicts[risk["id"]]["final"]}
    controls = truth["controls"]
    tested = [control["id"] for control in controls if control["signal"] in classes_caught]
    flagged = [control["id"] for control in controls if verdicts[control["id"]]["final"]]
    clean = [control for control in tested if control not in flagged]
    return {
        "6.1": {"score": len(caught) / len(offline), "caught": caught, "of": len(offline)},
        "6.2": {
            "score": len(clean) / len(controls),
            "controls_flagged": flagged,
            "controls_tested": tested,
            "note": "a control is tested only when the tool caught a planted risk of its class",
        },
        "verdicts": verdicts,
    }


def _machine(outputs: list[Output]) -> dict[str, Output]:
    return {f"{o.label}:{o.format}": o for o in outputs if o.format in extract.MACHINE_FORMATS}


def _determinism(base: list[Output], repeat: list[Output]) -> dict[str, Any]:
    def comparable(output: Output) -> tuple[bytes, Any]:
        # A tool that records where it wrote its report differs between runs only because
        # the harness gave each run its own directory.
        raw = output.raw.replace(str(output.path.parent).encode(), b"<out>")
        try:
            return raw, extract.normalized(json.loads(raw))
        except ValueError:
            return raw, extract.normalized(output.doc)

    first, second = _machine(base), _machine(repeat)
    shared = sorted(set(first) & set(second))
    if not shared:
        return {"score": 0.0, "note": "no machine-readable output in both runs"}
    pairs = {name: (comparable(first[name]), comparable(second[name])) for name in shared}
    identical = [name for name, (one, two) in pairs.items() if one[0] == two[0]]
    stable = [name for name, (one, two) in pairs.items() if one[1] == two[1]]
    per_output = [1.0 if name in identical else 0.6 if name in stable else 0.0 for name in shared]
    return {
        "score": sum(per_output) / len(per_output),
        "byte_identical": identical,
        "identical_after_dropping_time_and_id_fields": [n for n in stable if n not in identical],
        "differs": [name for name in shared if name not in stable],
    }


def _change_visibility(
    truth: dict[str, Any], base: list[Record], repeat: list[Record], drift: list[Record]
) -> dict[str, Any]:
    all_keys = [[key.lower() for key in change["keys"]] for change in truth["changes"]]

    def specific(record: Record) -> bool:
        # A record that mentions several planted changes is a container (a document
        # element, an agent listing everything it can reach); any change alters it.
        return sum(any(k in record.own for k in keys) for keys in all_keys) < CONTAINER_CHANGES

    def texts(change: dict[str, Any], records: list[Record]) -> frozenset[str]:
        keys = [key.lower() for key in change["keys"]]
        return frozenset(
            extract.UUID.sub("<uuid>", record.full)
            for record in records
            if not record.is_file and any(k in record.own for k in keys) and specific(record)
        )

    visible, unstable = [], []
    for change in truth["changes"]:
        before, again, after = texts(change, base), texts(change, repeat), texts(change, drift)
        # Only a record that two identical runs agree on can show a change; one that
        # already differs between them proves nothing.
        stable = before & again
        if change["kind"] == "added":
            seen = not before and bool(after)
        elif change["kind"] == "removed":
            seen = bool(before) and not after
        elif not stable:
            if before:
                unstable.append(change["id"])
            seen = False
        else:
            seen = not stable <= after
        if seen:
            visible.append(change["id"])
    return {
        "score": len(visible) / len(truth["changes"]),
        "visible": visible,
        "not_attributable_output_varies_between_identical_runs": unstable,
    }


def _native_diff(
    truth: dict[str, Any], run: dict[str, Any] | None, out_dir: Path, panel: list[str] | None
) -> dict[str, Any]:
    """The share of planted changes a tool's own drift report states.

    The blind raters' verdicts are used when present. Without them the report is searched
    for each change's key, which misses a change reported under another name.
    """
    if not run:
        return {"score": 0.0, "note": "no drift command"}
    if panel is not None:
        known = {change["id"] for change in truth["changes"]}
        reported = sorted(set(panel) & known)
        method = "blind raters"
    else:
        text = ""
        for path in sorted(out_dir.glob("*")):
            if path.is_file():
                text += path.read_text(errors="replace").lower()
        reported = [
            change["id"]
            for change in truth["changes"]
            if any(key.lower() in text for key in change["keys"])
        ]
        method = "key search"
    return {
        "score": len(reported) / len(truth["changes"]),
        "reported": reported,
        "judged_by": method,
        "exit_code": run["exit_code"],
    }


def _leaks(tokens: list[str], outputs: list[Output]) -> list[str]:
    return sorted(
        {f"{o.label}:{o.format}" for o in outputs for token in tokens if token.encode() in o.raw}
    )


def _reports_read_failure(outputs: list[Output]) -> dict[str, Any]:
    """Whether a tool says it could not read a broken file, as opposed to merely listing it."""

    def states_failure(text: str) -> bool:
        return any(name in text for name in BROKEN_FILES) and bool(READ_FAILURE.search(text))

    def walk(node: Any) -> bool:
        if isinstance(node, dict):
            own = " ".join(
                f"{key} {value}"
                for key, value in node.items()
                if not isinstance(value, (dict, list))
            )
            own += " " + " ".join(
                str(e)
                for v in node.values()
                if isinstance(v, list)
                for e in v
                if not isinstance(e, (dict, list))
            )
            return states_failure(own.lower()) or any(walk(value) for value in node.values())
        if isinstance(node, list):
            return any(walk(value) for value in node)
        return False

    machine = [f"{o.label}:{o.format}" for o in outputs if o.doc is not None and walk(o.doc)]
    console = [
        f"{o.label}:{o.format}"
        for o in outputs
        if o.doc is None and any(states_failure(line) for line in o.text.lower().splitlines())
    ]
    return {
        "score": 1.0 if machine else 0.5 if console else 0.0,
        "stated_in_machine_output": machine,
        "stated_on_console_only": [] if machine else console,
    }


def weighted_total(scores: dict[str, float], scenario: Any) -> float:
    """A tool's total out of 100 under an alternative weighting, for the sensitivity table."""
    rows = [
        (criterion, group, weight)
        for criterion, group, _, weight, method in CRITERIA
        if not (scenario == "measured" and method != "measured")
        and not (isinstance(scenario, set) and group not in scenario)
    ]
    if scenario == "equal":
        totals = {group: sum(w for _, g, w in rows if g == group) for group in GROUPS}
        return sum(scores[c] * w / totals[g] * 100 / len(GROUPS) for c, g, w in rows)
    return sum(scores[c] * w for c, _, w in rows) * 100 / sum(w for _, _, w in rows)


def score_tool(
    truth: dict[str, Any],
    record: dict[str, Any],
    work: Path,
    assessment: dict[str, Any],
    validators: Any,
) -> dict[str, Any]:
    runs = record["runs"]

    def load(variant: str) -> list[Output]:
        if variant not in runs:
            return []
        return extract.load_outputs(runs[variant], work / "out" / variant.replace(":", "-"))

    base, repeat, drift = load("base"), load("repeat"), load("drift")
    records = extract.records(base)
    detected = detect_all(truth, records)
    exposed = Exposure(truth, detected, records, base)
    details: dict[str, Any] = {}
    scores: dict[str, float] = {}

    for pillar, criterion in PILLAR_CRITERION.items():
        items = [item for item in truth["items"] if item["pillar"] == pillar]
        earned = {item["id"]: detected[item["id"]][0] for item in items}
        scores[criterion] = sum(earned.values()) / len(items)
        details[criterion] = {
            "identified": sorted(i for i, c in earned.items() if c),
            "missed": sorted(i for i, c in earned.items() if not c),
        }
    base_credit = sum(credit for credit, _ in detected.values())
    recall = base_credit / len(truth["items"])

    details["2.1"] = _decoys(truth, records, exposed)
    details.update(_fact_rates(truth, detected))
    details["3.5"] = _edges(truth, detected, extract.links(base))

    cdx = [o for o in base if o.format == "cyclonedx-json" and isinstance(o.doc, dict)]
    spdx = [o for o in base if o.format == "spdx-json" and isinstance(o.doc, dict)]
    sarif = [o for o in base if o.format == "sarif" and isinstance(o.doc, dict)]
    details["4.1"] = validators.cyclonedx(cdx)
    details["4.2"] = validators.spdx(spdx)
    details["4.5"] = validators.sarif(sarif)

    cdx_records = [r for r in records if r.source.endswith("cyclonedx-json")]
    by_kind: dict[str, list[dict[str, Any]]] = {"model": [], "dataset": []}
    for item in truth["items"]:
        if item["kind"] in by_kind and detected[item["id"]][0]:
            by_kind[item["kind"]].append(item)

    def typed(items: list[dict[str, Any]], cdx_type: str) -> float:
        if not items:
            return 0.0
        hits = sum(
            any(
                r.cdx_type == cdx_type and any(_matches(r, k) for k in item["keys"])
                for r in cdx_records
            )
            for item in items
        )
        return hits / len(items)

    model_cards = any('"modelcard": {' in r.full for r in cdx_records)
    details["4.3"] = {
        "models_typed_machine_learning_model": typed(by_kind["model"], "machine-learning-model"),
        "datasets_typed_data": typed(by_kind["dataset"], "data"),
        "any_model_card": model_cards,
    }
    details["4.3"]["score"] = (
        0.5 * details["4.3"]["models_typed_machine_learning_model"]
        + 0.3 * details["4.3"]["datasets_typed_data"]
        + 0.2 * model_cards
    )
    frameworks = [i for i in truth["items"] if i["kind"] == "framework" and detected[i["id"]][0]]
    with_purl = sum(
        any(re.search(r"pkg:(pypi|npm)/", r.full) for r in detected[item["id"]][1])
        for item in frameworks
    )
    hf_purl = any("pkg:huggingface/" in r.full for r in records)
    details["4.4"] = {
        "frameworks_with_purl": with_purl,
        "frameworks_detected": len(frameworks),
        "huggingface_purl": hf_purl,
        "score": 0.7 * (with_purl / len(frameworks) if frameworks else 0.0) + 0.3 * hf_purl,
    }

    details["5.1"] = _determinism(base, repeat)
    details["5.3"] = _reports_read_failure(load("hostile:malformed"))

    overrides = assessment.get("adjudication", {})
    risk = _risks(truth, extract.findings(base), overrides)
    details["6.1"], details["6.2"], details["risk_verdicts"] = (
        risk["6.1"],
        risk["6.2"],
        risk["verdicts"],
    )

    details["7.1"] = _change_visibility(
        truth, records, extract.records(repeat), extract.records(drift)
    )
    details["7.2"] = _native_diff(
        truth, runs.get("diff"), work / "out" / "diff", assessment.get("changes_reported")
    )

    canaries = sorted(truth["exec_canaries"])
    tripped = {
        variant: runs[variant]["canaries_tripped"]
        for variant in ("base", "repeat", "drift", EXEC_PROBE)
        if runs.get(variant, {}).get("canaries_tripped")
    }
    faced = [name for name in canaries if exposed(f"canary.{name}")]
    details["8.1"] = {
        "score": 0.0 if tripped else len(faced) / len(canaries),
        "canaries_tripped": tripped,
        "canaries_faced": faced,
        "default_command_probe_ran": EXEC_PROBE in runs,
    }

    escaped = load("hostile:symlink-escape")
    tokens = truth["leak_tokens"]
    content = [tokens["outside.content"], tokens["outside.digest"]]
    escapes = {
        "import": (exposed("escape.import"), _leaks(content, base)),
        "dir-symlink": (
            exposed("escape.dir-symlink"),
            _leaks([*content, tokens["outside.inventory"]], escaped),
        ),
        "file-symlink": (
            exposed("escape.file-symlink"),
            _leaks([tokens["outside.model-name"], tokens["outside.model-digest"]], escaped),
        ),
    }
    details["8.2"] = {
        "score": sum(faced_it and not leaked for faced_it, leaked in escapes.values())
        / len(escapes),
        "checks": {
            name: {"faced": faced_it, "out_of_tree_content_in": leaked}
            for name, (faced_it, leaked) in escapes.items()
        },
    }

    secrets = {name: token for name, token in tokens.items() if name.startswith("secret.")}
    disclosed = {name: _leaks([token], [*base, *drift]) for name, token in secrets.items()}
    disclosed = {name: where for name, where in disclosed.items() if where}
    secrets_faced = [name for name in secrets if exposed(name)]
    kept = [name for name in secrets_faced if name not in disclosed]
    details["8.3"] = {
        "score": len(kept) / len(secrets),
        "disclosed": disclosed,
        "secrets_faced": secrets_faced,
    }

    hostile_names = load("hostile:escape-names")
    everything = b" ".join(output.raw for output in hostile_names)
    terminal = [
        o
        for o in hostile_names
        if o.format.startswith("console-") or o.format in {"text", "markdown"}
    ]
    rendered = [o for o in hostile_names if o.format in {"html", "markdown"}]
    ansi_faced, html_faced = b"AIBOM-BENCH-TITLE" in everything, b"AIBOM-BENCH-XSS" in everything
    ansi = _leaks([truth["markers"]["ansi"]], terminal)
    html = _leaks([truth["markers"]["html"]], rendered)
    details["8.4"] = {
        "score": 0.5 * (ansi_faced and not ansi) + 0.5 * (html_faced and not html),
        "terminal_escape": {"faced": ansi_faced, "raw_in": ansi},
        "html": {"faced": html_faced, "raw_in": html},
    }

    cases = {}
    for case in truth["hostile_cases"]:
        variant = f"hostile:{case}"
        run = runs.get(variant)
        faced_it = exposed(f"hostile.{case}")
        if not run:
            cases[case] = {"passed": False, "faced": faced_it, "reason": "not run"}
            continue
        timed_out = any(scan["timed_out"] for scan in run["scans"])
        credit = sum(c for c, _ in detect_all(truth, extract.records(load(variant))).values())
        retention = credit / base_credit if base_credit else 0.0
        cases[case] = {
            "passed": faced_it and not timed_out and retention >= RETENTION_FLOOR,
            "faced": faced_it,
            "timed_out": timed_out,
            "retention": round(retention, 3),
            "unhandled_error_in_stderr": any(
                CRASH.search(path.read_text(errors="replace"))
                for path in (work / "out" / variant.replace(":", "-")).glob("*.stderr")
            ),
            "seconds": max(scan["seconds"] for scan in run["scans"]),
        }
    details["8.5"] = {
        "score": sum(case["passed"] for case in cases.values()) / len(truth["hostile_cases"]),
        "cases": cases,
    }

    produced = bool(_machine(base))
    probe = runs.get(EGRESS_PROBE)
    attempts = sorted(
        {a for scan in (probe or {}).get("scans", []) for a in scan.get("egress_attempts") or []}
    )
    with_flags = sorted(
        {
            a
            for scan in runs.get("repeat", {}).get("scans", [])
            for a in scan.get("egress_attempts") or []
        }
    )
    details["8.6"] = {
        "score": 0.5 * produced
        + 0.5 * (probe is not None and bool(probe["scans"]) and not attempts),
        "inventory_produced_without_network": produced,
        "default_command_connection_attempts": attempts,
        "connection_attempts_with_scored_flags": with_flags,
    }

    for criterion, _, _, _, method in CRITERIA:
        if method == "assessed":
            entry = assessment.get("criteria", {}).get(
                criterion, {"level": 0, "tier": "N", "evidence": "not assessed"}
            )
            details[criterion] = {
                **entry,
                "score": float(entry["level"]) * TIER_FACTOR[entry["tier"]],
            }
        if criterion not in scores:
            scores[criterion] = float(details[criterion]["score"])

    points = {c: round(scores[c] * weight, 2) for c, _, _, weight, _ in CRITERIA}
    total = round(sum(points.values()), 1)
    groups: dict[str, dict[str, float]] = {}
    for criterion, group, _, weight, _ in CRITERIA:
        entry = groups.setdefault(group, {"points": 0.0, "of": 0.0})
        entry["points"] = round(entry["points"] + points[criterion], 2)
        entry["of"] += weight
    base_scans = runs.get("base", {}).get("scans", [])
    return {
        "tool": record["tool"],
        "version": record.get("version"),
        "total": total,
        "grade": next(letter for floor, letter in GRADES if total >= floor),
        "groups": groups,
        "points": points,
        "scores": {criterion: round(value, 4) for criterion, value in scores.items()},
        "sensitivity": {
            name: round(weighted_total(scores, scenario), 1)
            for name, scenario in SENSITIVITY.items()
        },
        "recall": round(recall, 3),
        "components_reported": len(records),
        "seconds": round(sum(scan["seconds"] for scan in base_scans), 1),
        "max_rss_mb": max((scan["max_rss_mb"] for scan in base_scans), default=0),
        "details": details,
    }


def dump(results: list[dict[str, Any]], path: Path, work: Path) -> None:
    """Write the results with the host's directories masked in quoted evidence."""
    text = json.dumps(results, indent=2, sort_keys=True)
    for location, label in ((work.resolve(), "<work>"), (work.resolve().parent, "<host>")):
        # Quoted findings are lowercased, so the path is matched in any case.
        text = re.sub(re.escape(str(location)), label, text, flags=re.IGNORECASE)
    # A quoted line can be cut or wrapped part-way through a path; mask what is left of it.
    root = "/".join(work.resolve().parts[:3]).replace("//", "/")
    text = re.sub(re.escape(root) + r"[^\s\"\\]*", "<host>", text, flags=re.IGNORECASE)
    path.write_text(text + "\n")
