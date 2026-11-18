"""Score one tool's recorded runs against the ground truth.

Ninety of the hundred points are computed here from tool output. The other ten come from
``assessments/<tool>.json``, where each judgement names its evidence and evidence tier.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import extract
from .extract import Finding, Output, Record

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
GRADES = [(85, "A"), (70, "B"), (55, "C"), (40, "D"), (25, "E"), (0, "F")]
TIER_FACTOR = {"M": 1.0, "V": 1.0, "S": 1.0, "D": 0.5, "N": 0.0}
FACT_COVERAGE_FLOOR = 8
RETENTION_FLOOR = 0.9
PILLAR_CRITERION = {"models": "1.1", "data": "1.2", "tools": "1.3", "agents": "1.4", "infra": "1.5"}

KIND_PATTERNS = {
    "model": r"machine-learning-model|\bmodel|llm|weights|gguf|safetensors|onnx|huggingface"
    r"|aipackage|\bai\b|foundation|embedding",
    "dataset": r"\bdata\b|dataset|training|corpus",
    "vector_store": r"vector|\brag\b|retriev|embedding|datastore|database|\bdata\b|index|memory"
    r"|store|knowledge",
    "knowledge_source": r"\brag\b|knowledge|source|\bdata\b|dataset|retriev|document|corpus"
    r"|bucket|connector",
    "framework": r"library|framework|package|sdk|pypi|npm|dependenc|pkg:|python|javascript"
    r"|application",
    "tool": r"tool|function|capabilit|action",
    "mcp_server": r"mcp|server|service",
    "skill": r"skill",
    "instructions": r"instruction|prompt|rule|memory|context|agent|config|guidance|\bide",
    "prompt": r"prompt|instruction|template|system",
    "agent": r"agent|a2a|crew|workflow|assistant|graph",
    "command": r"command|slash|prompt|skill|instruction",
    "hook": r"hook|setting|config|automation|\bide",
    "permission": r"permission|setting|policy|allow|config|authority|\bide",
    "plugin": r"plugin|extension|marketplace",
    "guardrail": r"guardrail|rail|policy|safety|config",
    "container": r"container|image|docker|oci|service|platform|deployment",
    "endpoint": r"endpoint|service|cloud|platform|deployment|\bapi\b|infrastructure|resource",
    "ci_agent": r"action|workflow|\bci\b|pipeline|agent|github",
}
CRASH = re.compile(
    r"Traceback \(most recent call last\)|^panic: |FATAL ERROR|Segmentation fault"
    r"|Maximum call stack|RecursionError|MemoryError",
    re.M,
)


def _matches(record: Record, key: str) -> bool:
    key = key.lower()
    return key[1:] in record.names if key.startswith("=") else key in record.own


def _detect(item: dict[str, Any], records: list[Record]) -> tuple[float, list[Record]]:
    pattern = re.compile(KIND_PATTERNS[item["kind"]])
    credit, matched = 0.0, []
    for record in records:
        strong = any(_matches(record, key) for key in item["keys"])
        weak = any(_matches(record, key) for key in item["weak_keys"])
        if not strong and not weak:
            continue
        if pattern.search(record.type_evidence):
            value = 1.0
        elif record.is_file or not strong:
            continue
        else:
            value = 0.5
        credit = max(credit, value)
        matched.append(record)
    return credit, matched


def detect_all(
    truth: dict[str, Any], records: list[Record]
) -> dict[str, tuple[float, list[Record]]]:
    return {item["id"]: _detect(item, records) for item in truth["items"]}


def _fact_rates(
    truth: dict[str, Any], detected: dict[str, tuple[float, list[Record]]]
) -> dict[str, Any]:
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
            text = " ".join(record.full for record in matched)
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


def _edges(
    truth: dict[str, Any],
    detected: dict[str, tuple[float, list[Record]]],
    pairs: set[frozenset[str]],
) -> dict[str, Any]:
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


def _decoys(truth: dict[str, Any], records: list[Record], recall: float) -> dict[str, Any]:
    hits = []
    for decoy in truth["decoys"]:
        pattern = re.compile(KIND_PATTERNS[decoy["signal"]])
        for record in records:
            if record.is_file or not any(key.lower() in record.own for key in decoy["keys"]):
                continue
            if pattern.search(record.type_evidence):
                hits.append(decoy["id"])
                break
    score = 0.0 if recall < 0.05 else 1 - len(hits) / len(truth["decoys"])
    return {"score": score, "reported_as_components": hits}


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
    flagged = [control["id"] for control in truth["controls"] if verdicts[control["id"]]["final"]]
    recall = len(caught) / len(offline)
    return {
        "6.1": {"score": recall, "caught": caught, "of": len(offline)},
        "6.2": {
            "score": 0.0 if not caught else 1 - len(flagged) / len(truth["controls"]),
            "controls_flagged": flagged,
        },
        "verdicts": verdicts,
    }


def _machine(outputs: list[Output]) -> dict[str, Output]:
    return {f"{o.label}:{o.format}": o for o in outputs if o.format in extract.MACHINE_FORMATS}


def _determinism(base: list[Output], repeat: list[Output]) -> dict[str, Any]:
    first, second = _machine(base), _machine(repeat)
    shared = sorted(set(first) & set(second))
    if not shared:
        return {"score": 0.0, "note": "no machine-readable output in both runs"}
    identical = [name for name in shared if first[name].raw == second[name].raw]
    stable = [
        name
        for name in shared
        if extract.normalized(first[name].doc) == extract.normalized(second[name].doc)
    ]
    score = 1.0 if len(identical) == len(shared) else 0.6 if len(stable) == len(shared) else 0.0
    return {
        "score": score,
        "byte_identical": identical,
        "identical_after_dropping_time_and_id_fields": stable,
        "compared": shared,
    }


def _change_visibility(
    truth: dict[str, Any],
    base: list[Record],
    repeat: list[Record],
    drift: list[Record],
) -> dict[str, Any]:
    def texts(change: dict[str, Any], records: list[Record]) -> frozenset[str]:
        keys = [key.lower() for key in change["keys"]]
        return frozenset(
            record.full
            for record in records
            if not record.is_file and any(k in record.own for k in keys)
        )

    visible, unstable = [], []
    for change in truth["changes"]:
        before, again, after = texts(change, base), texts(change, repeat), texts(change, drift)
        if change["kind"] == "added":
            seen = not before and bool(after)
        elif change["kind"] == "removed":
            seen = bool(before) and not after
        elif before != again:
            unstable.append(change["id"])
            seen = False
        else:
            seen = bool(before) and before != after
        if seen:
            visible.append(change["id"])
    return {
        "score": len(visible) / len(truth["changes"]),
        "visible": visible,
        "not_attributable_output_varies_between_identical_runs": unstable,
    }


def _native_diff(
    truth: dict[str, Any], run: dict[str, Any] | None, out_dir: Path
) -> dict[str, Any]:
    if not run:
        return {"score": 0.0, "note": "no drift command"}
    text = ""
    for path in sorted(out_dir.glob("*")):
        if path.is_file():
            text += path.read_text(errors="replace").lower()
    reported = [
        change["id"]
        for change in truth["changes"]
        if any(key.lower() in text for key in change["keys"])
    ]
    return {
        "score": len(reported) / len(truth["changes"]),
        "reported": reported,
        "exit_code": run["exit_code"],
    }


def _leaks(tokens: list[str], outputs: list[Output]) -> list[str]:
    return sorted(
        {f"{o.label}:{o.format}" for o in outputs for token in tokens if token.encode() in o.raw}
    )


def _inventory_credit(truth: dict[str, Any], outputs: list[Output]) -> float:
    return sum(credit for credit, _ in detect_all(truth, extract.records(outputs)).values())


def _crashed(out_dir: Path) -> bool:
    return any(CRASH.search(path.read_text(errors="replace")) for path in out_dir.glob("*.stderr"))


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
    details: dict[str, Any] = {}
    scores: dict[str, float] = {}

    for pillar, criterion in PILLAR_CRITERION.items():
        items = [item for item in truth["items"] if item["pillar"] == pillar]
        earned = {item["id"]: detected[item["id"]][0] for item in items}
        scores[criterion] = sum(earned.values()) / len(items)
        details[criterion] = {
            "classified": sorted(i for i, c in earned.items() if c == 1.0),
            "present_untyped": sorted(i for i, c in earned.items() if c == 0.5),
            "missed": sorted(i for i, c in earned.items() if c == 0.0),
        }
    recall = sum(credit for credit, _ in detected.values()) / len(truth["items"])

    details["2.1"] = _decoys(truth, records, recall)
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
    malformed = load("hostile:malformed")
    named = [
        f"{o.label}:{o.format}"
        for o in malformed
        if b"packages/broken" in o.raw or b"skills/broken" in o.raw or b"models.broken" in o.raw
    ]
    in_machine = [name for name in named if name.split(":", 1)[1] in extract.MACHINE_FORMATS]
    details["5.3"] = {
        "score": 1.0 if in_machine else 0.5 if named else 0.0,
        "malformed_files_named_in": named,
    }

    console = [o for o in base if o.format.startswith("console-")]
    overrides = assessment.get("adjudication", {})
    risk = _risks(truth, extract.findings([*base, *console]), overrides)
    details["6.1"], details["6.2"], details["risk_verdicts"] = (
        risk["6.1"],
        risk["6.2"],
        risk["verdicts"],
    )

    details["7.1"] = _change_visibility(
        truth, records, extract.records(repeat), extract.records(drift)
    )
    details["7.2"] = _native_diff(truth, runs.get("diff"), work / "out" / "diff")

    tripped = sorted(
        {
            name
            for variant in ("base", "repeat", "drift")
            for name in runs.get(variant, {}).get("canaries_tripped", [])
        }
    )
    details["8.1"] = {"score": 0.0 if tripped else 1.0, "canaries_tripped": tripped}

    outside = [
        truth["leak_tokens"][name]
        for name in ("outside.content", "outside.digest", "outside.inventory")
    ]
    import_leak = _leaks(outside, base)
    symlink_leak = _leaks(outside, load("hostile:symlink-escape"))
    details["8.2"] = {
        "score": 0.5 * (not import_leak) + 0.5 * (not symlink_leak),
        "out_of_tree_content_via_import": import_leak,
        "out_of_tree_content_via_symlink": symlink_leak,
    }
    secrets = {
        name: token for name, token in truth["leak_tokens"].items() if name.startswith("secret.")
    }
    disclosed = {name: _leaks([token], [*base, *drift]) for name, token in secrets.items()}
    disclosed = {name: where for name, where in disclosed.items() if where}
    details["8.3"] = {"score": 1 - len(disclosed) / len(secrets), "disclosed": disclosed}

    escaped = load("hostile:escape-names")
    ansi = _leaks(
        [truth["markers"]["ansi"]],
        [o for o in escaped if o.format.startswith("console-") or o.format in {"text", "markdown"}],
    )
    html = _leaks(
        [truth["markers"]["html"]], [o for o in escaped if o.format in {"html", "markdown"}]
    )
    details["8.4"] = {
        "score": 0.5 * (not ansi) + 0.5 * (not html),
        "raw_terminal_escape_in": ansi,
        "raw_html_in": html,
    }

    base_credit = sum(credit for credit, _ in detected.values())
    cases = {}
    for case in truth["hostile_cases"]:
        variant = f"hostile:{case}"
        run = runs.get(variant)
        if not run:
            cases[case] = {"passed": False, "reason": "not run"}
            continue
        timed_out = any(scan["timed_out"] for scan in run["scans"])
        credit = _inventory_credit(truth, load(variant))
        retention = credit / base_credit if base_credit else 0.0
        crashed = _crashed(work / "out" / variant.replace(":", "-"))
        passed = not timed_out and base_credit > 0 and retention >= RETENTION_FLOOR
        cases[case] = {
            "passed": passed,
            "timed_out": timed_out,
            "retention": round(retention, 3),
            "unhandled_error_in_stderr": crashed,
            "seconds": max(scan["seconds"] for scan in run["scans"]),
        }
    details["8.5"] = {
        "score": sum(case["passed"] for case in cases.values()) / len(truth["hostile_cases"]),
        "cases": cases,
    }

    produced = bool(_machine(base))
    attempts = sorted(
        {
            a
            for scan in runs.get("repeat", {}).get("scans", [])
            for a in scan.get("egress_attempts") or []
        }
    )
    details["8.6"] = {
        "score": 0.5 * produced + 0.5 * (produced and not attempts),
        "inventory_produced_without_network": produced,
        "connection_attempts": attempts,
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
        "recall": round(recall, 3),
        "components_reported": len(records),
        "seconds": round(sum(scan["seconds"] for scan in base_scans), 1),
        "max_rss_mb": max((scan["max_rss_mb"] for scan in base_scans), default=0),
        "details": details,
    }


def dump(results: list[dict[str, Any]], path: Path) -> None:
    path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
