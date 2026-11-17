#!/usr/bin/env python3
"""Score AI-BOM tools against the AAB ground truth.

Reads the raw outputs ``run_tools.py`` produced, the ground truth ``build_fixture.py`` wrote
and one rubric file per tool, then writes ``scores.json`` and ``RESULTS.md``.

Measured criteria come from the outputs; rubric criteria come from ``rubric/<tool>.yaml`` with
an evidence label each. A criterion labelled D (documentation) earns at most 60 percent of
its points; U (unverified) earns nothing and leaves the in-scope denominator.

Usage: score.py --ground-truth FILE --raw DIR --rubric DIR --out DIR [--sarif-schema FILE]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

DISCOVERY_RUNS = {"default-1", "autodetect", "json", "native", "sarif", "spdx"}
DEFAULT_RUNS = ("default-1", "default-2")
SAFE_RUNS = ("offline", "safe")
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
TIMESTAMP_RE = re.compile(r"\d{4}-\d\d-\d\d[T _-]\d\d:\d\d(:\d\d(\.\d+)?)?(Z|[+-]\d\d:?\d\d)?")
EPOCH_RE = re.compile(r"(?<=[@:_-])\d{10}(?!\d)")
NODE_PID_RE = re.compile(r"\(node:\d+\)")
VOLATILE_KEYS = {
    "serialnumber",
    "timestamp",
    "created",
    "generated_at",
    "generatedat",
    "scan_time",
    "scantime",
    "duration",
    "duration_seconds",
    "durationseconds",
    "duration_ms",
    "elapsed",
    "elapsed_ms",
    "start_time",
    "end_time",
    "starttime",
    "endtime",
    "scan_id",
    "scanid",
    "run_id",
    "runid",
    "scan_timestamp",
    "date",
    "scan_date",
    "startutc",
    "endutc",
    "scanned_at",
    "completed_at",
    "started_at",
    "finished_at",
}
VOLATILE_PROPERTY_HINTS = (
    "duration",
    "elapsed",
    "timestamp",
    "scan_time",
    "scantime",
    "date",
    "generated",
    "runtime_seconds",
)
IDENTIFIER_KEYS = {
    "bom-ref",
    "ref",
    "id",
    "instance_id",
    "scan_id",
    "@id",
    "spdxid",
    "canonical-id",
    "canonical_id",
    "dependson",
    "source_instance_id",
    "target_instance_id",
}
VERSION_PLACEHOLDERS = {"", "unknown", "configured", "none", "null", "n/a"}
CONFIDENCE_HINTS = (
    "confidence",
    "trusttier",
    "assurancelevel",
    "tier",
    "provenance:confidence",
    "declared",
    "inferred",
    "verified",
    "reviewneeded",
)
LOCATOR_PROPERTY_HINTS = (
    "file",
    "path",
    "source",
    "location",
    "srcfile",
    "config_source",
    "configsource",
    "line",
    "surface",
)
# A component property is a finding only when its name carries a risk hint and its value
# has the problem polarity: "versionPinned=false" and "floating-reference=true" are findings,
# "floating-reference=false", "transport=stdio" and "risk_score=0" are not.
NEGATIVE_POLARITY_HINTS = (
    "pinned",
    "safe",
    "safety",
    "verified",
    "signed",
    "valid",
    "confined",
    "scoped",
    "authenticated",
    "encrypted",
    "bound",
)
POSITIVE_POLARITY_HINTS = (
    "floating",
    "unpinned",
    "credential",
    "exposure",
    "exposed",
    "reviewneeded",
    "review_needed",
    "insecure",
    "unsafe",
    "risk",
    "issue",
    "warning",
    "finding",
    "flag",
    "secret",
    "violation",
    "misconfig",
    "alert",
    "has-credentials",
    "credentialexposure",
    "dangerous",
    "plaintext",
    "vulnerab",
)
FALSY_VALUES = {"", "false", "none", "null", "0", "0.0", "n/a", "unknown", "[]", "{}", "no"}
VULN_ID_RE = re.compile(
    r"\b(CVE|GHSA|PYSEC|OSV|RUSTSEC|GO|MAL)-\d{4}-|\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b",
    re.I,
)
TELEMETRY_HOSTS = {
    "api.aisbom.io",
    "api.segment.io",
    "www.google-analytics.com",
    "app.posthog.com",
    "us.i.posthog.com",
    "sentry.io",
}
G7_CLUSTERS = ["metadata", "system", "models", "datasets", "infrastructure", "security", "kpi"]


def property_is_finding(name: str, value: str) -> bool:
    n, v = name.lower(), str(value).strip().lower()
    if any(h in n for h in NEGATIVE_POLARITY_HINTS):
        if v in {
            "false",
            "no",
            "unsafe",
            "unpinned",
            "unverified",
            "unsigned",
            "invalid",
            "unbound",
            "unscoped",
        } or v.startswith(("unsafe", "unpinned", "unverified", "unsigned", "invalid", "unbound")):
            return True
    if any(h in n for h in POSITIVE_POLARITY_HINTS):
        if v not in FALSY_VALUES and not (v.replace(".", "", 1).isdigit() and float(v) == 0):
            return True
    return False


DIMENSIONS = {
    "D1": ("Discovery coverage", 30),
    "D2": ("Evidence and attribute quality", 15),
    "D3": ("Risk and integrity analysis", 12),
    "D4": ("Standards conformance and interoperability", 12),
    "D5": ("Trustworthiness of the BOM artifact", 10),
    "D6": ("Scanner safety and tool hygiene", 12),
    "D7": ("Runtime reconciliation", 5),
    "D8": ("Operability", 4),
}
FAMILY_POINTS = {"agent": 8, "mcp": 10, "model": 6, "data": 4, "tools": 2}
GRADE_BANDS = [(85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F")]


# --------------------------------------------------------------------------- loading


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def classify(doc) -> str:
    if not isinstance(doc, dict):
        return "other"
    if doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if doc.get("version") == "2.1.0" and isinstance(doc.get("runs"), list):
        return "sarif"
    ctx = doc.get("@context")
    if ctx and "spdx" in json.dumps(ctx).lower():
        return "spdx"
    return "native"


def run_outputs(run_dir: Path) -> list[tuple[str, Path, object]]:
    found = []
    for path in sorted(run_dir.iterdir()):
        if path.suffix.lower() not in {".json", ".sarif"} or path.name in {
            "meta.json",
            "summary.json",
        }:
            continue
        doc = load_json(path)
        if doc is None:
            continue
        found.append((classify(doc), path, doc))
    return found


# --------------------------------------------------------------------------- records


class Record:
    """A component-like thing (component, service, native object) or a finding."""

    def __init__(
        self, kind: str, text: str, source: str, component: dict | None = None, name: str = ""
    ):
        self.kind = kind  # component | finding
        self.text = text.lower()
        # camelCase and punctuation split into words, so "isShaPinned=false" exposes "sha" and "pinned"
        self.words = re.sub(
            r"[^a-z0-9]+", " ", re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text).lower()
        )
        self.source = source
        self.component = component
        self.name = name.lower()


def flatten_text(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)


def cyclonedx_records(doc: dict, source: str) -> list[Record]:
    records: list[Record] = []

    def add_component(comp: dict, where: str):
        if not isinstance(comp, dict):
            return
        records.append(
            Record(
                "component",
                flatten_text(comp),
                f"{source}:{where}",
                comp,
                str(comp.get("name", "")),
            )
        )
        for prop in comp.get("properties", []) or []:
            if property_is_finding(str(prop.get("name", "")), str(prop.get("value", ""))):
                text = f"{comp.get('name', '')} {comp.get('purl', '')} {comp.get('bom-ref', '')} {prop.get('name', '')}={prop.get('value', '')}"
                records.append(
                    Record("finding", text, f"{source}:property", None, str(comp.get("name", "")))
                )
        for child in comp.get("components", []) or []:
            add_component(child, where + "/nested")

    for comp in doc.get("components", []) or []:
        add_component(comp, "components")
    meta_comp = (doc.get("metadata") or {}).get("component")
    if isinstance(meta_comp, dict):
        add_component(meta_comp, "metadata.component")
    for svc in doc.get("services", []) or []:
        records.append(
            Record(
                "component", flatten_text(svc), f"{source}:services", svc, str(svc.get("name", ""))
            )
        )
    for form in doc.get("formulation", []) or []:
        for comp in form.get("components", []) or []:
            add_component(comp, "formulation")
        for svc in form.get("services", []) or []:
            records.append(
                Record(
                    "component",
                    flatten_text(svc),
                    f"{source}:formulation.services",
                    svc,
                    str(svc.get("name", "")),
                )
            )
    refs = {c.get("bom-ref"): c for c in (doc.get("components") or []) if isinstance(c, dict)}
    for vuln in doc.get("vulnerabilities", []) or []:
        parts = [flatten_text({k: v for k, v in vuln.items() if k != "affects"})]
        for aff in vuln.get("affects", []) or []:
            ref = aff.get("ref")
            comp = refs.get(ref)
            parts.append(str(ref))
            if comp:
                parts.append(f"{comp.get('name', '')} {comp.get('purl', '')}")
        records.append(Record("finding", " ".join(parts), f"{source}:vulnerabilities"))
    for ann in doc.get("annotations", []) or []:
        records.append(Record("finding", flatten_text(ann), f"{source}:annotations"))
    return records


def sarif_records(doc: dict, source: str) -> list[Record]:
    records = []
    for run in doc.get("runs", []) or []:
        rules = {}
        driver = (run.get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules", []) or []:
            rules[rule.get("id")] = rule
        for result in run.get("results", []) or []:
            rule = rules.get(result.get("ruleId"), {})
            text = (
                flatten_text(result)
                + " "
                + flatten_text(
                    {
                        k: rule.get(k)
                        for k in ("id", "name", "shortDescription", "fullDescription", "help")
                        if k in rule
                    }
                )
            )
            records.append(Record("finding", text, f"{source}:results"))
    return records


def spdx_records(doc: dict, source: str) -> list[Record]:
    records = []
    for element in doc.get("@graph", []) or []:
        if not isinstance(element, dict):
            continue
        etype = str(element.get("type", ""))
        if etype.endswith(
            ("Package", "AIPackage", "DatasetPackage", "File", "Snippet")
        ) or etype.startswith(("ai_", "dataset_", "software_")):
            records.append(
                Record(
                    "component",
                    flatten_text(element),
                    f"{source}:graph",
                    element,
                    str(element.get("name", "")),
                )
            )
    return records


FINDING_KEYS = {
    "findings",
    "risk_flags",
    "riskflags",
    "risks",
    "issues",
    "alerts",
    "warnings",
    "flags",
    "violations",
    "vulnerabilities",
    "security_findings",
    "misconfigurations",
    "results",
}
# Keys whose string lists name discovered things (models, tools, images) rather than diagnostics.
INVENTORY_LIST_HINTS = (
    "model",
    "tool",
    "agent",
    "skill",
    "dataset",
    "image",
    "server",
    "asset",
    "unique",
    "endpoint",
    "framework",
    "provider",
    "source",
    "package",
    "component",
    "prompt",
    "instruction",
)
DIAGNOSTIC_KEY_HINTS = (
    "scanned",
    "excluded",
    "failure",
    "warning",
    "issue",
    "coverage",
    "error",
    "ignored",
    "skipped",
    "unresolved",
    "missing",
)


def native_records(doc, source: str) -> list[Record]:
    """Flatten a tool's native JSON into component and finding records.

    A dict is a finding when it sits under a findings-like key or carries severity plus a
    message. Any other dict with a ``name``, ``location``, ``path`` or ``file`` string is a
    component; so is each string in a list whose key names an inventory (models, tools,
    images) rather than a diagnostic (scanned, excluded, failures).
    """
    records: list[Record] = []

    def walk(node, parent_key: str = ""):
        pk = parent_key.lower()
        if isinstance(node, dict):
            keys = {k.lower() for k in node}
            if (
                pk in FINDING_KEYS
                or ({"severity", "message"} <= keys)
                or ({"severity", "description"} <= keys)
                or ({"rule_id"} <= keys)
                or ({"severity", "title"} <= keys)
            ):
                records.append(
                    Record("finding", flatten_text(node), f"{source}:{parent_key or 'root'}")
                )
            elif not any(h in pk for h in DIAGNOSTIC_KEY_HINTS):
                label = next(
                    (
                        node[k]
                        for k in (
                            "name",
                            "location",
                            "path",
                            "file",
                            "image",
                            "model",
                            "tool_name",
                            "id",
                        )
                        if isinstance(node.get(k), str) and node.get(k)
                    ),
                    None,
                )
                if label is not None:
                    shallow = {
                        k: v
                        for k, v in node.items()
                        if not isinstance(v, (list, dict))
                        or k.lower()
                        in {
                            "properties",
                            "metadata",
                            "evidence",
                            "hashes",
                            "licenses",
                            "model_refs",
                            "scopes",
                            "permissions",
                            "env",
                        }
                    }
                    records.append(
                        Record(
                            "component",
                            flatten_text(shallow),
                            f"{source}:{parent_key or 'root'}",
                            None,
                            str(label),
                        )
                    )
            for key, value in node.items():
                walk(value, key)
        elif isinstance(node, list):
            if (
                node
                and all(isinstance(v, str) for v in node)
                and any(h in pk for h in INVENTORY_LIST_HINTS)
                and not any(h in pk for h in DIAGNOSTIC_KEY_HINTS)
            ):
                for value in node:
                    records.append(
                        Record(
                            "component",
                            json.dumps({parent_key: value}),
                            f"{source}:{parent_key}",
                            None,
                            value,
                        )
                    )
            for value in node:
                walk(value, parent_key)

    walk(doc)
    return records


# --------------------------------------------------------------------------- matching


def match_items(items: list[dict], records: list[Record]) -> dict[str, list[str]]:
    """Return item id -> list of record names that matched. Each record satisfies one item."""
    matched: dict[str, list[str]] = defaultdict(list)
    for rec in records:
        if rec.kind != "component":
            continue
        candidates = []
        for it in items:
            best = 0
            for tok in it["tokens"]:
                t = tok.lower()
                if t in rec.text:
                    best = max(best, len(t))
            for nm in it.get("names", []):
                n = nm.lower()
                if (
                    rec.name == n
                    or f'"name": "{n}"' in rec.text
                    or f"pkg:pypi/{n}@" in rec.text
                    or f"pkg:npm/{n}@" in rec.text
                    or f'pkg:pypi/{n}"' in rec.text
                    or f'pkg:npm/{n}"' in rec.text
                    or f"pkg:npm/{n.replace('@', '%40')}@" in rec.text
                ):
                    best = max(best, 1000)
            if best:
                candidates.append((best, it["id"]))
        if not candidates:
            continue
        candidates.sort(reverse=True)
        chosen = None
        for _, item_id in candidates:
            if not matched.get(item_id):
                chosen = item_id
                break
        if chosen is None:
            chosen = candidates[0][1]
        matched[chosen].append(rec.name or rec.source)
    # second pass: shared tokens for still-unmatched items, using records that matched nothing
    used = {n for names in matched.values() for n in names}
    for it in items:
        if matched.get(it["id"]) or not it.get("shared_tokens"):
            continue
        hits = [
            rec
            for rec in records
            if rec.kind == "component"
            and (rec.name or rec.source) not in used
            and any(t.lower() in rec.text for t in it["shared_tokens"])
        ]
        if len(hits) >= 1:
            matched[it["id"]].append(hits[0].name or hits[0].source)
            used.add(hits[0].name or hits[0].source)
    return matched


def reason_matches(text: str, reason: str) -> bool:
    r = reason.lower()
    if not re.fullmatch(r"[a-z0-9 _-]+", r):
        return r in text
    return re.search(r"(?<![a-z0-9])" + re.escape(r) + r"(?![a-z0-9])", text) is not None


def match_risks(risks: list[dict], records: list[Record]) -> dict[str, list[str]]:
    """A finding surfaces a planted risk when it names the subject and, with the subject
    removed from the text, states the reason as a whole word. Findings that carry an
    advisory identifier (CVE, GHSA, PYSEC) are dependency vulnerabilities, not planted risks."""
    found: dict[str, list[str]] = defaultdict(list)
    for rec in records:
        if rec.kind != "finding" or VULN_ID_RE.search(rec.text):
            continue
        for risk in risks:
            subjects = [s.lower() for s in risk["subject_tokens"] if s.lower() in rec.text]
            if not subjects:
                continue
            stripped_text, stripped_words = rec.text, rec.words
            for s in subjects:
                stripped_text = stripped_text.replace(s, " ")
                stripped_words = stripped_words.replace(re.sub(r"[^a-z0-9]+", " ", s), " ")
            if any(
                reason_matches(stripped_text, r) or reason_matches(stripped_words, r)
                for r in risk["reason_tokens"]
            ):
                found[risk["id"]].append(rec.source)
    return found


def decoys_reported(decoys: list[dict], records: list[Record]) -> list[str]:
    hits = []
    for decoy in decoys:
        for rec in records:
            if rec.kind == "component" and any(t.lower() in rec.text for t in decoy["tokens"]):
                hits.append(decoy["id"])
                break
    return hits


# --------------------------------------------------------------------------- attributes


def component_attributes(comp: dict, local_hash: str | None) -> dict:
    props = comp.get("properties", []) or []
    prop_names = " ".join(str(p.get("name", "")).lower() for p in props)
    text = flatten_text(comp).lower()
    locator = False
    if (
        comp.get("evidence", {}).get("occurrences")
        if isinstance(comp.get("evidence"), dict)
        else False
    ):
        locator = True
    for p in props:
        name = str(p.get("name", "")).lower()
        value = str(p.get("value", ""))
        if any(h in name for h in LOCATOR_PROPERTY_HINTS) and (
            "/" in value or "." in value or value.isdigit()
        ):
            locator = True
    if "/" in str(comp.get("name", "")) and not str(comp.get("name", "")).startswith("@"):
        locator = True
    for ref in comp.get("externalReferences", []) or []:
        if str(ref.get("type", "")) in {
            "distribution",
            "vcs",
            "other",
            "documentation",
        } and "/" in str(ref.get("url", "")):
            locator = True
    hashes = comp.get("hashes", []) or []
    hash_present = bool(hashes)
    hash_correct = bool(
        local_hash and any(str(h.get("content", "")).lower() == local_hash for h in hashes)
    )
    version = str(comp.get("version", "") or "").strip().lower()
    version_present = version not in VERSION_PLACEHOLDERS
    license_present = bool(comp.get("licenses")) or (
        "license" in prop_names
        and any(
            str(p.get("value", "")).strip() not in {"", "unknown", "UNKNOWN"}
            for p in props
            if "license" in str(p.get("name", "")).lower()
        )
    )
    supplier_present = any(
        comp.get(k) for k in ("supplier", "manufacturer", "publisher", "authors", "author", "group")
    )
    confidence = any(h in prop_names for h in CONFIDENCE_HINTS) or '"confidence"' in text
    return {
        "locator": locator,
        "hash_present": hash_present,
        "hash_correct": hash_correct,
        "version": version_present,
        "license": license_present,
        "supplier": supplier_present,
        "confidence": confidence,
    }


# --------------------------------------------------------------------------- determinism


def normalize_string(s: str, run_dir: str) -> str:
    s = s.replace(run_dir, "<run>")
    s = UUID_RE.sub("<uuid>", s)
    s = TIMESTAMP_RE.sub("<timestamp>", s)
    s = EPOCH_RE.sub("<epoch>", s)
    s = NODE_PID_RE.sub("(node:<pid>)", s)
    return s


def normalize(obj, run_dir: str, drop_identifiers: bool = False):
    """Remove run-specific noise: timestamps, serial numbers, UUIDs, process ids, the run
    directory, and properties whose name says they hold a duration or a date. With
    ``drop_identifiers`` the reference keys go too, which isolates identifier churn."""
    if isinstance(obj, dict):
        out = {}
        if (
            isinstance(obj.get("name"), str)
            and "value" in obj
            and len(obj) <= 2
            and any(h in obj["name"].lower() for h in VOLATILE_PROPERTY_HINTS)
        ):
            return None
        for k, v in obj.items():
            kl = k.lower()
            if kl in VOLATILE_KEYS or (drop_identifiers and kl in IDENTIFIER_KEYS):
                continue
            out[k] = normalize(v, run_dir, drop_identifiers)
        return out
    if isinstance(obj, list):
        items = [normalize(v, run_dir, drop_identifiers) for v in obj]
        items = [v for v in items if v is not None]
        try:
            return sorted(items, key=lambda x: json.dumps(x, sort_keys=True))
        except TypeError:
            return items
    if isinstance(obj, str):
        stripped = obj.strip()
        if stripped[:1] in "{[" and len(stripped) > 2:
            try:
                return normalize(json.loads(stripped), run_dir, drop_identifiers)
            except (ValueError, RecursionError):
                pass
        return normalize_string(obj, run_dir)
    return obj


def determinism(raw: Path) -> dict:
    a_dir, b_dir = raw / DEFAULT_RUNS[0], raw / DEFAULT_RUNS[1]
    if not a_dir.exists() or not b_dir.exists():
        return {"status": "not-run"}
    pairs = []
    for path in sorted(a_dir.iterdir()):
        if (
            path.suffix.lower() in {".json", ".sarif"}
            and path.name not in {"meta.json", "summary.json"}
            and (b_dir / path.name).exists()
        ):
            pairs.append((path, b_dir / path.name))
    if not pairs:
        return {"status": "no-output"}
    statuses = []
    details = {}
    for a, b in pairs:
        da, db = load_json(a), load_json(b)
        if da is None or db is None:
            statuses.append("unreadable")
            continue
        raw_equal = a.read_bytes() == b.read_bytes()
        na, nb = normalize(da, str(a_dir)), normalize(db, str(b_dir))
        if na == nb:
            statuses.append("identical-raw" if raw_equal else "identical-normalized")
            continue
        ia, ib = normalize(da, str(a_dir), True), normalize(db, str(b_dir), True)
        if ia == ib:
            statuses.append("identifier-only")
            details[a.name] = "only reference identifiers change between runs"
            continue
        statuses.append("differs")
        diff_keys = sorted(
            k
            for k in set(na) | set(nb)
            if isinstance(na, dict) and isinstance(nb, dict) and na.get(k) != nb.get(k)
        )
        details[a.name] = diff_keys[:10]
    serial_a = (load_json(pairs[0][0]) or {}).get("serialNumber")
    serial_b = (load_json(pairs[0][1]) or {}).get("serialNumber")
    if "differs" in statuses:
        status = "differs"
    elif "identifier-only" in statuses:
        status = "identifier-only"
    elif all(s == "identical-raw" for s in statuses):
        status = "identical-raw"
    else:
        status = "identical-normalized"
    return {
        "status": status,
        "per_file": dict(zip([p[0].name for p in pairs], statuses, strict=False)),
        "diff_keys": details,
        "serial_stable": bool(serial_a) and serial_a == serial_b,
    }


# --------------------------------------------------------------------------- validation


def validate_cyclonedx(doc: dict, text: str) -> tuple[str, str]:
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except Exception as exc:
        return "unavailable", f"validator import failed: {exc}"
    spec = str(doc.get("specVersion", ""))
    name = "V" + spec.replace(".", "_")
    try:
        version = SchemaVersion[name]
    except KeyError:
        return "unsupported", f"spec {spec} not supported by validator"
    try:
        error = JsonStrictValidator(version).validate_str(text)
    except Exception as exc:
        return "error", str(exc)[:300]
    return ("valid", "") if error is None else ("invalid", str(error)[:400])


def validate_sarif(doc: dict, schema_path: Path | None) -> tuple[str, str]:
    if not schema_path or not schema_path.exists():
        return "unavailable", "no schema"
    try:
        import jsonschema

        jsonschema.validate(doc, json.loads(schema_path.read_text()))
        return "valid", ""
    except jsonschema.ValidationError as exc:
        return "invalid", f"{list(exc.absolute_path)[:6]}: {exc.message[:300]}"
    except Exception as exc:
        return "error", str(exc)[:300]


def check_spdx(doc: dict) -> dict:
    ctx = json.dumps(doc.get("@context"))
    graph = doc.get("@graph") if isinstance(doc.get("@graph"), list) else []
    types = defaultdict(int)
    for el in graph:
        if isinstance(el, dict):
            types[str(el.get("type"))] += 1
    ai = sum(v for k, v in types.items() if k.startswith("ai_") or "AIPackage" in k)
    ds = sum(v for k, v in types.items() if k.startswith("dataset_") or "DatasetPackage" in k)
    return {
        "well_formed": "3.0.1" in ctx and bool(graph),
        "context": ctx[:80],
        "elements": len(graph),
        "ai_profile_elements": ai,
        "dataset_profile_elements": ds,
    }


def g7_clusters(doc: dict) -> list[str]:
    meta = doc.get("metadata") or {}
    comps = doc.get("components") or []
    text = flatten_text(doc).lower()
    present = []
    if meta.get("tools") or meta.get("authors") or meta.get("timestamp") or doc.get("serialNumber"):
        present.append("metadata")
    if isinstance(meta.get("component"), dict) and meta["component"].get("name"):
        present.append("system")
    ml = [c for c in comps if c.get("type") == "machine-learning-model"]
    if ml:
        present.append("models")
    if (
        any(c.get("type") == "data" for c in comps)
        or any(
            c.get("modelCard", {}).get("modelParameters", {}).get("datasets")
            for c in ml
            if isinstance(c.get("modelCard"), dict)
        )
        or '"datasets"' in text
    ):
        present.append("datasets")
    if (
        any(c.get("type") in {"container", "platform", "device", "operating-system"} for c in comps)
        or doc.get("services")
        or any(f.get("components") for f in doc.get("formulation", []) or [])
    ):
        present.append("infrastructure")
    if (
        any(c.get("hashes") for c in comps)
        or doc.get("vulnerabilities")
        or doc.get("signature")
        or "sha-256" in text
    ):
        present.append("security")
    if any(
        isinstance(c.get("modelCard"), dict) and c["modelCard"].get("quantitativeAnalysis")
        for c in ml
    ):
        present.append("kpi")
    return present


def ml_structures(doc: dict) -> int:
    comps = doc.get("components") or []
    points = 0
    if any(c.get("type") == "machine-learning-model" for c in comps):
        points += 1
    if any(isinstance(c.get("modelCard"), dict) for c in comps) or any(
        c.get("type") == "data" and (c.get("data") or c.get("properties")) for c in comps
    ):
        points += 1
    if (
        doc.get("services")
        or doc.get("formulation")
        or any(isinstance(c.get("evidence"), dict) for c in comps)
    ):
        points += 1
    return min(points, 3)


# --------------------------------------------------------------------------- scoring


def cap(points: float, label: str, maximum: float) -> float:
    if label == "U":
        return 0.0
    if label == "D":
        return min(points, round(maximum * 0.6, 2))
    return min(points, maximum)


class Scorer:
    def __init__(
        self,
        truth: dict,
        raw_root: Path,
        rubric_dir: Path,
        fixture: Path | None,
        sarif_schema: Path | None,
    ):
        self.truth = truth
        self.raw_root = raw_root
        self.rubric_dir = rubric_dir
        self.fixture = fixture
        self.sarif_schema = sarif_schema
        self.local_hashes = {}
        if fixture:
            for it in truth["items"]:
                if it.get("local_file"):
                    p = fixture / it["path"]
                    if p.is_file():
                        self.local_hashes[it["id"]] = hashlib.sha256(p.read_bytes()).hexdigest()

    def rubric(self, tool: str) -> dict:
        path = self.rubric_dir / f"{tool}.yaml"
        return yaml.safe_load(path.read_text()) if path.exists() else {"tool": tool}

    def manual(self, rub: dict, key: str, maximum: float) -> tuple[float, str, str]:
        entry = (rub.get("manual") or {}).get(key)
        if not entry:
            return 0.0, "U", "no rubric entry"
        label = entry.get("label", "D")
        return cap(float(entry.get("points", 0)), label, maximum), label, entry.get("note", "")

    def score_tool(self, tool: str) -> dict:
        rub = self.rubric(tool)
        raw = self.raw_root / tool
        result = {
            "tool": tool,
            "display": rub.get("display", tool),
            "runnable": raw.exists() and rub.get("runnable", True),
            "criteria": {},
            "dimensions": {},
            "notes": rub.get("notes", ""),
            "not_run_reason": rub.get("not_run_reason", ""),
        }
        crit = result["criteria"]

        def put(key, points, maximum, label, note=""):
            crit[key] = {
                "points": round(min(points, maximum), 2),
                "max": maximum,
                "label": label,
                "note": note,
            }

        records: list[Record] = []
        cyclonedx_docs: list[tuple[Path, dict, str]] = []
        sarif_docs: list[tuple[Path, dict]] = []
        spdx_docs: list[tuple[Path, dict]] = []
        all_output_text = ""
        metas = {}
        if result["runnable"]:
            for run_dir in sorted(raw.iterdir()):
                if not run_dir.is_dir():
                    continue
                meta = load_json(run_dir / "meta.json")
                if meta:
                    metas[run_dir.name] = meta
                for kind, path, doc in run_outputs(run_dir):
                    text = path.read_text(encoding="utf-8", errors="replace")
                    all_output_text += "\n" + text
                    if run_dir.name not in DISCOVERY_RUNS:
                        continue
                    if kind == "cyclonedx":
                        cyclonedx_docs.append((path, doc, text))
                        records += cyclonedx_records(doc, f"{run_dir.name}/{path.name}")
                    elif kind == "sarif":
                        sarif_docs.append((path, doc))
                        records += sarif_records(doc, f"{run_dir.name}/{path.name}")
                    elif kind == "spdx":
                        spdx_docs.append((path, doc))
                        records += spdx_records(doc, f"{run_dir.name}/{path.name}")
                    else:
                        records += native_records(doc, f"{run_dir.name}/{path.name}")
                # stdout can carry findings for console-first tools
                stdout = run_dir / "stdout.txt"
                if stdout.exists():
                    all_output_text += "\n" + stdout.read_text(encoding="utf-8", errors="replace")

        items = self.truth["items"]
        matched = match_items(items, records) if records else {}
        result["matched_items"] = {k: v[:5] for k, v in matched.items()}
        result["missed_items"] = [it["id"] for it in items if not matched.get(it["id"])]
        set(rub.get("claimed_families") or FAMILY_POINTS)

        # ---- D1
        decoy_hits = decoys_reported(self.truth["decoys"], records) if records else []
        result["decoys_reported"] = decoy_hits
        family_recall = {}
        for family, pts in FAMILY_POINTS.items():
            fam_items = [it for it in items if it["family"] == family]
            hit = sum(1 for it in fam_items if matched.get(it["id"]))
            recall = hit / len(fam_items) if fam_items else 0
            family_recall[family] = {
                "found": hit,
                "total": len(fam_items),
                "recall": round(recall, 3),
            }
            if result["runnable"]:
                put(f"D1.{family}", recall * pts, pts, "M", f"{hit}/{len(fam_items)} items")
            else:
                p, lab, note = self.manual(rub, f"D1.{family}", pts)
                put(f"D1.{family}", p, pts, lab, note)
        result["family_recall"] = family_recall
        penalty = min(3, len(decoy_hits)) if result["runnable"] else 0
        crit["D1.decoy_penalty"] = {
            "points": -penalty,
            "max": 0,
            "label": "M" if result["runnable"] else "U",
            "note": ", ".join(decoy_hits) or "none reported",
        }

        # ---- D2
        attr_rows = []
        for it in items:
            if not matched.get(it["id"]):
                continue
            best = None
            for rec in records:
                if (
                    rec.kind == "component"
                    and rec.component is not None
                    and (rec.name or rec.source) in matched[it["id"]]
                ):
                    attrs = component_attributes(rec.component, self.local_hashes.get(it["id"]))
                    attrs["item"] = it["id"]
                    attrs["local"] = bool(it.get("local_file"))
                    if best is None or sum(
                        1
                        for k in ("locator", "hash_present", "version", "license", "supplier")
                        if attrs[k]
                    ) > sum(
                        1
                        for k in ("locator", "hash_present", "version", "license", "supplier")
                        if best[k]
                    ):
                        best = attrs
            if best:
                attr_rows.append(best)
        result["attribute_rows"] = len(attr_rows)
        if result["runnable"] and attr_rows:
            n = len(attr_rows)
            frac = lambda key, rows: (sum(1 for r in rows if r[key]) / len(rows)) if rows else 0.0  # noqa: E731
            local_rows = [r for r in attr_rows if r["local"]]
            put(
                "D2.locator",
                frac("locator", attr_rows) * 4,
                4,
                "M",
                f"{sum(1 for r in attr_rows if r['locator'])}/{n} matched components carry a locator",
            )
            put(
                "D2.hash",
                frac("hash_present", local_rows) * 3,
                3,
                "M",
                f"{sum(1 for r in local_rows if r['hash_present'])}/{len(local_rows)} local artifacts hashed; {sum(1 for r in local_rows if r['hash_correct'])} match the file's SHA-256",
            )
            put(
                "D2.version",
                frac("version", attr_rows) * 3,
                3,
                "M",
                f"{sum(1 for r in attr_rows if r['version'])}/{n} carry a version or revision",
            )
            put(
                "D2.license",
                frac("license", attr_rows) * 2,
                2,
                "M",
                f"{sum(1 for r in attr_rows if r['license'])}/{n} carry a license",
            )
            put(
                "D2.supplier",
                frac("supplier", attr_rows) * 1,
                1,
                "M",
                f"{sum(1 for r in attr_rows if r['supplier'])}/{n} carry a supplier, author, publisher or group",
            )
            conf = frac("confidence", attr_rows)
            put(
                "D2.confidence",
                2 if conf >= 0.5 else (1 if conf > 0 else 0),
                2,
                "M",
                f"confidence or tier labels on {round(conf * 100)}% of matched components",
            )
        else:
            for key, mx in [
                ("D2.locator", 4),
                ("D2.hash", 3),
                ("D2.version", 3),
                ("D2.license", 2),
                ("D2.supplier", 1),
                ("D2.confidence", 2),
            ]:
                p, lab, note = self.manual(rub, key, mx)
                put(key, p, mx, lab, note)

        # ---- D3
        risks = self.truth["risks"]
        if result["runnable"]:
            found = match_risks(risks, records)
            # also accept findings printed to stdout of the default run
            stdout_text = ""
            for run in ("default-1", "sarif", "json", "native"):
                p = raw / run / "stdout.txt"
                if p.exists():
                    stdout_text += p.read_text(encoding="utf-8", errors="replace").lower()
            for risk in risks:
                if (
                    risk["id"] not in found
                    and any(s.lower() in stdout_text for s in risk["subject_tokens"])
                    and any(r.lower() in stdout_text for r in risk["reason_tokens"])
                ):
                    # subject and reason must co-occur within a short window on the console
                    for s in risk["subject_tokens"]:
                        idx = stdout_text.find(s.lower())
                        if idx >= 0 and any(
                            r.lower() in stdout_text[max(0, idx - 400) : idx + 400]
                            for r in risk["reason_tokens"]
                        ):
                            found[risk["id"]].append("stdout")
                            break
            result["risks_found"] = {k: sorted(set(v))[:4] for k, v in found.items()}
            result["risks_missed"] = [r["id"] for r in risks if not found.get(r["id"])]
            recall = len(found) / len(risks)
            put(
                "D3.recall",
                recall * 10,
                10,
                "M",
                f"{len(found)}/{len(risks)} planted risks surfaced",
            )
        else:
            p, lab, note = self.manual(rub, "D3.recall", 10)
            put("D3.recall", p, 10, lab, note)
        p, lab, note = self.manual(rub, "D3.quality", 2)
        put("D3.quality", p, 2, lab, note)

        # ---- D4
        if result["runnable"]:
            if cyclonedx_docs:
                statuses = [validate_cyclonedx(doc, text) for _, doc, text in cyclonedx_docs]
                result["cyclonedx_validation"] = {
                    str(p.relative_to(raw)): s
                    for (p, _, _), s in zip(cyclonedx_docs, statuses, strict=False)
                }
                if all(s[0] == "valid" for s in statuses):
                    put(
                        "D4.cyclonedx",
                        3,
                        3,
                        "M",
                        f"{len(statuses)} document(s) valid against spec {cyclonedx_docs[0][1].get('specVersion')}",
                    )
                elif any(s[0] == "valid" for s in statuses):
                    put(
                        "D4.cyclonedx",
                        2,
                        3,
                        "M",
                        "some CycloneDX documents fail strict validation: "
                        + "; ".join(
                            f"{p.name}: {s[1][:120]}"
                            for (p, _, _), s in zip(cyclonedx_docs, statuses, strict=False)
                            if s[0] != "valid"
                        ),
                    )
                elif any(s[0] in {"unsupported", "unavailable"} for s in statuses):
                    put("D4.cyclonedx", 2, 3, "U", statuses[0][1])
                else:
                    put("D4.cyclonedx", 1, 3, "M", "emitted but invalid: " + statuses[0][1][:200])
            else:
                put("D4.cyclonedx", 0, 3, "M", "no CycloneDX output")
            if spdx_docs:
                checks = [check_spdx(doc) for _, doc in spdx_docs]
                result["spdx_checks"] = checks
                put(
                    "D4.spdx",
                    2 if all(c["well_formed"] for c in checks) else 1,
                    2,
                    "M",
                    f"SPDX 3.0.1 JSON-LD: {checks[0]['elements']} elements, {checks[0]['ai_profile_elements']} AI-profile, {checks[0]['dataset_profile_elements']} dataset-profile",
                )
            else:
                put("D4.spdx", 0, 2, "M", "no SPDX output")
            if sarif_docs:
                statuses = [validate_sarif(doc, self.sarif_schema) for _, doc in sarif_docs]
                result["sarif_validation"] = statuses
                put(
                    "D4.sarif",
                    2 if all(s[0] == "valid" for s in statuses) else 1,
                    2,
                    "M",
                    "; ".join(f"{s[0]} {s[1][:120]}".strip() for s in statuses),
                )
            else:
                put("D4.sarif", 0, 2, "M", "no SARIF output")
            if cyclonedx_docs:
                best_doc = max((d for _, d, _ in cyclonedx_docs), key=lambda d: ml_structures(d))
                put(
                    "D4.ml_structures",
                    ml_structures(best_doc),
                    3,
                    "M",
                    "typed ML components, modelCard/data, services/formulation/evidence",
                )
                clusters = sorted(
                    {c for _, d, _ in cyclonedx_docs for c in g7_clusters(d)}, key=G7_CLUSTERS.index
                )
                result["g7_clusters"] = clusters
                put(
                    "D4.g7",
                    len(clusters) / 7 * 2,
                    2,
                    "M",
                    f"{len(clusters)}/7 clusters: {', '.join(clusters)}",
                )
            else:
                put("D4.ml_structures", 0, 3, "M", "no CycloneDX output")
                put("D4.g7", 0, 2, "M", "no CycloneDX output")
        else:
            for key, mx in [
                ("D4.cyclonedx", 3),
                ("D4.spdx", 2),
                ("D4.sarif", 2),
                ("D4.ml_structures", 3),
                ("D4.g7", 2),
            ]:
                p, lab, note = self.manual(rub, key, mx)
                put(key, p, mx, lab, note)

        # ---- D5
        if result["runnable"]:
            det = determinism(raw)
            result["determinism"] = det
            if det["status"].startswith("identical"):
                put("D5.determinism", 4, 4, "M", f"two default runs {det['status']}")
            elif det["status"] == "identifier-only":
                put(
                    "D5.determinism",
                    2,
                    4,
                    "M",
                    "content identical, but reference identifiers (bom-ref, ids) change between runs",
                )
            elif det["status"] == "differs":
                put(
                    "D5.determinism",
                    0,
                    4,
                    "M",
                    "outputs differ after normalization: " + json.dumps(det.get("diff_keys"))[:200],
                )
            else:
                put("D5.determinism", 0, 4, "U", det["status"])
            put(
                "D5.serial",
                1 if det.get("serial_stable") else 0,
                1,
                "M",
                "serial number identical across runs"
                if det.get("serial_stable")
                else "serial number or digest changes per run",
            )
        else:
            for key, mx in [("D5.determinism", 4), ("D5.serial", 1)]:
                p, lab, note = self.manual(rub, key, mx)
                put(key, p, mx, lab, note)
        for key, mx in [("D5.signing", 3), ("D5.diff", 2)]:
            p, lab, note = self.manual(rub, key, mx)
            put(key, p, mx, lab, note)

        # ---- D6
        if result["runnable"]:
            default_canaries = sorted(
                {c for r in DEFAULT_RUNS for c in (metas.get(r, {}).get("canaries_fired") or [])}
            )
            safe_canaries = sorted(
                {c for r in SAFE_RUNS for c in (metas.get(r, {}).get("canaries_fired") or [])}
            )
            any_canaries = sorted(
                {c for m in metas.values() for c in (m.get("canaries_fired") or [])}
            )
            result["canaries"] = {
                "default": default_canaries,
                "safe": safe_canaries,
                "any_run": any_canaries,
            }
            if not any_canaries:
                put("D6.no_exec", 3, 3, "M", "no canary fired in any run")
            elif not safe_canaries and any(r in metas for r in SAFE_RUNS):
                put(
                    "D6.no_exec",
                    1,
                    3,
                    "M",
                    f"canary fired in default mode ({', '.join(default_canaries)}), not in safe mode",
                )
            else:
                put("D6.no_exec", 0, 3, "M", f"canary fired: {', '.join(any_canaries)}")
            outside = self.truth["sentinels"]["outside"].lower() in all_output_text.lower()
            put(
                "D6.confinement",
                0 if outside else 2,
                2,
                "M",
                "outside-sentinel appears in output"
                if outside
                else "outside-sentinel absent from every output",
            )
            token = self.truth["sentinels"]["token"] in all_output_text
            put(
                "D6.redaction",
                0 if token else 2,
                2,
                "M",
                "credential sentinel copied into output"
                if token
                else "credential sentinel absent from every output",
            )
            fixture_mods = {
                r: m.get("fixture_changes")
                for r, m in metas.items()
                if any(
                    m.get("fixture_changes", {}).get(k) for k in ("added", "removed", "modified")
                )
            }
            result["fixture_modifications"] = fixture_mods
            egress = {r: m.get("egress", {}) for r, m in metas.items()}
            result["egress"] = {
                r: {
                    "connect": e.get("connect_targets", []),
                    "http": e.get("http_targets", []),
                    "nonloopback": e.get("nonloopback_connects", []),
                    "dns": e.get("dns_attempts", 0),
                }
                for r, e in egress.items()
            }
            default_quiet = all(
                not egress.get(r, {}).get("connect_targets")
                and not egress.get(r, {}).get("http_targets")
                and not egress.get(r, {}).get("nonloopback_connects")
                for r in DEFAULT_RUNS
                if r in egress
            )
            result["default_mode_quiet"] = default_quiet
            default_hosts = {
                t.split(":")[0]
                for r in DEFAULT_RUNS
                for t in egress.get(r, {}).get("connect_targets", [])
                + egress.get(r, {}).get("http_targets", [])
            }
            telemetry = sorted(h for h in default_hosts if h in TELEMETRY_HOSTS)
            result["default_telemetry_hosts"] = telemetry
            offline_runs = [r for r in SAFE_RUNS if r in metas]
            if offline_runs:
                quiet = all(
                    not egress[r].get("connect_targets")
                    and not egress[r].get("http_targets")
                    and not egress[r].get("nonloopback_connects")
                    for r in offline_runs
                )
                if quiet and telemetry:
                    put(
                        "D6.offline",
                        1,
                        2,
                        "M",
                        f"offline mode is quiet, but the default mode phones home to {', '.join(telemetry)}",
                    )
                else:
                    put(
                        "D6.offline",
                        2 if quiet else 1,
                        2,
                        "M",
                        ("no network attempt in " if quiet else "network attempted in ")
                        + ", ".join(offline_runs),
                    )
            elif default_quiet:
                put(
                    "D6.offline",
                    2,
                    2,
                    "M",
                    "no offline flag, but the default run made no network attempt",
                )
            else:
                p, lab, note = self.manual(rub, "D6.offline", 2)
                put("D6.offline", p, 2, lab, note or "no offline mode exercised")
        else:
            for key, mx in [
                ("D6.no_exec", 3),
                ("D6.confinement", 2),
                ("D6.redaction", 2),
                ("D6.offline", 2),
            ]:
                p, lab, note = self.manual(rub, key, mx)
                put(key, p, mx, lab, note)
        for key, mx in [("D6.pinning", 2), ("D6.security_policy", 1)]:
            p, lab, note = self.manual(rub, key, mx)
            put(key, p, mx, lab, note)

        # ---- D7
        runtime_dir = raw / "trace-diff"
        if result["runnable"] and runtime_dir.exists():
            text = ""
            for p in runtime_dir.iterdir():
                if p.is_file():
                    text += p.read_text(encoding="utf-8", errors="replace").lower()
            undeclared = [
                u["name"] for u in self.truth["runtime"]["undeclared"] if u["name"].lower() in text
            ]
            result["runtime_undeclared_found"] = undeclared
            # precision: a declared item reported as undeclared is a false alarm
            undeclared_section = ""
            for p in runtime_dir.iterdir():
                doc = load_json(p) if p.suffix in {".json", ".txt"} else None
                if isinstance(doc, dict):
                    undeclared_section += json.dumps(
                        [v for k, v in walk_key(doc, "undeclared")]
                    ).lower()
            false_alarms = [
                d["name"]
                for d in self.truth["runtime"]["declared"]
                if d["name"].lower() in undeclared_section
            ]
            result["runtime_false_alarms"] = false_alarms
            points = {2: 3, 1: 2, 0: 0}[len(undeclared)]
            if points == 3 and false_alarms:
                points = 2
            put(
                "D7.ingest",
                points,
                3,
                "M",
                f"undeclared items surfaced: {', '.join(undeclared) or 'none'}; declared items reported as undeclared: {', '.join(false_alarms) or 'none'}",
            )
        else:
            p, lab, note = self.manual(rub, "D7.ingest", 3)
            put("D7.ingest", p, 3, lab, note)
        p, lab, note = self.manual(rub, "D7.capability", 2)
        put("D7.capability", p, 2, lab, note)

        # ---- D8
        default_meta = metas.get("default-1", {})
        if (
            result["runnable"]
            and default_meta.get("exit_code") not in (0, None)
            and default_meta.get("outputs")
        ):
            put(
                "D8.gate",
                1,
                1,
                "M",
                f"default run exited {default_meta['exit_code']} with findings while still writing the BOM",
            )
        else:
            p, lab, note = self.manual(rub, "D8.gate", 1)
            put("D8.gate", p, 1, lab, note)
        if result["runnable"] and sarif_docs:
            put("D8.ci", 1, 1, "M", "SARIF produced for code-scanning upload")
        else:
            p, lab, note = self.manual(rub, "D8.ci", 1)
            put("D8.ci", p, 1, lab, note)
        if result["runnable"] and "default-1" in metas:
            dur = metas["default-1"].get("duration_seconds", 0)
            result["default_duration_seconds"] = dur
            put(
                "D8.speed",
                1 if dur < 120 and not metas["default-1"].get("timed_out") else 0,
                1,
                "M",
                f"default run {dur}s",
            )
        else:
            p, lab, note = self.manual(rub, "D8.speed", 1)
            put("D8.speed", p, 1, lab, note)
        p, lab, note = self.manual(rub, "D8.docs", 1)
        put("D8.docs", p, 1, lab, note)

        # ---- totals
        claimed_dims = set(rub.get("claimed_dimensions") or DIMENSIONS)
        total = 0.0
        in_scope_earned = 0.0
        in_scope_max = 0.0
        for dim, (title, maximum) in DIMENSIONS.items():
            earned = sum(c["points"] for k, c in crit.items() if k.startswith(dim + "."))
            earned = max(0.0, min(earned, maximum))
            result["dimensions"][dim] = {"title": title, "points": round(earned, 2), "max": maximum}
            total += earned
            if dim in claimed_dims:
                in_scope_max += sum(
                    c["max"]
                    for k, c in crit.items()
                    if k.startswith(dim + ".") and c["label"] != "U"
                )
                in_scope_earned += earned
        result["total"] = round(total, 1)
        result["grade"] = next(g for floor, g in GRADE_BANDS if total >= floor)
        result["in_scope_score"] = (
            round(100 * in_scope_earned / in_scope_max, 1) if in_scope_max else None
        )
        result["evidence_mix"] = {
            lab: sum(1 for c in crit.values() if c["label"] == lab) for lab in ("M", "D", "U")
        }
        return result


def walk_key(node, key: str, path: str = ""):
    """Yield (path, value) for every dict entry named ``key`` anywhere in ``node``."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k.lower() == key:
                yield path + "/" + k, v
            yield from walk_key(v, key, path + "/" + k)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk_key(v, key, f"{path}[{i}]")


def sensitivity(results: list[dict]) -> list[str]:
    """Rank the tools again under weightings a critic would propose."""
    lines = [
        "",
        "## Sensitivity of the ranking to the weights",
        "",
        "The chosen weights encode a view of what a BOM is for. These alternatives check whether the order depends on that view.",
        "",
        "| Tool | As weighted | Equal dimensions | Discovery 50% | Equal family weights in D1 | Measured criteria only |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    rows = []
    for r in results:
        dims = r["dimensions"]
        equal = sum(100 / len(DIMENSIONS) * d["points"] / d["max"] for d in dims.values())
        rest = sum(d["points"] for k, d in dims.items() if k != "D1")
        rest_max = sum(d["max"] for k, d in dims.items() if k != "D1")
        discovery_heavy = 50 * dims["D1"]["points"] / dims["D1"]["max"] + 50 * rest / rest_max
        fr = r.get("family_recall") or {}
        if fr and r["runnable"]:
            d1_equal = (
                30 * sum(v["recall"] for v in fr.values()) / len(fr)
                + r["criteria"]["D1.decoy_penalty"]["points"]
            )
        else:
            d1_equal = dims["D1"]["points"]
        equal_family = r["total"] - dims["D1"]["points"] + max(0.0, d1_equal)
        m_pts = sum(
            c["points"] for c in r["criteria"].values() if c["label"] == "M" and c["max"] > 0
        )
        m_max = sum(c["max"] for c in r["criteria"].values() if c["label"] == "M" and c["max"] > 0)
        m_count = sum(1 for c in r["criteria"].values() if c["label"] == "M" and c["max"] > 0)
        measured = f"{100 * m_pts / m_max:.1f}" if m_max and m_count >= 10 else "n/a"
        rows.append((r["display"], r["total"], equal, discovery_heavy, equal_family, measured))
    for row in sorted(rows, key=lambda x: -x[1]):
        lines.append(
            f"| {row[0]} | {row[1]:.1f} | {row[2]:.1f} | {row[3]:.1f} | {row[4]:.1f} | {row[5]} |"
        )
    lines.append("")
    lines.append(
        "Measured-only divides points earned on M-labelled criteria by their maximum, so a tool graded mostly from documentation is shown only for tools with at least ten measured criteria."
    )
    return lines


# --------------------------------------------------------------------------- report


def render_markdown(results: list[dict], truth: dict) -> str:
    results = sorted(results, key=lambda r: -r["total"])
    lines = [
        "# AAB v1.0 results",
        "",
        f"Fixture `{truth['fixture']}`: {len(truth['items'])} labelled items, {len(truth['risks'])} planted risks, {len(truth['decoys'])} decoys. Evidence labels: M measured, D documentation (capped at 60 percent), U unverified (0).",
        "",
    ]
    lines.append(
        "| Rank | Tool | Full-stack | Grade | In-scope | "
        + " | ".join(f"{d} /{m}" for d, (_, m) in DIMENSIONS.items())
        + " | Evidence M/D/U |"
    )
    lines.append("|" + " --- |" * (6 + len(DIMENSIONS)))
    for i, r in enumerate(results, 1):
        dims = " | ".join(f"{r['dimensions'][d]['points']:g}" for d in DIMENSIONS)
        mix = r["evidence_mix"]
        lines.append(
            f"| {i} | {r['display']} | **{r['total']}** | {r['grade']} | {r['in_scope_score'] if r['in_scope_score'] is not None else 'n/a'} | {dims} | {mix['M']}/{mix['D']}/{mix['U']} |"
        )
    lines += [
        "",
        "## Discovery recall by family",
        "",
        "| Tool | " + " | ".join(FAMILY_POINTS) + " | Decoys reported |",
        "|" + " --- |" * (len(FAMILY_POINTS) + 2),
    ]
    for r in results:
        fr = r.get("family_recall", {})
        cells = " | ".join(
            f"{fr[f]['found']}/{fr[f]['total']}" if f in fr and r["runnable"] else "n/a"
            for f in FAMILY_POINTS
        )
        lines.append(
            f"| {r['display']} | {cells} | {', '.join(r.get('decoys_reported', [])) or '-'} |"
        )
    lines += [
        "",
        "## Planted risks surfaced",
        "",
        "| Tool | Found | Missed |",
        "| --- | --- | --- |",
    ]
    for r in results:
        if r["runnable"]:
            lines.append(
                f"| {r['display']} | {', '.join(sorted(r.get('risks_found', {}), key=lambda k: int(k[1:])))} | {', '.join(r.get('risks_missed', []))} |"
            )
        else:
            lines.append(f"| {r['display']} | not run | not run |")
    lines += [
        "",
        "## Scanner safety probes",
        "",
        "| Tool | Canary (code executed) | Outside sentinel | Credential sentinel | Default-mode egress | Offline-mode egress | Determinism |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in results:
        if not r["runnable"]:
            lines.append(
                f"| {r['display']} | not run | not run | not run | not run | not run | not run |"
            )
            continue
        c = r["criteria"]
        eg = r.get("egress", {})
        default_eg = sorted(
            {
                t
                for run in DEFAULT_RUNS
                for t in eg.get(run, {}).get("connect", [])
                + eg.get(run, {}).get("http", [])
                + eg.get(run, {}).get("nonloopback", [])
            }
        )
        safe_eg = sorted(
            {
                t
                for run in SAFE_RUNS
                for t in eg.get(run, {}).get("connect", [])
                + eg.get(run, {}).get("http", [])
                + eg.get(run, {}).get("nonloopback", [])
            }
        )
        has_safe = any(run in eg for run in SAFE_RUNS)
        lines.append(
            f"| {r['display']} | {', '.join(r['canaries']['any_run']) or 'none'} | {'leaked' if c['D6.confinement']['points'] == 0 else 'confined'} | {'copied' if c['D6.redaction']['points'] == 0 else 'absent'} | {', '.join(default_eg) or 'none observed'} | {(', '.join(safe_eg) or 'none observed') if has_safe else 'no offline mode run'} | {r.get('determinism', {}).get('status', 'n/a')} |"
        )
    lines += sensitivity(results)
    lines += ["", "## Per-tool criteria", ""]
    for r in results:
        lines.append(f"### {r['display']}: {r['total']} ({r['grade']})")
        lines.append("")
        if r.get("not_run_reason"):
            lines.append(f"Not run: {r['not_run_reason']}")
            lines.append("")
        if r.get("notes"):
            lines.append(r["notes"])
            lines.append("")
        lines.append("| Criterion | Points | Max | Label | Evidence |")
        lines.append("| --- | ---: | ---: | --- | --- |")
        for key, c in r["criteria"].items():
            lines.append(
                f"| {key} | {c['points']:g} | {c['max']:g} | {c['label']} | {c['note'].replace('|', '/')} |"
            )
        if r["runnable"]:
            lines.append("")
            lines.append(
                f"Missed items: {', '.join(r['missed_items']) or 'none'}. Default run: {r.get('default_duration_seconds', '?')}s. CycloneDX validation: {json.dumps(r.get('cyclonedx_validation', {}))[:300]}"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--ground-truth", required=True, type=Path)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--rubric", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--fixture", type=Path, help="fixture root, for hash correctness checks")
    parser.add_argument("--sarif-schema", type=Path)
    parser.add_argument("--tools", help="comma-separated tool names (default: every rubric file)")
    args = parser.parse_args()

    truth = json.loads(args.ground_truth.read_text())
    scorer = Scorer(truth, args.raw, args.rubric, args.fixture, args.sarif_schema)
    tools = (
        args.tools.split(",") if args.tools else sorted(p.stem for p in args.rubric.glob("*.yaml"))
    )
    results = [scorer.score_tool(tool) for tool in tools]
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "scores.json").write_text(json.dumps(results, indent=2) + "\n")
    (args.out / "RESULTS.md").write_text(render_markdown(results, truth))
    for r in sorted(results, key=lambda r: -r["total"]):
        print(
            f"{r['display']:45} {r['total']:6}  {r['grade']}  in-scope={r['in_scope_score']}  missed={len(r.get('missed_items', []))}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
