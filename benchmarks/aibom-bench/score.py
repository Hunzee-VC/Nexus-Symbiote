#!/usr/bin/env python3
"""Score AIBOM-Bench runs against ground truth.

Every tool's output files (CycloneDX, SPDX 3, SPDX 2, SARIF, or native JSON) are
reduced to two record kinds, components and findings, by format-generic readers.
Scoring then matches the random tokens from the ground truth against those records.
Nothing here is specific to one tool, so the same rules apply to every tool.

Matching is deliberately strict about where a token appears, so that dumping file
contents or listing paths does not count as understanding:

- A component is detected only when its token sits in a short value (at most
  VALUE_LIMIT characters) that names fewer than three of the scenario's components,
  inside a record that carries a word of the item's kind (model, server, skill, ...).
- Attribute checks are read from the most specific qualifying records.
- A finding counts only when its own message text (not keys, not evidence) names the
  class of problem, at a word boundary, at a non-informational severity.

    python3 score.py --corpus /opt/aibom-bench/corpus --runs /opt/aibom-bench/runs \
        --tools tools.json --out results
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
GRADE_BANDS = [(85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F")]
GRADES = "ABCDF"
VALUE_LIMIT = 300
AGGREGATE_LIMIT = 3

FINDING_KEY = re.compile(
    r"(finding|risk|issue|vuln|alert|warning|violation|threat|verdict|flags|results?$|problem)",
    re.I,
)
SKIP_EXACT = {
    "control_mappings", "framework_refs", "framework_catalogs", "catalog", "catalogs",
    "stats", "statistics", "scopes", "codeowners", "authors", "lifecycles",
    "externalreferences", "hashes", "creationinfo", "rules", "taxonomies",
    "invocations", "summary", "scan_sources", "references", "tags", "cwes",
}  # fmt: skip
SKIP_SUBSTR = ("fail", "exclu", "skipped", "error", "ignored", "unsupported", "scanned_files",
               "files_scanned", "log")  # fmt: skip
MSG_KEY = re.compile(
    r"^(message|text|title|detail|details|description|desc|summary|reason|recommendation|"
    r"remediation|category|rule|ruleid|rule_id|name|type|kind|check|issue|risk|explanation|"
    r"help|shortdescription|fulldescription|label|verdict|finding|value|markdown|statement|"
    r"comment|why|impact)$",
    re.I,
)
SEVERITY_KEYS = ("severity", "level", "risk_level", "risklevel", "risk_severity", "risk",
                 "verdict", "rating")  # fmt: skip
NUMERIC_SEVERITY_KEYS = ("security-severity", "security_severity", "cvss", "cvss_score",
                         "cvssscore")  # fmt: skip
GENERIC_PROJECT_TYPES = {"application", "framework", "container", "platform",
                         "operating-system", "device", "firmware", "file"}  # fmt: skip
KIND_WORDS: dict[str, list[str]] = {
    "mcp": ["mcp", "server", "stdio", "model context protocol", "tool"],
    "tooldefs": ["tool", "mcp", "server", "function"],
    "skills": ["skill", "instruction", "rule", "prompt", "hook", "plugin", "command", "agent",
               "memory", "claude", "cursor", "copilot", "guideline", "ai"],
    "agents": ["agent", "a2a", "crew", "graph", "assistant", "orchestrat"],
    "models": ["model", "machine-learning", "safetensors", "gguf", "onnx", "pytorch", "torch",
               "keras", "weights", "checkpoint", "llm", "embedding", "adapter", "lora",
               "huggingface", "ml"],
    "data": ["data", "dataset", "collection", "index", "vector", "rag", "corpus", "embedding",
             "chroma", "pinecone"],
    "packages": ["pkg:", "package", "library", "dependency", "dependencies", "pypi", "npm",
                 "version"],
}  # fmt: skip
KIND_WORDS["safety"] = sorted({w for k in ("mcp", "models") for w in KIND_WORDS[k]})
# Ground-truth items expected to carry ML-BOM / SPDX 3 AI and Dataset typing.
# Safety probes the positive control must trip, or the benchmark cannot see them fail.
PROBES = ("X01", "X02", "X03", "X04", "X07", "X08", "X09")
AI_PROFILE_ITEMS = ("M01", "M03", "M05", "M06", "M09", "R01", "R03")
DATASET_PROFILE_ITEMS = ("D01", "D02", "D03")
SPDX3_AI_TYPES = {"ai_AIPackage", "AIPackage", "ai:AIPackage"}
SPDX3_DATASET_TYPES = {"dataset_DatasetPackage", "DatasetPackage", "dataset:DatasetPackage"}
HEX_DIGEST = re.compile(r"\b[0-9a-f]{32,128}\b")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
ISO_TIME = re.compile(r"\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}(\.\d+)?(z|[+-]\d{2}:?\d{2})?", re.I)
VOLATILE_KEY = re.compile(
    r"^(.*[_-])?(time|timestamp|date|created|generated|started|completed|finished|elapsed|"
    r"duration|seconds|nonce|uuid|serial|serialnumber|run_?id|batch_?id|session_?id|"
    r"scan_?id|cache_?key)([_-]?(at|s|ms|utc))?$",
    re.I,
)
BUILD_TOOLS_JS = {"npm", "yarn", "pnpm", "bun"}


@dataclass
class Rec:
    kind: str
    text: str
    severity: str | None
    source: str
    values: list[str] = field(default_factory=list)
    msg: str = ""
    keys: str = ""


def norm_severity(value: Any, numeric: bool = False) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if not numeric:
            return None
        v = float(value)
        if v >= 9:
            return "critical"
        if v >= 7:
            return "high"
        if v >= 4:
            return "medium"
        return "low" if v > 0 else "info"
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if v in ("critical", "crit", "blocker"):
        return "critical"
    if v in ("high", "error", "severe", "malicious", "dangerous"):
        return "high"
    if v in ("medium", "moderate", "warning", "warn", "suspicious"):
        return "medium"
    if v in ("low", "minor"):
        return "low"
    if v in ("info", "informational", "note", "none", "safe", "clean", "pass", "ok"):
        return "info"
    if numeric:
        try:
            return norm_severity(float(v), numeric=True)
        except ValueError:
            return None
    return None


def worst(*sevs: str | None) -> str | None:
    best = None
    for s in sevs:
        if s and (best is None or SEVERITY_ORDER[s] > SEVERITY_ORDER[best]):
            best = s
    return best


def dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False).lower()


def leaves(obj: Any) -> list[str]:
    out: list[str] = []
    if isinstance(obj, dict):
        for v in obj.values():
            out += leaves(v)
    elif isinstance(obj, list):
        for v in obj:
            out += leaves(v)
    elif isinstance(obj, str):
        out.append(obj.lower())
    return out


def message_text(obj: Any) -> str:
    """The finding's own words: values under message-like keys, recursively."""
    parts: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and MSG_KEY.match(k):
                parts.append(v)
            elif isinstance(v, dict) and MSG_KEY.match(k):
                parts += leaves(v)
            elif isinstance(v, list) and MSG_KEY.match(k):
                parts += [x for x in v if isinstance(x, str)]
    return " ".join(parts).lower()


def identity(d: dict[str, Any]) -> str:
    """Short scalar fields of an entry, used to attribute findings to it."""
    parts = [
        f"{k}={v}"
        for k, v in d.items()
        if isinstance(v, (str, int)) and not isinstance(v, bool) and len(str(v)) < 300
    ]
    return " ".join(parts).lower()


def severity_of(d: dict[str, Any]) -> str | None:
    sev = None
    for k, v in d.items():
        lk = k.lower()
        if lk in SEVERITY_KEYS:
            sev = worst(sev, norm_severity(v))
        elif lk in NUMERIC_SEVERITY_KEYS:
            sev = worst(sev, norm_severity(v, numeric=True))
    props = d.get("properties")
    if isinstance(props, dict):
        sev = worst(sev, severity_of(props))
    return sev


def keys_of(obj: Any) -> list[str]:
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k).lower())
            out += keys_of(v)
    elif isinstance(obj, list):
        for v in obj:
            out += keys_of(v)
    return out


def component(obj: dict[str, Any], src: str, container: str = "") -> Rec:
    return Rec("component", dumps(obj), None, src, leaves(obj), "",
               " ".join(keys_of(obj) + [container.lower()]))  # fmt: skip


def finding(obj: Any, src: str, sev: str | None, context: str = "", msg: str = "") -> Rec:
    return Rec("finding", dumps(obj) + " " + context, sev, src, [], msg or message_text(obj))


# ------------------------------------------------------------------------- readers


def read_cyclonedx(doc: dict[str, Any], src: str) -> list[Rec]:
    recs: list[Rec] = []
    by_ref: dict[str, str] = {}

    def walk(entries: Any) -> None:
        if not isinstance(entries, list):
            return
        for e in entries:
            if not isinstance(e, dict):
                continue
            ref = e.get("bom-ref")
            if isinstance(ref, str):
                by_ref[ref] = identity(e)
            recs.append(component(e, src))
            for p in e.get("properties") or []:
                name = str((p or {}).get("name", ""))
                if isinstance(p, dict) and re.search(
                    r"(risk|finding|threat|warning|vuln|issue|alert)", name, re.I
                ):
                    sev = norm_severity(p.get("value")) if re.search(
                        r"(severity|level)$", name, re.I) else None  # fmt: skip
                    recs.append(finding(p, src, sev, identity(e),
                                        f"{name} {p.get('value', '')}".lower()))  # fmt: skip
            walk(e.get("components"))
            walk(e.get("services"))

    walk(doc.get("components"))
    walk(doc.get("services"))
    meta = doc.get("metadata") or {}
    mc = meta.get("component") or {}
    meta_ref = mc.get("bom-ref")
    if (
        isinstance(mc, dict)
        and mc
        and (
            str(mc.get("type", "")).lower() not in GENERIC_PROJECT_TYPES
            or not (doc.get("components") or doc.get("services"))
        )
    ):
        walk([mc])
    else:
        walk(mc.get("components") if isinstance(mc, dict) else None)
    for f in doc.get("formulation") or []:
        if isinstance(f, dict):
            walk(f.get("components"))
            walk(f.get("services"))
    for v in doc.get("vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        affected = " ".join(
            by_ref.get(a.get("ref", ""), a.get("ref", ""))
            for a in v.get("affects") or []
            if isinstance(a, dict)
        )
        sev = worst(*[norm_severity((r or {}).get("severity")) for r in v.get("ratings") or []])
        msg = " ".join(str(v.get(k, "")) for k in ("id", "description", "detail",
                                                    "recommendation")).lower()  # fmt: skip
        recs.append(finding(v, src, sev, affected.lower(), msg))
    for a in doc.get("annotations") or []:
        if not isinstance(a, dict):
            continue
        subjects = [s for s in a.get("subjects") or [] if isinstance(s, str)]
        text = str(a.get("text", ""))
        m = re.search(r"\b(?:severity\W+)?(critical|high|medium|moderate|low|info)\b", text, re.I)
        sev = norm_severity(m.group(1)) if m else None
        if sev is None and all(s == meta_ref for s in subjects):
            continue  # a document-level note, not a finding about a component
        ctx = " ".join(by_ref.get(s, s) for s in subjects).lower()
        recs.append(finding(a, src, sev, ctx, text.lower()))
    return recs


def read_spdx3(doc: dict[str, Any], src: str) -> list[Rec]:
    recs: list[Rec] = []
    elements: list[Any] = []
    for key in ("@graph", "element", "elements"):
        if isinstance(doc.get(key), list):
            elements += doc[key]
    ids = {e.get("spdxId") or e.get("@id"): identity(e) for e in elements if isinstance(e, dict)}
    skip = ("relationship", "creationinfo", "person", "organization", "tool", "spdxdocument",
            "sbom", "bom", "softwareagent", "agent", "hash", "externalidentifier",
            "externalref", "license", "licenseexpression", "simplelicensingtext")  # fmt: skip
    for e in elements:
        if not isinstance(e, dict):
            continue
        typ = str(e.get("type") or e.get("@type") or "").lower()
        if "vuln" in typ or "annotation" in typ:
            refs = [e.get(k) for k in ("subject", "from", "to")]
            refs = [x for r in refs for x in (r if isinstance(r, list) else [r]) if x]
            ctx = " ".join(ids.get(r, str(r)) for r in refs).lower()
            recs.append(finding(e, src, severity_of(e), ctx))
        elif not any(typ.endswith(s) for s in skip):
            recs.append(component(e, src))
    return recs


def read_spdx2(doc: dict[str, Any], src: str) -> list[Rec]:
    return [
        component(e, src)
        for e in (doc.get("packages") or []) + (doc.get("files") or [])
        if isinstance(e, dict)
    ]


def read_sarif(doc: dict[str, Any], src: str) -> list[Rec]:
    recs: list[Rec] = []
    for run in doc.get("runs") or []:
        tool = run.get("tool") or {}
        components = [tool.get("driver") or {}] + list(tool.get("extensions") or [])
        rules_by_id: dict[str, Any] = {}
        for comp in components:
            for r in comp.get("rules") or []:
                if isinstance(r, dict) and r.get("id"):
                    rules_by_id[r["id"]] = r
        driver_rules = (tool.get("driver") or {}).get("rules") or []
        for res in run.get("results") or []:
            if not isinstance(res, dict):
                continue
            rule: dict[str, Any] = rules_by_id.get(res.get("ruleId"), {})
            ref = res.get("rule") or {}
            idx = res.get("ruleIndex", ref.get("index") if isinstance(ref, dict) else None)
            comp_idx = ((ref.get("toolComponent") or {}).get("index")
                        if isinstance(ref, dict) else None)  # fmt: skip
            if not rule and isinstance(idx, int):
                pool = (components[1 + comp_idx].get("rules") or []) if isinstance(
                    comp_idx, int) and 1 + comp_idx < len(components) else driver_rules  # fmt: skip
                rule = pool[idx] if 0 <= idx < len(pool) else {}
            if not rule and isinstance(ref, dict) and ref.get("id"):
                rule = rules_by_id.get(ref["id"], {})
            if res.get("kind") in ("pass", "notApplicable", "informational", "open", "review"):
                sev: str | None = "info" if res.get("kind") != "open" else None
            else:
                sev = worst(
                    norm_severity((res.get("properties") or {}).get("security-severity"), True),
                    norm_severity((rule.get("properties") or {}).get("security-severity"), True),
                ) or norm_severity(res.get("level")) or norm_severity(
                    (rule.get("defaultConfiguration") or {}).get("level"))  # fmt: skip
            msg_parts = [str((res.get("message") or {}).get("text", "")), str(res.get("ruleId", "")),
                         str(rule.get("name", ""))]  # fmt: skip
            for k in ("shortDescription", "fullDescription", "help"):
                msg_parts.append(str((rule.get(k) or {}).get("text", "")))
            recs.append(finding(res, src, sev, dumps(rule), " ".join(msg_parts).lower()))
    return recs


def skip_key(k: str) -> bool:
    lk = k.lower()
    return lk in SKIP_EXACT or any(s in lk for s in SKIP_SUBSTR)


def read_generic(doc: Any, src: str) -> list[Rec]:
    recs: list[Rec] = []

    def emit(
        e: dict[str, Any], parent: dict[str, Any] | None, as_finding: bool, key_hint: str = ""
    ) -> None:
        if as_finding:
            ctx = identity(parent) if parent else ""
            recs.append(finding(e, src, severity_of(e), ctx))
        else:
            recs.append(component(e, src, key_hint))
            sev = severity_of(e)
            if sev and sev != "info":
                recs.append(finding(e, src, sev))
        for k, v in e.items():
            if not skip_key(k) and isinstance(v, (list, dict)):
                walk(v, k, e, as_finding, depth=1)

    def walk(node: Any, key: str, parent: dict[str, Any] | None, in_finding: bool,
             depth: int = 0) -> None:  # fmt: skip
        is_finding = in_finding or bool(FINDING_KEY.search(key))
        if isinstance(node, dict):
            vals = list(node.values())
            # A dict of dicts keyed by name ({"servers": {"a": {...}, "b": {...}}}) is a
            # list whose names live in the keys.
            if depth > 0 and vals and all(isinstance(v, dict) for v in vals):
                for k, v in node.items():
                    if not skip_key(k):
                        emit({"_key": k, **v}, parent, is_finding, key)
                return
            for k, v in node.items():
                if not skip_key(k):
                    walk(v, k, node, in_finding, depth + 1)
        elif isinstance(node, list):
            for e in node:
                if isinstance(e, dict):
                    emit(e, parent, is_finding, key)
                elif isinstance(e, list):
                    walk(e, key, parent, is_finding, depth + 1)

    walk(doc, "", None, False)
    return recs


def parse_json_outputs(data: bytes) -> list[Any]:
    try:
        return [json.loads(data)]
    except (ValueError, UnicodeDecodeError):
        pass
    docs = []
    text = data.decode("utf-8", "replace")
    start = text.find("{")
    if start > 0:
        try:
            return [json.loads(text[start:])]
        except ValueError:
            pass
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                docs.append(json.loads(line))
            except ValueError:
                continue
    return docs


def is_sarif(doc: Any) -> bool:
    return (
        isinstance(doc, dict)
        and isinstance(doc.get("runs"), list)
        and (
            str(doc.get("version", "")).startswith("2.1") or "sarif" in str(doc.get("$schema", ""))
        )
    )


def is_spdx3(doc: Any) -> bool:
    return isinstance(doc, dict) and "spdx.org/rdf/3" in json.dumps(doc.get("@context"))


def read_doc(doc: Any, name: str) -> list[Rec]:
    if isinstance(doc, dict) and doc.get("bomFormat") == "CycloneDX":
        return read_cyclonedx(doc, name)
    if is_spdx3(doc) or (isinstance(doc, dict) and "@graph" in doc):
        return read_spdx3(doc, name)
    if isinstance(doc, dict) and "spdxVersion" in doc:
        return read_spdx2(doc, name)
    if is_sarif(doc):
        return read_sarif(doc, name)
    return read_generic(doc, name)


def read_outputs(run_dir: Path) -> tuple[list[Rec], dict[str, Any], dict[str, bytes]]:
    recs: list[Rec] = []
    docs: dict[str, Any] = {}
    raw: dict[str, bytes] = {}
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        name = str(path.relative_to(run_dir))
        if path.name.endswith(".strace") or path.name == "_run.json":
            continue
        data = path.read_bytes()
        raw[name] = data
        if path.name.endswith(".stderr"):
            continue
        parsed = parse_json_outputs(data)
        for i, doc in enumerate(parsed):
            key = name if i == 0 else f"{name}#{i}"
            docs[key] = doc
            recs += read_doc(doc, key)
    return recs, docs, raw


# ------------------------------------------------------------------------- matching


def has(text: str, needles: list[str]) -> bool:
    """Substring match; a needle written "=x" only matches a value equal to x."""
    return any(
        (text == n[1:].lower()) if n.startswith("=") else (n.lower() in text) for n in needles
    )


def has_word(text: str, words: list[str]) -> bool:
    return any(re.search(r"(?<![a-z0-9])" + re.escape(w.lower()), text) for w in words)


def informative(r: Rec) -> bool:
    return r.severity != "info"


def short(v: str) -> bool:
    return len(v) <= VALUE_LIMIT and "\n" not in v


def qualifying(r: Rec, match: list[str], tokens: list[str], domain: str) -> int | None:
    """How many scenario tokens a qualifying record names, or None if it does not qualify.

    The token must sit in a short single-line value that names fewer than
    AGGREGATE_LIMIT of the scenario's components (a name, a command, a URL; not a file
    dump), and evidence of the item's kind must come from somewhere else in the record:
    another short value, a key, or the name of the list that holds it. A path alone is
    not a typed inventory entry.
    """
    if r.kind != "component":
        return None
    words = KIND_WORDS[domain]
    for v in r.values:
        if not short(v) or not has(v, match) or sum(t in v for t in tokens) >= AGGREGATE_LIMIT:
            continue
        others = [x for x in r.values if x is not v and short(x)]
        if has_word(" ".join(others) + " " + r.keys, words):
            return sum(t in r.text for t in tokens)
    return None


def score_component(
    item: dict[str, Any], recs: list[Rec], tokens: list[str]
) -> tuple[float, dict[str, Any]]:
    dom = item.get("kind_domain") or item["domain"]
    scored = [(n, r) for r in recs if (n := qualifying(r, item["match"], tokens, dom)) is not None]
    ev: dict[str, Any] = {"detected": bool(scored), "records": len(scored)}
    if not scored:
        return 0.0, ev
    earned = float(item["weight"])
    tightest = min(n for n, _ in scored)
    blob = " ".join(r.text for n, r in scored if n == tightest)
    for chk in item["checks"]:
        ok = has(blob, chk["any_of"])
        ev[chk["id"]] = ok
        earned += chk["weight"] if ok else 0
    return earned, ev


def specific_findings(recs: list[Rec], tokens: list[str]) -> list[Rec]:
    """Findings that name at most AGGREGATE_LIMIT of the scenario's components.

    A repository-level finding whose evidence lists every component ("no human
    oversight: server A, B, C, ...") is not a judgement about any one of them, so it
    neither earns per-component credit nor counts as a false positive.
    """
    return [
        r for r in recs
        if r.kind == "finding" and sum(t in r.text for t in tokens) <= AGGREGATE_LIMIT
    ]  # fmt: skip


def score_finding(item: dict[str, Any], recs: list[Rec]) -> tuple[float, dict[str, Any]]:
    hits = [
        r for r in recs
        if informative(r) and has(r.text, item["match"]) and has_word(r.msg, item["keywords"])
    ]  # fmt: skip
    return (float(item["weight"]) if hits else 0.0), {"detected": bool(hits)}


def possible(item: dict[str, Any]) -> float:
    return float(item["weight"]) + sum(c["weight"] for c in item.get("checks", []))


def volatile_normalize(obj: Any, subs: list[tuple[str, str]]) -> Any:
    if isinstance(obj, dict):
        return {k: volatile_normalize(v, subs) for k, v in obj.items() if not VOLATILE_KEY.match(k)}
    if isinstance(obj, list):
        return [volatile_normalize(v, subs) for v in obj]
    if isinstance(obj, str):
        s = obj
        for a, b in subs:
            s = s.replace(a, b)
        s = UUID.sub("<uuid>", s)
        return ISO_TIME.sub("<time>", s)
    return obj


def bomrefs(node: Any) -> list[str]:
    out: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "bom-ref" and isinstance(v, str):
                out.append(v)
            else:
                out += bomrefs(v)
    elif isinstance(node, list):
        for v in node:
            out += bomrefs(v)
    return out


def canonical(obj: Any) -> Any:
    """Order-insensitive form: arrays are compared as multisets."""
    if isinstance(obj, dict):
        return {k: canonical(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return sorted((canonical(v) for v in obj), key=lambda v: json.dumps(v, sort_keys=True))
    return obj


def text_normalize(data: bytes, subs: list[tuple[str, str]]) -> str:
    s = data.decode("utf-8", "replace")
    for a, b in subs:
        s = s.replace(a, b)
    s = UUID.sub("<uuid>", s)
    s = ISO_TIME.sub("<time>", s)
    return re.sub(r"\d+(\.\d+)?\s*(ms|s|sec|seconds)\b", "<dur>", s)


STRACE_CONNECT4 = re.compile(r"sa_family=AF_INET,.*?htons\((\d+)\).*?inet_addr\(\"([\d.]+)\"\)")
STRACE_CONNECT6 = re.compile(r"sa_family=AF_INET6,.*?htons\((\d+)\).*?\"([0-9a-f:.]+)\"")
STRACE_EXECVE = re.compile(r'execve\("([^"]*)", \[(.*?)\]')


def egress(strace_files: list[Path]) -> list[str]:
    dests = set()
    for f in strace_files:
        for line in f.read_text(errors="replace").splitlines():
            if "connect(" not in line:
                continue
            m = STRACE_CONNECT4.search(line) or STRACE_CONNECT6.search(line)
            if m:
                port, addr = m.group(1), m.group(2)
                if addr.startswith("::ffff:"):
                    addr = addr[7:]
                if addr.startswith("127.") or addr in ("::1", "0.0.0.0", "::"):  # noqa: S104
                    continue
                dests.add(f"{addr}:{port}")
    return sorted(dests)


def build_execs(strace_files: list[Path]) -> list[str]:
    """Package-manager or build invocations that would run the scanned project's code."""
    found = []
    for f in strace_files:
        for line in f.read_text(errors="replace").splitlines():
            m = STRACE_EXECVE.search(line)
            if not m:
                continue
            argv = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(2))
            if not argv:
                continue
            prog = argv[0].rsplit("/", 1)[-1]
            args = argv[1:]
            hit = False
            if prog in BUILD_TOOLS_JS and any(a in ("install", "i", "ci", "add") for a in args):
                hit = "--ignore-scripts" not in args
            elif prog.startswith("pip") or (prog.startswith("python") and "pip" in args):
                # Only installs of the scanned project's own files: ".", "-e <path>" or
                # "-r <file>" pointing into the scan copy (or relative to it).
                targets = [args[i + 1] for i, a in enumerate(args[:-1])
                           if a in ("-r", "--requirement", "-e", "--editable")]  # fmt: skip
                local = [x for x in targets if "/_work/" in x or not x.startswith("/")]
                checkout = [a for a in args if a == "." or "/_work/" in a]
                hit = "install" in args and bool(local or checkout)
            elif (
                prog.startswith("python")
                and any(a.endswith("setup.py") for a in args)
                or prog in ("uv", "poetry", "pdm")
                and ("sync" in args or "install" in args)
            ):
                hit = True
            if hit:
                status = "ran" if line.rstrip().endswith("= 0") else "attempted"
                found.append(f"{status}: {' '.join(argv)[:160]}")
    return sorted(set(found))


class ToolRun:
    def __init__(self, runs: Path, tool: str) -> None:
        self.tool = tool
        self.root = runs / tool
        self.recs: dict[str, list[Rec]] = {}
        self.docs: dict[str, dict[str, Any]] = {}
        self.raw: dict[str, dict[str, bytes]] = {}
        self.meta: dict[str, Any] = {}
        for d in sorted(self.root.iterdir()) if self.root.exists() else []:
            if not d.is_dir():
                continue
            r, docs, raw = read_outputs(d)
            self.recs[d.name], self.docs[d.name], self.raw[d.name] = r, docs, raw
            run_json = d / "_run.json"
            if run_json.exists():
                self.meta[d.name] = json.loads(run_json.read_text())

    def stale(self, digest: str) -> list[str]:
        return [t for t, m in self.meta.items() if m.get("corpus_digest") not in (None, digest)]

    def r(self, scn: str) -> list[Rec]:
        return self.recs.get(scn, [])

    def tags(self, scn: str) -> list[str]:
        return [t for t in self.meta if t.split("#")[0] == scn]


def cdx_validator() -> Any:
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError:
        sys.exit("cyclonedx-python-lib[validation] is required to score F01; see README.md")
    versions = {"1.4": SchemaVersion.V1_4, "1.5": SchemaVersion.V1_5, "1.6": SchemaVersion.V1_6}
    if hasattr(SchemaVersion, "V1_7"):
        versions["1.7"] = SchemaVersion.V1_7

    def validate(doc: dict[str, Any]) -> str | None:
        v = versions.get(str(doc.get("specVersion")))
        if v is None:
            return f"unsupported specVersion {doc.get('specVersion')}"
        err = JsonStrictValidator(v).validate_str(json.dumps(doc))
        return None if err is None else str(err)[:300]

    return validate


def purl_ok(p: str) -> bool:
    try:
        from packageurl import PackageURL
    except ImportError:
        sys.exit("packageurl-python is required to score F04; see README.md")
    try:
        PackageURL.from_string(p)
        return True
    except ValueError:
        return False


def nonempty_cdx(d: Any) -> bool:
    if not (isinstance(d, dict) and d.get("bomFormat") == "CycloneDX"):
        return False
    mc = (d.get("metadata") or {}).get("component") or {}
    return bool(d.get("components") or d.get("services")) or (
        str(mc.get("type", "")).lower() not in GENERIC_PROJECT_TYPES and bool(mc)
    )


def standards(
    item: dict[str, Any],
    run: ToolRun,
    validate: Any,
    truth: dict[str, Any],
    detected_in: set[str],
) -> tuple[float, dict[str, Any]]:
    kind, w = item["kind"], float(item["weight"])
    main = {k: v for k, v in run.docs.items() if "#" not in k}
    # An empty document conforms trivially; only documents that inventory something count.
    cdx = [(s, n, d) for s, docs in main.items() for n, d in docs.items() if nonempty_cdx(d)]
    if kind == "cyclonedx_valid":
        if not cdx:
            return 0.0, {"cyclonedx_documents": 0}
        errors = {f"{s}/{n}": validate(d) for s, n, d in cdx}
        bad = {k: v for k, v in errors.items() if v}
        return w * (1 - len(bad) / len(errors)), {"documents": len(errors), "invalid": bad}
    if kind == "spdx3_present":
        spdx3 = []
        for scn, docs in main.items():
            for d in docs.values():
                if is_spdx3(d) and any(r.kind == "component" for r in read_spdx3(d, "")):
                    spdx3.append((scn, d))
        if not spdx3:
            return 0.0, {"spdx3_documents": 0}
        # Structural check only (no SPDX 3 JSON schema or SHACL validation in v1.0).
        well_formed = sum(
            1 for _, d in spdx3
            if all(isinstance(e, dict) and (e.get("type") or e.get("@type"))
                   and (e.get("spdxId") or e.get("@id"))
                   for e in (d.get("@graph") or d.get("element") or d.get("elements") or []))
        )  # fmt: skip
        typed = {"ai": 0, "dataset": 0}
        expect = {"ai": [i for i in truth["items"] if i["id"] in AI_PROFILE_ITEMS],
                  "dataset": [i for i in truth["items"] if i["id"] in DATASET_PROFILE_ITEMS]}  # fmt: skip
        for prof, items in expect.items():
            types = SPDX3_AI_TYPES if prof == "ai" else SPDX3_DATASET_TYPES
            for it in items:
                for scn, d in spdx3:
                    if scn != it["scenario"]:
                        continue
                    els = d.get("@graph") or d.get("element") or d.get("elements") or []
                    if any(isinstance(e, dict) and str(e.get("type") or e.get("@type")) in types
                           and has(dumps(e), it["match"]) for e in els):  # fmt: skip
                        typed[prof] += 1
                        break
        frac = (typed["ai"] + typed["dataset"]) / (len(expect["ai"]) + len(expect["dataset"]))
        return w * (0.5 * well_formed / len(spdx3) + 0.5 * frac), {
            "spdx3_documents": len(spdx3),
            "well_formed": well_formed,
            "ai_typed": typed["ai"],
            "dataset_typed": typed["dataset"],
        }
    if kind == "mlbom_semantics":

        def typed_frac(ids: tuple[str, ...], ctype: str) -> float:
            items = [i for i in truth["items"] if i["id"] in ids]
            hits = 0
            for it in items:
                for scn, _, d in cdx:
                    if scn != it["scenario"]:
                        continue
                    if any(r.kind == "component" and f'"type": "{ctype}"' in r.text
                           and qualifying(r, it["match"], [], it["domain"]) is not None
                           for r in read_cyclonedx(d, "")):  # fmt: skip
                        hits += 1
                        break
            return hits / len(items) if items else 0.0

        model = typed_frac(AI_PROFILE_ITEMS, "machine-learning-model")
        data = typed_frac(DATASET_PROFILE_ITEMS, "data")
        return w * (0.5 * model + 0.5 * data), {"models_typed": round(model, 2),
                                                "datasets_typed": round(data, 2)}  # fmt: skip
    if kind == "purl_valid":
        purls: list[str] = []

        def collect(node: Any) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    if k in ("purl", "software_packageUrl", "packageUrl") and isinstance(v, str):
                        purls.append(v)
                    elif (
                        k == "referenceLocator"
                        and str(node.get("referenceType")) == "purl"
                        or k == "identifier"
                        and str(node.get("externalIdentifierType")) in ("packageUrl", "purl")
                    ):
                        purls.append(str(v))
                    else:
                        collect(v)
            elif isinstance(node, list):
                for v in node:
                    collect(v)

        for docs in main.values():
            for d in docs.values():
                if nonempty_cdx(d) or is_spdx3(d) or (isinstance(d, dict) and "spdxVersion" in d):
                    collect(d)
        purls = sorted(set(purls))
        if not purls:
            return 0.0, {"purls": 0}
        valid = [p for p in purls if purl_ok(p)]
        hf_tokens = [m.lower() for i in truth["items"] if i["id"] in ("R01", "R02", "R03")
                     for m in i["match"]]  # fmt: skip
        hf = any(p.lower().startswith("pkg:huggingface/") and has(p.lower(), hf_tokens)
                 for p in valid)  # fmt: skip
        frac = len(valid) / len(purls)
        return w * (0.5 * frac + 0.5 * hf), {
            "purls": len(purls),
            "invalid": sorted(set(purls) - set(valid))[:10],
            "huggingface_purl": hf,
        }
    if kind == "refs_resolve":
        if not cdx:
            return 0.0, {}
        multi, with_deps, clean = 0, 0, 0
        for _, _, d in cdx:
            refs = bomrefs(d)
            deps = d.get("dependencies") or []
            used = [x.get("ref") for x in deps if isinstance(x, dict)]
            used += [y for x in deps if isinstance(x, dict) for y in x.get("dependsOn") or []]
            for v in d.get("vulnerabilities") or []:
                used += [a.get("ref") for a in v.get("affects") or [] if isinstance(a, dict)]
            for a in d.get("annotations") or []:
                used += [x for x in (a or {}).get("subjects") or [] if isinstance(x, str)]
            if len(d.get("components") or []) + len(d.get("services") or []) > 1:
                multi += 1
                if any((x or {}).get("dependsOn") for x in deps if isinstance(x, dict)):
                    with_deps += 1
            unique = len(refs) == len(set(refs))
            if unique and all(u in refs or str(u).startswith("urn:cdx:") for u in used if u):
                clean += 1
        graph = with_deps / multi if multi else 0.0
        return w * (0.5 * graph + 0.5 * clean / len(cdx)), {
            "multi_component_documents": multi,
            "with_dependency_edges": with_deps,
            "unique_refs_and_all_resolve": clean,
            "documents": len(cdx),
        }
    if kind == "deterministic":
        same, total, diffs = 0, 0, []
        for scn in ("s01-models", "s04-mcp"):
            if scn not in detected_in:
                continue
            a, b = run.raw.get(scn, {}), run.raw.get(scn + "#2", {})
            subs = [(str(run.root / (scn + "#2")), "<out>"), (str(run.root / scn), "<out>"),
                    (str(run.root.parent / "_home" / run.tool / (scn + "#2")), "<home>"),
                    (str(run.root.parent / "_home" / run.tool / scn), "<home>")]  # fmt: skip
            names = {n for n in set(a) | set(b) if not n.startswith("_cmd")}
            for name in sorted(names):
                total += 1
                if name not in a or name not in b:
                    diffs.append(f"{scn}/{name} (missing in one run)")
                    continue
                try:
                    x = canonical(volatile_normalize(json.loads(a[name]), subs))
                    y = canonical(volatile_normalize(json.loads(b[name]), subs))
                    ok = x == y
                except ValueError:
                    ok = text_normalize(a[name], subs) == text_normalize(b[name], subs)
                same += ok
                if not ok:
                    diffs.append(f"{scn}/{name}")
        if not total:
            return 0.0, {"files": 0}
        return w * same / total, {"files": total, "identical": same, "differs": diffs}
    if kind == "metadata":
        for _, _, d in cdx:
            tools = (d.get("metadata") or {}).get("tools")
            comps = tools.get("components", []) if isinstance(tools, dict) else tools or []
            if any(isinstance(t, dict) and t.get("name") and t.get("version") for t in comps):
                return w, {"tool_identified": True}
        return 0.0, {"tool_identified": False}
    raise ValueError(kind)


def safety(item: dict[str, Any], run: ToolRun, truth: dict[str, Any]) -> tuple[float, dict]:
    kind, w, scn = item["kind"], float(item["weight"]), item["scenario"]
    if kind == "canary_absent":
        found = sorted({f"{t}:{c}" for t in run.tags(scn)
                        for c in run.meta[t].get("canaries") or [] if c in item["canaries"]})  # fmt: skip
        ev: dict[str, Any] = {"canaries_written": found, "runs": run.tags(scn)}
        bad = bool(found)
        if item.get("detect_build_exec"):
            # Any scenario counts: whether a scanner installs the target's dependencies
            # must not depend on which fixture happens to trigger it.
            execs = []
            for t in sorted(run.meta):
                for cmd in build_execs(sorted((run.root / t).glob("*.strace"))):
                    execs.append(f"{t}: {cmd}")
            ev["build_commands"] = execs
            bad = bad or bool(execs)
        return (0.0 if bad else w), ev
    if kind == "outside_absent":
        leaked = [f"{t}/{n}" for t in run.tags(scn) for n, d in run.raw.get(t, {}).items()
                  if any(tok.lower().encode() in d.lower() for tok in item["match"])]  # fmt: skip
        return (0.0 if leaked else w), {"leaked_in": leaked}
    if kind == "ansi_absent":
        hits = [f"{t}/{n}" for t in run.tags(scn) for n, d in run.raw.get(t, {}).items()
                if any(p.encode() in d for p in item["patterns"])]  # fmt: skip
        return (0.0 if hits else w), {"raw_escape_in": hits}
    if kind == "completes":
        cmds = run.meta.get(scn, {}).get("commands") or []
        timed = [c["argv"][0] for c in cmds if c["timed_out"]]
        killed = [c["exit"] for c in cmds if c["exit"] < 0 or c["exit"] in (137, 139)]
        produced = bool(run.docs.get(scn))
        ok = bool(cmds) and not timed and not killed and produced
        return (w if ok else 0.0), {"timed_out": bool(timed), "killed_by_signal": killed,
                                    "produced_output": produced,
                                    "seconds": [c["seconds"] for c in cmds]}  # fmt: skip
    if kind == "bounded_memory":
        cmds = run.meta.get(scn, {}).get("commands") or []
        peak = max((c["max_rss_bytes"] for c in cmds), default=0)
        timed_out = any(c["timed_out"] for c in cmds)
        ok = bool(cmds) and not timed_out and peak < item["limit_bytes"]
        return (w if ok else 0.0), {"peak_rss_mib": peak >> 20, "timed_out": timed_out}
    if kind == "secret_absent":
        needles = []
        for s in truth["safety"]["secrets"]:
            b = s.encode()
            needles += [b, base64.b64encode(b), base64.urlsafe_b64encode(b), b.hex().encode()]
        leaked = [f"{t}/{n}" for t in run.tags(scn) for n, d in run.raw.get(t, {}).items()
                  if any(x in d for x in needles)]  # fmt: skip
        return (0.0 if leaked else w), {"leaked_in": leaked}
    if kind == "no_egress":
        files = [f for t in run.meta if t.endswith("#default")
                 for f in sorted((run.root / t).glob("*.strace"))]  # fmt: skip
        basis = "default-mode runs"
        if not files:
            files = sorted((run.root / "s04-mcp").glob("*.strace"))
            basis = "benchmark-mode s04-mcp"
        dests = egress(files)
        return (0.0 if dests else w), {"connect_attempts": dests, "basis": basis}
    raise ValueError(kind)


def drift(item: dict[str, Any], run: ToolRun, truth: dict[str, Any]) -> tuple[float, dict]:
    """Compare a tool's records before (baseline) and after one description change.

    Both versions are scanned at the same path. drift_changed: some record naming the
    changed tool must differ. drift_stable: a record specific to the unchanged tool
    (naming it but not the changed tool) must be identical, or must keep a per-tool
    fingerprint that is not shared with the changed tool, so a reviewer can tell which
    tool changed.
    """
    subs = [(item["scenario"], "<scn>"), (item["baseline"], "<scn>")]
    toks = [m.lower() for i in truth["items"] if i["scenario"] == item["baseline"]
            and i["kind"] == "component" for m in i["match"]]  # fmt: skip
    other: list[str] = []
    if item["kind"] == "drift_stable":
        other = [m for i in truth["items"] if i["kind"] == "drift_changed"
                 and i["scenario"] == item["scenario"] for m in i["match"]]  # fmt: skip

    def records(scn: str) -> list[str]:
        return sorted(
            json.dumps(volatile_normalize(json.loads(r.text), subs), sort_keys=True)
            for r in run.r(scn)
            if qualifying(r, item["match"], toks, item["domain"]) is not None
            and not (other and has(r.text, other)) and r.text.startswith("{")
        )  # fmt: skip

    a, b = records(item["baseline"]), records(item["scenario"])
    if not a or not b:
        return 0.0, {"present": False}
    changed = a != b
    ok = changed if item["kind"] == "drift_changed" else not changed
    ev: dict[str, Any] = {"present": True, "changed": changed}
    if item["kind"] == "drift_stable" and changed:

        def digests(texts: list[str]) -> set[str]:
            return {d for t in texts for d in HEX_DIGEST.findall(t)}

        changed_only = [r.text for scn in (item["baseline"], item["scenario"]) for r in run.r(scn)
                        if r.kind == "component" and has(r.text, other)
                        and not has(r.text, item["match"])]  # fmt: skip
        kept = (digests(a) & digests(b)) - digests(changed_only)
        ok = bool(kept)
        ev["stable_fingerprint"] = bool(kept)
    return (float(item["weight"]) if ok else 0.0), ev


def grade(score: float) -> str:
    return next(g for floor, g in GRADE_BANDS if round(score, 1) >= floor)


def score_tool(
    truth: dict[str, Any], run: ToolRun, validate: Any, declared: list[str]
) -> dict[str, Any]:
    domains = {d: {"earned": 0.0, "possible": 0.0, "penalty": 0.0} for d in truth["domains"]}
    items_out, gates = [], []
    tokens: dict[str, list[str]] = {}
    for item in truth["items"]:
        if item["kind"] in ("component", "negative_component"):
            tokens.setdefault(item["scenario"], []).extend(m.lower() for m in item["match"])

    def toks(scn: str) -> list[str]:
        return tokens.get(scn) or tokens.get(scn.replace("-v2", "-v1"), [])

    specific = {
        s["id"]: specific_findings(run.r(s["id"]), toks(s["id"])) for s in truth["scenarios"]
    }
    find_earned = find_possible = 0.0
    detected_in: set[str] = set()
    for item in truth["items"]:
        if item["kind"] == "component" and item["scenario"] not in detected_in:
            got, _ = score_component(item, run.r(item["scenario"]), toks(item["scenario"]))
            if got > 0:
                detected_in.add(item["scenario"])
    for item in truth["items"]:
        kind, dom = item["kind"], domains[item["domain"]]
        scn = item["scenario"]
        if kind == "component":
            got, ev = score_component(item, run.r(scn), toks(scn))
        elif kind == "finding":
            got, ev = score_finding(item, specific.get(scn, []))
            find_earned += got
            find_possible += possible(item)
        elif kind == "negative_component":
            hit = any(qualifying(r, item["match"], toks(scn), item["domain"]) is not None
                      for r in run.r(scn))  # fmt: skip
            got, ev = (-float(item["weight"]) if hit else 0.0), {"false_positive": hit}
        elif kind == "negative_finding":
            hit = any(r.severity in ("medium", "high", "critical") and has(r.text, item["match"])
                      and has_word(r.msg, item["keywords"]) for r in specific.get(scn, []))  # fmt: skip
            got, ev = (-float(item["weight"]) if hit else 0.0), {"false_positive": hit}
        elif kind.startswith("drift_"):
            got, ev = drift(item, run, truth)
        elif item["domain"] == "standards":
            got, ev = standards(item, run, validate, truth, detected_in)
        else:
            got, ev = safety(item, run, truth)
            if item.get("gate") and got < float(item["weight"]):
                gates.append({"item": item["id"], "cap": item["gate"], "title": item["title"]})
        if kind.startswith("negative"):
            dom["penalty"] += -got
        else:
            dom["possible"] += possible(item)
            dom["earned"] += got
        items_out.append({"id": item["id"], "domain": item["domain"], "kind": kind,
                          "title": item["title"], "earned": round(got, 2),
                          "possible": possible(item) if not kind.startswith("negative") else 0,
                          "evidence": ev})  # fmt: skip
    # Safety credit requires a functioning scan: a tool that never parsed the hostile
    # scenario (none of its benign sentinels is reported) is not shown to be safe on it.
    # Gates still apply whenever a check fails.
    detected = {i["id"]: i["evidence"].get("detected") for i in items_out}
    requires = {i["id"]: i.get("requires") for i in truth["items"]}
    default_ok = any(
        score_component(i, run.r(t), toks(i["scenario"]))[0] > 0
        for i in truth["items"] if i["kind"] == "component"
        for t in run.tags(i["scenario"]) if t.endswith("#default")
    )  # fmt: skip
    for i in truth["items"]:
        if i.get("requires_default_detection"):
            requires[i["id"]] = ["<plain invocation detected a component>"]
            detected["<plain invocation detected a component>"] = default_ok
    for out in items_out:
        req = requires.get(out["id"])
        if req and not any(detected.get(r) for r in req) and out["earned"] > 0:
            domains[out["domain"]]["earned"] -= out["earned"]
            out["earned"] = 0.0
            out["evidence"]["not_exercised"] = f"none of {req} detected"
    total = 0.0
    in_scope_num = in_scope_den = 0.0
    for name, d in domains.items():
        pct = max(0.0, d["earned"] - d["penalty"]) / d["possible"] if d["possible"] else 0.0
        d["pct"] = round(100 * pct, 1)
        wt = truth["domains"][name]["weight"]
        total += wt * pct
        if name in declared:
            in_scope_num += wt * pct
            in_scope_den += wt
    raw_grade = grade(total)
    final = raw_grade
    for g in gates:
        if GRADES.index(final) < GRADES.index(g["cap"]):
            final = g["cap"]
    return {
        "score": round(total, 1),
        "in_scope_score": round(100 * in_scope_num / in_scope_den, 1) if in_scope_den else None,
        "risk_findings_pct": round(100 * find_earned / find_possible, 1) if find_possible else 0,
        "grade": final,
        "uncapped_grade": raw_grade,
        "gates": gates,
        "domains": domains,
        "items": items_out,
    }


def rank_key(e: dict[str, Any]) -> tuple[int, float]:
    if e.get("grade") not in tuple(GRADES):
        return (len(GRADES), 0.0)
    return (GRADES.index(e["grade"]), -(e.get("score") or 0.0))


def scorecard(results: dict[str, Any]) -> str:
    doms = list(results["domains"])
    head = ["Rank", "Tool", "Version", "Grade", "Score", "In-scope", "Risk findings"]
    head += doms + ["Gates"]
    lines = [
        f"# AIBOM-Bench {results['version']} scorecard",
        "",
        f"Seed `{results['seed']}`, corpus digest `{results['corpus_digest'][:16]}`. "
        "Ranked by grade (after gates), then score. Domain columns are percentages; Score is "
        "the weighted total out of 100; Risk findings is the share of finding points earned "
        "across all domains.",
        "",
        "| " + " | ".join(head) + " |",
        "|"
        + "|".join("---:" if h not in ("Tool", "Version", "Gates") else "---" for h in head)
        + "|",
    ]
    ranked = sorted(((k, v) for k, v in results["tools"].items() if not v.get("calibration")),
                    key=lambda kv: rank_key(kv[1]))  # fmt: skip
    rank = 0
    for _, e in ranked:
        if e.get("grade") == "N/R":
            lines.append(f"| – | {e['display']} | {e.get('version') or '–'} | N/R | – | – | – | "
                         + " | ".join("–" for _ in doms) + " | not run |")  # fmt: skip
            continue
        rank += 1
        gates = ", ".join(f"{g['item']}→{g['cap']}" for g in e["gates"]) or "–"
        grade_cell = e["grade"] + (f" (was {e['uncapped_grade']})"
                                   if e["grade"] != e["uncapped_grade"] else "")  # fmt: skip
        in_scope = "–" if e["in_scope_score"] is None else f"{e['in_scope_score']:.1f}"
        cells = [str(rank), e["display"], str(e.get("version", "?")).replace("|", "/"),
                 grade_cell, f"{e['score']:.1f}", in_scope, f"{e['risk_findings_pct']:.0f}"]  # fmt: skip
        cells += [f"{e['domains'][d]['pct']:.0f}" for d in doms] + [gates]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    for _, e in results["tools"].items():
        if e.get("calibration"):
            failed = [i["id"] for i in e["items"] if i["domain"] == "safety"
                      and i["kind"] != "component" and i["earned"] < i["possible"]]  # fmt: skip
            lines.append(f"- **{e['display']}** (calibration, not ranked): grade {e['grade']}, "
                         f"gates {[g['item'] for g in e['gates']]}, failed safety checks {failed}, "
                         f"probes that did not fire {e.get('dead_probes', [])}.")  # fmt: skip
    for _, e in ranked:
        if e.get("grade") == "N/R":
            lines.append(f"- **{e['display']}** not run: {e['not_run_reason']}")
        elif e.get("mode_note"):
            lines.append(f"- **{e['display']}**: {e['mode_note']}")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--runs", type=Path, required=True)
    ap.add_argument("--tools", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    truth = json.loads((args.corpus / "ground_truth.json").read_text())
    tools = json.loads(args.tools.read_text())["tools"]
    validate = cdx_validator()
    results: dict[str, Any] = {"benchmark": truth["benchmark"], "version": truth["version"],
                               "seed": truth["seed"], "corpus_digest": truth["corpus_digest"],
                               "domains": truth["domains"], "tools": {}}  # fmt: skip
    for name, spec in tools.items():
        entry: dict[str, Any] = {"display": spec.get("display", name), "source": spec.get("source"),
                                 "version": spec.get("version"),
                                 "mode_note": spec.get("mode_note")}  # fmt: skip
        if not spec.get("runnable", True):
            entry.update({"grade": "N/R", "not_run_reason": spec["not_run_reason"]})
            results["tools"][name] = entry
            continue
        meta_path = args.runs / name / "_tool.json"
        if meta_path.exists():
            meta = json.loads(meta_path.read_text())
            entry["version_reported"] = meta.get("version_reported", meta.get("version"))
            if meta.get("corpus_digest") != truth["corpus_digest"]:
                sys.exit(f"{name}: runs were made on corpus {meta.get('corpus_digest')}, "
                         f"not {truth['corpus_digest']}; regenerate or re-run")  # fmt: skip
        run = ToolRun(args.runs, name)
        stale = run.stale(truth["corpus_digest"])
        if stale:
            sys.exit(f"{name}: runs {stale[:3]} were made on a different corpus; re-run them")
        entry.update(score_tool(truth, run, validate, spec.get("declared_scope", [])))
        entry["calibration"] = bool(spec.get("calibration"))
        entry["runtime_seconds"] = round(sum(c["seconds"] for m in run.meta.values()
                                             for c in m["commands"]), 1)  # fmt: skip
        entry["exit_codes"] = {t: [c["exit"] for c in m["commands"]] for t, m in run.meta.items()}
        results["tools"][name] = entry
    control = results["tools"].get("positive-control")
    if control and "items" in control:
        evidence_keys = ("canaries_written", "build_commands", "leaked_in", "raw_escape_in",
                         "connect_attempts")  # fmt: skip
        failed = {i["id"] for i in control["items"]
                  if any(i["evidence"].get(k) for k in evidence_keys)}  # fmt: skip
        dead = sorted(set(PROBES) - failed)
        control["dead_probes"] = dead
        if dead:
            print(f"WARNING: safety probes that the positive control did not trip: {dead}",
                  file=sys.stderr)  # fmt: skip
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    (args.out / "scorecard.md").write_text(scorecard(results))
    for name, e in sorted(results["tools"].items(), key=lambda kv: rank_key(kv[1])):
        print(f"{name:22} {e.get('grade', ''):4} {e.get('score', '-'):>6} "
              f"in-scope={e.get('in_scope_score', '-')} findings={e.get('risk_findings_pct', '-')} "
              f"gates={[g['item'] for g in e.get('gates', [])]}")  # fmt: skip


if __name__ == "__main__":
    main()
