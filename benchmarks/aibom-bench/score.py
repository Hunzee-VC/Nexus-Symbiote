#!/usr/bin/env python3
"""Score AIBOM-Bench runs against ground truth.

Every tool's output files (CycloneDX, SPDX 3, SPDX 2, SARIF, or native JSON) are
reduced to two record kinds, components and findings, by format-generic readers. A
record is the JSON text of one inventory entry or one finding, plus the identity of
its parent entry for nested findings. Scoring then matches the random tokens from the
ground truth against those records. Nothing here is specific to one tool, so the
same rules apply to every tool.

    python3 score.py --corpus /opt/aibom-bench/corpus --runs /opt/aibom-bench/runs \
        --tools tools.json --out results
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
GRADE_BANDS = [(85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F")]
GATE_ORDER = {"F": 0, "D": 1, "C": 2}

FINDING_KEY = re.compile(
    r"(finding|risk|issue|vuln|alert|warning|violation|threat|verdict|flags|result|problem)",
    re.I,
)
SKIP_KEY = re.compile(
    r"(control_mappings|framework|catalog|stats|scopes|codeowners|^errors$|log|scanned|"
    r"skipped|scan_sources|^tools$|authors|lifecycles|^licenses$|externalreferences|"
    r"^hashes$|creationinfo|^rules$|taxonomies|invocations|artifacts_scanned|summary)",
    re.I,
)
RISKY_PROPERTY = re.compile(r"(risk|finding|threat|warning|vuln|issue|severity|alert)", re.I)
HEX_DIGEST = re.compile(r"\b[0-9a-f]{32,128}\b")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
ISO_TIME = re.compile(r"\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}(\.\d+)?(z|[+-]\d{2}:?\d{2})?", re.I)
VOLATILE_KEY = re.compile(
    r"(time|date|serial|uuid|run_?id|batch_?id|started|completed|elapsed|duration|created|"
    r"generated|nonce|session|^seconds$|cache)",
    re.I,
)
PURL = re.compile(
    r"^pkg:[a-z][a-z0-9.+-]*/"
    r"([A-Za-z0-9.\-_~%]+/)*[A-Za-z0-9.\-_~%]+"
    r"(@[A-Za-z0-9.\-_~%:+]+)?"
    r"(\?[A-Za-z0-9.\-_~%]+=[^#\s]*(&[A-Za-z0-9.\-_~%]+=[^#\s]*)*)?"
    r"(#[^\s]*)?$"
)


@dataclass
class Rec:
    kind: str
    text: str
    severity: str | None
    source: str


def norm_severity(value: Any) -> str | None:
    if isinstance(value, (int, float)):
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
    try:
        return norm_severity(float(v))
    except ValueError:
        return None


def dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False).lower()


def identity(d: dict[str, Any]) -> str:
    """Short scalar fields of a parent entry, attached to the findings nested under it."""
    parts = [
        f"{k}={v}"
        for k, v in d.items()
        if isinstance(v, (str, int)) and not isinstance(v, bool) and len(str(v)) < 300
    ]
    return " ".join(parts).lower()


def severity_of(d: dict[str, Any]) -> str | None:
    best = None
    for key in ("severity", "level", "risk_level", "riskLevel", "risk", "verdict",
                "security-severity", "rating"):  # fmt: skip
        if key in d:
            s = norm_severity(d[key])
            if s and (best is None or SEVERITY_ORDER[s] > SEVERITY_ORDER[best]):
                best = s
    props = d.get("properties")
    if isinstance(props, dict):
        s = severity_of(props)
        if s and (best is None or SEVERITY_ORDER[s] > SEVERITY_ORDER[best]):
            best = s
    return best


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
            recs.append(Rec("component", dumps(e), None, src))
            for p in e.get("properties") or []:
                if isinstance(p, dict) and RISKY_PROPERTY.search(str(p.get("name", ""))):
                    recs.append(Rec("finding", dumps(p) + " " + identity(e),
                                    norm_severity(p.get("value")), src))  # fmt: skip
            walk(e.get("components"))
            walk(e.get("services"))

    walk(doc.get("components"))
    walk(doc.get("services"))
    meta = doc.get("metadata") or {}
    walk((meta.get("component") or {}).get("components"))
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
        sev = None
        for r in v.get("ratings") or []:
            s = norm_severity((r or {}).get("severity"))
            if s and (sev is None or SEVERITY_ORDER[s] > SEVERITY_ORDER[sev]):
                sev = s
        recs.append(Rec("finding", dumps(v) + " " + affected.lower(), sev, src))
    for a in doc.get("annotations") or []:
        if not isinstance(a, dict) or a.get("bom-ref") == "metadata-annotations":
            continue
        subjects = " ".join(by_ref.get(s, s) for s in a.get("subjects") or [] if isinstance(s, str))
        text = str(a.get("text", ""))
        m = re.search(r"\b(critical|high|medium|moderate|low|info)\b", text, re.I)
        recs.append(Rec("finding", dumps(a) + " " + subjects.lower(),
                        norm_severity(m.group(1)) if m else None, src))  # fmt: skip
    return recs


def read_spdx3(doc: dict[str, Any], src: str) -> list[Rec]:
    recs: list[Rec] = []
    elements = doc.get("@graph") or doc.get("elements") or []
    skip = ("relationship", "creationinfo", "person", "organization", "tool", "spdxdocument",
            "sbom", "bom", "softwareagent", "agent", "hash", "externalidentifier",
            "externalref", "license")  # fmt: skip
    for e in elements:
        if not isinstance(e, dict):
            continue
        typ = str(e.get("type") or e.get("@type") or "").lower()
        if "vuln" in typ or "annotation" in typ:
            recs.append(Rec("finding", dumps(e), severity_of(e), src))
        elif not any(typ.endswith(s) or typ == s for s in skip):
            recs.append(Rec("component", dumps(e), None, src))
    return recs


def read_spdx2(doc: dict[str, Any], src: str) -> list[Rec]:
    return [
        Rec("component", dumps(e), None, src)
        for e in (doc.get("packages") or []) + (doc.get("files") or [])
        if isinstance(e, dict)
    ]


def read_sarif(doc: dict[str, Any], src: str) -> list[Rec]:
    recs: list[Rec] = []
    for run in doc.get("runs") or []:
        rules = {}
        for r in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []:
            if isinstance(r, dict):
                rules[r.get("id")] = r
        for res in run.get("results") or []:
            if not isinstance(res, dict):
                continue
            rule = rules.get(res.get("ruleId"), {})
            sev = norm_severity((res.get("properties") or {}).get("security-severity"))
            sev = sev or norm_severity((rule.get("properties") or {}).get("security-severity"))
            sev = sev or norm_severity(res.get("level"))
            sev = sev or norm_severity((rule.get("defaultConfiguration") or {}).get("level"))
            recs.append(Rec("finding", dumps(res) + " " + dumps(rule), sev, src))
    return recs


def read_generic(doc: Any, src: str) -> list[Rec]:
    recs: list[Rec] = []

    def walk(node: Any, key: str, parent: dict[str, Any] | None, in_finding: bool) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if SKIP_KEY.search(k):
                    continue
                walk(v, k, node, in_finding)
        elif isinstance(node, list):
            finding_list = in_finding or bool(FINDING_KEY.search(key))
            for e in node:
                if isinstance(e, dict):
                    if finding_list:
                        ctx = identity(parent) if parent else ""
                        recs.append(Rec("finding", dumps(e) + " " + ctx, severity_of(e), src))
                    else:
                        recs.append(Rec("component", dumps(e), None, src))
                    for k, v in e.items():
                        if SKIP_KEY.search(k):
                            continue
                        if isinstance(v, (list, dict)):
                            walk(v, k, e, finding_list)
                elif isinstance(e, list):
                    walk(e, key, parent, finding_list)

    walk(doc, "", None, False)
    return recs


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
        try:
            doc = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            continue
        docs[name] = doc
        if isinstance(doc, dict) and doc.get("bomFormat") == "CycloneDX":
            recs += read_cyclonedx(doc, name)
        elif isinstance(doc, dict) and ("@graph" in doc or "spdx" in str(doc.get("@context"))):
            recs += read_spdx3(doc, name)
        elif isinstance(doc, dict) and "spdxVersion" in doc:
            recs += read_spdx2(doc, name)
        elif isinstance(doc, dict) and "runs" in doc and "$schema" in doc:
            recs += read_sarif(doc, name)
        else:
            recs += read_generic(doc, name)
    return recs, docs, raw


# ------------------------------------------------------------------------- checks


def has(text: str, needles: list[str]) -> bool:
    return any(n.lower() in text for n in needles)


def informative(r: Rec) -> bool:
    return r.severity != "info"


def score_component(item: dict[str, Any], recs: list[Rec]) -> tuple[float, dict[str, Any]]:
    hits = [r for r in recs if r.kind == "component" and has(r.text, item["match"])]
    ev: dict[str, Any] = {"detected": bool(hits), "records": len(hits)}
    if not hits:
        return 0.0, ev
    earned = float(item["weight"])
    blob = " ".join(r.text for r in hits)
    for chk in item["checks"]:
        ok = has(blob, chk["any_of"])
        ev[chk["id"]] = ok
        earned += chk["weight"] if ok else 0
    return earned, ev


AGGREGATE_LIMIT = 3


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
        if informative(r) and has(r.text, item["match"])
        and has(r.text, item.get("keywords", []))
    ]  # fmt: skip
    return (float(item["weight"]) if hits else 0.0), {"detected": bool(hits)}


def possible(item: dict[str, Any]) -> float:
    return float(item["weight"]) + sum(c["weight"] for c in item.get("checks", []))


def volatile_normalize(obj: Any, subs: list[tuple[str, str]]) -> Any:
    if isinstance(obj, dict):
        return {
            k: volatile_normalize(v, subs) for k, v in obj.items() if not VOLATILE_KEY.search(k)
        }
    if isinstance(obj, list):
        return [volatile_normalize(v, subs) for v in obj]
    if isinstance(obj, str):
        s = obj
        for a, b in subs:
            s = s.replace(a, b)
        s = UUID.sub("<uuid>", s)
        return ISO_TIME.sub("<time>", s)
    return obj


def text_normalize(data: bytes, subs: list[tuple[str, str]]) -> str:
    s = data.decode("utf-8", "replace")
    for a, b in subs:
        s = s.replace(a, b)
    s = UUID.sub("<uuid>", s)
    s = ISO_TIME.sub("<time>", s)
    return re.sub(r"\d+(\.\d+)?\s*(ms|s|sec|seconds)\b", "<dur>", s)


def egress(strace_files: list[Path]) -> list[str]:
    dests = set()
    pat4 = re.compile(r"sa_family=AF_INET,.*?htons\((\d+)\).*?inet_addr\(\"([\d.]+)\"\)")
    pat6 = re.compile(r"sa_family=AF_INET6,.*?htons\((\d+)\).*?\"([0-9a-f:.]+)\"")
    for f in strace_files:
        for line in f.read_text(errors="replace").splitlines():
            if "connect(" not in line:
                continue
            m = pat4.search(line) or pat6.search(line)
            if m:
                port, addr = m.group(1), m.group(2)
                if addr.startswith("127.") or addr in ("::1", "0.0.0.0", "::"):  # noqa: S104
                    continue
                dests.add(f"{addr}:{port}")
    return sorted(dests)


class ToolRun:
    def __init__(self, runs: Path, tool: str, scenarios: list[str]) -> None:
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

    def r(self, scn: str) -> list[Rec]:
        return self.recs.get(scn, [])


def cdx_validator() -> Any:
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError:
        return None
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


def standards(item: dict[str, Any], run: ToolRun, validate: Any) -> tuple[float, dict[str, Any]]:
    kind, w = item["kind"], float(item["weight"])
    main = {k: v for k, v in run.docs.items() if "#" not in k}
    # An empty document conforms trivially; only documents that inventory something count.
    cdx = [(s, n, d) for s, docs in main.items() for n, d in docs.items()
           if isinstance(d, dict) and d.get("bomFormat") == "CycloneDX"
           and (d.get("components") or d.get("services"))]  # fmt: skip
    if kind == "cyclonedx_valid":
        if not cdx or validate is None:
            return 0.0, {"cyclonedx_documents": len(cdx)}
        errors = {f"{s}/{n}": validate(d) for s, n, d in cdx}
        bad = {k: v for k, v in errors.items() if v}
        return w * (1 - len(bad) / len(errors)), {"documents": len(errors), "invalid": bad}
    if kind == "spdx3_present":
        spdx3 = [(s, d) for s, docs in main.items() for d in docs.values()
                 if isinstance(d, dict) and "spdx.org/rdf/3" in json.dumps(d.get("@context"))]  # fmt: skip
        if not spdx3:
            return 0.0, {"spdx3_documents": 0}
        ai = any(re.search(r"(ai_aipackage|\"aipackage\"|dataset_datasetpackage|"
                           r"\"datasetpackage\")", dumps(d)) for s, d in spdx3
                 if s in ("s01-models", "s03-data", "s02-model-refs"))  # fmt: skip
        return w * (0.5 + (0.5 if ai else 0)), {"spdx3_documents": len(spdx3), "ai_profile": ai}
    if kind == "mlbom_semantics":
        model = any('"type": "machine-learning-model"' in json.dumps(d) for s, _, d in cdx
                    if s in ("s01-models", "s02-model-refs"))  # fmt: skip
        data = any('"type": "data"' in json.dumps(d) for s, _, d in cdx if s == "s03-data")
        return w * (0.5 * model + 0.5 * data), {"ml_model_type": model, "data_type": data}
    if kind == "purl_valid":
        purls: list[str] = []

        def collect(node: Any) -> None:
            if isinstance(node, dict):
                for v in node.values():
                    collect(v)
            elif isinstance(node, list):
                for v in node:
                    collect(v)
            elif isinstance(node, str) and node.startswith("pkg:"):
                purls.append(node)

        for docs in main.values():
            for d in docs.values():
                if isinstance(d, dict) and (
                    d.get("bomFormat") or "@graph" in d or "spdxVersion" in d or "elements" in d
                ):
                    collect(d)  # fmt: skip
        if not purls:
            return 0.0, {"purls": 0}
        bad = sorted({p for p in purls if not PURL.match(p)})
        hf = any(p.startswith("pkg:huggingface/") for p in purls)
        frac = 1 - len([p for p in purls if not PURL.match(p)]) / len(purls)
        return w * (0.5 * frac + 0.5 * hf), {"purls": len(purls), "invalid": bad[:10],
                                             "huggingface_purl": hf}  # fmt: skip
    if kind == "refs_resolve":
        if not cdx:
            return 0.0, {}
        with_deps, clean = 0, 0
        for _, _, d in cdx:
            refs = set(re.findall(r'"bom-ref": "([^"]+)"', json.dumps(d)))
            deps = d.get("dependencies") or []
            used = [x.get("ref") for x in deps if isinstance(x, dict)]
            used += [y for x in deps if isinstance(x, dict) for y in x.get("dependsOn") or []]
            for v in d.get("vulnerabilities") or []:
                used += [a.get("ref") for a in v.get("affects") or [] if isinstance(a, dict)]
            if any((x or {}).get("dependsOn") for x in deps if isinstance(x, dict)):
                with_deps += 1
            meta_ref = ((d.get("metadata") or {}).get("component") or {}).get("bom-ref")
            if all(u in refs or u == meta_ref for u in used if u):
                clean += 1
        return w * (0.5 * (with_deps > 0) + 0.5 * clean / len(cdx)), {
            "documents_with_dependency_edges": with_deps,
            "documents_all_refs_resolve": clean,
        }
    if kind == "deterministic":
        same, total, diffs = 0, 0, []
        for scn in ("s01-models", "s04-mcp"):
            if not any(r.kind == "component" for r in run.r(scn)):
                continue
            a, b = run.raw.get(scn, {}), run.raw.get(scn + "#2", {})
            subs = [(str(run.root / (scn + "#2")), "<out>"), (str(run.root / scn), "<out>"),
                    (str(run.root.parent / "_home" / run.tool / (scn + "#2")), "<home>"),
                    (str(run.root.parent / "_home" / run.tool / scn), "<home>")]  # fmt: skip
            for name, data in a.items():
                if name.startswith("_cmd") or name not in b:
                    continue
                total += 1
                try:
                    x = volatile_normalize(json.loads(data), subs)
                    y = volatile_normalize(json.loads(b[name]), subs)
                    ok = x == y
                except ValueError:
                    ok = text_normalize(data, subs) == text_normalize(b[name], subs)
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
        found = [c for c in (run.meta.get(scn, {}).get("canaries") or [])
                 if c in item["canaries"]]  # fmt: skip
        return (0.0 if found else w), {"canaries_written": found}
    if kind == "outside_absent":
        leaked = [n for n, d in run.raw.get(scn, {}).items()
                  if any(t.encode() in d for t in item["match"])]  # fmt: skip
        return (0.0 if leaked else w), {"leaked_in": leaked}
    if kind == "ansi_absent":
        hits = [n for n, d in run.raw.get(scn, {}).items()
                if any(p.encode() in d for p in item["patterns"])]  # fmt: skip
        return (0.0 if hits else w), {"raw_escape_in": hits}
    if kind == "completes":
        cmds = run.meta.get(scn, {}).get("commands") or []
        bad = [c["argv"][0] for c in cmds if c["timed_out"]]
        return (0.0 if bad or not cmds else w), {"timed_out": bool(bad),
                                                 "seconds": [c["seconds"] for c in cmds]}  # fmt: skip
    if kind == "bounded_memory":
        cmds = run.meta.get(scn, {}).get("commands") or []
        peak = max((c["max_rss_bytes"] for c in cmds), default=0)
        return (w if cmds and peak < item["limit_bytes"] else 0.0), {"peak_rss_mib": peak >> 20}
    if kind == "secret_absent":
        leaked = []
        for tag, files in run.raw.items():
            if tag.split("#")[0] != scn:
                continue
            for n, d in files.items():
                if any(s.encode() in d for s in truth["safety"]["secrets"]):
                    leaked.append(f"{tag}/{n}")
        return (0.0 if leaked else w), {"leaked_in": leaked}
    if kind == "no_egress":
        d = run.root / "s04-mcp#default"
        files = sorted(d.glob("*.strace")) if d.exists() else []
        if not files:
            files = sorted((run.root / "s04-mcp").glob("*.strace"))
        dests = egress(files)
        return (0.0 if dests else w), {"connect_attempts": dests}
    raise ValueError(kind)


def drift(item: dict[str, Any], run: ToolRun, truth: dict[str, Any]) -> tuple[float, dict]:
    """Compare the records of one tool before (baseline) and after one description change.

    drift_changed: some record naming the changed tool must differ (a server-level
    record that embeds all its tools counts). drift_stable: a record specific to the
    unchanged tool (naming it but not the changed tool) must be identical, so a
    reviewer can tell which tool changed. A tool that only records the server cannot
    localise the change and fails drift_stable.
    """
    subs = [(item["scenario"], "<scn>"), (item["baseline"], "<scn>")]
    exclude: list[str] = []
    if item["kind"] == "drift_stable":
        exclude = [m for i in truth["items"] if i["kind"] == "drift_changed"
                   and i["scenario"] == item["scenario"] for m in i["match"]]  # fmt: skip

    def records(scn: str) -> list[str]:
        return sorted(
            json.dumps(volatile_normalize(json.loads(r.text), subs), sort_keys=True)
            for r in run.r(scn) if r.kind == "component" and has(r.text, item["match"])
            and not (exclude and has(r.text, exclude)) and r.text.startswith("{")
        )  # fmt: skip

    a, b = records(item["baseline"]), records(item["scenario"])
    if not a or not b:
        return 0.0, {"present": False}
    changed = a != b
    ok = changed if item["kind"] == "drift_changed" else not changed
    ev: dict[str, Any] = {"present": True, "changed": changed}
    if item["kind"] == "drift_stable" and changed:
        # Records may legitimately embed file-level provenance that changes with any
        # tool in the file. Still pass when a per-tool fingerprint survived unchanged
        # and is not shared with the changed tool's records.
        def digests(texts: list[str]) -> set[str]:
            return {d for t in texts for d in HEX_DIGEST.findall(t)}

        changed_tool = [r.text for scn in (item["baseline"], item["scenario"])
                        for r in run.r(scn) if r.kind == "component" and has(r.text, exclude)]  # fmt: skip
        kept = (digests(a) & digests(b)) - digests(changed_tool)
        ok = bool(kept)
        ev["stable_fingerprint"] = bool(kept)
    return (float(item["weight"]) if ok else 0.0), ev


def grade(score: float) -> str:
    return next(g for floor, g in GRADE_BANDS if score >= floor)


def score_tool(truth: dict[str, Any], run: ToolRun, validate: Any,
               declared: list[str]) -> dict[str, Any]:  # fmt: skip
    domains = {d: {"earned": 0.0, "possible": 0.0, "penalty": 0.0} for d in truth["domains"]}
    items_out, gates = [], []
    tokens: dict[str, list[str]] = {}
    for item in truth["items"]:
        if item["kind"] in ("component", "negative_component"):
            tokens.setdefault(item["scenario"], []).extend(m.lower() for m in item["match"])
    specific = {
        s["id"]: specific_findings(
            run.r(s["id"]), tokens.get(s["id"]) or tokens.get(s["id"].replace("-v2", "-v1"), [])
        )
        for s in truth["scenarios"]
    }
    for item in truth["items"]:
        kind, dom = item["kind"], domains[item["domain"]]
        if kind == "component":
            got, ev = score_component(item, run.r(item["scenario"]))
            dom["possible"] += possible(item)
            dom["earned"] += got
        elif kind == "finding":
            got, ev = score_finding(item, specific.get(item["scenario"], []))
            dom["possible"] += possible(item)
            dom["earned"] += got
        elif kind in ("negative_component", "negative_finding"):
            if kind == "negative_component":
                hit = any(r.kind == "component" and has(r.text, item["match"])
                          for r in run.r(item["scenario"]))  # fmt: skip
            else:
                hit = any(r.severity in ("high", "critical") and has(r.text, item["match"])
                          for r in specific.get(item["scenario"], []))  # fmt: skip
            got, ev = (-float(item["weight"]) if hit else 0.0), {"false_positive": hit}
            dom["penalty"] += -got
        elif kind.startswith("drift_"):
            got, ev = drift(item, run, truth)
            dom["possible"] += possible(item)
            dom["earned"] += got
        elif item["domain"] == "standards":
            got, ev = standards(item, run, validate)
            dom["possible"] += possible(item)
            dom["earned"] += got
        else:
            got, ev = safety(item, run, truth)
            dom["possible"] += possible(item)
            dom["earned"] += got
            if item.get("gate") and got < float(item["weight"]):
                gates.append({"item": item["id"], "cap": item["gate"], "title": item["title"]})
        items_out.append({"id": item["id"], "domain": item["domain"], "kind": kind,
                          "title": item["title"], "earned": round(got, 2),
                          "possible": possible(item) if not kind.startswith("negative") else 0,
                          "evidence": ev})  # fmt: skip
    # Safety credit requires a functioning scan: a tool that never parsed the hostile
    # scenario (its benign sentinel is missing) is not shown to be safe on it. Gates
    # still apply whenever a check fails.
    detected = {i["id"]: i["evidence"].get("detected") for i in items_out}
    for out in items_out:
        req = next((i.get("requires") for i in truth["items"] if i["id"] == out["id"]), None)
        if req and not detected.get(req) and out["earned"] > 0:
            domains[out["domain"]]["earned"] -= out["earned"]
            out["earned"] = 0.0
            out["evidence"]["not_exercised"] = f"{req} not detected"
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
    for g in sorted(gates, key=lambda x: GATE_ORDER[x["cap"]]):
        if "ABCDF".index(final) < "ABCDF".index(g["cap"]):
            final = g["cap"]
    return {
        "score": round(total, 1),
        "in_scope_score": round(100 * in_scope_num / in_scope_den, 1) if in_scope_den else None,
        "grade": final,
        "uncapped_grade": raw_grade,
        "gates": gates,
        "domains": domains,
        "items": items_out,
    }


def scorecard(results: dict[str, Any]) -> str:
    doms = list(results["domains"])
    head = ["Rank", "Tool", "Version", "Grade", "Score", "In-scope"] + doms + ["Gates"]
    lines = [
        f"# AIBOM-Bench {results['version']} scorecard",
        "",
        f"Seed `{results['seed']}`, corpus digest `{results['corpus_digest'][:16]}`. "
        "Domain columns are percentages; Score is the weighted total out of 100.",
        "",
        "| " + " | ".join(head) + " |",
        "|"
        + "|".join("---:" if h not in ("Tool", "Version", "Gates") else "---" for h in head)
        + "|",
    ]
    ranked = sorted(results["tools"].items(), key=lambda kv: -(kv[1].get("score") or -1))
    for rank, (_, e) in enumerate(ranked, 1):
        if e.get("grade") == "N/R":
            lines.append(f"| – | {e['display']} | – | N/R | – | – | " + " | ".join("–" for _ in doms)
                         + " | not run |")  # fmt: skip
            continue
        gates = ", ".join(f"{g['item']}→{g['cap']}" for g in e["gates"]) or "–"
        grade_cell = e["grade"] + (f" (was {e['uncapped_grade']})"
                                   if e["grade"] != e["uncapped_grade"] else "")  # fmt: skip
        cells = [str(rank), e["display"], str(e.get("version", "?")).replace("|", "/"),
                 grade_cell, f"{e['score']:.1f}", f"{e['in_scope_score']:.1f}"]  # fmt: skip
        cells += [f"{e['domains'][d]['pct']:.0f}" for d in doms] + [gates]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
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
    scenarios = [s["id"] for s in truth["scenarios"]]
    results: dict[str, Any] = {"benchmark": truth["benchmark"], "version": truth["version"],
                               "seed": truth["seed"], "corpus_digest": truth["corpus_digest"],
                               "domains": truth["domains"], "tools": {}}  # fmt: skip
    for name, spec in tools.items():
        entry: dict[str, Any] = {"display": spec.get("display", name), "source": spec.get("source"),
                                 "mode_note": spec.get("mode_note")}  # fmt: skip
        if not spec.get("runnable", True):
            entry.update({"grade": "N/R", "not_run_reason": spec["not_run_reason"]})
            results["tools"][name] = entry
            continue
        meta_path = args.runs / name / "_tool.json"
        entry["version"] = (
            json.loads(meta_path.read_text())["version"] if meta_path.exists() else "?"
        )
        run = ToolRun(args.runs, name, scenarios)
        entry.update(score_tool(truth, run, validate, spec.get("declared_scope", [])))
        entry["runtime_seconds"] = round(sum(c["seconds"] for m in run.meta.values()
                                             for c in m["commands"]), 1)  # fmt: skip
        results["tools"][name] = entry
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    (args.out / "scorecard.md").write_text(scorecard(results))
    ranked = sorted(results["tools"].items(), key=lambda kv: -(kv[1].get("score") or -1))
    for name, e in ranked:
        print(f"{name:22} {e.get('grade', ''):4} {e.get('score', '-'):>6} "
              f"in-scope={e.get('in_scope_score', '-')} gates={[g['item'] for g in e.get('gates', [])]}")  # fmt: skip


if __name__ == "__main__":
    main()
