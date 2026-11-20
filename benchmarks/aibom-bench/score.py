#!/usr/bin/env python3
"""Score AIBOM-Bench results.

    python score.py --results DIR --ground-truth ground_truth.json --schemas DIR --out scores.json

For every tool directory under ``--results`` it reads the outputs the runner
saved per mode and computes the automated parts of the benchmark: per-class
detection recall and decoy hits (D1), integrity digests and pins (D2),
schema validity and CycloneDX type usage (D4), expected-finding hints (D5),
secret leakage, neutralization, confined reads, execution and egress from the
strace log, corpus modification (D6), determinism (D7) and timing (D9). The
rest of the rubric is scored by a reviewer from these facts and the raw
outputs; the report says which is which.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

CONTROL = {
    "command",
    "exit",
    "seconds",
    "stderr",
    "strace.log",
    "corpus-delta.json",
    "home-writes.txt",
}
TEXT_MODES_PRIMARY = ("airgap", "network", "repeat")

TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
TIMING_RE = re.compile(
    r'"(?:[a-zA-Z_]*(?:elapsed|duration|took|time_ms|scan_time|timing|generated_at|timestamp|created)[a-zA-Z_]*)"\s*:\s*(?:"[^"]*"|[0-9.]+)'
)
CONNECT_RE = re.compile(r"connect\(\d+, \{sa_family=(AF_\w+)(.*?)\}, \d+\)\s*=\s*(-?\d+|\?)")
PORT_RE = re.compile(r"sin6?_port=htons\((\d+)\)")
INET_RE = re.compile(r'inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)"')
UNIX_RE = re.compile(r'sun_path="([^"]*)"')
EXECVE_RE = re.compile(r'execve\("([^"]+)", \[(.*?)\],.*?\)\s*=\s*(-?\d+)')
OPENAT_RE = re.compile(r'openat\(\w+, "([^"]+)", ([A-Z_|]+)(?:, \d+)?\)\s*=\s*(-?\d+)')


def read_bytes(p: Path) -> bytes:
    try:
        return p.read_bytes()
    except OSError:
        return b""


COVERAGE_KEYS = {
    "surfaces_scanned",
    "surfaces_excluded",
    "scan_failures",
    "files_scanned",
    "scanned_files",
    "traversal",
    "receipts",
    "issues",
    "scopes",
    "warnings",
    "errors",
    "logs",
    "coverage",
    "completeness",
    "scan_run",
    "files",
    "file_list",
    "excluded",
    "skipped",
}


def strip_coverage(data: bytes) -> bytes:
    """Remove keys that describe what a tool looked at, so that only what it
    reported as a component, finding or relationship can satisfy a match."""
    try:
        doc = json.loads(data)
    except Exception:  # noqa: BLE001
        return data

    def walk(o):
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items() if k not in COVERAGE_KEYS}
        if isinstance(o, list):
            return [walk(x) for x in o]
        return o

    return json.dumps(walk(doc), ensure_ascii=False).encode()


def outputs(mode_dir: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for p in sorted(mode_dir.iterdir()):
        if p.name in CONTROL or p.is_dir():
            continue
        out[p.name] = read_bytes(p)
    return out


def normalize(data: bytes) -> bytes:
    text = data.decode("utf-8", "replace")
    text = TS_RE.sub("<ts>", text)
    text = UUID_RE.sub("<uuid>", text)
    text = TIMING_RE.sub('"<timing>": 0', text)
    return text.encode()


def detect(blob: str, blob_lower: str, item: dict) -> str | None:
    for s in item.get("match_any", []):
        if s.lower() in blob_lower:
            return s
    rx = item.get("match_regex")
    if rx and re.search(rx, blob):
        return rx
    return None


def strace_summary(path: Path, corpus_hint: str, proxy_port: str | None = None) -> dict:
    if not path.exists():
        return {"available": False}
    inet: dict[str, int] = defaultdict(int)
    unix: dict[str, int] = defaultdict(int)
    execs: dict[str, int] = defaultdict(int)
    exec_from_corpus: list[str] = []
    symlink_opens: list[dict] = []
    passwd_opens = 0
    big_opens = 0
    for line in path.read_text(errors="replace").splitlines():
        m = CONNECT_RE.search(line)
        if m:
            fam, rest, ret = m.groups()
            if fam in ("AF_INET", "AF_INET6"):
                a = INET_RE.search(rest)
                addr = (a.group(1) or a.group(2)) if a else "?"
                pm = PORT_RE.search(rest)
                port = pm.group(1) if pm else "?"
                inet[f"{fam} {addr}:{port} ret={ret}"] += 1
            elif fam == "AF_UNIX":
                u = UNIX_RE.search(rest)
                unix[(u.group(1) if u else "?") + f" ret={ret}"] += 1
            continue
        m = EXECVE_RE.search(line)
        if m:
            exe, argv, ret = m.groups()
            if ret == "0":
                execs[exe] += 1
                if corpus_hint in exe or corpus_hint in argv:
                    exec_from_corpus.append(f"{exe} {argv[:200]}")
            continue
        m = OPENAT_RE.search(line)
        if m:
            p, flags, ret = m.groups()
            if "secrets-link" in p or "escape.gguf" in p or "vendor/loop" in p:
                symlink_opens.append(
                    {
                        "path": p.split("/corpus/")[-1],
                        "flags": flags,
                        "ret": int(ret),
                        "followed": "O_NOFOLLOW" not in flags and int(ret) >= 0,
                    }
                )
            elif p == "/etc/passwd":
                passwd_opens += 1
            elif "embeddings.bin" in p:
                big_opens += 1

    def is_egress(key: str) -> bool:
        addr, port = key.split()[1].rsplit(":", 1)
        loop = addr.startswith("127.") or addr in ("::1", "0.0.0.0", "::")  # noqa: S104
        return (not loop) or (proxy_port is not None and port == proxy_port)

    nonloop = {k: v for k, v in inet.items() if is_egress(k)}
    return {
        "available": True,
        "proxy_port": proxy_port,
        "inet_connects": dict(inet),
        "nonloopback_connects": nonloop,
        "unix_connects": dict(unix),
        "execve": dict(execs),
        "execve_from_corpus": exec_from_corpus,
        "symlink_opens": symlink_opens,
        "etc_passwd_opens": passwd_opens,
        "large_file_opens": big_opens,
    }


def load_schemas(schemas: Path):
    import jsonschema
    from referencing import Registry, Resource

    def res(name):
        return Resource.from_contents(json.loads((schemas / name).read_text()))

    registry = Registry().with_resources(
        [
            ("http://cyclonedx.org/schema/spdx.schema.json", res("spdx.schema.json")),
            ("http://cyclonedx.org/schema/jsf-0.82.schema.json", res("jsf-0.82.schema.json")),
            (
                "http://cyclonedx.org/schema/cryptography-defs.schema.json",
                res("cryptography-defs.schema.json"),
            ),
        ]
    )
    cdx = {
        "1.5": jsonschema.Draft7Validator(
            json.loads((schemas / "bom-1.5.schema.json").read_text()), registry=registry
        ),
        "1.6": jsonschema.Draft7Validator(
            json.loads((schemas / "bom-1.6.schema.json").read_text()), registry=registry
        ),
        "1.7": jsonschema.Draft7Validator(
            json.loads((schemas / "bom-1.7.schema.json").read_text()), registry=registry
        ),
    }
    sarif = jsonschema.Draft4Validator(
        json.loads((schemas / "sarif-schema-2.1.0.json").read_text())
    )
    spdx3 = jsonschema.Draft202012Validator(
        json.loads((schemas / "spdx-json-schema-3.0.1.json").read_text())
    )
    return cdx, sarif, spdx3


def validate_doc(name: str, data: bytes, validators) -> dict | None:
    try:
        doc = json.loads(data)
    except Exception as exc:  # noqa: BLE001
        if name.endswith((".json", ".sarif", ".cdx.json")):
            return {"file": name, "kind": "unparseable", "valid": False, "error": str(exc)[:200]}
        return None
    cdx, sarif, spdx3 = validators
    result: dict = {"file": name}
    if isinstance(doc, dict) and doc.get("bomFormat") == "CycloneDX":
        ver = str(doc.get("specVersion"))
        result["kind"] = f"cyclonedx-{ver}"
        v = cdx.get(ver)
        if v is None:
            result["valid"] = None
            result["error"] = f"no validator for specVersion {ver}"
        else:
            errs = list(v.iter_errors(doc))
            result["valid"] = not errs
            result["error_count"] = len(errs)
            result["first_errors"] = [
                f"{'/'.join(str(x) for x in e.path)}: {e.message[:160]}" for e in errs[:3]
            ]
        comps = doc.get("components", []) or []
        types = defaultdict(int)
        for c in comps:
            types[c.get("type", "?")] += 1
        result["components"] = len(comps)
        result["services"] = len(doc.get("services", []) or [])
        result["component_types"] = dict(types)
        result["with_purl"] = sum(1 for c in comps if c.get("purl"))
        result["with_hashes"] = sum(1 for c in comps if c.get("hashes"))
        result["with_evidence"] = sum(1 for c in comps if c.get("evidence"))
        result["with_modelcard"] = sum(1 for c in comps if c.get("modelCard"))
        result["with_properties"] = sum(1 for c in comps if c.get("properties"))
        result["dependencies"] = len(doc.get("dependencies", []) or [])
        result["vulnerabilities"] = len(doc.get("vulnerabilities", []) or [])
        result["has_formulation"] = bool(doc.get("formulation"))
        result["has_compositions"] = bool(doc.get("compositions"))
        result["has_annotations"] = bool(doc.get("annotations"))
        return result
    if isinstance(doc, dict) and "@context" in doc:
        result["kind"] = "spdx-3"
        errs = list(spdx3.iter_errors(doc))
        result["valid"] = not errs
        result["error_count"] = len(errs)
        result["first_errors"] = [
            f"{'/'.join(str(x) for x in e.path)}: {e.message[:160]}" for e in errs[:3]
        ]
        types = defaultdict(int)
        for n in doc.get("@graph") or [doc] + list(
            doc.get("element", [])
            if isinstance(doc.get("element"), list)
            and doc["element"]
            and isinstance(doc["element"][0], dict)
            else []
        ):
            types[n.get("type", "?")] += 1
        result["flat_document"] = "@graph" not in doc
        result["node_types"] = dict(types)
        result["ai_profile"] = any(t.startswith("ai_") for t in types)
        result["dataset_profile"] = any(t.startswith("dataset_") for t in types)
        return result
    if isinstance(doc, dict) and doc.get("spdxVersion"):
        result["kind"] = f"spdx-2 ({doc.get('spdxVersion')})"
        result["valid"] = None
        return result
    if isinstance(doc, dict) and doc.get("version") == "2.1.0" and "runs" in doc:
        result["kind"] = "sarif-2.1.0"
        errs = list(sarif.iter_errors(doc))
        result["valid"] = not errs
        result["error_count"] = len(errs)
        result["first_errors"] = [
            f"{'/'.join(str(x) for x in e.path)}: {e.message[:160]}" for e in errs[:3]
        ]
        results = [r for run in doc.get("runs", []) for r in run.get("results", [])]
        result["results"] = len(results)
        result["results_with_location"] = sum(1 for r in results if r.get("locations"))
        result["rules"] = sum(
            len(run.get("tool", {}).get("driver", {}).get("rules", []))
            for run in doc.get("runs", [])
        )
        return result
    return None


def score_tool(
    tool_dir: Path,
    gt: dict,
    validators,
    proxy_port: str | None,
    overrides: dict,
    strict: bool = False,
) -> dict:
    modes = {p.name: p for p in sorted(tool_dir.iterdir()) if p.is_dir()}
    per_mode: dict[str, dict] = {}
    all_outputs: dict[str, bytes] = {}
    for mode, mdir in modes.items():
        outs = outputs(mdir)
        info = {
            "exit": (mdir / "exit").read_text().strip() if (mdir / "exit").exists() else None,
            "seconds": float((mdir / "seconds").read_text())
            if (mdir / "seconds").exists()
            else None,
            "outputs": {k: len(v) for k, v in outs.items()},
            "corpus_delta": json.loads((mdir / "corpus-delta.json").read_text())
            if (mdir / "corpus-delta.json").exists()
            else None,
            "home_writes": (mdir / "home-writes.txt").read_text().split()
            if (mdir / "home-writes.txt").exists()
            else [],
        }
        if (mdir / "strace.log").exists():
            info["strace"] = strace_summary(mdir / "strace.log", "/corpus/", proxy_port)
        info["schema"] = [r for r in (validate_doc(n, d, validators) for n, d in outs.items()) if r]
        per_mode[mode] = info
        for n, d in outs.items():
            all_outputs[f"{mode}/{n}"] = d

    if strict:
        all_outputs = {
            k: strip_coverage(v) for k, v in all_outputs.items() if k.split("/")[-1] != "stderr"
        }
    blob = "\n".join(d.decode("utf-8", "replace") for d in all_outputs.values())
    blob_lower = blob.lower()

    # D1 detection
    classes = gt["classes"]
    class_weights = {
        "mcp-server": 3,
        "tool": 2,
        "skill": 2,
        "prompt": 2,
        "model": 3,
        "model-file": 2,
        "dataset": 2,
        "training": 1,
        "vector-store": 1,
        "a2a": 1,
        "agent-config": 2,
        "ci-agent": 1,
        "container": 1,
        "package": 1,
        "guardrail": 0.5,
    }
    hits: dict[str, dict] = {}
    per_class_num: dict[str, float] = defaultdict(float)
    per_class_den: dict[str, float] = defaultdict(float)
    for comp in gt["components"]:
        w = 0.5 if comp.get("soft") else 1.0
        m = detect(blob, blob_lower, comp)
        detected = m is not None
        note = None
        ov = overrides.get(comp["id"])
        if ov is not None:
            detected = bool(ov["detected"])
            note = ov["why"]
        hits[comp["id"]] = {
            "detected": detected,
            "matched": m,
            "soft": bool(comp.get("soft")),
            "override": note,
        }
        per_class_den[comp["class"]] += w
        if detected:
            per_class_num[comp["class"]] += w
    class_recall = {
        c: (per_class_num[c] / per_class_den[c] if per_class_den[c] else None) for c in classes
    }
    wsum = sum(class_weights[c] for c in classes if class_recall[c] is not None)
    weighted_recall = (
        sum(class_weights[c] * class_recall[c] for c in classes if class_recall[c] is not None)
        / wsum
    )
    decoy_hits = {}
    penalty = 0.0
    for d in gt["decoys"]:
        m = detect(blob, blob_lower, d)
        decoy_hits[d["id"]] = {"reported": m is not None, "kind": d["kind"]}
        if m:
            penalty += 0.5 if d["kind"] == "hard" else 0.25
    anchors = [(0.85, 4), (0.65, 3), (0.45, 2), (0.25, 1)]
    d1_anchor = next((s for thr, s in anchors if weighted_recall >= thr), 0)
    d1_score = max(0.0, d1_anchor - penalty)

    # D2 integrity digests and pins
    digests = {p: (h in blob_lower) for p, h in gt["integrity_digests"].items()}
    pins = {k: (v.lower() in blob_lower) for k, v in gt["pins"].items()}

    # D5 finding hints
    stderr_blob = "\n".join(
        (m / "stderr").read_text(errors="replace")
        for m in modes.values()
        if (m / "stderr").exists()
    )
    finding_hits = {}
    for f in gt["expected_findings"]:
        in_out = [h for h in f["hints"] if h.lower() in blob_lower]
        in_err = [h for h in f["hints"] if h.lower() in stderr_blob.lower()]
        finding_hits[f["id"]] = {
            "title": f["title"],
            "hints_in_outputs": in_out,
            "hints_in_stderr_only": [h for h in in_err if h not in in_out],
        }

    # D6 secrets, leak markers, neutralization
    secret_leaks = []
    for name, data in all_outputs.items():
        for sid, val in gt["secrets"].items():
            if val.encode() in data:
                secret_leaks.append({"file": name, "secret": sid})
    stderr_leaks = [sid for sid, val in gt["secrets"].items() if val in stderr_blob]
    passwd_leak = [
        n for n, d in all_outputs.items() if gt["leak_markers"]["etc-passwd"].encode() in d
    ]
    neut = {
        "raw_esc_files": [],
        "json_escaped_esc_files": [],
        "raw_rlo_files": [],
        "raw_zwsp_files": [],
    }
    for name, data in all_outputs.items():
        if b"\x1b[2K" in data:
            neut["raw_esc_files"].append(name)
        if b"\\u001b[2K" in data or b"\\u001B[2K" in data:
            neut["json_escaped_esc_files"].append(name)
        if "\u202e".encode() in data:
            neut["raw_rlo_files"].append(name)
        if "\u200b".encode() in data:
            neut["raw_zwsp_files"].append(name)
    stderr_raw_esc = "\x1b[2K" in stderr_blob

    # D7 determinism
    determinism = None
    if "airgap" in modes and "repeat" in modes:
        a, b = outputs(modes["airgap"]), outputs(modes["repeat"])
        files = sorted(set(a) | set(b))
        if len(files) > 1:
            files = [f for f in files if f != "stdout"]
        identical = [f for f in files if a.get(f) == b.get(f)]
        norm_identical = [
            f
            for f in files
            if f not in identical and normalize(a.get(f, b"")) == normalize(b.get(f, b""))
        ]
        differing = [f for f in files if f not in identical and f not in norm_identical]
        determinism = {
            "byte_identical": identical,
            "identical_after_normalization": norm_identical,
            "differ": differing,
        }
    net_vs_air = None
    if "airgap" in modes and "network" in modes:
        a, b = outputs(modes["airgap"]), outputs(modes["network"])
        net_vs_air = {
            f: (normalize(a.get(f, b"")) == normalize(b.get(f, b"")))
            for f in sorted(set(a) | set(b))
        }

    return {
        "modes": per_mode,
        "d1": {
            "weighted_recall": round(weighted_recall, 3),
            "class_recall": {
                c: (round(r, 3) if r is not None else None) for c, r in class_recall.items()
            },
            "anchor": d1_anchor,
            "decoy_penalty": penalty,
            "score": d1_score,
            "decoys": decoy_hits,
            "components": hits,
        },
        "d2": {"digests_present": digests, "pins_present": pins},
        "d5": {"finding_hints": finding_hits},
        "d6": {
            "secret_leaks_in_outputs": secret_leaks,
            "secret_leaks_in_stderr": stderr_leaks,
            "etc_passwd_in_outputs": passwd_leak,
            "neutralization": neut,
            "stderr_raw_esc": stderr_raw_esc,
        },
        "d7": {"determinism": determinism, "network_vs_airgap_equal": net_vs_air},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True, type=Path)
    ap.add_argument(
        "--ground-truth", default=Path(__file__).with_name("ground_truth.json"), type=Path
    )
    ap.add_argument("--schemas", required=True, type=Path)
    ap.add_argument(
        "--strict",
        action="store_true",
        help="match only against components, findings and relationships: coverage and log keys are stripped from JSON outputs first",
    )
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument(
        "--overrides", default=Path(__file__).with_name("review_overrides.json"), type=Path
    )
    ap.add_argument(
        "--proxy-port",
        default=None,
        help="port of the loopback egress proxy the traced run used (connects to it count as egress)",
    )
    args = ap.parse_args()
    gt = json.loads(args.ground_truth.read_text())
    validators = load_schemas(args.schemas)
    overrides_all: dict[str, dict[str, dict]] = defaultdict(dict)
    if args.overrides.exists() and args.overrides.read_text().strip():
        for ov in json.loads(args.overrides.read_text())["overrides"]:
            overrides_all[ov["tool"]][ov["id"]] = ov
    scores = {}
    for tool_dir in sorted(p for p in args.results.iterdir() if p.is_dir()):
        scores[tool_dir.name] = score_tool(
            tool_dir,
            gt,
            validators,
            args.proxy_port,
            overrides_all.get(tool_dir.name, {}),
            args.strict,
        )
    args.out.write_text(json.dumps(scores, indent=2, sort_keys=True) + "\n")
    print(
        f"{'tool':18} {'recall':>7} {'D1':>4} {'decoys':>6} {'leaks':>5} {'passwd':>6} {'rawESC':>6} {'determ':>7} {'net':>4}"
    )
    for tool, s in scores.items():
        det = s["d7"]["determinism"]
        dsum = (
            "n/a"
            if det is None
            else (
                "byte"
                if not det["identical_after_normalization"] and not det["differ"]
                else ("norm" if not det["differ"] else "DIFF")
            )
        )
        nl = s["modes"].get("network", {}).get("strace", {}).get("nonloopback_connects", {})
        print(
            f"{tool:18} {s['d1']['weighted_recall']:>7.3f} {s['d1']['score']:>4} {sum(1 for d in s['d1']['decoys'].values() if d['reported']):>6} "
            f"{len(s['d6']['secret_leaks_in_outputs']):>5} {len(s['d6']['etc_passwd_in_outputs']):>6} {len(s['d6']['neutralization']['raw_esc_files']):>6} {dsum:>7} {len(nl):>4}"
        )


if __name__ == "__main__":
    main()
