"""Scan another tree's two corpora with several source trees and compare each with main.

python3 accept.py BENCH CORPORA OUT PYTHON name=SRC [name=SRC ...]     (first name is the baseline)
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

BENCH, CORPORA, OUT, PYTHON = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
TREES = [arg.split("=", 1) for arg in sys.argv[5:]]
spec = importlib.util.spec_from_file_location("other_score", BENCH / "score.py")
other = importlib.util.module_from_spec(spec)
spec.loader.exec_module(other)
FORMATS = ("json", "cyclonedx", "spdx", "sarif")
UNSHARE = shutil.which("unshare") or "/usr/bin/unshare"


def scan(name: str, src: str, corpus: str) -> Path:
    out = OUT / corpus / name
    out.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "PYTHONPATH": src,
        "SOURCE_DATE_EPOCH": "1700000000",
        "HOME": str(OUT / "home"),
    }
    codes = {}
    for fmt in FORMATS:
        done = subprocess.run(  # noqa: S603
            [
                UNSHARE,
                "-rn",
                PYTHON,
                "-m",
                "nexus_symbiote.cli",
                "scan",
                str(CORPORA / corpus / "corpus"),
            ]
            + ["-f", fmt, "-o", str(out / f"bom.{fmt}.json")],
            env=env,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        codes[fmt] = done.returncode
        (out / f"{fmt}.stderr").write_text(done.stderr)
    risk = subprocess.run(  # noqa: S603
        [UNSHARE, "-rn", PYTHON, "-m", "nexus_symbiote.cli", "risk", str(out / "bom.json.json")],
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    (out / "risk.txt").write_text(risk.stdout + risk.stderr)
    (out / "codes.json").write_text(json.dumps({**codes, "risk": risk.returncode}))
    return out


def facts(out: Path, ground: dict) -> dict:
    blobs = {p.name: p.read_bytes() for p in sorted(out.glob("bom.*.json"))}
    text = "\n".join(other.strip_coverage(b).decode("utf-8", "replace") for b in blobs.values())
    lower = text.lower()
    inventory = json.loads(blobs["bom.json.json"])
    findings = Counter(
        (risk["category"], risk["severity"])
        for component in inventory["components"]
        for risk in component.get("risks") or []
    )
    completeness = inventory["metadata"]["completeness"]
    everything = (
        b"\n".join(blobs.values())
        + (out / "risk.txt").read_bytes()
        + b"".join(p.read_bytes() for p in out.glob("*.stderr"))
    )
    return {
        "hits": {c["id"] for c in ground["components"] if other.detect(text, lower, c) is not None},
        "decoys": {d["id"] for d in ground["decoys"] if other.detect(text, lower, d) is not None},
        "findings": findings,
        "components": Counter(c["component_type"] for c in inventory["components"]),
        "failures": len(completeness["scan_failures"]),
        "status": Counter(completeness["scanner_status"].values()),
        "leaks": sorted(k for k, v in ground["secrets"].items() if v.encode() in everything),
        "codes": json.loads((out / "codes.json").read_text()),
        "risk_tail": [
            line
            for line in (out / "risk.txt").read_text().splitlines()
            if "Risk Score" in line or "Gate" in line
        ][:3],
    }


for corpus, truth in (("A", "ground_truth.json"), ("B", "ground_truth_b.json")):
    ground = json.loads((BENCH / truth).read_text())
    results = {name: facts(scan(name, src, corpus), ground) for name, src in TREES}
    base_name = TREES[0][0]
    base = results[base_name]
    print(f"\n===== corpus {corpus}: {len(ground['components'])} components")
    print(
        f"{base_name}: hits {len(base['hits'])}, decoys {sorted(base['decoys'])}, failures {base['failures']}, "
        f"status {dict(base['status'])}, leaks {base['leaks']}, codes {base['codes']}, {base['risk_tail']}"
    )
    print(f"   findings: {dict(sorted((f'{c}/{s}', n) for (c, s), n in base['findings'].items()))}")
    for name, _ in TREES[1:]:
        cur = results[name]
        delta = {
            f"{c}/{s}": cur["findings"][(c, s)] - base["findings"][(c, s)]
            for (c, s) in sorted(set(cur["findings"]) | set(base["findings"]))
            if cur["findings"][(c, s)] != base["findings"][(c, s)]
        }
        comp = {
            k: cur["components"][k] - base["components"][k]
            for k in sorted(set(cur["components"]) | set(base["components"]))
            if cur["components"][k] != base["components"][k]
        }
        print(
            f"{name}: hits {len(cur['hits'])} (+{sorted(cur['hits'] - base['hits'])} -{sorted(base['hits'] - cur['hits'])}) "
            f"decoys +{sorted(cur['decoys'] - base['decoys'])} -{sorted(base['decoys'] - cur['decoys'])}"
        )
        print(
            f"   findings delta {delta}; components delta {comp}; failures {cur['failures']}; status {dict(cur['status'])}; "
            f"leaks {cur['leaks']}; codes {cur['codes']}; {cur['risk_tail']}"
        )
