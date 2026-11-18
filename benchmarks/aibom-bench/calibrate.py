#!/usr/bin/env python3
"""Calibrate the scorer with synthetic tools.

- oracle: writes exactly the ground truth as one CycloneDX file and one SARIF file
  per scenario. It should earn full marks on every detection domain.
- empty: writes valid but empty documents. It should earn nothing.
- cat: dumps every file of the scenario, path and full contents, as JSON records.
  It understands nothing, so it must stay near the floor.
- lister: reports every file path with its SHA-256, like a file-system SBOM.
  It gets credit only where a path alone identifies a component of the right kind.

A scorer change that moves any of these numbers needs an explanation in SPEC.md.

    python3 calibrate.py --corpus /opt/aibom-bench/corpus --work /tmp/aibom-calibration
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
KIND = {"models": "model", "data": "dataset", "mcp": "mcp server", "tooldefs": "mcp tool",
        "skills": "agent skill", "agents": "agent", "packages": "package",
        "safety": "mcp server model"}  # fmt: skip


def oracle_documents(gt: dict[str, Any], scn: str) -> tuple[dict[str, Any], dict[str, Any]]:
    comps: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for it in gt["items"]:
        if it.get("scenario") not in (scn, scn.replace("-v2", "-v1")):
            continue
        if it["kind"] == "component":
            typ = {"models": "machine-learning-model", "data": "data"}.get(it["domain"], "library")
            props = [{"name": c["id"], "value": c["any_of"][0]} for c in it["checks"]]
            if scn.endswith("-v2") and it["id"] == "T04":
                props.append({"name": "definition-digest", "value": "changed"})
            comps.append({"type": typ, "name": it["match"][0], "bom-ref": it["id"],
                          "description": KIND[it["domain"]], "properties": props})  # fmt: skip
        elif it["kind"] == "finding":
            text = f"{it['match'][0]}: {it['keywords'][0]}"
            results.append({"ruleId": it["id"], "level": "error", "message": {"text": text}})
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "oracle", "version": "1"}]}
        },  # fmt: skip
        "components": comps,
        "dependencies": [{"ref": c["bom-ref"], "dependsOn": []} for c in comps],
    }
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "oracle"}}, "results": results}],
    }
    return bom, sarif


def file_records(scn_dir: Path, with_content: bool) -> list[dict[str, Any]]:
    out = []
    for p in sorted(scn_dir.rglob("*")):
        if p.is_symlink() or not p.is_file() or p.stat().st_size > 1 << 20:
            continue
        data = p.read_bytes()
        rec: dict[str, Any] = {"path": str(p.relative_to(scn_dir)),
                               "sha256": hashlib.sha256(data).hexdigest()}  # fmt: skip
        if with_content:
            rec["content"] = data.decode("utf-8", "replace")
        out.append(rec)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--work", type=Path, required=True)
    args = ap.parse_args()
    gt = json.loads((args.corpus / "ground_truth.json").read_text())
    runs = args.work / "runs"
    run_record = {"commands": [{"argv": ["synthetic"], "exit": 0, "timed_out": False,
                                "seconds": 0, "max_rss_bytes": 0}], "canaries": []}  # fmt: skip
    tools = ("oracle", "empty", "cat", "lister")
    for tool in tools:
        (runs / tool).mkdir(parents=True, exist_ok=True)
        (runs / tool / "_tool.json").write_text(
            json.dumps({"version": "synthetic", "corpus_digest": gt["corpus_digest"]})
        )
        for s in gt["scenarios"]:
            tags = ["", "#default"] + (["#2"] if s["id"] in ("s01-models", "s04-mcp") else [])
            for tag in tags:
                d = runs / tool / (s["id"] + tag)
                d.mkdir(parents=True, exist_ok=True)
                (d / "_run.json").write_text(json.dumps(run_record))
                if tool in ("cat", "lister"):
                    recs = file_records(args.corpus / "scenarios" / s["id"], tool == "cat")
                    (d / "inventory.json").write_text(json.dumps({"components": recs}))
                    continue
                bom, sarif = oracle_documents(gt, s["id"])
                if tool == "empty":
                    bom["components"], bom["dependencies"], sarif["runs"][0]["results"] = [], [], []
                (d / "bom.cdx.json").write_text(json.dumps(bom))
                (d / "findings.sarif").write_text(json.dumps(sarif))
    spec = {"tools": {t: {"display": t, "declared_scope": list(gt["domains"])} for t in tools}}
    (args.work / "tools.json").write_text(json.dumps(spec))
    subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, str(HERE / "score.py"), "--corpus", str(args.corpus), "--runs",
         str(runs), "--tools", str(args.work / "tools.json"), "--out", str(args.work / "out")],
        check=True,
    )  # fmt: skip


if __name__ == "__main__":
    main()
