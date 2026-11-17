"""Two calibration tools that prove the scorer's range.

The oracle writes a document from the ground truth and must score 100. The null tool
writes a valid, empty document and must score 0. Neither is ranked.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from .build import ML_MODEL
from .model import Case, Corpus, Files
from .runner import Record, plan, run_dir
from .tools import OUT_NAMES, Tool

ORACLE = Tool("oracle", "Oracle (ground truth)", "-", "-", "built in", {"cdx": ("oracle",)})
NULL = Tool("null", "Null (empty document)", "-", "-", "built in", {"cdx": ("null",)})


def _tree_digest(files: Files) -> str:
    hasher = hashlib.sha256()
    for path in sorted(files):
        hasher.update(path.encode("utf-8", "surrogateescape") + b"\0")
        hasher.update(hashlib.sha256(files[path]).digest())
    return hasher.hexdigest()


def oracle_document(case: Case, files: Files) -> dict[str, object]:
    components: list[dict[str, object]] = []
    for expect in case.expects:
        component: dict[str, object] = {
            "type": "application",
            "bom-ref": f"ref-{expect.id}",
            "name": " ".join(expect.any_of[0]),
        }
        properties = [{"name": "bench:kind", "value": expect.kind}]
        for attr in expect.attrs:
            if attr.kind == "type":
                component["type"] = attr.values[0]
            elif attr.kind == "version":
                component["version"] = attr.values[0]
            elif attr.kind == "purl":
                component["purl"] = attr.values[0]
            elif attr.kind == "sha256":
                content = hashlib.sha256(files[attr.values[0]]).hexdigest()
                component["hashes"] = [{"alg": "SHA-256", "content": content}]
            elif attr.kind == "license":
                component["licenses"] = [{"license": {"id": attr.values[0]}}]
            else:
                properties.append({"name": f"bench:{attr.label}", "value": " ".join(attr.values)})
        component["properties"] = properties
        components.append(component)
    document: dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "ref-project",
                "name": "project",
                "properties": [{"name": "bench:tree", "value": _tree_digest(files)}],
            }
        },
        "components": components,
        "dependencies": [
            {"ref": f"ref-{edge.source}", "dependsOn": [f"ref-{edge.target}"]}
            for edge in case.edges
        ],
    }
    if case.id.endswith("-risky"):
        document["vulnerabilities"] = [{"id": "BENCH-CONDITION", "ratings": [{"severity": "high"}]}]
    return document


def null_document() -> dict[str, object]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}


def write(tool: Tool, corpus: Corpus, work: Path) -> None:
    """Write the runs a calibration tool would have produced."""
    for job in plan(tool, corpus):
        directory = run_dir(work, job)
        (directory / "out").mkdir(parents=True, exist_ok=True)
        files = job.case.files if job.files is None else job.files
        document = oracle_document(job.case, files) if tool is ORACLE else null_document()
        (directory / "out" / OUT_NAMES["cdx"]).write_text(json.dumps(document, indent=2))
        (directory / "stdout.bin").write_bytes(b"")
        (directory / "stderr.bin").write_bytes(b"")
        record = Record(tool.id, job.case.id, job.variant, job.fmt, [tool.id], exit_code=0)
        (directory / "record.json").write_text(json.dumps(asdict(record)))


__all__ = ["ML_MODEL", "NULL", "ORACLE", "null_document", "oracle_document", "write"]
