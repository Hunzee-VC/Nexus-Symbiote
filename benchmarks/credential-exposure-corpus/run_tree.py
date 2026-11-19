"""Run one source tree over the corpus and record findings and value disclosure per case.

    cd <tree root> && HOME=<empty dir> PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
        python -B run_tree.py <label> <corpus dir> <results.jsonl> [first-id last-id]

Every command is the tree's own CLI, called in this process through click's CliRunner
(`nexus_symbiote.cli.main`, the function the `nexus-symbiote` entry point calls):

    scan --no-project-policy --report-only -f json|cyclonedx|spdx|sarif -o <file> <project>
    vex -o <file> <inventory.json>
    risk --no-project-policy <inventory.json>            (text)
    risk --no-project-policy --json-output <inventory.json>

For each case the planted value is searched in every file written and in everything the
commands printed: the value itself, its first and last six characters (and how far each
match extends), its percent-encoded form, and its SHA-256, SHA-1 and MD5 in hex.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import nexus_symbiote
from click.testing import CliRunner
from nexus_symbiote.cli import main

CATEGORIES = ("credential_exposure", "literal_credential")
FORMATS = ("json", "cyclonedx", "spdx", "sarif")


def strings(node: Any, out: list[str]) -> None:
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for key, value in node.items():
            out.append(str(key))
            strings(value, out)
    elif isinstance(node, list):
        for item in node:
            strings(item, out)


def searchable(text: str) -> str:
    """The text, and the strings of the JSON document it is, so that an escaped form is found."""
    try:
        document = json.loads(text)
    except ValueError:
        return text
    found: list[str] = []
    strings(document, found)
    return text + "\n" + "\n".join(found)


def needles(secret: str, value: str) -> dict[str, str]:
    wanted: dict[str, str] = {}
    for label, text in (("secret", secret), ("value", value)):
        if label == "value" and value == secret:
            continue
        if len(text) >= 6:
            wanted[f"{label}:whole"] = text
            wanted[f"{label}:prefix6"] = text[:6]
            wanted[f"{label}:suffix6"] = text[-6:]
            encoded = quote(text, safe="")
            if encoded != text:
                wanted[f"{label}:percent-encoded"] = encoded
        for algorithm in ("sha256", "sha1", "md5"):
            digest = hashlib.new(algorithm, text.encode("utf-8", "surrogatepass"), usedforsecurity=False)
            wanted[f"{label}:{algorithm}"] = digest.hexdigest()
    return wanted


def extent(text: str, secret: str, kind: str) -> int:
    """How many characters of the prefix or suffix of ``secret`` the text holds."""
    size = 6
    if kind.endswith("prefix6"):
        while size < len(secret) and secret[: size + 1] in text:
            size += 1
    else:
        while size < len(secret) and secret[-(size + 1) :] in text:
            size += 1
    return size


def leaks(case: dict[str, Any], outputs: dict[str, str]) -> list[dict[str, Any]]:
    found = []
    wanted = needles(case["secret"], case["value"])
    for name, text in outputs.items():
        hay = searchable(text)
        low = hay.lower()
        for kind, needle in wanted.items():
            hashed = kind.split(":")[1] in ("sha256", "sha1", "md5")
            where = (low if hashed else hay).find(needle.lower() if hashed else needle)
            if where < 0:
                continue
            source = case["secret"] if kind.startswith("secret") else case["value"]
            entry: dict[str, Any] = {"output": name, "kind": kind}
            if kind.endswith(("prefix6", "suffix6")):
                entry["extent"] = extent(hay, source, kind)
            entry["context"] = hay[max(0, where - 60) : where + 60]
            found.append(entry)
    return found


def run(arguments: list[str]) -> tuple[int, str]:
    result = CliRunner().invoke(main, arguments)
    text = result.output
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        text += f"\n[exception {type(result.exception).__name__}]"
    return result.exit_code, text


def one(case: dict[str, Any], corpus: Path, work: Path) -> dict[str, Any]:
    project = corpus / case["id"]
    outputs: dict[str, str] = {}
    codes: dict[str, int] = {}
    for form in FORMATS:
        target = work / f"out.{form}"
        code, printed = run(["scan", "--no-project-policy", "--report-only", "-f", form, "-o", str(target), str(project)])
        codes[f"scan-{form}"] = code
        outputs[f"scan-{form}-printed"] = printed
        outputs[form] = target.read_text(encoding="utf-8") if target.exists() else ""
    inventory = str(work / "out.json")
    vex = work / "out.vex.json"
    codes["vex"], outputs["vex-printed"] = run(["vex", "-o", str(vex), inventory])
    outputs["vex"] = vex.read_text(encoding="utf-8") if vex.exists() else ""
    codes["risk"], outputs["risk-text"] = run(["risk", "--no-project-policy", inventory])
    codes["risk-json"], outputs["risk-json"] = run(["risk", "--no-project-policy", "--json-output", inventory])
    record: dict[str, Any] = {"id": case["id"], "codes": codes}
    try:
        native = json.loads(outputs["json"])
    except ValueError:
        native = {"components": [], "metadata": {}}
        record["native_unreadable"] = True
    risks = [
        (component.get("name"), risk)
        for component in native.get("components", [])
        for risk in component.get("risks", [])
    ]
    record["findings"] = [
        {"category": risk["category"], "severity": risk["severity"], "detail": risk["detail"][:400], "component": name}
        for name, risk in risks
        if risk["category"] in CATEGORIES
    ]
    record["categories"] = sorted(f"{risk['severity']}:{risk['category']}" for _, risk in risks)
    completeness = native.get("metadata", {}).get("completeness", {})
    record["scan_failures"] = completeness.get("scan_failures", [])
    record["surfaces_excluded"] = completeness.get("surfaces_excluded", [])
    record["components"] = len(native.get("components", []))
    try:
        report = json.loads(outputs["risk-json"])
        record["score"] = report.get("overall_score")
        record["gate_reasons"] = report.get("gate_reasons")
        record["fingerprints"] = sorted(
            finding["fingerprint"] for finding in report.get("findings", []) if finding["category"] in CATEGORIES
        )
    except ValueError:
        record["score"] = None
    record["leaks"] = leaks(case, outputs)
    record["sizes"] = {name: len(text) for name, text in outputs.items() if not name.endswith("printed")}
    return record


def run_all() -> None:
    label, corpus, target = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    if len(sys.argv) > 5:
        manifest = [case for case in manifest if sys.argv[4] <= case["id"] <= sys.argv[5]]
    source = str(Path(nexus_symbiote.__file__).resolve())
    assert source.startswith(os.getcwd() + os.sep), (source, os.getcwd())
    started = time.time()
    work = Path(tempfile.mkdtemp(prefix=f"run-{label}-", dir=str(target.parent)))
    try:
        with target.open("w", encoding="utf-8") as stream:
            stream.write(json.dumps({"tree": label, "source": source, "cases": len(manifest)}) + "\n")
            for case in manifest:
                for leftover in work.iterdir():
                    leftover.unlink()
                record = one(case, corpus, work)
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print(f"{label}: {len(manifest)} cases from {source} in {time.time() - started:.0f}s", file=sys.stderr)


if __name__ == "__main__":
    run_all()
