"""Run the committed finite security regression corpus against real Nexus SymBiote code."""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import tracemalloc
from collections import Counter
from pathlib import Path
from typing import Any

import nexus_symbiote
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.hashing import open_regular_file
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.scanners.prompt import PromptScanner
from nexus_symbiote.utils.files import OutputRefusedError, write_output_file
from nexus_symbiote.validators.integrity import IntegrityValidator

KINDS = frozenset(
    {
        "model_signature",
        "model_format",
        "hidden_unicode",
        "mcp_pinning",
        "tool_drift",
        "credential_export",
        "parse_coverage",
    }
)
DEFAULT_MANIFEST = Path(__file__).resolve().parents[1] / "benchmarks" / "manifest.json"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_FIXTURE_BYTES = 8 * 1024 * 1024


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _strict_json(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for name, value in items:
            if name in result:
                raise ValueError("duplicate JSON key")
            result[name] = value
        return result

    def invalid_constant(value: str) -> None:
        raise ValueError(f"nonfinite JSON number {value}")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)


def _read_regular_bytes(path: Path, limit: int, label: str) -> bytes:
    with open_regular_file(path) as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{label} exceeds size limit")
    return data


def _contained(base: Path, value: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("fixture paths must be relative and confined")
    current = base
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("fixture symlinks are forbidden")
    resolved = current.resolve(strict=True)
    if not resolved.is_relative_to(base):
        raise ValueError("fixture path escapes corpus")
    return resolved


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    raw = _read_regular_bytes(path, MAX_MANIFEST_BYTES, "manifest")
    path = path.resolve(strict=True)
    manifest = _strict_json(raw)
    if (
        not isinstance(manifest, dict)
        or type(manifest.get("schema_version")) is not int
        or manifest["schema_version"] != 1
    ):
        raise ValueError("unsupported corpus schema")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 1000:
        raise ValueError("corpus must contain between 1 and 1000 cases")
    ids: set[str] = set()
    corpus_inputs = []
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("each case must be an object")
        cid = case.get("id")
        if not isinstance(cid, str) or not cid or cid in ids:
            raise ValueError("case IDs must be nonempty and unique")
        ids.add(cid)
        if case.get("kind") not in KINDS or case.get("task") not in {"detection", "control"}:
            raise ValueError(f"{cid}: unsupported case kind or task")
        if case.get("truth") is not None and type(case.get("truth")) is not bool:
            raise ValueError(f"{cid}: truth must be boolean or null")
        directory = _contained(path.parent, case["directory"])
        refs = case.get("references")
        if not isinstance(refs, list) or not refs:
            raise ValueError(f"{cid}: references required")
        names: set[str] = set()
        for ref in refs:
            name = ref["path"]
            if name in names:
                raise ValueError(f"{cid}: duplicate reference")
            names.add(name)
            artifact = _contained(directory, name)
            if (
                not artifact.is_file()
                or artifact.stat().st_size > MAX_FIXTURE_BYTES
                or _sha(artifact.read_bytes()) != ref["sha256"]
            ):
                raise ValueError(f"{cid}: fixture digest mismatch: {name}")
            corpus_inputs.append({"case": cid, **ref})
        actual = set()
        for artifact in directory.rglob("*"):
            if artifact.is_symlink():
                raise ValueError(f"{cid}: fixture symlinks are forbidden")
            if artifact.is_file():
                actual.add(artifact.relative_to(directory).as_posix())
        if actual != names:
            raise ValueError(f"{cid}: manifest must enumerate every input file")
    return manifest, _sha(_json({"manifest_sha256": _sha(raw), "inputs": corpus_inputs}))


def _evaluate(case: dict[str, Any], directory: Path) -> dict[str, Any]:
    kind = case["kind"]
    project = directory / "project"
    scanner = (
        ModelScanner()
        if kind.startswith("model_")
        else PromptScanner()
        if kind == "hidden_unicode"
        else MCPScanner()
    )
    result = scanner.scan(project)
    categories = sorted({r.category for c in result.components for r in getattr(c, "risks", [])})
    facts: dict[str, Any] = {
        "collector": result.scanner_name,
        "components": len(result.components),
        "risk_categories": categories,
        "collection_failures": list(result.scan_failures),
        "surfaces_scanned": len(result.surfaces_scanned),
        "surfaces_excluded": len(result.surfaces_excluded),
    }
    if kind == "parse_coverage":
        return {
            "prediction": None,
            "control_passed": bool(result.scan_failures),
            "unknown_reason": "invalid input cannot establish component absence",
            "facts": facts,
        }
    if result.scan_failures:
        return {"prediction": None, "unknown_reason": "collection incomplete", "facts": facts}
    if kind.startswith("model_"):
        models = [c for c in result.components if c.component_type == ComponentType.MODEL]
        facts["models"] = [
            {
                "format": m.serialization_format,
                "loader_risk": m.serialization_safety.value,
                "signing_status": m.signing_status,
            }
            for m in models
        ]
        if not models:
            return {
                "prediction": None,
                "unknown_reason": "required model was not collected",
                "facts": facts,
            }
        predicted = (
            "signing_status" in categories
            if kind == "model_signature"
            else any(c.startswith("serialization_format") for c in categories)
        )
    elif kind == "hidden_unicode":
        if not result.components:
            return {
                "prediction": None,
                "unknown_reason": "required instruction was not collected",
                "facts": facts,
            }
        predicted = bool(
            set(categories) & {"invisible_characters", "bidi_override", "tag_characters"}
        )
    elif kind == "mcp_pinning":
        servers = [c for c in result.components if c.component_type == ComponentType.MCP_SERVER]
        if not servers:
            return {
                "prediction": None,
                "unknown_reason": "required server was not collected",
                "facts": facts,
            }
        facts["version_pinned"] = [s.version_pinned for s in servers]
        predicted = any(not s.version_pinned for s in servers)
    elif kind == "tool_drift":
        tools = [c for c in result.components if c.component_type == ComponentType.TOOL]
        if len(tools) != 1 or not tools[0].definition_hash:
            return {
                "prediction": None,
                "unknown_reason": "required approved descriptor was not collected",
                "facts": facts,
            }
        observed = _strict_json(
            _read_regular_bytes(
                _contained(directory, "observed-tool.json"),
                MAX_FIXTURE_BYTES,
                "observed-tool.json",
            )
        )
        # The approved digest stays fixed while the actual observed descriptor is substituted.
        changed = tools[0].model_copy(
            update={
                "name": observed["name"],
                "description_text": observed.get("description", ""),
                "input_schema": observed.get("inputSchema"),
                "annotations": observed.get("annotations", {}),
            }
        )
        report = IntegrityValidator().validate(AIBOM(components=[changed]), project)
        facts["integrity_categories"] = sorted({issue.category for issue in report.issues})
        facts["hashes_verified"] = report.hashes_verified
        facts["hashes_failed"] = report.hashes_failed
        predicted = any(i.category == "hash_mismatch" for i in report.issues)
        if not predicted and report.hashes_verified == 0:
            return {
                "prediction": None,
                "unknown_reason": "descriptor integrity could not be established",
                "facts": facts,
            }
    elif kind == "credential_export":
        from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
        from nexus_symbiote.generators.sarif import SARIFGenerator
        from nexus_symbiote.generators.spdx import SPDXGenerator

        servers = [c for c in result.components if c.component_type == ComponentType.MCP_SERVER]
        if not servers:
            # An empty inventory leaks nothing; it must not pass as redaction.
            return {
                "prediction": None,
                "control_passed": False,
                "unknown_reason": "required server was not collected",
                "facts": facts,
            }
        bom = AIBOM(components=result.components)
        exports = {
            "native": bom.to_json(),
            "cyclonedx": CycloneDXGenerator().generate_json(bom),
            "spdx": SPDXGenerator().generate_json(bom),
            "sarif": SARIFGenerator().generate_json(bom),
        }
        forbidden = case.get("parameters", {}).get("forbidden_literals", [])
        if not forbidden or not all(isinstance(s, str) and s for s in forbidden):
            raise ValueError("credential control requires nonempty public sentinel literals")
        # Report format names only, never the literal we are checking for disclosure.
        leaked = [
            name
            for name, content in exports.items()
            if any(secret in content for secret in forbidden)
        ]
        # The evidence that should survive, such as the variable's name, must still be
        # there: dropping the whole server would also hide the secret. SARIF carries
        # findings only.
        required = case.get("parameters", {}).get("required_literals", [])
        if not required or not all(isinstance(s, str) and s for s in required):
            raise ValueError("credential control requires nonempty retained-evidence literals")
        missing = [
            name
            for name, content in exports.items()
            if name != "sarif" and not all(literal in content for literal in required)
        ]
        facts["export_formats_checked"] = sorted(exports)
        facts["formats_with_literal_leaks"] = leaked
        facts["formats_missing_evidence"] = missing
        predicted = bool(leaked)
        return {
            "prediction": predicted,
            "control_passed": not predicted and not missing,
            "facts": facts,
        }
    else:
        raise ValueError(f"unsupported evaluator {kind}")
    return {"prediction": predicted, "facts": facts}


def metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    detection = [r for r in results if r["task"] == "detection"]
    scored = [r for r in detection if type(r["truth"]) is bool and type(r["prediction"]) is bool]
    counts = Counter(
        "tp"
        if r["truth"] and r["prediction"]
        else "fn"
        if r["truth"]
        else "fp"
        if r["prediction"]
        else "tn"
        for r in scored
    )
    tp, fp, tn, fn = (counts[k] for k in ("tp", "fp", "tn", "fn"))

    def ratio(numerator: int, denominator: int) -> float | None:
        return numerator / denominator if denominator else None

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "detection_cases": len(detection),
        "scored_cases": len(scored),
        "unknown_predictions": sum(r["prediction"] is None for r in detection),
        "unknown_positive_labels": sum(
            r["prediction"] is None and r["truth"] is True for r in detection
        ),
        "unknown_negative_labels": sum(
            r["prediction"] is None and r["truth"] is False for r in detection
        ),
        "unlabeled_cases": sum(r["truth"] is None for r in detection),
        "precision": ratio(tp, tp + fp),
        "precision_denominator": tp + fp,
        "recall": ratio(tp, tp + fn),
        "recall_denominator": tp + fn,
        "specificity": ratio(tn, tn + fp),
        "specificity_denominator": tn + fp,
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "f1_denominator": 2 * tp + fp + fn,
        "label_coverage": ratio(len(scored), len(detection)),
    }


def _source_identity() -> dict[str, Any]:
    """Identify the evaluated package by content, and by revision only when that is certain.

    In CI the revision is the workflow's GITHUB_SHA. Elsewhere Git is asked only when the
    package directory holds files Git tracks: an installed copy inside a checkout (a
    virtual environment in the work tree, say) is not that checkout's revision.
    """
    package = Path(inspect.getfile(nexus_symbiote)).resolve().parent
    files = [
        {"path": p.relative_to(package).as_posix(), "sha256": _sha(p.read_bytes())}
        for p in sorted(package.rglob("*.py"))
        if not p.is_symlink()
    ]
    identity: dict[str, Any] = {
        "package_path": str(package),
        "source_digest": _sha(_json(files)),
        "source_files": len(files),
        "git_sha": None,
        "git_dirty": None,
        "revision_source": None,
    }
    workflow_sha = os.environ.get("GITHUB_SHA", "")
    if re.fullmatch(r"[0-9a-f]{40}", workflow_sha):
        identity.update(git_sha=workflow_sha, revision_source="GITHUB_SHA")
        return identity
    git = shutil.which("git")
    if git:
        try:

            def ask(*arguments: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(  # noqa: S603 - resolved git and fixed arguments
                    [git, "-C", str(package), *arguments],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

            tracked = ask("ls-files", "--error-unmatch", "--", "__init__.py")
            revision = ask("rev-parse", "HEAD")
            dirty = ask("status", "--porcelain", "--", ".")
            if tracked.returncode == 0 and revision.returncode == 0:
                identity.update(
                    git_sha=revision.stdout.strip(),
                    git_dirty=bool(dirty.stdout.strip()),
                    revision_source="git checkout of the evaluated package",
                )
        except (OSError, subprocess.TimeoutExpired):
            # Revision identity is optional evidence; a checkout without git keeps the rest.
            pass
    return identity


def run_benchmark(manifest_path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    manifest, corpus_digest = load_manifest(manifest_path)
    results = []
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    started = time.perf_counter()
    try:
        for case in manifest["cases"]:
            case_start = time.perf_counter()
            record = {k: case[k] for k in ["id", "kind", "task", "truth"]}
            try:
                record.update(
                    _evaluate(case, _contained(manifest_path.resolve().parent, case["directory"]))
                )
                record["error"] = None
            except Exception as exc:
                record.update(
                    prediction=None,
                    error=type(exc).__name__,
                    unknown_reason="evaluator failed; inspect this case independently",
                )
            if case["task"] == "control":
                record["passed"] = record.get("control_passed")
            else:
                record["passed"] = (
                    None
                    if record["prediction"] is None or case["truth"] is None
                    else record["prediction"] == case["truth"]
                )
            record["elapsed_seconds"] = time.perf_counter() - case_start
            results.append(record)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
    finally:
        if not was_tracing:
            tracemalloc.stop()
    return {
        "report_schema_version": 1,
        "scope": manifest["scope"],
        "tool": {
            "name": "nexus-symbiote",
            "version": nexus_symbiote.__version__,
            **_source_identity(),
        },
        "corpus": {
            "name": manifest["name"],
            "digest": corpus_digest,
            "manifest_sha256": _sha(
                _read_regular_bytes(manifest_path, MAX_MANIFEST_BYTES, "manifest")
            ),
            "cases": len(results),
        },
        "runner_sha256": _sha(Path(__file__).read_bytes()),
        "platform": {
            "python": platform.python_version(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "measurement": {
            "elapsed_seconds": elapsed,
            "python_traced_peak_bytes": peak,
            "memory_scope": "Python traced allocations, not RSS",
        },
        # Every case must pass the CI gate, so on a passing run these ratios are 1.0 by
        # construction: a regression record, not an accuracy estimate.
        "metrics_scope": (
            "finite regression corpus; the gate requires every case, so ratios on a"
            " passing run are 1.0 by construction and estimate nothing"
        ),
        "metrics": metrics(results),
        "metrics_by_kind": {
            kind: metrics([r for r in results if r["kind"] == kind])
            for kind in sorted({r["kind"] for r in results if r["task"] == "detection"})
        },
        "controls": {
            "cases": sum(r["task"] == "control" for r in results),
            "passed": sum(r["task"] == "control" and r["passed"] is True for r in results),
            "failed": sum(r["task"] == "control" and r["passed"] is False for r in results),
            "unknown": sum(r["task"] == "control" and r["passed"] is None for r in results),
        },
        "case_failures": sum(r["passed"] is False for r in results),
        "unknown_outcomes": sum(r["prediction"] is None for r in results),
        "execution_errors": sum(r["error"] is not None for r in results),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        report = run_benchmark(args.manifest)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Benchmark input rejected: {exc}", file=sys.stderr)
        return 2
    content = json.dumps(report, indent=2, allow_nan=False) + "\n"
    if args.out:
        try:
            write_output_file(args.out, content, create_parents=True)
        except (OutputRefusedError, OSError) as exc:
            print(f"Benchmark output rejected: {exc}", file=sys.stderr)
            return 2
    else:
        print(content, end="")
    incomplete = report["metrics"]["unknown_predictions"] or report["controls"]["unknown"]
    return 1 if report["case_failures"] or report["execution_errors"] or incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
