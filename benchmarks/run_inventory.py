"""Run the versioned, labeled inventory cases locally with the public CLI."""

import hashlib
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import MCPServerComponent, ModelComponent, ToolComponent
from nexus_symbiote.validators.risk import RiskScorer

DIRECTORY = Path(__file__).resolve().parent


def run() -> dict:
    manifest = json.loads((DIRECTORY / "manifest.json").read_text())
    rows = []
    totals = Counter()
    for case in manifest["cases"]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "input"
            project.mkdir()
            files = {k: v.encode() for k, v in case.get("files", {}).items()}
            files.update({k: bytes.fromhex(v) for k, v in case.get("hex_files", {}).items()})
            if "fixture" in case:
                source = (DIRECTORY / "fixtures" / case["fixture"]).read_bytes()
                if hashlib.sha256(source).hexdigest() != case["sha256"]:
                    raise ValueError("Reference source does not match its pinned digest")
                files[case["file"]] = source
            for name, data in files.items():
                path = project / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            output = root / "result.json"
            args = ["scan", "--no-project-policy", "-o", str(output), str(project)]
            result = CliRunner().invoke(main, args)
            if result.exit_code:
                raise RuntimeError(f"{case['id']}: {result.output}") from result.exception
            bom = AIBOM.load(output)
            tools = [c for c in bom.components if isinstance(c, ToolComponent)]
            servers = [c for c in bom.components if isinstance(c, MCPServerComponent)]
            models = [c for c in bom.components if isinstance(c, ModelComponent)]
            predicted = {t.name for t in tools}
            expected = set(case["tools"])
            checks = {}
            for name in case.get("checks", []):
                if name == "distinct_scoped_edges":
                    edges = {(e.source_ref, e.target_ref) for e in bom.dependencies}
                    ok = len({s.bom_ref for s in servers}) == 2 and all(
                        (t.mcp_server_ref, t.bom_ref) in edges for t in tools
                    )
                elif name == "origin_only":
                    ok = {s.endpoint_url for s in servers} == {
                        "http://localhost.attacker.invalid",
                        "https://trusted.invalid",
                    }
                elif name == "no_secret_in_bom":
                    ok = "SECRET_BENCH_MARKER" not in output.read_text()
                elif name == "deceptive_localhost_flagged":
                    ok = any(r.category == "transport_security" for s in servers for r in s.risks)
                elif name in {"unsafe_format", "safe_format", "unknown_format"}:
                    expected_format = {
                        "unsafe_format": "unsafe-code-execution",
                        "safe_format": "safe",
                        "unknown_format": "unknown",
                    }[name]
                    ok = (
                        len(models) == 1 and models[0].serialization_safety.value == expected_format
                    )
                elif name in {"unsigned", "signer_unverified"}:
                    status = (
                        "signature-not-found"
                        if name == "unsigned"
                        else "signature-present-unverified"
                    )
                    ok = (
                        len(models) == 1
                        and models[0].signing_status == status
                        and not models[0].signing_identity
                    )
                elif name in {"critical_gate", "unknown_coverage_gate"}:
                    passed, report = RiskScorer().passes_gate(bom)
                    ok = not passed and (
                        name != "critical_gate" or report.severity_counts.get("critical", 0) > 0
                    )
                elif name == "policy_rejected":
                    ok = CliRunner().invoke(main, ["scan", str(project)]).exit_code != 0
                elif name == "operator_policy_isolated":
                    ok = bool(models)
                else:
                    raise ValueError(f"Unknown benchmark assertion {name}")
                checks[name] = ok
            misses, extras = sorted(expected - predicted), sorted(predicted - expected)
            totals.update(
                tp=len(expected & predicted),
                fp=len(extras),
                fn=len(misses),
                tn=len(set(case["decoys"]) - predicted),
            )
            rows.append(
                {
                    "case": case["id"],
                    "tools": sorted(predicted),
                    "missing": misses,
                    "unexpected": extras,
                    "checks": checks,
                    "passed": not misses and not extras and all(checks.values()),
                }
            )
    return {
        "corpus_version": manifest["version"],
        "counts": dict(totals),
        "cases": rows,
        "passed": all(r["passed"] for r in rows),
    }


if __name__ == "__main__":
    report = run()
    print(json.dumps(report, indent=2))
    sys.exit(0 if report["passed"] else 1)
