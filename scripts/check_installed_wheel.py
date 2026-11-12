"""Exercise an installed nexus-symbiote on the demo agent and a TypeScript MCP server.

CI and the release compatibility job install the built wheel with dependencies resolved
from the package index, as users do, then run this with that environment's interpreter.
It scans a copy of examples/demo-agent with the pinned upstream filesystem server source
added, writes every export format and the risk report, and checks that the TypeScript tool
parser, the exporters and the gate all ran. It never imports the package under test itself.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FORMATS = ("json", "cyclonedx", "spdx", "sarif")
TYPESCRIPT_FIXTURE = Path("benchmarks/inventory/fixtures/upstream/server.ts.fixture")
EXPECTED_TOOLS = frozenset({"read_file", "write_file", "list_allowed_directories"})


def _cli(*arguments: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - this interpreter and fixed arguments
        [sys.executable, "-I", "-m", "nexus_symbiote", *arguments],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )


def build_fixture(source: Path, destination: Path) -> Path:
    project = destination / "demo-agent"
    shutil.copytree(source / "examples" / "demo-agent", project)
    server = project / "src" / "filesystem" / "server.ts"
    server.parent.mkdir(parents=True)
    shutil.copyfile(source / TYPESCRIPT_FIXTURE, server)
    return project


def exercise(source: Path, work: Path, formats: tuple[str, ...] = FORMATS) -> list[str]:
    """Problems found while scanning, exporting and scoring the fixture."""
    project = build_fixture(source, work)
    problems: list[str] = []
    version = _cli("--version", cwd=work)
    if version.returncode != 0 or not version.stdout.strip():
        problems.append("--version failed")
    for name in ("json", *[f for f in formats if f != "json"]):
        result = _cli(
            "scan", str(project), "--report-only", "-f", name, "-o", f"smoke-{name}.json", cwd=work
        )
        if result.returncode != 0:
            problems.append(f"scan -f {name} exited {result.returncode}")
            continue
        try:
            json.loads((work / f"smoke-{name}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            problems.append(f"scan -f {name} wrote no JSON document")
    if not problems:
        bom = json.loads((work / "smoke-json.json").read_text(encoding="utf-8"))
        names = {component.get("name") for component in bom.get("components", [])}
        if not names >= EXPECTED_TOOLS:
            problems.append("the TypeScript MCP tools were not inventoried")
        if not any(c.get("component_type") == "model" for c in bom.get("components", [])):
            problems.append("the demo agent's model was not inventoried")
        risk = _cli("risk", "smoke-json.json", "--json-output", cwd=work)
        if risk.returncode not in (0, 1) or "Traceback" in risk.stderr:
            problems.append(f"risk exited {risk.returncode}")
        else:
            try:
                report = json.loads(risk.stdout)
            except ValueError:
                report = None
            if not isinstance(report, dict) or "overall_score" not in report:
                problems.append("risk wrote no JSON report")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", type=Path, default=Path(), help="checkout or unpacked sdist with the fixtures"
    )
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="nexus-symbiote-smoke-") as scratch:
        problems = exercise(args.source.resolve(), Path(scratch))
    for problem in problems:
        print(f"Installed wheel check: {problem}")
    if not problems:
        print("Installed wheel check passed: scan, every export and risk ran on the fixture.")
    return int(bool(problems))


if __name__ == "__main__":
    raise SystemExit(main())
