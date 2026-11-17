#!/usr/bin/env python3
"""Run every AI-BOM tool against the fixture and record raw outputs, timing, exit codes,
canary hits, fixture modifications and network egress.

Each run executes under ``strace -f -e trace=connect,sendto,sendmsg,write,writev`` so the
harness can see proxy ``CONNECT`` targets, absolute-URI HTTP requests, non-loopback
connections and DNS attempts. The canary directory is emptied before each run and listed
after it. Outputs land in ``OUT/<tool>/<run>/`` next to ``command.txt``, ``stdout.txt``,
``stderr.txt``, ``strace.txt`` and ``meta.json``.

Usage: run_tools.py --fixture DIR --tools-root DIR --out DIR --canary-dir DIR [--only a,b]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TIMEOUT_SECONDS = 20 * 60
OWASP_MODEL = "distilbert/distilbert-base-uncased-finetuned-sst-2-english"

RE_CONNECT_TARGET = re.compile(r"CONNECT\s+([A-Za-z0-9.\-]+):(\d+)\s+HTTP")
RE_HTTP_ABSOLUTE = re.compile(
    r"(?:GET|POST|PUT|HEAD|PATCH|DELETE)\s+http://([A-Za-z0-9.\-]+(?::\d+)?)/"
)
RE_INET4 = re.compile(
    r'connect\(\d+, \{sa_family=AF_INET, sin_port=htons\((\d+)\), sin_addr=inet_addr\("([\d.]+)"\)'
)
RE_INET6 = re.compile(
    r'connect\(\d+, \{sa_family=AF_INET6, sin6_port=htons\((\d+)\), .*?inet_pton\(AF_INET6, "([0-9a-fA-F:.]+)"'
)
RE_DNS = re.compile(r"sin6?_port=htons\(53\)")


def is_loopback(address: str) -> bool:
    return (
        address.startswith("127.")
        or address in {"::1", "0.0.0.0", "::"}  # noqa: S104
        or address.startswith("::ffff:127.")
    )


def parse_strace(path: Path) -> dict:
    connect_targets: set[str] = set()
    http_targets: set[str] = set()
    nonloopback: set[str] = set()
    dns = 0
    if not path.exists():
        return {
            "connect_targets": [],
            "http_targets": [],
            "nonloopback_connects": [],
            "dns_attempts": 0,
            "strace_missing": True,
        }
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            for host, port in RE_CONNECT_TARGET.findall(line):
                connect_targets.add(f"{host}:{port}")
            for host in RE_HTTP_ABSOLUTE.findall(line):
                http_targets.add(host)
            for port, address in RE_INET4.findall(line):
                if not is_loopback(address):
                    nonloopback.add(f"{address}:{port}")
            for port, address in RE_INET6.findall(line):
                if not is_loopback(address):
                    nonloopback.add(f"[{address}]:{port}")
            if RE_DNS.search(line):
                dns += 1
    return {
        "connect_targets": sorted(connect_targets),
        "http_targets": sorted(http_targets),
        "nonloopback_connects": sorted(nonloopback),
        "dns_attempts": dns,
    }


def snapshot(fixture: Path) -> dict[str, tuple[int, int]]:
    result = {}
    for path in fixture.rglob("*"):
        if path.is_symlink():
            continue
        if path.is_file():
            stat = path.stat()
            result[path.relative_to(fixture).as_posix()] = (stat.st_size, stat.st_mtime_ns)
    return result


def fixture_changes(before: dict, after: dict) -> dict:
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    modified = sorted(k for k in set(before) & set(after) if before[k] != after[k])
    return {"added": added, "removed": removed, "modified": modified}


def clear_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def tool_definitions(tools_root: Path, fixture: Path) -> dict:
    nexus = str(tools_root / "nexus/bin/nexus-symbiote")
    agent_bom = str(tools_root / "agent-bom/bin/agent-bom")
    ai_bom = str(tools_root / "ai-bom/bin/ai-bom")
    aisbom = str(tools_root / "aisbom/bin/aisbom")
    cisco_python = str(tools_root / "cisco/bin/python")
    cisco_cli = str(tools_root / "cisco/bin/cisco-aibom")
    cdxgen_aibom = str(tools_root / "npm/node_modules/.bin/aibom")
    cdxgen = str(tools_root / "npm/node_modules/.bin/cdxgen")
    owasp_python = str(tools_root / "owasp/venv/bin/python")
    owasp_src = str(tools_root / "owasp/src")
    fx = str(fixture)
    traces = str(fixture / "telemetry" / "traces.json")

    node = shutil.which("node") or "node"

    return {
        "nexus-symbiote": {
            "version": [nexus, "--version"],
            "runs": [
                {
                    "name": "default-1",
                    "argv": [nexus, "scan", fx, "-f", "cyclonedx", "-o", "{out}/bom.cdx.json"],
                },
                {
                    "name": "default-2",
                    "argv": [nexus, "scan", fx, "-f", "cyclonedx", "-o", "{out}/bom.cdx.json"],
                },
                {
                    "name": "native",
                    "argv": [nexus, "scan", fx, "-f", "json", "-o", "{out}/bom.native.json"],
                },
                {
                    "name": "native-2",
                    "argv": [nexus, "scan", fx, "-f", "json", "-o", "{out}/bom.native.json"],
                },
                {
                    "name": "spdx",
                    "argv": [nexus, "scan", fx, "-f", "spdx", "-o", "{out}/bom.spdx.json"],
                },
                {
                    "name": "sarif",
                    "argv": [nexus, "scan", fx, "-f", "sarif", "-o", "{out}/bom.sarif"],
                },
                {
                    "name": "offline",
                    "argv": [
                        nexus,
                        "--offline",
                        "scan",
                        fx,
                        "-f",
                        "cyclonedx",
                        "-o",
                        "{out}/bom.cdx.json",
                    ],
                },
                {
                    "name": "trace-diff",
                    "argv": [
                        nexus,
                        "trace-diff",
                        "{raw}/native/bom.native.json",
                        traces,
                        "--json-output",
                        "--sarif",
                        "{out}/trace.sarif",
                    ],
                },
                {
                    "name": "minimum-elements",
                    "argv": [
                        nexus,
                        "minimum-elements",
                        "{raw}/native/bom.native.json",
                        "-f",
                        "json",
                        "-o",
                        "{out}/minimum-elements.json",
                    ],
                },
                {
                    "name": "diff",
                    "argv": [
                        nexus,
                        "diff",
                        "{raw}/native/bom.native.json",
                        "{raw}/native-2/bom.native.json",
                        "--json-output",
                    ],
                },
                {
                    "name": "attest",
                    "pre": [
                        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", "{out}/signer.pem"],
                        ["chmod", "600", "{out}/signer.pem"],
                        [
                            "openssl",
                            "pkey",
                            "-in",
                            "{out}/signer.pem",
                            "-pubout",
                            "-out",
                            "{out}/signer.pub.pem",
                        ],
                    ],
                    "argv": [
                        nexus,
                        "attest",
                        "{raw}/native/bom.native.json",
                        "--key",
                        "{out}/signer.pem",
                        "--purpose",
                        "generated",
                        "--out",
                        "{out}/attestation.dsse.json",
                    ],
                },
                {
                    "name": "verify-attestation",
                    "argv": [
                        nexus,
                        "verify-attestation",
                        "{raw}/native/bom.native.json",
                        "{raw}/attest/attestation.dsse.json",
                        "--trusted-key",
                        "{raw}/attest/signer.pub.pem",
                        "--purpose",
                        "generated",
                        "--json-output",
                    ],
                },
            ],
        },
        "agent-bom": {
            "version": [agent_bom, "--version"],
            "runs": [
                {
                    "name": "default-1",
                    "argv": [agent_bom, "scan", fx, "-f", "cyclonedx", "-o", "{out}/bom.cdx.json"],
                },
                {
                    "name": "default-2",
                    "argv": [agent_bom, "scan", fx, "-f", "cyclonedx", "-o", "{out}/bom.cdx.json"],
                },
                {
                    "name": "json",
                    "argv": [agent_bom, "scan", fx, "-f", "json", "-o", "{out}/bom.json"],
                },
                {
                    "name": "sarif",
                    "argv": [agent_bom, "scan", fx, "-f", "sarif", "-o", "{out}/bom.sarif"],
                },
                {
                    "name": "spdx",
                    "argv": [agent_bom, "scan", fx, "-f", "spdx", "-o", "{out}/bom.spdx.json"],
                },
                {
                    "name": "offline",
                    "argv": [
                        agent_bom,
                        "scan",
                        fx,
                        "--offline",
                        "-f",
                        "cyclonedx",
                        "-o",
                        "{out}/bom.cdx.json",
                    ],
                },
                {
                    "name": "baseline",
                    "argv": [
                        agent_bom,
                        "scan",
                        fx,
                        "--offline",
                        "--baseline",
                        "{raw}/json/bom.json",
                        "-f",
                        "json",
                        "-o",
                        "{out}/bom.json",
                    ],
                },
            ],
        },
        "trusera-ai-bom": {
            "version": [ai_bom, "--version"],
            "runs": [
                {
                    "name": "default-1",
                    "argv": [ai_bom, "scan", fx, "-f", "cyclonedx", "-o", "{out}/bom.cdx.json"],
                },
                {
                    "name": "default-2",
                    "argv": [ai_bom, "scan", fx, "-f", "cyclonedx", "-o", "{out}/bom.cdx.json"],
                },
                {
                    "name": "json",
                    "argv": [ai_bom, "scan", fx, "-f", "json", "-o", "{out}/bom.json"],
                },
                {
                    "name": "sarif",
                    "argv": [ai_bom, "scan", fx, "-f", "sarif", "-o", "{out}/bom.sarif"],
                },
                {
                    "name": "deep",
                    "argv": [
                        ai_bom,
                        "scan",
                        fx,
                        "--deep",
                        "-f",
                        "cyclonedx",
                        "-o",
                        "{out}/bom.cdx.json",
                    ],
                },
            ],
        },
        "aisbom": {
            "version": [aisbom, "--version"],
            "runs": [
                {
                    "name": "default-1",
                    "argv": [
                        aisbom,
                        "scan",
                        fx,
                        "--format",
                        "json",
                        "--output",
                        "{out}/bom.cdx.json",
                    ],
                },
                {
                    "name": "default-2",
                    "argv": [
                        aisbom,
                        "scan",
                        fx,
                        "--format",
                        "json",
                        "--output",
                        "{out}/bom.cdx.json",
                    ],
                },
                {
                    "name": "spdx",
                    "argv": [
                        aisbom,
                        "scan",
                        fx,
                        "--format",
                        "spdx",
                        "--spdx-version",
                        "3.0",
                        "--output",
                        "{out}/bom.spdx.json",
                    ],
                },
                {
                    "name": "offline",
                    "argv": [
                        aisbom,
                        "scan",
                        fx,
                        "--offline",
                        "--format",
                        "json",
                        "--output",
                        "{out}/bom.cdx.json",
                    ],
                },
            ],
        },
        "cdxgen": {
            "version": [cdxgen, "--version"],
            "runs": [
                {"name": "default-1", "argv": [cdxgen_aibom, fx, "-o", "{out}/bom.cdx.json"]},
                {"name": "default-2", "argv": [cdxgen_aibom, fx, "-o", "{out}/bom.cdx.json"]},
                {"name": "autodetect", "argv": [cdxgen, fx, "-o", "{out}/bom.cdx.json"]},
                {
                    "name": "spdx",
                    "argv": [cdxgen_aibom, fx, "--format", "spdx", "-o", "{out}/bom.spdx.json"],
                },
                {
                    "name": "safe",
                    "argv": [cdxgen_aibom, fx, "--no-install-deps", "-o", "{out}/bom.cdx.json"],
                },
                {
                    "name": "sign",
                    "argv": [
                        cdxgen_aibom,
                        fx,
                        "--no-install-deps",
                        "--generate-key-and-sign",
                        "-o",
                        "{out}/bom.cdx.json",
                    ],
                },
            ],
        },
        "cisco-ai-bom": {
            "version": [cisco_cli, "--version"],
            "runs": [
                {
                    "name": "default-1",
                    "argv": [cisco_python, str(HERE / "cisco_deterministic.py"), fx, "{out}"],
                },
                {
                    "name": "default-2",
                    "argv": [cisco_python, str(HERE / "cisco_deterministic.py"), fx, "{out}"],
                },
                {
                    "name": "diff",
                    "argv": [
                        cisco_cli,
                        "diff",
                        "run",
                        "{raw}/default-1/report.json",
                        "{raw}/default-2/report.json",
                        "--format",
                        "json",
                    ],
                },
            ],
        },
        "wasmagent-agentbom": {
            "version": [
                node,
                "-e",
                "import('@wasmagent/agentbom-core/package.json', {with:{type:'json'}}).then(m=>console.log(m.default.version)).catch(()=>console.log('0.4.0'))",
            ],
            "cwd": str(tools_root / "npm"),
            "runs": [
                {
                    "name": "library-check",
                    "argv": [node, str(HERE / "wasmagent_check.mjs"), "{out}"],
                },
            ],
        },
        "owasp-aibom-generator": {
            "version": [
                owasp_python,
                "-c",
                "import importlib.metadata as m; print(m.version('cyclonedx-python-lib'))",
            ],
            "cwd": owasp_src,
            "runs": [
                {
                    "name": "default-1",
                    "argv": [owasp_python, "-m", "src.cli", OWASP_MODEL, "-o", "{out}/aibom.json"],
                },
                {
                    "name": "default-2",
                    "argv": [owasp_python, "-m", "src.cli", OWASP_MODEL, "-o", "{out}/aibom.json"],
                },
            ],
        },
    }


def run_one(
    tool: str,
    spec: dict,
    run: dict,
    raw_dir: Path,
    fixture: Path,
    canary_dir: Path,
    home: Path,
    use_strace: bool,
) -> dict:
    out = raw_dir / run["name"]
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    fill = lambda a: a.replace("{out}", str(out)).replace("{raw}", str(raw_dir))  # noqa: E731
    argv = [fill(a) for a in run["argv"]]
    cwd = run.get("cwd") or spec.get("cwd") or str(out)
    env = dict(os.environ)
    env.update(
        {
            "HOME": str(home),
            "AAB_CANARY_DIR": str(canary_dir),
            "NO_COLOR": "1",
            "TERM": "dumb",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    env.pop("CI", None)
    for pre in run.get("pre", []):
        subprocess.run(  # noqa: S603 argv lists built by this harness
            [fill(a) for a in pre], cwd=cwd, env=env, check=False, timeout=120, capture_output=True
        )
    clear_dir(canary_dir)
    before = snapshot(fixture)
    strace_file = out / "strace.txt"
    command = argv
    if use_strace:
        command = [
            "strace",
            "-f",
            "-qq",
            "-e",
            "trace=connect,sendto,sendmsg,write,writev",
            "-e",
            "signal=none",
            "-s",
            "300",
            "-o",
            str(strace_file),
            "--",
        ] + argv
    (out / "command.txt").write_text(" ".join(argv) + "\n")
    started = time.time()
    timed_out = False
    with open(out / "stdout.txt", "wb") as so, open(out / "stderr.txt", "wb") as se:
        try:
            proc = subprocess.run(  # noqa: S603 argv lists built by this harness
                command, cwd=cwd, env=env, stdout=so, stderr=se, timeout=TIMEOUT_SECONDS
            )
            code = proc.returncode
        except subprocess.TimeoutExpired:
            code = None
            timed_out = True
    duration = round(time.time() - started, 2)
    after = snapshot(fixture)
    canaries = sorted(p.name for p in canary_dir.iterdir()) if canary_dir.exists() else []
    outputs = {
        p.name: p.stat().st_size
        for p in out.iterdir()
        if p.is_file()
        and p.name not in {"command.txt", "stdout.txt", "stderr.txt", "strace.txt", "meta.json"}
    }
    meta = {
        "tool": tool,
        "run": run["name"],
        "argv": argv,
        "cwd": cwd,
        "exit_code": code,
        "timed_out": timed_out,
        "duration_seconds": duration,
        "outputs": outputs,
        "canaries_fired": canaries,
        "fixture_changes": fixture_changes(before, after),
        "egress": parse_strace(strace_file) if use_strace else {"not_traced": True},
        "stdout_bytes": (out / "stdout.txt").stat().st_size,
        "stderr_bytes": (out / "stderr.txt").stat().st_size,
    }
    (out / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    status = "timeout" if timed_out else f"exit {code}"
    print(
        f"[{tool}] {run['name']}: {status} in {duration}s, outputs={list(outputs)}, canaries={canaries}, egress={meta['egress'].get('connect_targets', [])}",
        flush=True,
    )
    return meta


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--tools-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--canary-dir", required=True, type=Path)
    parser.add_argument("--only", help="comma-separated tool names")
    parser.add_argument("--runs", help="comma-separated run names to execute (default all)")
    parser.add_argument("--no-strace", action="store_true")
    args = parser.parse_args()

    fixture = args.fixture.resolve()
    tools = tool_definitions(args.tools_root.resolve(), fixture)
    selected = args.only.split(",") if args.only else list(tools)
    run_filter = set(args.runs.split(",")) if args.runs else None
    use_strace = not args.no_strace and shutil.which("strace") is not None
    args.out.mkdir(parents=True, exist_ok=True)
    homes = args.out / "_homes"

    for tool in selected:
        spec = tools[tool]
        raw_dir = args.out / tool
        raw_dir.mkdir(parents=True, exist_ok=True)
        home = homes / tool
        home.mkdir(parents=True, exist_ok=True)
        try:
            version = subprocess.run(  # noqa: S603 argv lists built by this harness
                spec["version"],
                capture_output=True,
                text=True,
                timeout=120,
                env={**os.environ, "HOME": str(home), "NO_COLOR": "1"},
                cwd=spec.get("cwd"),
            )
            (raw_dir / "version.txt").write_text((version.stdout + version.stderr).strip() + "\n")
        except Exception as exc:  # version is informational
            (raw_dir / "version.txt").write_text(f"version check failed: {exc}\n")
        for run in spec["runs"]:
            if run_filter and run["name"] not in run_filter:
                continue
            run_one(tool, spec, run, raw_dir, fixture, args.canary_dir, home, use_strace)
    return 0


if __name__ == "__main__":
    sys.exit(main())
