#!/usr/bin/env python3
"""Run AI-BOM tools over the AIBOM-Bench corpus inside a confinement sandbox.

Each command runs (1) in a fresh network namespace with no interfaces up, (2) as an
unprivileged user that cannot write the corpus, (3) under strace recording connect()
attempts, (4) with a fresh HOME, and (5) under a wall-clock timeout, with peak RSS
taken from wait4(). The runner never trusts tool output: it only records it.

Run as root on a disposable machine (unshare and setpriv need it):

    python3 run.py --corpus /opt/aibom-bench/corpus --tools tools.json \
        --tools-root /opt/aibom-bench/tools --runs /opt/aibom-bench/runs
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

TIMEOUT_S = 300
DETERMINISM_SCENARIOS = ("s01-models", "s04-mcp")
EGRESS_SCENARIO = "s04-mcp"


def chown_tree(path: Path, uid: int, gid: int) -> None:
    os.chown(path, uid, gid)
    for p in path.rglob("*"):
        os.chown(p, uid, gid, follow_symlinks=False)


def expand(arg: str, ctx: dict[str, str]) -> str:
    for key, value in ctx.items():
        arg = arg.replace("{" + key + "}", value)
    return arg


def run_cmd(
    argv: list[str], env: dict[str, str], cwd: Path, prefix: Path, user: str
) -> dict[str, Any]:
    sandbox = [
        "unshare", "-n", "--",
        "strace", "-f", "-qq", "-e", "trace=connect", "-o", f"{prefix}.strace", "--",
        "setpriv", f"--reuid={user}", f"--regid={user}", "--init-groups", "--",
        "env", "-i", *[f"{k}={v}" for k, v in env.items()], *argv,
    ]  # fmt: skip
    started = time.monotonic()
    with open(f"{prefix}.stdout", "wb") as so, open(f"{prefix}.stderr", "wb") as se:
        proc = subprocess.Popen(  # noqa: S603 - argv is the operator's tool matrix
            sandbox, cwd=cwd, stdout=so, stderr=se, stdin=subprocess.DEVNULL,
            start_new_session=True,
        )  # fmt: skip
        timed_out = False
        while True:
            pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
            if pid:
                break
            if time.monotonic() - started > TIMEOUT_S:
                timed_out = True
                os.killpg(proc.pid, signal.SIGKILL)
                pid, status, usage = os.wait4(proc.pid, 0)
                break
            time.sleep(0.05)
    return {
        "argv": argv,
        "exit": os.waitstatus_to_exitcode(status),
        "timed_out": timed_out,
        "seconds": round(time.monotonic() - started, 2),
        "max_rss_bytes": usage.ru_maxrss * 1024,
    }


def run_tool_scenario(
    tool: str,
    spec: dict[str, Any],
    scenario: str,
    tag: str,
    commands: list[list[str]],
    corpus: Path,
    runs: Path,
    user: str,
) -> dict[str, Any]:
    import pwd

    pw = pwd.getpwnam(user)
    out = runs / tool / f"{scenario}{tag}"
    home = runs / "_home" / tool / f"{scenario}{tag}"
    for d in (out, home):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
    template = spec.get("home_template")
    if template:
        shutil.copytree(template, home, dirs_exist_ok=True)
    chown_tree(out, pw.pw_uid, pw.pw_gid)
    chown_tree(home, pw.pw_uid, pw.pw_gid)
    canary = corpus / "canary"
    for p in canary.iterdir():
        p.unlink()
    canary.chmod(0o1777)
    env = {
        "HOME": str(home),
        "PATH": ":".join(spec.get("path", []) + ["/usr/local/bin", "/usr/bin", "/bin"]),
        "LANG": "C.UTF-8",
        "TERM": "xterm-256color",
        "TMPDIR": str(home),
    }
    env.update(spec.get("env", {}))
    ctx = {"scn": str(corpus / "scenarios" / scenario), "out": str(out), "home": str(home)}
    results = []
    for i, cmd in enumerate(commands):
        argv = [expand(a, ctx) for a in cmd]
        results.append(run_cmd(argv, env, out, out / f"_cmd{i}", user))
    found = sorted(p.name for p in canary.iterdir())
    for p in canary.iterdir():
        p.unlink()
    record = {"tool": tool, "scenario": scenario, "tag": tag, "commands": results,
              "canaries": found}  # fmt: skip
    (out / "_run.json").write_text(json.dumps(record, indent=2))
    return record


def tool_version(spec: dict[str, Any]) -> str:
    try:
        cp = subprocess.run(  # noqa: S603
            spec["version_cmd"], capture_output=True, text=True, timeout=60,
            env={"PATH": ":".join(spec.get("path", []) + ["/usr/bin", "/bin"]),
                 "HOME": "/tmp"},  # noqa: S108
        )  # fmt: skip
        return (cp.stdout + cp.stderr).strip().splitlines()[-1][:120]
    except Exception as exc:  # noqa: BLE001 - recorded, not fatal
        return f"unknown ({type(exc).__name__})"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--tools", type=Path, required=True)
    ap.add_argument("--runs", type=Path, required=True)
    ap.add_argument("--tools-root", required=True, help="value for {T} in tools.json")
    ap.add_argument("--sandbox-user", default="bench")
    ap.add_argument("--only", nargs="*", help="tool names to run")
    ap.add_argument("--scenarios", nargs="*", help="scenario ids to run")
    args = ap.parse_args()
    truth = json.loads((args.corpus / "ground_truth.json").read_text())
    raw = args.tools.read_text().replace("{T}", args.tools_root)
    tools = json.loads(raw)["tools"]
    scenarios = [s["id"] for s in truth["scenarios"]]
    if args.scenarios:
        scenarios = [s for s in scenarios if s in args.scenarios]
    for name, spec in tools.items():
        if args.only and name not in args.only:
            continue
        if not spec.get("runnable", True):
            continue
        meta = {"tool": name, "version": tool_version(spec), "corpus_digest":
                truth["corpus_digest"], "seed": truth["seed"]}  # fmt: skip
        (args.runs / name).mkdir(parents=True, exist_ok=True)
        (args.runs / name / "_tool.json").write_text(json.dumps(meta, indent=2))
        for scn in scenarios:
            rec = run_tool_scenario(name, spec, scn, "", spec["commands"], args.corpus,
                                    args.runs, args.sandbox_user)  # fmt: skip
            secs = sum(c["seconds"] for c in rec["commands"])
            codes = [c["exit"] for c in rec["commands"]]
            print(f"{name:16} {scn:28} exit={codes} {secs:7.1f}s canaries={rec['canaries']}",
                  flush=True)  # fmt: skip
            if scn in DETERMINISM_SCENARIOS:
                run_tool_scenario(name, spec, scn, "#2", spec["commands"], args.corpus,
                                  args.runs, args.sandbox_user)  # fmt: skip
            if scn == EGRESS_SCENARIO and spec.get("default_commands"):
                run_tool_scenario(name, spec, scn, "#default", spec["default_commands"],
                                  args.corpus, args.runs, args.sandbox_user)  # fmt: skip


if __name__ == "__main__":
    main()
