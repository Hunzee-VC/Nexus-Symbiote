#!/usr/bin/env python3
"""Run AI-BOM tools over the seeded hostile corpus inside a confinement sandbox.

Each command runs in fresh network, PID and mount namespaces (only loopback up,
private /tmp, /var/tmp and /dev/shm), as an unprivileged user with no_new_privs,
under strace recording connect() and execve(), with a fresh HOME and TMPDIR, and
under a wall-clock timeout, with peak RSS taken from wait4(). When the tool's main
process exits, every process it left behind is killed. CI=true is set, as in a CI job.

The tool scans a fresh, writable copy of the scenario owned by the sandbox user, and
runs with that copy as its working directory, as in a CI checkout. A new copy is made
for every command, so a later output format never sees files an earlier command wrote.
Both versions of the drift scenario are scanned at the same path, as successive
commits would be.

Evidence the runner records (stdout, stderr, strace, _run.json) lives in a root-owned
directory; the tool can write only its out/ subdirectory.

Run as root on a disposable machine:

    python3 run.py --corpus /opt/seeded-corpus/corpus --tools tools.json \
        --tools-root /opt/seeded-corpus/tools --runs /opt/seeded-corpus/runs
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

TIMEOUT_S = 300
DETERMINISM_SCENARIOS = ("s01-models", "s04-mcp")
SCAN_ALIAS = {"s05-tooldefs-v1": "s05-tooldefs", "s05-tooldefs-v2": "s05-tooldefs"}
HERE = Path(__file__).resolve().parent

# Runs as root inside the new namespaces, then hands over to strace and the tool.
LO_UP = (
    "import fcntl,socket,struct;s=socket.socket();"
    "f=struct.unpack('16sH14s',fcntl.ioctl(s,0x8913,struct.pack('16sH14s',b'lo',0,b'')))[1];"
    "fcntl.ioctl(s,0x8914,struct.pack('16sH14s',b'lo',f|1,b''))"
)
ROOT_SETUP = (
    "mount -t tmpfs -o mode=1777 tmpfs /tmp && mount -t tmpfs -o mode=1777 tmpfs /var/tmp && "
    "(mount -t tmpfs -o mode=1777 tmpfs /dev/shm || true) && "
    f'{sys.executable} -c "{LO_UP}" && exec "$@"'
)
# Runs as the sandbox user: start the tool, then kill whatever it left behind.
REAPER = '"$@"; rc=$?; kill -KILL -1 2>/dev/null; exit $rc'


def chown_tree(path: Path, uid: int, gid: int) -> None:
    os.chown(path, uid, gid, follow_symlinks=False)
    for p in path.rglob("*"):
        os.chown(p, uid, gid, follow_symlinks=False)


def expand(arg: str, ctx: dict[str, str]) -> str:
    for key, value in ctx.items():
        arg = arg.replace("{" + key + "}", value)
    return arg


def sandbox_argv(argv: list[str], env: dict[str, str], prefix: Path, user: str) -> list[str]:
    return [
        "unshare", "-n", "-p", "-f", "--kill-child", "-m", "--",
        "sh", "-c", ROOT_SETUP, "sh",
        "strace", "-f", "-qq", "-s", "256", "-e", "trace=connect,execve",
        "-o", f"{prefix}.strace", "--",
        "setpriv", "--no-new-privs", f"--reuid={user}", f"--regid={user}", "--clear-groups",
        "--", "sh", "-c", REAPER, "sh",
        "env", "-i", *[f"{k}={v}" for k, v in env.items()], *argv,
    ]  # fmt: skip


def run_cmd(
    argv: list[str], env: dict[str, str], cwd: Path, prefix: Path, user: str
) -> dict[str, Any]:
    started = time.monotonic()
    with open(f"{prefix}.stdout", "wb") as so, open(f"{prefix}.stderr", "wb") as se:
        proc = subprocess.Popen(  # noqa: S603 - argv is the operator's tool matrix
            sandbox_argv(argv, env, prefix, user), cwd=cwd, stdout=so, stderr=se,
            stdin=subprocess.DEVNULL, start_new_session=True,
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
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return {
        "argv": argv,
        "exit": os.waitstatus_to_exitcode(status),
        "timed_out": timed_out,
        "seconds": round(time.monotonic() - started, 2),
        "max_rss_bytes": usage.ru_maxrss * 1024,
    }


def clear_dir(d: Path) -> list[str]:
    names = []
    for p in d.iterdir():
        names.append(p.name)
        try:
            if p.is_dir() and not p.is_symlink():
                shutil.rmtree(p)
            else:
                p.unlink()
        except OSError:
            pass
    return sorted(names)


def fresh_scan_copy(corpus: Path, scenario: str, work: Path, uid: int, gid: int) -> Path:
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    alias = SCAN_ALIAS.get(scenario, scenario)
    scan_dir = work / "scenarios" / alias
    # Laid out like the corpus, so relative symbolic links keep their targets.
    shutil.copytree(corpus / "scenarios" / scenario, scan_dir, symlinks=True)
    shutil.copytree(corpus / "outside", work / "outside", symlinks=True)
    chown_tree(work, uid, gid)
    return scan_dir


def run_tool_scenario(
    tool: str,
    spec: dict[str, Any],
    scenario: str,
    tag: str,
    commands: list[list[str]],
    tool_env: dict[str, str],
    corpus: Path,
    runs: Path,
    user: str,
    digest: str,
) -> dict[str, Any]:
    import pwd

    pw = pwd.getpwnam(user)
    run_dir = runs / tool / f"{scenario}{tag}"
    out = run_dir / "out"
    home = runs / "_home" / tool / f"{scenario}{tag}"
    work = runs / "_work" / tool
    for d in (run_dir, home):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
    run_dir.chmod(0o755)
    out.mkdir()
    template = spec.get("home_template")
    if template:
        shutil.copytree(template, home, dirs_exist_ok=True)
    chown_tree(out, pw.pw_uid, pw.pw_gid)
    chown_tree(home, pw.pw_uid, pw.pw_gid)
    canary = corpus / "canary"
    clear_dir(canary)
    canary.chmod(0o1777)
    env = {
        "HOME": str(home),
        "PATH": ":".join(spec.get("path", []) + ["/usr/local/bin", "/usr/bin", "/bin"]),
        "LANG": "C.UTF-8",
        "TERM": "xterm-256color",
        "TMPDIR": str(home),
        "CI": "true",
    }
    results = []
    scan_dir = work / "scenarios" / SCAN_ALIAS.get(scenario, scenario)
    for i, cmd in enumerate(commands):
        scan_dir = fresh_scan_copy(corpus, scenario, work, pw.pw_uid, pw.pw_gid)
        ctx = {"scn": str(scan_dir), "out": str(out), "home": str(home), "bench": str(HERE)}
        full_env = {**env, **{k: expand(v, ctx) for k, v in tool_env.items()}}
        argv = [expand(a, ctx) for a in cmd]
        results.append(run_cmd(argv, full_env, scan_dir, run_dir / f"_cmd{i}", user))
    found = clear_dir(canary)
    record = {"tool": tool, "scenario": scenario, "tag": tag, "scan_dir": str(scan_dir),
              "corpus_digest": digest, "commands": results, "canaries": found}  # fmt: skip
    (run_dir / "_run.json").write_text(json.dumps(record, indent=2))
    if work.exists():
        shutil.rmtree(work)
    return record


def tool_version(spec: dict[str, Any], runs: Path, user: str) -> str:
    """Run the version command in the same sandbox, never as root on the host."""
    prefix = runs / "_version"
    prefix.parent.mkdir(parents=True, exist_ok=True)
    env = {"PATH": ":".join(spec.get("path", []) + ["/usr/bin", "/bin"]), "HOME": "/tmp"}  # noqa: S108
    try:
        run_cmd(spec["version_cmd"], env, Path("/"), prefix, user)
        text = Path(f"{prefix}.stdout").read_bytes() + Path(f"{prefix}.stderr").read_bytes()
        return text.decode("utf-8", "replace").strip()[:400]
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
    corpus = args.corpus.resolve()
    truth_path = corpus / "ground_truth.json"
    truth = json.loads(truth_path.read_text())
    # Payloads write to the canary path baked in at generation time; a relocated corpus
    # would silently disable every execution gate.
    if Path(truth["safety"]["canary_path"]).resolve() != (corpus / "canary").resolve():
        sys.exit(f"corpus was generated for {truth['safety']['canary_path']}; regenerate it here")
    for secret_file in (truth_path, corpus / "catalog.md"):
        if secret_file.exists():
            secret_file.chmod(0o600)  # keep a holdout seed's answers from the tools
    lock = open(corpus / "canary" / ".." / ".run.lock", "w")  # noqa: SIM115
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit("another run.py is using this corpus; canary evidence would be mixed")
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
        meta = {"tool": name, "version": spec.get("version"),
                "version_reported": tool_version(spec, args.runs / name, args.sandbox_user),
                "corpus_digest": truth["corpus_digest"], "seed": truth["seed"]}  # fmt: skip
        (args.runs / name).mkdir(parents=True, exist_ok=True)
        (args.runs / name / "_tool.json").write_text(json.dumps(meta, indent=2))
        common = (corpus, args.runs, args.sandbox_user, truth["corpus_digest"])
        for scn in scenarios:
            rec = run_tool_scenario(name, spec, scn, "", spec["commands"], spec.get("env", {}),
                                    *common)  # fmt: skip
            secs = sum(c["seconds"] for c in rec["commands"])
            codes = [c["exit"] for c in rec["commands"]]
            print(f"{name:16} {scn:28} exit={codes} {secs:7.1f}s canaries={rec['canaries']}",
                  flush=True)  # fmt: skip
            if scn in DETERMINISM_SCENARIOS:
                run_tool_scenario(name, spec, scn, "#2", spec["commands"], spec.get("env", {}),
                                  *common)  # fmt: skip
            if spec.get("default_commands"):
                # The plain invocation: no benchmark flags and none of the tool env overrides.
                d = run_tool_scenario(name, spec, scn, "#default", spec["default_commands"], {},
                                      *common)  # fmt: skip
                print(f"{name:16} {scn + '#default':28} canaries={d['canaries']}", flush=True)


if __name__ == "__main__":
    main()
