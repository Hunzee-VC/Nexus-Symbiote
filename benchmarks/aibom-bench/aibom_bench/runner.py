"""Run one tool against every corpus variant and record what it did.

Every scan runs in a new network namespace with no interfaces except loopback, an empty
environment, a private HOME and no credentials. The second base run is traced so attempted
connections are recorded even though none can succeed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from . import corpus as corpus_module
from . import variants

BASE_TIMEOUT = 300
HOSTILE_TIMEOUT = 180
SOURCE_DATE_EPOCH = "1767225600"
# The two probes run a tool's plain documented command, with none of the safety or offline
# flags the scored scans may pass. One records attempted connections with no network
# available. The other runs on a small project with the host's network, so a tool that
# resolves dependencies by running the project's own install steps can do so.
EGRESS_PROBE = "probe:default-egress"
EXEC_PROBE = "probe:default-exec"
NETNS = ["unshare", "-n", "--", sys.executable, str(Path(__file__).with_name("netns_exec.py"))]
CONNECT = re.compile(
    r"connect\(\d+, \{sa_family=AF_INET6?, sin6?_port=htons\((\d+)\),"
    r".*?(?:inet_addr\(\"([^\"]+)\"\)|inet_pton\(AF_INET6, \"([^\"]+)\")"
)


def _fill(template: str, values: dict[str, str]) -> str:
    for name, value in values.items():
        template = template.replace("{" + name + "}", value)
    return template


def _build(variant: str, canary_dir: str) -> corpus_module.Corpus:
    if variant == EXEC_PROBE:
        return variants.build_exec_probe(canary_dir)
    built = corpus_module.build_base(canary_dir)
    if variant == "drift":
        variants.apply_drift(built)
    elif variant.startswith("hostile:"):
        variants.apply_hostile(built, variant.split(":", 1)[1])
    elif variant not in {"base", "repeat", EGRESS_PROBE}:
        raise ValueError(f"unknown variant: {variant}")
    return built


def _run(
    argv: list[str], env: dict[str, str], cwd: Path, stdout: Path, stderr: Path, timeout: int
) -> dict[str, object]:
    started = time.monotonic()
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(  # noqa: S603 - argv comes from a reviewed adapter file
            argv,
            env=env,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            start_new_session=True,
        )
        timed_out = False
        while True:
            pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if pid:
                break
            if time.monotonic() - started > timeout:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                _, status, usage = os.wait4(process.pid, 0)
                break
            time.sleep(0.05)
    return {
        "exit_code": os.waitstatus_to_exitcode(status),
        "seconds": round(time.monotonic() - started, 2),
        "max_rss_mb": round(usage.ru_maxrss / 1024, 1),
        "timed_out": timed_out,
    }


def _egress(trace: Path) -> list[str]:
    attempts = set()
    if not trace.exists():
        return []
    for line in trace.read_text(errors="replace").splitlines():
        match = CONNECT.search(line)
        if not match:
            continue
        address = match[2] or match[3]
        if address.startswith("127.") or address in {"::1", "::ffff:127.0.0.1"}:
            continue
        attempts.add(f"{address}:{match[1]}")
    return sorted(attempts)


def run_tool(
    adapter: dict[str, object],
    tools_root: Path,
    work_root: Path,
    selected: list[str],
    canary_dir: str = corpus_module.DEFAULT_CANARY_DIR,
) -> dict[str, object]:
    slug = str(adapter["tool"])
    work = work_root / slug
    values = {
        "tooldir": str(tools_root / slug),
        "repo": str(Path(__file__).resolve().parents[3]),
    }
    values["bin"] = _fill(str(adapter["bin"]), values)
    cwd = work / "cwd"
    cwd.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": ":".join(
            [
                *(_fill(part, values) for part in adapter.get("path", [])),
                "/usr/local/bin:/usr/bin:/bin",
            ]  # type: ignore[union-attr]
        ),
        "TERM": "dumb",
        "LANG": "C.UTF-8",
        "NO_COLOR": "1",
        "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
    }
    canaries = Path(canary_dir)
    runs: dict[str, object] = {}
    for variant in selected:
        target_root = work / "target"
        if target_root.exists():
            shutil.rmtree(target_root)
        target = variants.write(_build(variant, canary_dir), target_root)
        if canaries.exists():
            shutil.rmtree(canaries)
        canaries.mkdir(parents=True)
        out = work / "out" / variant.replace(":", "-")
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        # HOME is emptied for every variant, so a cache from one corpus cannot answer for
        # another, and keeps one path, so a tool that records it stays comparable.
        home = work / "home"
        if home.exists():
            shutil.rmtree(home)
        home.mkdir(parents=True)
        env["HOME"] = str(home)
        probe = variant in {EGRESS_PROBE, EXEC_PROBE}
        extra = adapter.get("default_env" if probe else "env", {})
        run_env = {**env, **{key: _fill(str(value), values) for key, value in extra.items()}}  # type: ignore[union-attr]
        values.update({"target": str(target), "out": str(out)})
        timeout = HOSTILE_TIMEOUT if variant.startswith("hostile:") else BASE_TIMEOUT
        scans = []
        planned = adapter["scans"]
        if probe:
            default = adapter.get("default")
            planned = [{"label": "default", **default}] if default else []  # type: ignore[dict-item]
        traced = variant in {"repeat", EGRESS_PROBE}
        for scan in planned:  # type: ignore[union-attr]
            if variant not in scan.get("only", [variant]):
                continue
            if any(done["timed_out"] for done in scans):
                break
            label = scan["label"]
            argv = [_fill(part, values) for part in scan["argv"]]
            trace = out / f"{label}.strace"
            prefix = [] if variant == EXEC_PROBE else [*NETNS]
            if traced:
                prefix += ["strace", "-f", "-qq", "-e", "trace=connect", "-o", str(trace)]
            result = _run(
                [*prefix, *argv],
                run_env,
                Path(_fill(scan.get("cwd", str(cwd)), values)),
                out / f"{label}.stdout",
                out / f"{label}.stderr",
                timeout,
            )
            outputs = [
                {"path": _fill(entry["path"], values), "format": entry["format"]}
                for entry in scan.get("outputs", [])
            ]
            if scan.get("stdout_format"):
                outputs.append(
                    {"path": str(out / f"{label}.stdout"), "format": scan["stdout_format"]}
                )
            for entry in outputs:
                path = Path(entry["path"])
                entry["bytes"] = path.stat().st_size if path.is_file() else None
            scans.append(
                {
                    "label": label,
                    "argv": argv,
                    **result,
                    "outputs": outputs,
                    "egress_attempts": _egress(trace) if traced else None,
                }
            )
        runs[variant] = {
            "scans": scans,
            "canaries_tripped": sorted(path.name for path in canaries.iterdir()),
        }
        shutil.rmtree(target_root)
    diff = adapter.get("diff")
    if diff and {"base", "drift"} <= set(selected):
        out = work / "out" / "diff"
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        values.update(
            {
                "base": str(work / "out" / "base"),
                "drift": str(work / "out" / "drift"),
                "out": str(out),
            }
        )
        argv = [_fill(part, values) for part in diff["argv"]]  # type: ignore[index]
        diff_env = {
            **env,
            **{key: _fill(str(value), values) for key, value in adapter.get("env", {}).items()},  # type: ignore[union-attr]
        }
        result = _run(
            [*NETNS, *argv], diff_env, cwd, out / "diff.stdout", out / "diff.stderr", BASE_TIMEOUT
        )
        runs["diff"] = {"argv": argv, **result}
    record = {"tool": slug, "version": adapter.get("version"), "runs": runs}
    (work / "runs.json").write_text(json.dumps(record, indent=2) + "\n")
    return record
