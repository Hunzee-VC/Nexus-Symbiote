"""Run tools against materialized cases inside a private network and mount namespace.

Every run sees the same absolute paths (``/mnt/bench/...``), an empty home directory,
no network and a cleared environment. The scanned project is a fresh copy, so the
runner can report what a tool changed in it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess  # noqa: S404 - the runner's purpose is to start the tools under test
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import corpus as corpus_module
from .cases_hostile import secret_values
from .model import (
    CANARY_DIR,
    CASE_DIR,
    HOME_DIR,
    OUT_DIR,
    OUTSIDE_DIR,
    RELOCATED_CASE_DIR,
    Case,
    Corpus,
    Files,
)
from .tools import OUT_NAMES, Tool

TIMEOUT_SECONDS = 300.0
MEMORY_GUARD_KB = 3 * 1024 * 1024
CANARY_NAME = re.compile(r"^h\d\d-[a-z-]+-canary$")
STATE_READ_LIMIT = 5 * 1024 * 1024

SANDBOX_SCRIPT = """
set -eu
mount -t tmpfs -o size=64m,mode=755 tmpfs /mnt
mkdir -p "$B_MOUNT" "$B_SANDBOX_HOME" "$B_SANDBOX_OUT" "$B_SANDBOX_CANARY" "$B_SANDBOX_OUTSIDE"
mount --bind "$B_CASE" "$B_MOUNT"
mount --bind "$B_HOME" "$B_SANDBOX_HOME"
mount --bind "$B_OUT" "$B_SANDBOX_OUT"
mount --bind "$B_CANARY" "$B_SANDBOX_CANARY"
mount --bind "$B_OUTSIDE" "$B_SANDBOX_OUTSIDE"
cd "$B_MOUNT"
exec "$@"
"""


@dataclass(frozen=True)
class Job:
    tool: Tool
    case: Case
    fmt: str
    variant: str = "base"
    files: Files | None = None

    @property
    def key(self) -> str:
        return f"{self.tool.id}/{self.case.id}/{self.variant.replace(':', '_')}/{self.fmt}"


@dataclass
class Record:
    tool: str
    case: str
    variant: str
    fmt: str
    argv: list[str]
    exit_code: int | None = None
    timed_out: bool = False
    memory_killed: bool = False
    wall_seconds: float = 0.0
    max_rss_kb: int = 0
    output_bytes: int = -1
    canaries: list[str] = field(default_factory=list)
    created: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    secrets_in_state: int = 0
    state_files: int = 0


def sandbox_supported() -> bool:
    """True when this process may create network and mount namespaces."""
    probe = ["unshare", "-n", "-m", "--", "sh", "-c", "mount -t tmpfs tmpfs /mnt"]
    try:
        return subprocess.run(probe, capture_output=True, check=False).returncode == 0  # noqa: S603
    except OSError:
        return False


def _environment(tool: Tool, home: str) -> list[str]:
    node = shutil.which("node")
    path = "/usr/local/bin:/usr/bin:/bin"
    if node:
        path = f"{Path(node).parent}:{path}"
    variables = {
        "HOME": home,
        "XDG_CONFIG_HOME": f"{home}/.config",
        "XDG_CACHE_HOME": f"{home}/.cache",
        "XDG_DATA_HOME": f"{home}/.local/share",
        "PATH": path,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "CI": "true",
    }
    variables.update(dict(tool.env))
    return ["env", "-i", *[f"{name}={value}" for name, value in variables.items()]]


def _rss_kb(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", encoding="ascii", errors="replace") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return 0
    return 0


def _wait(process: subprocess.Popen[bytes], record: Record) -> None:
    start = time.monotonic()
    deadline = start + TIMEOUT_SECONDS
    while True:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid:
            record.exit_code = os.waitstatus_to_exitcode(status)
            record.max_rss_kb = int(usage.ru_maxrss)
            break
        now = time.monotonic()
        over_memory = _rss_kb(process.pid) > MEMORY_GUARD_KB
        if now > deadline or over_memory:
            record.timed_out = now > deadline
            record.memory_killed = over_memory
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _, status, usage = os.wait4(process.pid, 0)
            record.exit_code = os.waitstatus_to_exitcode(status)
            record.max_rss_kb = int(usage.ru_maxrss)
            break
        time.sleep(0.02)
    process.returncode = record.exit_code
    record.wall_seconds = round(time.monotonic() - start, 3)


def _state_secrets(home: Path, secrets: Iterable[bytes]) -> tuple[int, int]:
    """Count files a tool left in its home directory, and those that hold a canary secret."""
    needles = list(secrets)
    files = 0
    leaking = 0
    for directory, _names, filenames in os.walk(home):
        for name in filenames:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            files += 1
            try:
                with open(path, "rb") as handle:
                    data = handle.read(STATE_READ_LIMIT)
            except OSError:
                continue
            if any(needle in data for needle in needles):
                leaking += 1
    return files, leaking


def run_dir(work: Path, job: Job) -> Path:
    return work / "runs" / job.key


def run_job(job: Job, corpus: Corpus, tools_root: Path, work: Path) -> Record:
    """Materialize the case, run the tool once in the sandbox and record what happened."""
    base = run_dir(work, job)
    if base.exists():
        shutil.rmtree(base)
    case_dir, home, out, canary, outside = (
        base / name for name in ("case", "home", "out", "canary", "outside")
    )
    for directory in (home, out, canary, outside):
        directory.mkdir(parents=True)
    corpus_module.materialize(job.case, case_dir, job.files)
    corpus_module.write_tree(corpus.outside, outside)
    before = corpus_module.tree_state(case_dir)

    mount = RELOCATED_CASE_DIR if job.variant == "relocated" else CASE_DIR
    sandbox_home = mount if job.case.home_scope else HOME_DIR
    argv = job.tool.argv(job.fmt, str(tools_root))
    record = Record(
        job.tool.id, job.case.id, job.variant, job.fmt, job.tool.argv(job.fmt, "{root}")
    )
    command = [
        "unshare",
        "-n",
        "-m",
        "--",
        "sh",
        "-c",
        SANDBOX_SCRIPT,
        "sh",
        *_environment(job.tool, sandbox_home),
        *argv,
    ]
    control = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "B_CASE": str(case_dir),
        "B_MOUNT": mount,
        "B_HOME": str(home),
        "B_OUT": str(out),
        "B_CANARY": str(canary),
        "B_OUTSIDE": str(outside),
        "B_SANDBOX_HOME": HOME_DIR,
        "B_SANDBOX_OUT": OUT_DIR,
        "B_SANDBOX_CANARY": CANARY_DIR,
        "B_SANDBOX_OUTSIDE": OUTSIDE_DIR,
    }
    with open(base / "stdout.bin", "wb") as stdout, open(base / "stderr.bin", "wb") as stderr:
        process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell interpolation of inputs
            command,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            env=control,
            start_new_session=True,
        )
        _wait(process, record)

    produced = out / OUT_NAMES[job.fmt]
    if produced.is_file():
        record.output_bytes = produced.stat().st_size
    record.canaries = sorted(path.name for path in canary.iterdir())
    after = corpus_module.tree_state(case_dir)
    record.created = sorted(set(after) - set(before))
    record.deleted = sorted(set(before) - set(after))
    record.modified = sorted(
        path for path in before if path in after and before[path] != after[path]
    )
    record.canaries += [path for path in record.created if CANARY_NAME.match(Path(path).name)]
    state_root = case_dir if job.case.home_scope else home
    record.state_files, record.secrets_in_state = _state_secrets(
        state_root, (value.encode() for value in secret_values())
    )
    (base / "record.json").write_text(json.dumps(asdict(record), indent=2) + "\n")
    for directory in (case_dir, home, canary, outside):
        shutil.rmtree(directory, ignore_errors=True)
    return record


def plan(tool: Tool, corpus: Corpus) -> list[Job]:
    """Every run one tool needs for a full round."""
    formats = list(tool.commands)
    extra = [fmt for fmt in formats if fmt != "cdx"]
    jobs: list[Job] = []
    for case in corpus.discovery:
        jobs.append(Job(tool, case, "cdx"))
        if "native" in formats:
            jobs.append(Job(tool, case, "native"))
    for pair in corpus.risk:
        for member in (pair.clean, pair.risky):
            jobs += [Job(tool, member, fmt) for fmt in formats]
    seen = {pair.risky.id for pair in corpus.risk}
    for hostile in corpus.hostile:
        for candidate in (hostile.case, hostile.twin):
            if candidate is None or candidate.id in seen:
                continue
            seen.add(candidate.id)
            jobs += [Job(tool, candidate, fmt) for fmt in ["cdx", *extra]]
    by_id = {case.id: case for case in corpus.discovery}
    for base_id in sorted({mutation.base for mutation in corpus.mutations}):
        jobs.append(Job(tool, by_id[base_id], "cdx", "repeat"))
        jobs.append(Job(tool, by_id[base_id], "cdx", "relocated"))
    for mutation in corpus.mutations:
        base = by_id[mutation.base]
        jobs.append(Job(tool, base, "cdx", f"mut:{mutation.id}", mutation.apply(base.files)))
    return jobs


def run_all(
    tools: Iterable[Tool],
    corpus: Corpus,
    tools_root: Path,
    work: Path,
    workers: int = 4,
    only_cases: frozenset[str] | None = None,
) -> list[Record]:
    jobs = [
        job
        for tool in tools
        if tool.measured
        for job in plan(tool, corpus)
        if only_cases is None or job.case.id in only_cases
    ]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda job: run_job(job, corpus, tools_root, work), jobs))
