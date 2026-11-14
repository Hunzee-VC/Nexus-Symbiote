"""Stage one digest-pinned launcher and stop it, including ``setsid`` descendants.

``live.stdio`` and ``live.session`` both copy the approved bytes and execute that
private copy. One helper keeps the copy, the digest check and the termination from
drifting apart. When the kernel allows a user and PID namespace, the launcher is
pid 1 of that namespace and dies with every descendant. If the kernel refuses the
namespace, launch fails before executing the pinned program. On Linux,
``--no-isolation`` starts the launcher through a short exec wrapper that makes it a
child subreaper, and cleanup stops the launcher before it sweeps the tree, so while the
launcher is alive its descendants are killed with the session, including a double-fork.
A descendant that outlives the launcher can escape, and so can one that deliberately
evades the sweep. Elsewhere that cleanup is best effort. Neither is a PID or filesystem
namespace.
"""

from __future__ import annotations

import contextlib
import contextvars
import ctypes
import hashlib
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from nexus_symbiote.core.hashing import open_regular_file

_ISOLATION: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "nexus_symbiote_pinned_isolation", default=True
)
_LAUNCHER_BUDGET = 128 * 1024 * 1024
_NAMESPACE_OK: bool | None = None
_NAMESPACED: set[int] = set()
_STOP_SECONDS = 1.0
_SWEEP_PASSES = 8
# Runs in a fresh interpreter, so the caller executes no Python between fork and exec.
# The interpreter ignores SIGPIPE and SIGXFSZ at startup and adds LC_CTYPE under the C
# locale, so the wrapper restores both signals and passes the launch environment itself.
_SUBREAPER_EXEC = """\
import ctypes, os, signal, sys
PR_SET_CHILD_SUBREAPER = 36
prctl = ctypes.CDLL(None).prctl
prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
if prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
    os._exit(127)
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
os.execve(sys.argv[1], [sys.argv[1]], {"PATH": os.defpath})
"""


class PinnedProcessError(OSError):
    """The pinned launcher could not be staged or isolated."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def isolation_enabled() -> bool:
    return _ISOLATION.get()


@contextmanager
def isolation_off() -> Iterator[None]:
    """Explicitly accept a launch without kernel containment; descendants can escape."""
    token = _ISOLATION.set(False)
    try:
        yield
    finally:
        _ISOLATION.reset(token)


def stage_pinned_executable(command: str, digest: str, work: Path) -> Path:
    """Copy the exact bytes of ``command`` to ``work/server`` and check ``digest``."""
    if (
        os.name != "posix"
        or not Path(command).is_absolute()
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    ):
        raise PinnedProcessError(
            "invalid-launch-policy", "expected an absolute POSIX executable and its SHA-256 pin"
        )
    staged = work / "server"
    hasher = hashlib.sha256()
    budget = _LAUNCHER_BUDGET
    try:
        with open_regular_file(Path(command)) as source, staged.open("xb") as out:
            if os.fstat(source.fileno()).st_size > budget:
                raise PinnedProcessError("launcher-unavailable", "launcher exceeds byte budget")
            while chunk := source.read(1024 * 1024):
                budget -= len(chunk)
                if budget < 0:
                    raise PinnedProcessError("launcher-unavailable", "launcher exceeds byte budget")
                hasher.update(chunk)
                out.write(chunk)
    except PinnedProcessError:
        raise
    except OSError as exc:
        raise PinnedProcessError("launcher-unavailable", "launcher cannot be read") from exc
    if digest != "sha256:" + hasher.hexdigest():
        raise PinnedProcessError(
            "launcher-digest-mismatch", "launcher differs from approved digest"
        )
    staged.chmod(0o500)
    return staged


def _unshare_path() -> str | None:
    found = shutil.which("unshare", path=os.defpath)
    if found is None or not Path(found).is_absolute():
        return None
    return found


def namespace_available() -> bool:
    """Whether this process can start a user and PID namespace.

    The result is cached. Ubuntu 24.04 with AppArmor's unprivileged-user-namespace
    restriction returns false; the probe is one short ``unshare`` of ``/bin/true``.
    """
    global _NAMESPACE_OK
    if _NAMESPACE_OK is None:
        _NAMESPACE_OK = _probe_namespace()
    return _NAMESPACE_OK


def _probe_namespace() -> bool:
    tool = _unshare_path()
    true_bin = shutil.which("true", path=os.defpath)
    if tool is None or true_bin is None or not Path(true_bin).is_absolute():
        return False
    try:
        result = subprocess.run(  # noqa: S603
            [
                tool,
                "--user",
                "--map-root-user",
                "--pid",
                "--fork",
                "--kill-child",
                "--",
                true_bin,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def isolated_argv(staged: Path) -> list[str]:
    """The argv that runs ``staged``.

    A PID namespace is required unless the operator explicitly opted out. A PPid
    tree sweep cannot contain children that daemonize and are reparented, so an
    opted-out launch on Linux makes the launcher a child subreaper first.
    """
    if not isolation_enabled():
        return _subreaper_argv(staged) or [str(staged)]
    if not namespace_available():
        raise PinnedProcessError(
            "isolation-unavailable",
            "kernel PID containment is unavailable; no launcher was executed. "
            "Explicitly opt out only in an independently isolated worker",
        )
    tool = _unshare_path()
    if tool is None:
        raise PinnedProcessError("isolation-unavailable", "PID namespace launcher is unavailable")
    # --kill-child delivers SIGKILL to the namespace init when unshare dies, and the
    # kernel then kills every process in that namespace, including setsid descendants.
    return [
        tool,
        "--user",
        "--map-root-user",
        "--pid",
        "--fork",
        "--kill-child",
        "--",
        str(staged),
    ]


def _descendant_pids(root: int) -> set[int]:
    """Process-tree descendants of ``root``, including those that called ``setsid``."""
    children: dict[int, list[int]] = {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return set()
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/status", encoding="utf-8") as status:
                ppid = next(
                    (int(line.split()[1]) for line in status if line.startswith("PPid:")),
                    None,
                )
        except OSError:
            continue
        if ppid is not None:
            children.setdefault(ppid, []).append(pid)
    found: set[int] = set()
    stack = [root]
    while stack:
        current = stack.pop()
        for child in children.get(current, ()):
            if child not in found:
                found.add(child)
                stack.append(child)
    return found


def _kill_descendants(root: int) -> None:
    """SIGKILL the descendant tree until a scan finds no descendant it has not signalled.

    A killed process cannot complete another fork, and a child it forked before the
    signal is found by the next scan, under ``root`` once its parent has died, because
    a living subreaper ``root`` adopts it. Zombies stay in the tree until reaped, so a
    scan counts only descendants not yet signalled. A process that keeps forking faster
    than the scans can outlast the bounded passes.
    """
    signalled: set[int] = set()
    for _ in range(_SWEEP_PASSES):
        victims = _descendant_pids(root) - signalled
        if not victims:
            return
        for victim in victims:
            try:
                os.kill(victim, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                # It exited after the /proc scan, or it runs as another user and cannot be
                # signalled. Neither may stop cleanup before the launcher's group is killed.
                pass
        signalled |= victims


def _stop_launcher(pid: int) -> None:
    """Stop the launcher so it cannot fork while its descendants are swept.

    A stopped launcher is still alive, so on Linux it stays the subreaper that adopts the
    children of every descendant the sweep kills. The kernel reports the stop only once
    every thread has stopped, which a thread does on its way out of the kernel, so a fork
    in progress has attached its child by then. The wait is bounded: a launcher that is
    traced or blocked in the kernel is swept while it may still run.
    """
    try:
        os.kill(pid, signal.SIGSTOP)
    except (ProcessLookupError, PermissionError):
        # It is gone, or not ours to signal; the sweep and killpg still run.
        return
    deadline = time.monotonic() + _STOP_SECONDS
    delay = 0.0005
    while True:
        try:
            # WNOWAIT leaves the exit status for the caller's wait().
            changed = os.waitid(os.P_PID, pid, os.WSTOPPED | os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except OSError:
            # Not a child this process can wait for, or a system without these flags.
            return
        if changed is not None or time.monotonic() >= deadline:
            return
        time.sleep(delay)
        delay = min(delay * 2, 0.02)


def _subreaper_argv(staged: Path) -> list[str] | None:
    """Run ``staged`` through an exec wrapper that makes it a child subreaper, or None.

    A double-fork calls ``setsid`` and then exits the intermediate process, so the
    grandchild's parent would otherwise become pid 1 and leave the descendant tree.
    The flag is kept across exec, so while the launcher is alive it adopts every
    orphaned descendant and the tree sweep still finds it. Once the launcher has
    exited, its descendants are adopted outside that tree and the sweep misses them.
    The wrapper runs before the pinned bytes, with this interpreter, a fixed program,
    the fixed launch environment and ``-I -S``, so environment variables, the working
    directory and site-packages do not reach it. Only Linux has
    ``PR_SET_CHILD_SUBREAPER``; elsewhere, or without a separately runnable
    interpreter, an opted-out launch keeps best-effort cleanup. The calling process
    is never marked.
    """
    interpreter = sys.executable
    if (
        not sys.platform.startswith("linux")
        or getattr(sys, "frozen", False)
        or not interpreter
        or not Path(interpreter).is_absolute()
    ):
        return None
    try:
        if not hasattr(ctypes.CDLL(None), "prctl"):
            return None
    except OSError:
        return None
    return [interpreter, "-I", "-S", "-B", "-c", _SUBREAPER_EXEC, str(staged)]


def _executable_image(staged: Path) -> bool:
    """True when the kernel can exec the file directly: ELF or a shebang script.

    ``unshare`` and the subreaper wrapper execute the launcher themselves, so an exec
    failure there looks like an empty MCP session. Checking the image first keeps a
    file that is neither an ELF image nor a script ``launcher-start-failed`` on every
    launch path.
    """
    try:
        with staged.open("rb") as handle:
            prefix = handle.read(4)
    except OSError:
        return False
    return prefix.startswith(b"\x7fELF") or prefix.startswith(b"#!")


def spawn_pinned(staged: Path, work: Path) -> subprocess.Popen[bytes]:
    """Start the staged launcher with a private cwd, a default PATH and a new session.

    No Python runs in the child between fork and exec: that is unsafe in a threaded
    caller, and ``Popen`` would wait for it before any protocol deadline exists. The
    subreaper wrapper does its work after exec, within the caller's deadline.
    """
    if not _executable_image(staged):
        raise PinnedProcessError("launcher-start-failed", "launcher could not be run")
    try:
        argv = isolated_argv(staged)
        namespaced = isolation_enabled()
        proc = subprocess.Popen(  # noqa: S603
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=work,
            env={"PATH": os.defpath},
            start_new_session=True,
            bufsize=0,
        )
    except PinnedProcessError:
        raise
    except OSError as exc:
        raise PinnedProcessError("launcher-start-failed", "launcher could not be run") from exc
    if namespaced:
        _NAMESPACED.add(proc.pid)
    return proc


def terminate_process_group(proc: subprocess.Popen[bytes]) -> None:
    """Kill the session and, outside a PID namespace, every descendant of the launcher.

    On Linux the launcher is a child subreaper on that path, so a double-fork is
    reparented to it instead of pid 1 and the tree sweep still finds it. There the
    launcher is stopped first, so it cannot start a process after the sweep, such as a
    helper that a watchdog restarts, which would be reparented to pid 1 when killpg
    kills the launcher. A descendant left behind by a launcher that already exited was
    adopted outside the tree and is not found.
    """
    namespaced = proc.pid in _NAMESPACED
    # The sweep reads Linux's /proc, and macOS has no os.waitid before Python 3.13. Until
    # it is reaped, the pid is still this launcher's.
    stop = not namespaced and sys.platform.startswith("linux") and proc.returncode is None
    try:
        if stop:
            _stop_launcher(proc.pid)
        if not namespaced:
            _kill_descendants(proc.pid)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            # The group already exited; the caller's wait() still reaps the launcher.
            pass
        if not namespaced:
            _kill_descendants(proc.pid)
    finally:
        # A finished pid must not stay marked. The kernel can reuse it for a later
        # launcher that is not in a PID namespace, and that launcher would then skip
        # the descendant-tree kill.
        _NAMESPACED.discard(proc.pid)
        if stop:
            # killpg has normally killed it already. If cleanup failed before that, a
            # stopped launcher would never read EOF and the caller's wait() would hang.
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(proc.pid, signal.SIGKILL)
