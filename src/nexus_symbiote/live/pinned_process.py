"""Stage one digest-pinned launcher and stop it, including ``setsid`` descendants.

``live.stdio`` and ``live.session`` both copy the approved bytes and execute that
private copy. One helper keeps the copy, the digest check and the termination from
drifting apart. When the kernel allows a user and PID namespace, the launcher is
pid 1 of that namespace. It starts only once the caller holds a pidfd for it, and
cleanup kills it through that pidfd, or, where no pidfd can be held, as the child of a
stopped ``unshare``. Cleanup then waits until the kernel has ended every process in
the namespace, or reports that it could not. If the kernel refuses the namespace,
launch fails before executing the pinned program. On Linux,
``--no-isolation`` starts the launcher under a short wrapper that is a child subreaper
and stays its parent until no process of the launcher's tree is left. Every descendant,
including a double-fork, a ``clone(CLONE_PARENT)`` child and one that outlives the
launcher, stays under the wrapper. Cleanup stops that tree before it kills it, and
reports a failure when the wrapper ended first or the tree could not be emptied. A
launcher that deliberately evades cleanup, for example by killing the wrapper, can
escape. Elsewhere that cleanup is best effort. Neither is a PID or filesystem namespace.
"""

from __future__ import annotations

import contextlib
import contextvars
import ctypes
import hashlib
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

from nexus_symbiote.core.hashing import open_regular_file

_ISOLATION: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "nexus_symbiote_pinned_isolation", default=True
)
_LAUNCHER_BUDGET = 128 * 1024 * 1024
_NAMESPACE_OK: bool | None = None
_NAMESPACED: set[int] = set()
_INITS: dict[int, int] = {}
_RELEASE = b"\n"
_START_SECONDS = 5.0
# Opt-out launches only, recorded while the pid is unreaped: the session the launch leads,
# if any, and whether the pid is the supervising wrapper rather than the launcher.
_OPT_OUT: dict[int, tuple[int | None, bool]] = {}
_STOP_SECONDS = 1.0
_SWEEP_PASSES = 8
_TEARDOWN_SECONDS = 5.0
_HALTED = frozenset({b"T", b"t", b"Z", b"X"})
# Runs in a fresh interpreter, so the caller executes no Python between fork and exec.
# The interpreter ignores SIGPIPE and SIGXFSZ at startup and adds LC_CTYPE under the C
# locale, so the launcher restores both signals and receives the launch environment
# itself. The wrapper forks the launcher and stays its parent: a clone(CLONE_PARENT)
# child of the launcher is the wrapper's child, and as a subreaper it adopts every
# orphan below, so the whole tree stays under the pid the caller holds. It exits only
# once that tree is empty, with the launcher's status, re-raising a fatal signal as
# unshare --fork does. Any other way out of the wrapper is a SIGKILL, which cleanup
# reports, never an exit that looks like an empty tree.
_SUBREAPER_EXEC = """\
import ctypes, os, signal, sys
PR_SET_CHILD_SUBREAPER = 36
PR_SET_DUMPABLE = 4
prctl = ctypes.CDLL(None).prctl
prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
if prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
    os._exit(127)
# Held until the wrapper ignores them, so the launcher's first kill(0, SIGTERM) is too.
mask = signal.pthread_sigmask(signal.SIG_BLOCK, signal.valid_signals())
launcher = os.fork()
if launcher:
    try:
        # Only the launcher's tree holds the session's pipes, so its exit still ends them.
        null = os.open(os.devnull, os.O_RDWR)
        os.dup2(null, 0)
        os.dup2(null, 1)
        os.close(null)
        # No core file when a fatal signal is re-raised, and no same-uid ptrace attach.
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        # A launcher's kill(0, SIGTERM) must not end the wrapper before its tree.
        for number in signal.valid_signals() - {signal.SIGKILL, signal.SIGSTOP, signal.SIGCHLD}:
            try:
                signal.signal(number, signal.SIG_IGN)
            except (OSError, ValueError):
                pass
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        status = 0
        while True:
            try:
                pid, raw = os.waitpid(-1, 0)
            except ChildProcessError:
                break
            if pid == launcher:
                status = raw
        code = os.waitstatus_to_exitcode(status)
        if code >= 0:
            os._exit(code)
        if -code != signal.SIGKILL:
            signal.signal(-code, signal.SIG_DFL)
            signal.pthread_sigmask(signal.SIG_UNBLOCK, {-code})
        os.kill(os.getpid(), -code)
    finally:
        os.kill(os.getpid(), signal.SIGKILL)
signal.pthread_sigmask(signal.SIG_SETMASK, mask)
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
os.execve(sys.argv[1], [sys.argv[1]], {"PATH": os.defpath})
"""
# The namespace init runs this before the pinned bytes and waits for one byte on stdin.
# The caller writes it once it holds a pidfd for the init, so no launcher code can leave
# unshare's process group, kill unshare through it, or exit before cleanup can reach it.
_GATE_EXEC = """\
import os, signal, sys
if os.read(0, 1) != b"\\n":
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


@contextlib.contextmanager
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
    return _launch_argv(staged)[0]


def _launch_argv(staged: Path) -> tuple[list[str], bool]:
    """The argv that runs ``staged``, and whether the namespace init waits to be released."""
    if not isolation_enabled():
        return _subreaper_argv(staged) or [str(staged)], False
    if not namespace_available():
        raise PinnedProcessError(
            "isolation-unavailable",
            "kernel PID containment is unavailable; no launcher was executed. "
            "Explicitly opt out only in an independently isolated worker",
        )
    tool = _unshare_path()
    if tool is None:
        raise PinnedProcessError("isolation-unavailable", "PID namespace launcher is unavailable")
    gate = _gate_argv(staged)
    # --kill-child is a parent-death signal, which the launcher can clear, so cleanup
    # kills the namespace init itself; the flag covers an unshare that dies first.
    argv = [tool, "--user", "--map-root-user", "--pid", "--fork", "--kill-child", "--"]
    return [*argv, *(gate or [str(staged)])], gate is not None


def _stat_fields(pid: int) -> list[bytes] | None:
    """The fields of ``/proc/<pid>/stat`` after the command name, or None if unreadable.

    The command name before the last ``)`` is raw bytes that any process can set, so it
    is never decoded: a name that is not UTF-8 must not stop a cleanup scan.
    """
    try:
        with open(f"/proc/{pid}/stat", "rb") as stat:
            return stat.read().rpartition(b")")[2].split()
    except OSError:
        return None


def _parent(pid: int) -> int | None:
    """The parent of ``pid`` from ``/proc/<pid>/stat``, or None if it cannot be read."""
    fields = _stat_fields(pid)
    try:
        return int(fields[1]) if fields is not None else None
    except (ValueError, IndexError):
        return None


def _state(pid: int) -> bytes:
    """The one-letter state of ``pid``, or ``X`` once it cannot be read."""
    fields = _stat_fields(pid)
    return fields[0] if fields else b"X"


def _children_by_parent() -> dict[int, list[int]]:
    """Each parent pid's children, from one scan of ``/proc``; OSError if it is unreadable."""
    children: dict[int, list[int]] = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        parent = _parent(int(entry))
        if parent is not None:
            children.setdefault(parent, []).append(int(entry))
    return children


def _tree(root: int) -> set[int]:
    """Process-tree descendants of ``root``; OSError if ``/proc`` cannot be scanned."""
    children = _children_by_parent()
    found: set[int] = set()
    stack = [root]
    while stack:
        current = stack.pop()
        for child in children.get(current, ()):
            if child not in found:
                found.add(child)
                stack.append(child)
    return found


def _descendant_pids(root: int) -> set[int]:
    """Process-tree descendants of ``root``, including those that called ``setsid``."""
    try:
        return _tree(root)
    except OSError:
        return set()


def _kill_descendants(root: int) -> bool:
    """SIGKILL the descendant tree until a scan finds no descendant it has not signalled.

    A killed process cannot complete another fork, and a child it forked before the
    signal is found by the next scan, under ``root`` once its parent has died, because
    a living subreaper ``root`` adopts it. Zombies stay in the tree until reaped, so a
    scan counts only descendants not yet signalled. A process that keeps forking faster
    than the scans can outlast the bounded passes. Returns whether a scan found none
    left, which a ``/proc`` that cannot be scanned never shows.
    """
    signalled: set[int] = set()
    for _ in range(_SWEEP_PASSES):
        try:
            victims = _tree(root) - signalled
        except OSError:
            return False
        if not victims:
            return True
        for victim in victims:
            try:
                os.kill(victim, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                # It exited after the /proc scan, or it runs as another user and cannot be
                # signalled. Neither may stop cleanup before the launcher's group is killed.
                pass
        signalled |= victims
    try:
        return not _tree(root) - signalled
    except OSError:
        return False


def _stop_tree(root: int) -> None:
    """SIGSTOP every descendant of the stopped ``root`` until a scan finds none running.

    A stopped process can neither fork nor reap. So a watchdog anywhere in the tree
    cannot restart a helper that the sweep kills, and no pid the sweep finds is freed for
    reuse before it is signalled. Like the stop of ``root``, the wait is bounded: a
    process that is blocked in the kernel or traced is swept while it may still run, and
    one this user may not signal is left to the sweep.
    """
    refused: set[int] = set()
    deadline = time.monotonic() + _STOP_SECONDS
    delay = 0.0005
    while True:
        running = [pid for pid in _descendant_pids(root) - refused if _state(pid) not in _HALTED]
        if not running or time.monotonic() >= deadline:
            return
        for pid in running:
            try:
                os.kill(pid, signal.SIGSTOP)
            except ProcessLookupError:
                pass
            except PermissionError:
                refused.add(pid)
        time.sleep(delay)
        delay = min(delay * 2, 0.02)


def _stop_launcher(pid: int) -> int | None:
    """Stop the launcher, its wrapper or ``unshare``, so it cannot fork or reap in cleanup.

    A stopped subreaper is still alive, so on Linux it still adopts the children of
    every descendant the sweep kills. The kernel reports the stop only once
    every thread has stopped, which a thread does on its way out of the kernel, so a fork
    in progress has attached its child by then. The wait is bounded: a launcher that is
    traced or blocked in the kernel is swept while it may still run. Returns the
    ``si_code`` of the stop or exit that was seen, or None if neither was.
    """
    try:
        os.kill(pid, signal.SIGSTOP)
    except (ProcessLookupError, PermissionError):
        # It is gone, or not ours to signal; the sweep and killpg still run.
        return None
    deadline = time.monotonic() + _STOP_SECONDS
    delay = 0.0005
    while True:
        try:
            # WNOWAIT leaves the exit status for the caller's wait().
            changed = os.waitid(os.P_PID, pid, os.WSTOPPED | os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except OSError:
            # Not a child this process can wait for, or a system without these flags.
            return None
        if changed is not None:
            return changed.si_code
        if time.monotonic() >= deadline:
            return None
        time.sleep(delay)
        delay = min(delay * 2, 0.02)


def _status(pid: int) -> dict[str, str] | None:
    """The fields of ``/proc/<pid>/status``, or None once the pid no longer exists.

    The kernel escapes newlines, tabs and backslashes in the ``Name`` field but passes
    other bytes through, so a name that is not UTF-8 is decoded with escapes.
    """
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8", errors="surrogateescape") as status:
            return dict(line.rstrip("\n").split(":\t", 1) for line in status if ":\t" in line)
    except (FileNotFoundError, ProcessLookupError):
        return None


def _ended(pid: int) -> bool:
    """Whether ``pid`` has finished exiting, or cannot be shown not to have.

    The init of a PID namespace becomes a zombie only after the kernel has killed every
    other process in the namespace and waited for them. A thread-group leader that exits
    while another thread runs is a zombie too, so the thread count must have fallen to
    the leader alone. A status that cannot be read is not taken as an exit.
    """
    try:
        status = _status(pid)
    except (OSError, ValueError):
        return False
    if status is None:
        return True
    return status.get("State", "")[:1] in {"Z", "X"} and status.get("Threads") == "1"


def _end_namespace(supervisor: int) -> bool:
    """SIGKILL each child of the stopped ``unshare`` and wait until the kernel ends it.

    A launcher can clear the parent-death signal that ``--kill-child`` sets and leave
    the process group that killpg reaches. A SIGKILL from the parent namespace always
    reaches the namespace init, and the kernel then kills every process in the
    namespace, nested namespaces included. While ``unshare`` is stopped it cannot reap
    its child, so the child's pid cannot be reused before it is signalled and seen to
    exit. Returns False when the scan fails or the deadline passes first.
    """
    try:
        inits = _children_by_parent().get(supervisor, [])
    except OSError:
        return False
    for pid in inits:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(pid, signal.SIGKILL)
    deadline = time.monotonic() + _TEARDOWN_SECONDS
    delay = 0.0005
    while inits := [pid for pid in inits if not _ended(pid)]:
        if time.monotonic() >= deadline:
            return False
        time.sleep(delay)
        delay = min(delay * 2, 0.02)
    return True


def _end_init(init: int) -> bool:
    """SIGKILL the namespace init through its pidfd and wait until the namespace has ended.

    The pidfd becomes readable once the init has exited and every thread of it is gone,
    which the kernel allows only after it has killed and reaped every other process in
    the namespace. A pidfd keeps naming the init after ``unshare`` has died, even once
    its pid has been reaped and reused. Returns False when the deadline passes first.
    """
    with contextlib.suppress(ProcessLookupError):
        signal.pidfd_send_signal(init, signal.SIGKILL)
    poller = select.poll()
    poller.register(init, select.POLLIN)
    events = poller.poll(int(_TEARDOWN_SECONDS * 1000))
    return any(revents & select.POLLIN for _, revents in events)


def _end_unheld_namespace(proc: subprocess.Popen[bytes], stop: bool) -> bool:
    """End a namespace whose init the caller holds no pidfd for, or report that it cannot.

    A stopped ``unshare`` keeps its child's pid from being reaped and reused. If it has
    already exited, it reaped the init first, so the namespace has ended; if a signal
    killed it, the init may have cleared its parent-death signal and outlived it.
    """
    if not stop:
        return proc.returncode is not None and proc.returncode >= 0
    seen = _stop_launcher(proc.pid)
    if seen == os.CLD_STOPPED:
        return _end_namespace(proc.pid)
    return seen == os.CLD_EXITED


def _interpreter() -> str | None:
    """This interpreter, when a fixed exec wrapper can run it, or None."""
    interpreter = sys.executable
    if (
        not sys.platform.startswith("linux")
        or getattr(sys, "frozen", False)
        or not interpreter
        or not Path(interpreter).is_absolute()
    ):
        return None
    return interpreter


def _pidfd_supported() -> bool:
    return hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")


def _gate_argv(staged: Path) -> list[str] | None:
    """Run ``staged`` as the namespace init only once it is released, or None.

    The wrapper has the same constraints as the subreaper wrapper. Without a separately
    runnable interpreter, ``os.pidfd_open`` or ``signal.pidfd_send_signal``, the init
    starts at once, and cleanup finds it as the child of a stopped ``unshare`` instead.
    """
    interpreter = _interpreter()
    if interpreter is None or not _pidfd_supported():
        return None
    return [interpreter, "-I", "-S", "-B", "-c", _GATE_EXEC, str(staged)]


def _exited(pid: int) -> bool:
    try:
        return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    except OSError:
        return False


def _namespace_init(supervisor: int, depth: int) -> int | None:
    """The child of ``supervisor`` that is pid 1 of a PID namespace one level deeper."""
    for child in _children_by_parent().get(supervisor, []):
        status = _status(child)
        nspid = status.get("NSpid", "").split() if status is not None else []
        if len(nspid) == depth + 1 and nspid[-1] == "1":
            return child
    return None


def _hold_init(supervisor: int) -> int | None:
    """A pidfd for the namespace init of ``supervisor``, which waits in the gate.

    The pid is read again after the pidfd is opened: it is still the child of
    ``unshare``, which forks once, so the pidfd names the init and not a process that
    reused its pid. Returns None when ``/proc`` or the kernel cannot provide a verified
    pidfd; cleanup then falls back to stopping ``unshare``. Raises
    ``PinnedProcessError`` when no init starts, before any launcher code has run.
    """
    if not _pidfd_supported():
        return None
    try:
        status = _status(supervisor)
    except OSError:
        return None
    depth = len(status.get("NSpid", "").split()) if status is not None else 0
    if depth == 0:
        return None
    deadline = time.monotonic() + _START_SECONDS
    delay = 0.0005
    while True:
        try:
            init = _namespace_init(supervisor, depth)
        except OSError:
            return None
        if init is not None:
            break
        if _exited(supervisor) or time.monotonic() >= deadline:
            raise PinnedProcessError(
                "isolation-unavailable",
                "the PID namespace init did not start; no launcher was executed",
            )
        time.sleep(delay)
        delay = min(delay * 2, 0.02)
    try:
        pidfd = os.pidfd_open(init)
    except OSError:
        return None
    if _parent(init) == supervisor:
        return pidfd
    os.close(pidfd)
    raise PinnedProcessError(
        "isolation-unavailable", "the PID namespace init exited before the launcher was executed"
    )


def _own_session(pid: int) -> int | None:
    """``pid`` when it leads its own session, as ``start_new_session`` makes it, or None.

    The session sweep kills every member, so it must never reach the caller's session.
    The id stays this launch's while ``pid`` is unreaped, because no other process can
    then hold that pid to start a session with it.
    """
    try:
        return pid if os.getsid(pid) == pid else None
    except OSError:
        return None


def _kill_session(sid: int) -> None:
    """SIGKILL every live process that still shares ``sid``, for a few bounded passes.

    ``killpg`` misses a member that called ``setpgid``, and the tree sweep misses one
    whose ancestor died with no subreaper alive above it. A member that called ``setsid``
    has left the session and is not found here.
    """
    own = os.getpid()
    signalled: set[int] = set()
    for _ in range(_SWEEP_PASSES):
        try:
            entries = os.listdir("/proc")
        except OSError:
            return
        victims: set[int] = set()
        for entry in entries:
            if not entry.isdigit() or int(entry) in signalled or int(entry) in {own, 1}:
                continue
            fields = _stat_fields(int(entry))
            if fields is not None and len(fields) > 3 and fields[3] == str(sid).encode():
                if fields[0] not in {b"Z", b"X"}:
                    victims.add(int(entry))
        if not victims:
            return
        for pid in victims:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGKILL)
        signalled |= victims


def _end_wrapped_tree(proc: subprocess.Popen[bytes], stop: bool) -> bool:
    """Kill every process under the subreaper wrapper and report whether its tree ended.

    While the wrapper is alive, every process the launcher started is in its tree: the
    launcher is its child, a ``clone(CLONE_PARENT)`` child of the launcher is its child,
    and an orphan anywhere below is adopted by it. The wrapper is stopped first, so it
    cannot reap a killed process whose pid could then be reused, and the tree next, so a
    watchdog cannot restart a helper, and the tree is swept while the wrapper still
    adopts. The wrapper is then continued: it reaps the killed tree and exits only once
    no process of it is left, which confirms the tree ended and leaves nothing for pid 1
    to reap. A wrapper that exited normally before cleanup had emptied its tree already.

    Returns False when a signal ended the wrapper before cleanup, or a stopped wrapper
    died during it, since its tree may then have been adopted elsewhere; when the sweep
    did not empty the tree; and when a process of the tree, such as one this user may
    not signal, is still alive at the deadline. A wrapper stopped before it forked is
    not continued, since it would then start the launcher, but killed. The wrapper
    re-raises the signal that killed the launcher, so a launcher that crashed before
    cleanup is reported too, as on the namespaced path without a pidfd.
    """
    if not stop:
        # The wrapper was reaped already, so its pid may name another process.
        return proc.returncode is not None and proc.returncode >= 0
    seen = _stop_launcher(proc.pid)
    if seen == os.CLD_EXITED:
        return True
    if seen in {os.CLD_KILLED, os.CLD_DUMPED}:
        return False
    _stop_tree(proc.pid)
    try:
        # The wrapper forks once, so a tree shows that it has started the launcher.
        forked = bool(_tree(proc.pid))
    except OSError:
        return False
    if not _kill_descendants(proc.pid):
        return False
    if seen == os.CLD_STOPPED:
        # A stopped wrapper cannot exit by itself, so one that has ended was killed, and
        # an orphan the sweep made after that went to pid 1.
        if _exited(proc.pid):
            return False
        if not forked:
            # Continued, it could still start the launcher; it is killed while stopped.
            return True
        with contextlib.suppress(ProcessLookupError):
            os.kill(proc.pid, signal.SIGCONT)
    return _await_reaped(proc.pid)


def _await_reaped(wrapper: int) -> bool:
    """Wait until the running ``wrapper`` has reaped every process of its tree.

    The wrapper exits once it has none left. One that stops reaping cannot hide a live
    process: at the deadline, a tree whose processes have all exited has ended too, and
    a process still alive, or one blocked in the kernel, returns False.
    """
    deadline = time.monotonic() + _TEARDOWN_SECONDS
    delay = 0.0005
    while True:
        try:
            tree = _tree(wrapper)
        except OSError:
            return False
        if not tree:
            return True
        if time.monotonic() >= deadline:
            return all(_state(pid) in {b"Z", b"X"} for pid in tree)
        time.sleep(delay)
        delay = min(delay * 2, 0.02)


def _subreaper_argv(staged: Path) -> list[str] | None:
    """Run ``staged`` as the child of a subreaper wrapper that outlives it, or None.

    A double-fork calls ``setsid`` and then exits the intermediate process, so the
    grandchild's parent would otherwise become pid 1 and leave the descendant tree, and
    ``clone(CLONE_PARENT)`` gives the new process the launcher's parent. The wrapper is
    that parent and a subreaper, and it stays alive until its whole tree has exited, so
    both stay under the pid the caller holds, also after the launcher has exited. The
    wrapper runs before the pinned bytes, with this interpreter, a fixed program, the
    fixed launch environment and ``-I -S``, so environment variables, the working
    directory and site-packages do not reach it. Only Linux has
    ``PR_SET_CHILD_SUBREAPER``; elsewhere, or without a separately runnable
    interpreter, an opted-out launch keeps best-effort cleanup. The calling process
    is never marked.
    """
    interpreter = _interpreter()
    if interpreter is None:
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
    subreaper wrapper does its work after exec, within the caller's deadline. A
    namespace init waits in the gate until this process holds a pidfd for it, at most
    ``_START_SECONDS``.
    """
    if not _executable_image(staged):
        raise PinnedProcessError("launcher-start-failed", "launcher could not be run")
    try:
        argv, gated = _launch_argv(staged)
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
    else:
        _OPT_OUT[proc.pid] = (_own_session(proc.pid), argv[0] != str(staged))
    if gated:
        _release(proc)
    return proc


def _release(proc: subprocess.Popen[bytes]) -> None:
    """Hold the namespace init, then let it execute the launcher; on failure, end it."""
    assert proc.stdin is not None and proc.stdout is not None
    init: int | None = None
    try:
        init = _hold_init(proc.pid)
        os.write(proc.stdin.fileno(), _RELEASE)
    except BaseException as exc:
        # The init still waits in the gate, with the parent-death signal set, so killing
        # unshare ends it before any launcher code runs.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
        if init is not None:
            with contextlib.suppress(OSError):
                os.close(init)
        _NAMESPACED.discard(proc.pid)
        proc.stdin.close()
        proc.stdout.close()
        proc.wait()
        if isinstance(exc, PinnedProcessError) or not isinstance(exc, OSError):
            raise
        raise PinnedProcessError("launcher-start-failed", "launcher could not be run") from exc
    if init is not None:
        _INITS[proc.pid] = init


def terminate_process_group(proc: subprocess.Popen[bytes]) -> None:
    """Kill the session and every process the launcher started.

    In a PID namespace, the init is killed through the pidfd taken at launch, and
    cleanup waits until the kernel has ended the namespace. Without that pidfd,
    ``unshare`` is stopped so that it cannot reap the init, and the init is found as its
    child. If the namespace cannot be confirmed ended by the deadline, or ``unshare``
    was killed before cleanup with no pidfd held, ``unshare`` is still killed and
    ``PinnedProcessError`` reports ``isolation-teardown-failed``.

    Outside a namespace, on Linux, ``proc`` is a subreaper wrapper whose child is the
    launcher, and which stays alive until the launcher's whole tree has exited, so a
    double-fork and a ``clone(CLONE_PARENT)`` child are in the tree the sweep walks.
    The wrapper and then its tree are stopped, so nothing can start a process after the
    sweep, such as a helper that a watchdog restarts, and the tree is killed before the
    wrapper, which then reaps the tree. If the wrapper had ended by a signal, died during
    cleanup, the sweep did not empty the tree or a process of it outlived the deadline,
    ``PinnedProcessError`` reports ``isolation-teardown-failed``.
    Without the wrapper, cleanup is best effort and reports nothing: the launcher is
    stopped and swept the same way, but a descendant of a launcher that already exited
    was adopted outside the tree. Either way every process left in the launch's session
    is killed last.
    """
    namespaced = proc.pid in _NAMESPACED
    init = _INITS.pop(proc.pid, None)
    sid, wrapped = _OPT_OUT.pop(proc.pid, (None, False))
    # The sweep reads Linux's /proc, and macOS has no os.waitid before Python 3.13. Until
    # it is reaped, the pid is still this launcher's.
    stop = sys.platform.startswith("linux") and proc.returncode is None
    ended = True
    try:
        try:
            if namespaced or wrapped:
                try:
                    if wrapped:
                        ended = _end_wrapped_tree(proc, stop)
                    elif init is not None:
                        ended = _end_init(init)
                    else:
                        ended = _end_unheld_namespace(proc, stop)
                except Exception:
                    # Whatever failed, the launch was not shown to have ended.
                    ended = False
            else:
                if stop:
                    _stop_launcher(proc.pid)
                _kill_descendants(proc.pid)
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                # The group already exited; the caller's wait() still reaps the launcher.
                pass
        if sid is not None and stop:
            # Only while the launch is unreaped is no other session using its pid as an id.
            _kill_session(sid)
        if not namespaced:
            _kill_descendants(proc.pid)
    finally:
        # A finished pid must not stay marked. The kernel can reuse it for a later
        # launcher that is not in a PID namespace, and that launcher would then skip
        # the descendant-tree kill.
        _NAMESPACED.discard(proc.pid)
        if init is not None:
            try:
                if hasattr(signal, "pidfd_send_signal"):
                    with contextlib.suppress(OSError):
                        signal.pidfd_send_signal(init, signal.SIGKILL)
            finally:
                with contextlib.suppress(OSError):
                    os.close(init)
        if stop:
            # killpg has normally killed it already. If cleanup failed before that, a
            # stopped launcher would never read EOF and the caller's wait() would hang.
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(proc.pid, signal.SIGKILL)
    if not ended:
        scope = "PID namespace" if namespaced else "process tree"
        raise PinnedProcessError(
            "isolation-teardown-failed",
            f"the launcher's {scope} could not be confirmed ended; "
            "a process from it may still be running",
        )
