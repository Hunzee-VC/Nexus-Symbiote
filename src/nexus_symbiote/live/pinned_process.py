"""Stage one digest-pinned launcher and stop it, including ``setsid`` descendants.

``live.stdio`` and ``live.session`` both copy the approved bytes and execute that
private copy. One helper keeps the copy, the digest check and the termination from
drifting apart. When the kernel allows a user and PID namespace, the launcher is
pid 1 of that namespace and dies with every descendant. Ubuntu 24.04 runners often
refuse the namespace; there the helper kills the descendant tree itself, so a
``setsid`` child still does not outlive the session.
"""

from __future__ import annotations

import contextvars
import hashlib
import os
import re
import shutil
import signal
import subprocess
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


class PinnedProcessError(OSError):
    """The pinned launcher could not be staged or isolated."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def isolation_enabled() -> bool:
    return _ISOLATION.get()


@contextmanager
def isolation_off() -> Iterator[None]:
    """Run pinned launchers in the caller's PID namespace. Descendants can escape."""
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

    A PID namespace is used when isolation is on and the kernel allows it. Otherwise
    the staged launcher is executed directly and termination kills its descendants.
    """
    if not isolation_enabled() or not namespace_available():
        return [str(staged)]
    tool = _unshare_path()
    if tool is None:
        return [str(staged)]
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
    """SIGKILL the descendant tree. Repeated so a fork during the sweep is caught."""
    for _ in range(8):
        victims = _descendant_pids(root)
        if not victims:
            return
        for victim in victims:
            try:
                os.kill(victim, signal.SIGKILL)
            except ProcessLookupError:
                pass


def _executable_image(staged: Path) -> bool:
    """True when the kernel can exec the file directly: ELF or a shebang script.

    A PID namespace hides an exec failure inside ``unshare``, which then looks like an
    empty MCP session. Checking the image first keeps that failure ``launcher-start-failed``
    on hosts that allow the namespace and on hosts that refuse it.
    """
    try:
        with staged.open("rb") as handle:
            prefix = handle.read(4)
    except OSError:
        return False
    return prefix.startswith(b"\x7fELF") or prefix.startswith(b"#!")


def spawn_pinned(staged: Path, work: Path) -> subprocess.Popen[bytes]:
    """Start the staged launcher with a private cwd, a default PATH and a new session."""
    if not _executable_image(staged):
        raise PinnedProcessError("launcher-start-failed", "launcher could not be run")
    try:
        argv = isolated_argv(staged)
        namespaced = isolation_enabled() and bool(argv) and argv[0] != str(staged)
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
    """Kill the launcher's session and, outside a PID namespace, its descendants.

    Descendants are killed first, while their parent is still alive, so a ``setsid``
    child is still visible in the process tree. The process group is killed after that.
    """
    namespaced = proc.pid in _NAMESPACED
    if isolation_enabled() and not namespaced:
        _kill_descendants(proc.pid)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if isolation_enabled() and not namespaced:
        _kill_descendants(proc.pid)
