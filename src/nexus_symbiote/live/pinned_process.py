"""Stage one digest-pinned launcher and run it in a PID namespace.

``live.stdio`` and ``live.session`` both copy the approved bytes and execute that
private copy. One helper keeps the copy, the digest check and the process-group
termination from drifting apart. The launcher is pid 1 of a new PID namespace, so
a descendant that calls ``setsid`` still dies when the namespace's init is killed.
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
                    raise PinnedProcessError(
                        "launcher-unavailable", "launcher exceeds byte budget"
                    )
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


def isolated_argv(staged: Path) -> list[str]:
    """The argv that runs ``staged``, inside a PID namespace unless isolation is off."""
    if not isolation_enabled():
        return [str(staged)]
    tool = _unshare_path()
    if tool is None:
        raise PinnedProcessError(
            "isolation-unavailable",
            "pinned execution needs util-linux unshare for a user and PID namespace",
        )
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


def spawn_pinned(staged: Path, work: Path) -> subprocess.Popen[bytes]:
    """Start the staged launcher with a private cwd, a default PATH and a new session."""
    try:
        return subprocess.Popen(  # noqa: S603
            isolated_argv(staged),
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


def terminate_process_group(proc: subprocess.Popen[bytes]) -> None:
    """Kill the launcher's session. The PID namespace reaps descendants."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
