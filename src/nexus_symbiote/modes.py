"""Offline and live operating modes.

Offline is the default. While a command runs offline, the process refuses at
the Python level to resolve host names, open outbound connections, listen for
connections or start processes, and the live HTTPS transport and the pinned
launcher check the mode again before they act. Live mode permits only the
explicit live operations of ``discover-mcp``, ``advisories`` and
``verify-live``; it adds no live step to any other command. The mode comes from
the command line or the environment, never from a project policy file, which
lives in the checkout being inventoried.

The guard is a tripwire for this package and its Python dependencies, not a
sandbox: native code that calls the operating system directly bypasses it.
Where a hard boundary is required, add operating-system controls such as a
network namespace, an egress policy or seccomp.
"""

from __future__ import annotations

import enum
import os
import socket
import subprocess
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, NoReturn

ENV_VAR = "NEXUS_SYMBIOTE_MODE"
LIVE_COMMANDS = frozenset({"advisories", "discover-mcp", "verify-live"})

_SOCKET_METHODS = ("connect", "connect_ex", "listen", "sendto", "sendmsg")
_SOCKET_FUNCTIONS = (
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
    "getnameinfo",
    "create_connection",
    "create_server",
)
_OS_FUNCTIONS = (
    "system",
    "popen",
    "fork",
    "forkpty",
    "posix_spawn",
    "posix_spawnp",
    "execv",
    "execve",
)
_MISSING = object()


class Mode(enum.Enum):
    OFFLINE = "offline"
    LIVE = "live"


class OfflineViolation(BaseException):
    """A network or process operation was attempted while offline mode was enforced.

    It derives from BaseException so that broad ``except Exception`` handlers in
    collectors cannot turn a violated guarantee into a recorded, soft failure.
    """


@dataclass(frozen=True)
class ResolvedMode:
    mode: Mode
    source: str

    @property
    def offline(self) -> bool:
        return self.mode is Mode.OFFLINE


def resolve(*, offline: bool, live: bool, environ: Mapping[str, str]) -> ResolvedMode:
    """Choose the mode: an explicit flag, then the environment, then offline."""
    if offline and live:
        raise ValueError("choose --offline or --live, not both")
    if offline or live:
        return ResolvedMode(Mode.OFFLINE if offline else Mode.LIVE, "flag")
    value = environ.get(ENV_VAR)
    if value is None:
        return ResolvedMode(Mode.OFFLINE, "default")
    if value not in {mode.value for mode in Mode}:
        raise ValueError(f"{ENV_VAR} must be 'offline' or 'live'")
    return ResolvedMode(Mode(value), "environment")


_lock = threading.Lock()
_active: Mode | None = None


def current() -> Mode | None:
    """The enforced mode, or None when no command enforces one (library use)."""
    return _active


def require_live(operation: str) -> None:
    """Refuse ``operation`` when offline mode is enforced; a no-op otherwise."""
    if _active is Mode.OFFLINE:
        raise OfflineViolation(operation)


def _refusal(operation: str) -> Callable[..., NoReturn]:
    def refuse(*_args: Any, **_kwargs: Any) -> NoReturn:
        raise OfflineViolation(operation)

    return refuse


def _guard() -> list[tuple[Any, str, Any]]:
    """Install every refusal, restoring what was installed if one of them fails."""
    patches: list[tuple[Any, str, Any]] = []
    try:
        _install(patches)
    except BaseException:
        _restore(patches)
        raise
    return patches


def _install(patches: list[tuple[Any, str, Any]]) -> None:
    """Replace each guarded entry point, recording the original for ``_restore``."""

    def patch(owner: Any, name: str, operation: str) -> None:
        if hasattr(owner, name):
            patches.append((owner, name, vars(owner).get(name, _MISSING)))
            setattr(owner, name, _refusal(operation))

    for name in _SOCKET_METHODS:
        patch(socket.socket, name, f"network access (socket.{name})")
    for name in _SOCKET_FUNCTIONS:
        patch(socket, name, f"network access (socket.{name})")
    patch(subprocess.Popen, "_execute_child", "process execution (subprocess)")
    for name in _OS_FUNCTIONS:
        patch(os, name, f"process execution (os.{name})")
    try:
        import _posixsubprocess
    except ImportError:
        pass
    else:
        patch(_posixsubprocess, "fork_exec", "process execution (fork_exec)")


def _restore(patches: list[tuple[Any, str, Any]]) -> None:
    for owner, name, original in reversed(patches):
        if original is _MISSING:
            delattr(owner, name)
        else:
            setattr(owner, name, original)


@contextmanager
def enforce(mode: Mode) -> Iterator[None]:
    """Enforce ``mode`` for the duration of the block; offline installs the guard."""
    global _active
    with _lock:
        if _active is not None:
            if _active is not mode:
                raise RuntimeError("another operating mode is already enforced")
            nested = True
        else:
            nested = False
            patches = _guard() if mode is Mode.OFFLINE else []
            _active = mode
    if nested:
        yield
        return
    try:
        yield
    finally:
        with _lock:
            _restore(patches)
            _active = None
