"""Offline and live operating modes for the command-line interface.

Offline is the default. While an offline command runs, this process refuses to
resolve host names, open or accept network connections, or start processes.
Live mode is an explicit operator choice (``--live`` before the command, or
``NEXUS_SYMBIOTE_MODE=live``) and only the commands in ``LIVE_COMMANDS`` need
it. A project policy file never selects the mode: it lives in the checkout
being inventoried, which is untrusted input.

The offline guard is a tripwire for this package and its Python dependencies,
not a sandbox. It replaces the Python entry points and adds a CPython audit
hook that fires for the C socket type as well (``_socket.socket``, also named
``socket.SocketType``, is immutable and cannot be patched) and refuses creating
any socket other than a Unix-domain socket. Native code that
calls the operating system directly bypasses it. Where a hard boundary is
required, also run the tool without network access, for example in a network
namespace or behind a deny-all egress policy.
"""

from __future__ import annotations

import _socket
import enum
import functools
import os
import socket
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, NoReturn

ENV_VAR = "NEXUS_SYMBIOTE_MODE"
LIVE_COMMANDS: dict[str, str] = {
    "advisories": "queries the OSV vulnerability API (api.osv.dev) over HTTPS",
    "discover-mcp": "connects to the MCP endpoint you name over HTTPS",
    "verify-live": "starts the operator-pinned MCP server launchers",
}

_SOCKET_METHODS = ("connect", "connect_ex", "listen", "sendto", "sendmsg")
_RESOLVER_FUNCTIONS = (
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
    "getnameinfo",
)
_CONNECTION_FUNCTIONS = ("create_connection", "create_server")
_PROCESS_FUNCTIONS = (
    "system",
    "fork",
    "forkpty",
    "posix_spawn",
    "posix_spawnp",
    "execv",
    "execve",
)
_MISSING = object()
# CPython raises these audit events inside the C implementations, so they also
# catch _socket.socket methods, references captured before the guard, and
# connect_ex (which raises socket.connect). listen, accept, send and recv have
# no audit event; the attribute patches above remain the guard for those.
# _posixsubprocess.fork_exec has no audit event either; it is patched instead.
_AUDIT_EVENTS = {
    "socket.connect": "network access (socket.connect)",
    "socket.sendto": "network access (socket.sendto)",
    "socket.sendmsg": "network access (socket.sendmsg)",
    "socket.getaddrinfo": "name resolution (socket.getaddrinfo)",
    "socket.gethostbyname": "name resolution (socket.gethostbyname)",
    "socket.gethostbyaddr": "name resolution (socket.gethostbyaddr)",
    "socket.getnameinfo": "name resolution (socket.getnameinfo)",
    "os.system": "process creation (os.system)",
    "os.fork": "process creation (os.fork)",
    "os.forkpty": "process creation (os.forkpty)",
    "os.posix_spawn": "process creation (os.posix_spawn)",
    "os.exec": "process creation (os.exec)",
    "subprocess.Popen": "process creation (subprocess)",
}
# Parsing a host-name address in connect, sendto or bind resolves it before any
# event above fires, so only Unix-domain sockets may be created. _socket.socket()
# reports the default family as -1 before it becomes AF_INET.
_LOCAL_SOCKET_FAMILY = int(socket.AF_UNIX)


class Mode(enum.Enum):
    OFFLINE = "offline"
    LIVE = "live"


class OfflineViolation(BaseException):
    """Network access or process creation was attempted while offline.

    It derives from BaseException so that a broad ``except Exception`` in a
    collector cannot turn a broken offline guarantee into a soft, recorded
    collection failure: the command stops instead.
    """


class LiveModeRequiredError(Exception):
    """A live command was started without live mode."""

    def __init__(self, command: str) -> None:
        self.command = command
        action = LIVE_COMMANDS.get(command, "needs network or process access")
        super().__init__(
            f"{command} is a live command: it {action}. Commands run offline by default. "
            f"Re-run with --live before the command (nexus-symbiote --live {command} ...) "
            f"or set {ENV_VAR}=live."
        )


@dataclass(frozen=True)
class ResolvedMode:
    mode: Mode
    source: str

    @property
    def offline(self) -> bool:
        return self.mode is Mode.OFFLINE


def resolve(*, offline: bool, live: bool, environ: Mapping[str, str]) -> ResolvedMode:
    """Choose the mode: an explicit flag, then the environment, then offline.

    An unrecognized environment value is an error rather than a fallback, so a
    typo can neither enable live mode nor hide a request for it.
    """
    if offline and live:
        raise ValueError("choose --offline or --live, not both")
    if offline or live:
        return ResolvedMode(Mode.OFFLINE if offline else Mode.LIVE, "flag")
    value = environ.get(ENV_VAR)
    if value is None or value == "":
        return ResolvedMode(Mode.OFFLINE, "default")
    if value not in {mode.value for mode in Mode}:
        raise ValueError(f"{ENV_VAR} must be 'offline' or 'live', not {value!r}")
    return ResolvedMode(Mode(value), "environment")


_lock = threading.Lock()
_active: Mode | None = None


def _audit(event: str, args: tuple[Any, ...]) -> None:
    if _active is not Mode.OFFLINE:
        return
    if event == "socket.__new__":
        if args[1] != _LOCAL_SOCKET_FAMILY:
            raise OfflineViolation("network access (socket other than Unix-domain)")
        return
    operation = _AUDIT_EVENTS.get(event)
    if operation is not None:
        raise OfflineViolation(operation)


@functools.cache
def _install_audit_hook() -> None:
    """Install the process-wide tripwire once.

    An audit hook cannot be removed, so instead of being installed and restored
    with the attribute patches it stays and checks ``_active`` on every event.
    """
    sys.addaudithook(_audit)


def current() -> Mode | None:
    """The enforced mode, or None when no command enforces one (library use)."""
    return _active


def command_mode(requested: Mode, command: str | None) -> Mode:
    """The mode one command runs in: only a live command can run live."""
    if requested is Mode.LIVE and command in LIVE_COMMANDS:
        return Mode.LIVE
    return Mode.OFFLINE


def require_live(command: str) -> None:
    """Refuse ``command`` unless this run enforces live mode.

    Outside the CLI's root group no mode is enforced; the environment then
    decides, and it defaults to offline.
    """
    mode = _active
    if mode is None:
        mode = resolve(offline=False, live=False, environ=os.environ).mode
    if mode is not Mode.LIVE:
        raise LiveModeRequiredError(command)


def _refusal(operation: str) -> Callable[..., NoReturn]:
    def refuse(*_args: Any, **_kwargs: Any) -> NoReturn:
        raise OfflineViolation(operation)

    return refuse


def _install(patches: list[tuple[Any, str, Any]]) -> None:
    def patch(owner: Any, name: str, operation: str) -> None:
        if hasattr(owner, name):
            patches.append((owner, name, vars(owner).get(name, _MISSING)))
            setattr(owner, name, _refusal(operation))

    for name in _SOCKET_METHODS:
        patch(socket.socket, name, f"network access (socket.{name})")
    # socket re-exports the resolver functions from _socket; a caller holding
    # either module's reference must hit the guard.
    for name in _RESOLVER_FUNCTIONS:
        patch(socket, name, f"name resolution (socket.{name})")
        patch(_socket, name, f"name resolution (socket.{name})")
    for name in _CONNECTION_FUNCTIONS:
        patch(socket, name, f"network access (socket.{name})")
    patch(subprocess.Popen, "_execute_child", "process creation (subprocess)")
    for name in _PROCESS_FUNCTIONS:
        patch(os, name, f"process creation (os.{name})")
    try:
        import _posixsubprocess
    except ImportError:
        pass
    else:
        patch(_posixsubprocess, "fork_exec", "process creation (fork_exec)")
    # subprocess binds its own reference to fork_exec at import time.
    patch(subprocess, "_fork_exec", "process creation (fork_exec)")


def _restore(patches: list[tuple[Any, str, Any]]) -> None:
    for owner, name, original in reversed(patches):
        if original is _MISSING:
            delattr(owner, name)
        else:
            setattr(owner, name, original)


def _guard() -> list[tuple[Any, str, Any]]:
    patches: list[tuple[Any, str, Any]] = []
    try:
        _install(patches)
    except BaseException:
        _restore(patches)
        raise
    return patches


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
            patches = []
            if mode is Mode.OFFLINE:
                _install_audit_hook()
                patches = _guard()
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
