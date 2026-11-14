"""A setsid descendant of a pinned launcher dies with the session."""

from __future__ import annotations

import hashlib
import os
import signal
import sys
import time
from pathlib import Path

import pytest

from nexus_symbiote.live import pinned_process
from nexus_symbiote.live.pinned_process import isolation_off
from nexus_symbiote.live.session import PinnedStdioSession
from nexus_symbiote.live.stdio import observe_pinned


def _launcher(tmp_path: Path, marker: Path) -> tuple[Path, str]:
    path = tmp_path / "launcher"
    path.write_text(
        f"""#!{sys.executable}
import json, os, sys, time
marker = {str(marker)!r}
if os.fork() == 0:
    os.setsid()
    open(marker, "w").write(os.readlink("/proc/self"))
    time.sleep(60)
    raise SystemExit
for _ in range(100):
    if os.path.exists(marker) and os.path.getsize(marker):
        break
    time.sleep(0.01)
for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "notifications/initialized":
        continue
    if method == "initialize":
        result = {{
            "protocolVersion": "2025-06-18",
            "capabilities": {{"tools": {{}}}},
            "serverInfo": {{"name": "fixture", "version": "1"}},
        }}
    elif method == "tools/list":
        result = {{"tools": [{{"name": "weather", "description": "x", "inputSchema": {{"type": "object"}}}}]}}
    else:
        raise SystemExit(1)
    print(json.dumps({{"jsonrpc": "2.0", "id": request["id"], "result": result}}), flush=True)
"""
    )
    path.chmod(0o700)
    return path, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _host_pid(marker: Path) -> int:
    return int(marker.read_text())


def _assert_dead(pid: int) -> None:
    """The namespace teardown follows the supervisor's death by a short interval."""
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    raise AssertionError(f"process {pid} was still running")


def test_observe_pinned_kills_a_setsid_descendant(tmp_path: Path) -> None:
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    observe_pinned(str(command), digest)
    _assert_dead(_host_pid(marker))


def test_a_pinned_session_kills_a_setsid_descendant(tmp_path: Path) -> None:
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    with PinnedStdioSession(command=str(command), sha256=digest, server_id="server:mail"):
        pass
    _assert_dead(_host_pid(marker))


def test_setsid_descendant_dies_when_the_pid_namespace_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pinned_process, "namespace_available", lambda: False)
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    observe_pinned(str(command), digest)
    _assert_dead(_host_pid(marker))


def test_without_isolation_a_setsid_descendant_survives(tmp_path: Path) -> None:
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    with isolation_off():
        observe_pinned(str(command), digest)
    host = _host_pid(marker)
    os.kill(host, 0)
    os.kill(host, signal.SIGKILL)
