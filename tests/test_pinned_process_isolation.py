"""Default launches require kernel containment; explicit opt-out is best effort only."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.live import pinned_process
from nexus_symbiote.live.pinned_process import isolation_off
from nexus_symbiote.live.session import PinnedStdioSession
from nexus_symbiote.live.stdio import LaunchPolicyError, observe_pinned
from nexus_symbiote.runtime import AuthorizationError
from tests.test_pinned_stdio import command, inventory, launcher


def _launcher(tmp_path: Path, marker: Path, *, detached: bool = False) -> tuple[Path, str]:
    path = tmp_path / "launcher"
    path.write_text(
        f"""#!{sys.executable}
import json, os, sys, time
marker = {str(marker)!r}
if os.fork() == 0:
    os.setsid()
    if {detached!r}:
        if os.fork() == 0:
            open(marker, "w").write(os.readlink("/proc/self"))
            time.sleep(60)
        os._exit(0)
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
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    raise AssertionError(f"process {pid} was still running")


def test_observe_pinned_requires_containment_or_kills_its_descendants(tmp_path: Path) -> None:
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    if not pinned_process.namespace_available():
        with pytest.raises(LaunchPolicyError) as denied:
            observe_pinned(str(command), digest)
        assert denied.value.reason == "isolation-unavailable"
        assert not marker.exists()
        return
    observe_pinned(str(command), digest)
    _assert_dead(_host_pid(marker))


def test_a_pinned_session_requires_containment_or_kills_its_descendants(tmp_path: Path) -> None:
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    session = PinnedStdioSession(command=str(command), sha256=digest, server_id="server:mail")
    if not pinned_process.namespace_available():
        with pytest.raises(AuthorizationError, match="kernel PID containment"), session:
            pass
        assert not marker.exists()
        return
    with session:
        pass
    _assert_dead(_host_pid(marker))


@pytest.mark.parametrize("namespace_available", [False, True])
def test_a_missing_namespace_or_launcher_never_starts_the_pinned_program(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, namespace_available: bool
) -> None:
    monkeypatch.setattr(pinned_process, "namespace_available", lambda: namespace_available)
    if namespace_available:
        monkeypatch.setattr(pinned_process, "_unshare_path", lambda: None)
    starts = []

    def refuse_start(*args, **kwargs):
        starts.append(args)
        raise AssertionError("the pinned program must not be started")

    monkeypatch.setattr(pinned_process.subprocess, "Popen", refuse_start)
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    with pytest.raises(LaunchPolicyError) as denied:
        observe_pinned(str(command), digest)
    assert denied.value.reason == "isolation-unavailable"
    assert starts == []
    assert not marker.exists()


def test_a_finished_pid_is_not_remembered_as_namespaced() -> None:
    proc = subprocess.Popen(["/bin/true"], start_new_session=True)  # noqa: S603
    proc.wait(timeout=5)
    pinned_process._NAMESPACED.add(proc.pid)
    pinned_process.terminate_process_group(proc)
    assert proc.pid not in pinned_process._NAMESPACED


def test_a_forgotten_pid_is_swept_again_when_reused(monkeypatch: pytest.MonkeyPatch) -> None:
    swept: list[int] = []
    monkeypatch.setattr(pinned_process, "_kill_descendants", swept.append)
    proc = subprocess.Popen(["/bin/true"], start_new_session=True)  # noqa: S603
    proc.wait(timeout=5)
    pinned_process._NAMESPACED.add(proc.pid)
    pinned_process.terminate_process_group(proc)
    assert swept == []
    pinned_process.terminate_process_group(proc)
    assert swept == [proc.pid, proc.pid]


def test_opt_out_kills_a_double_fork_and_a_refused_namespace_never_starts_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker, detached=True)
    with isolation_off():
        observe_pinned(str(command), digest)
    _assert_dead(_host_pid(marker))

    monkeypatch.setattr(pinned_process, "namespace_available", lambda: False)
    off = tmp_path / "off"
    off.mkdir()
    blocked = off / "pid"
    blocked_command, blocked_digest = _launcher(off, blocked, detached=True)
    with pytest.raises(LaunchPolicyError) as denied:
        observe_pinned(str(blocked_command), blocked_digest)
    assert denied.value.reason == "isolation-unavailable"
    assert not blocked.exists()


class _NoPrctl:
    """A C library without prctl, as on macOS."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def __getattr__(self, name: str) -> object:
        raise AttributeError(name)


def test_subreaper_hook_needs_linux_and_prctl(monkeypatch: pytest.MonkeyPatch) -> None:
    assert pinned_process._subreaper_hook() is not None
    monkeypatch.setattr(pinned_process.ctypes, "CDLL", _NoPrctl)
    assert pinned_process._subreaper_hook() is None
    monkeypatch.undo()
    monkeypatch.setattr(pinned_process.sys, "platform", "darwin")
    assert pinned_process._subreaper_hook() is None


def test_opt_out_without_prctl_still_launches_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # prctl is looked up before the fork, so a C library without it never makes the
    # child fail between fork and exec; the launch keeps best-effort cleanup.
    monkeypatch.setattr(pinned_process.ctypes, "CDLL", _NoPrctl)
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    with isolation_off():
        observe_pinned(str(command), digest)
    _assert_dead(_host_pid(marker))


def test_cli_requires_an_explicit_opt_out_when_the_namespace_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pinned_process, "namespace_available", lambda: False)
    arguments, _ = command(tmp_path, inventory(), launcher(tmp_path))
    blocked = CliRunner().invoke(main, [*arguments, "--json-output"])
    assert blocked.exit_code == 1, blocked.output
    assert json.loads(blocked.stdout)["results"][0]["reason"] == "isolation-unavailable"
    allowed = CliRunner().invoke(main, [*arguments, "--json-output", "--no-isolation"])
    assert allowed.exit_code == 0, allowed.output
    assert "kernel PID containment is disabled" in allowed.stderr
