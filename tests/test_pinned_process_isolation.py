"""Default launches require kernel containment; explicit opt-out is best effort only."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.live import pinned_process, stdio
from nexus_symbiote.live.pinned_process import isolation_off
from nexus_symbiote.live.session import PinnedStdioSession
from nexus_symbiote.live.stdio import (
    LaunchPolicyError,
    SessionDeadlineError,
    StdioProtocolError,
    observe_pinned,
)
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
    """Wait for ``pid`` to exit; a running, sleeping or stopped process still fails.

    The namespace teardown follows the supervisor's death by a short interval. A
    killed orphan stays a zombie until its new parent waits, and a pid 1 that does
    not reap never does, so state Z (or X) counts as dead. ``kill(pid, 0)`` succeeds
    for a zombie and cannot tell the two apart.
    """
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as stat:
                state = stat.read().rpartition(")")[2].split()[0]
        except (FileNotFoundError, ProcessLookupError):
            return
        if state in {"Z", "X"}:
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


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("CDLL", _NoPrctl),
        ("platform", "darwin"),
        ("frozen", True),
        ("executable", ""),
        ("executable", "python3"),
    ],
)
def test_subreaper_wrapper_needs_linux_prctl_and_an_interpreter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attribute: str, value: object
) -> None:
    staged = tmp_path / "server"
    assert pinned_process._subreaper_argv(staged) == [
        sys.executable,
        "-I",
        "-S",
        "-B",
        "-c",
        pinned_process._SUBREAPER_EXEC,
        str(staged),
    ]
    owner = pinned_process.ctypes if attribute == "CDLL" else pinned_process.sys
    monkeypatch.setattr(owner, attribute, value, raising=False)
    assert pinned_process._subreaper_argv(staged) is None
    with isolation_off():
        assert pinned_process.isolated_argv(staged) == [str(staged)]


def test_opt_out_without_prctl_still_launches_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without prctl the launch skips the subreaper wrapper and keeps best-effort cleanup.
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
    usage = " ".join(CliRunner().invoke(main, ["verify-live", "--help"]).output.split())
    for text in (" ".join(allowed.stderr.split()), usage):
        assert "killed with the session while it is alive" in text
        assert "a descendant that outlives the launcher can escape" in text
        assert "not a namespace or sandbox" in text


def test_a_descendant_that_cannot_be_signalled_does_not_abort_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    kill, killpg = os.kill, os.killpg
    groups: list[int] = []

    def refuse(pid: int, sig: int) -> None:
        if marker.exists() and pid == _host_pid(marker):
            raise PermissionError(1, "Operation not permitted")
        kill(pid, sig)

    def record(pgid: int, sig: int) -> None:
        groups.append(pgid)
        killpg(pgid, sig)

    monkeypatch.setattr(pinned_process.os, "kill", refuse)
    monkeypatch.setattr(pinned_process.os, "killpg", record)
    try:
        with isolation_off():
            observe_pinned(str(command), digest)
    finally:
        monkeypatch.undo()
        kill(_host_pid(marker), signal.SIGKILL)
    assert len(groups) == 1
    _assert_dead(groups[0])


def test_no_launch_runs_python_between_fork_and_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # preexec_fn is unsafe in a threaded caller, and Popen waits for it before any
    # protocol deadline exists. The opt-out instead executes a fixed wrapper.
    launches: list[tuple[list[str], dict[str, Any]]] = []
    popen = subprocess.Popen

    def record(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        launches.append((argv, kwargs))
        return popen(argv, **kwargs)

    monkeypatch.setattr(pinned_process.subprocess, "Popen", record)
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker, detached=True)
    with isolation_off():
        observe_pinned(str(command), digest)
    _assert_dead(_host_pid(marker))
    argv, kwargs = launches[-1]
    if pinned_process.namespace_available():
        observe_pinned(str(command), digest)
    assert all(options.get("preexec_fn") is None for _, options in launches)
    wrapper = [sys.executable, "-I", "-S", "-B", "-c", pinned_process._SUBREAPER_EXEC]
    assert argv == [*wrapper, str(Path(kwargs["cwd"]) / "server")]
    assert kwargs["env"] == {"PATH": os.defpath}
    assert kwargs["start_new_session"] is True


# The shell applies a redirection to itself while the command runs, so the
# descriptors are read in a command substitution before any redirection.
STATE = r"""#!/bin/sh
fds=$(readlink /proc/$$/cwd /proc/$$/fd/0 /proc/$$/fd/1 /proc/$$/fd/2)
tr '\0' '\n' < /proc/$$/environ >> OUT
grep -E '^Sig(Ign|Blk):' /proc/$$/status >> OUT
tr '\0' '\n' < /proc/$$/cmdline >> OUT
printf '%s\n' "$fds" >> OUT
cat /proc/$$/stat >> OUT
"""


def _launch_state(tmp_path: Path, name: str) -> list[str]:
    out = tmp_path / f"{name}.state"
    script = tmp_path / name
    script.write_text(STATE.replace("OUT", shlex.quote(str(out))))
    script.chmod(0o700)
    pin = "sha256:" + hashlib.sha256(script.read_bytes()).hexdigest()
    with isolation_off(), pytest.raises(StdioProtocolError):
        observe_pinned(str(script), pin)
    *lines, stat = out.read_text().splitlines()
    pid = stat.split()[0]
    assert stat.rpartition(")")[2].split()[2:4] == [pid, pid]
    work = re.compile(r"\S*/nexus-live-\w+")
    return [re.sub(r"pipe:\[\d+\]", "pipe", work.sub("WORK", line)) for line in lines]


def test_the_subreaper_wrapper_hands_over_the_state_of_a_direct_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wrapped = _launch_state(tmp_path, "wrapped")
    monkeypatch.setattr(pinned_process, "_subreaper_argv", lambda staged: None)
    direct = _launch_state(tmp_path, "direct")
    assert wrapped == direct
    assert wrapped[0] == f"PATH={os.defpath}"
    assert [line.split(":")[0] for line in wrapped[1:3]] == ["SigBlk", "SigIgn"]
    assert wrapped[3:] == ["/bin/sh", "WORK/server", "WORK", "pipe", "pipe", "/dev/null"]


def test_a_stalled_subreaper_wrapper_is_bounded_by_the_protocol_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pinned_process, "_SUBREAPER_EXEC", "import time; time.sleep(60)")
    monkeypatch.setattr(stdio, "DEADLINE_SECONDS", 1.0)
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    started = time.monotonic()
    with isolation_off(), pytest.raises(SessionDeadlineError):
        observe_pinned(str(command), digest)
    assert time.monotonic() - started < 10
    assert not marker.exists()
