"""Default launches require kernel containment; explicit opt-out is best effort only."""

from __future__ import annotations

import contextlib
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
from nexus_symbiote.live import pinned_process, stdio, verify
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

_SERVE = """
for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "notifications/initialized":
        continue
    if method == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fixture", "version": "1"},
        }
    elif method == "tools/list":
        result = {"tools": [{"name": "weather", "description": "x", "inputSchema": {"type": "object"}}]}
    else:
        raise SystemExit(1)
    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
"""


def _pinned(path: Path, prelude: str, serve: str = _SERVE) -> tuple[Path, str]:
    """A Python MCP server that runs ``prelude`` first, and its pin."""
    path.write_text(f"#!{sys.executable}\nimport json, os, sys, threading, time\n{prelude}{serve}")
    path.chmod(0o700)
    return path, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _launcher(tmp_path: Path, marker: Path, *, detached: bool = False) -> tuple[Path, str]:
    return _pinned(
        tmp_path / "launcher",
        f"""marker = {str(marker)!r}
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
""",
    )


def _watchdog_launcher(tmp_path: Path, helpers: Path) -> tuple[Path, str]:
    """A launcher whose watchdog thread restarts a ``setsid`` helper whenever it exits."""
    return _pinned(
        tmp_path / "watchdog",
        f"""import subprocess
helpers = {str(helpers)!r}
def watchdog():
    while True:
        helper = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True
        )
        open(os.path.join(helpers, str(helper.pid)), "w").close()
        helper.wait()
threading.Thread(target=watchdog, daemon=True).start()
while not os.listdir(helpers):
    time.sleep(0.01)
""",
    )


def _host_pid(marker: Path) -> int:
    return int(marker.read_text())


def _stat(pid: int) -> list[str]:
    """The state, parent and later fields of ``/proc/<pid>/stat``; ``["X"]`` once reaped."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as stat:
            return stat.read().rpartition(")")[2].split()
    except (FileNotFoundError, ProcessLookupError):
        return ["X"]


def _assert_dead(pid: int) -> None:
    """Wait for ``pid`` to exit; a running, sleeping or stopped process still fails.

    The namespace teardown follows the supervisor's death by a short interval. A
    killed orphan stays a zombie until its new parent waits, and a pid 1 that does
    not reap never does, so state Z (or X) counts as dead. ``kill(pid, 0)`` succeeds
    for a zombie and cannot tell the two apart.
    """
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if _stat(pid)[0] in {"Z", "X"}:
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


def test_opt_out_stops_the_launcher_before_its_tree_is_swept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The watchdog restarts its helper whenever the sweep kills it. A launcher that still
    # runs after the sweep starts another one in a new session, which pid 1 adopts once
    # killpg kills the launcher, out of reach of the second sweep. Cleanup must stop the
    # launcher first. Real timing opens that window only in some runs, so killpg here
    # waits until a running launcher has started such a helper, and returns once the
    # helper has been reparented, as a preempted cleanup thread would.
    helpers = tmp_path / "helpers"
    helpers.mkdir()
    command, digest = _watchdog_launcher(tmp_path, helpers)
    killpg = os.killpg
    late: set[int] = set()

    def preempted_killpg(pgid: int, sig: int) -> None:
        deadline = time.monotonic() + 5
        while not late and _stat(pgid)[0] not in {"T", "Z", "X"}:
            for pid in pinned_process._descendant_pids(pgid):
                fields = _stat(pid)
                # Alive, and leading its own session, so killpg does not reach it.
                if fields[0] not in {"Z", "X"} and fields[3] == str(pid):
                    late.add(pid)
            if time.monotonic() > deadline:
                break
            time.sleep(0.005)
        killpg(pgid, sig)
        while any(_stat(pid)[1:2] == [str(pgid)] for pid in late):
            if time.monotonic() > deadline:
                break
            time.sleep(0.005)

    monkeypatch.setattr(pinned_process.os, "killpg", preempted_killpg)
    try:
        with isolation_off():
            observe_pinned(str(command), digest)
        started = {int(entry.name) for entry in helpers.iterdir()}
        assert started
        for pid in sorted(started | late):
            _assert_dead(pid)
    finally:
        for pid in {int(entry.name) for entry in helpers.iterdir()} | late:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)


def test_a_launcher_that_does_not_stop_is_still_killed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A tracer can swallow SIGSTOP. The wait for the stop is bounded, and the running
    # launcher still adopts its double-forked grandchild until the sweep kills it.
    kill = os.kill

    def swallow_stop(pid: int, sig: int) -> None:
        if sig != signal.SIGSTOP:
            kill(pid, sig)

    monkeypatch.setattr(pinned_process.os, "kill", swallow_stop)
    monkeypatch.setattr(pinned_process, "_STOP_SECONDS", 0.2)
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker, detached=True)
    started = time.monotonic()
    with isolation_off():
        observe_pinned(str(command), digest)
    assert time.monotonic() - started < 10
    _assert_dead(_host_pid(marker))


def test_cleanup_elsewhere_than_linux_does_not_stop_the_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Python before 3.13 has no os.waitid on macOS, and the sweep that the stop serves
    # reads Linux's /proc.
    monkeypatch.setattr(pinned_process.sys, "platform", "darwin")
    monkeypatch.delattr(pinned_process.os, "waitid")
    kill = os.kill
    sent: list[int] = []

    def record(pid: int, sig: int) -> None:
        sent.append(sig)
        kill(pid, sig)

    monkeypatch.setattr(pinned_process.os, "kill", record)
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    with isolation_off():
        observe_pinned(str(command), digest)
    assert signal.SIGSTOP not in sent
    _assert_dead(_host_pid(marker))


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
        assert "stopped before cleanup" in text
        assert "killed with the session while it is alive" in text
        assert "a descendant that outlives the launcher can escape" in text
        assert "as can one that deliberately evades cleanup" in text
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


# The signal lines are read with builtins before the shell first forks. dash blocks
# every signal around a fork and clears its mask afterwards, so a later read shows
# either of those masks, never the one the launcher inherited. The shell applies a
# redirection to itself while the redirected command runs, so the descriptors are
# read in a command substitution outside any redirected command.
STATE = r"""#!/bin/sh
signals=
while read -r key value; do
  case $key in SigBlk:|SigIgn:) signals="$signals$key $value
" ;; esac
done < /proc/$$/status
fds=$(readlink /proc/$$/cwd /proc/$$/fd/0 /proc/$$/fd/1 /proc/$$/fd/2)
tr '\0' '\n' < /proc/$$/environ >> OUT
printf '%s' "$signals" >> OUT
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


def _wrapped_and_direct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[list[str], list[str], set[int]]:
    """The launch state through the wrapper and by direct exec, and the blocked signals.

    The launcher inherits the calling thread's blocked signals, so one is blocked here
    to show that the mask reaches the launcher, and a mask the wrapper adds would not.
    """
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
    try:
        wrapped = _launch_state(tmp_path, "wrapped")
        with monkeypatch.context() as direct_exec:
            direct_exec.setattr(pinned_process, "_subreaper_argv", lambda staged: None)
            direct = _launch_state(tmp_path, "direct")
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    return wrapped, direct, {*previous, signal.SIGUSR2}


def test_the_subreaper_wrapper_hands_over_the_state_of_a_direct_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wrapped, direct, blocked = _wrapped_and_direct(tmp_path, monkeypatch)
    assert wrapped == direct
    assert wrapped[0] == f"PATH={os.defpath}"
    mask = sum(1 << (number - 1) for number in blocked)
    assert wrapped[1].split() == ["SigBlk:", f"{mask:016x}"]
    assert wrapped[2].split(":")[0] == "SigIgn"
    assert wrapped[3:] == ["/bin/sh", "WORK/server", "WORK", "pipe", "pipe", "/dev/null"]


@pytest.mark.parametrize(
    ("restored", "leak"),
    [
        ("os.execve(", "signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})\nos.execve("),
        ("signal.signal(signal.SIGPIPE, signal.SIG_DFL)\n", ""),
        ("signal.signal(signal.SIGXFSZ, signal.SIG_DFL)\n", ""),
        ('{"PATH": os.defpath}', "os.environ"),
    ],
    ids=["blocked-signal", "ignored-sigpipe", "ignored-sigxfsz", "environment"],
)
def test_the_launch_state_comparison_detects_a_wrapper_that_leaks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restored: str, leak: str
) -> None:
    leaky = pinned_process._SUBREAPER_EXEC.replace(restored, leak)
    assert leaky != pinned_process._SUBREAPER_EXEC
    monkeypatch.setattr(pinned_process, "_SUBREAPER_EXEC", leaky)
    wrapped, direct, _ = _wrapped_and_direct(tmp_path, monkeypatch)
    assert wrapped != direct


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


# A launcher, or a library it loads, can clear the parent-death signal that
# ``--kill-child`` sets and leave the process group that killpg reaches. Each variant
# records the host pid of every process it wants to outlive the session.
_ESCAPE = """import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
pids = {pids!r}
def record():
    open(os.path.join(pids, os.readlink("/proc/self")), "w").close()
if libc.prctl(1, 0, 0, 0, 0) != 0:
    raise SystemExit(3)
{leave}
record()
{spawn}
deadline = time.monotonic() + 5
while len(os.listdir(pids)) < {count} and time.monotonic() < deadline:
    time.sleep(0.01)
"""
_FORKED = """if os.fork() == 0:
    os.setsid()
    record()
    time.sleep(60)
    os._exit(0)
"""
_DAEMON = """if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        record()
        time.sleep(60)
    os._exit(0)
"""
# The launcher is root in its user namespace, so it can start a nested PID namespace.
_NESTED = """if libc.unshare(0x20000000) != 0:
    raise SystemExit(4)
if os.fork() == 0:
    record()
    time.sleep(60)
    os._exit(0)
"""
_ESCAPES = {
    "setsid": ("os.setsid()", "", 1),
    "setpgid": ("os.setpgid(0, 0)", "", 1),
    "setsid-child": ("os.setsid()", _FORKED, 2),
    "setsid-double-fork": ("os.setsid()", _DAEMON, 2),
    "nested-pid-namespace": ("os.setsid()", _NESTED, 2),
}


def _escaping_launcher(tmp_path: Path, variant: str) -> tuple[Path, str, Path, int]:
    pids = tmp_path / "pids"
    pids.mkdir()
    leave, spawn, count = _ESCAPES[variant]
    prelude = _ESCAPE.format(pids=str(pids), leave=leave, spawn=spawn, count=count)
    # Outlive the end of stdin as well, in case cleanup closes it first.
    command, digest = _pinned(tmp_path / "launcher", prelude, _SERVE + "time.sleep(60)\n")
    return command, digest, pids, count


def _recorded(pids: Path) -> list[int]:
    return sorted(int(entry.name) for entry in pids.iterdir())


def _kill_leftovers(pids: Path) -> None:
    for pid in _recorded(pids):
        if _stat(pid)[0] not in {"Z", "X"}:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)


@pytest.mark.parametrize("entry", ["observe_pinned", "PinnedStdioSession"])
@pytest.mark.parametrize("variant", sorted(_ESCAPES))
def test_a_launcher_that_drops_its_death_signal_and_group_ends_with_the_session(
    tmp_path: Path, variant: str, entry: str
) -> None:
    command, digest, pids, count = _escaping_launcher(tmp_path, variant)
    if not pinned_process.namespace_available():
        with pytest.raises(LaunchPolicyError) as denied:
            observe_pinned(str(command), digest)
        assert denied.value.reason == "isolation-unavailable"
        assert _recorded(pids) == []
        return
    try:
        if entry == "observe_pinned":
            assert [tool["name"] for tool in observe_pinned(str(command), digest).tools] == [
                "weather"
            ]
        else:
            with PinnedStdioSession(command=str(command), sha256=digest, server_id="server:mail"):
                pass
        recorded = _recorded(pids)
        assert len(recorded) == count
        # Cleanup returns only once the kernel has ended the namespace, so there is no
        # grace period here.
        states = {pid: _stat(pid)[0] for pid in recorded}
        assert set(states.values()) <= {"Z", "X"}, states
    finally:
        _kill_leftovers(pids)


def test_a_launcher_that_exits_after_its_reply_is_not_a_teardown_failure(tmp_path: Path) -> None:
    serve = _SERVE.replace(
        "flush=True)\n", 'flush=True)\n    if method == "tools/list":\n        os._exit(0)\n'
    )
    command, digest = _pinned(tmp_path / "launcher", "", serve)
    if not pinned_process.namespace_available():
        with pytest.raises(LaunchPolicyError, match="kernel PID containment"):
            observe_pinned(str(command), digest)
        return
    for _ in range(5):
        assert [tool["name"] for tool in observe_pinned(str(command), digest).tools] == ["weather"]


# A stand-in for ``unshare --fork`` that needs no namespace: it waits for a child that
# has left its session, as a namespace init that called setsid has.
_SUPERVISOR = """import os, sys, time
if sys.argv[2] == "idle":
    time.sleep(60)
child = os.fork()
if child == 0:
    os.setsid()
    open(sys.argv[1], "w").write(str(os.getpid()))
    if sys.argv[2] == "exit":
        os._exit(0)
    time.sleep(60)
    os._exit(0)
os.waitpid(child, 0)
"""


def _supervised(tmp_path: Path, mode: str = "wait") -> tuple[subprocess.Popen[bytes], int | None]:
    """A process marked as ``unshare``, and the pid of its child once it has one."""
    marker = tmp_path / "init"
    proc = subprocess.Popen(  # noqa: S603
        [sys.executable, "-I", "-S", "-c", _SUPERVISOR, str(marker), mode],
        start_new_session=True,
    )
    pinned_process._NAMESPACED.add(proc.pid)
    if mode == "idle":
        return proc, None
    deadline = time.monotonic() + 10
    while not (marker.exists() and marker.read_text()) and time.monotonic() < deadline:
        time.sleep(0.01)
    if mode == "exit":
        os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT)
    return proc, int(marker.read_text())


def _end_supervised(proc: subprocess.Popen[bytes], init: int | None) -> None:
    pinned_process._NAMESPACED.discard(proc.pid)
    for pid in (proc.pid, init):
        if pid is not None and _stat(pid)[0] not in {"Z", "X"}:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
    proc.wait(timeout=5)


def test_namespaced_cleanup_kills_an_init_that_left_the_process_group(tmp_path: Path) -> None:
    proc, init = _supervised(tmp_path)
    assert init is not None
    try:
        pinned_process.terminate_process_group(proc)
        assert proc.wait(timeout=5) == -signal.SIGKILL
        assert _stat(init)[0] in {"Z", "X"}
        assert proc.pid not in pinned_process._NAMESPACED
    finally:
        _end_supervised(proc, init)


@pytest.mark.parametrize("mode", ["idle", "exit"])
def test_namespaced_cleanup_without_a_running_init_succeeds(tmp_path: Path, mode: str) -> None:
    # unshare stopped before it forked, or after its init exited: nothing is left to end.
    proc, init = _supervised(tmp_path, mode)
    try:
        pinned_process.terminate_process_group(proc)
        assert proc.wait(timeout=5) == (-signal.SIGKILL if mode == "idle" else 0)
    finally:
        _end_supervised(proc, init)


def test_namespaced_cleanup_fails_closed_when_the_init_does_not_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An init that never finishes exiting, as one blocked in the kernel would, must not
    # be reported as ended.
    proc, init = _supervised(tmp_path)
    kill = os.kill

    def spare_init(pid: int, sig: int) -> None:
        if pid != init:
            kill(pid, sig)

    try:
        monkeypatch.setattr(pinned_process.os, "kill", spare_init)
        monkeypatch.setattr(pinned_process, "_TEARDOWN_SECONDS", 0.2)
        with pytest.raises(pinned_process.PinnedProcessError) as failed:
            pinned_process.terminate_process_group(proc)
        assert failed.value.reason == "isolation-teardown-failed"
        assert proc.wait(timeout=5) == -signal.SIGKILL
        assert proc.pid not in pinned_process._NAMESPACED
    finally:
        monkeypatch.undo()
        _end_supervised(proc, init)


def test_namespaced_cleanup_signals_no_child_of_a_running_unshare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Only a stopped unshare keeps its child's pid from being reaped and reused, so a
    # stop that never arrives is reported, and no pid is signalled on a stale scan.
    proc, init = _supervised(tmp_path)
    kill = os.kill
    sent: list[int] = []

    def swallow_stop(pid: int, sig: int) -> None:
        sent.append(pid)
        if sig != signal.SIGSTOP:
            kill(pid, sig)

    try:
        monkeypatch.setattr(pinned_process.os, "kill", swallow_stop)
        monkeypatch.setattr(pinned_process, "_STOP_SECONDS", 0.2)
        with pytest.raises(pinned_process.PinnedProcessError) as failed:
            pinned_process.terminate_process_group(proc)
        assert failed.value.reason == "isolation-teardown-failed"
        assert set(sent) == {proc.pid}
        assert proc.wait(timeout=5) == -signal.SIGKILL
    finally:
        monkeypatch.undo()
        _end_supervised(proc, init)


@pytest.mark.parametrize(
    ("status", "ended"),
    [
        (None, True),
        ({"State": "Z (zombie)", "Threads": "1"}, True),
        ({"State": "X (dead)", "Threads": "1"}, True),
        # A thread-group leader that exited while another thread still runs.
        ({"State": "Z (zombie)", "Threads": "2"}, False),
        ({"State": "S (sleeping)", "Threads": "1"}, False),
        ({"State": "D (disk sleep)", "Threads": "1"}, False),
        ({"State": "T (stopped)", "Threads": "1"}, False),
        ({"State": "Z (zombie)"}, False),
        ({}, False),
    ],
)
def test_an_init_has_ended_only_once_every_thread_has_exited(
    monkeypatch: pytest.MonkeyPatch, status: dict[str, str] | None, ended: bool
) -> None:
    monkeypatch.setattr(pinned_process, "_status", lambda pid: status)
    assert pinned_process._ended(4242) is ended


def test_an_unreadable_init_status_is_not_an_ended_init(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(pid: int) -> dict[str, str] | None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(pinned_process, "_status", refuse)
    assert pinned_process._ended(4242) is False


def test_the_status_reader_returns_the_fields_of_a_live_and_a_reaped_process() -> None:
    fields = pinned_process._status(os.getpid())
    assert fields is not None
    assert fields["State"][0] in {"R", "S"}
    assert fields["PPid"] == str(os.getppid())
    proc = subprocess.Popen(["/bin/true"])  # noqa: S603
    proc.wait(timeout=5)
    assert pinned_process._status(proc.pid) is None


def test_verify_live_fails_a_server_whose_namespace_did_not_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    terminate = stdio.terminate_process_group

    def teardown_fails(proc: subprocess.Popen[bytes]) -> None:
        terminate(proc)
        raise pinned_process.PinnedProcessError("isolation-teardown-failed", "did not end")

    monkeypatch.setattr(stdio, "terminate_process_group", teardown_fails)
    arguments, _ = command(tmp_path, inventory(), launcher(tmp_path))
    result = CliRunner().invoke(main, [*arguments, "--json-output", "--no-isolation"])
    assert result.exit_code == 1, result.output
    report = json.loads(result.stdout)
    assert not report["complete"]
    assert report["results"][0]["reason"] == "isolation-teardown-failed"
    assert report["results"][0]["error"] == verify.REASONS["isolation-teardown-failed"]
