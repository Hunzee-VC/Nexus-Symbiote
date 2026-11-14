"""Suite-wide isolation, a per-test time limit, skip accounting and Hypothesis profiles.

Every test starts without the ambient variables that the tool, the Action runner and the gate
scripts read, with HOME, the XDG directories and TMPDIR in a private temporary directory and
the default collection limits, and must leave no operating mode enforced and no other limits.
Python-level TCP connects, UDP datagrams and name resolution to anywhere but loopback are
blocked for the test process (subprocesses and native code are not; the tool's own offline
guard covers its subprocess runs). A
test that runs longer than ``test_timeout`` seconds fails with its traceback. Every skip is listed with its reason; with ``--strict-skips`` (CI) a skip
for any reason other than the host's file system, or, outside CI, a missing pip, fails the run.
"""

from __future__ import annotations

import ipaddress
import os
import re
import signal
import socket
import tempfile
import threading
from collections.abc import Callable, Iterator
from types import FrameType, ModuleType
from typing import Any

import pytest
from click.testing import CliRunner
from hypothesis import HealthCheck, settings

from nexus_symbiote import limits, modes

ISOLATED_PREFIXES = ("NEXUS_SYMBIOTE_", "SYMBIOTE_", "SHADOWSCAN_", "GITHUB_", "RUNNER_")
ISOLATED_NAMES = frozenset(
    {
        "GH_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_RUNTIME_TOKEN",
        "COLUMNS",
        "LINES",
        "FORCE_COLOR",
        "NO_COLOR",
        "CLICOLOR",
        "CLICOLOR_FORCE",
        "TTY_COMPATIBLE",
        "TTY_INTERACTIVE",
        "SOURCE_DATE_EPOCH",
        "SOAK_OVERRIDE",
        # The unsigned-discovery gate fails closed when these say the run is automated;
        # a test that needs that sets one itself.
        "CI",
        "GITLAB_CI",
        "CIRCLECI",
        "TF_BUILD",
        "JENKINS_URL",
        "BUILDKITE",
        "DRONE",
        "TRAVIS",
    }
)
PRIVATE_DIRECTORIES = ("XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME")
# Skips that depend only on the host: a case-insensitive alias exists only on a
# case-insensitive file system, and some file systems refuse unusual names.
# Anchored to the canonical reason texts, so a skip whose reason merely contains
# the words cannot pass a strict run.
EXPECTED_SKIP_REASONS = (
    re.compile(r"\Afile system rejects "),
    re.compile(r"\Aneeds a case-sensitive file system "),
    re.compile(r"\Athe file system is case-sensitive\b"),
)
# Expected only outside CI: an environment that uv created has no pip, while CI always
# installs with pip, so there the differential against pip's own reader has to run.
LOCAL_SKIP_REASONS = (
    re.compile(r"\Apip is not importable here; CI, which installs with pip, runs this test\Z"),
)
DEFAULT_TIMEOUT_SECONDS = 300


@pytest.fixture
def nonisolated_pinned_fixtures() -> Iterator[None]:
    """Protocol fixtures opt out explicitly; containment has separate default-denial tests."""
    from nexus_symbiote.live.pinned_process import isolation_off

    with isolation_off():
        yield


settings.register_profile(
    "repository",
    derandomize=True,
    database=None,
    deadline=None,
    print_blob=True,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "fuzz",
    derandomize=False,
    max_examples=2000,
    deadline=None,
    print_blob=True,
    suppress_health_check=[HealthCheck.too_slow],
)
# Hypothesis's own --hypothesis-profile option is applied later and still wins.
settings.load_profile("repository")


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addini(
        "test_timeout",
        "seconds after which a test fails as hung; 0 disables the limit",
        default=str(DEFAULT_TIMEOUT_SECONDS),
    )
    parser.addoption(
        "--strict-skips",
        action="store_true",
        help=(
            "fail the run when a test is skipped for a reason other than the host file system "
            "(or, outside CI, a missing pip)"
        ),
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "timeout(seconds): this test's own time limit instead of test_timeout"
    )
    config.addinivalue_line(
        "markers",
        "locked_only: compares what a pinned dependency generates, such as a pydantic JSON"
        " schema, with a committed file; the dependency-floor job deselects it",
    )
    config.pluginmanager.register(SkipAccounting(config), "nexus-symbiote-skip-accounting")


class SkipAccounting:
    """Collect every skip, so that a test which silently stops running is visible."""

    def __init__(self, config: pytest.Config) -> None:
        self.config = config
        self.skips: list[tuple[str, str]] = []

    def _record(self, report: pytest.TestReport | pytest.CollectReport) -> None:
        if not report.skipped or hasattr(report, "wasxfail"):
            return
        longrepr = report.longrepr
        if isinstance(longrepr, tuple) and len(longrepr) == 3:
            reason = str(longrepr[2])
        else:
            reason = str(longrepr)
        self.skips.append((report.nodeid, reason.removeprefix("Skipped: ")))

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        self._record(report)

    def pytest_collectreport(self, report: pytest.CollectReport) -> None:
        self._record(report)

    def unexpected(self) -> list[tuple[str, str]]:
        expected = EXPECTED_SKIP_REASONS + (() if os.environ.get("CI") else LOCAL_SKIP_REASONS)
        return [
            (nodeid, reason)
            for nodeid, reason in self.skips
            if not any(pattern.search(reason) for pattern in expected)
        ]

    @pytest.hookimpl(tryfirst=True)
    def pytest_sessionfinish(self, session: pytest.Session, exitstatus: int) -> None:
        if self.config.getoption("--strict-skips") and self.unexpected() and exitstatus == 0:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED

    def pytest_terminal_summary(self, terminalreporter: Any) -> None:
        if not self.skips:
            return
        unexpected = set(self.unexpected())
        terminalreporter.section("skip accounting")
        for nodeid, reason in self.skips:
            state = "UNEXPECTED" if (nodeid, reason) in unexpected else "expected"
            terminalreporter.write_line(f"{state}: {nodeid}: {reason}")
        if unexpected and self.config.getoption("--strict-skips"):
            terminalreporter.write_line("--strict-skips: unexpected skips fail this run")


@pytest.fixture(autouse=True)
def _isolated_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[None]:
    for name in list(os.environ):
        if name.startswith(ISOLATED_PREFIXES) or name in ISOLATED_NAMES:
            monkeypatch.delenv(name)
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    for name in PRIVATE_DIRECTORIES:
        monkeypatch.setenv(name, str(home / name.lower()))
    private_tmp = home / "tmp"
    private_tmp.mkdir()
    monkeypatch.setenv("TMPDIR", str(private_tmp))
    # tempfile caches the directory on first use; the cache must follow TMPDIR.
    tempfile.tempdir = None

    def _is_loopback_target(address: Any) -> bool:
        if not isinstance(address, tuple):
            return True  # AF_UNIX or other local socket type
        if not address:
            return False
        host = address[0]
        if isinstance(host, (bytes, bytearray)):
            host = bytes(host).decode("ascii", "replace")
        if not isinstance(host, str):
            return False
        if host.lower() == "localhost":
            return True
        try:
            return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
        except ValueError:
            return False

    def _resolvable_offline(host: Any) -> bool:
        """A host getaddrinfo answers without a DNS query: none, loopback or numeric."""
        if host in (None, ""):
            return True
        if isinstance(host, (bytes, bytearray)):
            host = bytes(host).decode("ascii", "replace")
        if not isinstance(host, str):
            return True
        if host.lower() == "localhost":
            return True
        try:
            ipaddress.ip_address(host.split("%", 1)[0])
        except ValueError:
            return False
        return True

    orig_connect = socket.socket.connect
    orig_connect_ex = socket.socket.connect_ex
    orig_sendto = socket.socket.sendto
    orig_sendmsg = socket.socket.sendmsg
    orig_getaddrinfo = socket.getaddrinfo

    # The guards hold in every mode: while a test enforces the offline mode, the
    # tool's own patches sit in front and these stay as the suite's backstop.
    def _guarded_connect(sock: socket.socket, address: Any) -> Any:
        if not _is_loopback_target(address):
            raise OSError("test suite blocked outbound non-loopback socket connection")
        return orig_connect(sock, address)

    def _guarded_connect_ex(sock: socket.socket, address: Any) -> int:
        if not _is_loopback_target(address):
            raise OSError("test suite blocked outbound non-loopback socket connection")
        return orig_connect_ex(sock, address)

    def _guarded_sendto(sock: socket.socket, *args: Any) -> int:
        if args and not _is_loopback_target(args[-1]):
            raise OSError("test suite blocked outbound non-loopback datagram")
        return orig_sendto(sock, *args)

    def _guarded_sendmsg(sock: socket.socket, *args: Any, **kwargs: Any) -> int:
        if len(args) >= 4 and not _is_loopback_target(args[3]):
            raise OSError("test suite blocked outbound non-loopback datagram")
        return orig_sendmsg(sock, *args, **kwargs)

    def _guarded_getaddrinfo(host: Any = None, *args: Any, **kwargs: Any) -> Any:
        if not _resolvable_offline(host):
            raise OSError("test suite blocked outbound name resolution")
        return orig_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _guarded_connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", _guarded_sendto)
    monkeypatch.setattr(socket.socket, "sendmsg", _guarded_sendmsg)
    monkeypatch.setattr(socket, "getaddrinfo", _guarded_getaddrinfo)
    # Collection limits are process state (the root --limit option sets them): every test
    # starts at the defaults, and what a test leaves in force never reaches the next one.
    try:
        with limits.applied(limits.DEFAULTS):
            yield
            limits_left = limits.current() != limits.DEFAULTS
    finally:
        tempfile.tempdir = None
    leaked = modes.current()
    if leaked is not None:
        pytest.fail(f"the test left the {leaked.value} mode enforced", pytrace=False)
    if limits_left:
        pytest.fail("the test left collection limits other than the defaults", pytrace=False)


@pytest.fixture(autouse=True)
def _restored_scanner_registry() -> Iterator[None]:
    from nexus_symbiote import cli

    saved = dict(cli.SCANNER_REGISTRY)
    yield
    cli.SCANNER_REGISTRY.clear()
    cli.SCANNER_REGISTRY.update(saved)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def load_script() -> Callable[[str], ModuleType]:
    from tests.support import load_script

    return load_script


def _time_limit(item: pytest.Item) -> float:
    marker = item.get_closest_marker("timeout")
    if marker is not None and marker.args:
        return float(marker.args[0])
    return float(item.config.getini("test_timeout") or 0)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Iterator[None]:
    seconds = _time_limit(item)
    if (
        seconds <= 0
        or not hasattr(signal, "setitimer")
        or threading.current_thread() is not threading.main_thread()
        or item.config.pluginmanager.hasplugin("timeout")
    ):
        yield
        return

    def expire(_signum: int, _frame: FrameType | None) -> None:
        pytest.fail(f"test exceeded its {seconds:g}-second time limit")

    previous = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
