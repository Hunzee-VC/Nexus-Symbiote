"""Exercise the suite guard with intercepted resolvers, never real DNS traffic."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

CONFTEST = (Path(__file__).parent / "conftest.py").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("api", "blocked", "allowed"),
    [
        ("gethostbyaddr", ("192.0.2.1",), ("127.0.0.1",)),
        ("gethostbyaddr", ("example.test",), ("localhost",)),
        ("getnameinfo", (("192.0.2.1", 80), 0), (("127.0.0.1", 80), 0)),
        ("getnameinfo", ((None, 80), 0), (("::1", 80), 0)),
        ("getaddrinfo", ("fixture.invalid", 80), (None, 80)),
        ("gethostbyname", ("fixture.localhost",), ("localhost",)),
        ("gethostbyname_ex", (1234,), ("127.0.0.1",)),
    ],
)
def test_resolver_guard_rejects_before_the_underlying_function(
    pytester, monkeypatch, api, blocked, allowed
):
    calls = []

    def intercepted(*args, **kwargs):
        calls.append((args, kwargs))
        return "local resolver sentinel"

    monkeypatch.setattr(socket, api, intercepted)
    pytester.makeconftest(CONFTEST)
    pytester.makeini("[pytest]\ntest_timeout = 30\n")
    pytester.makepyfile(
        f"""
        import socket
        import pytest

        def test_refused():
            with pytest.raises(OSError, match="test suite blocked outbound non-loopback"):
                socket.{api}(*{blocked!r})

        def test_local_control():
            assert socket.{api}(*{allowed!r}) == "local resolver sentinel"
        """
    )
    pytester.runpytest("-p", "no:cacheprovider").assert_outcomes(passed=2)
    assert calls == [(allowed, {})]


@pytest.mark.parametrize("api", ["connect", "connect_ex", "sendto", "sendmsg"])
def test_socket_guard_refuses_malformed_internet_targets(pytester, monkeypatch, api):
    calls = []

    def intercepted(sock, *args):
        calls.append(args)
        return 0

    monkeypatch.setattr(socket.socket, api, intercepted)
    pytester.makeconftest(CONFTEST)
    pytester.makeini("[pytest]\ntest_timeout = 30\n")
    leading = {"connect": "", "connect_ex": "", "sendto": "b'x', ", "sendmsg": "[b'x'], [], 0, "}[
        api
    ]
    pytester.makepyfile(
        f"""
        import socket
        import pytest

        @pytest.mark.parametrize("target", [(), (None, 80), (1234, 80)])
        def test_refused(target):
            with socket.socket() as sock:
                with pytest.raises(OSError, match="test suite blocked outbound non-loopback"):
                    sock.{api}({leading}target)

        def test_local_control():
            with socket.socket() as sock:
                assert sock.{api}({leading}("127.0.0.1", 80)) == 0
        """
    )
    pytester.runpytest("-p", "no:cacheprovider").assert_outcomes(passed=4)
    assert len(calls) == 1
