"""Socket/TLS/destination regressions for live discovery; no network used."""

from __future__ import annotations

import io
import socket
import ssl
import threading
import time

import pytest

from nexus_symbiote.scanners import live_mcp as live


class FakeSocket:
    def __init__(self, incoming=b""):
        self.connected = []
        self.timeouts = []
        self.closed = False
        self.incoming = io.BytesIO(incoming)
        self.sent = []

    def connect(self, address):
        self.connected.append(address)

    def settimeout(self, value):
        self.timeouts.append(value)

    def close(self):
        self.closed = True

    def recv_into(self, buffer):
        raw = self.incoming.read(len(buffer))
        buffer[: len(raw)] = raw
        return len(raw)

    def sendall(self, data):
        self.sent.append(data)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "192.168.1.1",
        "0.0.0.0",  # noqa: S104 - refusal fixture, never bound
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "::7f00:1",
        "::a9fe:a9fe",
        "::ffff:0:7f00:1",
        "::ffff:0:a00:1",
    ],
)
def test_literal_nonpublic_destinations_refused(address):
    with pytest.raises(live.DiscoveryError):
        live._resolve_public(address, 443, 1)


def test_mixed_dns_answers_fail_closed(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443)),
        ],
    )
    with pytest.raises(live.DiscoveryError):
        live._resolve_public("fixture.example", 443, 1)


def test_stuck_lookups_time_out_and_at_most_two_stay_outstanding(monkeypatch):
    release = threading.Event()
    lookups = []
    answer = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))

    def stuck(*args, **kwargs):
        lookups.append(args[0])
        release.wait(10)
        return [answer]

    monkeypatch.setattr(socket, "getaddrinfo", stuck)
    try:
        for _ in range(2):
            started = time.monotonic()
            with pytest.raises(live.DiscoveryError, match="DNS resolution timed out"):
                live._resolve_public("fixture.example", 443, 0.2)
            assert time.monotonic() - started < 2
        with pytest.raises(live.DiscoveryError, match="resolver capacity unavailable"):
            live._resolve_public("fixture.example", 443, 0.2)
        assert lookups == ["fixture.example", "fixture.example"]
    finally:
        release.set()
    # Both slots return once the stuck lookups finish, and resolution works again.
    assert live._RESOLVER_SLOTS.acquire(timeout=5) and live._RESOLVER_SLOTS.acquire(timeout=5)
    live._RESOLVER_SLOTS.release()
    live._RESOLVER_SLOTS.release()
    assert live._resolve_public("fixture.example", 443, 1) == (socket.AF_INET, "93.184.216.34")


def test_https_dials_pinned_numeric_ip_and_verifies_original_hostname(monkeypatch):
    raw, secured = FakeSocket(), FakeSocket()
    context = ssl.create_default_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    wraps = []

    def wrap(stream, *, server_hostname):
        wraps.append((stream, server_hostname))
        return secured

    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(context, "wrap_socket", wrap)
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: raw)
    monkeypatch.setattr(
        socket, "create_connection", lambda *a, **kw: pytest.fail("second DNS path")
    )
    connection = live._PinnedHTTPSConnection(
        "fixture.example", 443, socket.AF_INET, "93.184.216.34", 2
    )
    connection.connect()
    assert raw.connected == [("93.184.216.34", 443)]
    assert wraps == [(raw, "fixture.example")]
    assert all(0 < timeout <= 2 for timeout in raw.timeouts)
    connection.close()
    assert secured.closed


def test_tls_failure_closes_untrusted_socket(monkeypatch):
    raw = FakeSocket()
    context = ssl.create_default_context()

    def fail(*a, **kw):
        raise ssl.SSLCertVerificationError("bad certificate")

    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(context, "wrap_socket", fail)
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: raw)
    connection = live._PinnedHTTPSConnection(
        "fixture.example", 443, socket.AF_INET, "93.184.216.34", 2
    )
    with pytest.raises(ssl.SSLCertVerificationError):
        connection.connect()
    assert raw.closed


def test_absolute_deadline_applies_to_buffered_http_reads_and_close_lifetime():
    raw = FakeSocket(b"HTTP/1.1 200 OK\r\n\r\n{}")
    adapter = live._DeadlineSocket(raw, time.monotonic() + 1)
    reader = adapter.makefile("rb")
    adapter.close()
    assert not raw.closed
    assert reader.read(4) == b"HTTP"
    reader.close()
    assert raw.closed
    expired = live._DeadlineSocket(FakeSocket(b"x"), time.monotonic() - 1)
    with pytest.raises(TimeoutError):
        expired.makefile("rb").read(1)


class Reply:
    def __init__(self, status=200, headers=None, body=b"{}"):
        self.status = status
        self.headers = headers if headers is not None else [("Content-Type", "application/json")]
        self.body = body
        self.fp = io.BytesIO(body)

    def getheaders(self):
        return self.headers

    def read(self, size):
        return self.body[:size]

    def readline(self, limit=-1):
        return self.fp.readline(limit)

    def close(self):
        self.fp.close()


def transport_fixture(monkeypatch, replies):
    calls = []
    resolutions = []

    def resolve(host, port, timeout):
        resolutions.append((host, port))
        if len(resolutions) > 1:
            return socket.AF_INET, "127.0.0.1"
        return socket.AF_INET, "93.184.216.34"

    class Connection:
        def __init__(self, host, port, family, address, timeout):
            self.address = address
            calls.append(self)

        def request(self, method, path, *, body, headers):
            self.method, self.path, self.body, self.headers = method, path, body, headers

        def getresponse(self):
            return replies.pop(0)

        def close(self):
            self.closed = True

    monkeypatch.setattr(live, "_resolve_public", resolve)
    monkeypatch.setattr(live, "_PinnedHTTPSConnection", Connection)
    return live.PinnedHTTPTransport(), calls, resolutions


def test_dns_snapshot_is_pinned_across_session_requests(monkeypatch):
    transport, calls, resolutions = transport_fixture(monkeypatch, [Reply(), Reply()])
    for _ in range(2):
        transport.request("https://fixture.example/mcp", b"{}", {}, timeout=1, max_bytes=100)
    assert resolutions == [("fixture.example", 443)]
    assert [call.address for call in calls] == ["93.184.216.34", "93.184.216.34"]
    assert all(call.method == "POST" and call.path == "/mcp" for call in calls)


@pytest.mark.parametrize(
    "reply",
    [
        Reply(status=302, headers=[("Location", "https://127.0.0.1/secret")]),
        Reply(headers=[("Content-Type", "application/json"), ("Content-Length", "999999")]),
        Reply(headers=[("Content-Type", "application/json"), ("Content-Encoding", "gzip")]),
        Reply(headers=[("Content-Length", "2"), ("Transfer-Encoding", "chunked")]),
        Reply(headers=[("Mcp-Session-Id", "one"), ("mcp-session-id", "two")]),
        Reply(body=b"x" * 101),
    ],
)
def test_transport_rejects_redirect_size_compression_and_ambiguous_headers(monkeypatch, reply):
    transport, calls, _ = transport_fixture(monkeypatch, [reply])
    with pytest.raises(live.DiscoveryError):
        transport.request("https://fixture.example/mcp", b"{}", {}, timeout=1, max_bytes=100)
    assert len(calls) == 1
    assert calls[0].closed


def test_streaming_response_stops_at_requested_jsonrpc_result(monkeypatch):
    body = b'data: {"jsonrpc":"2.0","id":2,"result":{"tools":[]}}\n\n'
    transport, calls, _ = transport_fixture(
        monkeypatch,
        [
            Reply(
                headers=[("Content-Type", "text/event-stream")],
                body=body,
            )
        ],
    )
    reply = transport.request(
        "https://fixture.example/mcp",
        b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
        {},
        timeout=1,
        max_bytes=200,
    )
    assert reply.body == body
    assert calls[0].closed


def test_real_http_parser_uses_pinned_tls_adapter_and_connection_close(monkeypatch):
    raw = FakeSocket()
    secured = FakeSocket(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
    )
    context = ssl.create_default_context()
    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(context, "wrap_socket", lambda stream, *, server_hostname: secured)
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: raw)
    monkeypatch.setattr(live, "_resolve_public", lambda *a: (socket.AF_INET, "93.184.216.34"))
    result = live.PinnedHTTPTransport().request(
        "https://fixture.example/mcp", b"{}", {}, timeout=1, max_bytes=100
    )
    assert result.status == 200
    assert result.body == b"{}"
    assert raw.connected == [("93.184.216.34", 443)]
    assert secured.closed


def test_pinned_https_context_requires_tls12_and_verified_hostnames():
    connection = live._PinnedHTTPSConnection(
        "fixture.example", 443, socket.AF_INET, "93.184.216.34", 1.0
    )
    context = connection._tls_context
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
