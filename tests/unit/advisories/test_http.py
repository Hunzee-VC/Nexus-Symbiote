"""HttpClient against a local http.server on 127.0.0.1 (no external network)."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from symbiote import __version__
from symbiote.advisories.http import (
    HttpClient,
    HttpError,
    MalformedResponse,
    NotFound,
    ResponseTooLarge,
    Unreachable,
)


class _State:
    def __init__(self) -> None:
        self.hits: dict[str, int] = {}
        self.headers: dict[str, dict[str, str]] = {}
        self.bodies: dict[str, bytes] = {}


class _Handler(BaseHTTPRequestHandler):
    state: _State

    def log_message(self, format: str, *args: object) -> None:
        pass

    def _send(
        self, status: int, body: bytes, *, length: bool = True, extra: dict[str, str] | None = None
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if length:
            self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        n = int(self.headers.get("Content-Length", "0"))
        self.state.bodies[self.path] = self.rfile.read(n)
        self.do_GET()

    def do_GET(self) -> None:
        st = self.state
        st.hits[self.path] = st.hits.get(self.path, 0) + 1
        st.headers[self.path] = dict(self.headers.items())
        hit = st.hits[self.path]
        if self.path == "/ok":
            self._send(200, b'{"ok": true}')
        elif self.path == "/flaky":
            if hit == 1:
                self._send(503, b"busy")
            else:
                self._send(200, b'{"ok": "second"}')
        elif self.path == "/down":
            self._send(503, b"busy")
        elif self.path == "/missing":
            self._send(404, b"{}")
        elif self.path == "/forbidden":
            self._send(403, b"{}")
        elif self.path == "/big-declared":
            self._send(200, b"[" + b"1," * 600 + b"1]")
        elif self.path == "/big-streamed":
            self.close_connection = True
            self._send(200, b"[" + b"1," * 600 + b"1]", length=False)
        elif self.path == "/malformed":
            self._send(200, b"{not json")
        elif self.path == "/deep":
            self._send(200, b"[" * 100 + b"]" * 100)
        elif self.path == "/latin1":
            self._send(200, b'{"a": "\xff"}')
        elif self.path == "/trickle":
            body = b'{"a": "' + b"x" * 14 + b'"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                for byte in body:  # one byte every 0.15 s: each recv succeeds well inside the socket timeout
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.15)
            except OSError:
                pass  # the client gave up, as it should
        elif self.path == "/redirect-http":
            self._send(302, b"", extra={"Location": "http://registry.example.invalid/pkg"})
        else:
            self._send(404, b"{}")


@pytest.fixture
def server() -> Iterator[tuple[str, _State]]:
    state = _State()
    handler = type("H", (_Handler,), {"state": state})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}", state
    finally:
        httpd.shutdown()
        httpd.server_close()


def _client(tmp_path: Path | None = None, **kw: object) -> HttpClient:
    kw.setdefault("timeout", 5.0)
    return HttpClient(tmp_path, retry_delay=0, **kw)  # type: ignore[arg-type]


def test_get_sends_user_agent_and_parses(server: tuple[str, _State]) -> None:
    base, state = server
    assert _client().get_json(f"{base}/ok") == {"ok": True}
    assert state.headers["/ok"]["User-Agent"] == f"symbiote/{__version__}"


def test_post_sends_canonical_json(server: tuple[str, _State]) -> None:
    base, state = server
    _client().post_json(f"{base}/ok", {"b": 1, "a": {"y": 2, "x": 1}})
    assert state.bodies["/ok"] == b'{"a":{"x":1,"y":2},"b":1}'
    assert state.headers["/ok"]["Content-Type"] == "application/json"


def test_one_retry_on_transient_status(server: tuple[str, _State]) -> None:
    base, state = server
    assert _client().get_json(f"{base}/flaky") == {"ok": "second"}
    assert state.hits["/flaky"] == 2


def test_persistent_server_error_is_unreachable_after_one_retry(server: tuple[str, _State]) -> None:
    base, state = server
    with pytest.raises(Unreachable, match="after one retry"):
        _client().get_json(f"{base}/down")
    assert state.hits["/down"] == 2


def test_status_errors_are_typed(server: tuple[str, _State]) -> None:
    base, _ = server
    with pytest.raises(NotFound):
        _client().get_json(f"{base}/missing")
    with pytest.raises(HttpError, match="403"):
        _client().get_json(f"{base}/forbidden")


@pytest.mark.parametrize("path", ["/big-declared", "/big-streamed"])
def test_byte_cap(server: tuple[str, _State], path: str) -> None:
    base, _ = server
    with pytest.raises(ResponseTooLarge):
        _client(max_bytes=512).get_json(f"{base}{path}")


@pytest.mark.parametrize("path", ["/malformed", "/deep", "/latin1"])
def test_malformed_responses(server: tuple[str, _State], path: str) -> None:
    base, _ = server
    with pytest.raises(MalformedResponse):
        _client().get_json(f"{base}{path}")


def test_redirect_to_plain_http_is_refused(server: tuple[str, _State]) -> None:
    base, _ = server
    with pytest.raises(Unreachable, match="non-HTTPS"):
        _client().get_json(f"{base}/redirect-http")


@pytest.mark.parametrize(
    "url",
    [
        "http://registry.npmjs.org/left-pad",  # plain HTTP to a public host
        "ftp://127.0.0.1/x",
        "file:///etc/passwd",
        "https://user:secret@registry.npmjs.org/x",  # credentials in URLs are refused
        "https:///nohost",
    ],
)
def test_unsafe_urls_are_refused_before_any_request(url: str) -> None:
    with pytest.raises(HttpError):
        _client(offline=False).get_json(url)


def test_offline_raises_unreachable_without_cache() -> None:
    with pytest.raises(Unreachable, match="offline"):
        HttpClient(offline=True).get_json("https://registry.npmjs.org/left-pad")


def test_cache_ttl(server: tuple[str, _State], tmp_path: Path) -> None:
    base, state = server
    clock = [1_000_000.0]
    client = _client(tmp_path, ttl_seconds=60, clock=lambda: clock[0])
    url = f"{base}/ok"
    client.get_json(url)
    client.get_json(url)
    assert state.hits["/ok"] == 1  # served from the cache
    # The cache key is a SHA-256 of method, URL and body; the file holds no request headers.
    key = HttpClient.cache_key("GET", url, None)
    entry = json.loads((tmp_path / f"{key}.json").read_text())
    assert entry["body"] == '{"ok": true}' and "User-Agent" not in json.dumps(entry)
    # POST with a different body is a different entry.
    assert HttpClient.cache_key("POST", url, b"{}") != key

    # Offline mode answers from a fresh entry...
    offline = HttpClient(tmp_path, offline=True, ttl_seconds=60, clock=lambda: clock[0])
    assert offline.get_json(url) == {"ok": True}
    # ...but not from an expired one.
    clock[0] += 61
    with pytest.raises(Unreachable):
        offline.get_json(url)
    client.get_json(url)
    assert state.hits["/ok"] == 2


def test_damaged_cache_entry_is_refetched(server: tuple[str, _State], tmp_path: Path) -> None:
    base, state = server
    url = f"{base}/ok"
    (tmp_path / f"{HttpClient.cache_key('GET', url, None)}.json").write_text("{garbage")
    assert _client(tmp_path).get_json(url) == {"ok": True}
    assert state.hits["/ok"] == 1


def test_connection_refused_is_unreachable() -> None:
    with pytest.raises(Unreachable):
        _client(timeout=1.0).get_json("http://127.0.0.1:1/never")


def test_trickling_body_is_cut_off_at_the_deadline(server: tuple[str, _State]) -> None:
    """A body trickled slower than the deadline (but faster than the socket timeout) cannot hold the request."""
    base, state = server
    started = time.monotonic()
    with pytest.raises(Unreachable, match="timed out while reading"):
        _client(timeout=0.5).get_json(f"{base}/trickle")
    # Two attempts, each bounded by the deadline plus one recv; the whole body would take ~3.5 s per attempt.
    assert time.monotonic() - started < 3.0
    assert state.hits["/trickle"] == 2
