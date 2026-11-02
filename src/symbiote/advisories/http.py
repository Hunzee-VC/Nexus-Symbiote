"""A small, bounded HTTP client for registry and advisory lookups (``spec/monitoring.md`` §3).

Every registry response is untrusted input. The client therefore:

* speaks HTTPS only (plain HTTP is accepted for loopback hosts, which serve local mirrors and test fixtures),
  and never follows a redirect to a non-HTTPS URL;
* caps the bytes it reads (``Content-Length`` is checked first, then the stream is read in chunks) and the
  wall-clock time a body may take to arrive (checked after every ``recv``, so a trickling server is cut off);
* parses JSON with a size cap and a nesting-depth limit (deeply nested documents are refused, not recursed);
* retries once on a transient failure (connection error, timeout, 429, 502, 503, 504);
* keeps an optional on-disk TTL cache keyed by SHA-256 of method, URL and body;
* honours the standard proxy variables (``HTTPS_PROXY``/``NO_PROXY``) and CA settings (``SSL_CERT_FILE``,
  ``SSL_CERT_DIR``, ``REQUESTS_CA_BUNDLE``, ``CURL_CA_BUNDLE``).

In ``offline`` mode it answers from a fresh cache entry or raises :class:`Unreachable`: an unanswered lookup is
an error the caller records as ``coverage="unreachable"``, never an empty, clean answer. Request bodies and
URLs used here are public registry queries; the client sends no credentials.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import ipaddress
import json
import os
import ssl
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import IO, Any, Final
from urllib.parse import urlsplit

from symbiote import __version__

__all__ = [
    "MAX_JSON_DEPTH",
    "HttpClient",
    "HttpError",
    "HttpStatusError",
    "MalformedResponse",
    "NotFound",
    "ResponseTooLarge",
    "Unreachable",
]

#: Deepest JSON nesting accepted from a registry (real packuments and OSV records stay well below 16).
MAX_JSON_DEPTH: Final = 64

_TRANSIENT_STATUS: Final = frozenset({429, 502, 503, 504})
_CHUNK: Final = 64 * 1024
_MAX_REDIRECTS: Final = 3
_CACHE_FORMAT: Final = 1
_LOOPBACK_NAMES: Final = frozenset({"localhost"})


class HttpError(Exception):
    """A lookup that produced no usable answer."""

    def __init__(self, message: str, *, url: str | None = None) -> None:
        super().__init__(message)
        self.url = url


class Unreachable(HttpError):  # noqa: N818 - agreed public names
    """The service could not be reached (offline mode, network error, timeout, server error, unsafe redirect)."""


class HttpStatusError(HttpError):
    """The service answered with a non-success status that retrying will not fix."""

    def __init__(self, message: str, *, url: str | None = None, status: int) -> None:
        super().__init__(message, url=url)
        self.status = status


class NotFound(HttpStatusError):  # noqa: N818 - agreed public names
    """HTTP 404: the package, version or record does not exist (or was removed)."""


class ResponseTooLarge(HttpError):  # noqa: N818 - agreed public names
    """The response exceeded the byte cap."""


class MalformedResponse(HttpError):  # noqa: N818 - agreed public names
    """The response was not acceptable JSON (syntax, encoding, nesting depth or shape)."""


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _check_url(url: str) -> str:
    """Return the URL's host after checking the scheme (https, or http to a loopback host)."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError as exc:
        raise HttpError(f"invalid URL: {exc}", url=url) from None
    if not host:
        raise HttpError("URL has no host", url=url)
    if parts.username is not None or parts.password is not None:
        raise HttpError("URLs carrying credentials are refused", url=url)
    if parts.scheme == "https" or (parts.scheme == "http" and _is_loopback(host)):
        return host
    raise HttpError(f"refusing non-HTTPS URL scheme {parts.scheme!r}", url=url)


def _json_depth_ok(value: Any, limit: int) -> bool:
    """Iteratively check that ``value`` nests no deeper than ``limit`` containers."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict):
            if depth > limit:
                return False
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            if depth > limit:
                return False
            stack.extend((v, depth + 1) for v in item)
    return True


def parse_json(data: bytes, *, url: str | None = None, max_depth: int = MAX_JSON_DEPTH) -> Any:
    """Parse untrusted JSON bytes with a nesting-depth limit; errors become :class:`MalformedResponse`."""
    try:
        text = data.decode("utf-8")
        value = json.loads(text)
    except RecursionError:
        raise MalformedResponse("JSON nesting too deep", url=url) from None
    except (UnicodeDecodeError, ValueError) as exc:
        raise MalformedResponse(f"invalid JSON: {type(exc).__name__}", url=url) from None
    if not _json_depth_ok(value, max_depth):
        raise MalformedResponse(f"JSON nesting deeper than {max_depth}", url=url)
    return value


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Follow at most a few redirects, and only to HTTPS URLs."""

    max_redirections = _MAX_REDIRECTS

    def redirect_request(  # noqa: PLR0917 - signature fixed by urllib
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: http.client.HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        try:
            scheme = urlsplit(newurl).scheme
        except ValueError:
            scheme = ""
        if scheme != "https":
            raise Unreachable(f"refusing redirect to a non-HTTPS URL (HTTP {code})", url=req.full_url)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()  # system store; honours SSL_CERT_FILE / SSL_CERT_DIR
    for var in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        path = os.environ.get(var)
        if path and Path(path).is_file():
            with contextlib.suppress(ssl.SSLError, OSError):
                ctx.load_verify_locations(cafile=path)
    return ctx


class HttpClient:
    """Bounded JSON-over-HTTPS client with an on-disk TTL cache and an offline mode."""

    def __init__(
        self,
        cache_dir: Path | None = None,
        *,
        offline: bool = False,
        timeout: float = 10.0,
        max_bytes: int = 8 * 1024 * 1024,
        ttl_seconds: int = 3600,
        clock: Callable[[], float] = time.time,
        retry_delay: float = 0.5,
    ) -> None:
        self.cache_dir = cache_dir
        self.offline = offline
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.ttl_seconds = ttl_seconds
        self.retry_delay = retry_delay
        self._clock = clock
        self.user_agent = f"symbiote/{__version__}"
        self._opener: urllib.request.OpenerDirector | None = None
        self._direct_opener: urllib.request.OpenerDirector | None = None

    # ------------------------------------------------------------------ public API

    def get_json(self, url: str, *, accept: str = "application/json") -> Any:
        """GET ``url`` and return the parsed JSON body."""
        return self._json("GET", url, None, accept)

    def post_json(self, url: str, payload: Mapping[str, Any], *, accept: str = "application/json") -> Any:
        """POST ``payload`` as JSON to ``url`` and return the parsed JSON body."""
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self._json("POST", url, body, accept)

    @staticmethod
    def cache_key(method: str, url: str, body: bytes | None) -> str:
        h = hashlib.sha256()
        h.update(method.upper().encode("ascii"))
        h.update(b"\n")
        h.update(url.encode("utf-8"))
        h.update(b"\n")
        h.update(body or b"")
        return h.hexdigest()

    # ------------------------------------------------------------------ internals

    def _json(self, method: str, url: str, body: bytes | None, accept: str) -> Any:
        _check_url(url)
        key = self.cache_key(method, url, body)
        cached = self._cache_get(key)
        if cached is not None:
            try:
                return parse_json(cached, url=url)
            except MalformedResponse:
                pass  # a damaged cache entry is ignored and refetched
        if self.offline:
            raise Unreachable("offline mode and no fresh cache entry", url=url)
        raw = self._fetch_with_retry(method, url, body, accept)
        if len(raw) > self.max_bytes:  # defence in depth: the transport already reads at most the cap
            raise ResponseTooLarge(f"response exceeds the {self.max_bytes}-byte cap", url=url)
        value = parse_json(raw, url=url)
        self._cache_put(key, url, raw)
        return value

    def _fetch_with_retry(self, method: str, url: str, body: bytes | None, accept: str) -> bytes:
        try:
            return self._transport(method, url, body, accept)
        except _Transient as first:
            if self.retry_delay > 0:
                time.sleep(self.retry_delay)
            try:
                return self._transport(method, url, body, accept)
            except _Transient as second:
                raise Unreachable(
                    f"{second.reason} (after one retry; first: {first.reason})", url=url
                ) from None

    def _openers(self, host: str) -> urllib.request.OpenerDirector:
        if _is_loopback(host):
            if self._direct_opener is None:
                self._direct_opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({}),
                    _SafeRedirect(),
                    urllib.request.HTTPSHandler(context=_ssl_context()),
                )
            return self._direct_opener
        if self._opener is None:
            self._opener = urllib.request.build_opener(
                urllib.request.ProxyHandler(),  # HTTPS_PROXY / NO_PROXY from the environment
                _SafeRedirect(),
                urllib.request.HTTPSHandler(context=_ssl_context()),
            )
        return self._opener

    def _transport(self, method: str, url: str, body: bytes | None, accept: str) -> bytes:
        """Perform one request and return the capped body; raise :class:`_Transient` for retryable failures.

        Tests substitute this method to serve recorded fixtures.
        """
        host = _check_url(url)
        headers = {"User-Agent": self.user_agent, "Accept": accept, "Accept-Encoding": "identity"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310 - scheme checked
        deadline = time.monotonic() + self.timeout
        try:
            with self._openers(host).open(req, timeout=self.timeout) as resp:
                final = resp.geturl()
                if final != url:
                    _check_url(final)
                length = resp.headers.get("Content-Length")
                if length is not None and length.isdigit() and int(length) > self.max_bytes:
                    raise ResponseTooLarge(
                        f"declared Content-Length {length} exceeds the {self.max_bytes}-byte cap", url=url
                    )
                return self._read_capped(resp, url, deadline)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            if status in _TRANSIENT_STATUS or status >= 500:
                raise _Transient(f"HTTP {status}") from None
            if status == 404:
                raise NotFound("HTTP 404", url=url, status=status) from None
            raise HttpStatusError(f"HTTP {status}", url=url, status=status) from None
        except HttpError:
            raise
        except TimeoutError:
            raise _Transient("timed out") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLError | ssl.CertificateError):
                raise Unreachable(f"TLS failure: {type(exc.reason).__name__}", url=url) from None
            raise _Transient(f"connection failed: {type(exc.reason).__name__}") from None
        except (ConnectionError, OSError, http.client.HTTPException) as exc:
            raise _Transient(f"connection failed: {type(exc).__name__}") from None

    def _read_capped(self, resp: IO[bytes], url: str, deadline: float) -> bytes:
        # ``read1`` returns after at most one ``recv``, so a server trickling bytes cannot hold a read open past
        # the deadline (``read(n)`` would block until ``n`` bytes or EOF): a request is bounded by the deadline
        # plus one socket timeout.
        read: Callable[[int], bytes] = getattr(resp, "read1", resp.read)
        chunks: list[bytes] = []
        total = 0
        while True:
            if time.monotonic() > deadline:
                raise _Transient("timed out while reading the response")
            chunk = read(_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > self.max_bytes:
                raise ResponseTooLarge(f"response exceeds the {self.max_bytes}-byte cap", url=url)
            chunks.append(chunk)
        return b"".join(chunks)

    # ------------------------------------------------------------------ cache

    def _cache_path(self, key: str) -> Path | None:
        return None if self.cache_dir is None else self.cache_dir / f"{key}.json"

    def _cache_get(self, key: str) -> bytes | None:
        path = self._cache_path(key)
        if path is None:
            return None
        try:
            if path.stat().st_size > self.max_bytes * 2 + 4096:
                return None
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError):
            return None
        if not isinstance(entry, dict) or entry.get("format") != _CACHE_FORMAT:
            return None
        stored_at, body = entry.get("stored_at"), entry.get("body")
        if not isinstance(stored_at, int | float) or not isinstance(body, str):
            return None
        age = self._clock() - float(stored_at)
        if age < 0 or age > self.ttl_seconds:
            return None
        return body.encode("utf-8")

    def _cache_put(self, key: str, url: str, raw: bytes) -> None:
        path = self._cache_path(key)
        if path is None or self.ttl_seconds <= 0:
            return
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return
        entry = {"format": _CACHE_FORMAT, "url": url, "stored_at": self._clock(), "body": text}
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(entry, fh)
                os.replace(tmp, path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
        except OSError:
            return  # a cache that cannot be written only costs a refetch


class _Transient(Exception):  # noqa: N818 - internal control-flow signal, never escapes the client
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
