"""Offline test support: an :class:`HttpClient` whose transport serves recorded fixtures."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from symbiote.advisories.http import HttpClient, Unreachable

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "advisories"
NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
OSV = "https://api.osv.dev/v1/query"

Route = str | bytes | Exception | Callable[[bytes | None], bytes]


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class FakeClient(HttpClient):
    """Serves ``routes[url]`` (a fixture name, raw bytes, an exception to raise, or a callable on the body).

    OSV queries are routed by ``osv[(package name, version)]``; unknown OSV queries get an empty answer.
    Any other unknown URL raises :class:`Unreachable`, as an unplugged network would.
    """

    def __init__(
        self,
        routes: dict[str, Route] | None = None,
        *,
        osv: dict[tuple[str, str], Route] | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(retry_delay=0, **kwargs)  # type: ignore[arg-type]
        self.routes = routes or {}
        self.osv = osv or {}
        self.calls: list[tuple[str, str, bytes | None]] = []

    def _transport(self, method: str, url: str, body: bytes | None, accept: str) -> bytes:
        self.calls.append((method, url, body))
        route: Route | None
        if url == OSV:
            q = json.loads(body or b"{}")
            route = self.osv.get((q["package"]["name"], q["version"]), b"{}")
        else:
            route = self.routes.get(url)
        if route is None:
            raise Unreachable("no route (offline test)", url=url)
        if isinstance(route, Exception):
            raise route
        if isinstance(route, bytes):
            return route
        if isinstance(route, str):
            return fixture(route)
        return route(body)
