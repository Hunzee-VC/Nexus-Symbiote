"""MCP Registry advisor (``registry.modelcontextprotocol.io/v0/servers``).

Finds the registry entries whose ``packages[].identifier`` (and registry type) match a dependency, and reports
the server's registry status (``active``/``deprecated``/``deleted``) and its latest published version. The search
is bounded (a few pages) and matching is exact on the package identifier: a server merely *named* like the
package is not attributed to it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final
from urllib.parse import urlencode

from symbiote.advisories.http import HttpClient, MalformedResponse
from symbiote.advisories.npm import parse_time
from symbiote.advisories.types import ReleaseInfo

__all__ = ["MCP_REGISTRY", "McpRegistryEntry", "lookup_server", "parse_servers", "search_term"]

MCP_REGISTRY: Final = "https://registry.modelcontextprotocol.io"
MAX_PAGES: Final = 3
PAGE_LIMIT: Final = 100
_META_KEY: Final = "io.modelcontextprotocol.registry/official"
_CURSOR: Final = re.compile(r"[A-Za-z0-9._~:/@+-]{1,512}")
_TERM: Final = re.compile(r"[A-Za-z0-9._-]{1,128}")
_STATUSES: Final = frozenset({"active", "deprecated", "deleted"})

#: Ecosystem names used by symbiote -> the registry's ``registryType``.
_REGISTRY_TYPE: Final = {"npm": "npm", "pypi": "pypi", "oci": "oci", "nuget": "nuget", "mcpb": "mcpb"}


@dataclass(slots=True)
class McpRegistryEntry:
    server_name: str
    status: str | None
    latest_version: str | None
    published_at: datetime | None
    #: Every version of the server seen (registry versions, not necessarily package versions).
    versions: list[ReleaseInfo] = field(default_factory=list)
    source: str = ""


def search_term(identifier: str) -> str | None:
    """The registry search term for a package identifier: its last path segment, without the scope."""
    tail = identifier.rsplit("/", 1)[-1].lstrip("@")
    return tail if _TERM.fullmatch(tail) else None


def _text(value: object, limit: int = 256) -> str | None:
    return value[:limit] if isinstance(value, str) and value else None


def parse_servers(
    data: object, *, identifier: str, registry_type: str, url: str
) -> tuple[list[tuple[str, dict[str, Any], dict[str, Any]]], str | None]:
    """Matching ``(server name, server, official meta)`` triples on one page, and the next cursor."""
    if not isinstance(data, dict) or not isinstance(data.get("servers"), list):
        raise MalformedResponse("MCP Registry response has no 'servers' list", url=url)
    matches: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for item in data["servers"]:
        if not isinstance(item, dict):
            continue
        server = item.get("server", item)
        if not isinstance(server, dict):
            continue
        name = _text(server.get("name"))
        packages = server.get("packages")
        if name is None or not isinstance(packages, list):
            continue
        hit = any(
            isinstance(p, dict)
            and p.get("identifier") == identifier
            and str(p.get("registryType", p.get("registry_type", ""))).lower() == registry_type
            for p in packages
        )
        if not hit:
            continue
        meta_root = item.get("_meta") if isinstance(item.get("_meta"), dict) else server.get("_meta")
        meta = meta_root.get(_META_KEY) if isinstance(meta_root, dict) else None
        matches.append((name, server, meta if isinstance(meta, dict) else {}))
    cursor: str | None = None
    md = data.get("metadata")
    if isinstance(md, dict):
        nxt = md.get("nextCursor", md.get("next_cursor"))
        if isinstance(nxt, str) and _CURSOR.fullmatch(nxt):
            cursor = nxt
    return matches, cursor


def lookup_server(client: HttpClient, *, ecosystem: str, identifier: str) -> McpRegistryEntry | None:
    """The registry entry for a package, or ``None`` when no server lists that package.

    Raises an HTTP error when the registry cannot be read (the caller records it; absence is not concluded).
    """
    registry_type = _REGISTRY_TYPE.get(ecosystem)
    term = search_term(identifier)
    if registry_type is None or term is None:
        return None
    found: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    cursor: str | None = None
    first_url = ""
    for _ in range(MAX_PAGES):
        params: dict[str, str | int] = {"search": term, "limit": PAGE_LIMIT}
        if cursor is not None:
            params["cursor"] = cursor
        url = f"{MCP_REGISTRY}/v0/servers?{urlencode(params)}"
        first_url = first_url or url
        page, cursor = parse_servers(
            client.get_json(url), identifier=identifier, registry_type=registry_type, url=url
        )
        found.extend(page)
        if cursor is None:
            break
    if not found:
        return None
    # A package may be listed by several server names; prefer the one with the most versions seen.
    by_name: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    for name, server, meta in found:
        by_name.setdefault(name, []).append((server, meta))
    name = sorted(by_name, key=lambda n: (-len(by_name[n]), n))[0]
    entries = by_name[name]
    versions: list[ReleaseInfo] = []
    latest: tuple[dict[str, Any], dict[str, Any]] | None = None
    for server, meta in entries:
        version = _text(server.get("version"), 128)
        if version is None:
            continue
        status = meta.get("status")
        versions.append(
            ReleaseInfo(
                version=version,
                published_at=parse_time(meta.get("publishedAt")),
                deprecated=f"MCP Registry status: {status}" if status in ("deprecated", "deleted") else None,
            )
        )
        if meta.get("isLatest") is True:
            latest = (server, meta)
    if latest is None:
        oldest = datetime.min.replace(tzinfo=UTC)
        latest = max(entries, key=lambda e: parse_time(e[1].get("publishedAt")) or oldest)
    server, meta = latest
    status = meta.get("status")
    return McpRegistryEntry(
        server_name=name,
        status=status if isinstance(status, str) and status in _STATUSES else None,
        latest_version=_text(server.get("version"), 128),
        published_at=parse_time(meta.get("publishedAt")),
        versions=versions,
        source=first_url,
    )
