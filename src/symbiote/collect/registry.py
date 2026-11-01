"""MCP registry resolution collector (``spec/collectors.md`` row ``mcp-registry``).

Looks configured servers up in the official MCP registry and records a *name-resolution record*
(``spec/digests.md §4``): requested ref → resolved immutable ref → publisher verification →
signer. The registry itself carries no attestation fields, so ``signer`` stays ``unsigned``
unless package-ecosystem attestations are supplied by other collectors.

Network access is injectable (``options["http_get"]``) so tests run offline; an unreachable
registry yields coverage ``registry: unreachable`` **and** a resolution with ``state=unknown`` —
never "not registered" (I2, ``spec/agentbom-profile.md §3.14``).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any, ClassVar
from urllib.parse import quote

from packageurl import PackageURL

from symbiote.collect.base import BaseCollector, CollectContext, CollectionResult
from symbiote.digest import jsondoc_digest
from symbiote.model.edges import Edge
from symbiote.model.entities import (
    Evidence,
    PublisherFacts,
    RegistryFacts,
    RegistryResolution,
    RequestedRef,
    ResolvedRef,
    TyposquatDistance,
)
from symbiote.model.enums import (
    AliasPinning,
    AssuranceLevel,
    CollectorMode,
    CoverageStatus,
    EdgeScope,
    EdgeType,
    EvidenceKind,
    RegistryStatus,
    RequestedRefKind,
    Surface,
)
from symbiote.model.ids import evidence_id, make_id

DEFAULT_REGISTRY_BASE = "https://registry.modelcontextprotocol.io"

#: Well-known server names used for typosquat distance when the caller supplies none.
DEFAULT_POPULAR_NAMES: tuple[str, ...] = (
    "io.github.github/github-mcp-server",
    "io.github.modelcontextprotocol/filesystem",
    "io.github.modelcontextprotocol/fetch",
    "io.github.modelcontextprotocol/memory",
    "io.github.anthropics/claude-code",
)

HttpGet = Callable[[str], tuple[int, Any]]


def _default_http_get(url: str) -> tuple[int, Any]:
    import httpx

    response = httpx.get(url, timeout=10.0, headers={"accept": "application/json"})
    try:
        payload = response.json()
    except ValueError:
        payload = None
    return response.status_code, payload


def levenshtein(a: str, b: str, *, cap: int = 6) -> int:
    """Bounded edit distance (early exit above ``cap`` keeps the scan fast)."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        best = i
        for j, cb in enumerate(b, start=1):
            cost = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb))
            current.append(cost)
            best = min(best, cost)
        if best > cap:
            return cap + 1
        previous = current
    return previous[-1]


def _server_object(entry: Mapping[str, Any]) -> Mapping[str, Any]:
    server = entry.get("server")
    return server if isinstance(server, Mapping) else entry


_PUBLIC_REGISTRIES = {
    "npm": "https://registry.npmjs.org",
    "pypi": "https://pypi.org",
    "nuget": "https://api.nuget.org",
    "cargo": "https://crates.io",
}


def _matches_package(package: Mapping[str, Any], purl: PackageURL) -> bool:
    if purl.subpath or set(purl.qualifiers or {}) - {"repository_url"}:
        return False
    identifier = "/".join(part for part in (purl.namespace, purl.name) if part)
    package_registry = str(package.get("registryBaseUrl") or "").rstrip("/")
    expected_registry = (purl.qualifiers or {}).get("repository_url", "").rstrip("/")
    if expected_registry and package_registry != expected_registry:
        return False
    if package_registry and not expected_registry and package_registry != _PUBLIC_REGISTRIES.get(purl.type):
        return False
    return (
        package.get("registryType") == purl.type
        and package.get("identifier") == identifier
        and (purl.version is None or package.get("version") == purl.version)
    )


def _match_entry(
    entries: list[Mapping[str, Any]], target: Mapping[str, Any]
) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    raw_purl = target.get("package_purl")
    try:
        purl = PackageURL.from_string(str(raw_purl)) if raw_purl else None
    except ValueError:
        return None
    name = str(target.get("registry_name") or target.get("name", ""))
    remote = target.get("remote_url")
    matches = []
    for entry in entries:
        server = _server_object(entry)
        if ("/" in name or not (remote or purl)) and server.get("name") != name:
            continue
        if remote and not any(
            isinstance(r, Mapping) and r.get("url") == remote for r in server.get("remotes", [])
        ):
            continue
        if purl:
            for package in server.get("packages", []):
                if isinstance(package, Mapping) and _matches_package(package, purl):
                    matches.append((entry, package))
        else:
            matches.append((entry, {}))
    return matches[0] if len(matches) == 1 else None


class McpRegistryCollector(BaseCollector):
    """``mcp-registry``: resolve configured servers against the official MCP registry."""

    name: ClassVar[str] = "mcp-registry"
    version: ClassVar[str] = "0.1.0"
    surfaces: ClassVar[tuple[Surface, ...]] = (Surface.REGISTRY,)
    mode: ClassVar[CollectorMode] = CollectorMode.OBSERVED

    def detect(self, ctx: CollectContext) -> bool:
        return bool(ctx.options.get("registry")) and bool(ctx.options.get("registry_targets"))

    def collect(self, ctx: CollectContext) -> CollectionResult:
        result = self.new_result()
        base = str(ctx.options.get("registry_base", DEFAULT_REGISTRY_BASE)).rstrip("/")
        http_get: HttpGet = ctx.options.get("http_get") or _default_http_get
        popular = [str(p) for p in ctx.options.get("popular_names", DEFAULT_POPULAR_NAMES)]
        for target in ctx.options.get("registry_targets", []):
            server_id = str(target.get("server_id") or make_id("server", str(target.get("name", "unknown"))))
            name = str(target.get("name", server_id.split(":", 1)[-1]))
            url = f"{base}/v0/servers?search={quote(name)}"
            requested = RequestedRef(
                kind=RequestedRefKind.MCP_REGISTRY,
                ref=str(target.get("package_purl") or target.get("remote_url") or name),
            )
            try:
                status_code, payload = http_get(url)
            except Exception as exc:  # network failure class, not a scan failure
                result.add_source(Surface.REGISTRY, url, ok=False, error_class="unreachable", locator=url)
                result.warnings.append(f"{server_id}: registry unreachable: {type(exc).__name__}: {exc}")
                result.entities.append(
                    RegistryResolution(
                        id=make_id("res", name, collision_seed=server_id),
                        requested=requested,
                        resolved_at=ctx.now,
                        resolver=self.ref,
                        resolved=ResolvedRef(state="unknown"),
                        warnings=[f"registry unreachable: {type(exc).__name__}"],
                    )
                )
                result.set_status(Surface.REGISTRY, CoverageStatus.UNREACHABLE)
                continue
            if status_code != 200 or not isinstance(payload, Mapping):
                result.add_source(Surface.REGISTRY, url, ok=False, error_class="unreachable", locator=url)
                result.entities.append(
                    RegistryResolution(
                        id=make_id("res", name, collision_seed=server_id),
                        requested=requested,
                        resolved_at=ctx.now,
                        resolver=self.ref,
                        resolved=ResolvedRef(state="unknown"),
                        warnings=[f"registry answered HTTP {status_code}"],
                    )
                )
                continue
            entries = [e for e in payload.get("servers", []) if isinstance(e, Mapping)]
            metadata = payload.get("metadata") or {}
            more = isinstance(metadata, Mapping) and metadata.get("nextCursor")
            match = None if more else _match_entry(entries, target)
            if match is None:
                nearest = (
                    min(popular, key=lambda p: levenshtein(name, p.rsplit("/", 1)[-1])) if popular else None
                )
                distance = levenshtein(name, nearest.rsplit("/", 1)[-1]) if nearest else None
                resolution = RegistryResolution(
                    id=make_id("res", name, collision_seed=server_id),
                    requested=requested,
                    resolved_at=ctx.now,
                    resolver=self.ref,
                    resolved=ResolvedRef(state="unknown"),
                    registry=RegistryFacts(url=base, status=RegistryStatus.UNKNOWN),
                    typosquat_distance=TyposquatDistance(nearest=nearest, levenshtein=distance)
                    if nearest is not None and distance is not None and distance <= 2
                    else None,
                    warnings=[
                        "registry results are incomplete or do not identify exactly one matching entry"
                    ],
                )
                result.entities.append(resolution)
                result.add_source(
                    Surface.REGISTRY,
                    url,
                    ok=not more,
                    items=len(entries),
                    locator=url,
                    error_class="truncated" if more else None,
                )
                continue
            entry, package = match
            server_obj = _server_object(entry)
            meta_raw = entry.get("_meta")
            official = (
                meta_raw.get("io.modelcontextprotocol.registry/official")
                if isinstance(meta_raw, Mapping)
                else None
            )
            meta: Mapping[str, Any] = official if isinstance(official, Mapping) else {}
            entry_name = str(server_obj.get("name", name))
            namespace = entry_name.rsplit("/", 1)[0]
            version = str(server_obj.get("version", "")) or None
            file_hash = package.get("fileSha256")
            digest = (
                "sha256:" + file_hash.lower()
                if isinstance(file_hash, str) and re.fullmatch(r"[0-9a-fA-F]{64}", file_hash)
                else None
            )
            # The registry states the digest. Only a caller pin can corroborate it here.
            expected_digest = target.get("package_digest")
            pinned = bool(digest and expected_digest == digest)
            record_digest = jsondoc_digest("application/vnd.mcp.server+json", server_obj)
            status = RegistryStatus.UNKNOWN
            raw_status = str(meta.get("status", entry.get("status", "unknown"))).lower()
            if raw_status in RegistryStatus._value2member_map_:
                status = RegistryStatus(raw_status)
            resolution = RegistryResolution(
                id=make_id("res", name, collision_seed=server_id),
                requested=requested,
                resolved_at=ctx.now,
                resolver=self.ref,
                resolved=ResolvedRef(
                    immutable_ref=digest if pinned else None,
                    digest=digest if pinned else None,
                    state="present" if pinned else "unknown",
                ),
                registry=RegistryFacts(
                    url=base,
                    entry_id=entry_name,
                    version=version,
                    status=status,
                    is_latest=meta.get("isLatest") if isinstance(meta.get("isLatest"), bool) else None,
                    schema_version=str(server_obj.get("$schema", "")) or None,
                ),
                publisher=PublisherFacts(namespace=namespace),
                alias_policy=AliasPinning.PINNED if pinned else AliasPinning.UNKNOWN,
                warnings=[]
                if pinned
                else ["registry metadata did not establish a matching immutable artifact digest"],
            )
            result.entities.append(resolution)
            if record_digest.ok and record_digest.value:
                result.evidence.append(
                    Evidence(
                        id=evidence_id(record_digest.value),
                        evidence_kind=EvidenceKind.REGISTRY_RECORD,
                        media_type="application/vnd.mcp.server+json",
                        digest=record_digest.value,
                        uri=url,
                        created=ctx.now,
                    )
                )
            result.edges.append(
                Edge(
                    type=EdgeType.RESOLVED_FROM,
                    **{"from": server_id, "to": resolution.id},
                    scope=EdgeScope.RUNTIME,
                    assurance=AssuranceLevel.OBSERVED,
                )
            )
            result.add_source(Surface.REGISTRY, url, ok=True, items=len(entries), locator=url)
        return result


__all__ = [
    "DEFAULT_POPULAR_NAMES",
    "DEFAULT_REGISTRY_BASE",
    "McpRegistryCollector",
    "levenshtein",
]
