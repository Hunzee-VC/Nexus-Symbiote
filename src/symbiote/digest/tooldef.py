"""Digests of model-visible artefacts: tool definitions, tool sets, server identity, prompts, documents, agents.

All payload field sets are frozen under their type URI (``spec/digests.md §3``; ``spec/versioning.md``).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from symbiote.digest.envelope import envelope_digest, strip_prefix
from symbiote.digest.jcs import UndigestableError, utf16_sort_key
from symbiote.model.common import DigestResult
from symbiote.model.enums import DigestStatus

TOOLDEF_FIELDS: tuple[str, ...] = (
    "name",
    "title",
    "description",
    "inputSchema",
    "outputSchema",
    "annotations",
)
TOOLDEF_FULL_EXTRA: tuple[str, ...] = ("_meta", "icons", "execution")

_DEFAULT_PORTS = {"http": "80", "https": "443", "ws": "80", "wss": "443"}


def tooldef_payload(raw_tool: Mapping[str, Any], *, full: bool = False) -> dict[str, Any]:
    """Select the digested fields from a raw ``tools/list`` result object. Absent keys stay absent."""
    if "name" not in raw_tool or not isinstance(raw_tool["name"], str):
        raise UndigestableError("missing-name", "tool definition has no string 'name'")
    if "inputSchema" not in raw_tool:
        raise UndigestableError("missing-input-schema", raw_tool["name"])
    fields = TOOLDEF_FIELDS + TOOLDEF_FULL_EXTRA if full else TOOLDEF_FIELDS
    return {k: raw_tool[k] for k in fields if k in raw_tool}


def tooldef_digest(raw_tool: Mapping[str, Any]) -> DigestResult:
    """``tooldef/v1`` — the model-visible surface (name, title, description, schemas, annotations)."""
    try:
        return envelope_digest("tooldef/v1", tooldef_payload(raw_tool))
    except UndigestableError as exc:
        return DigestResult(algorithm="tooldef/v1", status=DigestStatus.UNDIGESTABLE, reason=str(exc))


def tooldef_full_digest(raw_tool: Mapping[str, Any]) -> DigestResult:
    """``tooldef-full/v1`` — also covers ``_meta``, ``icons`` and ``execution``."""
    try:
        return envelope_digest("tooldef-full/v1", tooldef_payload(raw_tool, full=True))
    except UndigestableError as exc:
        return DigestResult(algorithm="tooldef-full/v1", status=DigestStatus.UNDIGESTABLE, reason=str(exc))


def toolset_digest(
    server_digest: str | None,
    protocol_version: str | None,
    tools: Iterable[tuple[str, DigestResult]],
) -> DigestResult:
    """``toolset/v1`` — the allowlist unit: sorted (name, digest) pairs plus server identity."""
    entries: list[dict[str, str]] = []
    for name, result in tools:
        if not result.ok or result.value is None:
            return DigestResult(
                algorithm="toolset/v1",
                status=DigestStatus.UNDIGESTABLE,
                reason=f"tool {name!r} undigestable: {result.reason}",
            )
        entries.append({"name": name, "digest": result.value})
    entries.sort(key=lambda e: utf16_sort_key(e["name"]))
    return envelope_digest(
        "toolset/v1", {"server": server_digest, "protocolVersion": protocol_version, "tools": entries}
    )


def normalize_endpoint(url: str) -> str:
    """Lowercase scheme and host, explicit port, path kept, query and fragment dropped."""
    parts = urlsplit(url.strip())
    if not parts.scheme or not parts.hostname:
        raise UndigestableError("invalid-endpoint", url)
    scheme = parts.scheme.lower()
    host = parts.hostname.lower()
    port = parts.port if parts.port is not None else _DEFAULT_PORTS.get(scheme)
    if port is None:
        raise UndigestableError("invalid-endpoint", f"no port for scheme {scheme}")
    netloc = f"{host}:{port}"
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def server_identity_digest(
    *,
    kind: str,
    transport: str,
    endpoint: str | None = None,
    package: Mapping[str, str | None] | None = None,
    server_info: Mapping[str, str | None] | None = None,
    instructions_digest: str | None = None,
) -> DigestResult:
    """``server/v1`` — tool-server identity (``spec/digests.md §3.4``)."""
    try:
        payload: dict[str, Any] = {
            "kind": kind,
            "transport": transport,
            "endpoint": normalize_endpoint(endpoint) if endpoint else None,
            "package": {"purl": package.get("purl"), "digest": package.get("digest")} if package else None,
            "serverInfo": {"name": server_info.get("name"), "version": server_info.get("version")}
            if server_info
            else None,
            "instructionsDigest": instructions_digest,
        }
    except UndigestableError as exc:
        return DigestResult(algorithm="server/v1", status=DigestStatus.UNDIGESTABLE, reason=str(exc))
    return envelope_digest("server/v1", payload)


def prompt_digest(
    *, engine: str, role: str, template: str, variables_schema: Mapping[str, Any] | None
) -> DigestResult:
    """``prompt/v1``."""
    return envelope_digest(
        "prompt/v1",
        {
            "engine": engine,
            "role": role,
            "template": template,
            "variablesSchema": dict(variables_schema) if variables_schema is not None else None,
        },
    )


def jsondoc_digest(media_type: str, body: Any) -> DigestResult:
    """``jsondoc/v1`` — agent cards, registry records, OpenAPI documents, policy JSON."""
    return envelope_digest("jsondoc/v1", {"mediaType": media_type, "body": body})


def agent_digest(
    *,
    name: str,
    version: str,
    framework: str | None,
    instruction_digests: Iterable[str],
    tool_digests: Iterable[str],
    model_digests: Iterable[str],
    policy_bundle: str | None,
) -> DigestResult:
    """``agent/v1`` — canonical agent definition."""
    return envelope_digest(
        "agent/v1",
        {
            "name": name,
            "version": version,
            "framework": framework,
            "instructions": list(instruction_digests),
            "tools": sorted(tool_digests),
            "models": sorted(model_digests),
            "policyBundle": policy_bundle,
        },
    )


__all__ = [
    "TOOLDEF_FIELDS",
    "TOOLDEF_FULL_EXTRA",
    "agent_digest",
    "jsondoc_digest",
    "normalize_endpoint",
    "prompt_digest",
    "server_identity_digest",
    "strip_prefix",
    "tooldef_digest",
    "tooldef_full_digest",
    "tooldef_payload",
    "toolset_digest",
]
