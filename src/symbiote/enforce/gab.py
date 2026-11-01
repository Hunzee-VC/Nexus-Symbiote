"""Gateway Allowlist Bundle (GAB): what a tool gateway needs to enforce an approved snapshot.

A gateway applies: verify the attestations under its identity policy; at ``tools/list`` compute ``tooldef/v1``
for every served tool from the raw JSON and block any tool whose digest is not allowlisted (a known name with a
new digest is the rug-pull signal); refuse a server whose identity differs; enforce the approval gate at
``tools/call``; refuse when the snapshot expired, the serial regressed or the trust status expired or revoked.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import Field

from symbiote.digest.tooldef import tooldef_digest, toolset_digest
from symbiote.model.base import SymbioteModel
from symbiote.model.document import AgentBOM
from symbiote.model.entities import TrustStatus
from symbiote.model.enums import ApprovalGate, TrustState, TrustSubjectKind

GAB_VERSION = "1"


def _iso(dt: datetime | None) -> str | None:
    return (
        None if dt is None else dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def gab_from_document(
    bom: AgentBOM,
    *,
    trust_status: Iterable[TrustStatus] = (),
    attestations: Iterable[str] = (),
    max_staleness: str = "PT24H",
    fail_closed_on_expired_trust_status: bool = True,
    require_annotations_for_destructive: bool = True,
) -> dict[str, Any]:
    """Build the GAB JSON from a finalised (ideally approved) document."""
    agent = bom.root_agent
    tools_by_server: dict[str, list] = {}
    for tool in bom.tools:
        tools_by_server.setdefault(tool.server_ref, []).append(tool)
    gates = {g.subject_ref: g.approval_gate for g in bom.grants if g.layer.value == "declared"}
    servers: dict[str, Any] = {}
    for srv in sorted(bom.tool_servers, key=lambda s: s.id):
        tool_entries: dict[str, Any] = {}
        denied: list[str] = []
        for tool in sorted(tools_by_server.get(srv.id, []), key=lambda t: t.tool_name):
            if not tool.digest.ok or tool.digest.value is None:
                denied.append(tool.tool_name)  # undigestable tools cannot be pinned, so they cannot be served
                continue
            gate = gates.get(tool.id, tool.approval_gate)
            if gate is ApprovalGate.UNKNOWN:
                gate = ApprovalGate.REQUIRED  # fail closed on unknown gates
            tool_entries[tool.tool_name] = {
                "digest": tool.digest.value,
                "fullDigest": tool.full_digest.value if tool.full_digest and tool.full_digest.ok else None,
                "gate": gate.value,
                "capabilities": sorted(c.value for c in tool.capabilities),
                "sideEffectClass": tool.side_effect_class.value,
            }
        signer = None
        if srv.registry_resolution_ref:
            res = next((r for r in bom.resolutions if r.id == srv.registry_resolution_ref), None)
            if res and res.signer:
                signer = {
                    "status": res.signer.status.value,
                    "identity": res.signer.identity,
                    "issuer": res.signer.issuer,
                }
        servers[srv.id] = {
            "identity": {
                "digest": srv.digest,
                "kind": srv.server_kind.value,
                "transport": srv.transport.value.value if srv.transport.value else None,
                "endpointOrigin": srv.endpoint.value if srv.endpoint and srv.endpoint.value else None,
                "package": {"purl": srv.package.value.purl, "digest": srv.package.value.digest}
                if srv.package and srv.package.value
                else None,
                "instructionsDigest": srv.instructions_digest.value
                if srv.instructions_digest and srv.instructions_digest.value
                else None,
                "signer": signer,
            },
            "toolset": srv.toolset_digest.value if srv.toolset_digest and srv.toolset_digest.value else None,
            "tools": tool_entries,
            "deniedTools": denied,
        }
    models: dict[str, Any] = {}
    for m in sorted(bom.models, key=lambda m: m.id):
        if m.hosted and m.hosted.value:
            h = m.hosted.value
            models[m.id] = {
                "kind": "hosted",
                "provider": h.provider,
                "alias": h.requested_ref,
                "resolvedRef": h.resolved_ref.value,
                "aliasPinning": h.alias_pinning.value,
            }
        elif m.weights and m.weights.value:
            models[m.id] = {
                "kind": "weights",
                "manifestRoot": m.weights.value.manifest_root,
                "purl": m.weights.value.purl,
            }
        else:
            models[m.id] = {"kind": m.model_kind.value, "identity": "unknown"}
    instructions = {i.id: i.digest for i in sorted(bom.instructions, key=lambda i: i.id)}
    ts = list(trust_status)
    trust = {
        "serial": max((t.serial for t in ts), default=0),
        "expires": _iso(min((t.expires for t in ts if t.expires), default=None)),
        "revoked": sorted(
            t.subject_key
            for t in ts
            if t.status is TrustState.REVOKED and t.subject_kind is not TrustSubjectKind.PUBLISHER_IDENTITY
        ),
        "quarantined": sorted(t.subject_key for t in ts if t.status is TrustState.QUARANTINED),
        "revokedPublishers": sorted(
            t.subject_key
            for t in ts
            if t.status is TrustState.REVOKED and t.subject_kind is TrustSubjectKind.PUBLISHER_IDENTITY
        ),
    }
    return {
        "gabVersion": GAB_VERSION,
        "agent": {"id": agent.id, "name": agent.name, "version": agent.version},
        "snapshot": {
            "kind": bom.snapshot.kind.value,
            "digest": bom.snapshot.digest,
            "serial": bom.snapshot.serial,
            "prev": bom.snapshot.prev,
            "notBefore": _iso(bom.snapshot.validity.not_before),
            "notAfter": _iso(bom.snapshot.validity.not_after),
        },
        "policy": {
            "maxStaleness": max_staleness,
            "failClosedOnExpiredTrustStatus": fail_closed_on_expired_trust_status,
            "requireAnnotationsForDestructive": require_annotations_for_destructive,
        },
        "servers": servers,
        "models": models,
        "instructions": instructions,
        "trustStatus": trust,
        "attestations": list(attestations),
    }


def export_allowlist(
    bom: AgentBOM, fmt: Literal["gab", "opa-data", "mcp-gateway-generic"] = "gab", **kwargs: Any
) -> dict[str, Any] | list[dict[str, Any]]:
    gab = gab_from_document(bom, **kwargs)
    if fmt == "gab":
        return gab
    if fmt == "opa-data":
        return {"symbiote": {"allowlist": gab}}
    if fmt == "mcp-gateway-generic":
        return [
            {"server": sid, "tool": name, "digest": entry["digest"], "gate": entry["gate"]}
            for sid, srv in gab["servers"].items()
            for name, entry in srv["tools"].items()
        ]
    raise ValueError(f"unknown allowlist format {fmt!r}")


class Decision(SymbioteModel):
    action: Literal["allow", "block", "drop"]
    reason: str
    server: str
    tool: str | None = None
    expected: str | None = None
    actual: str | None = None
    gate: str | None = None
    signals: list[str] = Field(default_factory=list)


def check_served_tool(
    gab: Mapping[str, Any], server_id: str, raw_tool: Mapping[str, Any], *, now: datetime | None = None
) -> Decision:
    """Reference enforcement for one served tool definition (raw JSON-RPC object)."""
    now = now or datetime.now(UTC)
    snap = gab.get("snapshot", {})
    if snap.get("notAfter") and datetime.fromisoformat(snap["notAfter"].replace("Z", "+00:00")) <= now:
        return Decision(action="block", reason="snapshot-expired", server=server_id, signals=["SYM-SNAP-002"])
    ts = gab.get("trustStatus", {})
    if (
        ts.get("expires")
        and datetime.fromisoformat(ts["expires"].replace("Z", "+00:00")) <= now
        and gab.get("policy", {}).get("failClosedOnExpiredTrustStatus", True)
    ):
        return Decision(
            action="block", reason="trust-status-expired", server=server_id, signals=["SYM-TRUST-001"]
        )
    server = gab.get("servers", {}).get(server_id)
    if server is None:
        return Decision(action="block", reason="server-not-allowlisted", server=server_id)
    name = str(raw_tool.get("name", ""))
    result = tooldef_digest(raw_tool)
    if not result.ok or result.value is None:
        return Decision(
            action="block",
            reason=f"undigestable: {result.reason}",
            server=server_id,
            tool=name,
            signals=["SYM-TOOL-004"],
        )
    if result.value in set(ts.get("revoked", [])) or result.value in set(ts.get("quarantined", [])):
        return Decision(
            action="block",
            reason="tool-digest-revoked-or-quarantined",
            server=server_id,
            tool=name,
            actual=result.value,
            signals=["SYM-TRUST-001"],
        )
    entry = server.get("tools", {}).get(name)
    if entry is None:
        if name in server.get("deniedTools", []):
            return Decision(
                action="block", reason="tool-denied", server=server_id, tool=name, actual=result.value
            )
        return Decision(
            action="drop",
            reason="unknown-tool-name",
            server=server_id,
            tool=name,
            actual=result.value,
            signals=["SYM-TOOL-002"],
        )
    if entry["digest"] != result.value:
        return Decision(
            action="block",
            reason="rug-pull-signal: known name, new digest",
            server=server_id,
            tool=name,
            expected=entry["digest"],
            actual=result.value,
            signals=["SYM-TOOL-002"],
        )
    return Decision(
        action="allow",
        reason="digest-matches-allowlist",
        server=server_id,
        tool=name,
        expected=entry["digest"],
        actual=result.value,
        gate=entry.get("gate"),
    )


def check_served_toolset(
    gab: Mapping[str, Any],
    server_id: str,
    raw_tools: Iterable[Mapping[str, Any]],
    *,
    protocol_version: str | None = None,
    now: datetime | None = None,
) -> list[Decision]:
    """Check every served tool and the whole set (an approved tool that disappeared is also a finding)."""
    tools = list(raw_tools)
    decisions = [check_served_tool(gab, server_id, t, now=now) for t in tools]
    server = gab.get("servers", {}).get(server_id, {})
    served_names = {str(t.get("name", "")) for t in tools}
    for name in server.get("tools", {}):
        if name not in served_names:
            decisions.append(
                Decision(
                    action="drop",
                    reason="approved-tool-missing",
                    server=server_id,
                    tool=name,
                    expected=server["tools"][name]["digest"],
                    signals=["SYM-TOOL-002"],
                )
            )
    expected_set = server.get("toolset")
    if expected_set:
        actual_set = toolset_digest(
            server.get("identity", {}).get("digest"),
            protocol_version,
            [(str(t.get("name", "")), tooldef_digest(t)) for t in tools],
        )
        if actual_set.value != expected_set:
            decisions.append(
                Decision(
                    action="block",
                    reason="toolset-digest-mismatch",
                    server=server_id,
                    expected=expected_set,
                    actual=actual_set.value,
                    signals=["SYM-TOOL-002"],
                )
            )
    return decisions


__all__ = [
    "GAB_VERSION",
    "Decision",
    "check_served_tool",
    "check_served_toolset",
    "export_allowlist",
    "gab_from_document",
]
