"""Compare approved inventory with served MCP tool descriptors.

Live, the descriptors come from operator-pinned stdio launchers. Offline, they
come from a recorded export in the ``RECORDED_FORMAT`` shape, which
``recorded_descriptors`` writes from a live report.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    hash_canonical,
    hash_tool_definition,
    normalize_digest,
)
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.graph import validate_graph
from nexus_symbiote.live.stdio import MAX_TOOLS, list_pinned_tools

RECORDED_FORMAT = "nexus-symbiote.recorded-tools/1"


@dataclass
class LiveToolFinding:
    name: str
    definition_hash: str | None
    status: str  # "match" | "changed" | "new" | "missing" | "unverifiable"

    descriptor: dict[str, Any] | None = field(default=None, repr=False)


@dataclass
class ServerVerifyResult:
    server_name: str
    server_ref: str
    reachable: bool = False
    error: str | None = None
    transport: str | None = None
    tool_findings: list[LiveToolFinding] = field(default_factory=list)
    live_schema_hash: str | None = None

    @property
    def rug_pull_detected(self) -> bool:
        return any(f.status != "match" for f in self.tool_findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server_name,
            "server_ref": self.server_ref,
            "reachable": self.reachable,
            "error": self.error,
            "transport": self.transport,
            "rug_pull_detected": self.rug_pull_detected,
            "live_schema_hash": self.live_schema_hash,
            "tools": [
                {"name": f.name, "definition_hash": f.definition_hash, "status": f.status}
                for f in self.tool_findings
            ],
        }


@dataclass
class LiveVerifyReport:
    servers_checked: int = 0
    servers_reachable: int = 0
    results: list[ServerVerifyResult] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return any(r.rug_pull_detected for r in self.results)

    @property
    def complete(self) -> bool:
        return (
            self.servers_checked > 0
            and self.servers_checked == self.servers_reachable
            and all(
                finding.status != "unverifiable"
                for result in self.results
                for finding in result.tool_findings
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "servers_checked": self.servers_checked,
            "servers_reachable": self.servers_reachable,
            "has_drift": self.has_drift,
            "results": [r.to_dict() for r in self.results],
        }


def list_tools_stdio(
    command: str, args: list[str], *, expected_sha256: str | None = None
) -> list[dict[str, Any]]:
    """Caller must supply a trusted binary digest. Only standalone launchers are supported."""
    if args or not expected_sha256:
        raise OSError("a pinned standalone executable without arguments is required")
    return list_pinned_tools(command, expected_sha256)


def fetch_tools_from_config(
    server_name: str, config: dict[str, Any], *, trusted_launcher: dict[str, str] | None = None
) -> tuple[str, list[dict[str, Any]]]:
    """Legacy project config conveys no authority to start a process."""
    if not isinstance(trusted_launcher, dict) or set(trusted_launcher) != {"command", "sha256"}:
        raise OSError("missing or invalid operator launch policy for this server reference")
    command, pin = trusted_launcher["command"], trusted_launcher["sha256"]
    if not isinstance(command, str) or not isinstance(pin, str):
        raise OSError("invalid operator launch policy")
    return "stdio", list_tools_stdio(command, [], expected_sha256=pin)


def parse_recorded(document: Any) -> dict[str, list[dict[str, Any]]]:
    """Validate a recorded-descriptor export: server references to complete tool lists."""
    if (
        not isinstance(document, dict)
        or set(document) != {"format", "servers"}
        or document["format"] != RECORDED_FORMAT
        or not isinstance(document["servers"], dict)
    ):
        raise ValueError(f"expected a {RECORDED_FORMAT} document with format and servers")
    recorded: dict[str, list[dict[str, Any]]] = {}
    for reference, listing in document["servers"].items():
        if not isinstance(listing, dict) or set(listing) != {"tools"}:
            raise ValueError("each server maps to an object holding only its complete tools list")
        tools = listing["tools"]
        if not isinstance(tools, list) or len(tools) > MAX_TOOLS:
            raise ValueError("invalid or oversized recorded tool list")
        names: set[str] = set()
        for tool in tools:
            name = tool.get("name") if isinstance(tool, dict) else None
            if (
                not isinstance(name, str)
                or not name
                or len(name) > 256
                or not name.isprintable()
                or name in names
                or not isinstance(tool.get("inputSchema"), dict)
            ):
                raise ValueError("invalid or duplicate recorded MCP tool")
            names.add(name)
        recorded[reference] = tools
    return recorded


def recorded_descriptors(report: LiveVerifyReport) -> dict[str, Any]:
    """The descriptors a report observed, in the format ``parse_recorded`` reads back."""
    return {
        "format": RECORDED_FORMAT,
        "servers": {
            result.server_ref: {
                "tools": [f.descriptor for f in result.tool_findings if f.descriptor is not None]
            }
            for result in report.results
            if result.reachable
        },
    }


def verify_mcp_servers(
    bom: AIBOM,
    config_lookup: dict[str, dict[str, Any]] | None = None,
    *,
    trusted_launchers: dict[str, dict[str, str]] | None = None,
    recorded: Mapping[str, list[dict[str, Any]]] | None = None,
) -> LiveVerifyReport:
    """Bind collection to the exact server reference in an independent launch policy.

    With ``recorded``, descriptors come from that export instead and nothing is
    launched; any transport is accepted because no process is started.
    """
    report = LiveVerifyReport()
    if validate_graph(bom):
        report.results.append(
            ServerVerifyResult(
                server_name="[inventory]",
                server_ref="[inventory]",
                error="Inventory relationships are invalid",
            )
        )
        return report
    for server in bom.components:
        if not isinstance(server, MCPServerComponent):
            continue
        result = ServerVerifyResult(
            server_name=server.name, server_ref=server.bom_ref, transport=server.transport
        )
        report.servers_checked += 1
        report.results.append(result)
        try:
            if recorded is not None:
                if server.bom_ref not in recorded:
                    raise ValueError("no recorded descriptors for this server reference")
                tools = recorded[server.bom_ref]
            else:
                if server.transport not in ("stdio", None):
                    raise ValueError("unsupported transport")
                _, tools = fetch_tools_from_config(
                    server.name, {}, trusted_launcher=(trusted_launchers or {}).get(server.bom_ref)
                )
            live = {}
            for tool in tools:
                if set(tool) - {"name", "description", "inputSchema", "annotations"}:
                    raise ValueError("tool fields exceed the approved fingerprint version")
                desc, annotations = tool.get("description", ""), tool.get("annotations")
                if not isinstance(desc, str) or (
                    annotations is not None and not isinstance(annotations, dict)
                ):
                    raise ValueError("invalid descriptor")
                schema = tool.get("inputSchema")
                if not isinstance(schema, dict) or schema.get("type") != "object":
                    raise ValueError("MCP tools require an object input schema")
                Draft202012Validator.check_schema(schema)
                for hint in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
                    if annotations and hint in annotations and type(annotations[hint]) is not bool:
                        raise ValueError("invalid MCP annotation hint")
                live[tool["name"]] = hash_tool_definition(
                    tool["name"], desc, tool["inputSchema"], annotations or None
                )
            approved = [
                t
                for t in bom.components
                if isinstance(t, ToolComponent) and t.mcp_server_ref == server.bom_ref
            ]
            by_name = {t.name: t for t in approved}
            if len(by_name) != len(approved):
                raise ValueError("ambiguous tool references")
        except (OSError, ValueError, TypeError, RecursionError, SchemaError):
            result.error = (
                "Recorded descriptors missing or invalid for this server reference"
                if recorded is not None
                else "Pinned MCP discovery refused or incomplete; review launch policy and protocol limits"
            )
            continue
        result.reachable = True
        report.servers_reachable += 1
        for tool in tools:
            name = tool["name"]
            old = by_name.get(name)
            if old is None:
                status = "new"
            elif (
                old.definition_hash_version != TOOL_DEFINITION_HASH_VERSION
                or not old.definition_hash
            ):
                status = "unverifiable"
            else:
                try:
                    algorithm, expected = normalize_digest(old.definition_hash, "sha256")
                    status = "match" if f"{algorithm}:{expected}" == live[name] else "changed"
                except ValueError:
                    status = "unverifiable"
            result.tool_findings.append(LiveToolFinding(name, live[name], status, tool))
        for old in approved:
            if old.name not in live:
                result.tool_findings.append(
                    LiveToolFinding(old.name, old.definition_hash, "missing")
                )
        result.live_schema_hash = hash_canonical(
            {"profile": TOOL_DEFINITION_HASH_VERSION, "tools": dict(sorted(live.items()))}
        )
    return report


def record_candidate(bom: AIBOM, report: LiveVerifyReport, *, observed: bool = True) -> None:
    """Update a separate unsigned candidate; observations confer no authority.

    ``observed`` is True when this run launched the servers. Descriptors replayed
    from a recorded export keep declared assurance: this run did not observe them.
    """
    from datetime import UTC, datetime
    from urllib.parse import quote

    from nexus_symbiote import modes
    from nexus_symbiote.core.aibom import DependencyEdge
    from nexus_symbiote.core.enums import AssuranceLevel
    from nexus_symbiote.core.models import ClaimEvidence, CompletenessClaim, LiveOperation

    if not report.complete or any(
        finding.status == "missing" for result in report.results for finding in result.tool_findings
    ):
        raise ValueError("incomplete inventory; candidate cannot be emitted")
    for result in report.results:
        for finding in result.tool_findings:
            descriptor = finding.descriptor
            if descriptor is None:
                raise ValueError("candidate requires an observed descriptor")
            tool = next(
                (
                    component
                    for component in bom.components
                    if isinstance(component, ToolComponent)
                    and component.mcp_server_ref == result.server_ref
                    and component.name == finding.name
                ),
                None,
            )
            if tool is None:
                tool = ToolComponent(
                    bom_ref=f"tool:{quote(result.server_ref, safe='')}/{quote(finding.name, safe='')}",
                    name=finding.name,
                    mcp_server_ref=result.server_ref,
                )
                bom.add_component(tool)
                bom.add_dependency(
                    DependencyEdge(
                        source_ref=result.server_ref,
                        target_ref=tool.bom_ref,
                        relationship="provides-tool",
                        assurance_level="observed" if observed else "declared",
                        conditions=(
                            "served descriptor observed"
                            if observed
                            else "descriptor read from a recorded export"
                        )
                        + "; backend behavior and authorization unverified",
                    )
                )
            tool.definition_hash = finding.definition_hash
            tool.definition_hash_version = TOOL_DEFINITION_HASH_VERSION
            tool.description_text = descriptor.get("description", "")
            tool.input_schema = descriptor["inputSchema"]
            tool.annotations = descriptor.get("annotations") or {}
            level = AssuranceLevel.OBSERVED if observed else AssuranceLevel.DECLARED
            tool.assurance_level = level
            tool.claims["tool_definition"] = ClaimEvidence(
                assurance=level,
                method=(
                    "operator-pinned-stdio-tools-list" if observed else "recorded-tools-list-export"
                ),
                scope="served-descriptor" if observed else "recorded-descriptor",
                collector="nexus-symbiote-live-stdio"
                if observed
                else "nexus-symbiote-recorded-tools",
                observed_at=datetime.now(UTC),
            )
        server = bom.get_component(result.server_ref)
        if isinstance(server, MCPServerComponent):
            server.schema_hash = result.live_schema_hash
            server.tool_refs = [
                component.bom_ref
                for component in bom.components
                if isinstance(component, ToolComponent)
                and component.mcp_server_ref == result.server_ref
            ]
            server.tool_count = len(server.tool_refs)
    claim = bom.metadata.completeness or CompletenessClaim(scope="live-candidate")
    bom.metadata.completeness = claim
    if observed:
        now = datetime.now(UTC)
        claim.collection_mode = "live"
        claim.offline_enforced = False
        claim.live_operations.extend(
            LiveOperation(
                command="verify-live", kind="process", target=r.server_ref, observed_at=now
            )
            for r in report.results
            if r.reachable
        )
    else:
        claim.collection_mode = claim.collection_mode or "offline"
        claim.offline_enforced = bool(claim.offline_enforced) and (
            modes.current() is modes.Mode.OFFLINE
        )
