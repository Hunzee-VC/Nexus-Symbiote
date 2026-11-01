"""Compare approved inventory with descriptors served by operator-pinned stdio launchers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.live.stdio import list_pinned_tools


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
        return any(f.status in ("changed", "new", "missing") for f in self.tool_findings)

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


def verify_mcp_servers(
    bom: AIBOM,
    config_lookup: dict[str, dict[str, Any]] | None = None,
    *,
    trusted_launchers: dict[str, dict[str, str]] | None = None,
) -> LiveVerifyReport:
    """Bind collection to the exact server reference in an independent launch policy."""
    report = LiveVerifyReport()
    for server in bom.components:
        if not isinstance(server, MCPServerComponent):
            continue
        result = ServerVerifyResult(
            server_name=server.name, server_ref=server.bom_ref, transport=server.transport
        )
        report.servers_checked += 1
        report.results.append(result)
        try:
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
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            result.error = str(exc)
            continue
        result.reachable = True
        report.servers_reachable += 1
        for tool in tools:
            name = tool["name"]
            old = by_name.get(name)
            if old is None:
                status = "new"
            elif old.definition_hash_version != "rfc8785-jcs-v1" or not old.definition_hash:
                status = "unverifiable"
            else:
                status = "match" if old.definition_hash == live[name] else "changed"
            result.tool_findings.append(LiveToolFinding(name, live[name], status, tool))
        for old in approved:
            if old.name not in live:
                result.tool_findings.append(
                    LiveToolFinding(old.name, old.definition_hash, "missing")
                )
        result.live_schema_hash = (
            "sha256:" + hashlib.sha256("".join(sorted(live.values())).encode()).hexdigest()
        )
    return report
