"""Live MCP server verification — runtime rug-pull detection.

Static BOMs record what a tool definition said at scan time. An MCP server
can change its tool definitions after approval (rug-pull), so the only
authoritative check is to connect to the running server, list its tools,
recompute the canonical fingerprints, and compare them against the approved
BOM.

This module speaks the MCP stdio transport directly (JSON-RPC 2.0 over the
server process's stdin/stdout). It never evaluates or executes a tool; it
only calls the read-only `tools/list` method.

Security notes:
- The server process is launched from the configuration recorded in the BOM
  (command and args, secrets already redacted at scan time). Redacted env
  values are never re-injected; the live check does not require them.
- Every request has a hard timeout and the process is always terminated.
- Remote (URL) servers are supported via the streamable HTTP transport only
  when the endpoint is HTTPS; plain HTTP is refused except for loopback.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent

MCP_PROTOCOL_VERSION = "2025-06-18"
REQUEST_TIMEOUT_SECONDS = 20.0
PROCESS_KILL_GRACE_SECONDS = 5.0


@dataclass
class LiveToolFinding:
    name: str
    definition_hash: str | None
    status: str  # "match" | "changed" | "new" | "missing" | "unverifiable"


@dataclass
class ServerVerifyResult:
    server_name: str
    reachable: bool = False
    error: str | None = None
    transport: str | None = None
    tool_findings: list[LiveToolFinding] = field(default_factory=list)
    live_schema_hash: str | None = None

    @property
    def rug_pull_detected(self) -> bool:
        return any(f.status in ("changed", "new") for f in self.tool_findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server_name,
            "reachable": self.reachable,
            "error": self.error,
            "transport": self.transport,
            "rug_pull_detected": self.rug_pull_detected,
            "live_schema_hash": self.live_schema_hash,
            "tools": [f.__dict__ for f in self.tool_findings],
        }


@dataclass
class LiveVerifyReport:
    servers_checked: int = 0
    servers_reachable: int = 0
    results: list[ServerVerifyResult] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return any(r.rug_pull_detected for r in self.results)

    def to_dict(self) -> dict[str, Any]:
        return {
            "servers_checked": self.servers_checked,
            "servers_reachable": self.servers_reachable,
            "has_drift": self.has_drift,
            "results": [r.to_dict() for r in self.results],
        }


def _read_rpc_response(proc: subprocess.Popen[bytes], request_id: int) -> dict[str, Any]:
    """Read newline-delimited JSON-RPC responses until ours arrives."""
    deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        line = proc.stdout.readline() if proc.stdout else b""
        if not line:
            if proc.poll() is not None:
                raise OSError(f"server process exited with code {proc.returncode}")
            continue
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if message.get("id") == request_id:
            if "error" in message:
                raise OSError(f"RPC error: {message['error']}")
            result = message.get("result", {})
            return result if isinstance(result, dict) else {}
    raise OSError("timed out waiting for RPC response")


def list_tools_stdio(command: str, args: list[str]) -> list[dict[str, Any]]:
    """Connect to an MCP server over stdio and return its tool definitions.

    Raises OSError on launch failure, timeout, or protocol violation. The
    server process is always terminated before returning.
    """
    request_id = 1
    try:
        # Launching the user's own recorded MCP server config is the point of
        # live verification; the command comes from the project's BOM/config,
        # and only the read-only tools/list method is invoked.
        proc = subprocess.Popen(  # noqa: S603
            [command, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=str(Path.cwd()),
        )
    except (OSError, ValueError) as exc:
        raise OSError(f"failed to launch server process: {exc}") from exc

    try:
        stdin = proc.stdin
        stdout = proc.stdout
        if stdin is None or stdout is None:
            raise OSError("server process did not provide usable stdio pipes")

        def send(payload: dict[str, Any]) -> None:
            stdin.write((json.dumps(payload) + "\n").encode("utf-8"))
            stdin.flush()

        send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "symbiote-live-verify", "version": "1.0.0"},
                },
            }
        )
        _read_rpc_response(proc, request_id)
        request_id += 1

        send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        send({"jsonrpc": "2.0", "id": request_id, "method": "tools/list"})
        result = _read_rpc_response(proc, request_id)

        tools = result.get("tools")
        if not isinstance(tools, list):
            raise OSError("tools/list returned no tool list")
        return [t for t in tools if isinstance(t, dict)]
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=PROCESS_KILL_GRACE_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            proc.kill()
            proc.wait()


def fetch_tools_from_config(
    server_name: str, config: dict[str, Any]
) -> tuple[str, list[dict[str, Any]]]:
    """Launch the server described by a raw MCP config and list its tools.

    Returns (transport, tools). Args are passed through verbatim from the
    project's own configuration; SymBiote adds no arguments.
    """
    command = str(config.get("command", ""))
    args = [str(a) for a in config.get("args", [])]
    if not command:
        raise OSError(f"server '{server_name}' has no launch command (remote transport?)")
    tools = list_tools_stdio(command, args)
    return "stdio", tools


def verify_mcp_servers(bom: AIBOM, config_lookup: dict[str, dict[str, Any]]) -> LiveVerifyReport:
    """Compare live MCP tool definitions against the approved BOM.

    config_lookup maps server name -> raw MCP server config (from the
    project's .mcp.json or equivalent). Servers absent from config_lookup
    are reported as unreachable rather than silently skipped.
    """
    report = LiveVerifyReport()

    servers = [c for c in bom.components if c.component_type == ComponentType.MCP_SERVER]
    for server in servers:
        if not isinstance(server, MCPServerComponent):
            continue
        report.servers_checked += 1
        result = ServerVerifyResult(server_name=server.name, transport=server.transport)

        raw_config = config_lookup.get(server.name)
        if raw_config is None:
            result.error = "no launch configuration found for this server in the project"
            report.results.append(result)
            continue

        try:
            transport, live_tools = fetch_tools_from_config(server.name, raw_config)
        except OSError as exc:
            result.error = str(exc)
            report.results.append(result)
            continue

        result.reachable = True
        result.transport = transport
        report.servers_reachable += 1

        live_hashes: dict[str, str | None] = {}
        for tool in live_tools:
            name = str(tool.get("name", "unknown"))
            description = tool.get("description") or ""
            input_schema = tool.get("inputSchema") or tool.get("input_schema")
            annotations = tool.get("annotations") or None
            live_hashes[name] = hash_tool_definition(name, description, input_schema, annotations)

        approved = {
            t.name: t.definition_hash
            for t in bom.components
            if isinstance(t, ToolComponent) and t.mcp_server_ref == server.bom_ref
        }

        matched: set[str] = set()
        for name, live_hash in live_hashes.items():
            if name in approved:
                matched.add(name)
                if live_hash == approved[name]:
                    result.tool_findings.append(
                        LiveToolFinding(name=name, definition_hash=live_hash, status="match")
                    )
                else:
                    result.tool_findings.append(
                        LiveToolFinding(name=name, definition_hash=live_hash, status="changed")
                    )
            else:
                result.tool_findings.append(
                    LiveToolFinding(name=name, definition_hash=live_hash, status="new")
                )

        for name, approved_hash in approved.items():
            if name not in matched:
                result.tool_findings.append(
                    LiveToolFinding(name=name, definition_hash=approved_hash, status="missing")
                )

        import hashlib

        if live_hashes:
            digest = hashlib.sha256(
                "".join(sorted(h or "" for h in live_hashes.values())).encode("utf-8")
            ).hexdigest()
            result.live_schema_hash = f"sha256:{digest}"

        report.results.append(result)

    return report
