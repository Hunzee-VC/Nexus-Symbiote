"""Live MCP introspection: the ``observed`` side of the tool surface (``spec/collectors.md`` row ``mcp-live``).

Digests are computed over the **raw JSON-RPC result objects** exactly as served — never over SDK
re-serialisations (``spec/digests.md §7``: the gateway sees raw JSON; so must the BOM). For stdio
servers this module therefore speaks newline-delimited JSON-RPC itself with no SDK dependency;
remote transports (``streamable-http``/``sse``) are not attempted in this version and surface as an
honest coverage gap instead of a silent absence (I2).

Safety rules enforced here:

* a server process is launched **only** when its name/id is on the ``live_allow`` allowlist
  (``--live-allow``); everything else is recorded as not-allowlisted coverage, never executed;
* environment *values* are passed to the child process but never recorded — entities carry names
  only (the declared collector already recorded those);
* every server gets a hard wall-clock deadline (default 15 s); a hung server yields a coverage
  fact, not a hung scan.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from queue import Empty, Queue
from typing import Any, ClassVar

from symbiote.collect.base import BaseCollector, CollectContext, CollectionResult
from symbiote.digest import (
    bytes_digest,
    canonical_bytes,
    digest_str,
    jsondoc_digest,
    server_identity_digest,
    tool_text_flags,
    tooldef_digest,
    tooldef_full_digest,
    toolset_digest,
)
from symbiote.digest.jcs import UndigestableError
from symbiote.model.common import Claim, EvidenceRef
from symbiote.model.edges import Edge
from symbiote.model.entities import (
    Evidence,
    ServerInfo,
    ToolAnnotations,
    ToolDefinition,
    ToolListMeta,
    ToolServer,
)
from symbiote.model.enums import (
    AssuranceLevel,
    CollectorMode,
    CoverageStatus,
    EdgeScope,
    EdgeType,
    EvidenceKind,
    Surface,
    ToolServerKind,
    ToolSource,
    ToolState,
    Transport,
    UnknownReason,
)

PROTOCOL_VERSION = "2025-06-18"
DEFAULT_SERVER_DEADLINE = 15.0
_MAX_PAGES = 64
_MAX_STDERR_BYTES = 64 * 1024


class McpLiveError(RuntimeError):
    """A live introspection failure with a coverage ``error_class``."""

    def __init__(self, error_class: str, detail: str) -> None:
        super().__init__(f"{error_class}: {detail}")
        self.error_class = error_class
        self.detail = detail


@dataclass(slots=True)
class LiveServerSpec:
    """What the caller (CLI / mcp-config stage) knows about a server to introspect."""

    id: str
    name: str
    transport: str = "stdio"
    command: str | None = None
    args: Sequence[str] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: str | None = None
    url: str | None = None
    package_purl: str | None = None
    package_digest: str | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> LiveServerSpec:
        name = str(raw.get("name") or raw.get("id") or "server").split(":", 1)[-1]
        return cls(
            id=str(raw.get("id") or f"server:{name}"),
            name=name,
            transport=str(raw.get("transport") or ("stdio" if raw.get("command") else "streamable-http")),
            command=raw.get("command"),
            args=[str(a) for a in raw.get("args", [])],
            env={str(k): str(v) for k, v in dict(raw.get("env", {})).items()},
            cwd=raw.get("cwd"),
            url=raw.get("url"),
            package_purl=raw.get("package_purl"),
            package_digest=raw.get("package_digest"),
        )


@dataclass(slots=True)
class LiveCapture:
    """Raw wire facts from one server: exactly what was served, before any model shaping."""

    protocol_version: str | None
    server_info: Mapping[str, Any] | None
    instructions: str | None
    raw_tools: list[Mapping[str, Any]]
    list_meta: Mapping[str, Any]
    pages: int


# --------------------------------------------------------------------------------------------- stdio client


class _StdioRpc:
    """Minimal newline-delimited JSON-RPC 2.0 client over a child process's stdio."""

    def __init__(self, proc: subprocess.Popen[bytes], deadline: float) -> None:
        self._proc = proc
        self._deadline = deadline
        self._queue: Queue[Any] = Queue()
        self._next_id = 0
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        stdout = self._proc.stdout
        assert stdout is not None
        for line in stdout:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                self._queue.put(json.loads(stripped.decode("utf-8")))
            except (ValueError, UnicodeDecodeError):
                continue  # servers sometimes log to stdout; non-JSON lines are not protocol data
        self._queue.put(None)  # EOF marker

    def _remaining(self) -> float:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise McpLiveError("timeout", "server deadline exceeded")
        return remaining

    def _send(self, payload: Mapping[str, Any]) -> None:
        stdin = self._proc.stdin
        assert stdin is not None
        try:
            stdin.write(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
            stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise McpLiveError("unreachable", f"server closed stdin: {exc}") from exc

    def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

    def request(self, method: str, params: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)
        while True:
            try:
                item = self._queue.get(timeout=min(self._remaining(), 0.5))
            except Empty:
                continue
            if item is None:
                raise McpLiveError("unreachable", f"server exited before replying to {method}")
            if not isinstance(item, Mapping) or item.get("id") != request_id:
                continue  # notifications and unrelated responses
            if "error" in item:
                error = item["error"]
                raise McpLiveError("protocol-error", f"{method}: {error.get('code')}: {error.get('message')}")
            result = item.get("result")
            if not isinstance(result, Mapping):
                raise McpLiveError("protocol-error", f"{method}: result is not an object")
            return result


def introspect_stdio(
    spec: LiveServerSpec,
    *,
    deadline_seconds: float = DEFAULT_SERVER_DEADLINE,
    base_env: Mapping[str, str] | None = None,
) -> LiveCapture:
    """Launch ``spec`` and capture ``initialize`` + every ``tools/list`` page as raw objects."""
    if not spec.command:
        raise McpLiveError("unsupported-source", "stdio server without a command")
    env: dict[str, str] = dict(base_env if base_env is not None else {"PATH": os.environ.get("PATH", "")})
    env.update(spec.env)
    try:
        proc = subprocess.Popen(  # noqa: S603 - allowlisted by the caller; see module docstring
            [spec.command, *spec.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=spec.cwd,
            env=env,
        )
    except OSError as exc:
        raise McpLiveError("unreachable", f"failed to launch {spec.command!r}: {exc}") from exc
    deadline = time.monotonic() + deadline_seconds
    rpc = _StdioRpc(proc, deadline)
    try:
        init = rpc.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "symbiote", "version": "0.1.0"},
            },
        )
        rpc.notify("notifications/initialized")
        raw_tools: list[Mapping[str, Any]] = []
        list_meta: dict[str, Any] = {}
        cursor: str | None = None
        pages = 0
        while True:
            params: dict[str, Any] = {"cursor": cursor} if cursor else {}
            result = rpc.request("tools/list", params)
            pages += 1
            tools = result.get("tools")
            if not isinstance(tools, list):
                raise McpLiveError("protocol-error", "tools/list result has no tools array")
            raw_tools.extend(t for t in tools if isinstance(t, Mapping))
            for key in ("ttlMs", "cacheScope"):
                if key in result:
                    list_meta[key] = result[key]
            cursor = result.get("nextCursor")
            if not cursor:
                break
            if pages >= _MAX_PAGES:
                raise McpLiveError("truncated", f"more than {_MAX_PAGES} tools/list pages")
        server_info = init.get("serverInfo") if isinstance(init.get("serverInfo"), Mapping) else None
        instructions = init.get("instructions") if isinstance(init.get("instructions"), str) else None
        return LiveCapture(
            protocol_version=init.get("protocolVersion")
            if isinstance(init.get("protocolVersion"), str)
            else None,
            server_info=server_info,
            instructions=instructions,
            raw_tools=raw_tools,
            list_meta=list_meta,
            pages=pages,
        )
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            proc.kill()
        if proc.stderr is not None:
            proc.stderr.read(_MAX_STDERR_BYTES)


# --------------------------------------------------------------------------------------------- shaping


def _sub_digest(value: Any) -> str | None:
    try:
        return digest_str(canonical_bytes(value))
    except UndigestableError:
        return None


def capture_to_entities(
    spec: LiveServerSpec, capture: LiveCapture, *, collector_ref: str, ctx: CollectContext
) -> tuple[ToolServer, list[ToolDefinition], Evidence, list[Edge]]:
    """Shape one server's raw capture into observed entities with wire-exact digests."""
    server_slug = spec.id.split(":", 1)[1]
    instructions_digest = bytes_digest(capture.instructions.encode("utf-8")) if capture.instructions else None
    server_digest = server_identity_digest(
        kind="mcp",
        transport=spec.transport,
        endpoint=spec.url,
        package={"purl": spec.package_purl, "digest": spec.package_digest} if spec.package_purl else None,
        server_info={
            "name": str(capture.server_info.get("name")) if capture.server_info else None,
            "version": str(capture.server_info.get("version")) if capture.server_info else None,
        }
        if capture.server_info
        else None,
        instructions_digest=instructions_digest,
    )
    tools: list[ToolDefinition] = []
    digest_pairs: list[tuple[str, Any]] = []
    for raw in capture.raw_tools:
        name = str(raw.get("name", ""))
        if not name:
            continue
        definition = tooldef_digest(raw)
        digest_pairs.append((name, definition))
        description = raw.get("description")
        annotations_raw = raw.get("annotations")
        annotations_claim = None
        if isinstance(annotations_raw, Mapping):
            annotations_claim = Claim.observed(
                ToolAnnotations(
                    read_only_hint=annotations_raw.get("readOnlyHint"),
                    destructive_hint=annotations_raw.get("destructiveHint"),
                    idempotent_hint=annotations_raw.get("idempotentHint"),
                    open_world_hint=annotations_raw.get("openWorldHint"),
                    title=annotations_raw.get("title"),
                ),
                collector=collector_ref,
                locator=f"live:{spec.id}:tools/list",
                observed_at=ctx.now,
            )
        tools.append(
            ToolDefinition(
                id=f"tool:{server_slug}/{name}",
                server_ref=spec.id,
                tool_name=name,
                title=raw.get("title"),
                description=description if isinstance(description, str) else None,
                input_schema=dict(raw.get("inputSchema") or {}),
                output_schema=dict(raw["outputSchema"])
                if isinstance(raw.get("outputSchema"), Mapping)
                else None,
                annotations=annotations_claim,
                digest=definition,
                full_digest=tooldef_full_digest(raw),
                description_digest=_sub_digest(description) if description is not None else None,
                input_schema_digest=_sub_digest(raw.get("inputSchema")) if "inputSchema" in raw else None,
                source=ToolSource.SERVED_LIVE,
                state=ToolState.SERVED,
                text_flags=tool_text_flags(raw),
            )
        )
    toolset = toolset_digest(
        server_digest.value if server_digest.ok else None, capture.protocol_version, digest_pairs
    )
    capture_payload = {
        "server": spec.id,
        "protocolVersion": capture.protocol_version,
        "tools": capture.raw_tools,
        "pages": capture.pages,
    }
    capture_digest = jsondoc_digest("application/vnd.symbiote.tools-list+json", capture_payload)
    if not capture_digest.ok or capture_digest.value is None:
        capture_digest_value = bytes_digest(json.dumps(capture_payload, sort_keys=True).encode())
    else:
        capture_digest_value = capture_digest.value
    evidence = Evidence(
        id="ev:" + capture_digest_value[len("sha256:") :][:12],
        evidence_kind=EvidenceKind.TOOLS_LIST_CAPTURE,
        media_type="application/vnd.symbiote.tools-list+json",
        digest=capture_digest_value,
        uri=f"live:{spec.id}",
        created=ctx.now,
    )
    evidence_ref = EvidenceRef(digest=capture_digest_value, media_type=evidence.media_type)

    def observed(value: Any, locator: str) -> Claim[Any]:
        return Claim.observed(
            value,
            collector=collector_ref,
            locator=locator,
            observed_at=ctx.now,
            evidence=[evidence_ref],
        )

    server = ToolServer(
        id=spec.id,
        name=spec.name,
        server_kind=ToolServerKind.MCP,
        digest=server_digest.value,
        transport=observed(Transport(spec.transport), f"live:{spec.id}:initialize"),
        endpoint=observed(spec.url, f"live:{spec.id}:initialize") if spec.url else None,
        env_var_names=sorted(spec.env.keys()),
        server_info=observed(
            ServerInfo(
                name=str(capture.server_info.get("name", "")) if capture.server_info else "",
                version=str(capture.server_info.get("version")) if capture.server_info else None,
                title=capture.server_info.get("title") if capture.server_info else None,
            ),
            f"live:{spec.id}:initialize",
        )
        if capture.server_info
        else None,
        protocol_version=observed(capture.protocol_version, f"live:{spec.id}:initialize")
        if capture.protocol_version
        else None,
        instructions_digest=observed(instructions_digest, f"live:{spec.id}:initialize")
        if instructions_digest
        else None,
        authentication=Claim.unknown(UnknownReason.NOT_COLLECTED, locator=f"live:{spec.id}"),
        crosses_trust_boundary=observed(spec.transport != "stdio", f"live:{spec.id}"),
        tool_list_meta=ToolListMeta(
            ttl_ms=capture.list_meta.get("ttlMs"), cache_scope=capture.list_meta.get("cacheScope")
        )
        if capture.list_meta
        else None,
        toolset_digest=observed(toolset.value, f"live:{spec.id}:tools/list") if toolset.ok else None,
        toolset_digest_result=toolset,
    )
    edges = [
        Edge(
            type=EdgeType.PROVIDES_TOOL,
            **{"from": spec.id, "to": tool.id},
            scope=EdgeScope.RUNTIME,
            assurance=AssuranceLevel.OBSERVED,
            evidence=[evidence_ref],
            first_seen=ctx.now,
            last_seen=ctx.now,
        )
        for tool in tools
    ]
    return server, tools, evidence, edges


# --------------------------------------------------------------------------------------------- collector


class McpLiveCollector(BaseCollector):
    """``mcp-live``: introspect allowlisted stdio servers and record what they actually serve."""

    name: ClassVar[str] = "mcp-live"
    version: ClassVar[str] = "0.1.0"
    surfaces: ClassVar[tuple[Surface, ...]] = (Surface.TOOLS,)
    mode: ClassVar[CollectorMode] = CollectorMode.OBSERVED

    def detect(self, ctx: CollectContext) -> bool:
        return bool(ctx.options.get("live")) and bool(ctx.options.get("live_servers"))

    def collect(self, ctx: CollectContext) -> CollectionResult:
        result = self.new_result()
        specs = [LiveServerSpec.from_mapping(raw) for raw in ctx.options.get("live_servers", [])]
        allow = {str(a) for a in ctx.options.get("live_allow", [])}
        deadline = float(ctx.options.get("live_deadline_seconds", DEFAULT_SERVER_DEADLINE))
        base_env = ctx.options.get("live_base_env")
        for spec in specs:
            source = f"live:{spec.id}"
            if spec.id not in allow and spec.name not in allow:
                result.add_source(
                    Surface.TOOLS, source, ok=False, error_class="not-allowlisted", locator=source
                )
                result.warnings.append(
                    f"{spec.id}: not on --live-allow; declared facts only (no command executed)"
                )
                continue
            if spec.transport != "stdio":
                result.add_source(
                    Surface.TOOLS, source, ok=False, error_class="unsupported-source", locator=source
                )
                result.warnings.append(
                    f"{spec.id}: transport {spec.transport!r} not supported by this version "
                    "(stdio only); recorded as a coverage gap"
                )
                continue
            try:
                capture = introspect_stdio(spec, deadline_seconds=deadline, base_env=base_env)
            except McpLiveError as exc:
                result.add_source(
                    Surface.TOOLS, source, ok=False, error_class=exc.error_class, locator=source
                )
                result.warnings.append(f"{spec.id}: {exc}")
                continue
            server, tools, evidence, edges = capture_to_entities(
                spec, capture, collector_ref=self.ref, ctx=ctx
            )
            result.entities.append(server)
            result.entities.extend(tools)
            result.evidence.append(evidence)
            result.edges.extend(edges)
            result.add_source(Surface.TOOLS, source, ok=True, items=len(tools), locator=source)
            if capture.pages >= _MAX_PAGES:
                result.set_status(Surface.TOOLS, CoverageStatus.TRUNCATED, truncated_at=len(tools))
        return result


__all__ = [
    "DEFAULT_SERVER_DEADLINE",
    "LiveCapture",
    "LiveServerSpec",
    "McpLiveCollector",
    "McpLiveError",
    "capture_to_entities",
    "introspect_stdio",
]
