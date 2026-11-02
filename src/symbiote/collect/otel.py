"""OTel GenAI trace collector: what the agent *actually did* (``spec/collectors.md`` row ``otel-traces``).

Reads OTLP/JSON documents (``resourceSpans``) and JSONL span files offline — no exporter, no
network. GenAI semantic-convention attributes become observed entities and edges:

* ``execute_tool`` spans → ``ToolDefinition(state=invoked)`` + ``invokesTool`` edges with counts
  and first/last-seen; ``gen_ai.tool.definitions`` (when the instrumentation captures served
  definitions) yields wire-exact ``tooldef/v1`` digests.
* ``chat``/``embeddings`` spans → hosted ``Model`` entities + ``usesModel`` edges; a response
  model differing from the requested model is recorded in the trace summary (alias routing —
  ``symbiote diff`` turns it into ``model-routed`` against the declared snapshot).
* ``invoke_agent``/``create_agent`` spans → sub-agent entities + ``spawns`` edges.
* ``gen_ai.data_source.id`` / ``gen_ai.memory.store.id`` → observed ``DataSource``s with edges.
* ``gen_ai.system_instructions`` values are hashed and sized, never stored (``Instruction``).

Resource attributes ``agentbom.snapshot.digest`` and ``agentbom.deployment.id`` are carried into
the trace summary so a delta can cite the snapshot that was active.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from symbiote.collect.base import BaseCollector, CollectContext, CollectionResult
from symbiote.digest import bytes_digest, jsondoc_digest, tooldef_digest
from symbiote.model.common import Claim, DigestResult, EvidenceRef
from symbiote.model.edges import Edge
from symbiote.model.entities import (
    Agent,
    DataSource,
    Evidence,
    HostedIdentity,
    Instruction,
    Model,
    ToolDefinition,
    ToolServer,
)
from symbiote.model.enums import (
    AgentRole,
    AssuranceLevel,
    CollectorMode,
    DataSourceKind,
    DigestStatus,
    EdgeScope,
    EdgeType,
    EvidenceKind,
    InstructionKind,
    ModelKind,
    Surface,
    ToolSource,
    ToolState,
    UnknownReason,
)
from symbiote.model.ids import evidence_id, make_id, tool_id

_NS = 1_000_000_000
# Clamp span timestamps to a sane epoch-nanosecond window: a hostile export must
# not crash aggregation or datetime conversion with astronomical values.
_MAX_TIME_NS = 4_102_444_800 * _NS  # 2100-01-01


def _safe_ns(value: Any) -> int | None:
    try:
        ns = int(value)
    except (TypeError, ValueError):
        return None
    if 0 < ns <= _MAX_TIME_NS:
        return ns
    return None


def _decode_value(value: Any) -> Any:
    if not isinstance(value, Mapping):
        return value
    for key in ("stringValue", "boolValue", "doubleValue"):
        if key in value:
            return value[key]
    if "intValue" in value:
        try:
            return int(value["intValue"])
        except (TypeError, ValueError):
            return value["intValue"]
    if "arrayValue" in value and isinstance(value["arrayValue"], Mapping):
        return [_decode_value(v) for v in value["arrayValue"].get("values", [])]
    return value


def _decode_attributes(raw: Any) -> dict[str, Any]:
    if isinstance(raw, Mapping):  # already flat (JSONL convenience form)
        return dict(raw)
    attrs: dict[str, Any] = {}
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, Mapping) and "key" in item:
                attrs[str(item["key"])] = _decode_value(item.get("value"))
    return attrs


@dataclass(slots=True)
class SpanFacts:
    name: str
    attributes: dict[str, Any]
    resource: dict[str, Any]
    start_ns: int | None = None
    end_ns: int | None = None

    def time(self, ns: int | None) -> datetime | None:
        return datetime.fromtimestamp(ns / _NS, tz=UTC) if ns else None


def iter_spans(payload: Any) -> Iterator[SpanFacts]:
    """Yield spans from an OTLP/JSON document or a single flat span object."""
    if isinstance(payload, Mapping) and "resourceSpans" in payload:
        for rs in payload.get("resourceSpans", []):
            resource = _decode_attributes(rs.get("resource", {}).get("attributes", []))
            for scope in rs.get("scopeSpans", []) or rs.get("instrumentationLibrarySpans", []):
                for span in scope.get("spans", []):
                    yield SpanFacts(
                        name=str(span.get("name", "")),
                        attributes=_decode_attributes(span.get("attributes", [])),
                        resource=resource,
                        start_ns=_safe_ns(span.get("startTimeUnixNano")),
                        end_ns=_safe_ns(span.get("endTimeUnixNano")),
                    )
        return
    if isinstance(payload, Mapping):
        yield SpanFacts(
            name=str(payload.get("name", "")),
            attributes=_decode_attributes(payload.get("attributes", {})),
            resource=_decode_attributes(payload.get("resource", {})),
            start_ns=_safe_ns(payload.get("startTimeUnixNano")),
            end_ns=_safe_ns(payload.get("endTimeUnixNano")),
        )


def read_span_file(path: Path) -> Iterator[SpanFacts]:
    with path.open("rb") as source:
        limit = 16 * 1024 * 1024
        raw = source.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("OTel trace exceeds 16 MiB per source")
    text = raw.decode("utf-8")
    stripped = text.lstrip()
    if stripped.startswith("{") and '"resourceSpans"' in stripped[:2000]:
        yield from iter_spans(json.loads(text))
        return
    for raw_line in text.splitlines():
        stripped_line = raw_line.strip()
        if not stripped_line:
            continue
        yield from iter_spans(json.loads(stripped_line))


@dataclass(slots=True)
class _ToolAgg:
    count: int = 0
    first_ns: int | None = None
    last_ns: int | None = None
    raw_definition: Mapping[str, Any] | None = None
    definition_conflict: bool = False


@dataclass(slots=True)
class _Aggregate:
    tools: dict[str, _ToolAgg] = field(default_factory=dict)
    models: dict[tuple[str, str], set[str]] = field(
        default_factory=dict
    )  # (provider, requested) -> responses
    agents: dict[str, str] = field(default_factory=dict)  # agent id attr -> display name
    data_sources: set[str] = field(default_factory=set)
    memory_stores: set[str] = field(default_factory=set)
    system_instruction_hashes: dict[str, int] = field(default_factory=dict)
    snapshot_digests: set[str] = field(default_factory=set)
    deployment_ids: set[str] = field(default_factory=set)
    window: tuple[int | None, int | None] = (None, None)
    spans: int = 0

    def observe_window(self, start: int | None, end: int | None) -> None:
        lo, hi = self.window
        if start is not None:
            lo = start if lo is None else min(lo, start)
        if end is not None:
            hi = end if hi is None else max(hi, end)
        self.window = (lo, hi)


def aggregate(spans: Iterable[SpanFacts]) -> _Aggregate:
    agg = _Aggregate()
    for span in spans:
        agg.spans += 1
        attrs = span.attributes
        agg.observe_window(span.start_ns, span.end_ns)
        if digest := span.resource.get("agentbom.snapshot.digest"):
            agg.snapshot_digests.add(str(digest))
        if dep := span.resource.get("agentbom.deployment.id"):
            agg.deployment_ids.add(str(dep))
        operation = str(attrs.get("gen_ai.operation.name", ""))
        if operation == "execute_tool" or attrs.get("gen_ai.tool.name"):
            name = str(attrs.get("gen_ai.tool.name", "")).strip()
            if name:
                entry = agg.tools.setdefault(name, _ToolAgg())
                entry.count += 1
                if span.start_ns is not None:
                    entry.first_ns = (
                        span.start_ns if entry.first_ns is None else min(entry.first_ns, span.start_ns)
                    )
                if span.end_ns is not None:
                    entry.last_ns = span.end_ns if entry.last_ns is None else max(entry.last_ns, span.end_ns)
                definitions = attrs.get("gen_ai.tool.definitions")
                if isinstance(definitions, str):
                    try:
                        parsed = json.loads(definitions)
                    except ValueError:
                        parsed = None
                    if isinstance(parsed, list):
                        for raw in parsed:
                            if isinstance(raw, Mapping) and raw.get("name") == name:
                                if entry.raw_definition is not None and entry.raw_definition != raw:
                                    entry.definition_conflict = True
                                entry.raw_definition = raw
        if operation in ("chat", "embeddings", "generate_content", "text_completion"):
            provider = str(attrs.get("gen_ai.provider.name") or attrs.get("gen_ai.system") or "unknown")
            requested = str(attrs.get("gen_ai.request.model", "")).strip()
            if requested:
                responses = agg.models.setdefault((provider, requested), set())
                response = str(attrs.get("gen_ai.response.model", "")).strip()
                if response:
                    responses.add(response)
        if operation in ("invoke_agent", "create_agent"):
            agent_key = str(attrs.get("gen_ai.agent.id") or attrs.get("gen_ai.agent.name") or "").strip()
            if agent_key:
                agg.agents[agent_key] = str(attrs.get("gen_ai.agent.name") or agent_key)
        if source_id := attrs.get("gen_ai.data_source.id"):
            agg.data_sources.add(str(source_id))
        if store_id := attrs.get("gen_ai.memory.store.id"):
            agg.memory_stores.add(str(store_id))
        if instructions := attrs.get("gen_ai.system_instructions"):
            raw = str(instructions).encode("utf-8")
            agg.system_instruction_hashes[bytes_digest(raw)] = len(raw)
    return agg


class OtelTracesCollector(BaseCollector):
    """``otel-traces``: observed snapshot inputs from GenAI semantic-convention span files."""

    name: ClassVar[str] = "otel-traces"
    version: ClassVar[str] = "0.1.0"
    surfaces: ClassVar[tuple[Surface, ...]] = (Surface.RUNTIME,)
    mode: ClassVar[CollectorMode] = CollectorMode.OBSERVED

    def detect(self, ctx: CollectContext) -> bool:
        return bool(ctx.options.get("otel_files"))

    def collect(self, ctx: CollectContext) -> CollectionResult:
        result = self.new_result()
        # Scope is selected by the operator for ctx.agent_id, independently of trace contents.
        scope = ctx.options.get("otel_scope")
        fields = ("agentbom.tenant.id", "agentbom.deployment.id", "agentbom.snapshot.digest")
        if (
            not isinstance(scope, Mapping)
            or not all(isinstance(scope.get(k), str) and scope[k] for k in fields)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", scope[fields[2]])
        ):
            result.add_source(Surface.RUNTIME, "otel", ok=False, error_class="unbound-scope")
            result.warnings.append(
                "OTel attribution requires a trusted tenant, deployment and snapshot selector"
            )
            return result
        selected = {k: scope[k] for k in fields}
        for raw_path in dict.fromkeys(ctx.options.get("otel_files", [])):
            path = Path(raw_path)
            source = ctx.display(path)
            groups: dict[str, list[SpanFacts]] = {}
            skipped = 0
            try:
                for span in read_span_file(path):
                    if any(span.resource.get(k) != v for k, v in selected.items()):
                        skipped += 1
                        continue
                    identity = str(
                        span.attributes.get("mcp.server.id") or span.resource.get("service.instance.id") or ""
                    )
                    groups.setdefault(identity, []).append(span)
            except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError) as exc:
                result.add_source(
                    Surface.RUNTIME, source, ok=False, error_class="unsupported-source", locator=source
                )
                result.warnings.append(f"{source}: {type(exc).__name__}")
                continue
            for identity, spans in sorted(groups.items()):
                annotations = {**selected, "traceSource": source, "sourceInstance": identity}
                self._emit(
                    ctx,
                    result,
                    aggregate(spans),
                    annotations,
                    hashlib.sha256(
                        json.dumps([asdict(span) for span in spans], sort_keys=True).encode()
                    ).hexdigest(),
                )
            if skipped:
                result.add_source(Surface.RUNTIME, source, ok=False, error_class="scope-mismatch")
                result.warnings.append(f"{source}: omitted {skipped} spans outside the selected scope")
            if groups or not skipped:
                result.add_source(
                    Surface.RUNTIME, source, items=sum(len(v) for v in groups.values()), locator=source
                )
        return result

    # ------------------------------------------------------------------ shaping

    def _emit(
        self,
        ctx: CollectContext,
        result: CollectionResult,
        agg: _Aggregate,
        attribution: dict[str, str],
        span_digest: str,
    ) -> None:
        scope_id = hashlib.sha256(json.dumps(attribution, sort_keys=True).encode()).hexdigest()
        server_id = make_id("server", "observed", scope_id)
        summary = {
            "scope": attribution,
            "spanDigest": "sha256:" + span_digest,
            "spans": agg.spans,
            "tools": {
                name: {"count": entry.count, "definitionCaptured": entry.raw_definition is not None}
                for name, entry in sorted(agg.tools.items())
            },
            "models": {
                f"{provider}/{requested}": sorted(responses)
                for (provider, requested), responses in sorted(agg.models.items())
            },
            "aliasRouting": sorted(
                f"{provider}/{requested}->{response}"
                for (provider, requested), responses in agg.models.items()
                for response in responses
                if response and response != requested
            ),
            "snapshotDigests": sorted(agg.snapshot_digests),
            "deploymentIds": sorted(agg.deployment_ids),
            "windowNs": list(agg.window),
        }
        digest = jsondoc_digest("application/vnd.symbiote.trace-summary+json", summary)
        digest_value = (
            digest.value
            if digest.ok and digest.value
            else bytes_digest(json.dumps(summary, sort_keys=True).encode())
        )
        evidence = Evidence(
            id=evidence_id(digest_value),
            evidence_kind=EvidenceKind.TRACE_SUMMARY,
            media_type="application/vnd.symbiote.trace-summary+json",
            digest=digest_value,
            created=ctx.now,
        )
        if agg.spans:
            result.evidence.append(evidence)
        ref = EvidenceRef(digest=digest_value, media_type=evidence.media_type)

        def seen(ns: int | None) -> datetime | None:
            return datetime.fromtimestamp(ns / _NS, tz=UTC) if ns else None

        if agg.tools:
            result.entities.append(_observed_stub_server(server_id))
        for name, entry in sorted(agg.tools.items()):
            if entry.raw_definition is not None and not entry.definition_conflict:
                definition = tooldef_digest(entry.raw_definition)
                schema = dict(entry.raw_definition.get("inputSchema") or {})
                description = entry.raw_definition.get("description")
            else:
                definition = DigestResult(
                    algorithm="tooldef/v1",
                    status=DigestStatus.UNDIGESTABLE,
                    reason="conflicting tool definitions"
                    if entry.definition_conflict
                    else "not-observed: the span carried no tool definition",
                )
                schema = {}
                description = None
            tool = ToolDefinition(
                id=tool_id(server_id, name),
                server_ref=server_id,
                tool_name=name,
                description=description if ctx.include_text and isinstance(description, str) else None,
                input_schema=schema,
                digest=definition,
                source=ToolSource.TRACE,
                state=ToolState.INVOKED,
                invocation_count=entry.count,
                first_seen=seen(entry.first_ns),
                last_seen=seen(entry.last_ns),
            )
            result.entities.append(tool)
            result.edges.append(
                Edge(
                    type=EdgeType.INVOKES_TOOL,
                    **{"from": ctx.agent_id, "to": tool.id},
                    scope=EdgeScope.RUNTIME,
                    qualifiers=attribution,
                    assurance=AssuranceLevel.OBSERVED,
                    evidence=[ref],
                    observed_count=entry.count,
                    first_seen=seen(entry.first_ns),
                    last_seen=seen(entry.last_ns),
                )
            )
        for (provider, requested), responses in sorted(agg.models.items()):
            resolved = sorted(r for r in responses if r)
            model = Model(
                id=make_id("model", f"{provider}-{requested}", scope_id),
                model_kind=ModelKind.HOSTED,
                hosted=Claim.observed(
                    HostedIdentity(
                        provider=provider,
                        requested_ref=requested,
                        resolved_ref=Claim.observed(
                            resolved[0], collector=self.ref, observed_at=ctx.now, evidence=[ref]
                        )
                        if len(resolved) == 1
                        else Claim.unknown(UnknownReason.PROVIDER_UNDISCLOSED),
                    ),
                    collector=self.ref,
                    observed_at=ctx.now,
                    evidence=[ref],
                    locator="otel:gen_ai.request.model",
                ),
            )
            result.entities.append(model)
            result.edges.append(
                Edge(
                    type=EdgeType.USES_MODEL,
                    **{"from": ctx.agent_id, "to": model.id},
                    scope=EdgeScope.RUNTIME,
                    qualifiers=attribution,
                    assurance=AssuranceLevel.OBSERVED,
                    evidence=[ref],
                )
            )
        for agent_key, display in sorted(agg.agents.items()):
            sub = Agent(
                id=make_id("agent", agent_key, scope_id),
                name=display,
                version="observed",
                role=AgentRole.SUB_AGENT,
            )
            result.entities.append(sub)
            result.edges.append(
                Edge(
                    type=EdgeType.SPAWNS,
                    **{"from": ctx.agent_id, "to": sub.id},
                    scope=EdgeScope.RUNTIME,
                    qualifiers=attribution,
                    assurance=AssuranceLevel.OBSERVED,
                    evidence=[ref],
                )
            )
        for source_id in sorted(agg.data_sources):
            ds = DataSource(
                id=make_id("data", source_id, scope_id),
                data_kind=DataSourceKind.RETRIEVAL_CONNECTOR,
                instruction_bearing=Claim.unknown(UnknownReason.NOT_COLLECTED),
                live=True,
            )
            result.entities.append(ds)
            result.edges.append(
                Edge(
                    type=EdgeType.READS_CONTEXT_FROM,
                    **{"from": ctx.agent_id, "to": ds.id},
                    scope=EdgeScope.RUNTIME,
                    qualifiers=attribution,
                    assurance=AssuranceLevel.OBSERVED,
                    evidence=[ref],
                )
            )
        for store_id in sorted(agg.memory_stores):
            store = DataSource(
                id=make_id("data", f"memory-{store_id}", scope_id),
                data_kind=DataSourceKind.MEMORY_STORE,
                instruction_bearing=Claim.unknown(UnknownReason.NOT_COLLECTED),
            )
            result.entities.append(store)
            result.edges.append(
                Edge(
                    type=EdgeType.READS_MEMORY_FROM,
                    **{"from": ctx.agent_id, "to": store.id},
                    scope=EdgeScope.RUNTIME,
                    qualifiers=attribution,
                    assurance=AssuranceLevel.OBSERVED,
                    evidence=[ref],
                )
            )
        for instruction_digest, size in sorted(agg.system_instruction_hashes.items()):
            result.entities.append(
                Instruction(
                    id="instr:otel-" + instruction_digest[len("sha256:") :][:12],
                    instruction_kind=InstructionKind.SYSTEM_PROMPT,
                    uri="otel:gen_ai.system_instructions",
                    media_type="text/plain",
                    size=size,
                    digest=instruction_digest,
                )
            )


__all__ = ["OtelTracesCollector", "SpanFacts", "aggregate", "iter_spans", "read_span_file"]


def _observed_stub_server(server_id: str) -> ToolServer:
    """Placeholder server entity for trace-only tools whose serving server is unknown."""
    from symbiote.model.enums import ToolServerKind

    return ToolServer(
        id=server_id,
        name="observed-from-traces",
        server_kind=ToolServerKind.BUILTIN,
        transport=Claim.unknown(UnknownReason.NOT_COLLECTED),
        authentication=Claim.unknown(UnknownReason.NOT_COLLECTED),
        crosses_trust_boundary=Claim.unknown(UnknownReason.NOT_COLLECTED),
    )
