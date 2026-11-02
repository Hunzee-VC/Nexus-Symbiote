"""Builders shared by the foreign-dialect adapters (cdxgen, agent-harness-aibom).

A dialect adapter translates a tool's own property vocabulary into model entities *where the semantics are
known* and leaves everything else to the verbatim passthrough. The helpers here build entities from already
normalised facts, so each adapter only owns its name table. Assurance is always ``declared`` (the facts come
from a document the owner controls, ``spec/agentbom-profile.md §5``); digests are computed only from
definition text actually present in the document (fail-closed otherwise, ADR-0004).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from symbiote.digest.tooldef import tooldef_digest
from symbiote.imp._common import (
    ImportContext,
    PropertyBag,
    as_digest,
    enum_or_none,
    hashes_sha256,
    is_url,
    parse_bool,
    parse_json,
    properties_of,
)
from symbiote.imp.native import Draft
from symbiote.model import enums as E
from symbiote.model.common import Claim, DigestResult, Provenance
from symbiote.model.entities import (
    Agent,
    Authentication,
    FrameworkRef,
    HostedIdentity,
    Instruction,
    Model,
    PackageRef,
    Serialization,
    ServerInfo,
    ToolAnnotations,
    ToolDefinition,
    ToolServer,
    WeightsIdentity,
)
from symbiote.model.ids import make_id, slugify, tool_id

_TRANSPORTS = {
    "stdio": E.Transport.STDIO,
    "sse": E.Transport.SSE,
    "http": E.Transport.STREAMABLE_HTTP,
    "streamable-http": E.Transport.STREAMABLE_HTTP,
    "streamablehttp": E.Transport.STREAMABLE_HTTP,
    "streamable_http": E.Transport.STREAMABLE_HTTP,
    "websocket": E.Transport.WEBSOCKET,
    "ws": E.Transport.WEBSOCKET,
    "in-process": E.Transport.IN_PROCESS,
    "inprocess": E.Transport.IN_PROCESS,
}
_AUTH_MODES = {
    "none": E.AuthMode.NONE,
    "oauth": E.AuthMode.OAUTH2,
    "oauth2": E.AuthMode.OAUTH2,
    "api-key": E.AuthMode.API_KEY,
    "apikey": E.AuthMode.API_KEY,
    "api_key": E.AuthMode.API_KEY,
    "bearer": E.AuthMode.API_KEY,
    "token": E.AuthMode.API_KEY,
    "mtls": E.AuthMode.MTLS,
    "obo": E.AuthMode.OBO_TOKEN,
    "obo-token": E.AuthMode.OBO_TOKEN,
}
_LAUNCHERS = {
    "npx": E.Launcher.NPX,
    "uvx": E.Launcher.UVX,
    "docker": E.Launcher.DOCKER,
    "dnx": E.Launcher.DNX,
}
_FORMATS = {
    "safetensors": E.SerializationFormat.SAFETENSORS,
    "onnx": E.SerializationFormat.ONNX,
    "gguf": E.SerializationFormat.GGUF,
    "pickle": E.SerializationFormat.PICKLE,
    "pkl": E.SerializationFormat.PICKLE,
    "pt": E.SerializationFormat.TORCH_ZIP,
    "pth": E.SerializationFormat.TORCH_ZIP,
    "torch": E.SerializationFormat.TORCH_ZIP,
    "pytorch": E.SerializationFormat.TORCH_ZIP,
    "bin": E.SerializationFormat.TORCH_ZIP,
    "savedmodel": E.SerializationFormat.TF_SAVEDMODEL,
    "h5": E.SerializationFormat.KERAS_H5,
    "keras": E.SerializationFormat.KERAS_H5,
    "joblib": E.SerializationFormat.JOBLIB,
    "npz": E.SerializationFormat.NPZ,
}
_RISKY_FORMATS = {
    E.SerializationFormat.PICKLE,
    E.SerializationFormat.TORCH_ZIP,
    E.SerializationFormat.JOBLIB,
    E.SerializationFormat.KERAS_H5,
}


def split_list(value: str | None) -> list[str]:
    """``"a, b"`` / ``'["a","b"]'`` / newline-separated → list of non-empty strings."""
    if not value:
        return []
    parsed = parse_json(value)
    if isinstance(parsed, list):
        return [str(v) for v in parsed if v not in (None, "")]
    sep = "\n" if "\n" in value else ","
    return [v.strip() for v in value.split(sep) if v.strip()]


def names_only(values: list[str]) -> list[str]:
    """Env-var / header entries reduced to their names (``NAME=value`` never keeps the value)."""
    out = []
    for v in values:
        name = v.split("=", 1)[0].split(":", 1)[0].strip()
        if name and name not in out:
            out.append(name)
    return out


def transport_of(value: str | None, *, command: str | None, url: str | None) -> Claim[E.Transport]:
    if value and value.strip().lower() in _TRANSPORTS:
        return Claim(value=_TRANSPORTS[value.strip().lower()])
    if command:
        return Claim(value=E.Transport.STDIO)
    if url:
        return Claim(
            value=E.Transport.SSE if url.rstrip("/").endswith("/sse") else E.Transport.STREAMABLE_HTTP
        )
    return Claim.unknown(E.UnknownReason.NOT_COLLECTED)


def auth_of(value: str | None, *, transport: Claim[E.Transport]) -> Claim[Authentication]:
    if value and value.strip().lower() in _AUTH_MODES:
        return Claim(value=Authentication(mode=_AUTH_MODES[value.strip().lower()]))
    if value:
        return Claim(value=Authentication(mode=E.AuthMode.OTHER))
    if transport.value is E.Transport.STDIO:
        return Claim(value=Authentication(mode=E.AuthMode.NONE))
    return Claim.unknown(E.UnknownReason.NOT_COLLECTED)


def trust_zone_of(transport: Claim[E.Transport], url: str | None) -> tuple[E.TrustZone, Claim[bool]]:
    if transport.value is E.Transport.STDIO or transport.value is E.Transport.IN_PROCESS:
        return E.TrustZone.LOCAL_PROCESS, Claim(value=False)
    if url and ("localhost" in url or "127.0.0.1" in url or "[::1]" in url):
        return E.TrustZone.LOOPBACK, Claim(value=False)
    if url:
        return E.TrustZone.EXTERNAL, Claim(value=True)
    return E.TrustZone.UNKNOWN, Claim.unknown(E.UnknownReason.NOT_COLLECTED)


def declared(locator: str | None, collector: str | None = None) -> Provenance:
    return Provenance(
        assurance=E.AssuranceLevel.DECLARED, method=E.ClaimMethod.CONFIG, locator=locator, collector=collector
    )


class AdapterBase:
    """State and builders common to the foreign-dialect adapters."""

    name: str = "generic"
    default_kind: E.SnapshotKind = E.SnapshotKind.DECLARED
    prefixes: tuple[str, ...] = ()

    def __init__(self) -> None:
        self.servers_by_name: dict[str, str] = {}
        self.collector_ref: str | None = None

    # ---- element iteration

    @staticmethod
    def elements(doc: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
        """``(where, element)`` for every top-level component and service (``where`` is ``component``/``service``)."""
        out: list[tuple[str, Mapping[str, Any]]] = []
        for c in doc.get("components") or []:
            if isinstance(c, Mapping):
                out.append(("component", c))
        for s in doc.get("services") or []:
            if isinstance(s, Mapping):
                out.append(("service", s))
        return out

    def bag(self, element: Mapping[str, Any]) -> PropertyBag:
        return PropertyBag(properties_of(element))

    def finish(self, ctx: ImportContext, bag: PropertyBag, entity_id: str, path: str) -> dict[str, str]:
        return ctx.preserve_remaining(entity_id, bag, path=path)

    # ---- builders

    def server(
        self,
        ctx: ImportContext,
        draft: Draft,
        element: Mapping[str, Any],
        bag: PropertyBag,
        *,
        name: str,
        client: str | None,
        transport_raw: str | None,
        command: str | None,
        url: str | None,
        auth_raw: str | None,
        env_names: list[str],
        header_names: list[str],
        pinning: str | None,
        locator: str | None,
        server_version: str | None = None,
        protocol_version: str | None = None,
        kind: E.ToolServerKind = E.ToolServerKind.MCP,
        tags: list[str] | None = None,
    ) -> ToolServer:
        bom_ref = str(element.get("bom-ref") or "")
        sid = make_id("server", f"{client}-{name}" if client else name)
        taken = draft.ids()
        if sid in taken:
            sid = make_id("server", f"{client}-{name}" if client else name, collision_seed=bom_ref or name)
        transport = transport_of(transport_raw, command=command, url=url)
        auth = auth_of(auth_raw, transport=transport)
        zone, crosses = trust_zone_of(transport, url)
        purl = str(element["purl"]) if element.get("purl") else None
        package = None
        if purl or pinning or (command and command.split("/")[-1] in _LAUNCHERS):
            floating = pinning is None or pinning.strip().lower() not in ("pinned", "true", "yes")
            if pinning is None and purl and ("@" in purl.rsplit("/", 1)[-1]):
                floating = False
            package = Claim(
                value=PackageRef(
                    purl=purl,
                    digest=hashes_sha256(element),
                    floating=floating,
                    launcher=_LAUNCHERS.get((command or "").split("/")[-1], E.Launcher.OTHER),
                )
            )
        server_info = Claim(value=ServerInfo(name=name, version=server_version)) if server_version else None
        server = ToolServer(
            id=sid,
            name=name,
            description=element.get("description") if isinstance(element.get("description"), str) else None,
            provenance=declared(locator, self.collector_ref),
            tags=tags or [],
            server_kind=kind,
            client=client,
            transport=transport,
            endpoint=Claim(value=url) if url else None,
            package=package,
            command=command,
            env_var_names=names_only(env_names),
            header_names=names_only(header_names),
            server_info=server_info,
            protocol_version=Claim(value=protocol_version) if protocol_version else None,
            authentication=auth,
            trust_zone=zone,
            crosses_trust_boundary=crosses,
            foreign=self.finish(ctx, bag, sid, f"/toolServers/{sid}"),
        )
        draft.add(server, bom_ref=bom_ref or None)
        self.servers_by_name[name] = sid
        self.servers_by_name[bom_ref] = sid
        return server

    def tool(
        self,
        ctx: ImportContext,
        draft: Draft,
        element: Mapping[str, Any] | None,
        bag: PropertyBag | None,
        *,
        tool_name: str,
        server_id: str,
        description: str | None,
        input_schema: dict[str, Any] | None,
        annotations_raw: Any,
        locator: str | None,
    ) -> ToolDefinition:
        bom_ref = str(element.get("bom-ref") or "") if element is not None else ""
        tid = tool_id(server_id, tool_name)
        if draft.has(tid):
            tid = tool_id(server_id, f"{tool_name}-{slugify(bom_ref or description or 'dup')[:8]}")
        payload: dict[str, Any] = {"name": tool_name}
        if description is not None:
            payload["description"] = description
        if isinstance(input_schema, dict):
            payload["inputSchema"] = input_schema
            digest = tooldef_digest(payload)
        else:
            digest = DigestResult(
                algorithm="tooldef/v1",
                status=E.DigestStatus.UNDIGESTABLE,
                reason="tool definition text not carried by the source document",
            )
            ctx.lose(
                f"/tools/{tid}/digest",
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.DROPPED,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=tid,
                field_name="digest",
            )
        annotations = None
        ann = parse_json(annotations_raw) if isinstance(annotations_raw, str) else annotations_raw
        if isinstance(ann, Mapping):
            annotations = Claim(
                value=ToolAnnotations(
                    title=ann.get("title") if isinstance(ann.get("title"), str) else None,
                    read_only_hint=parse_bool(ann.get("readOnlyHint", ann.get("readOnly"))),
                    destructive_hint=parse_bool(ann.get("destructiveHint", ann.get("destructive"))),
                    idempotent_hint=parse_bool(ann.get("idempotentHint", ann.get("idempotent"))),
                    open_world_hint=parse_bool(ann.get("openWorldHint", ann.get("openWorld"))),
                )
            )
        tool = ToolDefinition(
            id=tid,
            description=description,
            provenance=declared(locator, self.collector_ref),
            server_ref=server_id,
            tool_name=tool_name,
            input_schema=input_schema if isinstance(input_schema, dict) else {},
            annotations=annotations,
            digest=digest,
            source=E.ToolSource.DECLARED_CONFIG,
            foreign=self.finish(ctx, bag, tid, f"/tools/{tid}") if bag is not None else {},
        )
        draft.add(tool, bom_ref=bom_ref or None)
        return tool

    def model(
        self,
        ctx: ImportContext,
        draft: Draft,
        element: Mapping[str, Any],
        bag: PropertyBag,
        *,
        name: str,
        provider: str | None,
        requested_ref: str | None,
        endpoint: str | None,
        formats_raw: list[str],
        unsafe_deserialization: str | None,
        locator: str | None,
    ) -> Model:
        bom_ref = str(element.get("bom-ref") or "")
        mid = make_id("model", name)
        if draft.has(mid):
            mid = make_id("model", name, collision_seed=bom_ref or name)
        manifest_root = hashes_sha256(element)
        purl = str(element["purl"]) if element.get("purl") else None
        formats = [f for f in (_FORMATS.get(v.strip().lower().lstrip(".")) for v in formats_raw) if f]
        hosted = None
        weights = None
        if manifest_root or (
            purl and purl.startswith(("pkg:huggingface", "pkg:oci", "pkg:mlflow", "pkg:generic"))
        ):
            kind = E.ModelKind.WEIGHTS
            if manifest_root:
                weights = Claim(
                    value=WeightsIdentity(
                        purl=purl, manifest_root=manifest_root, file_count=0, formats=formats
                    )
                )
            else:
                weights = Claim.unknown(E.UnknownReason.NOT_COLLECTED)
        else:
            kind = E.ModelKind.HOSTED
            version = str(element["version"]) if element.get("version") else None
            hosted = Claim(
                value=HostedIdentity(
                    provider=provider or "unknown",
                    endpoint_origin=endpoint,
                    requested_ref=requested_ref or name,
                    resolved_ref=Claim(value=version)
                    if version
                    else Claim.unknown(E.UnknownReason.NOT_COLLECTED),
                    alias_pinning=E.AliasPinning.UNKNOWN,
                )
            )
        serialization = None
        unsafe = parse_bool(unsafe_deserialization)
        if formats or unsafe is not None:
            risky = unsafe is True or any(f in _RISKY_FORMATS for f in formats)
            serialization = Claim(
                value=Serialization(
                    formats=formats,
                    risk_class=E.SerializationRisk.CODE_EXEC_ON_LOAD if risky else E.SerializationRisk.NONE,
                )
            )
        model = Model(
            id=mid,
            name=name,
            description=element.get("description") if isinstance(element.get("description"), str) else None,
            provenance=declared(locator, self.collector_ref),
            model_kind=kind,
            weights=weights,
            hosted=hosted,
            serialization=serialization,
            foreign=self.finish(ctx, bag, mid, f"/models/{mid}"),
        )
        draft.add(model, bom_ref=bom_ref or None)
        return model

    def instruction(
        self,
        ctx: ImportContext,
        draft: Draft,
        element: Mapping[str, Any],
        bag: PropertyBag,
        *,
        kind: E.InstructionKind,
        path: str | None,
        precedence: int,
        locator: str | None,
        tags: list[str] | None = None,
    ) -> Instruction | None:
        bom_ref = str(element.get("bom-ref") or "")
        digest = hashes_sha256(element)
        label = path or str(element.get("name") or bom_ref or "instruction")
        iid = make_id("instr", label)
        if draft.has(iid):
            iid = make_id("instr", label, collision_seed=bom_ref or label)
        if digest is None:
            ctx.lose(
                f"/instructions/{iid}",
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.DROPPED,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=iid,
                field_name="digest",
            )
            return None
        instr = Instruction(
            id=iid,
            name=str(element["name"]) if element.get("name") else None,
            provenance=declared(locator, self.collector_ref),
            tags=tags or [],
            instruction_kind=kind,
            path=None if is_url(path) else path,
            uri=path if is_url(path) else None,
            media_type=str(element.get("mime-type") or "text/markdown"),
            size=0,
            digest=digest,
            precedence=precedence,
            foreign=self.finish(ctx, bag, iid, f"/instructions/{iid}"),
        )
        draft.add(instr, bom_ref=bom_ref or None)
        return instr

    def sub_agent(
        self,
        ctx: ImportContext,
        draft: Draft,
        element: Mapping[str, Any],
        bag: PropertyBag,
        *,
        framework: str | None,
        framework_version: str | None,
        role: E.AgentRole,
        parent: str | None,
        locator: str | None,
    ) -> Agent:
        bom_ref = str(element.get("bom-ref") or "")
        name = str(element.get("name") or bom_ref or "agent")
        aid = make_id("agent", name)
        if draft.has(aid):
            aid = make_id("agent", name, collision_seed=bom_ref or name)
        agent = Agent(
            id=aid,
            name=name,
            provenance=declared(locator, self.collector_ref),
            version=str(element.get("version") or "unknown"),
            role=role,
            purpose=element.get("description") if isinstance(element.get("description"), str) else None,
            framework=Claim(value=FrameworkRef(name=framework, version=framework_version))
            if framework
            else None,
            parent_ref=parent,
            foreign=self.finish(ctx, bag, aid, f"/agents/{aid}"),
        )
        draft.add(agent, bom_ref=bom_ref or None)
        return agent

    @staticmethod
    def json_or_text(value: str | None) -> Any:
        if value is None:
            return None
        parsed = parse_json(value)
        return parsed if parsed is not None else value

    @staticmethod
    def digest_of(value: str | None) -> str | None:
        return as_digest(value)

    @staticmethod
    def dumps(value: Any) -> str:
        return json.dumps(value, sort_keys=True)

    @staticmethod
    def enum(enum_cls: Any, value: Any) -> Any:
        return enum_or_none(enum_cls, value)


__all__ = [
    "AdapterBase",
    "auth_of",
    "declared",
    "names_only",
    "split_list",
    "transport_of",
    "trust_zone_of",
]
