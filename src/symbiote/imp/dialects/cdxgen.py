"""cdxgen AI-BOM dialect (``cdx:mcp:*``, ``cdx:agent:*``, ``cdx:agentic:*``, ``cdx:ai:*``, ``cdx:mcpb:*``, ``cdx:gguf:*``).

cdxgen documents its agentic vocabulary in ``docs/CUSTOM_PROPERTIES.md`` (names such as ``cdx:mcp:transport``,
``cdx:mcp:pinning``, ``cdx:mcp:authMode``, ``cdx:mcp:toolAnnotations``, ``cdx:ai:toolSchema``,
``cdx:ai:unsafeDeserialization``, ``cdx:agent:permission``, ``cdx:agent:tools``). The adapter maps the names
whose semantics are known — listed in :data:`SERVER_KEYS`, :data:`TOOL_KEYS`, :data:`MODEL_KEYS` and
:data:`AGENT_KEYS` (matched case-insensitively on the segment after the namespace, dashes and underscores
ignored) — and preserves every other ``cdx:*`` property verbatim. Tool digests are computed only when the
document carries the definition text (``cdx:ai:toolSchema`` / ``cdx:mcp:tool:inputSchema``); a tool that is
only named stays ``undigestable`` (fail-closed) rather than receiving a guessed digest.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from symbiote.imp._common import ImportContext, PropertyBag, parse_json
from symbiote.imp.dialects._base import AdapterBase, declared, split_list
from symbiote.imp.native import Draft
from symbiote.model import enums as E
from symbiote.model.common import Claim
from symbiote.model.entities import Agent, Authentication, FrameworkRef, ToolServer
from symbiote.model.ids import make_id

PREFIXES = ("cdx:mcp:", "cdx:agent:", "cdx:agentic:", "cdx:ai:", "cdx:mcpb:", "cdx:gguf:")

#: Accepted server-level names (normalised: lowercase, no dashes/underscores) → model field.
SERVER_KEYS: dict[str, str] = {
    "transport": "transport",
    "command": "command",
    "url": "url",
    "endpoint": "url",
    "serverurl": "url",
    "authmode": "auth",
    "auth": "auth",
    "authentication": "auth",
    "pinning": "pinning",
    "pinned": "pinning",
    "env": "env",
    "envvars": "env",
    "environment": "env",
    "headers": "headers",
    "client": "client",
    "host": "client",
    "configfile": "locator",
    "config": "locator",
    "source": "locator",
    "sourcefile": "locator",
    "servername": "server_name",
    "name": "server_name",
    "serverversion": "server_version",
    "version": "server_version",
    "protocolversion": "protocol_version",
    "tools": "tools",
    "toolnames": "tools",
}
#: Accepted tool-level names.
TOOL_KEYS: dict[str, str] = {
    "toolname": "tool_name",
    "tool:name": "tool_name",
    "tool": "tool_name",
    "server": "server",
    "tool:server": "server",
    "toolserver": "server",
    "tool:description": "description",
    "tooldescription": "description",
    "toolschema": "schema",
    "tool:inputschema": "schema",
    "tool:schema": "schema",
    "inputschema": "schema",
    "toolannotations": "annotations",
    "tool:annotations": "annotations",
}
#: Accepted model-level names (``cdx:ai:*`` and ``cdx:gguf:*``).
MODEL_KEYS: dict[str, str] = {
    "provider": "provider",
    "modelprovider": "provider",
    "model": "requested_ref",
    "modelname": "requested_ref",
    "modelid": "requested_ref",
    "endpoint": "endpoint",
    "baseurl": "endpoint",
    "apibase": "endpoint",
    "format": "format",
    "modelformat": "format",
    "serialization": "format",
    "filetype": "format",
    "unsafedeserialization": "unsafe",
    "unsafeserialization": "unsafe",
    "source": "locator",
    "configfile": "locator",
}
#: Accepted agent-level names (``cdx:agent:*`` / ``cdx:agentic:*``).
AGENT_KEYS: dict[str, str] = {
    "framework": "framework",
    "frameworkversion": "framework_version",
    "tools": "tools",
    "model": "model",
    "role": "role",
    "source": "locator",
    "configfile": "locator",
    "name": "name",
}


def _norm(name: str) -> tuple[str, str]:
    """``cdx:mcp:toolAnnotations`` → ``("cdx:mcp:", "toolannotations")`` (tool sub-keys keep one colon)."""
    lowered = name.lower()
    for prefix in PREFIXES:
        if lowered.startswith(prefix):
            rest = lowered[len(prefix) :].replace("-", "").replace("_", "")
            return prefix, rest
    return "", lowered


def _facts(bag: PropertyBag, prefixes: tuple[str, ...], table: dict[str, str]) -> dict[str, str]:
    """Consume the known names of ``prefixes``; return ``{field: value}`` (first value wins)."""
    out: dict[str, str] = {}
    for name in sorted(bag.names()):
        prefix, key = _norm(name)
        if prefix not in prefixes or key not in table:
            continue
        field = table[key]
        value = bag.get(name)
        if value is not None and field not in out:
            out[field] = value
    return out


def _is_tool(bag: PropertyBag) -> bool:
    return any(_norm(n)[1] in TOOL_KEYS and _norm(n)[0] in ("cdx:mcp:", "cdx:ai:") for n in bag.names())


def _is_server(bag: PropertyBag) -> bool:
    return any(_norm(n)[0] in ("cdx:mcp:", "cdx:mcpb:") for n in bag.names()) and not _is_tool(bag)


def _is_agent(bag: PropertyBag) -> bool:
    return any(_norm(n)[0] in ("cdx:agent:", "cdx:agentic:") for n in bag.names())


class CdxgenAdapter(AdapterBase):
    name = "cdxgen"
    default_kind = E.SnapshotKind.DECLARED
    prefixes = PREFIXES

    def __init__(self) -> None:
        super().__init__()
        self.pending_tools: list[tuple[Mapping[str, Any], PropertyBag, dict[str, str]]] = []
        self.pending_tool_names: list[tuple[str, list[str], str | None]] = []
        self.agent_tool_names: list[str] = []

    def adapt(self, doc: Mapping[str, Any], ctx: ImportContext, draft: Draft, root: Agent) -> set[str]:
        md = doc.get("metadata") if isinstance(doc.get("metadata"), Mapping) else {}
        tools_md = md.get("tools") if isinstance(md, Mapping) else None
        tool_components = (
            tools_md.get("components", []) if isinstance(tools_md, Mapping) else (tools_md or [])
        )
        for t in tool_components:
            if isinstance(t, Mapping) and str(t.get("name", "")).lower() == "cdxgen":
                self.collector_ref = f"collector:cdxgen@{t.get('version') or 'unknown'}"
        claimed: set[str] = set()
        self._root(ctx, draft, root, md.get("component") if isinstance(md, Mapping) else None)
        for where, element in self.elements(doc):
            bag = self.bag(element)
            ref = str(element.get("bom-ref") or "")
            ctype = str(element.get("type", ""))
            if _is_tool(bag):
                facts = _facts(bag, ("cdx:mcp:", "cdx:ai:"), TOOL_KEYS)
                self.pending_tools.append((element, bag, facts))
                claimed.add(ref)
            elif _is_server(bag) or (where == "service" and any(_norm(n)[0] for n in bag.names())):
                self._server(ctx, draft, element, bag, root)
                claimed.add(ref)
            elif ctype == "machine-learning-model" and any(
                _norm(n)[0] in ("cdx:ai:", "cdx:gguf:") for n in bag.names()
            ):
                self._model(ctx, draft, element, bag, root)
                claimed.add(ref)
            elif _is_agent(bag) and ctype == "application":
                facts = _facts(bag, ("cdx:agent:", "cdx:agentic:"), AGENT_KEYS)
                agent = self.sub_agent(
                    ctx,
                    draft,
                    element,
                    bag,
                    framework=facts.get("framework"),
                    framework_version=facts.get("framework_version"),
                    role=E.AgentRole.EXTERNAL_AGENT
                    if facts.get("role", "").lower() == "external"
                    else E.AgentRole.SUB_AGENT,
                    parent=root.id,
                    locator=facts.get("locator"),
                )
                draft.edge(
                    E.EdgeType.SPAWNS if agent.role is E.AgentRole.SUB_AGENT else E.EdgeType.DELEGATES_TO,
                    root.id,
                    agent.id,
                )
                claimed.add(ref)
        for element, bag, facts in self.pending_tools:
            self._tool(ctx, draft, element, bag=bag, facts=facts, root=root)
        for server_id, names, locator in self.pending_tool_names:
            for tool_name in names:
                if not any(
                    t.server_ref == server_id and t.tool_name == tool_name for t in draft.entities["tools"]
                ):
                    self.tool(
                        ctx,
                        draft,
                        None,
                        None,
                        tool_name=tool_name,
                        server_id=server_id,
                        description=None,
                        input_schema=None,
                        annotations_raw=None,
                        locator=locator,
                    )
        return claimed

    def post(self, doc: Mapping[str, Any], ctx: ImportContext, draft: Draft, root: Agent) -> None:
        for tool_name in self.agent_tool_names:
            for t in draft.entities["tools"]:
                if t.tool_name == tool_name:
                    draft.edge(E.EdgeType.INVOKES_TOOL, root.id, t.id)
        for s in draft.entities["tool_servers"]:
            draft.edge(E.EdgeType.DEPENDS_ON, root.id, s.id)
        for m in draft.entities["models"]:
            draft.edge(E.EdgeType.USES_MODEL, root.id, m.id)

    # ---- element mappers

    def _root(self, ctx: ImportContext, draft: Draft, root: Agent, comp: Mapping[str, Any] | None) -> None:
        if not comp:
            return
        bag = self.bag(comp)
        facts = _facts(bag, ("cdx:agent:", "cdx:agentic:"), AGENT_KEYS)
        if not facts:
            return
        consumed = {
            n
            for n in bag.names()
            if _norm(n)[0] in ("cdx:agent:", "cdx:agentic:") and _norm(n)[1] in AGENT_KEYS
        }
        self.agent_tool_names = split_list(facts.get("tools"))
        changes: dict[str, Any] = {"foreign": {k: v for k, v in root.foreign.items() if k not in consumed}}
        if facts.get("framework") and root.framework is None:
            changes["framework"] = Claim(
                value=FrameworkRef(name=facts["framework"], version=facts.get("framework_version"))
            )
        if facts.get("locator") and root.provenance.locator is None:
            changes["provenance"] = root.provenance.replace(
                locator=facts["locator"], method=E.ClaimMethod.CONFIG
            )
        ctx.unforeign(root.id, consumed)
        draft.replace(root.replace(**changes))

    def _server(
        self, ctx: ImportContext, draft: Draft, element: Mapping[str, Any], bag: PropertyBag, root: Agent
    ) -> None:
        facts = _facts(bag, ("cdx:mcp:", "cdx:mcpb:"), SERVER_KEYS)
        name = facts.get("server_name") or str(element.get("name") or element.get("bom-ref") or "mcp-server")
        server = self.server(
            ctx,
            draft,
            element,
            bag,
            name=name,
            client=facts.get("client"),
            transport_raw=facts.get("transport"),
            command=facts.get("command"),
            url=facts.get("url")
            or next((str(e) for e in element.get("endpoints") or [] if isinstance(e, str)), None),
            auth_raw=facts.get("auth"),
            env_names=split_list(facts.get("env")),
            header_names=split_list(facts.get("headers")),
            pinning=facts.get("pinning"),
            locator=facts.get("locator"),
            server_version=facts.get("server_version")
            or (str(element["version"]) if element.get("version") else None),
            protocol_version=facts.get("protocol_version"),
        )
        if facts.get("tools"):
            self.pending_tool_names.append((server.id, split_list(facts["tools"]), facts.get("locator")))
        draft.edge(E.EdgeType.DEPENDS_ON, root.id, server.id)

    def _tool(
        self,
        ctx: ImportContext,
        draft: Draft,
        element: Mapping[str, Any],
        *,
        bag: PropertyBag,
        facts: dict[str, str],
        root: Agent,
    ) -> None:
        tool_name = facts.get("tool_name") or str(element.get("name") or element.get("bom-ref") or "tool")
        server_hint = facts.get("server") or (str(element["group"]) if element.get("group") else None)
        server_id = self.servers_by_name.get(server_hint or "") if server_hint else None
        if server_id is None:
            server_id = self._builtin_server(ctx, draft, root, server_hint)
        schema = parse_json(facts.get("schema")) if facts.get("schema") else None
        tool = self.tool(
            ctx,
            draft,
            element,
            bag,
            tool_name=tool_name,
            server_id=server_id,
            description=facts.get("description")
            or (element.get("description") if isinstance(element.get("description"), str) else None),
            input_schema=schema if isinstance(schema, dict) else None,
            annotations_raw=facts.get("annotations"),
            locator=facts.get("locator"),
        )
        draft.edge(E.EdgeType.INVOKES_TOOL, root.id, tool.id)

    def _builtin_server(self, ctx: ImportContext, draft: Draft, root: Agent, hint: str | None) -> str:
        """Tools without a resolvable server are attached to a named or built-in server of the agent."""
        name = hint or f"{root.id.split(':', 1)[1]}-builtin"
        sid = self.servers_by_name.get(name)
        if sid:
            return sid
        sid = make_id("server", name)
        if not draft.has(sid):
            unknown: Claim[Any] = Claim.unknown(E.UnknownReason.NOT_COLLECTED)
            builtin = hint is None
            draft.add(
                ToolServer(
                    id=sid,
                    name=name,
                    provenance=declared(None, self.collector_ref),
                    server_kind=E.ToolServerKind.BUILTIN if builtin else E.ToolServerKind.MCP,
                    transport=Claim(value=E.Transport.IN_PROCESS) if builtin else unknown,
                    authentication=Claim(value=Authentication(mode=E.AuthMode.NONE)) if builtin else unknown,
                    trust_zone=E.TrustZone.LOCAL_PROCESS if builtin else E.TrustZone.UNKNOWN,
                    crosses_trust_boundary=Claim(value=False) if builtin else unknown,
                )
            )
            draft.edge(E.EdgeType.DEPENDS_ON, root.id, sid)
            ctx.lose(
                f"/toolServers/{sid}",
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.DROPPED,
                entity=sid,
                field_name="server",
            )
        self.servers_by_name[name] = sid
        return sid

    def _model(
        self, ctx: ImportContext, draft: Draft, element: Mapping[str, Any], bag: PropertyBag, root: Agent
    ) -> None:
        facts = _facts(bag, ("cdx:ai:", "cdx:gguf:"), MODEL_KEYS)
        formats = split_list(facts.get("format"))
        if any(_norm(n)[0] == "cdx:gguf:" for n in bag.names()) and "gguf" not in [
            f.lower() for f in formats
        ]:
            formats.append("gguf")
        model = self.model(
            ctx,
            draft,
            element,
            bag,
            name=str(element.get("name") or facts.get("requested_ref") or "model"),
            provider=facts.get("provider")
            or (
                str(element["supplier"]["name"])
                if isinstance(element.get("supplier"), Mapping) and element["supplier"].get("name")
                else None
            ),
            requested_ref=facts.get("requested_ref"),
            endpoint=facts.get("endpoint"),
            formats_raw=formats,
            unsafe_deserialization=facts.get("unsafe"),
            locator=facts.get("locator"),
        )
        draft.edge(E.EdgeType.USES_MODEL, root.id, model.id)


__all__ = ["AGENT_KEYS", "MODEL_KEYS", "PREFIXES", "SERVER_KEYS", "TOOL_KEYS", "CdxgenAdapter"]
