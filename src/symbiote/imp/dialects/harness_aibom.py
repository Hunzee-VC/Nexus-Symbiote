"""agent-harness-aibom dialect (``harness-aibom:*``).

agent-harness-aibom describes what an agent harness (Claude Code, Codex, Cursor, Gemini CLI, …) loads: MCP
servers, instruction files, skills, hooks and the configured model. The adapter maps the names whose
semantics are known (:data:`KEYS`, matched case-insensitively with dashes/underscores ignored):

* ``component-type`` / ``kind`` ∈ ``mcp-server | tool | instruction | skill | hook | model | plugin`` decides
  the entity kind (file components with hashes default to instructions, services to MCP servers);
* ``harness`` / ``client`` → ``ToolServer.client`` and an ``harness:<name>`` tag; ``scope`` ∈ ``user | project
  | local`` → an instruction precedence of 3 / 2 / 1 (the ``instructions`` collector rule) and a ``scope:``
  tag; ``source`` / ``path`` / ``config-path`` → provenance locator (and the instruction path);
* ``transport``, ``command``, ``url``, ``env``, ``headers``, ``auth``, ``pinning`` → the server facts;
* ``model`` / ``provider`` → a hosted model; ``hook-event`` → an instruction of kind ``hook``;
* ``allowed-tools`` → skill allowed tools (kept as instruction frontmatter when the skill body is a file).

Every other ``harness-aibom:*`` property is preserved verbatim. Nothing is executed or fetched.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from symbiote.imp._common import ImportContext, PropertyBag
from symbiote.imp.dialects._base import AdapterBase, split_list
from symbiote.imp.native import Draft
from symbiote.model import enums as E
from symbiote.model.entities import Agent

PREFIXES = ("harness-aibom:",)

#: Accepted names (normalised) → fact.
KEYS: dict[str, str] = {
    "componenttype": "kind",
    "kind": "kind",
    "type": "kind",
    "harness": "client",
    "client": "client",
    "scope": "scope",
    "source": "locator",
    "path": "path",
    "configpath": "locator",
    "configfile": "locator",
    "transport": "transport",
    "command": "command",
    "url": "url",
    "endpoint": "url",
    "env": "env",
    "envvars": "env",
    "headers": "headers",
    "auth": "auth",
    "authmode": "auth",
    "pinning": "pinning",
    "pinned": "pinning",
    "model": "model",
    "provider": "provider",
    "hookevent": "hook_event",
    "allowedtools": "allowed_tools",
    "toolpermission": "permission",
    "permission": "permission",
    "precedence": "precedence",
    "name": "name",
    "version": "version",
}
_INSTRUCTION_KINDS = {
    "claude.md": E.InstructionKind.CLAUDE_MD,
    "agents.md": E.InstructionKind.AGENTS_MD,
    "gemini.md": E.InstructionKind.GEMINI_MD,
    ".cursorrules": E.InstructionKind.CURSOR_RULES,
    ".windsurfrules": E.InstructionKind.WINDSURF_RULES,
    "copilot-instructions.md": E.InstructionKind.COPILOT_INSTRUCTIONS,
    "skill.md": E.InstructionKind.SKILL_MD,
}
_PRECEDENCE = {"user": 3, "global": 3, "project": 2, "repo": 2, "local": 1, "directory": 1}


def _norm(name: str) -> str | None:
    lowered = name.lower()
    if not lowered.startswith(PREFIXES[0]):
        return None
    return lowered[len(PREFIXES[0]) :].replace("-", "").replace("_", "")


def _facts(bag: PropertyBag) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in sorted(bag.names()):
        key = _norm(name)
        if key is None or key not in KEYS:
            continue
        value = bag.get(name)
        if value is not None and KEYS[key] not in out:
            out[KEYS[key]] = value
    return out


def _instruction_kind(path: str | None, fallback: E.InstructionKind) -> E.InstructionKind:
    base = (path or "").rsplit("/", 1)[-1].lower()
    if base in _INSTRUCTION_KINDS:
        return _INSTRUCTION_KINDS[base]
    if base.endswith(".mdc"):
        return E.InstructionKind.CURSOR_RULES
    return fallback


class HarnessAibomAdapter(AdapterBase):
    name = "harness-aibom"
    default_kind = E.SnapshotKind.DECLARED
    prefixes = PREFIXES

    def adapt(self, doc: Mapping[str, Any], ctx: ImportContext, draft: Draft, root: Agent) -> set[str]:
        md = doc.get("metadata") if isinstance(doc.get("metadata"), Mapping) else {}
        tools_md = md.get("tools") if isinstance(md, Mapping) else None
        tool_components = (
            tools_md.get("components", []) if isinstance(tools_md, Mapping) else (tools_md or [])
        )
        for t in tool_components:
            if isinstance(t, Mapping) and "harness" in str(t.get("name", "")).lower():
                self.collector_ref = (
                    f"collector:{str(t['name']).lower().replace(' ', '-')}@{t.get('version') or 'unknown'}"
                )
        root_facts = _facts(self.bag(md.get("component") or {})) if isinstance(md, Mapping) else {}
        default_client = root_facts.get("client")
        claimed: set[str] = set()
        if root_facts:
            consumed = {n for n in self.bag(md.get("component") or {}).names() if (_norm(n) or "") in KEYS}
            ctx.unforeign(root.id, consumed)
            changes: dict[str, Any] = {
                "foreign": {k: v for k, v in root.foreign.items() if k not in consumed}
            }
            if default_client:
                changes["tags"] = sorted({*root.tags, f"harness:{default_client}"})
            if root_facts.get("locator") and root.provenance.locator is None:
                changes["provenance"] = root.provenance.replace(
                    locator=root_facts["locator"], method=E.ClaimMethod.CONFIG
                )
            root = root.replace(**changes)
            draft.replace(root)
        for where, element in self.elements(doc):
            bag = self.bag(element)
            if not any(_norm(n) is not None for n in bag.names()) and where != "service":
                continue
            facts = _facts(bag)
            ref = str(element.get("bom-ref") or "")
            kind = (facts.get("kind") or "").lower().replace("_", "-")
            ctype = str(element.get("type", ""))
            client = facts.get("client") or default_client
            locator = facts.get("locator") or facts.get("path")
            scope = (facts.get("scope") or "").lower()
            tags = [
                t for t in (f"harness:{client}" if client else None, f"scope:{scope}" if scope else None) if t
            ]
            if kind in ("mcp-server", "mcp", "server") or (where == "service" and kind == ""):
                server = self.server(
                    ctx,
                    draft,
                    element,
                    bag,
                    name=facts.get("name") or str(element.get("name") or ref or "mcp-server"),
                    client=client,
                    transport_raw=facts.get("transport"),
                    command=facts.get("command"),
                    url=facts.get("url")
                    or next((str(e) for e in element.get("endpoints") or [] if isinstance(e, str)), None),
                    auth_raw=facts.get("auth"),
                    env_names=split_list(facts.get("env")),
                    header_names=split_list(facts.get("headers")),
                    pinning=facts.get("pinning"),
                    locator=locator,
                    server_version=facts.get("version")
                    or (str(element["version"]) if element.get("version") else None),
                    tags=tags,
                )
                draft.edge(E.EdgeType.DEPENDS_ON, root.id, server.id)
                claimed.add(ref)
            elif kind == "model" or ctype == "machine-learning-model":
                model = self.model(
                    ctx,
                    draft,
                    element,
                    bag,
                    name=facts.get("model") or str(element.get("name") or "model"),
                    provider=facts.get("provider"),
                    requested_ref=facts.get("model"),
                    endpoint=facts.get("url"),
                    formats_raw=[],
                    unsafe_deserialization=None,
                    locator=locator,
                )
                draft.edge(E.EdgeType.USES_MODEL, root.id, model.id)
                claimed.add(ref)
            elif kind in ("instruction", "hook", "skill", "rules", "prompt") or (
                kind == "" and ctype == "file" and element.get("hashes")
            ):
                fallback = {
                    "hook": E.InstructionKind.HOOK,
                    "skill": E.InstructionKind.SKILL_MD,
                    "rules": E.InstructionKind.RULES_FILE,
                    "prompt": E.InstructionKind.SYSTEM_PROMPT,
                }.get(kind, E.InstructionKind.OTHER)
                path = (
                    facts.get("path")
                    or (str(element["name"]) if element.get("name") and "/" in str(element["name"]) else None)
                    or locator
                )
                precedence = (
                    int(facts["precedence"])
                    if facts.get("precedence", "").isdigit()
                    else _PRECEDENCE.get(scope, 0)
                )
                if facts.get("hook_event"):
                    tags.append(f"hook-event:{facts['hook_event']}")
                if facts.get("allowed_tools"):
                    for t in split_list(facts["allowed_tools"]):
                        tags.append(f"allowed-tool:{t}")
                instr = self.instruction(
                    ctx,
                    draft,
                    element,
                    bag,
                    kind=_instruction_kind(path, fallback),
                    path=path,
                    precedence=precedence,
                    locator=locator,
                    tags=sorted(set(tags)),
                )
                if instr is not None:
                    draft.edge(E.EdgeType.LOADS_INSTRUCTION, root.id, instr.id)
                    claimed.add(ref)
            elif kind == "tool":
                server_hint = str(element["group"]) if element.get("group") else None
                server_id = self.servers_by_name.get(server_hint or "") if server_hint else None
                if server_id is None:
                    continue  # a tool without its server stays a generic component (preserved verbatim)
                tool = self.tool(
                    ctx,
                    draft,
                    element,
                    bag,
                    tool_name=facts.get("name") or str(element.get("name") or "tool"),
                    server_id=server_id,
                    description=element.get("description")
                    if isinstance(element.get("description"), str)
                    else None,
                    input_schema=None,
                    annotations_raw=None,
                    locator=locator,
                )
                draft.edge(E.EdgeType.INVOKES_TOOL, root.id, tool.id)
                claimed.add(ref)
        return claimed

    def post(self, doc: Mapping[str, Any], ctx: ImportContext, draft: Draft, root: Agent) -> None:
        return None


__all__ = ["KEYS", "PREFIXES", "HarnessAibomAdapter"]
