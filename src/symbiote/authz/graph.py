"""Indexed traversal over an AgentBOM: what an agent can reach, and what a component can affect.

The incident questions in ``spec/agentbom-profile.md`` ("which agents hold credentials that this compromised
MCP server can use?", "what is the blast radius of a poisoned memory store?") are graph reachability over typed
edges. :class:`BomIndex` builds the adjacency once and answers them without re-scanning the document.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from symbiote.model.document import COLLECTIONS, AgentBOM
from symbiote.model.edges import Edge
from symbiote.model.entities import (
    Agent,
    CredentialBinding,
    DataSource,
    Grant,
    Model,
    ToolDefinition,
    ToolServer,
)
from symbiote.model.enums import EdgeType

__all__ = ["BlastRadius", "BomIndex"]


@dataclass(frozen=True, slots=True)
class BlastRadius:
    """Who and what a compromised component can affect."""

    subject: str
    agents: tuple[str, ...]
    tools: tuple[str, ...]
    credentials: tuple[str, ...]
    data_sources: tuple[str, ...]
    paths: tuple[tuple[str, ...], ...] = field(default_factory=tuple)


class BomIndex:
    """Adjacency and typed lookups over one :class:`AgentBOM`."""

    def __init__(self, bom: AgentBOM) -> None:
        self.bom = bom
        self.by_id: dict[str, Any] = {}
        for attr in COLLECTIONS:
            for ent in getattr(bom, attr):
                self.by_id[ent.id] = ent
        self._out: dict[str, list[Edge]] = defaultdict(list)
        self._in: dict[str, list[Edge]] = defaultdict(list)
        for edge in bom.edges:
            self._out[edge.from_ref].append(edge)
            self._in[edge.to_ref].append(edge)
        self._grants: dict[str, list[Grant]] = defaultdict(list)
        for grant in bom.grants:
            self._grants[grant.subject_ref].append(grant)
        self._tools_by_server: dict[str, list[ToolDefinition]] = defaultdict(list)
        for tool in bom.tools:
            self._tools_by_server[tool.server_ref].append(tool)

    # ------------------------------------------------------------------ basics

    def get(self, entity_id: str) -> Any:
        return self.by_id.get(entity_id)

    def out(self, entity_id: str, *types: EdgeType) -> list[Edge]:
        return [e for e in self._out.get(entity_id, []) if not types or e.type in types]

    def into(self, entity_id: str, *types: EdgeType) -> list[Edge]:
        return [e for e in self._in.get(entity_id, []) if not types or e.type in types]

    def agents(self) -> list[Agent]:
        return sorted(self.bom.agents, key=lambda a: a.id)

    def grants_for(self, subject_id: str) -> list[Grant]:
        return list(self._grants.get(subject_id, []))

    def server_of(self, tool: ToolDefinition) -> ToolServer | None:
        server = self.by_id.get(tool.server_ref)
        return server if isinstance(server, ToolServer) else None

    def tools_of_server(self, server_id: str) -> list[ToolDefinition]:
        return sorted(self._tools_by_server.get(server_id, []), key=lambda t: t.id)

    # ------------------------------------------------------------------ agent reach

    def servers_of(self, agent_id: str) -> list[ToolServer]:
        """Servers an agent uses: dependsOn(mcp-server), delegatesTo(a2a server), and servers of invoked tools."""
        found: dict[str, ToolServer] = {}
        for edge in self.out(agent_id, EdgeType.DEPENDS_ON, EdgeType.DELEGATES_TO):
            target = self.by_id.get(edge.to_ref)
            if isinstance(target, ToolServer):
                found[target.id] = target
        for tool in self._invoked_tools(agent_id):
            server = self.server_of(tool)
            if server is not None:
                found[server.id] = server
        return sorted(found.values(), key=lambda s: s.id)

    def _invoked_tools(self, agent_id: str) -> list[ToolDefinition]:
        tools: list[ToolDefinition] = []
        for edge in self.out(agent_id, EdgeType.INVOKES_TOOL):
            target = self.by_id.get(edge.to_ref)
            if isinstance(target, ToolDefinition):
                tools.append(target)
        return tools

    def tools_of(self, agent_id: str) -> list[ToolDefinition]:
        """Tools an agent can call: invoked tools plus every tool its servers provide."""
        found = {t.id: t for t in self._invoked_tools(agent_id)}
        for server in self.servers_of(agent_id):
            for tool in self.tools_of_server(server.id):
                found.setdefault(tool.id, tool)
        return sorted(found.values(), key=lambda t: t.id)

    def data_sources_of(self, agent_id: str) -> list[tuple[DataSource, Edge]]:
        out: list[tuple[DataSource, Edge]] = []
        for edge in self.out(agent_id, EdgeType.READS_CONTEXT_FROM, EdgeType.READS_MEMORY_FROM):
            target = self.by_id.get(edge.to_ref)
            if isinstance(target, DataSource):
                out.append((target, edge))
        return out

    def memory_writes_of(self, agent_id: str) -> list[DataSource]:
        out: list[DataSource] = []
        for edge in self.out(agent_id, EdgeType.WRITES_MEMORY_TO):
            target = self.by_id.get(edge.to_ref)
            if isinstance(target, DataSource):
                out.append(target)
        return out

    def credentials_of(self, holder_id: str) -> list[CredentialBinding]:
        out: list[CredentialBinding] = []
        for edge in self.out(holder_id, EdgeType.HOLDS_CREDENTIAL):
            target = self.by_id.get(edge.to_ref)
            if isinstance(target, CredentialBinding):
                out.append(target)
        for binding in self.bom.credential_bindings:
            if binding.subject_ref == holder_id and binding not in out:
                out.append(binding)
        return sorted(out, key=lambda c: c.id)

    def credentials_reachable(self, agent_id: str) -> list[CredentialBinding]:
        """Credentials an agent can exercise directly or through its servers and tools."""
        holders = [
            agent_id,
            *(s.id for s in self.servers_of(agent_id)),
            *(t.id for t in self.tools_of(agent_id)),
        ]
        seen: dict[str, CredentialBinding] = {}
        for holder in holders:
            for binding in self.credentials_of(holder):
                seen[binding.id] = binding
        return sorted(seen.values(), key=lambda c: c.id)

    def models_of(self, agent_id: str) -> list[Model]:
        out: list[Model] = []
        for edge in self.out(agent_id, EdgeType.USES_MODEL):
            target = self.by_id.get(edge.to_ref)
            if isinstance(target, Model):
                out.append(target)
        return out

    def sub_agents(self, agent_id: str) -> list[Agent]:
        out: list[Agent] = []
        for edge in self.out(agent_id, EdgeType.SPAWNS, EdgeType.DELEGATES_TO):
            target = self.by_id.get(edge.to_ref)
            if isinstance(target, Agent):
                out.append(target)
        return out

    # ------------------------------------------------------------------ blast radius

    def _dependents(self, entity_id: str) -> Iterable[str]:
        """Entities whose behaviour depends on ``entity_id`` (reverse of use edges)."""
        use_types = (
            EdgeType.DEPENDS_ON,
            EdgeType.INVOKES_TOOL,
            EdgeType.USES_MODEL,
            EdgeType.LOADS_INSTRUCTION,
            EdgeType.READS_CONTEXT_FROM,
            EdgeType.READS_MEMORY_FROM,
            EdgeType.DELEGATES_TO,
            EdgeType.SPAWNS,
            EdgeType.EMBEDS,
            EdgeType.DERIVED_FROM,
        )
        for edge in self.into(entity_id, *use_types):
            yield edge.from_ref
        entity = self.by_id.get(entity_id)
        if isinstance(entity, ToolServer):
            for tool in self.tools_of_server(entity_id):
                yield from (e.from_ref for e in self.into(tool.id, EdgeType.INVOKES_TOOL))
        if isinstance(entity, DataSource):
            for edge in self.into(entity_id, EdgeType.WRITES_MEMORY_TO):
                yield edge.from_ref

    def blast_radius(self, entity_id: str, *, max_depth: int = 8) -> BlastRadius:
        """Agents reachable by reverse-dependency from ``entity_id``, with the credentials and tools in play.

        For a tool server this answers "which agents use it, and which credentials does it hold"; for a data
        source, "which agents read or write it"; for a model or instruction, "which agents load it".
        """
        agents: set[str] = set()
        visited: set[str] = {entity_id}
        frontier: list[tuple[str, tuple[str, ...]]] = [(entity_id, (entity_id,))]
        paths: list[tuple[str, ...]] = []
        depth = 0
        while frontier and depth < max_depth:
            nxt: list[tuple[str, tuple[str, ...]]] = []
            for node, path in frontier:
                for dep in self._dependents(node):
                    if dep in visited:
                        continue
                    visited.add(dep)
                    new_path = (*path, dep)
                    if isinstance(self.by_id.get(dep), Agent):
                        agents.add(dep)
                        paths.append(new_path)
                    nxt.append((dep, new_path))
            frontier = nxt
            depth += 1
        subject = self.by_id.get(entity_id)
        tools: list[str] = []
        creds: set[str] = {c.id for c in self.credentials_of(entity_id)}
        data: list[str] = []
        if isinstance(subject, ToolServer):
            tools = [t.id for t in self.tools_of_server(entity_id)]
            for tool_id in tools:
                creds.update(c.id for c in self.credentials_of(tool_id))
        if isinstance(subject, DataSource):
            data = [entity_id]
        return BlastRadius(
            subject=entity_id,
            agents=tuple(sorted(agents)),
            tools=tuple(sorted(tools)),
            credentials=tuple(sorted(creds)),
            data_sources=tuple(data),
            paths=tuple(sorted(paths)),
        )
