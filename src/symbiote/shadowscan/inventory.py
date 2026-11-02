"""Export an AgentBOM as the inventory ShadowScan reconciles against (``spec/shadowscan-mapping.md §4``).

ShadowScan calls a finding *shadow* when nothing in the supplied inventory claims it. With the files written
here, "shadow" means "not in the AgentBOM": the declared or approved snapshot becomes the list of approved agents.

Three formats, all read by ``shadowscan --inventory``:

* **Agent Capability Cards** (``schema_version: 2``, one YAML per agent) — the richest form: the approved
  autonomy level on the L0-L5 scale, the intended purpose as a governance fact, the authorized tools with
  their definition digests, and a ``discovery`` block binding the concrete resources ShadowScan will see.
* a **simple list** (``agents.yaml``) and a **CSV** — the same bindings, for inventories kept in spreadsheets.

Only the keys ShadowScan validates strictly (``discovery``, ``governance``) are restricted to its vocabulary;
Symbiote-specific facts live in top-level sections ShadowScan ignores (``symbiote``, ``capability_surface``).
Resource bindings are **approvals**: generated patterns are literal (glob characters escaped) unless the caller
asks for a scan-root prefix, and a redacted or unknown identity yields no binding rather than a broad one.
"""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Iterable, Sequence
from enum import StrEnum
from typing import Any

import yaml

from symbiote import __version__
from symbiote.model import enums as E
from symbiote.model.document import AgentBOM
from symbiote.model.entities import Agent
from symbiote.model.ids import slugify
from symbiote.shadowscan.autonomy import from_iso

_GLOB = re.compile(r"[\[\]*?]")
_GITHUB = re.compile(r"^https?://github\.com/([^/\s]+)/([^/\s#?]+?)(?:\.git)?/?$")
MAX_TOOLS = 256


class InventoryFormat(StrEnum):
    CARDS = "cards"
    AGENTS = "agents"
    CSV = "csv"


def literal_pattern(resource: str) -> str:
    """Escape glob characters so a generated binding approves exactly this resource (ShadowScan semantics)."""
    return _GLOB.sub(lambda m: f"[{m.group(0)}]", resource)


def agent_identifier(agent: Agent) -> str:
    """The inventory ``agent_id``: the full Symbiote entity id (``agent:<slug>``).

    ShadowScan's own AgentBOM loader (``shadowscan/agentbom.py``) binds the same identifier, so a card written
    here and an AgentBOM passed to ``--inventory`` directly register a finding to one and the same agent id.
    """
    return agent.id


def agent_slug(agent: Agent) -> str:
    """The id without its ``agent:`` prefix (file names, review suggestions)."""
    return agent.id.split(":", 1)[1]


def _owner(bom: AgentBOM, agent: Agent) -> str | None:
    if not agent.owner_ref:
        return None
    party = next((p for p in bom.parties if p.id == agent.owner_ref), None)
    return party.name if party else agent.owner_ref.split(":", 1)[1]


def declared_level(agent: Agent) -> tuple[int | None, str | None]:
    """``(L-level, source)`` for the card: the owner's ISO level first, else the observed floor of an assessment."""
    if agent.automation_level is not None and agent.automation_level.value is not None:
        level, lossless = from_iso(agent.automation_level.value)
        source = agent.automation_level.assurance.value
        return level, source if lossless else f"{source}; iso 'autonomous' narrowed to L5"
    if agent.autonomy_assessment is not None:
        return agent.autonomy_assessment.floor, "observed-floor"
    return None, None


def discovery_resources(
    bom: AgentBOM, agent: Agent, *, extra: Iterable[str] = (), scan_root: str | None = None
) -> list[str]:
    """Resource patterns ShadowScan matches ``finding.resource`` against (review before use)."""
    patterns: list[str] = []
    for value in extra:
        if value and value not in patterns:
            patterns.append(value)
    if scan_root:
        root = scan_root.rstrip("/") or "/"
        for pattern in (literal_pattern(root), literal_pattern(root) + "/*"):
            if pattern not in patterns:
                patterns.append(pattern)
    for ref in agent.external_refs:
        m = _GITHUB.match(ref.url)
        if m:
            for pattern in (f"github:{m.group(1)}/{m.group(2)}", f"github:{m.group(1)}/{m.group(2)}/*"):
                if pattern not in patterns:
                    patterns.append(pattern)
    identities = {i.id: i for i in bom.identities}
    for ident_id in agent.identities:
        ident = identities.get(ident_id)
        if ident is None or "[REDACTED]" in ident.ref:
            continue
        if ident.identity_kind in (
            E.IdentityKind.IAM_ROLE,
            E.IdentityKind.SPIFFE,
            E.IdentityKind.GCP_SA,
        ) or ident.ref.startswith("arn:"):
            pattern = literal_pattern(ident.ref)
            if pattern not in patterns:
                patterns.append(pattern)
    for dep in bom.deployments:
        if (
            dep.agent_ref != agent.id
            or dep.workload_ref is None
            or dep.environment.kind is not E.EnvironmentKind.K8S
        ):
            continue
        wl = dep.workload_ref
        namespace = wl.namespace or dep.environment.namespace
        parts = [dep.environment.cluster, namespace, wl.kind, wl.name]
        # ShadowScan's AgentBOM loader binds only a complete cluster/namespace/kind/name identity; an
        # incomplete one would be a guess, and a guess is not an approval.
        if all(parts) and not any("/" in p for p in parts if p):
            pattern = literal_pattern("k8s:" + "/".join(p for p in parts if p))
            if pattern not in patterns:
                patterns.append(pattern)
    if agent.a2a_card is not None and agent.a2a_card.url:
        pattern = literal_pattern(agent.a2a_card.url)
        if pattern not in patterns:
            patterns.append(pattern)
    return patterns


def component_resources(bom: AgentBOM, agent: Agent) -> list[str]:
    """Endpoints and purls of the agent's tool servers: **descriptive** provenance, never approval bindings."""
    linked = {e.to_ref for e in bom.edges if e.from_ref == agent.id}
    out: list[str] = []
    for server in sorted(bom.tool_servers, key=lambda s: s.id):
        if agent.role is not E.AgentRole.ROOT and server.id not in linked:
            continue
        if server.endpoint is not None and server.endpoint.value:
            out.append(server.endpoint.value)
        if server.package is not None and server.package.value and server.package.value.purl:
            out.append(server.package.value.purl)
    return list(dict.fromkeys(out))


#: Symbiote data trust tiers → ShadowScan card zones (1 internal, 2 partner, 3 untrusted public).
ZONE_FROM_TIER = {
    E.TrustTier.INTERNAL_VERIFIED: 1,
    E.TrustTier.INTERNAL: 1,
    E.TrustTier.PARTNER: 2,
    E.TrustTier.UNTRUSTED_PUBLIC: 3,
}


def data_trust_zones(bom: AgentBOM, agent: Agent) -> dict[str, list[dict[str, int]]] | None:
    """``data_trust_zones`` from the data sources the agent reads or writes (unknown tiers claim no zone)."""
    sources = {d.id: d for d in bom.data_sources}
    read: list[int] = []
    write: list[int] = []
    for edge in bom.edges:
        if edge.from_ref != agent.id or edge.to_ref not in sources:
            continue
        zone = ZONE_FROM_TIER.get(sources[edge.to_ref].trust_tier)
        if zone is None:
            continue
        if edge.type in (E.EdgeType.READS_CONTEXT_FROM, E.EdgeType.READS_MEMORY_FROM):
            read.append(zone)
        elif edge.type is E.EdgeType.WRITES_MEMORY_TO:
            write.append(zone)
    if not read and not write:
        return None
    out: dict[str, list[dict[str, int]]] = {}
    if read:
        out["read_access"] = [{"zone": z} for z in sorted(set(read))]
    if write:
        out["write_access"] = [{"zone": z} for z in sorted(set(write))]
    return out


def _authorized_tools(bom: AgentBOM, agent: Agent) -> list[dict[str, str]]:
    servers = {s.id: s for s in bom.tool_servers}
    out: list[dict[str, str]] = []
    reachable = {e.to_ref for e in bom.edges if e.from_ref == agent.id}
    for tool in sorted(bom.tools, key=lambda t: t.id):
        server = servers.get(tool.server_ref)
        if (
            agent.role is not E.AgentRole.ROOT
            and tool.id not in reachable
            and (server is None or server.id not in reachable)
        ):
            continue
        entry: dict[str, str] = {"name": tool.tool_name}
        if server is not None and server.name:
            entry["provider"] = server.name
        if tool.digest.ok and tool.digest.value:
            entry["sha256"] = tool.digest.value[len("sha256:") :]
        if tool.side_effect_class is not E.SideEffectClass.UNKNOWN:
            entry["side_effect_class"] = tool.side_effect_class.value
        out.append(entry)
        if len(out) >= MAX_TOOLS:
            break
    return out


def _tool_servers(bom: AgentBOM, agent: Agent) -> list[dict[str, Any]]:
    linked = {e.to_ref for e in bom.edges if e.from_ref == agent.id}
    out: list[dict[str, Any]] = []
    for server in sorted(bom.tool_servers, key=lambda s: s.id):
        if agent.role is not E.AgentRole.ROOT and server.id not in linked:
            continue
        entry: dict[str, Any] = {"name": server.name or server.id, "kind": server.server_kind.value}
        if server.client:
            entry["client"] = server.client
        if server.transport.value is not None:
            entry["transport"] = server.transport.value.value
        if server.endpoint is not None and server.endpoint.value:
            entry["endpoint"] = server.endpoint.value
        if server.command:
            entry["command"] = server.command
        if server.package is not None and server.package.value and server.package.value.purl:
            entry["package"] = server.package.value.purl
        if server.digest:
            entry["sha256"] = server.digest[len("sha256:") :]
        out.append(entry)
    return out


def card_for(
    bom: AgentBOM,
    agent: Agent,
    *,
    resources: Iterable[str] = (),
    scan_root: str | None = None,
    classification: str | None = None,
) -> dict[str, Any]:
    """One ``schema_version: 2`` Agent Capability Card for ``agent``."""
    level, source = declared_level(agent)
    metadata: dict[str, Any] = {
        "agent_id": agent_identifier(agent),
        "name": agent.name or agent_slug(agent),
        "version": agent.version,
    }
    owner = _owner(bom, agent)
    if owner:
        metadata["owner_team"] = owner
    if classification:
        metadata["classification"] = classification
    metadata["tags"] = ["symbiote", f"agentbom-snapshot:{bom.snapshot.digest[len('sha256:') :][:12]}"]
    card: dict[str, Any] = {"schema_version": 2, "metadata": metadata}
    profile: dict[str, Any] = {}
    if level is not None:
        profile["level"] = level
    if agent.autonomy_profile:
        profile["action_modes"] = {a.capability.value: a.mode.value for a in agent.autonomy_profile}
    if profile:
        card["autonomy_profile"] = profile
    governance: dict[str, Any] = {}
    if agent.purpose:
        governance["intended_purpose"] = agent.purpose[:500]
    if governance:
        card["governance"] = governance
    tools = _authorized_tools(bom, agent)
    servers = _tool_servers(bom, agent)
    if tools or servers:
        card["capability_surface"] = {"authorized_tools": tools, "tool_servers": servers}
    zones = data_trust_zones(bom, agent)
    if zones is not None:
        card["data_trust_zones"] = zones
    spiffe = next(
        (
            i.ref
            for i in bom.identities
            if i.id in agent.identities and i.identity_kind is E.IdentityKind.SPIFFE
        ),
        None,
    )
    if spiffe:
        card["identity_and_delegation"] = {"spiffe_id": spiffe}
    card["provenance"] = {
        "schema": "symbiote-agentbom",
        "generator": f"symbiote {__version__}",
        "agentbom_ref": agent.id,
        "spec_version": bom.spec_version,
        "snapshot_id": bom.snapshot.id,
        "snapshot_digest": bom.snapshot.digest,
        "snapshot_kind": bom.snapshot.kind.value,
        "snapshot_serial": bom.snapshot.serial,
        "autonomy_level_source": source,
        "verification": "not-verified",
        "component_resources": component_resources(bom, agent),
    }
    names = [agent_slug(agent)]
    if agent.name:
        names.append(agent.name)
    if agent.a2a_card is not None:
        names.extend(s.name for s in agent.a2a_card.skills if s.name)
    discovery: dict[str, Any] = {
        "resources": discovery_resources(bom, agent, extra=resources, scan_root=scan_root)
    }
    if names:
        discovery["names"] = list(dict.fromkeys(n.strip() for n in names if n.strip()))
    if agent.framework is not None and agent.framework.value:
        discovery["frameworks"] = [f"framework.{slugify(agent.framework.value.name)}"]
    card["discovery"] = discovery
    return card


def selected_agents(bom: AgentBOM, *, include_external: bool = False) -> list[Agent]:
    agents = [a for a in bom.agents if include_external or a.role is not E.AgentRole.EXTERNAL_AGENT]
    return sorted(agents, key=lambda a: (a.role is not E.AgentRole.ROOT, a.id))


def inventory_cards(
    bom: AgentBOM,
    *,
    include_external: bool = False,
    resources: Iterable[str] = (),
    scan_root: str | None = None,
    classification: str | None = None,
) -> list[tuple[str, dict[str, Any]]]:
    """``(file name, card)`` for every selected agent; the root agent receives the explicit resources."""
    out: list[tuple[str, dict[str, Any]]] = []
    for agent in selected_agents(bom, include_external=include_external):
        card = card_for(
            bom,
            agent,
            resources=resources if agent.role is E.AgentRole.ROOT else (),
            scan_root=scan_root if agent.role is E.AgentRole.ROOT else None,
            classification=classification,
        )
        out.append((f"{slugify(agent_slug(agent))}.card.yaml", card))
    return out


def _simple_entries(
    bom: AgentBOM, *, include_external: bool, resources: Iterable[str], scan_root: str | None
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for agent in selected_agents(bom, include_external=include_external):
        level, _ = declared_level(agent)
        entry: dict[str, Any] = {"id": agent_identifier(agent), "name": agent.name or agent_slug(agent)}
        owner = _owner(bom, agent)
        if owner:
            entry["owner"] = owner
        root = agent.role is E.AgentRole.ROOT
        entry["resources"] = discovery_resources(
            bom, agent, extra=resources if root else (), scan_root=scan_root if root else None
        )
        entry["names"] = list(dict.fromkeys([agent_slug(agent), *([agent.name] if agent.name else [])]))
        if level is not None:
            entry["autonomy_level"] = level
        entries.append(entry)
    return entries


def _yaml(data: Any) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False, width=100)


def export_inventory(
    bom: AgentBOM,
    fmt: InventoryFormat | str = InventoryFormat.CARDS,
    *,
    include_external: bool = False,
    resources: Sequence[str] = (),
    scan_root: str | None = None,
    classification: str | None = None,
) -> dict[str, str]:
    """``{file name: text}`` for the chosen format (several files for cards, one for the list formats)."""
    fmt = InventoryFormat(fmt)
    header = (
        f"# ShadowScan inventory generated by Symbiote {__version__} from AgentBOM snapshot "
        f"{bom.snapshot.digest} ({bom.snapshot.kind.value}, serial {bom.snapshot.serial}).\n"
        "# Resource bindings are approvals: review every pattern before using this file with --inventory.\n"
    )
    if fmt is InventoryFormat.CARDS:
        return {
            name: header + _yaml(card)
            for name, card in inventory_cards(
                bom,
                include_external=include_external,
                resources=resources,
                scan_root=scan_root,
                classification=classification,
            )
        }
    entries = _simple_entries(
        bom, include_external=include_external, resources=resources, scan_root=scan_root
    )
    if fmt is InventoryFormat.AGENTS:
        return {"agents.yaml": header + _yaml({"agents": entries})}
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["agent_id", "name", "owner", "resources", "names", "autonomy_level"])
    for entry in entries:
        writer.writerow(
            [
                entry["id"],
                entry["name"],
                entry.get("owner", ""),
                "|".join(entry.get("resources", [])),
                "|".join(entry.get("names", [])),
                "" if entry.get("autonomy_level") is None else str(entry["autonomy_level"]),
            ]
        )
    return {"agents.csv": buf.getvalue()}


__all__ = [
    "MAX_TOOLS",
    "ZONE_FROM_TIER",
    "InventoryFormat",
    "agent_identifier",
    "agent_slug",
    "card_for",
    "component_resources",
    "data_trust_zones",
    "declared_level",
    "discovery_resources",
    "export_inventory",
    "inventory_cards",
    "literal_pattern",
    "selected_agents",
]
