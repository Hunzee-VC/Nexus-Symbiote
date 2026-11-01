"""Export an AgentBOM as Nexus-ShadowScan inventory records.

ShadowScan (https://github.com/aisecnomad/Nexus-ShadowScan) reconciles the
agents it discovers against an operator-supplied inventory. A sealed AgentBOM
is a machine-written inventory record, and ShadowScan ≥ #335 also loads the
AgentBOM document itself; these exporters serve operators who want the
classic formats instead:

* :func:`to_capability_card` — one schema-version-2 Agent Capability Card,
  with ``capability_surface.authorized_tools[].sha256`` carrying the
  ``tooldef/v1`` digests (ShadowScan's documented hook for tool pinning) and
  a ``discovery`` block derived exactly like ShadowScan's own AgentBOM
  loader derives resources, so both ingestion paths bind the same evidence.
* :func:`to_simple_inventory` — an ``agents:`` list entry.

Autonomy crosses vocabularies here: SymBiote records the ISO/IEC 22989
ladder (SPDX 3.1 ``isoAutomationLevel`` names); ShadowScan uses L0-L5. An
``automationLevel`` claim whose state is not ``present`` exports **no**
level — unknown must never read as low on either side.
"""

from __future__ import annotations

from typing import Any

from symbiote.model.document import AgentBOM
from symbiote.model.entities import Agent, DataSource
from symbiote.model.enums import CapabilityClass, EdgeType, IsoAutomationLevel, TrustTier

#: ISO/IEC 22989 ladder → ShadowScan L0-L5 (``docs/concepts/autonomy.md`` there).
LEVEL_FROM_ISO: dict[IsoAutomationLevel, int] = {
    IsoAutomationLevel.NOT_AUTOMATED: 0,
    IsoAutomationLevel.ASSISTIVE_AUTOMATION: 1,
    IsoAutomationLevel.PARTIAL_AUTOMATION: 2,
    IsoAutomationLevel.CONDITIONAL_AUTOMATION: 3,
    IsoAutomationLevel.HIGH_AUTOMATION: 4,
    IsoAutomationLevel.FULL_AUTOMATION: 5,
    IsoAutomationLevel.AUTONOMOUS: 5,
}

#: SymBiote data trust tiers → ShadowScan card zones (1 internal, 2 partner, 3 untrusted).
ZONE_FROM_TIER: dict[TrustTier, int] = {
    TrustTier.INTERNAL_VERIFIED: 1,
    TrustTier.INTERNAL: 1,
    TrustTier.PARTNER: 2,
    TrustTier.UNTRUSTED_PUBLIC: 3,
}


def _subject(bom: AgentBOM) -> Agent:
    return bom.root_agent


def declared_level(bom: AgentBOM) -> int | None:
    """The card-declared L0-L5 level, or ``None`` when the BOM does not state one."""
    claim = _subject(bom).automation_level
    if claim is None or claim.value is None:
        return None
    return LEVEL_FROM_ISO[claim.value]


def discovery_resources(bom: AgentBOM) -> list[str]:
    """Concrete resource strings ShadowScan can match findings against.

    Mirrors the derivation of ShadowScan's AgentBOM inventory loader
    (``shadowscan/agentbom.py``): deployment workload UID and
    ``k8s:<namespace>/<name>``, remote tool-server endpoints, pinned package
    purls, the agent's external refs and A2A card URL.
    """
    subject = _subject(bom)
    resources: list[str] = []
    for deployment in bom.deployments:
        if deployment.agent_ref != subject.id or deployment.workload_ref is None:
            continue
        workload = deployment.workload_ref
        if workload.uid:
            resources.append(workload.uid)
        if workload.namespace and workload.name:
            resources.append(f"k8s:{workload.namespace}/{workload.name}")
    for server in bom.tool_servers:
        if server.endpoint is not None and isinstance(server.endpoint.value, str):
            resources.append(server.endpoint.value)
        if server.package is not None and server.package.value is not None and server.package.value.purl:
            resources.append(server.package.value.purl)
    for ref in subject.external_refs:
        if ref.url:
            resources.append(ref.url)
    if subject.a2a_card is not None and subject.a2a_card.url:
        resources.append(subject.a2a_card.url)
    return [r for r in resources if r]


def _authorized_tools(bom: AgentBOM) -> list[dict[str, Any]]:
    egress_by_subject: dict[str, str] = {}
    for grant in bom.grants:
        if grant.capability is CapabilityClass.NETWORK_EGRESS and grant.scope.egress:
            egress_by_subject.setdefault(grant.subject_ref, grant.scope.egress[0])
    servers = {server.id: server for server in bom.tool_servers}
    tools: list[dict[str, Any]] = []
    for tool in bom.tools:
        entry: dict[str, Any] = {"name": tool.tool_name}
        server = servers.get(tool.server_ref)
        if server is not None and (server.name or server.id):
            entry["provider"] = server.name or server.id
        if tool.digest.ok and tool.digest.value:
            entry["sha256"] = tool.digest.value.removeprefix("sha256:")
        egress = egress_by_subject.get(tool.id)
        if egress:
            entry["egress_domain"] = egress
        tools.append(entry)
    return tools


def _trust_zones(bom: AgentBOM) -> dict[str, list[dict[str, int]]] | None:
    subject_id = _subject(bom).id
    sources = {source.id: source for source in bom.data_sources}

    def zones(*edge_types: EdgeType) -> list[dict[str, int]]:
        seen: set[int] = set()
        wanted = {edge_type.value for edge_type in edge_types}
        for edge in bom.edges:
            if edge.from_ref != subject_id or edge.type.value not in wanted:
                continue
            source: DataSource | None = sources.get(edge.to_ref)
            if source is None:
                continue
            zone = ZONE_FROM_TIER.get(source.trust_tier)
            if zone is not None:
                seen.add(zone)
        return [{"zone": zone} for zone in sorted(seen)]

    read = zones(EdgeType.READS_CONTEXT_FROM, EdgeType.READS_MEMORY_FROM)
    write = zones(EdgeType.WRITES_MEMORY_TO)
    if not read and not write:
        return None
    out: dict[str, list[dict[str, int]]] = {}
    if read:
        out["read_access"] = read
    if write:
        out["write_access"] = write
    return out


def to_capability_card(bom: AgentBOM) -> dict[str, Any]:
    """A schema-version-2 Agent Capability Card for ShadowScan's ``--inventory``."""
    subject = _subject(bom)
    parties = {party.id: party for party in bom.parties}
    owner = parties.get(subject.owner_ref) if subject.owner_ref else None
    metadata: dict[str, Any] = {"agent_id": subject.id, "version": subject.version}
    if subject.name:
        metadata["name"] = subject.name
    if owner is not None:
        metadata["owner_team"] = owner.name
    card: dict[str, Any] = {"schema_version": 2, "metadata": metadata}
    level = declared_level(bom)
    if level is not None:
        card["autonomy_profile"] = {"level": level}
    spiffe = next((i.ref for i in bom.identities if i.identity_kind.value == "spiffe"), None)
    if spiffe:
        card["identity_and_delegation"] = {"spiffe_id": spiffe}
    tools = _authorized_tools(bom)
    if tools:
        card["capability_surface"] = {"authorized_tools": tools}
    zones = _trust_zones(bom)
    if zones is not None:
        card["data_trust_zones"] = zones
    discovery: dict[str, Any] = {}
    resources = discovery_resources(bom)
    if resources:
        discovery["resources"] = resources
    names = [subject.id.split(":", 1)[-1]]
    if subject.name:
        names.append(subject.name)
    discovery["names"] = names
    card["discovery"] = discovery
    card["provenance"] = {
        "generator": "symbiote",
        "snapshot_id": bom.snapshot.id,
        "snapshot_digest": bom.snapshot.digest,
    }
    return card


def to_simple_inventory(bom: AgentBOM) -> dict[str, Any]:
    """An ``agents:`` list document (ShadowScan's simple inventory format)."""
    subject = _subject(bom)
    parties = {party.id: party for party in bom.parties}
    owner = parties.get(subject.owner_ref) if subject.owner_ref else None
    entry: dict[str, Any] = {"id": subject.id}
    if subject.name:
        entry["name"] = subject.name
        entry["names"] = [subject.name]
    if owner is not None:
        entry["owner"] = owner.name
    resources = discovery_resources(bom)
    if resources:
        entry["resources"] = resources
    level = declared_level(bom)
    if level is not None:
        entry["autonomy_level"] = level
    return {"agents": [entry]}


__all__ = [
    "LEVEL_FROM_ISO",
    "ZONE_FROM_TIER",
    "declared_level",
    "discovery_resources",
    "to_capability_card",
    "to_simple_inventory",
]
