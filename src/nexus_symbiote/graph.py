"""Repository association graph and potential blast radius, never effective authority."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import AssuranceLevel, ComponentType
from nexus_symbiote.core.models import AgentComponent, ClaimEvidence


class AgentDeclaration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str | None = Field(default=None, min_length=1)
    name: str = Field(min_length=1)
    version: str | None = None
    purpose: str | None = None
    framework: str | None = None
    owner: str | None = None


def assemble_repository_agent(bom: AIBOM, root: Path) -> AgentComponent:
    """Associate repository-discovered dependencies with a definition, not a running agent."""
    declared: AgentDeclaration | None = None
    from nexus_symbiote.policy import PolicyError, parse_yaml_mapping
    from nexus_symbiote.utils.confined import ConfinedCollection

    failures: list[str] = []
    with ConfinedCollection(root, failures, exclude_paths=(), max_file_bytes=1024 * 1024) as files:
        text = files.read_text("agent.yaml", missing_ok=True)
    if failures:
        raise PolicyError("agent manifest cannot be collected: " + "; ".join(failures))
    if text is not None:
        try:
            declared = AgentDeclaration.model_validate(parse_yaml_mapping(text))
        except ValueError as exc:
            raise PolicyError(
                "agent.yaml must conform to the declared agent identity schema"
            ) from exc
    identity = declared.id if declared and declared.id else str(root.resolve())
    agent_ref = "agent:repository:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    discovery = ClaimEvidence(
        assurance=AssuranceLevel.OBSERVED,
        method="filesystem-inventory",
        scope="repository",
        collector="repository-assembler",
        locator="agent.yaml" if declared else ".",
        observed_at=bom.metadata.timestamp,
    )
    agent = AgentComponent(
        bom_ref=agent_ref,
        name=declared.name if declared else root.name,
        version=declared.version if declared else None,
        framework=declared.framework if declared else None,
        supplier=declared.owner if declared else None,
        description=declared.purpose
        if declared
        else "Repository agent definition inferred from configuration",
        autonomy_level=None,
        deployment_status="unknown",
        assurance_level=AssuranceLevel.OBSERVED,
        claims={
            "repository_presence": discovery,
            "deployment": ClaimEvidence(
                method="not-collected",
                scope="runtime",
                unknown_reason="Repository scan cannot identify a running workload",
            ),
        },
        properties={
            "identity_source": "agent.yaml" if declared else "repository-path",
            "runtime_use": "unknown",
        },
    )
    if declared:
        for key in ("name", "version", "framework", "owner", "purpose"):
            if getattr(declared, key) is not None:
                agent.claims[key] = ClaimEvidence(
                    assurance=AssuranceLevel.DECLARED,
                    method="agent-manifest",
                    scope="repository",
                    collector="repository-assembler",
                    locator=f"agent.yaml#/{key}",
                )
    relations = {
        ComponentType.MCP_SERVER: ("tool_refs", "configured-with"),
        ComponentType.TOOL: ("tool_refs", "configured-with"),
        ComponentType.MODEL: ("model_refs", "uses-model"),
        ComponentType.PROMPT_TEMPLATE: ("prompt_refs", "reads-instructions"),
        ComponentType.SKILL_PACKAGE: ("skill_refs", "loads-skill"),
        ComponentType.MEMORY_STORE: ("memory_refs", "uses-memory"),
        ComponentType.GUARDRAIL_POLICY: ("guardrail_refs", "uses-guardrail"),
        ComponentType.RAG_SOURCE: ("data_refs", "retrieves-from"),
        ComponentType.DATA_SOURCE: ("data_refs", "retrieves-from"),
    }
    associated_kinds = {
        ComponentType.MCP_CLIENT,
        ComponentType.A2A_CLIENT,
        ComponentType.A2A_SERVER,
        ComponentType.IDE_AGENT,
        ComponentType.VERIFIED_EXTENSION,
    }
    for component in list(bom.components):
        if component.component_type in associated_kinds:
            bom.add_dependency(
                DependencyEdge(
                    source_ref=agent_ref,
                    target_ref=component.bom_ref,
                    relationship="configured-with",
                    assurance_level="declared",
                    conditions="repository association; runtime use and authority unobserved",
                )
            )
        if component.component_type not in relations:
            continue
        field_name, relationship = relations[component.component_type]
        getattr(agent, field_name).append(component.bom_ref)
        bom.add_dependency(
            DependencyEdge(
                source_ref=agent_ref,
                target_ref=component.bom_ref,
                relationship=relationship,
                assurance_level="declared",
                conditions="repository association; runtime use and authority unobserved",
            )
        )
        server_ref = getattr(component, "mcp_server_ref", None)
        if server_ref and bom.get_component(server_ref) is not None:
            bom.add_dependency(
                DependencyEdge(
                    source_ref=server_ref,
                    target_ref=component.bom_ref,
                    relationship="provides-tool",
                    assurance_level="declared",
                )
            )
    bom.add_component(agent)
    return agent


_REF_TYPES: dict[str, set[ComponentType]] = {
    "server_refs": {ComponentType.MCP_SERVER},
    "mcp_server_refs": {ComponentType.MCP_SERVER},
    "model_refs": {ComponentType.MODEL},
    "tool_refs": {ComponentType.TOOL, ComponentType.MCP_SERVER},
    "memory_refs": {ComponentType.MEMORY_STORE},
    "prompt_refs": {ComponentType.PROMPT_TEMPLATE},
    "guardrail_refs": {ComponentType.GUARDRAIL_POLICY},
    "sub_agent_refs": {ComponentType.AGENT},
    "data_refs": {ComponentType.DATA_SOURCE, ComponentType.RAG_SOURCE},
    "skill_refs": {ComponentType.SKILL_PACKAGE},
    "mcp_server_ref": {ComponentType.MCP_SERVER},
    "model_ref": {ComponentType.MODEL},
    "embedding_model_ref": {ComponentType.MODEL},
    "base_model_ref": {ComponentType.MODEL},
    "registry_ref": {ComponentType.REGISTRY_ENTRY},
}


def validate_graph(bom: AIBOM) -> list[str]:
    nodes = {c.bom_ref: c for c in bom.components}
    issues: list[str] = []
    if len(nodes) != len(bom.components):
        issues.append("duplicate component references")
    for component in bom.components:
        for field_name, allowed in _REF_TYPES.items():
            value = getattr(component, field_name, None)
            refs = value if isinstance(value, list) else [value] if value else []
            for ref in refs:
                target = nodes.get(ref)
                if target is None:
                    issues.append(f"{component.bom_ref}.{field_name}: missing target {ref}")
                elif target.component_type not in allowed:
                    issues.append(f"{component.bom_ref}.{field_name}: wrong target type {ref}")
    for edge in bom.dependencies:
        if edge.source_ref not in nodes or edge.target_ref not in nodes:
            issues.append(
                f"{edge.relationship}: dangling edge {edge.source_ref} -> {edge.target_ref}"
            )
        elif edge.relationship == "provides-tool" and (
            nodes[edge.source_ref].component_type is not ComponentType.MCP_SERVER
            or nodes[edge.target_ref].component_type is not ComponentType.TOOL
        ):
            issues.append("provides-tool must link an MCP server to a tool")
    return sorted(set(issues))


def blast_radius(bom: AIBOM, component_ref: str) -> dict[str, Any]:
    issues = validate_graph(bom)
    if issues:
        raise ValueError("invalid graph: " + "; ".join(issues))
    if bom.get_component(component_ref) is None:
        raise ValueError(f"unknown component: {component_ref}")
    forward: dict[str, set[str]] = {}
    reverse: dict[str, set[str]] = {}
    for component in bom.components:
        for field_name in _REF_TYPES:
            value = getattr(component, field_name, None)
            refs = value if isinstance(value, list) else [value] if value else []
            for ref in refs:
                forward.setdefault(component.bom_ref, set()).add(ref)
                reverse.setdefault(ref, set()).add(component.bom_ref)
    for edge in bom.dependencies:
        forward.setdefault(edge.source_ref, set()).add(edge.target_ref)
        reverse.setdefault(edge.target_ref, set()).add(edge.source_ref)

    def walk(start: str, graph: dict[str, set[str]]) -> set[str]:
        seen: set[str] = set()
        pending = [start]
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            pending.extend(graph.get(current, set()) - seen)
        return seen

    upstream = walk(component_ref, reverse)
    affected = sorted(
        c.bom_ref
        for c in bom.components
        if c.component_type is ComponentType.AGENT and c.bom_ref in upstream
    )
    reach = (
        set().union(*(walk(a, forward) for a in affected))
        if affected
        else walk(component_ref, forward)
    )
    principals = sorted(
        {
            auth.principal
            for c in bom.components
            if c.bom_ref in reach
            for auth in getattr(c, "authorizations", [])
        }
    )
    return {
        "subject": component_ref,
        "affected_agents": affected,
        "reachable_components": sorted(reach),
        "declared_principals": principals,
        "scope": "repository-association",
        "effective_authority": "unknown",
        "limitations": [
            "Reachability describes potential dependencies, not proven exploitability or runtime access."
        ],
    }
