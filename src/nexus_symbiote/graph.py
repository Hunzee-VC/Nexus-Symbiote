"""Repository association graph and potential blast radius, never effective authority."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, model_validator

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import AssuranceLevel, AutonomyLevel, ComponentType
from nexus_symbiote.core.models import (
    AgentComponent,
    ClaimEvidence,
    ModelComponent,
    PromptComponent,
)

NonemptyString = Annotated[str, Field(min_length=1)]


class ModelDeclaration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: NonemptyString | None = None
    provider: NonemptyString | None = None
    requested_ref: NonemptyString | None = None

    @model_validator(mode="after")
    def one_model_source(self) -> ModelDeclaration:
        local = self.path is not None
        hosted = self.provider is not None and self.requested_ref is not None
        if local == hosted or (local and (self.provider or self.requested_ref)):
            raise ValueError("model requires a local path or both provider and requested_ref")
        return self


class AgentDeclaration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str | None = Field(default=None, min_length=1)
    name: str = Field(min_length=1)
    version: str | None = None
    purpose: str | None = None
    framework: str | None = None
    owner: str | None = None
    instructions: list[NonemptyString] = Field(default_factory=list, max_length=1024)
    models: dict[NonemptyString, ModelDeclaration] = Field(default_factory=dict, max_length=1024)
    autonomy_level: AutonomyLevel | None = None


def _manifest_dependencies(
    bom: AIBOM, declared: AgentDeclaration, root: Path, agent_ref: str
) -> list[PromptComponent | ModelComponent]:
    """Collect instruction bytes and local path bindings before changing the BOM."""
    from nexus_symbiote import limits
    from nexus_symbiote.policy import PolicyError
    from nexus_symbiote.utils.confined import ConfinedCollection

    def relative(value: str) -> Path:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise PolicyError("agent.yaml references must be relative paths beneath the repository")
        return path

    additions: list[PromptComponent | ModelComponent] = []
    failures: list[str] = []
    with ConfinedCollection(root, failures) as files:
        for instruction in declared.instructions:
            path = relative(instruction)
            digest = files.hash_file(path)
            if digest is None:
                raise PolicyError("agent.yaml instruction could not be collected safely")
            existing = [
                comp
                for comp in bom.components
                if isinstance(comp, PromptComponent) and comp.source_path == path.as_posix()
            ]
            if any(comp.content_hash and comp.content_hash != digest for comp in existing):
                raise PolicyError("agent.yaml instruction changed since scanner collection")
            if any(comp.content_hash == digest for comp in existing):
                continue
            ref = "prompt:manifest:" + hashlib.sha256(path.as_posix().encode()).hexdigest()[:24]
            additions.append(
                PromptComponent(
                    bom_ref=ref,
                    name=path.name,
                    source_path=path.as_posix(),
                    content_hash=digest,
                    assurance_level=AssuranceLevel.OBSERVED,
                    claims={
                        "content_hash": ClaimEvidence(
                            assurance=AssuranceLevel.OBSERVED,
                            method="confined-file-sha256",
                            scope="repository",
                            locator=path.as_posix(),
                            observed_at=bom.metadata.timestamp,
                        )
                    },
                )
            )
        for key, model in declared.models.items():
            if model.path is not None:
                local = relative(model.path)
                matches = [
                    comp
                    for comp in bom.components
                    if isinstance(comp, ModelComponent)
                    and comp.source_path
                    and (Path(comp.source_path) == local or Path(comp.source_path).parent == local)
                ]
                if not matches:
                    raise PolicyError("agent.yaml local model has no collected model artifact")
                for comp in matches:
                    assert comp.source_path is not None
                    path = relative(comp.source_path)
                    try:
                        with files.open_regular(path, max_bytes=limits.bound("model-bytes")):
                            pass
                    except OSError as exc:
                        raise PolicyError("agent.yaml local model path is unavailable") from exc
            else:
                ref = f"model:{agent_ref}/hosted/{quote(key, safe='')}"
                additions.append(
                    ModelComponent(
                        bom_ref=ref,
                        name=model.requested_ref or key,
                        provider=model.provider,
                        requested_alias=model.requested_ref,
                        model_type="hosted",
                        source_path="agent.yaml",
                        claims={
                            "requested_alias": ClaimEvidence(
                                assurance=AssuranceLevel.DECLARED,
                                method="agent-manifest",
                                scope="repository",
                                locator=f"agent.yaml#/models/{quote(key, safe='')}",
                            )
                        },
                    )
                )
    if failures:
        raise PolicyError("agent.yaml dependencies could not be collected safely")
    refs = [comp.bom_ref for comp in additions]
    if len(refs) != len(set(refs)) or any(bom.get_component(ref) for ref in refs):
        raise PolicyError("agent.yaml dependencies contain conflicting component references")
    return additions


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
    additions = _manifest_dependencies(bom, declared, root, agent_ref) if declared else []
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
        if declared.autonomy_level is not None:
            agent.properties["declared_autonomy_level"] = declared.autonomy_level.value
        for key in (
            "name",
            "version",
            "framework",
            "owner",
            "purpose",
            "autonomy_level",
            "instructions",
            "models",
        ):
            if key in declared.model_fields_set and getattr(declared, key) is not None:
                agent.claims[key] = ClaimEvidence(
                    assurance=AssuranceLevel.DECLARED,
                    method="agent-manifest",
                    scope="repository",
                    collector="repository-assembler",
                    locator=f"agent.yaml#/{key}",
                )
    for addition in additions:
        bom.add_component(addition)
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
        # A report stored in this repository does not associate discovered assets
        # with this repository agent. Imported relationships remain unobserved.
        if component.properties.get("collection_mode") == "imported-unverified-report":
            continue
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
