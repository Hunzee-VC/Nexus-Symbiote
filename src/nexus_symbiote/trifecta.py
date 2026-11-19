"""Lethal-trifecta, toxic-flow chain, and tool-shadowing analysis.

Evaluates an AgentBOM offline for three structural agentic risks:

1. **Lethal trifecta (Item 15):** an agent scope combining untrusted input, private
   data access, and external egress or state mutation without an explicit approval gate
   is rated ``critical``. An identical agent with an explicit approval gate on the
   egress/mutating surface stays clean.
2. **Chained toxic flows (Item 24):** a leak or state-mutation chain possible only by
   combining two distinct tools (source + sink) produces one ``toxic_flow`` finding
   naming both components rather than treating each tool in isolation as clean.
3. **Tool shadowing (Item 24):** two distinct tool definitions that collide on a
   normalized tool name across servers or sources produce one ``tool_shadowing``
   finding, escalated to ``high`` when a lower-trust source shadows a higher-trust one.

All rules operate strictly on recorded inventory evidence without executing code or
contacting the network.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import (
    AssuranceLevel,
    CapabilityClass,
    HumanInTheLoop,
    RiskSeverity,
    TrustTier,
)
from nexus_symbiote.core.models import (
    A2AClientComponent,
    A2AServerComponent,
    AgentComponent,
    AnyComponent,
    AuthorizationRecord,
    CapabilityDeclaration,
    DataSourceComponent,
    IDEAgentComponent,
    MCPServerComponent,
    MemoryStoreComponent,
    RAGSourceComponent,
    ToolComponent,
)
from nexus_symbiote.risk_classes import RiskClass, classify

_UNTRUSTED_NAME_RE = re.compile(
    r"(?:^|[_\-.\s/])(?:fetch|scrape|browse|browser|web_?search|search_?web|"
    r"http_?get|curl|download|read_?email|fetch_?email|read_?issue|read_?pr|"
    r"webhook|external_?read|crawl)(?:$|[_\-.\s/])",
    re.IGNORECASE,
)
_PRIVATE_NAME_RE = re.compile(
    r"(?:^|[_\-.\s/])(?:read_?file|read_?secret|get_?secret|vault|keychain|"
    r"credentials?|env_?read|db_?query|query_?db|sql_?query|customer_?data|"
    r"private_?data|internal_?docs?|list_?secrets?)(?:$|[_\-.\s/])",
    re.IGNORECASE,
)
_SEPARATOR_RE = re.compile(r"[\s\-_.]+")
_SEVERITY_RANK: dict[RiskSeverity, int] = {
    RiskSeverity.CRITICAL: 0,
    RiskSeverity.HIGH: 1,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.LOW: 3,
    RiskSeverity.INFO: 4,
}
_TRUST_RANK: dict[TrustTier, int] = {
    TrustTier.INTERNAL_VERIFIED: 5,
    TrustTier.INTERNAL_UNVERIFIED: 4,
    TrustTier.THIRD_PARTY_SIGNED: 3,
    TrustTier.THIRD_PARTY_UNSIGNED: 2,
    TrustTier.UNTRUSTED_PUBLIC: 1,
    TrustTier.UNKNOWN: 0,
}
_GATED_CLAUDE_MODES = frozenset({"default", "ask", "plan"})
_UNGATED_CLAUDE_MODES = frozenset({"bypassPermissions", "acceptEdits"})
_GATED_CODEX_POLICIES = frozenset({"on-request", "untrusted"})
_UNGATED_CODEX_POLICIES = frozenset({"never"})
_SHADOW_HIGH_TIERS = frozenset(
    {TrustTier.THIRD_PARTY_UNSIGNED, TrustTier.UNTRUSTED_PUBLIC, TrustTier.UNKNOWN}
)


@dataclass(frozen=True)
class LegEvidence:
    """Evidence tying one component to a trifecta leg."""

    component_ref: str
    component_name: str
    basis: tuple[str, ...]
    locator: str | None
    assurance: AssuranceLevel
    gated: bool


@dataclass(frozen=True)
class FlowFinding:
    """A deterministic, evidence-backed trifecta, toxic-flow, or shadowing finding."""

    kind: str
    severity: RiskSeverity
    scope_ref: str
    summary: str
    component_refs: tuple[str, ...]
    evidence: tuple[dict[str, Any], ...]
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity.value,
            "scope_ref": self.scope_ref,
            "summary": self.summary,
            "component_refs": list(self.component_refs),
            "evidence": list(self.evidence),
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class TrifectaReport:
    """Result of lethal-trifecta, toxic-flow, and tool-shadowing analysis."""

    scopes_evaluated: int
    findings: tuple[FlowFinding, ...]
    shadowed_refs: tuple[str, ...]

    @property
    def has_critical(self) -> bool:
        return any(f.severity is RiskSeverity.CRITICAL for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return {
            "scopes_evaluated": self.scopes_evaluated,
            "finding_count": len(self.findings),
            "severity_counts": dict(sorted(counts.items())),
            "shadowed_refs": list(self.shadowed_refs),
            "findings": [f.to_dict() for f in self.findings],
        }


def canonical_tool_name(name: str) -> str:
    """Normalize a tool name for shadowing detection (NFKC, lower, collapsed separators)."""
    normalized = unicodedata.normalize("NFKC", name)
    cleaned = "".join(
        ch for ch in normalized if unicodedata.category(ch) not in {"Cf", "Cc", "Cs", "Co", "Cn"}
    )
    return _SEPARATOR_RE.sub("_", cleaned.strip().lower()).strip("_")


def _component_locator(component: AnyComponent) -> str | None:
    if component.source_path:
        return component.source_path
    for claim in component.claims.values():
        if claim.locator:
            return claim.locator
    return None


def _has_explicit_approval_gate(component: AnyComponent) -> bool:
    """Fail-closed check: True only when explicit approval evidence is recorded."""
    decl = getattr(component, "capabilities", None)
    if isinstance(decl, CapabilityDeclaration):
        if decl.human_in_the_loop is HumanInTheLoop.REQUIRED:
            return True
        if decl.human_in_the_loop is HumanInTheLoop.NONE:
            return False

    auths = getattr(component, "authorizations", None)
    if isinstance(auths, list) and auths:
        records = [a for a in auths if isinstance(a, AuthorizationRecord)]
        if records and all(r.approval_required is True for r in records):
            return True

    if isinstance(component, IDEAgentComponent):
        if component.ide_type == "claude-code":
            if component.permission_mode in _UNGATED_CLAUDE_MODES:
                return False
            if component.permission_mode in _GATED_CLAUDE_MODES:
                return True
        if component.ide_type == "codex":
            policy = component.properties.get("approval_policy")
            if isinstance(policy, str):
                if policy in _UNGATED_CODEX_POLICIES:
                    return False
                if policy in _GATED_CODEX_POLICIES:
                    return True

    props = component.properties
    if props.get("requires_approval") is True or props.get("approval_gate") is True:
        return True
    return bool(props.get("human_in_the_loop") == HumanInTheLoop.REQUIRED.value)


def _untrusted_input_basis(component: AnyComponent) -> tuple[str, ...]:
    basis: set[str] = set()
    props = component.properties
    if props.get("untrusted_input") is True or props.get("reads_untrusted_input") is True:
        basis.add("property:untrusted_input")
    if isinstance(component, (A2AServerComponent, A2AClientComponent)):
        basis.add(f"component_type:{component.component_type.value}")
    if isinstance(component, MCPServerComponent) and component.endpoint_url:
        rc = classify(component)
        if RiskClass.NETWORK_EGRESS in rc.classes:
            basis.add("mcp_server:remote_endpoint")
    decl = getattr(component, "capabilities", None)
    if isinstance(decl, CapabilityDeclaration):
        caps = set(decl.capabilities)
        if CapabilityClass.NETWORK in caps and CapabilityClass.READ in caps:
            basis.add("capabilities:network+read")
    if isinstance(component, ToolComponent):
        if _UNTRUSTED_NAME_RE.search(component.name):
            basis.add("tool_name:external_reader")
        elif component.description and _UNTRUSTED_NAME_RE.search(component.description):
            basis.add("tool_description:external_reader")
    return tuple(sorted(basis))


def _private_data_basis(component: AnyComponent) -> tuple[str, ...]:
    basis: set[str] = set()
    rc = classify(component)
    if RiskClass.SECRET_ACCESS in rc.classes:
        basis.add("risk_class:secret-access")
    if isinstance(component, (DataSourceComponent, MemoryStoreComponent, RAGSourceComponent)):
        basis.add(f"component_type:{component.component_type.value}")
    if isinstance(component, MCPServerComponent) and component.env:
        basis.add("mcp_server:env_present")
    decl = getattr(component, "capabilities", None)
    if isinstance(decl, CapabilityDeclaration):
        caps = set(decl.capabilities)
        for cap in (CapabilityClass.CREDENTIALS, CapabilityClass.FILESYSTEM, CapabilityClass.READ):
            if cap in caps and (
                cap is not CapabilityClass.READ
                or component.properties.get("private_data") is True
                or bool(decl.filesystem_paths)
                or bool(decl.oauth_scopes)
            ):
                basis.add(f"capabilities:{cap.value}")
        if decl.filesystem_paths:
            basis.add("filesystem_paths:declared")
        if decl.oauth_scopes:
            basis.add("oauth_scopes:declared")
    if component.properties.get("private_data") is True:
        basis.add("property:private_data")
    if isinstance(component, ToolComponent) and _PRIVATE_NAME_RE.search(component.name):
        basis.add("tool_name:private_reader")
    return tuple(sorted(basis))


def _egress_basis(component: AnyComponent) -> tuple[str, ...]:
    basis: set[str] = set()
    rc = classify(component)
    for cls in (
        RiskClass.NETWORK_EGRESS,
        RiskClass.EXFIL_CAPABLE,
        RiskClass.WRITE_CAPABLE,
        RiskClass.CODE_EXEC,
    ):
        if cls in rc.classes:
            basis.add(f"risk_class:{cls.value}")
    if component.properties.get("external_egress") is True:
        basis.add("property:external_egress")
    return tuple(sorted(basis))


def _scopes(bom: AIBOM) -> list[tuple[str, AnyComponent | None, list[AnyComponent]]]:
    by_ref = {comp.bom_ref: comp for comp in bom.components}
    dep_map: dict[str, list[str]] = {}
    for dep in bom.dependencies:
        dep_map.setdefault(dep.source_ref, []).append(dep.target_ref)
    server_tools: dict[str, list[AnyComponent]] = {}
    for comp in bom.components:
        if isinstance(comp, ToolComponent) and comp.mcp_server_ref:
            server_tools.setdefault(comp.mcp_server_ref, []).append(comp)

    agents = sorted(
        (c for c in bom.components if isinstance(c, (AgentComponent, IDEAgentComponent))),
        key=lambda c: c.bom_ref,
    )
    if not agents:
        ordered = sorted(bom.components, key=lambda c: c.bom_ref)
        return [("inventory:root", None, ordered)] if ordered else []

    result: list[tuple[str, AnyComponent | None, list[AnyComponent]]] = []
    for agent in agents:
        seen: set[str] = {agent.bom_ref}
        queue: list[str] = [agent.bom_ref]
        if isinstance(agent, AgentComponent):
            for ref in (
                *agent.tool_refs,
                *agent.data_refs,
                *agent.memory_refs,
                *agent.skill_refs,
                *agent.sub_agent_refs,
            ):
                if ref not in seen:
                    seen.add(ref)
                    queue.append(ref)
        idx = 0
        while idx < len(queue):
            current = queue[idx]
            idx += 1
            for nxt in dep_map.get(current, ()):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
            for tool in server_tools.get(current, ()):
                if tool.bom_ref not in seen:
                    seen.add(tool.bom_ref)
                    queue.append(tool.bom_ref)
        members = sorted(
            (by_ref[ref] for ref in seen if ref in by_ref),
            key=lambda c: c.bom_ref,
        )
        # If an IDEAgentComponent has no explicit edges, it governs the repository's MCP/tool surface.
        if isinstance(agent, IDEAgentComponent) and len(members) == 1:
            members = sorted(bom.components, key=lambda c: c.bom_ref)
        result.append((agent.bom_ref, agent, members))
    return result


def _evidence_entry(leg: str, item: LegEvidence) -> dict[str, Any]:
    return {
        "leg": leg,
        "component_ref": item.component_ref,
        "component_name": item.component_name,
        "basis": list(item.basis),
        "locator": item.locator,
        "assurance": item.assurance.value,
        "gated": item.gated,
    }


def _detect_shadowing(bom: AIBOM) -> tuple[list[FlowFinding], set[str]]:
    tools = [c for c in bom.components if isinstance(c, ToolComponent)]
    groups: dict[str, list[ToolComponent]] = {}
    for tool in sorted(tools, key=lambda t: t.bom_ref):
        key = canonical_tool_name(tool.name)
        if key:
            groups.setdefault(key, []).append(tool)

    findings: list[FlowFinding] = []
    shadowed_refs: set[str] = set()
    for canon_name, group in sorted(groups.items()):
        if len(group) < 2:
            continue
        distinct_origins = {(t.mcp_server_ref, t.source_path) for t in group}
        if len(distinct_origins) < 2 and len({t.bom_ref for t in group}) < 2:
            continue
        tiers = [t.trust_tier for t in group]
        has_trusted = any(
            _TRUST_RANK[t] >= _TRUST_RANK[TrustTier.THIRD_PARTY_SIGNED] for t in tiers
        )
        has_untrusted = any(t in _SHADOW_HIGH_TIERS for t in tiers)
        severity = RiskSeverity.HIGH if (has_trusted and has_untrusted) else RiskSeverity.MEDIUM
        refs = tuple(t.bom_ref for t in group)
        shadowed_refs.update(refs)
        evidence = tuple(
            {
                "leg": "shadowed_tool",
                "component_ref": t.bom_ref,
                "component_name": t.name,
                "canonical_name": canon_name,
                "server_ref": t.mcp_server_ref,
                "trust_tier": t.trust_tier.value,
                "locator": _component_locator(t),
                "assurance": t.assurance_level.value,
            }
            for t in group
        )
        findings.append(
            FlowFinding(
                kind="tool_shadowing",
                severity=severity,
                scope_ref="inventory:root",
                summary=(
                    f"Tool name '{canon_name}' is defined by {len(group)} distinct components "
                    f"({', '.join(refs)}), creating a tool-shadowing conflict."
                ),
                component_refs=refs,
                evidence=evidence,
                recommendation=(
                    "Namespace tools per server, pin tool definition digests, and remove "
                    "duplicate or lower-trust tool definitions that shadow trusted tools."
                ),
            )
        )
    return findings, shadowed_refs


def analyze_trifecta(bom: AIBOM) -> TrifectaReport:
    """Analyze an inventory for lethal trifectas, chained toxic flows, and tool shadowing."""
    scopes = _scopes(bom)
    findings: list[FlowFinding] = []

    for scope_ref, owner, members in scopes:
        owner_gated = owner is not None and _has_explicit_approval_gate(owner)
        untrusted: list[LegEvidence] = []
        private: list[LegEvidence] = []
        egress: list[LegEvidence] = []

        for comp in members:
            gated = owner_gated or _has_explicit_approval_gate(comp)
            locator = _component_locator(comp)
            u_basis = _untrusted_input_basis(comp)
            if u_basis:
                untrusted.append(
                    LegEvidence(
                        comp.bom_ref, comp.name, u_basis, locator, comp.assurance_level, gated
                    )
                )
            p_basis = _private_data_basis(comp)
            if p_basis:
                private.append(
                    LegEvidence(
                        comp.bom_ref, comp.name, p_basis, locator, comp.assurance_level, gated
                    )
                )
            e_basis = _egress_basis(comp)
            if e_basis:
                egress.append(
                    LegEvidence(
                        comp.bom_ref, comp.name, e_basis, locator, comp.assurance_level, gated
                    )
                )

        ungated_egress = [item for item in egress if not item.gated]

        if untrusted and private and ungated_egress:
            involved = sorted(
                {
                    *(i.component_ref for i in untrusted),
                    *(i.component_ref for i in private),
                    *(i.component_ref for i in ungated_egress),
                }
            )
            evidence = (
                *(_evidence_entry("untrusted_input", i) for i in untrusted),
                *(_evidence_entry("private_data", i) for i in private),
                *(_evidence_entry("egress", i) for i in ungated_egress),
            )
            findings.append(
                FlowFinding(
                    kind="lethal_trifecta",
                    severity=RiskSeverity.CRITICAL,
                    scope_ref=scope_ref,
                    summary=(
                        f"Scope '{scope_ref}' combines untrusted input, private data access, "
                        f"and ungated external egress/state mutation across {len(involved)} "
                        "component(s) without an approval gate."
                    ),
                    component_refs=tuple(involved),
                    evidence=evidence,
                    recommendation=(
                        "Break at least one leg of the trifecta or enforce an explicit "
                        "human-in-the-loop approval gate (human_in_the_loop: required) on "
                        "every egress and state-modifying tool."
                    ),
                )
            )

        # Item 24: Chained toxic flow across two distinct tools where neither alone is EXFIL_CAPABLE.
        private_tools = [
            item
            for item in private
            if isinstance(
                next((m for m in members if m.bom_ref == item.component_ref), None),
                ToolComponent,
            )
        ]
        egress_tools = [
            item
            for item in ungated_egress
            if isinstance(
                next((m for m in members if m.bom_ref == item.component_ref), None),
                ToolComponent,
            )
        ]
        if private_tools and egress_tools:
            member_by_ref = {m.bom_ref: m for m in members}
            chained_sources = [
                src
                for src in private_tools
                if RiskClass.EXFIL_CAPABLE not in classify(member_by_ref[src.component_ref]).classes
            ]
            chained_sinks = [
                snk
                for snk in egress_tools
                if RiskClass.EXFIL_CAPABLE not in classify(member_by_ref[snk.component_ref]).classes
            ]
            cross_pairs = [
                (src, snk)
                for src in chained_sources
                for snk in chained_sinks
                if src.component_ref != snk.component_ref
            ]
            if cross_pairs:
                pair_refs = tuple(
                    sorted(
                        {
                            ref
                            for src, snk in cross_pairs
                            for ref in (src.component_ref, snk.component_ref)
                        }
                    )
                )
                pair_evidence = (
                    *(_evidence_entry("toxic_source", src) for src in chained_sources),
                    *(_evidence_entry("toxic_sink", snk) for snk in chained_sinks),
                )
                findings.append(
                    FlowFinding(
                        kind="toxic_flow",
                        severity=RiskSeverity.HIGH,
                        scope_ref=scope_ref,
                        summary=(
                            f"Scope '{scope_ref}' enables a chained toxic flow across "
                            f"{len(pair_refs)} distinct tools ({', '.join(pair_refs)}) where "
                            "private data from one tool can leave through an ungated sink tool."
                        ),
                        component_refs=pair_refs,
                        evidence=pair_evidence,
                        recommendation=(
                            "Require explicit approval on egress/state-modifying sink tools or "
                            "isolate private-data tools from network-capable tools."
                        ),
                    )
                )

    shadow_findings, shadowed_refs = _detect_shadowing(bom)
    findings.extend(shadow_findings)
    findings.sort(key=lambda f: (_SEVERITY_RANK[f.severity], f.kind, f.scope_ref, f.component_refs))
    return TrifectaReport(
        scopes_evaluated=len(scopes),
        findings=tuple(findings),
        shadowed_refs=tuple(sorted(shadowed_refs)),
    )
