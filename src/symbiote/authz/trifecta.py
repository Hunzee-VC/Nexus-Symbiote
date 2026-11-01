"""The lethal trifecta and Meta's "Agents Rule of Two" as cited, three-valued assessments.

*Lethal trifecta* (Simon Willison, June 2025): an agent that (A) is exposed to untrusted content, (B) can access
private data, and (C) can communicate externally can be steered by an injected instruction into exfiltrating
that data. *Agents Rule of Two* (Meta, Oct 2025): without a human in the loop an agent should satisfy at most two
of (A) untrustworthy inputs, (B) access to sensitive systems or private data, (C) the ability to change state or
communicate externally. ``SYM-AUTHZ-001`` in ``spec/checks.md``.

Each leg is ``true`` / ``false`` / ``unknown`` with the entities that make it so. A leg counts only when it is not
behind a *required* human approval. Static configuration rarely states what a tool does, so name-based
heuristics (labelled ``heuristic`` in the reasons) recognise servers that ingest externally authored content
(issue trackers, mail, web fetch), reach sensitive systems (repositories, databases, cloud accounts) or send data
out. Unknown is never reported as safe: an indeterminate verdict is surfaced as such.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final, Literal

from symbiote.authz.classify import (
    approval_gate,
    capabilities,
    is_open_world,
    server_approval_gate,
    side_effect_class,
)
from symbiote.authz.graph import BomIndex
from symbiote.model.entities import DataSource, ToolDefinition, ToolServer
from symbiote.model.enums import (
    ApprovalGate,
    CapabilityClass,
    Classification,
    SideEffectClass,
    TriState,
    TrustTier,
    ValueState,
)

__all__ = ["Leg", "TrifectaAssessment", "assess_agent", "assess_all"]

LegName = Literal["untrusted-input", "sensitive-access", "exfiltration", "state-change"]

_UNTRUSTED_CONTENT: Final = re.compile(
    r"(github|gitlab|bitbucket|gitea|jira|linear|asana|trello|slack|discord|teams|telegram|whatsapp|gmail|email|"
    r"imap|outlook|mail|fetch|browser|puppeteer|playwright|firecrawl|brave|tavily|exa\b|serp|search|reddit|"
    r"twitter|x-api|notion|confluence|zendesk|intercom|freshdesk|web|rss|youtube|scrap|crawl|sentry|support)",
    re.I,
)
_SENSITIVE: Final = re.compile(
    r"(filesystem|file|\bfs\b|sqlite|postgres|mysql|mongo|redis|database|\bdb\b|bigquery|snowflake|\bgit\b|"
    r"github|gitlab|drive|dropbox|box\b|s3|aws|gcp|azure|kubernetes|k8s|vault|secret|1password|keychain|"
    r"salesforce|hubspot|stripe|crm|erp|sap|workday|okta|jira|confluence|notion|gmail|outlook|mail)",
    re.I,
)
_EGRESS: Final = re.compile(
    r"(email|gmail|mail|smtp|slack|discord|teams|twilio|sms|webhook|http|fetch|browser|puppeteer|playwright|"
    r"github|gitlab|linear|jira|notion|confluence|tweet|twitter|reddit|stripe|payment|paypal|post|upload)",
    re.I,
)
_SENSITIVE_DATA_CLASSES: Final = frozenset(
    {"pii", "credentials", "source-code", "phi", "pci", "secrets", "financial"}
)


@dataclass(frozen=True, slots=True)
class Leg:
    name: LegName
    value: TriState
    inputs: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    heuristic: bool = False


@dataclass(frozen=True, slots=True)
class TrifectaAssessment:
    agent_id: str
    untrusted_input: Leg
    sensitive_access: Leg
    exfiltration: Leg
    state_change: Leg
    lethal_trifecta: TriState
    rule_of_two: TriState
    inputs: tuple[str, ...] = field(default_factory=tuple)

    @property
    def heuristic(self) -> bool:
        return any(
            leg.heuristic
            for leg in (self.untrusted_input, self.sensitive_access, self.exfiltration, self.state_change)
        )


def _server_text(server: ToolServer) -> str:
    parts = [server.name or "", server.id]
    if server.package is not None and server.package.value is not None:
        parts.append(server.package.value.purl or "")
    if server.endpoint is not None and server.endpoint.value:
        parts.append(server.endpoint.value)
    return " ".join(parts)


class _LegBuilder:
    def __init__(self, name: LegName) -> None:
        self.name: LegName = name
        self.true_inputs: list[str] = []
        self.unknown_inputs: list[str] = []
        self.reasons: list[str] = []
        self.heuristic = False

    def true(self, entity_id: str, reason: str, *, heuristic: bool = False) -> None:
        self.true_inputs.append(entity_id)
        self.reasons.append(reason)
        self.heuristic = self.heuristic or heuristic

    def unknown(self, entity_id: str, reason: str) -> None:
        self.unknown_inputs.append(entity_id)
        self.reasons.append(reason)

    def build(self) -> Leg:
        if self.true_inputs:
            value = TriState.TRUE
            inputs = tuple(dict.fromkeys(self.true_inputs))
        elif self.unknown_inputs:
            value = TriState.UNKNOWN
            inputs = tuple(dict.fromkeys(self.unknown_inputs))
        else:
            value = TriState.FALSE
            inputs = ()
        return Leg(
            self.name,
            value,
            inputs,
            tuple(dict.fromkeys(self.reasons)),
            self.heuristic and value is TriState.TRUE,
        )


def _combine(*legs: Leg) -> TriState:
    values = [leg.value for leg in legs]
    if all(v is TriState.TRUE for v in values):
        return TriState.TRUE
    if any(v is TriState.FALSE for v in values):
        return TriState.FALSE
    return TriState.UNKNOWN


def _source_untrusted(source: DataSource) -> tuple[TriState, str]:
    bearing = source.instruction_bearing
    bearing_true = bearing.state is ValueState.PRESENT and bearing.value is True
    bearing_unknown = bearing.state is not ValueState.PRESENT
    if source.trust_tier is TrustTier.UNTRUSTED_PUBLIC and (bearing_true or bearing_unknown):
        state = TriState.TRUE if bearing_true else TriState.UNKNOWN
        return (
            state,
            f"{source.id}: untrusted-public source{' (instruction-bearing)' if bearing_true else ''}",
        )
    if source.trust_tier is TrustTier.UNKNOWN and not (
        bearing.state is ValueState.PRESENT and bearing.value is False
    ):
        return TriState.UNKNOWN, f"{source.id}: trust tier unknown (treated as untrusted-public)"
    return TriState.FALSE, ""


def _source_sensitive(source: DataSource) -> tuple[TriState, str]:
    classes = {c.lower() for c in source.data_classes}
    if source.classification in (
        Classification.INTERNAL,
        Classification.CONFIDENTIAL,
        Classification.RESTRICTED,
    ):
        return TriState.TRUE, f"{source.id}: classification {source.classification.value}"
    if classes & _SENSITIVE_DATA_CLASSES:
        return TriState.TRUE, f"{source.id}: data classes {sorted(classes & _SENSITIVE_DATA_CLASSES)}"
    if source.classification is Classification.UNKNOWN:
        return TriState.UNKNOWN, f"{source.id}: classification unknown"
    return TriState.FALSE, ""


def _tool_legs(tool: ToolDefinition, server: ToolServer | None, legs: dict[LegName, _LegBuilder]) -> None:
    gate = approval_gate(tool, server)
    caps = set(capabilities(tool))
    effect = side_effect_class(tool)
    open_world = is_open_world(tool)
    gated = gate.gate is ApprovalGate.REQUIRED
    if effect is SideEffectClass.READ_ONLY and open_world:
        legs["untrusted-input"].true(
            tool.id, f"{tool.id}: open-world read tool returns externally authored content"
        )
    elif effect is SideEffectClass.UNKNOWN and open_world is None:
        legs["untrusted-input"].unknown(tool.id, f"{tool.id}: no annotations (MCP default open-world=true)")
    if caps & {CapabilityClass.FILESYSTEM, CapabilityClass.CREDENTIALS}:
        legs["sensitive-access"].true(
            tool.id,
            f"{tool.id}: capability {sorted(c.value for c in caps & {CapabilityClass.FILESYSTEM, CapabilityClass.CREDENTIALS})}",
        )
    egress = caps & {CapabilityClass.NETWORK_EGRESS, CapabilityClass.COMMUNICATE, CapabilityClass.PAYMENT}
    change = egress | (caps & {CapabilityClass.WRITE, CapabilityClass.EXECUTE})
    for leg_name, relevant in (("exfiltration", egress), ("state-change", change)):
        builder = legs[leg_name]  # type: ignore[index]
        if relevant and not gated:
            if gate.gate is ApprovalGate.NONE:
                builder.true(
                    tool.id,
                    f"{tool.id}: {sorted(c.value for c in relevant)} without approval ({gate.reason})",
                )
            else:
                builder.unknown(
                    tool.id,
                    f"{tool.id}: {sorted(c.value for c in relevant)}, approval {gate.gate.value} ({gate.reason})",
                )
        elif effect is SideEffectClass.UNKNOWN and not gated:
            builder.unknown(tool.id, f"{tool.id}: side effects unknown, approval {gate.gate.value}")


def _server_legs(server: ToolServer, has_tools: bool, legs: dict[LegName, _LegBuilder]) -> None:
    text = _server_text(server)
    gate = server_approval_gate(server)
    if _UNTRUSTED_CONTENT.search(text):
        legs["untrusted-input"].true(
            server.id, f"{server.id}: ingests externally authored content (heuristic: name)", heuristic=True
        )
    elif not has_tools:
        legs["untrusted-input"].unknown(server.id, f"{server.id}: tools not observed")
    if _SENSITIVE.search(text):
        legs["sensitive-access"].true(
            server.id, f"{server.id}: reaches a sensitive system (heuristic: name)", heuristic=True
        )
    remote = (
        server.crosses_trust_boundary.state is ValueState.PRESENT
        and server.crosses_trust_boundary.value is True
    )
    sends = remote or bool(_EGRESS.search(text))
    if not has_tools:
        for leg_name in ("exfiltration", "state-change"):
            builder = legs[leg_name]  # type: ignore[index]
            if sends and gate.gate is ApprovalGate.NONE:
                why = (
                    "remote server: every call sends data across the trust boundary"
                    if remote
                    else "sends data out (heuristic: name)"
                )
                builder.true(
                    server.id, f"{server.id}: {why}; auto-approved ({gate.reason})", heuristic=not remote
                )
            elif gate.gate is not ApprovalGate.REQUIRED:
                builder.unknown(server.id, f"{server.id}: tools not observed; approval {gate.gate.value}")


def assess_agent(index: BomIndex, agent_id: str) -> TrifectaAssessment:
    """Assess one agent; inputs cite the data sources, servers, tools and credentials that make each leg."""
    legs: dict[LegName, _LegBuilder] = {
        name: _LegBuilder(name)
        for name in ("untrusted-input", "sensitive-access", "exfiltration", "state-change")
    }
    for source, _edge in index.data_sources_of(agent_id):
        state, why = _source_untrusted(source)
        if state is TriState.TRUE:
            legs["untrusted-input"].true(source.id, why)
        elif state is TriState.UNKNOWN:
            legs["untrusted-input"].unknown(source.id, why)
        state_b, why_b = _source_sensitive(source)
        if state_b is TriState.TRUE:
            legs["sensitive-access"].true(source.id, why_b)
        elif state_b is TriState.UNKNOWN:
            legs["sensitive-access"].unknown(source.id, why_b)
    for binding in index.credentials_reachable(agent_id):
        legs["sensitive-access"].true(binding.id, f"{binding.id}: holds a credential for a non-public system")
    servers = index.servers_of(agent_id)
    for server in servers:
        _server_legs(server, bool(index.tools_of_server(server.id)), legs)
    for tool in index.tools_of(agent_id):
        _tool_legs(tool, index.server_of(tool), legs)
    built = {name: builder.build() for name, builder in legs.items()}
    a, b, c, d = (
        built["untrusted-input"],
        built["sensitive-access"],
        built["exfiltration"],
        built["state-change"],
    )
    inputs = tuple(dict.fromkeys((*a.inputs, *b.inputs, *c.inputs, *d.inputs)))
    return TrifectaAssessment(
        agent_id=agent_id,
        untrusted_input=a,
        sensitive_access=b,
        exfiltration=c,
        state_change=d,
        lethal_trifecta=_combine(a, b, c),
        rule_of_two=_combine(a, b, d),
        inputs=inputs,
    )


def assess_all(index: BomIndex) -> list[TrifectaAssessment]:
    return [assess_agent(index, agent.id) for agent in index.agents()]
