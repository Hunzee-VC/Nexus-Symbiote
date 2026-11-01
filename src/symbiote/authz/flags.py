"""Computed flags: three-valued summaries with cited inputs (``spec/agentbom-profile.md`` §3.16, ``checks.md`` §3).

A flag is ``unknown`` whenever an input it depends on is unknown; it never defaults to ``false``.
"""

from __future__ import annotations

from collections.abc import Iterable

from symbiote.authz.classify import approval_gate, is_open_world, side_effect_class
from symbiote.authz.graph import BomIndex
from symbiote.authz.trifecta import assess_all
from symbiote.model.document import AgentBOM
from symbiote.model.entities import Flag, Model, ToolDefinition, ToolServer
from symbiote.model.enums import (
    AliasPinning,
    ApprovalGate,
    AuthMode,
    CredentialKind,
    FlagName,
    ModelKind,
    SerializationRisk,
    SideEffectClass,
    SignatureStatus,
    SnapshotKind,
    TriState,
    ValueState,
)

__all__ = [
    "compute_flags",
    "destructive_open_world_ungated",
    "floating_model_alias",
    "static_long_lived_credential",
    "unauthenticated_tool_server",
    "undeclared_components",
    "unpinned_tool_server",
    "unsafe_serialization",
    "unsigned_model",
]


def _tri(value: bool | None) -> TriState:
    return TriState.UNKNOWN if value is None else (TriState.TRUE if value else TriState.FALSE)


def unpinned_tool_server(index: BomIndex, server: ToolServer) -> tuple[TriState, list[str]]:
    """True when the server's model-visible tool surface is not pinned by digests (SYM-TOOL-001/004)."""
    tools = index.tools_of_server(server.id)
    inputs = [server.id, *(t.id for t in tools)]
    if any(not t.digest.ok for t in tools):
        return TriState.TRUE, inputs
    toolset = server.toolset_digest
    if toolset is None or toolset.state is not ValueState.PRESENT:
        return TriState.TRUE, inputs
    return TriState.FALSE, inputs


def destructive_open_world_ungated(index: BomIndex, tool: ToolDefinition) -> tuple[TriState, list[str]]:
    """SYM-TOOL-003: destructive (or default-destructive) and open-world, with no required approval."""
    effect = side_effect_class(tool)
    open_world = is_open_world(tool)
    gate = approval_gate(tool, index.server_of(tool)).gate
    inputs = [tool.id, tool.server_ref]
    if effect not in (SideEffectClass.DESTRUCTIVE, SideEffectClass.UNKNOWN) or open_world is False:
        return TriState.FALSE, inputs
    if gate is ApprovalGate.REQUIRED:
        return TriState.FALSE, inputs
    if effect is SideEffectClass.DESTRUCTIVE and open_world is True and gate is ApprovalGate.NONE:
        return TriState.TRUE, inputs
    return TriState.UNKNOWN, inputs


def floating_model_alias(model: Model) -> tuple[TriState, list[str]]:
    hosted = model.hosted
    if hosted is None or hosted.state is not ValueState.PRESENT or hosted.value is None:
        return TriState.UNKNOWN, [model.id]
    pinning = hosted.value.alias_pinning
    if pinning is AliasPinning.FLOATING:
        return TriState.TRUE, [model.id]
    if pinning is AliasPinning.PINNED:
        return TriState.FALSE, [model.id]
    resolved = hosted.value.resolved_ref
    return (TriState.UNKNOWN if resolved.state is not ValueState.PRESENT else TriState.FALSE), [model.id]


def unsigned_model(model: Model) -> tuple[TriState, list[str]]:
    if model.signature is None:
        return TriState.TRUE, [model.id]
    return _tri(model.signature.status is not SignatureStatus.VERIFIED), [model.id]


def unsafe_serialization(model: Model) -> tuple[TriState, list[str]]:
    claim = model.serialization
    if claim is None or claim.state is not ValueState.PRESENT or claim.value is None:
        return TriState.UNKNOWN, [model.id]
    ser = claim.value
    if ser.risk_class is SerializationRisk.CODE_EXEC_ON_LOAD or ser.trust_remote_code is TriState.TRUE:
        return TriState.TRUE, [model.id]
    if (
        ser.trust_remote_code is TriState.UNKNOWN
        and ser.risk_class is SerializationRisk.NONE
        and not ser.formats
    ):
        return TriState.UNKNOWN, [model.id]
    return TriState.FALSE, [model.id]


def unauthenticated_tool_server(server: ToolServer) -> tuple[TriState, list[str]]:
    crosses = server.crosses_trust_boundary
    if crosses.state is ValueState.PRESENT and crosses.value is False:
        return TriState.FALSE, [server.id]
    auth = server.authentication
    if auth.state is not ValueState.PRESENT or auth.value is None:
        return TriState.UNKNOWN, [server.id]
    if auth.value.mode is AuthMode.NONE:
        return (TriState.TRUE if crosses.state is ValueState.PRESENT else TriState.UNKNOWN), [server.id]
    return TriState.FALSE, [server.id]


def static_long_lived_credential(index: BomIndex, binding_id: str) -> tuple[TriState, list[str]]:
    binding = index.get(binding_id)
    kind = getattr(binding, "credential_kind", CredentialKind.UNKNOWN)
    if kind is CredentialKind.STATIC_LONG_LIVED:
        return TriState.TRUE, [binding_id]
    if kind is CredentialKind.UNKNOWN:
        return TriState.UNKNOWN, [binding_id]
    return TriState.FALSE, [binding_id]


def undeclared_components(bom: AgentBOM, baseline: AgentBOM | None) -> tuple[TriState, list[str]]:
    """Observed tools, servers or sub-agents absent from the declared/approved ``baseline``."""
    if baseline is None:
        if bom.snapshot.kind in (SnapshotKind.DECLARED, SnapshotKind.APPROVED):
            return TriState.FALSE, []
        return TriState.UNKNOWN, []
    known = {e.id for _, e in baseline.iter_entities()}
    known_digests = {t.digest.value for t in baseline.tools if t.digest.value}
    extra: list[str] = []
    for tool in bom.tools:
        if tool.id not in known and (tool.digest.value is None or tool.digest.value not in known_digests):
            extra.append(tool.id)
    extra.extend(s.id for s in bom.tool_servers if s.id not in known)
    extra.extend(a.id for a in bom.agents if a.id not in known)
    return _tri(bool(extra)), sorted(extra)


def _flag(name: FlagName, subject: str, value: TriState, inputs: Iterable[str]) -> Flag:
    return Flag(flag=name, subject_ref=subject, value=value, inputs=sorted(dict.fromkeys(inputs)))


def compute_flags(
    bom: AgentBOM, *, baseline: AgentBOM | None = None, index: BomIndex | None = None
) -> list[Flag]:
    """All computed flags for ``bom`` in deterministic order."""
    index = index or BomIndex(bom)
    flags: list[Flag] = []
    for assessment in assess_all(index):
        flags.append(
            _flag(
                FlagName.LETHAL_TRIFECTA, assessment.agent_id, assessment.lethal_trifecta, assessment.inputs
            )
        )
        flags.append(
            _flag(
                FlagName.RULE_OF_TWO_VIOLATION, assessment.agent_id, assessment.rule_of_two, assessment.inputs
            )
        )
    for server in sorted(bom.tool_servers, key=lambda s: s.id):
        value, inputs = unpinned_tool_server(index, server)
        flags.append(_flag(FlagName.UNPINNED_TOOL, server.id, value, inputs))
        value, inputs = unauthenticated_tool_server(server)
        flags.append(_flag(FlagName.UNAUTHENTICATED_TOOL_SERVER, server.id, value, inputs))
    for tool in sorted(bom.tools, key=lambda t: t.id):
        value, inputs = destructive_open_world_ungated(index, tool)
        flags.append(_flag(FlagName.DESTRUCTIVE_OPEN_WORLD_UNGATED, tool.id, value, inputs))
    for model in sorted(bom.models, key=lambda m: m.id):
        if model.model_kind is ModelKind.HOSTED:
            value, inputs = floating_model_alias(model)
            flags.append(_flag(FlagName.FLOATING_MODEL_ALIAS, model.id, value, inputs))
        if (
            model.model_kind in (ModelKind.WEIGHTS, ModelKind.ADAPTER, ModelKind.EMBEDDING)
            and model.weights is not None
        ):
            value, inputs = unsigned_model(model)
            flags.append(_flag(FlagName.UNSIGNED_MODEL, model.id, value, inputs))
            value, inputs = unsafe_serialization(model)
            flags.append(_flag(FlagName.UNSAFE_SERIALIZATION, model.id, value, inputs))
    for binding in sorted(bom.credential_bindings, key=lambda c: c.id):
        value, inputs = static_long_lived_credential(index, binding.id)
        flags.append(_flag(FlagName.STATIC_LONG_LIVED_CREDENTIAL, binding.id, value, inputs))
    value, inputs = undeclared_components(bom, baseline)
    flags.append(_flag(FlagName.UNDECLARED_COMPONENT_OBSERVED, bom.subject, value, inputs))
    return flags
