"""Model checks ``SYM-MODEL-*`` (``spec/checks.md`` §2 and §2.1 extensions)."""

from __future__ import annotations

from collections.abc import Iterator

from symbiote.authz.flags import floating_model_alias, unsafe_serialization
from symbiote.model.entities import Finding, Model
from symbiote.model.enums import (
    FindingState,
    ModelKind,
    SerializationRisk,
    Severity,
    SignatureOutcome,
    SignatureStatus,
    TriState,
)
from symbiote.policy.spec import CheckSpec, PolicyContext, asi, atlas, check

_WEIGHTS_KINDS = (ModelKind.WEIGHTS, ModelKind.ADAPTER, ModelKind.EMBEDDING)


def _is_weights(model: Model) -> bool:
    return model.model_kind in _WEIGHTS_KINDS and model.weights is not None


@check(
    "SYM-MODEL-001",
    "Floating hosted-model alias",
    Severity.MEDIUM,
    mappings=(asi(4), atlas("AML.T0010")),
    inputs=("models[].hosted.alias_pinning", "models[].hosted.resolved_ref"),
    remediation="Request a dated or versioned snapshot id (for example claude-sonnet-4-5-20250929, gpt-4o-2024-08-06) and re-run evaluations when you move it.",
)
def floating_alias(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """alias_pinning = floating, or resolved_ref unknown with no fingerprint."""
    for model in ctx.bom.models:
        if model.model_kind is not ModelKind.HOSTED:
            continue
        value, inputs = floating_model_alias(model)
        hosted = model.hosted.value if model.hosted is not None else None
        requested = hosted.requested_ref if hosted else model.name
        if value is TriState.TRUE:
            yield spec.finding(
                ctx,
                subjects=[model.id],
                inputs=inputs,
                message=f"Model {requested!r} is an alias the provider can repoint without notice.",
            )
        elif value is TriState.UNKNOWN and not (hosted and hosted.fingerprint):
            yield spec.finding(
                ctx,
                subjects=[model.id],
                inputs=inputs,
                state=FindingState.INDETERMINATE,
                message=f"Model {requested!r}: whether this id is a pinned snapshot is unknown.",
            )


@check(
    "SYM-MODEL-002",
    "Unsafe model serialization",
    Severity.CRITICAL,
    mappings=(asi(5), atlas("AML.T0010")),
    inputs=("models[].serialization",),
    remediation="Convert weights to safetensors, load with trust_remote_code=False and torch.load(weights_only=True), and treat chat templates as code (sandboxed Jinja, pinned digests).",
)
def unsafe_serial(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """risk_class = code-exec-on-load or trust_remote_code (critical); executable chat template (medium)."""
    for model in ctx.bom.models:
        if model.serialization is None or model.serialization.value is None:
            continue
        ser = model.serialization.value
        value, inputs = unsafe_serialization(model)
        if value is TriState.TRUE:
            why = (
                "loads remote code"
                if ser.trust_remote_code is TriState.TRUE
                else f"uses {', '.join(f.value for f in ser.formats) or 'an executable format'}"
            )
            yield spec.finding(
                ctx,
                subjects=[model.id],
                inputs=inputs,
                message=f"Model {model.name or model.id!r} executes code on load: it {why}.",
            )
        elif (
            ser.chat_template_executable is TriState.TRUE
            or ser.risk_class is SerializationRisk.TEMPLATE_EXECUTION
        ):
            yield spec.finding(
                ctx,
                subjects=[model.id],
                inputs=inputs,
                severity=Severity.MEDIUM,
                message=f"Model {model.name or model.id!r} ships an executable Jinja chat template.",
            )


@check(
    "SYM-MODEL-003",
    "Model not verified",
    Severity.HIGH,
    mappings=(asi(4),),
    inputs=("models[].signature",),
    remediation="Sign models with OpenSSF Model Signing and verify against a pinned signer identity and issuer before load; re-sign third-party models after internal admission.",
)
def not_verified(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """signature.status ≠ verified (signature-valid-unconstrained is named explicitly)."""
    for model in ctx.bom.models:
        if not _is_weights(model):
            continue
        sig = model.signature
        if sig is None or sig.status is SignatureStatus.UNSIGNED:
            yield spec.finding(
                ctx, subjects=[model.id], message=f"Model {model.name or model.id!r} is unsigned."
            )
        elif sig.status is not SignatureStatus.VERIFIED:
            detail = (
                "has a valid signature from an unconstrained signer (anyone could have signed it)"
                if sig.outcome is SignatureOutcome.SIGNATURE_VALID_UNCONSTRAINED
                else f"signature {sig.status.value} ({sig.outcome.value})"
            )
            yield spec.finding(
                ctx, subjects=[model.id], message=f"Model {model.name or model.id!r} {detail}."
            )


@check(
    "SYM-MODEL-004",
    "Unknown parent in model lineage",
    Severity.MEDIUM,
    mappings=(atlas("AML.T0010"),),
    inputs=("models[].derivations",),
    remediation="Record the base model (repo and commit) for every fine-tune, adapter, merge and quantization; a merge can smuggle in a poisoned parent.",
)
def unknown_parent(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A derivation whose parent is unknown."""
    for model in ctx.bom.models:
        unknown = [d for d in model.derivations if d.parent_state == "unknown" or d.parent in {"", "unknown"}]
        if unknown:
            kinds = sorted({d.kind.value for d in unknown})
            yield spec.finding(
                ctx,
                subjects=[model.id],
                message=f"Model {model.name or model.id!r} has derivations with unknown parents: {', '.join(kinds)}.",
            )


@check(
    "SYM-MODEL-005",
    "Malicious indicators in model artefacts",
    Severity.CRITICAL,
    mappings=(asi(5), atlas("AML.T0010"), atlas("AML.T0018")),
    inputs=("models[].tags", "models[].serialization.scanner_report_digest"),
    remediation="Quarantine the artefact and do not load it: the scanner found imports of os/subprocess/exec-style callables, a deliberately broken pickle, or template-injection gadgets.",
    extension=True,
)
def malicious_indicators(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Scanner indicators recorded by the models-local collector (``malicious-indicator:*`` tags)."""
    for model in ctx.bom.models:
        hits = sorted(t.split(":", 1)[1] for t in model.tags if t.startswith("malicious-indicator:"))
        if hits:
            yield spec.finding(
                ctx, subjects=[model.id], message=f"Model {model.name or model.id!r}: {', '.join(hits[:6])}."
            )


@check(
    "SYM-MODEL-006",
    "Structural anomalies in a weights file",
    Severity.MEDIUM,
    mappings=(asi(4),),
    inputs=("models[].tags",),
    remediation="Re-download from the source of record and compare digests; malformed headers can exploit loader parsing differences.",
    extension=True,
)
def structural_anomalies(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """safetensors/GGUF header anomalies recorded by the collector (``format-anomaly:*`` tags)."""
    for model in ctx.bom.models:
        hits = sorted(t.split(":", 1)[1] for t in model.tags if t.startswith("format-anomaly:"))
        if hits:
            yield spec.finding(
                ctx,
                subjects=[model.id],
                message=f"Model {model.name or model.id!r} has malformed weights metadata: {', '.join(hits[:6])}.",
            )


@check(
    "SYM-MODEL-007",
    "Model API traffic redirected by repository configuration",
    Severity.HIGH,
    mappings=(asi(4), asi(3), atlas("AML.T0010")),
    inputs=("models[].hosted.endpoint_origin", "models[].tags"),
    remediation=(
        "Remove base-URL overrides (ANTHROPIC_BASE_URL, OPENAI_BASE_URL, api_base) from files the repository "
        "ships; configure gateways in user or managed settings, and review any project file that changes where "
        "the agent sends prompts and API keys before trusting a checkout."
    ),
    extension=True,
)
def endpoint_redirected(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A project-scoped setting points a hosted model's API traffic at a host that is not the provider's.

    Anyone who can commit to the repository can then receive the prompts and the credential that authenticates
    them (the class of CVE-2025-59536 and CVE-2026-21852). User-scope overrides are deliberate and not flagged.
    """
    for model in ctx.bom.models:
        if "endpoint-override:project" not in model.tags:
            continue
        hosted = model.hosted.value if model.hosted is not None else None
        origin = hosted.endpoint_origin if hosted is not None else None
        yield spec.finding(
            ctx,
            subjects=[model.id],
            message=(
                f"Model {model.name or model.id!r}: a file in the repository sends its API traffic, and the key "
                f"that authenticates it, to {origin or 'a host that is not the provider'}."
            ),
        )
