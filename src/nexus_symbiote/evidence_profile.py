"""Per-component evidence profile (R1.1-8 / X9).

Reports concrete evidence attributes per component (pinned, digest-bound, signed under
policy, observed by a collector, reported at runtime, findings, and missing evidence),
never collapsing them into a scalar TrustScore.
"""

from __future__ import annotations

from typing import Any, Final

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, RiskSeverity
from nexus_symbiote.core.models import (
    AnyComponent,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    RegistryEntryComponent,
    ToolComponent,
)
from nexus_symbiote.utils.terminal import neutralize

EVIDENCE_PROFILE_SCHEMA: Final[str] = "nexus-symbiote/evidence-profile/v1"
_SEVERITY_RANK: Final[dict[RiskSeverity, int]] = {
    RiskSeverity.INFO: 1,
    RiskSeverity.LOW: 2,
    RiskSeverity.MEDIUM: 3,
    RiskSeverity.HIGH: 4,
    RiskSeverity.CRITICAL: 5,
}
_SIGNED_STATUSES: Final[frozenset[str]] = frozenset({"sigstore-signed", "digest-pinned"})


def _is_pinned(comp: AnyComponent) -> bool:
    if isinstance(comp, MCPServerComponent):
        return bool(comp.version_pinned)
    if isinstance(comp, RegistryEntryComponent):
        if comp.package_url or comp.hashes:
            return True
        if isinstance(comp.properties.get("version_pinned"), bool):
            return bool(comp.properties["version_pinned"])
    if isinstance(comp, ModelComponent):
        if comp.resolved_revision:
            return True
        return bool(comp.hashes)
    if (
        comp.version
        and comp.version not in {"latest", "main", "HEAD", "*"}
        and not any(op in comp.version for op in ("^", "~", ">", "<", "*"))
    ):
        return True
    return bool(comp.hashes)


def _is_digest_bound(comp: AnyComponent) -> bool:
    if comp.hashes:
        return True
    if isinstance(comp, ToolComponent) and comp.definition_hash:
        return True
    if isinstance(comp, MCPServerComponent) and comp.schema_hash:
        return True
    if isinstance(comp, PromptComponent) and comp.content_hash:
        return True
    return bool(
        isinstance(comp, ModelComponent)
        and (comp.safetensors_header_hash or comp.tensor_inventory_hash)
    )


def _is_signed_under_policy(comp: AnyComponent) -> bool:
    if comp.assurance_level == AssuranceLevel.VERIFIED:
        return True
    return bool(isinstance(comp, ModelComponent) and comp.signing_status in _SIGNED_STATUSES)


def _component_risks(comp: AnyComponent) -> list[Any]:
    risks = getattr(comp, "risks", None)
    return list(risks) if isinstance(risks, list) else []


def build_evidence_profile(
    aibom: AIBOM,
    *,
    runtime_matched_refs: set[str] | None = None,
) -> dict[str, Any]:
    """Compute a deterministic per-component evidence profile for an inventory."""
    matched = runtime_matched_refs or set()
    entries: list[dict[str, Any]] = []

    for comp in sorted(aibom.components, key=lambda c: c.bom_ref):
        pinned = _is_pinned(comp)
        digest_bound = _is_digest_bound(comp)
        signed = _is_signed_under_policy(comp)
        observed = comp.assurance_level in {AssuranceLevel.OBSERVED, AssuranceLevel.VERIFIED}
        reported_runtime = comp.bom_ref in matched or any(
            claim.assurance.value == "reported" or claim.method.startswith("otlp")
            for claim in comp.claims.values()
        )
        risks = _component_risks(comp)
        highest: str | None = None
        if risks:
            top = max(risks, key=lambda r: _SEVERITY_RANK.get(r.severity, 0))
            highest = top.severity.value

        missing: list[str] = []
        if not pinned:
            missing.append("pinned")
        if not digest_bound:
            missing.append("digest_bound")
        if not signed:
            missing.append("signed_under_policy")
        if not observed:
            missing.append("observed_by_collector")
        if not reported_runtime:
            missing.append("reported_at_runtime")

        entries.append(
            {
                "bom_ref": neutralize(comp.bom_ref),
                "name": neutralize(comp.name),
                "component_type": comp.component_type.value,
                "assurance_level": comp.assurance_level.value,
                "evidence": {
                    "pinned": pinned,
                    "digest_bound": digest_bound,
                    "signed_under_policy": signed,
                    "observed_by_collector": observed,
                    "reported_at_runtime": reported_runtime,
                },
                "finding_count": len(risks),
                "highest_finding_severity": highest,
                "missing_evidence": missing,
            }
        )

    return {
        "schema": EVIDENCE_PROFILE_SCHEMA,
        "component_count": len(entries),
        "components": entries,
    }
