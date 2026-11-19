"""Per-component evidence profile (R1.1-8 / X9)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from nexus_symbiote.core import models as m
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, RiskSeverity
from nexus_symbiote.utils.terminal import neutralize

if TYPE_CHECKING:
    from nexus_symbiote.utils.crypto import SignaturePolicySet

EVIDENCE_PROFILE_SCHEMA: Final[str] = "nexus-symbiote/evidence-profile/v1"
_SEVERITY_ORDER = (
    RiskSeverity.INFO,
    RiskSeverity.LOW,
    RiskSeverity.MEDIUM,
    RiskSeverity.HIGH,
    RiskSeverity.CRITICAL,
)
_SEVERITY_RANK: Final[dict[RiskSeverity, int]] = {s: i for i, s in enumerate(_SEVERITY_ORDER, 1)}
_EXACT_VERSION_RE: Final[re.Pattern[str]] = re.compile(
    r"v?[0-9]+(?:\.[0-9]+){0,3}(?:[-+._][0-9A-Za-z.-]+)?", re.ASCII
)
_COMMIT_HEX_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", re.ASCII)
_RANGE_CHARS: Final[frozenset[str]] = frozenset("^~><*!,| ")
_FLOATING_TAGS: Final[frozenset[str]] = frozenset(
    ["latest", "main", "master", "head", "nightly", "edge"]
)


def is_exact_version(version: str | None) -> bool:
    """Return True iff version names a single immutable release rather than a range or branch."""
    if not version:
        return False
    cleaned = version.strip()
    for pfx in ("===", "=="):
        if cleaned.startswith(pfx):
            cleaned = cleaned[len(pfx) :].strip()
            break
    if not cleaned or cleaned.lower() in _FLOATING_TAGS or any(c in cleaned for c in _RANGE_CHARS):
        return False
    return bool(_EXACT_VERSION_RE.fullmatch(cleaned))


def purl_has_exact_version(purl: str | None) -> bool:
    """Return True iff a Package URL carries an exact @version or @sha256:<64hex> qualifier."""
    if not purl or "@" not in purl:
        return False
    without_frag = purl.split("#", 1)[0].split("?", 1)[0]
    if "@" not in without_frag:
        return False
    ver_part = without_frag.rsplit("@", 1)[1]
    if ver_part.lower().startswith("sha256:") and len(ver_part) == 71:
        return bool(re.fullmatch(r"[0-9a-fA-F]{64}", ver_part[7:]))
    return is_exact_version(ver_part)


def _is_pinned(comp: m.AnyComponent) -> bool:
    if isinstance(comp, m.MCPServerComponent):
        return bool(comp.version_pinned)
    if isinstance(comp, m.RegistryEntryComponent):
        if comp.version is not None and not is_exact_version(comp.version):
            return False
        if isinstance(comp.properties.get("version_pinned"), bool):
            return bool(comp.properties["version_pinned"])
        return purl_has_exact_version(comp.package_url) or is_exact_version(comp.version)
    if (
        isinstance(comp, m.ModelComponent)
        and comp.resolved_revision
        and _COMMIT_HEX_RE.fullmatch(comp.resolved_revision)
    ):
        return True
    return is_exact_version(comp.version)


def _is_digest_bound(comp: m.AnyComponent) -> bool:
    if (
        comp.assurance_level == AssuranceLevel.DECLARED
        and "imported_source_format" in comp.properties
    ):
        binding = comp.properties.get("local_digest_binding")
        return isinstance(binding, str) and bool(binding)
    if any(isinstance(v, str) and bool(v) for v in comp.hashes.values()):
        return True
    if (isinstance(comp, m.ToolComponent) and comp.definition_hash) or (
        isinstance(comp, m.MCPServerComponent) and comp.schema_hash
    ):
        return True
    if isinstance(comp, m.PromptComponent) and comp.content_hash:
        return True
    return bool(
        isinstance(comp, m.ModelComponent)
        and (comp.safetensors_header_hash or comp.tensor_inventory_hash)
    )


def _verified_signed_refs(
    aibom: AIBOM, project_root: Path | None, signature_policies: SignaturePolicySet | None
) -> frozenset[str]:
    if (
        project_root is None
        or signature_policies is None
        or not (signature_policies or signature_policies.digest_pins)
    ):
        return frozenset()
    from nexus_symbiote.validators.integrity import IntegrityValidator

    report = IntegrityValidator(signature_policies, require_model_signatures=True).validate(
        aibom, project_root=project_root
    )
    failed = {issue.component_ref for issue in report.issues}
    return frozenset(
        c.bom_ref
        for c in aibom.components
        if isinstance(c, m.ModelComponent) and c.source_path and c.bom_ref not in failed
    )


def build_evidence_profile(
    aibom: AIBOM,
    *,
    runtime_matched_refs: set[str] | None = None,
    project_root: Path | None = None,
    signature_policies: SignaturePolicySet | None = None,
) -> dict[str, Any]:
    """Compute a deterministic per-component evidence profile without a scalar TrustScore."""
    matched = runtime_matched_refs or set()
    verified_refs = _verified_signed_refs(aibom, project_root, signature_policies)
    entries: list[dict[str, Any]] = []

    for comp in sorted(aibom.components, key=lambda c: c.bom_ref):
        obs = comp.assurance_level in {AssuranceLevel.OBSERVED, AssuranceLevel.VERIFIED}
        rep = comp.bom_ref in matched or any(
            cl.assurance.value == "reported" or cl.method.startswith("otlp")
            for cl in comp.claims.values()
        )
        evidence = {
            "pinned": _is_pinned(comp),
            "digest_bound": _is_digest_bound(comp),
            "signed_under_policy": comp.bom_ref in verified_refs,
            "observed_by_collector": obs,
            "reported_at_runtime": rep,
        }
        raw_risks = getattr(comp, "risks", None)
        risks = list(raw_risks) if isinstance(raw_risks, list) else []
        highest = (
            max(risks, key=lambda r: _SEVERITY_RANK.get(r.severity, 0)).severity.value
            if risks
            else None
        )
        entry: dict[str, Any] = {
            "bom_ref": neutralize(comp.bom_ref),
            "name": neutralize(comp.name),
            "component_type": comp.component_type.value,
            "assurance_level": comp.assurance_level.value,
            "evidence": evidence,
            "finding_count": len(risks),
            "highest_finding_severity": highest,
            "missing_evidence": [k for k, v in evidence.items() if not v],
        }
        if isinstance(comp, m.ModelComponent) and comp.signing_status:
            entry["declared_signing_status"] = neutralize(comp.signing_status)
        entries.append(entry)

    return {
        "schema": EVIDENCE_PROFILE_SCHEMA,
        "policy_verified": signature_policies is not None and project_root is not None,
        "component_count": len(entries),
        "components": entries,
    }
