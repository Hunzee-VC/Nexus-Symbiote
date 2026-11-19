"""SPDX 3.0.1 AI & Dataset profile helpers, ISO/IEC 22989 mapping, and agent.yaml 1.1 declarations."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import yaml

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import AssuranceLevel, AutonomyLevel, RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import (
    AgentComponent,
    AnyComponent,
    ClaimEvidence,
    DataSourceComponent,
    ModelComponent,
    RiskAssessment,
)
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import redact_text, redact_url
from nexus_symbiote.utils.terminal import neutralize

MAX_AGENT_YAML_BYTES: Final[int] = 256 * 1024
_RFC3339_RE: Final[re.Pattern[str]] = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})",
    re.ASCII,
)
_SAFE_LICENSE_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9.()+\- ]{1,128}", re.ASCII)
_SAFE_URL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:https|s3|gs|hf|oci)://[^\s<>\"'\\]+",
    re.ASCII,
)
_SPDX_DATASET_TYPES: Final[frozenset[str]] = frozenset(
    {
        "audio",
        "categorical",
        "graph",
        "image",
        "noAssertion",
        "numeric",
        "other",
        "sensor",
        "structured",
        "syntactic",
        "text",
        "timeseries",
        "timestamp",
        "video",
    }
)
_SPDX_AVAILABILITY_TYPES: Final[frozenset[str]] = frozenset(
    {"clickthrough", "directDownload", "query", "registration", "scrapingScript"}
)


@dataclass(frozen=True)
class AutomationLevelMapping:
    """Canonical mapping across SymBiote L0..L4, ShadowScan 0..5, ISO/IEC 22989, and SPDX AI."""

    iso_name: str
    symbiote_level: AutonomyLevel
    shadowscan_level: int
    spdx_autonomy_presence: str


ISO_22989_AUTOMATION_TABLE: Final[tuple[AutomationLevelMapping, ...]] = (
    AutomationLevelMapping("no_automation", AutonomyLevel.L0_CHATBOT, 0, "no"),
    AutomationLevelMapping("assistance", AutonomyLevel.L1_COPILOT, 1, "yes"),
    AutomationLevelMapping("partial_automation", AutonomyLevel.L1_COPILOT, 2, "yes"),
    AutomationLevelMapping("conditional_automation", AutonomyLevel.L2_AGENT, 3, "yes"),
    AutomationLevelMapping("high_automation", AutonomyLevel.L3_AUTONOMOUS, 4, "yes"),
    AutomationLevelMapping("full_automation", AutonomyLevel.L4_FULLY_AUTONOMOUS, 5, "yes"),
)

_BY_SYMBIOTE: Final[dict[AutonomyLevel, AutomationLevelMapping]] = {
    # L1_COPILOT maps deterministically to partial_automation when reverse-mapped from SymBiote's 5-level enum.
    AutonomyLevel.L0_CHATBOT: ISO_22989_AUTOMATION_TABLE[0],
    AutonomyLevel.L1_COPILOT: ISO_22989_AUTOMATION_TABLE[2],
    AutonomyLevel.L2_AGENT: ISO_22989_AUTOMATION_TABLE[3],
    AutonomyLevel.L3_AUTONOMOUS: ISO_22989_AUTOMATION_TABLE[4],
    AutonomyLevel.L4_FULLY_AUTONOMOUS: ISO_22989_AUTOMATION_TABLE[5],
}
_BY_SHADOWSCAN: Final[dict[int, AutomationLevelMapping]] = {
    row.shadowscan_level: row for row in ISO_22989_AUTOMATION_TABLE
}
_BY_ISO_NAME: Final[dict[str, AutomationLevelMapping]] = {
    row.iso_name: row for row in ISO_22989_AUTOMATION_TABLE
}


def resolve_automation_mapping(
    value: AutonomyLevel | int | str | None,
) -> AutomationLevelMapping | None:
    """Resolve an ISO/IEC 22989, SymBiote L0..L4 / L0-chatbot..L4-fully-autonomous, or ShadowScan 0..5 level."""
    if value is None:
        return None
    if isinstance(value, AutonomyLevel):
        return _BY_SYMBIOTE.get(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return _BY_SHADOWSCAN.get(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned in _BY_ISO_NAME:
            return _BY_ISO_NAME[cleaned]
        upper = cleaned.upper()
        for level in AutonomyLevel:
            if level.value.upper() == upper or level.value.split("-", 1)[0].upper() == upper:
                return _BY_SYMBIOTE[level]
        if cleaned.isdigit():
            return _BY_SHADOWSCAN.get(int(cleaned))
    return None


def spdx_autonomy_presence(comp: AnyComponent) -> str:
    """Return SPDX 3.0.1 PresenceType ('yes', 'no', or 'noAssertion') for an AI component."""
    declared_iso = comp.properties.get("iso_22989_automation")
    if isinstance(declared_iso, str):
        mapped = resolve_automation_mapping(declared_iso)
        if mapped is not None:
            return mapped.spdx_autonomy_presence
    if isinstance(comp, AgentComponent) and comp.autonomy_level is not None:
        mapped = resolve_automation_mapping(comp.autonomy_level)
        if mapped is not None:
            return mapped.spdx_autonomy_presence
    return "noAssertion"


def normalize_spdx_dataset_type(raw: str | None) -> str:
    """Map native or producer dataset_type strings to valid SPDX 3.0.1 DatasetType values."""
    if not raw:
        return "noAssertion"
    cleaned = raw.strip()
    if cleaned in _SPDX_DATASET_TYPES:
        return cleaned
    lowered = cleaned.lower()
    alias_map = {
        "pre-training": "text",
        "fine-tuning": "text",
        "evaluation": "structured",
        "alignment": "text",
        "tabular": "structured",
    }
    return alias_map.get(lowered, "other")


def _clean_text(value: Any, *, max_len: int = 512) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    cleaned = neutralize(redact_text(value.strip()))
    return cleaned[:max_len] if cleaned else None


def _clean_url(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    redacted = redact_url(value.strip())
    if "@" in redacted.split("://", 1)[-1].split("/", 1)[0]:
        return None
    return redacted if _SAFE_URL_RE.fullmatch(redacted) else None


def _clean_rfc3339(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if len(candidate) == 10 and re.fullmatch(r"\d{4}-\d{2}-\d{2}", candidate, re.ASCII):
        candidate = f"{candidate}T00:00:00Z"
    return candidate if _RFC3339_RE.fullmatch(candidate) else None


def _clean_license(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    return candidate if _SAFE_LICENSE_RE.fullmatch(candidate) else None


def _conflict_risk(field_name: str, component_name: str, locator: str) -> RiskAssessment:
    return RiskAssessment(
        severity=RiskSeverity.MEDIUM,
        category="declaration_conflict",
        detail=(
            f"Producer declaration in {locator} conflicts with collected '{field_name}' "
            f"on component '{neutralize(component_name)}'."
        ),
        recommendation=(
            f"Align {locator} with the repository's collected artifacts; producer declarations "
            "do not override observed collector evidence."
        ),
    )


def _record_claim(comp: AnyComponent, key: str, locator: str) -> None:
    comp.claims[f"declaration.{key}"] = ClaimEvidence(
        assurance=AssuranceLevel.DECLARED,
        method="agent-yaml-1.1",
        scope=key,
        locator=locator,
    )


def apply_agent_yaml_declarations(
    aibom: AIBOM,
    project_root: Path,
    *,
    explicit_path: Path | None = None,
    relative_path: str | None = None,
) -> list[str]:
    """Read producer declarations from agent.yaml 1.1 as DECLARED claims without overriding observed values.

    Returns neutralized diagnostic notices for any declaration conflicts detected.
    """
    failures: list[str] = []
    notices: list[str] = []
    raw_bytes: bytes | None = None
    locator = "agent.yaml"

    if explicit_path is not None:
        from nexus_symbiote.core.hashing import open_regular_file

        with open_regular_file(explicit_path) as handle:
            raw_bytes = handle.read(MAX_AGENT_YAML_BYTES + 1)
        if len(raw_bytes) > MAX_AGENT_YAML_BYTES:
            raise ValueError("agent.yaml exceeds maximum size limit (256 KiB)")
        locator = explicit_path.name
    else:
        candidates = (relative_path,) if relative_path is not None else ("agent.yaml", "agent.yml")
        with ConfinedCollection(project_root, failures) as files:
            for candidate in candidates:
                data = files.read_bytes(candidate, missing_ok=(relative_path is None))
                if data is not None:
                    if len(data) > MAX_AGENT_YAML_BYTES:
                        raise ValueError(f"{candidate} exceeds maximum size limit (256 KiB)")
                    raw_bytes = data
                    locator = candidate
                    break
        if relative_path is not None and (failures or raw_bytes is None):
            raise ValueError(f"cannot safely read {neutralize(relative_path)} inside project root")

    if raw_bytes is None:
        return notices

    parsed = yaml.safe_load(raw_bytes.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"{locator} must hold a YAML mapping")

    doc_digest = hash_bytes(raw_bytes)
    owner = _clean_text(parsed.get("owner"), max_len=200)
    data_usage = _clean_text(parsed.get("data_usage"), max_len=512)
    raw_compliance = parsed.get("compliance")
    compliance_list = (
        [c for item in raw_compliance if (c := _clean_text(item, max_len=128)) is not None]
        if isinstance(raw_compliance, list)
        else []
    )
    raw_regions = parsed.get("allowed_regions")
    allowed_regions = (
        [r for item in raw_regions if (r := _clean_text(item, max_len=64)) is not None]
        if isinstance(raw_regions, list)
        else []
    )
    raw_licenses = parsed.get("licenses")
    default_license = (
        _clean_license(raw_licenses[0])
        if isinstance(raw_licenses, list) and raw_licenses
        else _clean_license(raw_licenses)
    )
    iso_level = resolve_automation_mapping(parsed.get("automation_level"))

    for comp in aibom.components:
        if isinstance(comp, AgentComponent):
            if owner:
                if comp.supplier and comp.supplier != owner:
                    comp.risks.append(_conflict_risk("supplier", comp.name, locator))
                    notices.append(f"{comp.bom_ref}: supplier conflict with {locator}")
                elif not comp.supplier:
                    comp.supplier = owner
                _record_claim(comp, "owner", locator)
            if data_usage:
                comp.properties["declared_data_usage"] = data_usage
                _record_claim(comp, "data_usage", locator)
            if compliance_list:
                comp.properties["declared_compliance"] = compliance_list
                _record_claim(comp, "compliance", locator)
            if allowed_regions:
                comp.properties["allowed_regions"] = allowed_regions
                _record_claim(comp, "allowed_regions", locator)
            if default_license and "declared_license" not in comp.properties:
                comp.properties["declared_license"] = default_license
                _record_claim(comp, "license", locator)
            if iso_level is not None:
                if (
                    comp.autonomy_level is not None
                    and comp.autonomy_level != iso_level.symbiote_level
                ):
                    comp.risks.append(_conflict_risk("autonomy_level", comp.name, locator))
                    notices.append(f"{comp.bom_ref}: autonomy_level conflict with {locator}")
                comp.properties["iso_22989_automation"] = iso_level.iso_name
                _record_claim(comp, "automation_level", locator)
            for extra_key in ("release_time", "download_location", "version"):
                raw_val = parsed.get(extra_key)
                if extra_key == "release_time" and (ts := _clean_rfc3339(raw_val)):
                    comp.properties.setdefault("declared_release_time", ts)
                elif extra_key == "download_location" and (dl := _clean_url(raw_val)):
                    comp.properties.setdefault("declared_download_location", dl)
                elif extra_key == "version" and (ver := _clean_text(raw_val, max_len=128)):
                    if comp.version and comp.version != ver:
                        comp.risks.append(_conflict_risk("version", comp.name, locator))
                        notices.append(f"{comp.bom_ref}: version conflict with {locator}")
                    elif not comp.version:
                        comp.version = ver

    by_name: dict[str, AnyComponent] = {c.name: c for c in aibom.components}

    raw_datasets = parsed.get("datasets")
    dataset_refs_by_name: dict[str, str] = {}
    if isinstance(raw_datasets, list):
        for entry in raw_datasets[:200]:
            if not isinstance(entry, dict):
                continue
            ds_name = _clean_text(entry.get("name"), max_len=200)
            if not ds_name:
                continue
            existing = by_name.get(ds_name)
            ds_ver = _clean_text(entry.get("version"), max_len=128)
            ds_sup = _clean_text(entry.get("supplier"), max_len=200) or owner
            ds_lic = _clean_license(entry.get("license")) or default_license
            ds_uri = _clean_url(entry.get("download_location") or entry.get("source_uri"))
            ds_rel = _clean_rfc3339(entry.get("release_time") or entry.get("collection_date"))
            ds_type = _clean_text(entry.get("dataset_type"), max_len=64)
            ds_avail = _clean_text(entry.get("availability"), max_len=64)
            ds_pii = entry.get("sensitive_personal_information")

            if isinstance(existing, DataSourceComponent):
                ds_comp = existing
                if ds_ver and ds_comp.version and ds_comp.version != ds_ver:
                    ds_comp.risks.append(_conflict_risk("version", ds_name, locator))
                    notices.append(f"{ds_comp.bom_ref}: version conflict with {locator}")
                elif ds_ver and not ds_comp.version:
                    ds_comp.version = ds_ver
                if ds_lic and ds_comp.license and ds_comp.license != ds_lic:
                    ds_comp.risks.append(_conflict_risk("license", ds_name, locator))
                    notices.append(f"{ds_comp.bom_ref}: license conflict with {locator}")
                elif ds_lic and not ds_comp.license:
                    ds_comp.license = ds_lic
            else:
                digest_id = hashlib.sha256(ds_name.encode("utf-8")).hexdigest()[:16]
                ds_comp = DataSourceComponent(
                    bom_ref=f"dataset:declared:{digest_id}",
                    name=ds_name,
                    version=ds_ver,
                    supplier=ds_sup,
                    source_path=locator,
                    dataset_type=ds_type,
                    source_uri=ds_uri,
                    collection_date=ds_rel,
                    license=ds_lic,
                    assurance_level=AssuranceLevel.DECLARED,
                    trust_tier=TrustTier.UNKNOWN,
                )
                aibom.components.append(ds_comp)
                by_name[ds_name] = ds_comp

            if ds_sup and not ds_comp.supplier:
                ds_comp.supplier = ds_sup
            if ds_rel:
                ds_comp.properties["declared_release_time"] = ds_rel
            if ds_uri:
                ds_comp.properties["declared_download_location"] = ds_uri
            if ds_lic:
                ds_comp.properties["declared_license"] = ds_lic
            if ds_avail in _SPDX_AVAILABILITY_TYPES:
                ds_comp.properties["declared_availability"] = ds_avail
            if ds_pii in {"yes", "no", "noAssertion"}:
                ds_comp.properties["declared_sensitive_pii"] = ds_pii
            ds_comp.properties["declaration_source_sha256"] = doc_digest
            _record_claim(ds_comp, "dataset", locator)
            dataset_refs_by_name[ds_name] = ds_comp.bom_ref

    raw_models = parsed.get("models")
    if isinstance(raw_models, list):
        for entry in raw_models[:200]:
            if not isinstance(entry, dict):
                continue
            m_name = _clean_text(entry.get("name"), max_len=200)
            if not m_name:
                continue
            existing = by_name.get(m_name)
            m_ver = _clean_text(entry.get("version"), max_len=128)
            m_sup = _clean_text(entry.get("supplier"), max_len=200) or owner
            m_lic = _clean_license(entry.get("license")) or default_license
            m_dl = _clean_url(entry.get("download_location"))
            m_rel = _clean_rfc3339(entry.get("release_time"))
            m_domain = _clean_text(entry.get("domain"), max_len=128)
            training = entry.get("training")

            if isinstance(existing, ModelComponent):
                m_comp = existing
                if m_ver and m_comp.version and m_comp.version != m_ver:
                    m_comp.risks.append(_conflict_risk("version", m_name, locator))
                    notices.append(f"{m_comp.bom_ref}: version conflict with {locator}")
                elif m_ver and not m_comp.version:
                    m_comp.version = m_ver
                if m_sup and m_comp.supplier and m_comp.supplier != m_sup:
                    m_comp.risks.append(_conflict_risk("supplier", m_name, locator))
                    notices.append(f"{m_comp.bom_ref}: supplier conflict with {locator}")
                elif m_sup and not m_comp.supplier:
                    m_comp.supplier = m_sup
            else:
                digest_id = hashlib.sha256(m_name.encode("utf-8")).hexdigest()[:16]
                m_comp = ModelComponent(
                    bom_ref=f"model:declared:{digest_id}",
                    name=m_name,
                    version=m_ver,
                    supplier=m_sup,
                    source_path=locator,
                    model_type=_clean_text(entry.get("model_type"), max_len=64) or "foundation",
                    assurance_level=AssuranceLevel.DECLARED,
                    trust_tier=TrustTier.UNKNOWN,
                )
                aibom.components.append(m_comp)
                by_name[m_name] = m_comp

            if m_lic:
                prev_lic = m_comp.properties.get("declared_license")
                if isinstance(prev_lic, str) and prev_lic != m_lic:
                    m_comp.risks.append(_conflict_risk("license", m_name, locator))
                    notices.append(f"{m_comp.bom_ref}: license conflict with {locator}")
                else:
                    m_comp.properties["declared_license"] = m_lic
            if m_rel:
                m_comp.properties["declared_release_time"] = m_rel
            if m_dl:
                m_comp.properties["declared_download_location"] = m_dl
            if m_domain:
                m_comp.properties["declared_domain"] = m_domain
            if compliance_list:
                m_comp.properties.setdefault("declared_compliance", compliance_list)
            if isinstance(training, dict):
                summary = _clean_text(training.get("description") or training.get("method"))
                if summary:
                    m_comp.properties["declared_training_info"] = summary
                ds_list = training.get("datasets")
                if isinstance(ds_list, list):
                    for ds_ref_name in ds_list[:50]:
                        clean_ds = _clean_text(ds_ref_name, max_len=200)
                        if clean_ds and clean_ds in dataset_refs_by_name:
                            edge = DependencyEdge(
                                source_ref=m_comp.bom_ref,
                                target_ref=dataset_refs_by_name[clean_ds],
                                relationship="trained-on",
                            )
                            if edge not in aibom.dependencies:
                                aibom.dependencies.append(edge)
            m_comp.properties["declaration_source_sha256"] = doc_digest
            _record_claim(m_comp, "model", locator)

    return notices
