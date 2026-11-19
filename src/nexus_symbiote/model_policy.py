"""Model governance policy enforcement: pinning, licenses, trust_remote_code, and AIROM retirement.

Evaluates ModelComponent records in a native AgentBOM offline against operator-owned
policies and an offline AIROM-style model retirement catalog. Dated provider snapshot
identifiers (such as ``gpt-4o-2024-08-06`` or ``claude-sonnet-4-20250514``) and
cryptographic digests pass pinning checks cleanly while floating aliases fail closed.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import SerializationSafety
from nexus_symbiote.core.hashing import hash_bytes, open_regular_file, parse_json_strict
from nexus_symbiote.core.models import ModelComponent

RETIREMENT_CATALOG_FORMAT: Literal["nexus-symbiote/model-retirement-catalog/v1"] = (
    "nexus-symbiote/model-retirement-catalog/v1"
)
POLICY_FORMAT: Literal["nexus-symbiote/model-governance-policy/v1"] = (
    "nexus-symbiote/model-governance-policy/v1"
)
MAX_POLICY_BYTES = 2 * 1024 * 1024
MAX_CATALOG_BYTES = 8 * 1024 * 1024
MAX_KEY_BYTES = 64 * 1024
MAX_CATALOG_ENTRIES = 50_000

_SHA256_RE = re.compile(r"(?:^|@)sha256:[0-9a-f]{64}$", re.IGNORECASE)
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_ISO_DATE_SNAPSHOT_RE = re.compile(
    r"(?:^|[-_/@])20\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$"
)
_COMPACT_DATE_SNAPSHOT_RE = re.compile(
    r"(?:^|[-_/@])20\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])$"
)
_NUMBERED_SNAPSHOT_RE = re.compile(r"-(?:00[1-9]|0[1-9]\d|[1-9]\d{2})$")
_FLOATING_TAGS = frozenset(
    {"latest", "main", "master", "head", "default", "edge", "nightly", "canary"}
)
_FLOATING_SUFFIXES = (":latest", "-latest", "@latest", "-preview", "-exp", "-nightly")
_UNKNOWN_LITERALS = frozenset({"", "unknown", "none", "n/a", "na", "noassertion", "unspecified"})


class ModelPolicyError(ValueError):
    """Raised when a model governance policy, retirement catalog, key, or attestation is unsafe."""


class ModelPolicyWaiver(BaseModel):
    """Time-bounded operator waiver evaluated strictly against wall-clock UTC time."""

    model_config = ConfigDict(extra="forbid")

    rule: str = Field(min_length=1, max_length=128)
    model_ref: str = Field(min_length=1, max_length=512)
    owner: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=1_024)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def _require_tz(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("waiver expires_at must include an explicit UTC/timezone offset")
        return value.astimezone(UTC)


class ModelGovernancePolicy(BaseModel):
    """Operator-owned governance policy for models in an AgentBOM."""

    model_config = ConfigDict(extra="forbid")

    format: Literal["nexus-symbiote/model-governance-policy/v1"] = POLICY_FORMAT
    require_pinned_revision: bool = True
    require_known_license: bool = True
    allowed_licenses: list[str] = Field(default_factory=list)
    denied_licenses: list[str] = Field(default_factory=list)
    forbid_trust_remote_code: bool = True
    require_known_trust_remote_code: bool = False
    forbid_unsafe_serialization: bool = True
    retirement_warn_days: int = Field(default=90, ge=0, le=3_650)
    waivers: list[ModelPolicyWaiver] = Field(default_factory=list)


class ModelRetirementEntry(BaseModel):
    """One offline AIROM-style model lifecycle/retirement record."""

    model_config = ConfigDict(extra="forbid")

    model_id: str = Field(min_length=1, max_length=256)
    aliases: list[str] = Field(default_factory=list)
    provider: str | None = None
    status: Literal["active", "deprecated", "retired"]
    deprecated_date: date | None = None
    sunset_date: date | None = None
    replacement: str | None = None
    advisory_url: str | None = None


class ModelRetirementCatalog(BaseModel):
    """Offline AIROM-compatible model retirement and deprecation catalog."""

    model_config = ConfigDict(extra="forbid")

    format: Literal["nexus-symbiote/model-retirement-catalog/v1"] = RETIREMENT_CATALOG_FORMAT
    catalog_version: str = Field(min_length=1, max_length=64)
    source: str = Field(default="airom-offline", max_length=256)
    models: list[ModelRetirementEntry] = Field(default_factory=list)

    @field_validator("models")
    @classmethod
    def _bounded(cls, value: list[ModelRetirementEntry]) -> list[ModelRetirementEntry]:
        if len(value) > MAX_CATALOG_ENTRIES:
            raise ValueError(f"catalog exceeds {MAX_CATALOG_ENTRIES} entries")
        return value


@dataclass(frozen=True)
class ModelPolicyFinding:
    """One deterministic model governance violation."""

    rule: str
    severity: Literal["critical", "high", "medium", "low"]
    model_ref: str
    model_name: str
    detail: str
    recommendation: str | None = None
    observed_value: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ModelPolicyReport:
    """Result of evaluating an AgentBOM against ModelGovernancePolicy + optional retirement catalog."""

    passed: bool
    models_checked: int
    findings: tuple[ModelPolicyFinding, ...]
    waived_count: int
    expired_waiver_count: int
    policy_sha256: str
    policy_attested: bool
    catalog_sha256: str | None = None
    catalog_attested: bool = False
    evaluated_date_utc: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "nexus-symbiote/model-policy-report/v1",
            "passed": self.passed,
            "models_checked": self.models_checked,
            "finding_count": len(self.findings),
            "waived_count": self.waived_count,
            "expired_waiver_count": self.expired_waiver_count,
            "policy_sha256": self.policy_sha256,
            "policy_attested": self.policy_attested,
            "catalog_sha256": self.catalog_sha256,
            "catalog_attested": self.catalog_attested,
            "evaluated_date_utc": self.evaluated_date_utc,
            "findings": [f.to_dict() for f in self.findings],
        }


def _repo_roots(path: Path) -> list[Path]:
    return [cand for cand in (path, *path.parents) if os.path.lexists(cand / ".git")]


def _safe_stat(path: Path) -> os.stat_result | None:
    try:
        return path.stat()
    except OSError:
        return None


def ensure_outside_project(
    target: Path,
    project_root: Path | None,
    *,
    inventory_path: Path | None = None,
    label: str = "Policy file",
) -> None:
    """Refuse operator-owned policy, catalog, attestation, or key files inside the project tree."""
    resolved = target.resolve()
    untrusted: list[Path] = []
    if project_root is not None:
        r_root = project_root.resolve()
        untrusted.append(r_root)
        untrusted.extend(_repo_roots(r_root))
    if inventory_path is not None:
        inv_dir = inventory_path.resolve().parent
        untrusted.append(inv_dir)
        untrusted.extend(_repo_roots(inv_dir))
    untrusted.extend(_repo_roots(Path.cwd().resolve()))
    msg = f"{label} must live outside the scanned project and enclosing git repositories"
    if any(resolved.is_relative_to(root) for root in untrusted):
        raise ModelPolicyError(msg)
    if os.name == "posix" and untrusted:
        ids = {(st.st_dev, st.st_ino) for r in untrusted if (st := _safe_stat(r)) is not None}
        if any(
            (st.st_dev, st.st_ino) in ids
            for parent in resolved.parents
            if (st := _safe_stat(parent)) is not None
        ):
            raise ModelPolicyError(msg)


def _read_regular_single_link(path: Path, max_bytes: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as handle:
            if os.name == "posix" and os.fstat(handle.fileno()).st_nlink != 1:
                raise ModelPolicyError(f"{label} must not have additional hard links")
            raw = handle.read(max_bytes + 1)
    except OSError as exc:
        raise ModelPolicyError(f"Cannot safely read {label.lower()}: {exc}") from exc
    if len(raw) > max_bytes:
        raise ModelPolicyError(f"{label} exceeds {max_bytes} bytes")
    return raw


def _verify_optional_dsse(
    raw: bytes,
    *,
    attestation_path: Path | None,
    trusted_key_paths: Sequence[Path],
    allow_unsigned: bool,
    project_root: Path | None,
    inventory_path: Path | None,
    label: str,
) -> bool:
    if attestation_path is None:
        if not allow_unsigned:
            raise ModelPolicyError(
                f"{label} requires DSSE attestation and --trusted-key "
                "(or explicit --allow-unsigned-policy)"
            )
        return False
    if not trusted_key_paths:
        raise ModelPolicyError(f"{label} attestation requires at least one --trusted-key")
    from nexus_symbiote.attestation import (
        MAX_ENVELOPE_BYTES,
        AttestationError,
        parse_envelope,
        verify_attestation,
    )
    from nexus_symbiote.runtime import key_id

    ensure_outside_project(
        attestation_path, project_root, inventory_path=inventory_path, label=f"{label} attestation"
    )
    ring: dict[str, Ed25519PublicKey] = {}
    for kpath in trusted_key_paths:
        ensure_outside_project(
            kpath, project_root, inventory_path=inventory_path, label="Trusted key file"
        )
        kbytes = _read_regular_single_link(kpath, MAX_KEY_BYTES, "Trusted key file")
        try:
            pub = serialization.load_pem_public_key(kbytes)
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise ModelPolicyError("Trusted key must be an Ed25519 public key PEM") from exc
        if not isinstance(pub, Ed25519PublicKey):
            raise ModelPolicyError("Only Ed25519 public keys are supported")
        ring[key_id(pub)] = pub
    env_bytes = _read_regular_single_link(
        attestation_path, MAX_ENVELOPE_BYTES, f"{label} attestation"
    )
    try:
        verify_attestation(
            parse_envelope(env_bytes), raw, trusted_keys=ring, purpose="reviewed", match="bytes"
        )
    except AttestationError as exc:
        raise ModelPolicyError(f"{label} attestation verification failed: {exc}") from exc
    return True


def load_model_policy(
    path: Path,
    *,
    project_root: Path | None = None,
    inventory_path: Path | None = None,
    attestation_path: Path | None = None,
    trusted_key_paths: Sequence[Path] = (),
    allow_unsigned: bool = False,
) -> tuple[ModelGovernancePolicy, str, bool]:
    """Load an operator-owned JSON/YAML model governance policy (DSSE required by default)."""
    ensure_outside_project(
        path, project_root, inventory_path=inventory_path, label="Model governance policy"
    )
    raw = _read_regular_single_link(path, MAX_POLICY_BYTES, "Model governance policy")
    attested = _verify_optional_dsse(
        raw,
        attestation_path=attestation_path,
        trusted_key_paths=trusted_key_paths,
        allow_unsigned=allow_unsigned,
        project_root=project_root,
        inventory_path=inventory_path,
        label="Model governance policy",
    )
    text = raw.decode("utf-8")
    try:
        if path.suffix.lower() == ".json":
            doc = parse_json_strict(text, max_bytes=MAX_POLICY_BYTES)
        else:
            doc = yaml.safe_load(text)
        policy = ModelGovernancePolicy.model_validate(doc)
    except Exception as exc:
        raise ModelPolicyError(f"Invalid model governance policy: {exc}") from exc
    return policy, hash_bytes(raw), attested


def load_retirement_catalog(
    path: Path,
    *,
    project_root: Path | None = None,
    inventory_path: Path | None = None,
    attestation_path: Path | None = None,
    trusted_key_paths: Sequence[Path] = (),
    allow_unsigned: bool = False,
) -> tuple[ModelRetirementCatalog, str, bool]:
    """Load an offline AIROM-style model retirement catalog outside the scanned project."""
    ensure_outside_project(
        path, project_root, inventory_path=inventory_path, label="Model retirement catalog"
    )
    raw = _read_regular_single_link(path, MAX_CATALOG_BYTES, "Model retirement catalog")
    attested = _verify_optional_dsse(
        raw,
        attestation_path=attestation_path,
        trusted_key_paths=trusted_key_paths,
        allow_unsigned=allow_unsigned,
        project_root=project_root,
        inventory_path=inventory_path,
        label="Model retirement catalog",
    )
    try:
        doc = parse_json_strict(raw.decode("utf-8"), max_bytes=MAX_CATALOG_BYTES)
        catalog = ModelRetirementCatalog.model_validate(doc)
    except Exception as exc:
        raise ModelPolicyError(f"Invalid model retirement catalog: {exc}") from exc
    return catalog, hash_bytes(raw), attested


def is_pinned_model_identifier(identifier: str | None) -> bool:
    """Return True if a model identifier/revision is cryptographically pinned or a dated snapshot."""
    if not identifier or not isinstance(identifier, str):
        return False
    val = identifier.strip()
    low = val.lower()
    if low in _UNKNOWN_LITERALS or low in _FLOATING_TAGS:
        return False
    if any(low.endswith(suf) for suf in _FLOATING_SUFFIXES):
        return False
    return bool(
        _SHA256_RE.search(val)
        or _GIT_SHA_RE.match(val)
        or _ISO_DATE_SNAPSHOT_RE.search(val)
        or _COMPACT_DATE_SNAPSHOT_RE.search(val)
        or _NUMBERED_SNAPSHOT_RE.search(val)
    )


def model_has_pinned_revision(comp: ModelComponent) -> tuple[bool, str | None]:
    """Determine whether a ModelComponent carries a pinned revision, dated snapshot, or digest."""
    sha = comp.hashes.get("sha256")
    if isinstance(sha, str) and re.fullmatch(r"(?:sha256:)?[0-9a-fA-F]{64}", sha.strip()):
        return True, sha.strip()
    for candidate in (comp.resolved_revision, comp.version, comp.requested_alias, comp.name):
        if is_pinned_model_identifier(candidate):
            return True, candidate
    return False, comp.resolved_revision or comp.requested_alias or comp.version or comp.name


def extract_model_licenses(comp: ModelComponent) -> list[str]:
    """Extract normalized declared license strings from a ModelComponent's properties."""
    props: Mapping[str, Any] = comp.properties if isinstance(comp.properties, dict) else {}
    raw_vals: list[str] = []
    for key in ("license", "spdx_license"):
        val = props.get(key)
        if isinstance(val, str):
            raw_vals.append(val)
    multi = props.get("licenses")
    if isinstance(multi, list):
        raw_vals.extend(v for v in multi if isinstance(v, str))
    cleaned: list[str] = []
    for item in raw_vals:
        norm = item.strip()
        if norm.lower() not in _UNKNOWN_LITERALS:
            cleaned.append(norm)
    return sorted(set(cleaned))


def _build_catalog_index(catalog: ModelRetirementCatalog | None) -> dict[str, ModelRetirementEntry]:
    if catalog is None:
        return {}
    idx: dict[str, ModelRetirementEntry] = {}
    for entry in catalog.models:
        idx[entry.model_id.strip().lower()] = entry
        for alias in entry.aliases:
            idx[alias.strip().lower()] = entry
    return idx


def _lookup_retirement(
    comp: ModelComponent, index: Mapping[str, ModelRetirementEntry]
) -> ModelRetirementEntry | None:
    if not index:
        return None
    for cand in (comp.resolved_revision, comp.requested_alias, comp.name, comp.version):
        if isinstance(cand, str) and cand.strip():
            hit = index.get(cand.strip().lower())
            if hit is not None:
                return hit
    return None


def evaluate_model_policy(
    bom: AIBOM,
    policy: ModelGovernancePolicy,
    *,
    policy_sha256: str = "",
    policy_attested: bool = False,
    catalog: ModelRetirementCatalog | None = None,
    catalog_sha256: str | None = None,
    catalog_attested: bool = False,
    now_utc: datetime | None = None,
) -> ModelPolicyReport:
    """Evaluate all ModelComponents in ``bom`` against ``policy`` and optional retirement catalog.

    Waiver expiry and retirement sunset dates are evaluated strictly against wall-clock UTC time
    (or an explicit test clock ``now_utc``), never against BOM metadata timestamps or SOURCE_DATE_EPOCH.
    """
    current_dt = now_utc.astimezone(UTC) if now_utc is not None else datetime.now(UTC)
    today = current_dt.date()

    active_waivers: set[tuple[str, str]] = set()
    expired_waivers = 0
    for w in policy.waivers:
        if w.expires_at <= current_dt:
            expired_waivers += 1
        else:
            active_waivers.add((w.rule, w.model_ref))

    allowed_lic = {x.strip().lower() for x in policy.allowed_licenses if x.strip()}
    denied_lic = {x.strip().lower() for x in policy.denied_licenses if x.strip()}
    cat_index = _build_catalog_index(catalog)

    findings: list[ModelPolicyFinding] = []
    waived = 0
    models = sorted(
        (c for c in bom.components if isinstance(c, ModelComponent)), key=lambda c: c.bom_ref
    )

    def emit(
        rule: str,
        severity: Literal["critical", "high", "medium", "low"],
        comp: ModelComponent,
        detail: str,
        rec: str | None = None,
        observed: str | None = None,
    ) -> None:
        nonlocal waived
        if (rule, comp.bom_ref) in active_waivers:
            waived += 1
            return
        findings.append(
            ModelPolicyFinding(rule, severity, comp.bom_ref, comp.name, detail, rec, observed)
        )

    for comp in models:
        # 1. Pinning check (dated snapshots & cryptographic digests pass cleanly).
        if policy.require_pinned_revision:
            pinned, obs = model_has_pinned_revision(comp)
            if not pinned:
                emit(
                    "model_unpinned_alias",
                    "high",
                    comp,
                    f"Model {comp.name!r} uses a floating or unpinned identifier ({obs!r})",
                    "Pin to a dated provider snapshot (e.g. gpt-4o-2024-08-06) or immutable SHA-256/commit digest.",
                    obs,
                )

        # 2. License governance check (Invariant 4: unknown is never clean).
        licenses = extract_model_licenses(comp)
        if not licenses:
            if policy.require_known_license:
                emit(
                    "model_license_unknown",
                    "medium",
                    comp,
                    f"Model {comp.name!r} declares no known license",
                    "Record an explicit SPDX or commercial license identifier in model properties.",
                )
        else:
            for lic in licenses:
                low_lic = lic.lower()
                if low_lic in denied_lic or (allowed_lic and low_lic not in allowed_lic):
                    emit(
                        "model_license_disallowed",
                        "high",
                        comp,
                        f"Model {comp.name!r} license {lic!r} violates model governance policy",
                        "Replace with a policy-approved model license or obtain an expiring operator waiver.",
                        lic,
                    )

        # 3. trust_remote_code check.
        props = comp.properties if isinstance(comp.properties, dict) else {}
        trc = comp.trust_remote_code
        if trc is None and isinstance(props.get("trust_remote_code"), bool):
            trc = props["trust_remote_code"]
        if policy.forbid_trust_remote_code and trc is True:
            emit(
                "model_trust_remote_code",
                "critical",
                comp,
                f"Model {comp.name!r} enables trust_remote_code=True (arbitrary Python execution on load)",
                "Disable trust_remote_code and use native safetensors architecture implementations.",
                "true",
            )
        elif policy.require_known_trust_remote_code and trc is None:
            emit(
                "model_trust_remote_code_unknown",
                "medium",
                comp,
                f"Model {comp.name!r} does not declare trust_remote_code posture",
                "Explicitly set trust_remote_code=False in model loading configuration.",
            )

        # 4. Unsafe serialization (pickle/executable weights or unsafe chat template injection).
        if policy.forbid_unsafe_serialization and comp.serialization_safety in {
            SerializationSafety.UNSAFE_CODE_EXECUTION,
            SerializationSafety.UNSAFE_TEMPLATE_INJECTION,
        }:
            emit(
                "model_unsafe_serialization",
                "critical",
                comp,
                f"Model {comp.name!r} uses unsafe serialization ({comp.serialization_safety.value})",
                "Convert weights to safetensors and sanitize chat templates.",
                comp.serialization_format or comp.serialization_safety.value,
            )

        # 5. Offline AIROM-style retirement/deprecation check (strictly wall-clock UTC date).
        entry = _lookup_retirement(comp, cat_index)
        if entry is not None:
            rep_hint = (
                f"Migrate to {entry.replacement}."
                if entry.replacement
                else "Migrate to a supported active model revision."
            )
            if entry.status == "retired" or (
                entry.sunset_date is not None and entry.sunset_date <= today
            ):
                emit(
                    "model_retired",
                    "high",
                    comp,
                    f"Model {comp.name!r} ({entry.model_id}) is retired (sunset {entry.sunset_date})",
                    rep_hint,
                    entry.model_id,
                )
            elif entry.status == "deprecated" or (
                entry.sunset_date is not None
                and (entry.sunset_date - today).days <= policy.retirement_warn_days
            ):
                days_left = (entry.sunset_date - today).days if entry.sunset_date else None
                suffix = f" ({days_left} days until sunset)" if days_left is not None else ""
                emit(
                    "model_deprecated",
                    "medium",
                    comp,
                    f"Model {comp.name!r} ({entry.model_id}) is deprecated{suffix}",
                    rep_hint,
                    entry.model_id,
                )

    return ModelPolicyReport(
        passed=not findings,
        models_checked=len(models),
        findings=tuple(findings),
        waived_count=waived,
        expired_waiver_count=expired_waivers,
        policy_sha256=policy_sha256,
        policy_attested=policy_attested,
        catalog_sha256=catalog_sha256,
        catalog_attested=catalog_attested,
        evaluated_date_utc=today.isoformat(),
    )
