"""Operator VEX decisions, execution-bound trace outcomes, and advisory report loading.

Enforces two security invariants for CycloneDX 1.7 VEX generation:

- **Policy lives outside what it judges (Invariant 9):** operator VEX decision files
  must be regular files (never symlinks) stored outside the scanned project directory.
- **Expiring triage decisions fail closed (N5):** any non-``in_triage`` decision
  requires an ``owner`` and timezone-aware ``expires_at`` timestamp. Once expired
  against the deterministic reference time, it reverts to ``in_triage`` with an
  explicit warning recorded in the VEX document.
- **Execution-bound VEX (Item 23):** declared-never-loaded, invoked, and shadowed
  components map to distinct CycloneDX VEX outcomes with explicit reasons grounded
  in ``reported`` runtime trace evidence.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from nexus_symbiote.core.hashing import hash_bytes, open_regular_file, parse_json_strict

MAX_DECISIONS_BYTES = 4 * 1024 * 1024
MAX_DECISIONS = 5_000
MAX_REPORT_BYTES = 16 * 1024 * 1024

VEXState = Literal["not_affected", "exploitable", "resolved", "false_positive", "in_triage"]
VEXJustification = Literal[
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
]


class VEXDecisionError(ValueError):
    """Raised when an operator VEX decision, trace evidence, or advisory file is unsafe or invalid."""


class VEXDecisionEntry(BaseModel):
    """One operator-authored triage decision for a finding or advisory."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=256)
    component_ref: str | None = Field(default=None, max_length=1024)
    state: VEXState
    justification: VEXJustification | None = None
    detail: str = Field(min_length=1, max_length=2048)
    owner: str = Field(min_length=1, max_length=256)
    expires_at: datetime | None = None

    @field_validator("id", "detail", "owner")
    @classmethod
    def _clean_text(cls, value: str) -> str:
        if not value.strip() or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
            raise ValueError("must be a non-empty string without control characters")
        return value.strip()

    @field_validator("expires_at")
    @classmethod
    def _require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("expires_at must include an explicit UTC or timezone offset")
        return value.astimezone(UTC) if value is not None else None

    @model_validator(mode="after")
    def _validate_policy_rules(self) -> VEXDecisionEntry:
        if self.state != "in_triage" and self.expires_at is None:
            raise ValueError("non-in_triage VEX decisions must specify expires_at")
        if self.justification is not None and self.state != "not_affected":
            raise ValueError("justification is only valid when state is 'not_affected'")
        return self


class VEXDecisionSet(BaseModel):
    """Versioned container for operator VEX decisions."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    decisions: list[VEXDecisionEntry] = Field(default_factory=list)


@dataclass(frozen=True)
class LoadedVEXDecisions:
    """Validated operator VEX decisions with file digest provenance."""

    entries: tuple[VEXDecisionEntry, ...]
    sha256: str

    def lookup(self, vuln_id: str, component_ref: str) -> VEXDecisionEntry | None:
        """Return the most specific decision: component-scoped first, then global."""
        global_match: VEXDecisionEntry | None = None
        for entry in self.entries:
            if entry.id != vuln_id:
                continue
            if entry.component_ref == component_ref:
                return entry
            if entry.component_ref is None and global_match is None:
                global_match = entry
        return global_match


@dataclass(frozen=True)
class ExecutionEvidence:
    """Execution-bound component classification derived from runtime trace evidence."""

    invoked_refs: frozenset[str]
    declared_never_loaded_refs: frozenset[str]
    shadowed_refs: frozenset[str]
    sha256: str

    def outcome_for(self, component_ref: str) -> str | None:
        """Return 'shadowed', 'invoked', 'declared-never-loaded', or None."""
        if component_ref in self.shadowed_refs:
            return "shadowed"
        if component_ref in self.invoked_refs:
            return "invoked"
        if component_ref in self.declared_never_loaded_refs:
            return "declared-never-loaded"
        return None


def resolve_reference_time(
    explicit_now: datetime | None, bom_timestamp: datetime | None
) -> datetime:
    """Resolve deterministic reference time: explicit -> SOURCE_DATE_EPOCH -> BOM -> UTC now."""
    if explicit_now is not None:
        if explicit_now.tzinfo is None:
            raise VEXDecisionError("Reference time must be timezone-aware")
        return explicit_now.astimezone(UTC)
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is not None and epoch.strip():
        try:
            return datetime.fromtimestamp(int(epoch.strip()), tz=UTC)
        except (ValueError, OverflowError) as exc:
            raise VEXDecisionError("SOURCE_DATE_EPOCH must be an integer Unix timestamp") from exc
    if bom_timestamp is not None:
        return (
            bom_timestamp.astimezone(UTC)
            if bom_timestamp.tzinfo
            else bom_timestamp.replace(tzinfo=UTC)
        )
    return datetime.now(UTC)


def _ensure_outside_project(decisions_path: Path, project_root: Path | None) -> None:
    if project_root is None:
        return
    resolved_file = decisions_path.resolve()
    resolved_root = project_root.resolve()
    try:
        resolved_file.relative_to(resolved_root)
    except ValueError:
        return
    raise VEXDecisionError(
        "Operator VEX decisions file must live outside the scanned project directory"
    )


def load_vex_decisions(
    path: Path,
    *,
    project_root: Path | None = None,
) -> LoadedVEXDecisions:
    """Load and validate an operator-owned VEX decisions YAML or JSON file."""
    _ensure_outside_project(path, project_root)
    try:
        with open_regular_file(path) as handle:
            raw = handle.read(MAX_DECISIONS_BYTES + 1)
    except OSError as exc:
        raise VEXDecisionError(f"Cannot safely read VEX decisions file: {exc}") from exc
    if len(raw) > MAX_DECISIONS_BYTES:
        raise VEXDecisionError(f"VEX decisions file exceeds {MAX_DECISIONS_BYTES} bytes")

    text = raw.decode("utf-8")
    try:
        payload: Any = (
            parse_json_strict(text)
            if path.suffix.lower() == ".json" or text.lstrip().startswith("{")
            else yaml.safe_load(text)
        )
    except (ValueError, yaml.YAMLError) as exc:
        raise VEXDecisionError(f"Invalid VEX decisions syntax: {exc}") from exc

    if not isinstance(payload, dict):
        raise VEXDecisionError(
            "VEX decisions file must be a mapping with 'version' and 'decisions'"
        )
    if isinstance(payload.get("decisions"), list) and len(payload["decisions"]) > MAX_DECISIONS:
        raise VEXDecisionError(f"VEX decisions file exceeds {MAX_DECISIONS} entries")

    try:
        model = VEXDecisionSet.model_validate(payload)
    except Exception as exc:
        raise VEXDecisionError(f"Invalid VEX decisions schema: {exc}") from exc

    return LoadedVEXDecisions(entries=tuple(model.decisions), sha256=hash_bytes(raw))


def _extract_refs(items: object) -> set[str]:
    refs: set[str] = set()
    if not isinstance(items, list):
        return refs
    for item in items:
        if isinstance(item, str) and item.strip():
            refs.add(item.strip())
        elif isinstance(item, dict):
            for key in ("bom_ref", "component_ref", "ref"):
                val = item.get(key)
                if isinstance(val, str) and val.strip():
                    refs.add(val.strip())
                    break
    return refs


def load_execution_evidence(path: Path) -> ExecutionEvidence:
    """Load execution-bound trace evidence from a trace-diff or execution-evidence JSON report."""
    try:
        with open_regular_file(path) as handle:
            raw = handle.read(MAX_REPORT_BYTES + 1)
    except OSError as exc:
        raise VEXDecisionError(f"Cannot safely read trace evidence file: {exc}") from exc
    if len(raw) > MAX_REPORT_BYTES:
        raise VEXDecisionError(f"Trace evidence file exceeds {MAX_REPORT_BYTES} bytes")

    payload = parse_json_strict(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise VEXDecisionError("Trace evidence file must be a JSON object")

    invoked = _extract_refs(payload.get("invoked")) | _extract_refs(payload.get("matched"))
    never_loaded = _extract_refs(payload.get("declared_never_loaded")) | _extract_refs(
        payload.get("unobserved")
    )
    shadowed = _extract_refs(payload.get("shadowed")) | _extract_refs(payload.get("shadowed_refs"))
    return ExecutionEvidence(
        invoked_refs=frozenset(invoked),
        declared_never_loaded_refs=frozenset(never_loaded - invoked - shadowed),
        shadowed_refs=frozenset(shadowed),
        sha256=hash_bytes(raw),
    )


def load_advisory_report(path: Path) -> tuple[list[dict[str, Any]], str]:
    """Load an advisory report JSON produced by ``advisories`` (live or offline)."""
    try:
        with open_regular_file(path) as handle:
            raw = handle.read(MAX_REPORT_BYTES + 1)
    except OSError as exc:
        raise VEXDecisionError(f"Cannot safely read advisory report: {exc}") from exc
    if len(raw) > MAX_REPORT_BYTES:
        raise VEXDecisionError(f"Advisory report exceeds {MAX_REPORT_BYTES} bytes")

    payload = parse_json_strict(raw.decode("utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("advisories"), list):
        raise VEXDecisionError("Advisory report must be a JSON object with an 'advisories' array")
    advisories = [item for item in payload["advisories"] if isinstance(item, dict)]
    return advisories, hash_bytes(raw)
