"""Cross-cutting value objects: digests, claims, provenance, evidence references, parties."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Generic, TypeVar

from pydantic import Field, StringConstraints, field_validator, model_validator

from symbiote.model.base import SymbioteModel
from symbiote.model.enums import (
    AssuranceLevel,
    ClaimMethod,
    DigestStatus,
    EvidenceVerification,
    PartyKind,
    UnknownReason,
    ValueState,
)

#: ``sha256:<64 lowercase hex>`` — the only digest rendering used inside the model and the companion.
DigestStr = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]

#: Stable entity identifier (``spec/agentbom-profile.md §1.1``). Safe as a CycloneDX bom-ref and an IRI suffix.
EntityId = Annotated[
    str, StringConstraints(pattern=r"^[a-z][a-z0-9-]*:[A-Za-z0-9._~/@+-]+$", min_length=3, max_length=512)
]

#: Collector reference ``collector:<name>@<version>``.
CollectorRef = Annotated[str, StringConstraints(pattern=r"^collector:[a-z0-9][a-z0-9._-]*@[A-Za-z0-9._+-]+$")]

T = TypeVar("T")

_SECRET_SHAPES = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),  # OpenAI/Anthropic style keys
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    # JWT; the lookbehind (not \b) stops a match starting inside a run of token characters, keeping this linear
    re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),  # GitHub tokens
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),  # Slack tokens
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),  # Google API key
)


def looks_like_secret(value: str) -> bool:
    """Return True when ``value`` matches a well-known credential shape."""
    return any(p.search(value) for p in _SECRET_SHAPES)


class Validity(SymbioteModel):
    """Half-open validity window ``[not_before, not_after)``."""

    not_before: datetime | None = None
    not_after: datetime | None = None

    @model_validator(mode="after")
    def _ordered(self) -> Validity:
        if self.not_before and self.not_after and self.not_after <= self.not_before:
            raise ValueError("not_after must be later than not_before")
        return self


class DigestResult(SymbioteModel):
    """Outcome of a digest computation: a value, or a fail-closed ``undigestable`` marker (ADR-0004)."""

    algorithm: str = Field(description="Digest kind, e.g. 'tooldef/v1', 'sha256', 'dirmanifest/v1'")
    value: DigestStr | None = None
    status: DigestStatus = DigestStatus.OK
    reason: str | None = None

    @model_validator(mode="after")
    def _consistent(self) -> DigestResult:
        if self.status is DigestStatus.OK and self.value is None:
            raise ValueError("an ok digest needs a value")
        if self.status is DigestStatus.UNDIGESTABLE and not self.reason:
            raise ValueError("an undigestable result needs a reason")
        return self

    @property
    def ok(self) -> bool:
        return self.status is DigestStatus.OK


class EvidenceRef(SymbioteModel):
    """Reference to evidence by digest (never inline)."""

    digest: DigestStr
    media_type: str = "application/octet-stream"
    uri: str | None = None
    predicate_type: str | None = None
    verification: EvidenceVerification = EvidenceVerification.NONE
    signer_identity: str | None = None
    signer_issuer: str | None = None
    log_entry: str | None = None

    @property
    def evidence_id(self) -> str:
        return "ev:" + self.digest[len("sha256:") :][:12]


class Claim(SymbioteModel, Generic[T]):
    """A fact that can be wrong: value + state + assurance + evidence (``spec/agentbom-profile.md §1.3``)."""

    value: T | None = None
    state: ValueState = ValueState.PRESENT
    assurance: AssuranceLevel = AssuranceLevel.DECLARED
    method: ClaimMethod | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)
    locator: str | None = None
    collector: CollectorRef | None = None
    observed_at: datetime | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    unknown_reason: UnknownReason | None = None

    @model_validator(mode="after")
    def _invariants(self) -> Claim[T]:
        if self.state is ValueState.UNKNOWN:
            if self.value is not None:
                raise ValueError("I2: an unknown claim carries no value")
            if self.unknown_reason is None:
                raise ValueError("I2: an unknown claim needs unknown_reason")
        if self.state is ValueState.ABSENT_VERIFIED and self.value not in (None, [], {}, "", False):
            raise ValueError("an absent-verified claim carries no value")
        if self.state is ValueState.PRESENT and self.value is None:
            raise ValueError("a present claim needs a value")
        if self.assurance is AssuranceLevel.VERIFIED and not any(
            e.verification is EvidenceVerification.VERIFIED_CONSTRAINED for e in self.evidence
        ):
            raise ValueError("I3: verified assurance requires verified-constrained evidence")
        return self

    @property
    def is_unknown(self) -> bool:
        return self.state is ValueState.UNKNOWN

    @classmethod
    def unknown(
        cls, reason: UnknownReason, *, locator: str | None = None, collector: str | None = None
    ) -> Claim[T]:
        return cls(state=ValueState.UNKNOWN, unknown_reason=reason, locator=locator, collector=collector)

    @classmethod
    def declared(
        cls,
        value: T,
        *,
        locator: str | None = None,
        collector: str | None = None,
        method: ClaimMethod = ClaimMethod.CONFIG,
        observed_at: datetime | None = None,
    ) -> Claim[T]:
        return cls(
            value=value,
            assurance=AssuranceLevel.DECLARED,
            method=method,
            locator=locator,
            collector=collector,
            observed_at=observed_at,
        )

    @classmethod
    def observed(
        cls,
        value: T,
        *,
        evidence: list[EvidenceRef] | None = None,
        locator: str | None = None,
        collector: str | None = None,
        method: ClaimMethod = ClaimMethod.LIVE_QUERY,
        observed_at: datetime | None = None,
        confidence: float | None = None,
    ) -> Claim[T]:
        return cls(
            value=value,
            assurance=AssuranceLevel.OBSERVED,
            method=method,
            evidence=evidence or [],
            locator=locator,
            collector=collector,
            observed_at=observed_at,
            confidence=confidence,
        )

    @classmethod
    def absent_verified(
        cls,
        *,
        locator: str | None = None,
        collector: str | None = None,
        assurance: AssuranceLevel = AssuranceLevel.OBSERVED,
    ) -> Claim[T]:
        return cls(
            state=ValueState.ABSENT_VERIFIED, assurance=assurance, locator=locator, collector=collector
        )


class Provenance(SymbioteModel):
    """How an entity's existence was established (a claim without a value)."""

    assurance: AssuranceLevel = AssuranceLevel.DECLARED
    method: ClaimMethod | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)
    locator: str | None = None
    collector: CollectorRef | None = None
    observed_at: datetime | None = None

    @model_validator(mode="after")
    def _i3(self) -> Provenance:
        if self.assurance is AssuranceLevel.VERIFIED and not any(
            e.verification is EvidenceVerification.VERIFIED_CONSTRAINED for e in self.evidence
        ):
            raise ValueError("I3: verified assurance requires verified-constrained evidence")
        return self


class ExternalRef(SymbioteModel):
    type: str
    url: str
    digests: list[DigestStr] = Field(default_factory=list)
    comment: str | None = None


class Contact(SymbioteModel):
    name: str | None = None
    email: str | None = None


class Party(SymbioteModel):
    """An organization or person (owner, operator, assessor, registry operator)."""

    id: EntityId
    party_kind: PartyKind = Field(alias="kind")
    name: str
    urls: list[str] = Field(default_factory=list)
    contacts: list[Contact] = Field(default_factory=list)


class NoSecretStr(str):
    """Marker for string fields that must never contain credential material."""


def reject_secret(value: Any, field: str) -> Any:
    if isinstance(value, str) and looks_like_secret(value):
        raise ValueError(f"{field} looks like a secret value; record a reference, never the secret")
    return value


class ThreatRef(SymbioteModel):
    framework: str
    id: str
    uri: str | None = None


__all__ = [
    "Claim",
    "CollectorRef",
    "Contact",
    "DigestResult",
    "DigestStr",
    "EntityId",
    "EvidenceRef",
    "ExternalRef",
    "Party",
    "Provenance",
    "ThreatRef",
    "Validity",
    "field_validator",
    "looks_like_secret",
    "reject_secret",
]
