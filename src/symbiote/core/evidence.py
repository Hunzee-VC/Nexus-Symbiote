"""Deployment-scoped authority and evidence claims for native AgentBOMs.

These are records supplied by a producer, not proof of verification or runtime
enforcement. Consumers must independently verify the referenced evidence.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ClaimState(str, Enum):
    DECLARED = "declared"
    OBSERVED = "observed"
    VERIFIED = "verified"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not-applicable"


class AuthorityKind(str, Enum):
    DECLARED = "declared"
    EFFECTIVE = "effective"
    OBSERVED = "observed"


class VerificationStatus(str, Enum):
    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    INVALID = "invalid"
    UNSUPPORTED = "unsupported"


class EvidenceRecord(BaseModel):
    """A producer's evidence reference, not an independently verified result."""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(min_length=1, description="Non-secret source identifier")
    collector: str = Field(min_length=1)
    collected_at: datetime
    subject_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    verifier: str | None = None
    verification_policy: str | None = None
    verified_at: datetime | None = None

    @field_validator("collected_at", "verified_at")
    @classmethod
    def require_aware_time(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("evidence timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_verification_claim(self) -> Self:
        if self.verification_status == VerificationStatus.VERIFIED and not all(
            (self.subject_digest, self.verifier, self.verification_policy, self.verified_at)
        ):
            raise ValueError(
                "reported verification requires subject digest, verifier, policy and time"
            )
        return self


class AuthorityClaim(BaseModel):
    """A scoped authority assertion for an agent deployment.

    An unknown or not-applicable claim does not imply an empty permission set.
    """

    model_config = ConfigDict(extra="forbid")

    kind: AuthorityKind
    state: ClaimState = ClaimState.UNKNOWN
    principal: str | None = Field(default=None, min_length=1)
    action: str | None = Field(default=None, min_length=1)
    resource: str | None = Field(default=None, min_length=1)
    delegating_principal: str | None = Field(default=None, min_length=1)
    audience: str | None = Field(default=None, min_length=1)
    observed_at: datetime | None = None
    expires_at: datetime | None = None
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    unknown_reason: str | None = Field(default=None, min_length=1)

    @field_validator("observed_at", "expires_at")
    @classmethod
    def require_aware_time(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("authority timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        known = self.state in (ClaimState.DECLARED, ClaimState.OBSERVED, ClaimState.VERIFIED)
        if known and not (self.principal and self.action and self.resource):
            raise ValueError("known authority requires principal, action and resource")
        if not known and any(
            (self.principal, self.action, self.resource, self.delegating_principal, self.audience)
        ):
            raise ValueError("unknown or not-applicable authority must not carry a permission")
        if self.state == ClaimState.UNKNOWN and not self.unknown_reason:
            raise ValueError("unknown authority requires a reason")
        if self.state != ClaimState.UNKNOWN and self.unknown_reason is not None:
            raise ValueError("unknown_reason is only applicable to unknown claims")
        if self.state == ClaimState.OBSERVED and self.observed_at is None:
            raise ValueError("observed authority requires an observation time")
        if self.state == ClaimState.VERIFIED and not any(
            e.verification_status == VerificationStatus.VERIFIED for e in self.evidence
        ):
            raise ValueError("verified authority requires a reported verified evidence record")
        if known and not self.evidence:
            raise ValueError("known authority requires evidence provenance")
        return self


class DeploymentProfile(BaseModel):
    """Scope a set of permission assertions to one agent deployment."""

    model_config = ConfigDict(extra="forbid")

    deployment_id: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    tenant: str | None = Field(default=None, min_length=1)
    workload_identity: str | None = Field(default=None, min_length=1)
    authority: list[AuthorityClaim] = Field(default_factory=list)
