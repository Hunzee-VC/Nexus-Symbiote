"""Risk tiers, cadence, jitter, escalation and backoff (``spec/monitoring.md`` §1).

Everything here is pure: no clock reads, no I/O. The scheduler passes ``now`` in, so due times are reproducible.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING

from symbiote.model.enums import FindingState, FlagName, Severity, TriState

if TYPE_CHECKING:
    from symbiote.model.document import AgentBOM
    from symbiote.model.entities import Finding, Flag

__all__ = [
    "DEFAULT_CADENCE",
    "MAX_INTERVAL",
    "MIN_INTERVAL",
    "TIER_ORDER",
    "EscalationState",
    "RiskTier",
    "at_least",
    "backoff_delay",
    "derive_tier",
    "interval_for",
    "jitter",
    "max_tier",
    "next_due",
    "normalize_environment",
    "parse_interval",
    "severity_rank",
    "update_escalation",
]


class RiskTier(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


#: Most severe first.
TIER_ORDER: tuple[RiskTier, ...] = (RiskTier.CRITICAL, RiskTier.HIGH, RiskTier.MEDIUM, RiskTier.LOW)
_TIER_RANK = {t: i for i, t in enumerate(TIER_ORDER)}

DEFAULT_CADENCE: Mapping[RiskTier, timedelta] = MappingProxyType(
    {
        RiskTier.CRITICAL: timedelta(minutes=10),
        RiskTier.HIGH: timedelta(hours=1),
        RiskTier.MEDIUM: timedelta(days=1),
        RiskTier.LOW: timedelta(days=14),
    }
)

MIN_INTERVAL = timedelta(minutes=1)
#: Longest accepted interval: an agent that is never re-verified is not being monitored.
MAX_INTERVAL = timedelta(days=366)
#: Jitter is at most this fraction of the interval.
JITTER_FRACTION = 0.10
#: First error retry delay; doubles per consecutive error, capped at the tier interval.
BACKOFF_BASE = timedelta(minutes=1)

# Anchored, bounded: at most 7 digits and one unit letter; nothing else is accepted.
_INTERVAL_RE = re.compile(r"\A\s{0,8}(\d{1,7})\s{0,4}([smhdw])\s{0,8}\Z")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_ENVIRONMENTS = {
    "production": "production",
    "prod": "production",
    "staging": "staging",
    "stage": "staging",
    "internal": "internal",
    "development": "development",
    "dev": "development",
    "test": "development",
    "local": "development",
}


def parse_interval(text: str) -> timedelta:
    """Parse ``"10m"``, ``"1h"``, ``"1d"``, ``"2w"``, ``"90s"``. Below one minute (or above a year) is an error."""
    if not isinstance(text, str) or len(text) > 32:
        raise ValueError(f"invalid interval {text!r}: expected a number and a unit (s, m, h, d, w), e.g. 10m")
    match = _INTERVAL_RE.match(text.lower())
    if match is None:
        raise ValueError(f"invalid interval {text!r}: expected a number and a unit (s, m, h, d, w), e.g. 10m")
    value = timedelta(seconds=int(match.group(1)) * _UNIT_SECONDS[match.group(2)])
    if value < MIN_INTERVAL:
        raise ValueError(f"interval {text!r} is below the 1-minute floor")
    if value > MAX_INTERVAL:
        raise ValueError(f"interval {text!r} is longer than {MAX_INTERVAL.days} days")
    return value


def severity_rank(severity: Severity | str) -> int:
    """0 for critical … 4 for info (lower is more severe)."""
    return _SEVERITY_RANK[Severity(severity)]


def at_least(severity: Severity | str, threshold: Severity | str) -> bool:
    return severity_rank(severity) <= severity_rank(threshold)


def max_tier(*tiers: RiskTier | None) -> RiskTier:
    """The most severe of ``tiers`` (``low`` when none is given)."""
    present = [t for t in tiers if t is not None]
    if not present:
        return RiskTier.LOW
    return min(present, key=lambda t: _TIER_RANK[t])


def normalize_environment(environment: str | None) -> str:
    """Canonical environment name (``production``/``staging``/``internal``/``development``/the input)."""
    if not environment:
        return "development"
    key = environment.strip().lower()
    return _ENVIRONMENTS.get(key, key)


def derive_tier(
    bom: AgentBOM | None,
    environment: str | None,
    findings: Iterable[Finding] | None = None,
    flags: Iterable[Flag] | None = None,
    *,
    explicit: RiskTier | None = None,
) -> RiskTier:
    """The tier ``spec/monitoring.md`` §1 assigns to an agent.

    ``findings``/``flags`` default to the BOM's ``derived`` section. Only *failing* findings count (an
    indeterminate finding is not evidence of severity). ``explicit`` is a floor: derivation may raise it,
    never lower it.
    """
    if findings is None:
        findings = bom.derived.findings if bom is not None else ()
    if flags is None:
        flags = bom.derived.flags if bom is not None else ()
    failing = [f for f in findings if f.state is FindingState.FAIL]
    any_critical = any(f.severity is Severity.CRITICAL for f in failing)
    any_high = any(f.severity is Severity.HIGH for f in failing)
    risky_flags = {FlagName.LETHAL_TRIFECTA, FlagName.RULE_OF_TWO_VIOLATION}
    flagged = any(f.flag in risky_flags and f.value is TriState.TRUE for f in flags)
    env = normalize_environment(environment)
    if env == "production" and (flagged or any_critical):
        derived = RiskTier.CRITICAL
    elif env == "production" or any_high or any_critical:
        derived = RiskTier.HIGH
    elif env in ("staging", "internal"):
        derived = RiskTier.MEDIUM
    else:
        derived = RiskTier.LOW
    return max_tier(derived, explicit)


def jitter(name: str, interval: timedelta) -> timedelta:
    """Deterministic offset in ``[0, 10 %)`` of ``interval`` from SHA-256 of the agent name."""
    digest = hashlib.sha256(name.encode("utf-8")).digest()
    fraction = int.from_bytes(digest[:8], "big") / float(1 << 64)
    micros = int(interval / timedelta(microseconds=1) * JITTER_FRACTION * fraction)
    return timedelta(microseconds=micros)


def interval_for(
    tier: RiskTier,
    cadence: Mapping[RiskTier, timedelta],
    *,
    override: timedelta | None = None,
    escalated: bool = False,
) -> timedelta:
    """The interval to wait after a successful cycle.

    A per-agent ``override`` replaces the tier interval. While escalated, the critical cadence applies
    unless the agent's own interval is already shorter.
    """
    base = override if override is not None else cadence.get(tier, DEFAULT_CADENCE[tier])
    if escalated:
        critical = cadence.get(RiskTier.CRITICAL, DEFAULT_CADENCE[RiskTier.CRITICAL])
        return min(base, critical)
    return base


def next_due(name: str, last_run: datetime, interval: timedelta) -> datetime:
    """``last_run + interval + jitter(name, interval)``."""
    return last_run + interval + jitter(name, interval)


def backoff_delay(consecutive_errors: int, cap: timedelta) -> timedelta:
    """1, 2, 4 … minutes for the 1st, 2nd, 3rd … consecutive error, never more than ``cap``."""
    n = max(1, consecutive_errors)
    if n > 32:  # 2**31 minutes is already far beyond any cap
        return cap
    return min(BACKOFF_BASE * (1 << (n - 1)), cap)


@dataclass(frozen=True, slots=True)
class EscalationState:
    escalated: bool
    clean_streak: int
    #: ``"escalated"`` when this cycle escalated the agent, ``"deescalated"`` when it ended the escalation.
    change: str | None = None


def update_escalation(
    escalated: bool,
    clean_streak: int,
    *,
    triggered: bool,
    errored: bool,
    deescalate_after: int,
) -> EscalationState:
    """Adaptive escalation (§1).

    A triggering cycle (new failing finding at or above ``high``, definition drift, malicious or vulnerable
    dependency, verification failure) escalates and resets the clean streak. A cycle that errored is not clean
    and resets the streak without changing the escalation. Any other cycle is clean; after
    ``deescalate_after`` consecutive clean cycles the escalation ends.
    """
    if triggered:
        return EscalationState(True, 0, None if escalated else "escalated")
    if errored:
        return EscalationState(escalated, 0, None)
    streak = clean_streak + 1
    if escalated and streak >= max(1, deescalate_after):
        return EscalationState(False, streak, "deescalated")
    return EscalationState(escalated, streak, None)
