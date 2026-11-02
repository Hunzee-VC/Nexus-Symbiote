"""Intervals, tier derivation, jitter, due times, escalation and backoff (spec/monitoring.md §1)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from symbiote.model.entities import Finding, Flag
from symbiote.model.enums import FindingState, FlagName, Severity, TriState
from symbiote.monitor import (
    DEFAULT_CADENCE,
    RiskTier,
    backoff_delay,
    derive_tier,
    interval_for,
    jitter,
    next_due,
    parse_interval,
    update_escalation,
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("10m", timedelta(minutes=10)),
        ("1h", timedelta(hours=1)),
        ("1d", timedelta(days=1)),
        ("2w", timedelta(weeks=2)),
        ("14d", timedelta(days=14)),
        ("60s", timedelta(minutes=1)),
        (" 90S ", timedelta(seconds=90)),
    ],
)
def test_parse_interval(text: str, expected: timedelta) -> None:
    assert parse_interval(text) == expected


@pytest.mark.parametrize("text", ["30s", "59s", "0m", "0d"])
def test_parse_interval_floor(text: str) -> None:
    with pytest.raises(ValueError, match="floor"):
        parse_interval(text)


@pytest.mark.parametrize(
    "text", ["", "10", "m", "1.5h", "-1h", "1y", "10 minutes", "1h30m", "9" * 40 + "m", "2000d"]
)
def test_parse_interval_rejects(text: str) -> None:
    with pytest.raises(ValueError):
        parse_interval(text)


def test_default_cadence() -> None:
    assert dict(DEFAULT_CADENCE) == {
        RiskTier.CRITICAL: timedelta(minutes=10),
        RiskTier.HIGH: timedelta(hours=1),
        RiskTier.MEDIUM: timedelta(days=1),
        RiskTier.LOW: timedelta(days=14),
    }


def _finding(severity: Severity, state: FindingState = FindingState.FAIL) -> Finding:
    return Finding(
        check_id="SYM-X-001", severity=severity, state=state, subject_refs=["agent:a"], message="m"
    )


def _flag(name: FlagName, value: TriState) -> Flag:
    return Flag(flag=name, subject_ref="agent:a", value=value)


def test_derive_tier_rules() -> None:
    trifecta = [_flag(FlagName.LETHAL_TRIFECTA, TriState.TRUE)]
    unknown = [_flag(FlagName.LETHAL_TRIFECTA, TriState.UNKNOWN)]
    assert derive_tier(None, "production", [], trifecta) is RiskTier.CRITICAL
    assert (
        derive_tier(None, "production", [], [_flag(FlagName.RULE_OF_TWO_VIOLATION, TriState.TRUE)])
        is RiskTier.CRITICAL
    )
    assert derive_tier(None, "production", [_finding(Severity.CRITICAL)], []) is RiskTier.CRITICAL
    assert derive_tier(None, "production", [], unknown) is RiskTier.HIGH
    assert derive_tier(None, "prod", [], []) is RiskTier.HIGH
    assert derive_tier(None, "staging", [_finding(Severity.HIGH)], []) is RiskTier.HIGH
    assert derive_tier(None, "staging", [_finding(Severity.MEDIUM)], trifecta) is RiskTier.MEDIUM
    assert derive_tier(None, "internal", [], []) is RiskTier.MEDIUM
    assert derive_tier(None, "development", [], trifecta) is RiskTier.LOW
    assert derive_tier(None, None, [], []) is RiskTier.LOW
    # Only failing findings count; an indeterminate critical is not evidence of severity.
    assert (
        derive_tier(None, "staging", [_finding(Severity.CRITICAL, FindingState.INDETERMINATE)], [])
        is RiskTier.MEDIUM
    )


def test_explicit_tier_is_never_lowered() -> None:
    assert derive_tier(None, "development", [], [], explicit=RiskTier.CRITICAL) is RiskTier.CRITICAL
    assert derive_tier(None, "development", [], [], explicit=RiskTier.MEDIUM) is RiskTier.MEDIUM
    # ...but derivation may raise it.
    assert derive_tier(None, "production", [], [], explicit=RiskTier.LOW) is RiskTier.HIGH


def test_jitter_is_deterministic_and_bounded() -> None:
    interval = timedelta(hours=1)
    values = {name: jitter(name, interval) for name in (f"agent-{i}" for i in range(200))}
    assert all(timedelta(0) <= v < interval * 0.1 for v in values.values())
    assert jitter("agent-7", interval) == values["agent-7"]
    assert len(set(values.values())) > 150  # the fleet is spread out, not in lockstep
    assert jitter("x", timedelta(days=14)) < timedelta(days=1.4)


def test_next_due_and_interval_for() -> None:
    last = datetime(2026, 11, 1, tzinfo=UTC)
    cadence = dict(DEFAULT_CADENCE)
    iv = interval_for(RiskTier.MEDIUM, cadence)
    assert iv == timedelta(days=1)
    due = next_due("a", last, iv)
    assert last + iv <= due < last + iv * 1.1
    assert interval_for(RiskTier.MEDIUM, cadence, escalated=True) == timedelta(minutes=10)
    assert interval_for(RiskTier.LOW, cadence, override=timedelta(hours=2)) == timedelta(hours=2)
    # A per-agent interval shorter than the critical cadence is kept while escalated.
    assert interval_for(RiskTier.LOW, cadence, override=timedelta(minutes=5), escalated=True) == timedelta(
        minutes=5
    )


def test_escalation_and_deescalation() -> None:
    s = update_escalation(False, 5, triggered=True, errored=False, deescalate_after=3)
    assert (s.escalated, s.clean_streak, s.change) == (True, 0, "escalated")
    s = update_escalation(s.escalated, s.clean_streak, triggered=False, errored=False, deescalate_after=3)
    assert (s.escalated, s.clean_streak, s.change) == (True, 1, None)
    s = update_escalation(s.escalated, s.clean_streak, triggered=False, errored=True, deescalate_after=3)
    assert (s.escalated, s.clean_streak) == (True, 0)  # an error is never a clean cycle
    for _ in range(2):
        s = update_escalation(s.escalated, s.clean_streak, triggered=False, errored=False, deescalate_after=3)
        assert s.escalated
    s = update_escalation(s.escalated, s.clean_streak, triggered=False, errored=False, deescalate_after=3)
    assert (s.escalated, s.change) == (False, "deescalated")
    again = update_escalation(True, 0, triggered=True, errored=False, deescalate_after=3)
    assert again.change is None  # already escalated


def test_backoff() -> None:
    cap = timedelta(hours=1)
    assert [backoff_delay(n, cap) for n in (1, 2, 3, 4)] == [timedelta(minutes=m) for m in (1, 2, 4, 8)]
    assert backoff_delay(10, cap) == cap
    assert backoff_delay(1000, cap) == cap
    assert backoff_delay(5, timedelta(minutes=10)) == timedelta(minutes=10)
