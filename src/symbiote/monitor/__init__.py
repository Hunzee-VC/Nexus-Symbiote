"""Continuous assurance: risk-tiered re-scanning and re-verification of agents (``spec/monitoring.md``).

``tick`` runs every agent that is due (for cron, systemd timers, Kubernetes CronJobs and scheduled CI);
``run_forever`` is the long-running scheduler. Each agent's cadence follows its risk tier (``critical`` 10 min,
``high`` 1 h, ``medium`` 1 d, ``low`` 14 d), with deterministic jitter, adaptive escalation and error backoff.
"""

from __future__ import annotations

from symbiote.monitor.config import (
    AttestationConfig,
    ConfigError,
    MonitorConfig,
    NotifyTarget,
    Target,
    config_from_mapping,
    load_config,
)
from symbiote.monitor.notify import Delivery, build_payload, cycle_events, notify
from symbiote.monitor.risk import (
    DEFAULT_CADENCE,
    MIN_INTERVAL,
    EscalationState,
    RiskTier,
    backoff_delay,
    derive_tier,
    interval_for,
    jitter,
    next_due,
    parse_interval,
    update_escalation,
)
from symbiote.monitor.runner import CycleRecord, TickReport, fingerprint, plan, run_cycle, run_forever, tick
from symbiote.monitor.state import AgentState, StateError, StateLockedError, StateStore

__all__ = [
    "DEFAULT_CADENCE",
    "MIN_INTERVAL",
    "AgentState",
    "AttestationConfig",
    "ConfigError",
    "CycleRecord",
    "Delivery",
    "EscalationState",
    "MonitorConfig",
    "NotifyTarget",
    "RiskTier",
    "StateError",
    "StateLockedError",
    "StateStore",
    "Target",
    "TickReport",
    "backoff_delay",
    "build_payload",
    "config_from_mapping",
    "cycle_events",
    "derive_tier",
    "fingerprint",
    "interval_for",
    "jitter",
    "load_config",
    "next_due",
    "notify",
    "parse_interval",
    "plan",
    "run_cycle",
    "run_forever",
    "tick",
    "update_escalation",
]
