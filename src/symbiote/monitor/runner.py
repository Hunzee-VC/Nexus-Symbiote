"""The monitoring cycle, the tick and the long-running scheduler (``spec/monitoring.md`` §1, §2, §6).

:func:`run_cycle` runs one agent through collect → drift → policy → dependencies → verification → report.
Each step records what it could not do (``not-attempted``/``unreachable``/``error``), never a clean result: a
check that was attempted but could not complete (an advisor lookup that failed, an attestation that could not be
verified) makes the cycle ``incomplete`` (exit 6), which never counts towards de-escalation.
:func:`tick` runs every due agent once (bounded concurrency) under the monitor's exclusive lock;
:func:`run_forever` sleeps until the next due agent and ticks again until stopped.
"""

from __future__ import annotations

import contextlib
import logging
import signal
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from symbiote.model.enums import DeltaEventType, FindingState, Severity, ToolSource
from symbiote.monitor.config import MonitorConfig, Target
from symbiote.monitor.risk import (
    RiskTier,
    at_least,
    backoff_delay,
    derive_tier,
    interval_for,
    max_tier,
    next_due,
    update_escalation,
)
from symbiote.monitor.state import AgentState, StateLockedError, StateStore

if TYPE_CHECKING:
    from symbiote.model.document import AgentBOM
    from symbiote.model.entities import Finding

__all__ = [
    "CycleRecord",
    "TickReport",
    "fingerprint",
    "open_store",
    "plan",
    "run_cycle",
    "run_forever",
    "tick",
]

log = logging.getLogger("symbiote.monitor")

CycleStatus = Literal["ok", "findings", "incomplete", "error"]

#: Drift events that count as a *definition drift* for escalation, whatever their severity.
DEFINITION_EVENTS = frozenset(
    {
        DeltaEventType.TOOL_DEFINITION_CHANGED,
        DeltaEventType.TOOL_ANNOTATIONS_CHANGED,
        DeltaEventType.TOOL_REGISTERED,
        DeltaEventType.SERVER_ADDED,
        DeltaEventType.SERVER_IDENTITY_CHANGED,
        DeltaEventType.INSTRUCTION_CHANGED,
        DeltaEventType.SKILL_CHANGED,
        DeltaEventType.MODEL_ADDED,
        DeltaEventType.MODEL_ROUTED,
        DeltaEventType.MODEL_ALIAS_RESOLVED,
    }
)
_ESCALATING_SIGNALS = frozenset({"vulnerable", "malicious"})
_MAX_MESSAGE = 500


class _BudgetExceededError(RuntimeError):
    pass


def fingerprint(finding: Finding) -> str:
    """``check_id`` + sorted subjects (§2 step 3)."""
    return f"{finding.check_id}|{','.join(sorted(finding.subject_refs))}"


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _short(text: str) -> str:
    return text if len(text) <= _MAX_MESSAGE else text[: _MAX_MESSAGE - 1] + "…"


@dataclass(slots=True)
class CycleRecord:
    """One agent's cycle (§2 step 6). ``to_json`` is what is appended to the agent's history."""

    agent: str
    started_at: str
    finished_at: str | None = None
    status: CycleStatus = "ok"
    tier: str = RiskTier.LOW.value
    base_tier: str = RiskTier.LOW.value
    escalated: bool = False
    escalation: str | None = None
    escalation_reasons: list[str] = field(default_factory=list)
    clean_streak: int = 0
    consecutive_errors: int = 0
    next_due_at: str | None = None
    snapshot: dict[str, Any] | None = None
    previous_snapshot: str | None = None
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    resolved_findings: list[str] = field(default_factory=list)
    failing: int = 0
    indeterminate: int = 0
    drift: list[dict[str, Any]] = field(default_factory=list)
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    dependency_coverage: str = "not-attempted"
    verification: list[dict[str, Any]] = field(default_factory=list)
    steps: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: Checks that were attempted (or required by the configuration) but could not reach a conclusion.
    incomplete: list[str] = field(default_factory=list)
    chain_conflict: bool = False
    #: Something new at or above ``fail_on`` (finding, drift, vulnerable/malicious dependency, verification).
    exceeds_fail_on: bool = False
    notifications: list[dict[str, Any]] = field(default_factory=list)

    @property
    def triggered(self) -> bool:
        return bool(self.escalation_reasons)

    def to_json(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "status": self.status,
            "tier": self.tier,
            "baseTier": self.base_tier,
            "escalated": self.escalated,
            "escalation": self.escalation,
            "escalationReasons": list(self.escalation_reasons),
            "cleanStreak": self.clean_streak,
            "consecutiveErrors": self.consecutive_errors,
            "nextDueAt": self.next_due_at,
            "snapshot": self.snapshot,
            "previousSnapshot": self.previous_snapshot,
            "newFindings": list(self.new_findings),
            "resolvedFindings": list(self.resolved_findings),
            "failing": self.failing,
            "indeterminate": self.indeterminate,
            "drift": list(self.drift),
            "dependencies": list(self.dependencies),
            "dependencyCoverage": self.dependency_coverage,
            "verification": list(self.verification),
            "steps": dict(self.steps),
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "incomplete": list(self.incomplete),
            "chainConflict": self.chain_conflict,
            "exceedsFailOn": self.exceeds_fail_on,
            "notifications": list(self.notifications),
        }

    def exit_code(self) -> int:
        """``spec/monitoring.md`` §6 for one record: 7 chain conflict, 1 over ``fail_on``, 6 error or incomplete
        (``cli.md``: a source needed but unavailable), else 0."""
        if self.chain_conflict:
            return 7
        if self.exceeds_fail_on:
            return 1
        if self.status in ("error", "incomplete"):
            return 6
        return 0


@dataclass(slots=True)
class TickReport:
    started_at: str
    finished_at: str | None = None
    records: list[CycleRecord] = field(default_factory=list)
    #: Agents that were not due, with their due time.
    not_due: dict[str, str | None] = field(default_factory=dict)
    disabled: list[str] = field(default_factory=list)
    next_wake_at: str | None = None

    @property
    def exit_code(self) -> int:
        codes = {r.exit_code() for r in self.records}
        for code in (7, 1, 6):
            if code in codes:
                return code
        return 0

    def to_json(self) -> dict[str, Any]:
        return {
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "ran": [r.agent for r in self.records],
            "notDue": dict(self.not_due),
            "disabled": list(self.disabled),
            "nextWakeAt": self.next_wake_at,
            "exitCode": self.exit_code,
            "records": [r.to_json() for r in self.records],
        }


def open_store(config: MonitorConfig) -> StateStore:
    return StateStore(
        config.state_dir,
        lock_timeout=config.lock_timeout.total_seconds(),
        stale_after=config.lock_stale_after.total_seconds(),
    )


# ---------------------------------------------------------------------------------------------- the cycle


class _Clock:
    """Cooperative per-agent budget: checked between steps (the scan has its own collector budget)."""

    def __init__(self, budget: timedelta) -> None:
        self.deadline = time.monotonic() + budget.total_seconds()

    def remaining(self) -> float:
        return self.deadline - time.monotonic()

    def check(self, step: str) -> None:
        if self.remaining() <= 0:
            raise _BudgetExceededError(f"time budget exhausted before {step}")


def _load_baseline(path: Path) -> AgentBOM:
    from symbiote.export.companion import load_companion

    max_bytes = 64 * 1024 * 1024
    with path.open("rb") as fh:
        raw = fh.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError(f"{path.name}: larger than {max_bytes} bytes")
    return load_companion(raw)


def _drift_events(delta: Any, against: str) -> list[dict[str, Any]]:
    return [
        {
            "against": against,
            "type": e.type.value,
            "subject": e.subject_ref,
            "severity": e.severity_hint.value,
            "before": e.before,
            "after": e.after,
            "detail": _short(e.detail or ""),
        }
        for e in delta.events
    ]


def _dependencies(
    bom: AgentBOM, config: MonitorConfig, store: StateStore, now: datetime, record: CycleRecord
) -> None:
    if not config.advisories:
        record.steps["dependencies"] = "not-attempted"
        record.dependency_coverage = "not-attempted"
        return
    try:
        from symbiote import advisories
    except ImportError as exc:  # pragma: no cover - the package ships with symbiote
        record.steps["dependencies"] = "not-attempted"
        record.dependency_coverage = "not-attempted"
        record.warnings.append(f"advisories unavailable: {type(exc).__name__}")
        return
    try:
        refs = advisories.dependencies_from_bom(bom)
        client = advisories.HttpClient(store.cache_dir, offline=config.offline)
        intel = advisories.check_dependencies(refs, client=client, now=now, policy=config.update_policy)
    except Exception as exc:
        record.steps["dependencies"] = "unreachable"
        record.dependency_coverage = "unreachable"
        record.errors.append(_short(f"dependencies: {type(exc).__name__}: {exc}"))
        record.incomplete.append("dependencies: the advisor check failed")
        return
    coverages: set[str] = set()
    for item in intel:
        coverages.add(item.coverage)
        record.dependencies.append(
            {
                "kind": item.ref.kind.value,
                "ecosystem": item.ref.ecosystem,
                "name": item.ref.name,
                "version": item.ref.version,
                "subjects": list(item.ref.subjects),
                "coverage": item.coverage,
                "recommended": item.recommended.version if item.recommended else None,
                "latest": item.latest.version if item.latest else None,
                "advisories": [a.id for a in item.advisories],
                "signals": [
                    {
                        "kind": s.kind.value,
                        "severity": s.severity,
                        "detail": _short(s.detail),
                        "reference": s.reference,
                    }
                    for s in item.signals
                ],
                "errors": [_short(e) for e in item.errors[:5]],
            }
        )
    # Dependencies no advisor exists for are ``not-attempted`` per item: recorded, but not a failed lookup.
    attempted = coverages - {"not-attempted"}
    if not intel or attempted == {"queried"}:
        coverage = "queried"
    elif not attempted:
        coverage = "not-attempted"
    elif attempted == {"unreachable"}:
        coverage = "unreachable"
    else:
        coverage = "partial"
    record.dependency_coverage = coverage
    record.steps["dependencies"] = coverage
    failed = [item.ref.name for item in intel if _lookup_failed(item)]
    if failed:
        shown = ", ".join(sorted(set(failed))[:10])
        record.incomplete.append(_short(f"dependencies: {len(failed)} lookup(s) did not complete ({shown})"))


#: The one ``partial`` coverage that is structural rather than a failure: the MCP Registry answered for a
#: package type no vulnerability advisor covers (see ``symbiote.advisories.engine``).
_STRUCTURAL_PARTIAL = "no vulnerability advisor for "


def _lookup_failed(item: Any) -> bool:
    """True when an advisor lookup for ``item`` was attempted and did not complete (never read as clean)."""
    if item.coverage == "unreachable":
        return True
    if item.coverage == "partial":
        return any(not str(e).startswith(_STRUCTURAL_PARTIAL) for e in item.errors) or not item.errors
    return False


def _attestation(target: Target, baseline: AgentBOM | None) -> dict[str, Any]:
    """Verify the approved snapshot's Sigstore bundle: identity policy, predicate type and digest binding.

    Only ``status="pass"`` is a clean result. ``baseline`` must already have passed
    :func:`symbiote.snapshot.commit.verify_document` (its declared digest matches its content).
    """
    from symbiote.attest.statements import predicate_type

    check = "attestation"
    att = target.attestation
    assert att is not None
    try:
        from symbiote.attest import sigstore_backend as sb
    except ImportError:
        return {
            "check": check,
            "status": "not-attempted",
            "severity": "high",
            "message": "symbiote.attest unavailable",
        }
    if not getattr(sb, "HAVE_SIGSTORE", False):
        return {
            "check": check,
            "status": "not-attempted",
            "severity": "high",
            "message": "Sigstore support is not installed (pip install 'symbiote[sign]')",
        }
    if baseline is None:
        return {
            "check": check,
            "status": "error",
            "severity": "high",
            "message": "attestation is configured but there is no usable baseline (approved snapshot) to bind it to",
        }
    try:
        spec = sb.VerifyPolicySpec.from_yaml(att.policy)
        result = sb.verify_bundle(
            att.bundle, spec, expected_predicate_types=(predicate_type("agentbom-snapshot"),)
        )
    except Exception as exc:
        return {
            "check": check,
            "status": "error",
            "severity": "high",
            "message": _short(f"{type(exc).__name__}: {exc}"),
        }
    outcome = str(getattr(result.outcome, "value", result.outcome))
    if outcome not in ("verified", "signature-valid-unconstrained"):
        status = "error" if outcome == "error" else "fail"
        return {
            "check": check,
            "status": status,
            "severity": "critical" if status == "fail" else "high",
            "message": _short(f"bundle verification: {outcome}: {result.reason or ''}"),
        }
    stmt = result.statement or {}
    subjects = stmt.get("subject") if isinstance(stmt, dict) else None
    want = baseline.snapshot.digest.split(":", 1)[-1]
    bound = isinstance(subjects, list) and any(
        isinstance(s, dict) and isinstance(s.get("digest"), dict) and s["digest"].get("sha256") == want
        for s in subjects
    )
    if not bound:
        return {
            "check": check,
            "status": "fail",
            "severity": "critical",
            "message": "the attestation does not bind the approved snapshot digest",
        }
    if outcome == "signature-valid-unconstrained":
        # The signature is valid but no signer identity was required: not evidence of *who* approved it.
        return {
            "check": check,
            "status": "unconstrained",
            "severity": "high",
            "message": _short(
                f"signature valid but the verify policy names no signer identity (signed by "
                f"{result.identity or 'unknown identity'})"
            ),
        }
    msg = f"verified for {result.identity or 'unknown identity'}"
    return {"check": check, "status": "pass", "severity": "info", "message": _short(msg)}


def run_cycle(
    target: Target,
    *,
    config: MonitorConfig,
    state: StateStore,
    now: datetime | None = None,
    notify_env: dict[str, str] | None = None,
) -> CycleRecord:
    """Run one monitoring cycle for ``target`` and persist its outcome (state, history, previous companion).

    Never raises for a failure of the agent's own inputs: those make a ``status="error"`` record.
    """
    from symbiote.export.companion import companion_bytes
    from symbiote.policy import run_policy
    from symbiote.scan import scan
    from symbiote.snapshot import ChainConflictError, ChainStore, diff
    from symbiote.snapshot.commit import verify_document

    injected_now = now is not None
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    clock = _Clock(config.agent_budget)
    prior = state.get(target.name)
    record = CycleRecord(agent=target.name, started_at=now.isoformat())
    record.previous_snapshot = prior.last_snapshot_digest
    fail_on = config.fail_on
    bom: AgentBOM | None = None
    failing: list[Finding] = []
    fingerprints: set[str] | None = None
    verification_failed = False
    try:
        # 1. Collect -------------------------------------------------------------------------------
        if not target.path.is_dir():
            raise FileNotFoundError(f"agent path {target.path} is not a directory")
        try:
            outcome = scan(
                target.path,
                agent_name=target.agent_name,
                now=now,
                collectors=list(target.collectors) if target.collectors else None,
                budget_seconds=max(1.0, min(20.0, clock.remaining())),
                store=state.chain_dir_for(target.name),
            )
        except ChainConflictError as exc:
            record.chain_conflict = True
            for issue in exc.issues:
                record.verification.append(
                    {
                        "check": issue.check_id,
                        "status": "fail",
                        "severity": issue.severity.value,
                        "message": _short(issue.message),
                    }
                )
            raise
        bom = outcome.bom
        record.steps["collect"] = "ok"
        record.snapshot = {
            "id": bom.snapshot.id,
            "digest": bom.snapshot.digest,
            "serial": bom.snapshot.serial,
            "subject": bom.subject,
        }
        record.warnings.extend(_short(w) for w in outcome.warnings[:20])
        for issue in outcome.chain_issues:
            record.verification.append(
                {
                    "check": issue.check_id,
                    "status": "fail",
                    "severity": issue.severity.value,
                    "message": _short(issue.message),
                }
            )
        if not outcome.chain_issues:
            record.verification.append(
                {
                    "check": "chain",
                    "status": "pass",
                    "severity": "info",
                    "message": f"serial {bom.snapshot.serial} extends the chain",
                }
            )

        # 2. Drift ---------------------------------------------------------------------------------
        clock.check("drift")
        previous: AgentBOM | None = None
        try:
            previous = state.load_previous(target.name)
        except Exception as exc:
            record.errors.append(_short(f"previous snapshot unreadable: {type(exc).__name__}: {exc}"))
        if previous is not None:
            record.drift.extend(_drift_events(diff(previous, bom), "previous"))
            record.steps["drift"] = "ok"
        else:
            record.steps["drift"] = "not-attempted"  # first cycle: nothing to compare against
        baseline: AgentBOM | None = None
        baseline_tampered = False
        if target.baseline is not None:
            try:
                baseline = _load_baseline(target.baseline)
            except Exception as exc:
                record.errors.append(
                    _short(f"baseline {target.baseline.name} unreadable: {type(exc).__name__}")
                )
            if baseline is not None and not verify_document(baseline):
                # The approved companion's content no longer matches its own Merkle commitment (edited after
                # approval): it must not drive drift, served-vs-approved or the attestation binding.
                baseline = None
                baseline_tampered = True
                record.verification.append(
                    {
                        "check": "baseline-commitment",
                        "status": "fail",
                        "severity": "critical",
                        "message": f"baseline {target.baseline.name} does not match its own snapshot digest "
                        "(modified after approval)",
                    }
                )
            if baseline is not None:
                record.drift.extend(_drift_events(diff(baseline, bom), "baseline"))
                record.steps["baseline"] = "ok"
            else:
                record.steps["baseline"] = "fail" if baseline_tampered else "error"

        # 3. Policy --------------------------------------------------------------------------------
        clock.check("policy")
        if baseline is not None or outcome.policy is None:
            policy = run_policy(bom, baseline=baseline, now=now)
        else:
            policy = outcome.policy
        if policy.errors:
            record.warnings.extend(_short(f"policy: {e}") for e in policy.errors[:10])
        failing = [f for f in policy.findings if f.state is FindingState.FAIL]
        record.failing = len(failing)
        record.indeterminate = sum(1 for f in policy.findings if f.state is FindingState.INDETERMINATE)
        fingerprints = {fingerprint(f) for f in failing}
        known = set(prior.findings) if prior.last_snapshot_digest is not None else set()
        seen_new: set[str] = set()
        for f in failing:
            fp = fingerprint(f)
            if fp in known or fp in seen_new:
                continue
            seen_new.add(fp)
            record.new_findings.append(
                {
                    "check": f.check_id,
                    "severity": f.severity.value,
                    "subjects": sorted(f.subject_refs),
                    "message": _short(f.message),
                    "fingerprint": fp,
                }
            )
        record.resolved_findings = sorted(known - fingerprints)
        record.steps["policy"] = "ok"

        # 4. Dependencies --------------------------------------------------------------------------
        clock.check("dependencies")
        _dependencies(bom, config, state, now, record)

        # 5. Verification --------------------------------------------------------------------------
        clock.check("verification")
        expiry = ChainStore.expiry_issues(bom.snapshot, now=now)
        if baseline is not None:
            expiry += ChainStore.expiry_issues(baseline.snapshot, now=now)
        for issue in expiry:
            record.verification.append(
                {
                    "check": issue.check_id,
                    "status": "fail",
                    "severity": issue.severity.value,
                    "message": _short(issue.message),
                }
            )
        if not expiry:
            record.verification.append(
                {
                    "check": "SYM-SNAP-002",
                    "status": "pass",
                    "severity": "info",
                    "message": "snapshot validity holds",
                }
            )
        if target.baseline is None:
            record.verification.append(
                {
                    "check": "SYM-TOOL-002",
                    "status": "not-attempted",
                    "severity": "high",
                    "message": "no baseline configured",
                }
            )
        elif baseline is None:
            record.verification.append(
                {
                    "check": "SYM-TOOL-002",
                    "status": "error",
                    "severity": "high",
                    "message": "baseline unusable" if baseline_tampered else "baseline unreadable",
                }
            )
        else:
            served = [f for f in policy.findings if f.check_id == "SYM-TOOL-002"]
            bad = [f for f in served if f.state is FindingState.FAIL]
            unsure = [f for f in served if f.state is FindingState.INDETERMINATE]
            if bad:
                for f in bad:
                    record.verification.append(
                        {
                            "check": "SYM-TOOL-002",
                            "status": "fail",
                            "severity": f.severity.value,
                            "message": _short(f.message),
                        }
                    )
            elif unsure:
                record.verification.append(
                    {
                        "check": "SYM-TOOL-002",
                        "status": "not-attempted",
                        "severity": "high",
                        "message": _short(unsure[0].message),
                    }
                )
            elif any(t.source is ToolSource.SERVED_LIVE for t in bom.tools):
                record.verification.append(
                    {
                        "check": "SYM-TOOL-002",
                        "status": "pass",
                        "severity": "info",
                        "message": "served tools match the approved baseline",
                    }
                )
            else:
                # No served tool definitions were captured, so there is nothing to compare: not a pass.
                record.verification.append(
                    {
                        "check": "SYM-TOOL-002",
                        "status": "not-attempted",
                        "severity": "high",
                        "message": "no served tools observed (live collection not enabled)",
                    }
                )
        if target.attestation is not None:
            record.verification.append(_attestation(target, baseline))
        else:
            record.verification.append(
                {
                    "check": "attestation",
                    "status": "not-attempted",
                    "severity": "info",
                    "message": "no attestation configured",
                }
            )
        record.steps["verification"] = "ok"

        # Persist the companion for the next cycle's drift diff.
        state.save_previous(target.name, companion_bytes(bom, validate=False))
    except _BudgetExceededError as exc:
        record.errors.append(str(exc))
    except ChainConflictError as exc:
        record.errors.append(_short(f"anti-rollback conflict: {exc}"))
    except Exception as exc:
        record.errors.append(_short(f"{type(exc).__name__}: {exc}"))
        log.debug("cycle for %s failed", target.name, exc_info=True)

    # Evaluate the cycle --------------------------------------------------------------------------
    verification_failed = any(v["status"] == "fail" for v in record.verification)
    errored = bool(record.errors) or bom is None or record.chain_conflict
    for v in record.verification:
        configured_attestation = v["check"] == "attestation" and target.attestation is not None
        if v["status"] in ("error", "unreachable") or (
            configured_attestation and v["status"] not in ("pass", "fail")
        ):
            record.incomplete.append(_short(f"verification {v['check']}: {v['status']}: {v['message']}"))
    incomplete = bool(record.incomplete)
    reasons: list[str] = []
    # On an agent's first cycle every finding is "new"; that establishes the baseline and does not escalate.
    first_cycle = prior.last_snapshot_digest is None
    for nf in record.new_findings:
        if not first_cycle and at_least(nf["severity"], Severity.HIGH):
            reasons.append(f"new {nf['severity']} finding {nf['check']}")
    for d in record.drift:
        if d["against"] == "previous" and (
            DeltaEventType(d["type"]) in DEFINITION_EVENTS or at_least(d["severity"], Severity.HIGH)
        ):
            reasons.append(f"drift: {d['type']} {d['subject']}")
    for dep in record.dependencies:
        for s in dep["signals"]:
            if s["kind"] in _ESCALATING_SIGNALS:
                reasons.append(f"{s['kind']} dependency {dep['name']}")
    if verification_failed:
        reasons.extend(
            f"verification failed: {v['check']}" for v in record.verification if v["status"] == "fail"
        )
    record.escalation_reasons = list(dict.fromkeys(reasons))[:50]

    over = any(at_least(nf["severity"], fail_on) for nf in record.new_findings)
    over = over or any(at_least(d["severity"], fail_on) for d in record.drift)
    over = over or any(
        s["kind"] in _ESCALATING_SIGNALS and at_least(s["severity"], fail_on)
        for dep in record.dependencies
        for s in dep["signals"]
    )
    over = over or any(
        v["status"] == "fail" and at_least(v["severity"], fail_on) for v in record.verification
    )
    record.exceeds_fail_on = over
    if errored:
        record.status = "error"
    elif over:
        record.status = "findings"
    elif incomplete:
        record.status = "incomplete"
    else:
        record.status = "ok"

    # Tier, escalation and the next due time -------------------------------------------------------
    if bom is not None:
        base = derive_tier(bom, target.environment, failing, bom.derived.flags, explicit=target.risk)
    else:
        base = (
            prior.tier
            if prior.tier is not None
            else derive_tier(None, target.environment, explicit=target.risk)
        )
    esc = update_escalation(
        prior.escalated,
        prior.clean_streak,
        triggered=bool(record.escalation_reasons),
        # An incomplete cycle is not clean: it never counts towards de-escalation.
        errored=errored or incomplete,
        deescalate_after=config.deescalate_after,
    )
    effective = RiskTier.CRITICAL if esc.escalated else base
    interval = interval_for(base, config.cadence, override=target.interval, escalated=esc.escalated)
    consecutive_errors = prior.consecutive_errors + 1 if errored else 0
    due = (
        now + backoff_delay(consecutive_errors, interval) if errored else next_due(target.name, now, interval)
    )
    record.base_tier = base.value
    record.tier = effective.value
    record.escalated = esc.escalated
    record.escalation = esc.change
    record.clean_streak = esc.clean_streak
    record.consecutive_errors = consecutive_errors
    record.next_due_at = due.isoformat()

    # 6. Report ------------------------------------------------------------------------------------
    if config.notify:
        from symbiote.monitor.notify import notify

        record.notifications = [d.to_json() for d in notify(record, config.notify, env=notify_env)]
    record.finished_at = (now if injected_now else max(now, datetime.now(UTC))).isoformat()

    new_state = AgentState(
        name=target.name,
        last_run_at=now,
        next_due_at=due,
        tier=base,
        escalated=esc.escalated,
        clean_streak=esc.clean_streak,
        consecutive_errors=consecutive_errors,
        last_snapshot_digest=bom.snapshot.digest if bom is not None else prior.last_snapshot_digest,
        last_serial=bom.snapshot.serial if bom is not None else prior.last_serial,
        # Keep the last known findings when the policy step did not complete, so nothing is "resolved" by error.
        findings=sorted(fingerprints) if fingerprints is not None else list(prior.findings),
        last_status=record.status,
        last_error="; ".join(record.errors)[:_MAX_MESSAGE] if record.errors else None,
        last_summary={
            "failing": record.failing,
            "indeterminate": record.indeterminate,
            "newFindings": len(record.new_findings),
            "resolvedFindings": len(record.resolved_findings),
            "drift": len(record.drift),
            "dependencySignals": sum(len(d["signals"]) for d in record.dependencies),
            "verificationFailures": sum(1 for v in record.verification if v["status"] == "fail"),
        },
    )
    try:
        state.append_history(target.name, record.to_json())
        state.put(new_state)
    except OSError as exc:
        record.status = "error"
        record.errors.append(_short(f"could not persist monitor state: {exc.strerror or exc}"))
    return record


# ---------------------------------------------------------------------------------------------- scheduling


def _aware(value: datetime) -> datetime:
    """Read a naive datetime as UTC so it can be compared with the (aware) timestamps in the state."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _current_tier(t: Target, st: AgentState) -> RiskTier:
    """The base tier under the *current* configuration: the stored derived tier, never below an explicit tier."""
    if st.tier is None:
        return derive_tier(None, t.environment, explicit=t.risk)
    return max_tier(st.tier, t.risk)


def _effective_due(t: Target, st: AgentState, config: MonitorConfig) -> datetime | None:
    """When ``t`` is next due: the stored due time, or sooner when the configuration now asks for it.

    The stored ``next_due_at`` was computed from the tier, interval and cadence in force at the last cycle. If
    the configuration has since shortened them (``risk: critical``, a smaller ``interval`` or ``cadence``), the
    agent is due at ``last_run_at`` + the current interval (+ jitter) instead. Error backoff (an earlier stored
    due time) is kept.
    """
    if st.next_due_at is None or st.last_run_at is None:
        return st.next_due_at
    interval = interval_for(_current_tier(t, st), config.cadence, override=t.interval, escalated=st.escalated)
    return min(st.next_due_at, next_due(t.name, st.last_run_at, interval))


def _is_due(due_at: datetime | None, now: datetime) -> bool:
    return due_at is None or due_at <= now


def plan(config: MonitorConfig, *, now: datetime | None = None) -> list[dict[str, Any]]:
    """Due time, tier and escalation per agent, without running anything (``monitor plan``)."""
    now = _aware(now or datetime.now(UTC))
    store = open_store(config)
    states = store.load()
    out: list[dict[str, Any]] = []
    for t in config.agents:
        st = states.get(t.name, AgentState(name=t.name))
        base = _current_tier(t, st)
        effective = RiskTier.CRITICAL if st.escalated else base
        due_at = _effective_due(t, st, config)
        out.append(
            {
                "agent": t.name,
                "path": str(t.path),
                "environment": t.environment,
                "risk": t.risk.value if t.risk else "auto",
                "tier": effective.value,
                "baseTier": base.value,
                "escalated": st.escalated,
                "interval": str(
                    interval_for(base, config.cadence, override=t.interval, escalated=st.escalated)
                ),
                "lastRunAt": _iso(st.last_run_at),
                "nextDueAt": _iso(due_at),
                "due": t.enabled and _is_due(due_at, now),
                "enabled": t.enabled,
            }
        )
    return out


def _next_wake(config: MonitorConfig, store: StateStore) -> datetime | None:
    states = store.load()
    times: list[datetime] = []
    for t in config.agents:
        if not t.enabled:
            continue
        st = states.get(t.name)
        due_at = _effective_due(t, st, config) if st is not None else None
        if due_at is None:
            return None  # never run: due now
        times.append(due_at)
    return min(times) if times else None


def tick(
    config: MonitorConfig,
    *,
    now: datetime | None = None,
    notify_env: dict[str, str] | None = None,
) -> TickReport:
    """Run every agent that is due (``monitor tick``), under the exclusive monitor lock.

    Raises :class:`~symbiote.monitor.state.StateLockedError` when another tick holds the lock past the
    configured timeout.
    """
    fixed_now = _aware(now) if now is not None else None
    start = fixed_now or datetime.now(UTC)
    report = TickReport(started_at=start.isoformat())
    store = open_store(config)
    with store.locked():
        states = store.load(refresh=True)
        due: list[Target] = []
        for t in config.agents:
            if not t.enabled:
                report.disabled.append(t.name)
                continue
            st = states.get(t.name, AgentState(name=t.name))
            due_at = _effective_due(t, st, config)
            if _is_due(due_at, start):
                due.append(t)
            else:
                report.not_due[t.name] = _iso(due_at)

        def one(t: Target) -> CycleRecord:
            try:
                return run_cycle(
                    t, config=config, state=store, now=fixed_now or datetime.now(UTC), notify_env=notify_env
                )
            finally:
                store.heartbeat()

        if due:
            workers = max(1, min(config.concurrency, len(due)))
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="symbiote-monitor") as pool:
                report.records = list(pool.map(one, due))
        wake = _next_wake(config, store)
        report.next_wake_at = _iso(wake)
    report.finished_at = (fixed_now or datetime.now(UTC)).isoformat()
    return report


@contextlib.contextmanager
def _signals(stop: threading.Event) -> Iterator[None]:
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous: dict[signal.Signals, Any] = {}

    def handler(signum: int, _frame: Any) -> None:
        log.info("signal %s received: stopping after the current tick", signum)
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(ValueError, OSError):
            previous[sig] = signal.signal(sig, handler)
    try:
        yield
    finally:
        for sig, old in previous.items():
            with contextlib.suppress(ValueError, OSError):
                signal.signal(sig, old)


def run_forever(
    config: MonitorConfig,
    *,
    stop: threading.Event | None = None,
    on_tick: Callable[[TickReport], None] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> None:
    """Tick, sleep until the next due agent (at most ``config.max_sleep``, at least one second), repeat.

    Stops cleanly when ``stop`` is set or on SIGINT/SIGTERM (when running on the main thread). An injected
    ``clock`` drives both the ticks' ``now`` and the sleep calculation (deterministic scheduling in tests).
    """
    stop = stop or threading.Event()
    now_fn = clock or (lambda: datetime.now(UTC))
    cap = max(1.0, config.max_sleep.total_seconds())
    with _signals(stop):
        while not stop.is_set():
            wake: datetime | None = None
            try:
                report = tick(config, now=clock() if clock is not None else None)
                if on_tick is not None:
                    on_tick(report)
                wake = datetime.fromisoformat(report.next_wake_at) if report.next_wake_at else None
            except StateLockedError as exc:
                log.warning("tick skipped: %s", exc)
            except Exception as exc:  # the scheduler keeps going; the next tick retries
                log.warning("tick failed: %s: %s", type(exc).__name__, str(exc)[:300])
            delay = cap if wake is None else (wake - now_fn()).total_seconds()
            stop.wait(min(cap, max(1.0, delay)))


def records_exit_code(records: Sequence[CycleRecord]) -> int:
    report = TickReport(started_at="", records=list(records))
    return report.exit_code
