"""Policy engine: run checks, order findings, compute flags, decide the exit status (``spec/checks.md`` §4)."""

from __future__ import annotations

import fnmatch
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from symbiote.authz.flags import compute_flags
from symbiote.model.document import AgentBOM, Derived
from symbiote.model.entities import Finding, Flag
from symbiote.model.enums import FindingState, Severity
from symbiote.policy import checks as _checks  # noqa: F401 - registers the built-in checks
from symbiote.policy.rego import REGO_RULES
from symbiote.policy.spec import CHECKS, SEVERITY_ORDER, CheckSpec, PolicyContext

__all__ = ["PolicyResult", "explain", "list_checks", "run_policy", "severity_at_least"]

_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}


def severity_at_least(severity: Severity, threshold: Severity) -> bool:
    """True when ``severity`` is as severe as ``threshold`` or more."""
    return _RANK[severity] <= _RANK[threshold]


@dataclass(frozen=True, slots=True)
class PolicyResult:
    findings: tuple[Finding, ...]
    flags: tuple[Flag, ...]
    checks_run: tuple[str, ...]
    errors: tuple[str, ...] = field(default_factory=tuple)

    def failing(
        self, fail_on: Severity = Severity.HIGH, *, include_indeterminate: bool = False
    ) -> list[Finding]:
        states = (
            {FindingState.FAIL, FindingState.INDETERMINATE} if include_indeterminate else {FindingState.FAIL}
        )
        return [f for f in self.findings if f.state in states and severity_at_least(f.severity, fail_on)]

    def exit_code(self, fail_on: Severity = Severity.HIGH, *, include_indeterminate: bool = False) -> int:
        """``1`` when any finding at or above ``fail_on`` fails (``spec/cli.md`` exit codes), else ``0``."""
        return 1 if self.failing(fail_on, include_indeterminate=include_indeterminate) else 0

    def counts(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for state in FindingState:
            tally = Counter(f.severity.value for f in self.findings if f.state is state)
            out[state.value] = {sev.value: tally.get(sev.value, 0) for sev in SEVERITY_ORDER}
        return out

    def apply(self, bom: AgentBOM) -> AgentBOM:
        """Return ``bom`` with ``derived.flags`` and ``derived.findings`` replaced by this result."""
        derived = Derived(flags=list(self.flags), findings=list(self.findings))
        updated: AgentBOM = bom.replace(derived=derived.model_dump(mode="python"))
        return updated


def _selected(check_id: str, select: Iterable[str] | None, exclude: Iterable[str]) -> bool:
    if any(fnmatch.fnmatch(check_id, pat) for pat in exclude):
        return False
    return select is None or any(fnmatch.fnmatch(check_id, pat) for pat in select)


def run_policy(
    bom: AgentBOM,
    *,
    select: Iterable[str] | None = None,
    exclude: Iterable[str] = (),
    baseline: AgentBOM | None = None,
    state: Mapping[tuple[str, str], Mapping[str, Any]] | None = None,
    now: datetime | None = None,
    options: Mapping[str, Any] | None = None,
) -> PolicyResult:
    """Evaluate every selected check (glob patterns such as ``SYM-MCP-*``) and compute the flags.

    A check that raises does not abort the run: it yields an ``indeterminate`` finding naming the error, so a
    broken check can never be mistaken for a passing one.
    """
    kwargs: dict[str, Any] = {"baseline": baseline, "state": state or {}, "options": options or {}}
    if now is not None:
        kwargs["now"] = now
    ctx = PolicyContext.for_bom(bom, **kwargs)
    select_list = list(select) if select is not None else None
    exclude_list = list(exclude)
    findings: list[Finding] = []
    errors: list[str] = []
    ran: list[str] = []
    for check_id in sorted(CHECKS):
        if not _selected(check_id, select_list, exclude_list):
            continue
        spec = CHECKS[check_id]
        ran.append(check_id)
        try:
            findings.extend(spec.run(ctx))
        except Exception as exc:  # a crashing check must surface as indeterminate, never as a pass
            errors.append(f"{check_id}: {type(exc).__name__}: {exc}")
            findings.append(
                spec.finding(
                    ctx,
                    subjects=[bom.subject],
                    state=FindingState.INDETERMINATE,
                    message=f"Check could not be evaluated: {type(exc).__name__}.",
                )
            )
    findings.sort(key=lambda f: (_RANK[f.severity], f.check_id, f.state.value, f.subject_refs, f.message))
    flags = compute_flags(bom, baseline=baseline, index=ctx.index)
    return PolicyResult(
        findings=tuple(findings), flags=tuple(flags), checks_run=tuple(ran), errors=tuple(errors)
    )


def list_checks() -> list[CheckSpec]:
    return [CHECKS[c] for c in sorted(CHECKS)]


def explain(check_id: str) -> dict[str, Any]:
    """Documentation record for ``symbiote policy explain ID``."""
    spec = CHECKS[check_id]
    return {
        "id": spec.id,
        "title": spec.title,
        "severity": spec.severity.value,
        "description": spec.description,
        "remediation": spec.remediation,
        "inputs": list(spec.inputs),
        "mappings": [{"framework": m.framework, "id": m.id} for m in spec.mappings],
        "extension": spec.extension,
        "rego": spec.id in REGO_RULES,
    }
