"""Check specifications, the check registry and the evaluation context (``spec/checks.md``).

A check is a pure function from a :class:`PolicyContext` to findings. It must:

* cite every entity it read (``Finding.inputs``) and the entities it judges (``subject_refs``);
* report ``indeterminate`` — never pass — when a required input is unknown;
* carry its threat mappings and a remediation that tells an operator exactly what to change.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from symbiote.authz.graph import BomIndex
from symbiote.model.common import ThreatRef
from symbiote.model.document import AgentBOM
from symbiote.model.entities import Finding
from symbiote.model.enums import FindingState, Severity

__all__ = [
    "CHECKS",
    "SEVERITY_ORDER",
    "CheckSpec",
    "PolicyContext",
    "asi",
    "atlas",
    "check",
    "llm",
]

#: Lower index = more severe.
SEVERITY_ORDER: Final[tuple[Severity, ...]] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def asi(n: int) -> ThreatRef:
    """OWASP Top 10 for Agentic Applications (Dec 2025) id ``ASI01``..``ASI10``."""
    return ThreatRef(framework="owasp-asi-2025", id=f"ASI{n:02d}")


def llm(n: int) -> ThreatRef:
    """OWASP Top 10 for LLM Applications 2025 id ``LLM01``..``LLM10``."""
    return ThreatRef(framework="owasp-llm-2025", id=f"LLM{n:02d}")


def atlas(technique: str) -> ThreatRef:
    """MITRE ATLAS technique id, e.g. ``AML.T0109``."""
    return ThreatRef(framework="mitre-atlas", id=technique)


@dataclass(frozen=True, slots=True)
class PolicyContext:
    """Everything a check may read."""

    bom: AgentBOM
    index: BomIndex
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    #: approved (or declared) snapshot the deployed/observed document is compared with
    baseline: AgentBOM | None = None
    #: anti-rollback state: ``{(agent_ref, kind): {"serial": int, "digest": str}}``
    state: Mapping[tuple[str, str], Mapping[str, Any]] = field(default_factory=dict)
    options: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def for_bom(cls, bom: AgentBOM, **kwargs: Any) -> PolicyContext:
        return cls(bom=bom, index=BomIndex(bom), **kwargs)

    def locator_of(self, entity_id: str) -> str | None:
        entity = self.index.get(entity_id)
        prov = getattr(entity, "provenance", None)
        return getattr(prov, "locator", None)


CheckFn = Callable[["CheckSpec", PolicyContext], Iterable[Finding]]


@dataclass(frozen=True, slots=True)
class CheckSpec:
    id: str
    title: str
    severity: Severity
    description: str
    mappings: tuple[ThreatRef, ...]
    remediation: str
    inputs: tuple[str, ...]
    fn: CheckFn
    #: Rego rule body for ``symbiote policy export-rego`` (empty = evaluated by the built-in engine only)
    rego: str = ""
    #: True for checks introduced from the 2026 review gap analysis (documented in ``spec/checks.md`` §2.1)
    extension: bool = False

    def run(self, ctx: PolicyContext) -> list[Finding]:
        return list(self.fn(self, ctx))

    def finding(
        self,
        ctx: PolicyContext,
        *,
        subjects: Iterable[str],
        message: str,
        inputs: Iterable[str] = (),
        state: FindingState = FindingState.FAIL,
        severity: Severity | None = None,
        locator: str | None = None,
    ) -> Finding:
        subject_list = sorted(dict.fromkeys(subjects))
        input_list = sorted(dict.fromkeys([*subject_list, *inputs]))
        loc = (
            locator
            if locator is not None
            else next((lo for lo in (ctx.locator_of(s) for s in subject_list) if lo), None)
        )
        return Finding(
            check_id=self.id,
            severity=severity or self.severity,
            state=state,
            subject_refs=subject_list,
            inputs=input_list,
            message=message,
            mappings=list(self.mappings),
            locator=loc,
        )


#: Registry populated by :func:`check` at import time of ``symbiote.policy.checks``.
CHECKS: dict[str, CheckSpec] = {}


def check(
    check_id: str,
    title: str,
    severity: Severity,
    *,
    mappings: Iterable[ThreatRef] = (),
    remediation: str,
    inputs: Iterable[str] = (),
    description: str = "",
    rego: str = "",
    extension: bool = False,
) -> Callable[[CheckFn], CheckFn]:
    """Register a check function under ``check_id``."""

    def decorator(fn: CheckFn) -> CheckFn:
        if check_id in CHECKS:
            raise ValueError(f"duplicate check id {check_id}")
        CHECKS[check_id] = CheckSpec(
            id=check_id,
            title=title,
            severity=severity,
            description=description or (fn.__doc__ or "").strip(),
            mappings=tuple(mappings),
            remediation=remediation,
            inputs=tuple(inputs),
            fn=fn,
            rego=rego,
            extension=extension,
        )
        return fn

    return decorator
