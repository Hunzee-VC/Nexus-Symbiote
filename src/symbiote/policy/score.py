"""Completeness score (``spec/conformance.md`` "Completeness score").

``0-100 = sum(weight * field presence)`` over eight areas, reported **always** with the assurance distribution of
every claim in the document. It measures how much of the agent the BOM describes and how well that is
evidenced — it is never a trust or safety score, and the report says so.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any, Final

from symbiote.authz.classify import side_effect_class
from symbiote.model.document import AgentBOM
from symbiote.model.enums import (
    ApprovalGate,
    AssuranceLevel,
    Classification,
    CoverageStatus,
    CredentialKind,
    EnforcementPointKind,
    SideEffectClass,
    SignatureStatus,
    Surface,
    TrustTier,
    ValueState,
)

__all__ = ["WEIGHTS", "ScoreReport", "completeness_score"]

WEIGHTS: Final[dict[str, int]] = {
    "tools": 25,
    "authorization": 20,
    "models": 15,
    "data": 10,
    "identity": 10,
    "instructions": 10,
    "coverage": 5,
    "evidence": 5,
}
DISCLAIMER: Final = "BOM completeness, not a trust or safety score."


@dataclass(frozen=True, slots=True)
class AreaScore:
    area: str
    weight: int
    present: int
    total: int
    missing: tuple[str, ...]

    status: str = "assessed"

    @property
    def fraction(self) -> float:
        return self.present / self.total if self.total else 0.0


@dataclass(frozen=True, slots=True)
class ScoreReport:
    score: int
    areas: tuple[AreaScore, ...]
    assurance: dict[str, float]

    def to_json(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "note": DISCLAIMER,
            "areas": [
                {
                    "area": a.area,
                    "weight": a.weight,
                    "present": a.present,
                    "total": a.total,
                    "status": a.status,
                    "missing": list(a.missing[:25]),
                }
                for a in self.areas
            ],
            "assurance": self.assurance,
        }


def _area(
    name: str, checks: Iterable[tuple[str, bool]], bom: AgentBOM, surface: Surface | None = None
) -> AreaScore:
    items = list(checks)
    if not items:
        coverage = bom.coverage.surfaces[surface] if surface is not None else None
        confirmed_empty = (
            coverage is not None
            and coverage.status is CoverageStatus.QUERIED
            and coverage.items_seen == 0
            and bool(coverage.sources)
            and all(run.ok and run.items == 0 for run in coverage.sources)
        )
        if confirmed_empty:
            return AreaScore(name, WEIGHTS[name], 0, 0, (), "not-applicable")
        return AreaScore(name, WEIGHTS[name], 0, 0, ("no applicable facts established",), "unknown")
    missing = tuple(label for label, ok in items if not ok)
    return AreaScore(name, WEIGHTS[name], len(items) - len(missing), len(items), missing)


def _present(claim: Any) -> bool:
    return claim is not None and getattr(claim, "state", None) is ValueState.PRESENT


def _tools(bom: AgentBOM) -> Iterator[tuple[str, bool]]:
    for s in bom.tool_servers:
        yield f"{s.id}: transport", _present(s.transport)
        yield f"{s.id}: package or endpoint", _present(s.package) or _present(s.endpoint) or bool(s.command)
        yield f"{s.id}: authentication", _present(s.authentication)
        yield f"{s.id}: toolset digest", _present(s.toolset_digest)
    for t in bom.tools:
        yield f"{t.id}: digest", t.digest.ok
        yield f"{t.id}: annotations", _present(t.annotations)
        yield f"{t.id}: approval gate", t.approval_gate is not ApprovalGate.UNKNOWN
        yield f"{t.id}: side-effect class", side_effect_class(t) is not SideEffectClass.UNKNOWN


def _authorization(bom: AgentBOM) -> Iterator[tuple[str, bool]]:
    granted = {g.subject_ref for g in bom.grants}
    for s in bom.tool_servers:
        yield f"{s.id}: declared grant", s.id in granted
    for g in bom.grants:
        yield (
            f"{g.id}: enforcement point",
            g.enforcement_point.kind not in (EnforcementPointKind.UNKNOWN, EnforcementPointKind.NONE),
        )
        yield f"{g.id}: credential binding", g.credential_binding_ref is not None


def _models(bom: AgentBOM) -> Iterator[tuple[str, bool]]:
    for m in bom.models:
        yield f"{m.id}: identity", _present(m.weights) or _present(m.hosted)
        if m.weights is not None:
            yield f"{m.id}: serialization", _present(m.serialization)
            yield (
                f"{m.id}: verified signature",
                m.signature is not None and m.signature.status is SignatureStatus.VERIFIED,
            )
        if m.hosted is not None and m.hosted.value is not None:
            yield f"{m.id}: resolved snapshot", _present(m.hosted.value.resolved_ref)


def _data(bom: AgentBOM) -> Iterator[tuple[str, bool]]:
    for d in bom.data_sources:
        yield f"{d.id}: trust tier", d.trust_tier is not TrustTier.UNKNOWN
        yield f"{d.id}: classification", d.classification is not Classification.UNKNOWN
        yield f"{d.id}: writers", _present(d.writers)


def _identity(bom: AgentBOM) -> Iterator[tuple[str, bool]]:
    for c in bom.credential_bindings:
        yield f"{c.id}: credential kind", c.credential_kind is not CredentialKind.UNKNOWN
        yield f"{c.id}: identity", c.identity_ref in {i.id for i in bom.identities}


def _instructions(bom: AgentBOM) -> Iterator[tuple[str, bool]]:
    for i in bom.instructions:
        yield f"{i.id}: digest", bool(i.digest)
        yield f"{i.id}: editors", _present(i.editors)
    for s in bom.skills:
        yield f"{s.id}: manifest", bool(s.manifest.resources)


def _coverage(bom: AgentBOM) -> Iterator[tuple[str, bool]]:
    for surface, cov in sorted(bom.coverage.surfaces.items(), key=lambda kv: kv[0].value):
        yield f"surface {surface.value} queried", cov.status is CoverageStatus.QUERIED


def _evidence(bom: AgentBOM) -> Iterator[tuple[str, bool]]:
    for _, entity in bom.iter_entities():
        prov = getattr(entity, "provenance", None)
        if prov is not None:
            yield f"{entity.id}: locator or evidence", bool(prov.locator or prov.evidence)


def _claims(obj: Any) -> Iterator[str]:
    if isinstance(obj, dict):
        if "assurance" in obj and ("state" in obj or "value" in obj):
            yield str(obj["assurance"])
        for value in obj.values():
            yield from _claims(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _claims(value)


def completeness_score(bom: AgentBOM) -> ScoreReport:
    areas = (
        _area("tools", _tools(bom), bom, Surface.TOOLS),
        _area("authorization", _authorization(bom), bom, Surface.POLICY),
        _area("models", _models(bom), bom, Surface.MODEL_GATEWAY),
        _area("data", _data(bom), bom, Surface.DATA),
        _area("identity", _identity(bom), bom, Surface.IDENTITY),
        _area("instructions", _instructions(bom), bom, Surface.INSTRUCTIONS),
        _area("coverage", _coverage(bom), bom),
        _area("evidence", _evidence(bom), bom),
    )
    total_weight = sum(a.weight for a in areas if a.status != "not-applicable")
    score = round(100 * sum(a.weight * a.fraction for a in areas) / total_weight)
    tally = Counter(_claims(bom.to_json_dict()))
    n = sum(tally.values()) or 1
    assurance = {level.value: round(tally.get(level.value, 0) / n, 4) for level in AssuranceLevel}
    return ScoreReport(score=score, areas=areas, assurance=assurance)
