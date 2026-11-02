"""The ShadowScan L0-L5 autonomy scale and its projection onto ISO/IEC 22989 (``spec/shadowscan-mapping.md §3``).

ShadowScan labels each applicable finding with an **interval** ``[floor, ceiling]`` on a six-step scale
(``shadowscan.autonomy/v1``): the floor is the lowest level the evidence proves and rises only on evidence; the
ceiling is the highest level that positive restriction evidence has not ruled out and is 5 unless such evidence
exists. Unknown never counts as low — the same invariant as Symbiote's I2.

Symbiote's agent-wide summary is the ISO/IEC 22989 automation ladder (the SPDX 3.1 ``isoAutomationLevel``
names). The projection below is a strictly increasing injection, so a ShadowScan level survives a round trip
unchanged; ISO ``autonomous`` (a system that sets its own goals) has no ShadowScan counterpart and maps back to
L5 only with a recorded loss.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from symbiote.model.common import EvidenceRef
from symbiote.model.entities import AutonomyAssessment, AutonomyBasis
from symbiote.model.enums import AutonomyInitiation, AutonomyOversight, IsoAutomationLevel

SCALE = "shadowscan.autonomy/v1"
MIN_LEVEL = 0
MAX_LEVEL = 5
MAX_BASIS = 32


@dataclass(frozen=True, slots=True)
class Level:
    """One step of the ShadowScan scale."""

    number: int
    name: str
    label: str
    iso: IsoAutomationLevel
    meaning: str

    @property
    def title(self) -> str:
        return f"L{self.number} {self.label}"


LEVELS: tuple[Level, ...] = (
    Level(
        0,
        "chatbot",
        "Chatbot",
        IsoAutomationLevel.NOT_AUTOMATED,
        "Answers only; no tools or actions. A person starts every exchange and performs every action.",
    ),
    Level(
        1,
        "copilot",
        "Copilot",
        IsoAutomationLevel.ASSISTIVE_AUTOMATION,
        "Assists a person inside their session with drafts and read-only tools; the person performs or confirms every action.",
    ),
    Level(
        2,
        "supervised",
        "Supervised",
        IsoAutomationLevel.PARTIAL_AUTOMATION,
        "Runs side-effecting tool actions, each approved by a person who also starts the run.",
    ),
    Level(
        3,
        "semi-autonomous",
        "Semi-Autonomous / Agentic Workflow",
        IsoAutomationLevel.CONDITIONAL_AUTOMATION,
        "Multi-step execution with approval at checkpoints rather than per action; may be event-triggered.",
    ),
    Level(
        4,
        "high-autonomy",
        "High Autonomy",
        IsoAutomationLevel.HIGH_AUTOMATION,
        "Plans and acts in a loop with write or execution capabilities and no per-action approval; people supervise by exception.",
    ),
    Level(
        5,
        "fully-autonomous",
        "Fully Autonomous",
        IsoAutomationLevel.FULL_AUTOMATION,
        "Starts itself (event, schedule or another agent) and acts with no approval gates; people only monitor.",
    ),
)

_BY_NUMBER = {lv.number: lv for lv in LEVELS}
_BY_NAME = {lv.name: lv for lv in LEVELS}
_BY_ISO = {lv.iso: lv for lv in LEVELS}

#: Rank used when widening merged intervals (ShadowScan ``merge_autonomy`` semantics): an unknown gate admits
#: more autonomy than a recorded one, and a trigger more than a person starting the run.
OVERSIGHT_RANK = {AutonomyOversight.GATED: 0, AutonomyOversight.UNKNOWN: 1, AutonomyOversight.BYPASSED: 2}
INITIATION_RANK = {
    AutonomyInitiation.HUMAN: 0,
    AutonomyInitiation.UNKNOWN: 1,
    AutonomyInitiation.EVENT: 2,
    AutonomyInitiation.SCHEDULE: 3,
}


def level(number: int) -> Level:
    if number not in _BY_NUMBER:
        raise ValueError(f"ShadowScan autonomy level must be 0..5, got {number!r}")
    return _BY_NUMBER[number]


def level_by_name(name: str) -> Level | None:
    return _BY_NAME.get(name)


def to_iso(number: int) -> IsoAutomationLevel:
    """ISO/IEC 22989 projection of a ShadowScan level (strictly increasing, injective)."""
    return level(number).iso


def from_iso(value: IsoAutomationLevel | str) -> tuple[int, bool]:
    """``(shadowscan level, lossless)``: ``autonomous`` has no counterpart and maps to L5 with ``lossless=False``."""
    iso = IsoAutomationLevel(value)
    if iso is IsoAutomationLevel.AUTONOMOUS:
        return MAX_LEVEL, False
    return _BY_ISO[iso].number, True


def _int_level(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if MIN_LEVEL <= value <= MAX_LEVEL else None


def _basis(entries: Any) -> list[AutonomyBasis]:
    out: list[AutonomyBasis] = []
    for item in entries if isinstance(entries, list) else []:
        if not isinstance(item, Mapping):
            continue
        bound, rule, value = item.get("bound"), item.get("rule"), item.get("value")
        if not isinstance(bound, str) or not isinstance(rule, str) or isinstance(value, (list, dict)):
            continue
        out.append(AutonomyBasis(bound=bound, rule=rule, value=str(value)))
        if len(out) >= MAX_BASIS:
            break
    return out


def assessment_from_metadata(
    autonomy: Mapping[str, Any],
    *,
    assessor: str | None = None,
    evidence: Iterable[EvidenceRef] = (),
    observed_at: datetime | None = None,
) -> AutonomyAssessment | None:
    """Parse a ShadowScan ``metadata.autonomy`` block; ``None`` when it is not a well-formed v1 block.

    A malformed block is not an assessment: pretending to know the autonomy of a finding whose block a plugin
    or an older report corrupted would fail open, so the caller records the finding without one.
    """
    if autonomy.get("schema") != SCALE:
        return None
    floor, ceiling = _int_level(autonomy.get("floor")), _int_level(autonomy.get("ceiling"))
    if floor is None or ceiling is None or floor > ceiling:
        return None
    try:
        oversight = AutonomyOversight(str(autonomy.get("oversight", "unknown")))
        initiation = AutonomyInitiation(str(autonomy.get("initiation", "unknown")))
    except ValueError:
        return None
    declared = _int_level(autonomy.get("declared"))
    declared_source = autonomy.get("declared_source")
    return AutonomyAssessment(
        scale=SCALE,
        floor=floor,
        ceiling=ceiling,
        floor_level=to_iso(floor),
        ceiling_level=to_iso(ceiling),
        oversight=oversight,
        initiation=initiation,
        basis=_basis(autonomy.get("basis")),
        declared=declared,
        declared_source=str(declared_source) if isinstance(declared_source, str) and declared else None,
        assessor=assessor,
        evidence=list(evidence),
        observed_at=observed_at,
    )


def widen(assessments: Iterable[AutonomyAssessment]) -> AutonomyAssessment | None:
    """Combine several assessments of one agent into the interval that admits at least what each admits.

    Mirrors ``shadowscan merge``: highest floor, highest ceiling, the oversight and initiation that admit the
    most autonomy, the union of basis rules (order-independent), and the **lowest** declared level.
    """
    items = [a for a in assessments if a is not None]
    if not items:
        return None
    if len(items) == 1:
        return items[0]
    scale = items[0].scale
    if any(a.scale != scale for a in items):
        raise ValueError("cannot widen assessments on different scales")
    floor = max(a.floor for a in items)
    ceiling = max(a.ceiling for a in items)
    oversight = max((a.oversight for a in items), key=lambda o: OVERSIGHT_RANK[o])
    initiation = max((a.initiation for a in items), key=lambda i: INITIATION_RANK[i])
    seen: dict[tuple[str, str, str], AutonomyBasis] = {}
    for a in items:
        for b in a.basis:
            seen.setdefault((b.bound, b.rule, b.value), b)
    basis = sorted(seen.values(), key=lambda b: (b.bound, b.rule, b.value))[:MAX_BASIS]
    declared_items = [a for a in items if a.declared is not None]
    declared = min((a.declared for a in declared_items), default=None)  # type: ignore[type-var]
    declared_source = next((a.declared_source for a in declared_items if a.declared == declared), None)
    evidence: dict[str, EvidenceRef] = {}
    for a in items:
        for e in a.evidence:
            evidence.setdefault(e.digest, e)
    observed = [a.observed_at for a in items if a.observed_at is not None]
    assurances = {a.assurance for a in items}
    return AutonomyAssessment(
        scale=scale,
        floor=floor,
        ceiling=ceiling,
        floor_level=to_iso(floor) if scale == SCALE else items[0].floor_level,
        ceiling_level=to_iso(ceiling) if scale == SCALE else items[0].ceiling_level,
        oversight=oversight,
        initiation=initiation,
        basis=basis,
        declared=declared,
        declared_source=declared_source,
        assessor=items[0].assessor,
        assurance=min(assurances, key=lambda s: ["declared", "observed", "verified"].index(s.value)),
        evidence=sorted(evidence.values(), key=lambda e: e.digest),
        observed_at=max(observed) if observed else None,
    )


def table() -> list[dict[str, str]]:
    """The scale and its ISO projection as rows (``symbiote shadowscan levels``)."""
    return [
        {
            "level": f"L{lv.number}",
            "name": lv.name,
            "label": lv.label,
            "iso22989": lv.iso.value,
            "meaning": lv.meaning,
        }
        for lv in LEVELS
    ]


__all__ = [
    "INITIATION_RANK",
    "LEVELS",
    "MAX_BASIS",
    "MAX_LEVEL",
    "MIN_LEVEL",
    "OVERSIGHT_RANK",
    "SCALE",
    "Level",
    "assessment_from_metadata",
    "from_iso",
    "level",
    "level_by_name",
    "table",
    "to_iso",
    "widen",
]
