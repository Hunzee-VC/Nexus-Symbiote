"""One typed evaluation of a native completeness claim, shared by every gate.

``validate`` (completeness), ``risk`` (coverage status) and drift comparison must agree
on what "complete collection" means, so they all derive it from ``assess_coverage``.
A claim is complete only when every built-in collector is recorded complete, nothing
failed or was excluded, every requested collector completed and some surface was
recorded. A claim with no collector records is unknown rather than partial.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from nexus_symbiote.core.models import CompletenessClaim
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES

REPOSITORY_SCOPES = frozenset({"repository", "repository+shadowscan"})
MAX_LISTED_GAPS = 100
"""Failures or collector states listed one by one; the rest are counted in one gap."""


class CoverageStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class GapKind(StrEnum):
    NO_CLAIM = "no-claim"
    NO_COLLECTION_RECORDS = "no-collection-records"
    MISSING_COLLECTORS = "missing-collectors"
    COLLECTOR_NOT_COMPLETE = "collector-not-complete"
    REQUESTED_NOT_COMPLETED = "requested-not-completed"
    SCAN_FAILURE = "scan-failure"
    SURFACE_EXCLUDED = "surface-excluded"
    NO_SURFACES = "no-surfaces"


_UNKNOWN_KINDS = frozenset({GapKind.NO_CLAIM, GapKind.NO_COLLECTION_RECORDS, GapKind.NO_SURFACES})


@dataclass(frozen=True)
class CoverageGap:
    kind: GapKind
    subject: str
    reason: str


@dataclass(frozen=True)
class CoverageAssessment:
    status: CoverageStatus
    gaps: tuple[CoverageGap, ...]

    @property
    def complete(self) -> bool:
        return self.status is CoverageStatus.COMPLETE

    def reasons(self) -> list[str]:
        return [gap.reason for gap in self.gaps]


def assess_coverage(
    claim: CompletenessClaim | None, required: frozenset[str] = BUILTIN_SCANNER_NAMES
) -> CoverageAssessment:
    """Classify a completeness claim as complete, partial or unknown, with reasons."""
    if claim is None:
        gap = CoverageGap(
            GapKind.NO_CLAIM,
            "metadata",
            "AIBOM has no completeness claim — cannot assess coverage.",
        )
        return CoverageAssessment(CoverageStatus.UNKNOWN, (gap,))
    gaps: list[CoverageGap] = []
    if claim.scope in REPOSITORY_SCOPES and not claim.collectors_requested:
        gaps.append(
            CoverageGap(
                GapKind.NO_COLLECTION_RECORDS,
                "collection",
                "Repository completeness requires explicit collection records",
            )
        )
    gaps.extend(
        CoverageGap(GapKind.SCAN_FAILURE, "collection", f)
        for f in claim.scan_failures[:MAX_LISTED_GAPS]
    )
    if len(claim.scan_failures) > MAX_LISTED_GAPS:
        gaps.append(
            CoverageGap(
                GapKind.SCAN_FAILURE,
                "collection",
                f"{len(claim.scan_failures) - MAX_LISTED_GAPS} further collection failures",
            )
        )
    if set(claim.collectors_requested) - set(claim.collectors_completed):
        gaps.append(
            CoverageGap(
                GapKind.REQUESTED_NOT_COMPLETED,
                "collection",
                "Some requested collectors did not complete",
            )
        )
    missing = required - claim.scanner_status.keys()
    if missing:
        gaps.append(
            CoverageGap(
                GapKind.MISSING_COLLECTORS
                if claim.scanner_status
                else GapKind.NO_COLLECTION_RECORDS,
                "coverage",
                "Missing scanner coverage: " + ", ".join(sorted(missing)),
            )
        )
    if claim.surfaces_excluded:
        gaps.append(
            CoverageGap(
                GapKind.SURFACE_EXCLUDED,
                "coverage",
                "Excluded surfaces leave coverage incomplete.",
            )
        )
    incomplete = [(s, state) for s, state in claim.scanner_status.items() if state != "complete"]
    gaps.extend(
        CoverageGap(GapKind.COLLECTOR_NOT_COMPLETE, scanner, f"Scanner coverage is {state}.")
        for scanner, state in incomplete[:MAX_LISTED_GAPS]
    )
    if len(incomplete) > MAX_LISTED_GAPS:
        gaps.append(
            CoverageGap(
                GapKind.COLLECTOR_NOT_COMPLETE,
                "coverage",
                f"{len(incomplete) - MAX_LISTED_GAPS} further collectors are not complete",
            )
        )
    if not claim.surfaces_scanned:
        gaps.append(CoverageGap(GapKind.NO_SURFACES, "coverage", "No scanned surface is recorded."))
    if not gaps:
        return CoverageAssessment(CoverageStatus.COMPLETE, ())
    partial = any(gap.kind not in _UNKNOWN_KINDS for gap in gaps)
    return CoverageAssessment(
        CoverageStatus.PARTIAL if partial else CoverageStatus.UNKNOWN, tuple(gaps)
    )
