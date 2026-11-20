"""One typed evaluation of a native completeness claim, shared by the gates.

``validate`` (completeness) and ``risk`` (coverage status) both derive what "complete
collection" means from ``assess_coverage``, so the two gates cannot disagree about it.
A claim is complete only when every built-in collector is recorded complete, nothing
failed or was excluded, every requested collector completed and some surface was
recorded. A claim with no collector records is unknown rather than partial.

The claim keeps one record per collector: six walking collectors that meet the same
escaping symlink record the same failure six times, and each is listed as not
complete. The assessment states each distinct failure once, with how many records
it has, and each state once, with the collectors in it, so a report does not repeat
one cause for every collector that met it while the claim's records stay as they are.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
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


def group_failures(failures: Iterable[str]) -> list[tuple[str, int]]:
    """Each distinct failure in order of first record, with how many records it has."""
    counts = Counter(map(str, failures))
    return list(counts.items())


def failure_reason(failure: str, records: int) -> str:
    """One failure as a gate lists it: a repeated record says how many times."""
    return failure if records < 2 else f"{failure} (recorded {records} times)"


def _state_reasons(incomplete: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """One (subject, reason) per state, naming the collectors in it, states sorted."""
    by_state: dict[str, list[str]] = {}
    for scanner, state in incomplete:
        by_state.setdefault(state, []).append(scanner)
    return [
        ("coverage", f"Scanner coverage is {state} for " + ", ".join(sorted(names)) + ".")
        for state, names in sorted(by_state.items())
    ]


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
    failures = group_failures(claim.scan_failures)
    gaps.extend(
        CoverageGap(GapKind.SCAN_FAILURE, "collection", failure_reason(failure, records))
        for failure, records in failures[:MAX_LISTED_GAPS]
    )
    if len(failures) > MAX_LISTED_GAPS:
        gaps.append(
            CoverageGap(
                GapKind.SCAN_FAILURE,
                "collection",
                f"{len(failures) - MAX_LISTED_GAPS} further collection failures",
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
        CoverageGap(GapKind.COLLECTOR_NOT_COMPLETE, subject, reason)
        for subject, reason in _state_reasons(incomplete[:MAX_LISTED_GAPS])
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
