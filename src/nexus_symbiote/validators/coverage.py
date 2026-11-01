"""The single coverage rule, shared by the completeness validator and the risk gate.

A completeness claim is complete only when every required scanner ran to completion,
no scanner recorded a failure, and no surface was excluded.

Absence is not exclusion. A scanner that checked its documented locations and found
nothing records those locations as scanned, so a repository without an optional
surface can still be complete. Only real exclusions, such as an excluded path, an
unreadable file, or an unsupported platform, are recorded as excluded.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from nexus_symbiote.core.models import CompletenessClaim
from nexus_symbiote.core.vocab import REQUIRED_SCANNERS, SCANNER_COMPLETE, SCANNER_FAILED

COVERAGE_COMPLETE = "complete"
COVERAGE_PARTIAL = "partial"
COVERAGE_FAILED = "failed"
COVERAGE_UNKNOWN = "unknown"


@dataclass(frozen=True)
class CoverageAssessment:
    state: str
    reasons: tuple[str, ...] = field(default=())

    @property
    def is_complete(self) -> bool:
        return self.state == COVERAGE_COMPLETE


def assess_coverage(
    claim: CompletenessClaim | None,
    required: Iterable[str] = REQUIRED_SCANNERS,
) -> CoverageAssessment:
    """Classify a completeness claim as complete, partial, failed, or unknown.

    ``failed`` takes precedence over ``partial``. A claim with no record at all is
    ``unknown``, which the gate treats as a failure.
    """
    if claim is None:
        return CoverageAssessment(COVERAGE_UNKNOWN, ("no completeness claim is present",))

    reasons: list[str] = []
    failed = bool(claim.scan_failures)
    reasons.extend(f"scan failure: {failure}" for failure in claim.scan_failures)

    for name in sorted(set(required)):
        status = claim.scanner_status.get(name)
        if status is None:
            reasons.append(f"scanner not recorded: {name}")
        elif status == SCANNER_FAILED:
            failed = True
            reasons.append(f"scanner failed: {name}")
        elif status != SCANNER_COMPLETE:
            reasons.append(f"scanner {status}: {name}")

    reasons.extend(f"surface excluded: {surface}" for surface in claim.surfaces_excluded)

    if failed:
        state = COVERAGE_FAILED
    elif reasons:
        state = COVERAGE_PARTIAL
    else:
        state = COVERAGE_COMPLETE
    return CoverageAssessment(state, tuple(reasons))
