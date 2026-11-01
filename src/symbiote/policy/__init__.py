"""Policy engine, SARIF, conformance and completeness score (WP12).

``run_policy(bom)`` evaluates every built-in ``SYM-*`` check (``spec/checks.md``) over an AgentBOM and computes
the flags; ``to_sarif`` renders findings for GitHub code scanning; ``evaluate_conformance`` and
``completeness_score`` implement ``spec/conformance.md``. Checks report ``indeterminate`` — never pass — when an
input they need is unknown.
"""

from symbiote.policy.conformance import ConformanceReport, Requirement, evaluate_conformance
from symbiote.policy.engine import PolicyResult, explain, list_checks, run_policy, severity_at_least
from symbiote.policy.sarif import to_sarif
from symbiote.policy.score import ScoreReport, completeness_score
from symbiote.policy.spec import CHECKS, CheckSpec, PolicyContext

__all__ = [
    "CHECKS",
    "CheckSpec",
    "ConformanceReport",
    "PolicyContext",
    "PolicyResult",
    "Requirement",
    "ScoreReport",
    "completeness_score",
    "evaluate_conformance",
    "explain",
    "list_checks",
    "run_policy",
    "severity_at_least",
    "to_sarif",
]
