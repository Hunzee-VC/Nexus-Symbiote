"""Authorization model and computed flags (WP4).

Pure, cited predicates over an :class:`~symbiote.model.AgentBOM`: side-effect and capability classification,
approval gates implied by client auto-approval settings, agent reachability and blast radius, the lethal
trifecta / Rule-of-Two assessment, and the ten computed flags of ``spec/checks.md`` §3. The policy engine
(``symbiote.policy``) turns the same predicates into findings.
"""

from symbiote.authz.classify import (
    ApprovalDecision,
    approval_gate,
    capabilities,
    is_open_world,
    server_approval_gate,
    side_effect_class,
)
from symbiote.authz.flags import compute_flags
from symbiote.authz.graph import BlastRadius, BomIndex
from symbiote.authz.trifecta import Leg, TrifectaAssessment, assess_agent, assess_all

__all__ = [
    "ApprovalDecision",
    "BlastRadius",
    "BomIndex",
    "Leg",
    "TrifectaAssessment",
    "approval_gate",
    "assess_agent",
    "assess_all",
    "capabilities",
    "compute_flags",
    "is_open_world",
    "server_approval_gate",
    "side_effect_class",
]
