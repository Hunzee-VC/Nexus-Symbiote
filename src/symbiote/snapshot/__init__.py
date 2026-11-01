"""Snapshot engine: build, chain, and diff AgentBOM snapshots (WP5).

Public surface:

* :class:`~symbiote.snapshot.builder.SnapshotBuilder` — entities → salted Merkle commitment →
  sealed, validated ``AgentBOM`` with a chained ``Snapshot`` header.
* :class:`~symbiote.snapshot.state.ChainStore` — per ``(agent, kind)`` serial/digest chain with
  anti-rollback verdicts (``SYM-SNAP-001/002/003``).
* :func:`~symbiote.snapshot.diff.diff` — digest-based typed ``Delta`` between any two documents;
  the declared-vs-observed diff is the detection primitive.
* :func:`~symbiote.snapshot.diff.stale_evaluation_ids` — ``SYM-EVAL-001`` input.
"""

from __future__ import annotations

from symbiote.snapshot.body import (
    CLAIM_NOISE_KEYS,
    DIFF_EXCLUDED_FIELDS,
    body_digest,
    comparison_digest,
    diff_body,
    edge_leaf_id,
    flag_leaf_id,
    identity_digest,
    leaf_body,
)
from symbiote.snapshot.builder import SnapshotBuilder
from symbiote.snapshot.diff import (
    DEFAULT_EVENT_SEVERITY,
    current_config_digests,
    diff,
    stale_evaluation_ids,
)
from symbiote.snapshot.state import (
    ChainConflictError,
    ChainHead,
    ChainIssue,
    ChainStore,
    StoreLockedError,
)

__all__ = [
    "CLAIM_NOISE_KEYS",
    "DEFAULT_EVENT_SEVERITY",
    "DIFF_EXCLUDED_FIELDS",
    "ChainConflictError",
    "ChainHead",
    "ChainIssue",
    "ChainStore",
    "SnapshotBuilder",
    "StoreLockedError",
    "body_digest",
    "comparison_digest",
    "current_config_digests",
    "diff",
    "diff_body",
    "edge_leaf_id",
    "flag_leaf_id",
    "identity_digest",
    "leaf_body",
    "stale_evaluation_ids",
]
