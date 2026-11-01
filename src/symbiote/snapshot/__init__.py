"""Snapshot commitment, sealing, chain state, diff and verifiable redaction.

``spec/agentbom-profile.md §2`` and ``spec/digests.md §5``. Two halves, one package:

* **Commitment and finalisation** (``commit``/``redact``): collect leaves, compute the salted
  Merkle commitment, write the snapshot header, verify documents, redact entities.
* **WP5 engine** (``state``/``diff``/``body``): per ``(agent, kind)`` serial chains with
  anti-rollback verdicts (``SYM-SNAP-001/002/003``), chain-aware sealing
  (:func:`~symbiote.snapshot.state.seal_with_chain`), the typed digest-based
  :func:`~symbiote.snapshot.diff.diff` (declared-vs-observed is the detection primitive) and
  :func:`~symbiote.snapshot.diff.stale_evaluation_ids` (``SYM-EVAL-001``).
"""

from __future__ import annotations

from symbiote.snapshot.body import (
    CLAIM_NOISE_KEYS,
    DIFF_EXCLUDED_FIELDS,
    body_digest,
    comparison_digest,
    diff_body,
    identity_digest,
)
from symbiote.snapshot.commit import (
    collect_leaves,
    compute_commitment,
    entity_body,
    finalize,
    new_document,
    provisional_snapshot,
    verify_document,
)
from symbiote.snapshot.diff import (
    DEFAULT_EVENT_SEVERITY,
    current_config_digests,
    diff,
    stale_evaluation_ids,
)
from symbiote.snapshot.redact import redact_entities
from symbiote.snapshot.state import (
    ChainConflictError,
    ChainHead,
    ChainIssue,
    ChainStore,
    StoreLockedError,
    seal_with_chain,
)

__all__ = [
    "CLAIM_NOISE_KEYS",
    "DEFAULT_EVENT_SEVERITY",
    "DIFF_EXCLUDED_FIELDS",
    "ChainConflictError",
    "ChainHead",
    "ChainIssue",
    "ChainStore",
    "StoreLockedError",
    "body_digest",
    "collect_leaves",
    "comparison_digest",
    "compute_commitment",
    "current_config_digests",
    "diff",
    "diff_body",
    "entity_body",
    "finalize",
    "identity_digest",
    "new_document",
    "provisional_snapshot",
    "redact_entities",
    "seal_with_chain",
    "stale_evaluation_ids",
    "verify_document",
]
