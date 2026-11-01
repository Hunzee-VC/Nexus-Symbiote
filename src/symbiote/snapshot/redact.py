"""Verifiable redaction of entities (``spec/digests.md §5``, invariant I6)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

from symbiote.digest.merkle import redact as redact_commitment
from symbiote.model.document import COLLECTIONS, AgentBOM
from symbiote.model.entities import RedactedEntity, Redaction


def redact_entities(
    bom: AgentBOM,
    entity_ids: set[str],
    *,
    redaction_class: str,
    applied_by: str,
    applied_at: datetime | None = None,
) -> AgentBOM:
    """Replace the named entities by leaf-hash placeholders, withhold their salts and the nonce, record the redaction.

    The Merkle root is unchanged, so signatures over the snapshot still verify and ``verify_document`` succeeds
    using the recorded leaf hashes of the redacted leaves.
    """
    if bom.merkle is None:
        raise ValueError("finalize the document before redacting it")
    applied_at = applied_at or datetime.now(UTC)
    changes: dict[str, object] = {}
    placeholders: list[RedactedEntity] = list(bom.redacted)
    keys: set[tuple[str, str]] = set()
    leaf_by_id = {leaf.id: leaf for leaf in bom.merkle.leaves}
    for attr in COLLECTIONS:
        kept = []
        for ent in getattr(bom, attr):
            if ent.id in entity_ids:
                leaf = leaf_by_id.get(ent.id)
                if leaf is None:
                    raise ValueError(f"no Merkle leaf for {ent.id}")
                placeholders.append(
                    RedactedEntity(
                        id=ent.id, kind=leaf.kind, redaction_class=redaction_class, leaf_hash=leaf.leaf_hash
                    )
                )
                keys.add((leaf.kind, ent.id))
            else:
                kept.append(ent)
        if len(kept) != len(getattr(bom, attr)):
            changes[attr] = kept
    missing = entity_ids - {p.id for p in placeholders}
    if missing:
        raise KeyError(f"unknown entity ids: {sorted(missing)}")
    record = Redaction(
        redaction_class=redaction_class,
        count=len(keys),
        applied_by=applied_by,
        applied_at=applied_at,
        ids=sorted(entity_ids),
    )
    changes["redacted"] = placeholders
    changes["redactions"] = [*bom.redactions, record]
    changes["merkle"] = redact_commitment(bom.merkle, keys).model_dump(mode="python")
    return cast("AgentBOM", bom.replace(**changes))


__all__ = ["redact_entities"]
