"""Canonical bodies and identity digests for snapshot leaves and diffs.

Two distinct body forms serve two distinct purposes (``spec/digests.md``):

* **Leaf bodies** (:func:`leaf_body`) feed the salted Merkle commitment. They are the full companion
  JSON form of the entity with only ``id`` removed (the leaf envelope already carries ``kind`` and
  ``id``; ``spec/digests.md §3.8/§5``). Nothing else is stripped: the commitment covers every fact.
* **Diff bodies** (:func:`diff_body`) feed drift detection (I8: diffs operate on digests). They drop
  ``id``, ``provenance``, ``foreign`` and ``tags``, and strip per-``Claim`` observation noise
  (``method``, ``evidence``, ``locator``, ``collector``, ``observedAt``, ``confidence`` and
  ``assurance``), so re-collecting the same fact — or upgrading its assurance — never reads as a
  change to the fact itself. A claim's ``value``, ``state`` and ``unknownReason`` remain significant.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from symbiote.digest import envelope_digest
from symbiote.model.common import DigestResult, Party
from symbiote.model.edges import Edge
from symbiote.model.entities import (
    Agent,
    Approval,
    Entity,
    Evidence,
    Flag,
    Grant,
    Instruction,
    Model,
    Policy,
    PromptTemplate,
    RegistryResolution,
    Skill,
    ToolDefinition,
    ToolServer,
)

#: Top-level entity fields excluded from diff bodies (never from leaf bodies, except ``id``).
DIFF_EXCLUDED_FIELDS: frozenset[str] = frozenset({"id", "provenance", "foreign", "tags"})

#: Keys stripped from serialised ``Claim`` objects in diff bodies. The claim's ``value``, ``state``
#: and ``unknownReason`` stay; everything about *how* the fact was collected goes.
CLAIM_NOISE_KEYS: frozenset[str] = frozenset(
    {"method", "evidence", "locator", "collector", "observedAt", "confidence", "assurance"}
)

#: Entity kinds with a spec-defined body-digest type (``spec/digests.md §3.8``).
_BODY_DIGEST_KINDS: dict[str, str] = {
    "grant": "grant/v1",
    "appr": "approval/v1",
    "res": "resolution/v1",
}

#: Fallback body-digest type for entities with neither an intrinsic digest nor a §3.8 kind.
ENTITY_BODY_KIND = "entity/v1"


def leaf_body(entity: Entity | Party | Edge | Flag | Any) -> dict[str, Any]:
    """Companion JSON form of ``entity`` with ``id`` removed (Merkle leaf body, full fidelity)."""
    body = entity.to_json_dict()
    body.pop("id", None)
    return body


def _looks_like_claim(obj: dict[str, Any]) -> bool:
    return "state" in obj and "assurance" in obj


def _strip_claim_noise(obj: Any) -> Any:
    if isinstance(obj, dict):
        if _looks_like_claim(obj):
            return {k: _strip_claim_noise(v) for k, v in obj.items() if k not in CLAIM_NOISE_KEYS}
        return {k: _strip_claim_noise(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_claim_noise(v) for v in obj]
    return obj


def diff_body(entity: Entity | Party | Edge | Any) -> dict[str, Any]:
    """The fact content of ``entity`` for drift comparison (volatile collection metadata removed)."""
    body = entity.to_json_dict()
    for field in DIFF_EXCLUDED_FIELDS:
        body.pop(field, None)
    stripped = _strip_claim_noise(body)
    assert isinstance(stripped, dict)
    return stripped


def body_digest(entity: Entity | Party) -> DigestResult:
    """Reproducible digest of :func:`diff_body` under the entity's §3.8 kind (or ``entity/v1``)."""
    kind = ""
    if isinstance(entity, Entity):
        kind = entity.entity_kind
    digest_kind = _BODY_DIGEST_KINDS.get(kind, ENTITY_BODY_KIND)
    if digest_kind == ENTITY_BODY_KIND:
        return envelope_digest(digest_kind, {"kind": kind or "party", "body": diff_body(entity)})
    return envelope_digest(digest_kind, diff_body(entity))


def _model_weights_root(model: Model) -> str | None:
    if model.weights is not None and model.weights.value is not None:
        return model.weights.value.manifest_root
    return None


_IDENTITY_EXTRACTORS: tuple[tuple[type, Callable[[Any], str | None]], ...] = (
    (ToolDefinition, lambda e: e.digest.value),
    (ToolServer, lambda e: e.digest),
    (Instruction, lambda e: e.digest),
    (PromptTemplate, lambda e: e.digest.value or e.template_digest),
    (Skill, lambda e: e.digest),
    (Model, _model_weights_root),
    (Policy, lambda e: e.bundle_digest),
    (Evidence, lambda e: e.digest),
    (Agent, lambda e: e.digest),
)


def identity_digest(entity: Entity | Party) -> str | None:
    """The entity's *identity* digest where the model defines one, else ``None``.

    Identity digests are what diffs compare first (I8). Entities without an intrinsic identity
    digest are compared by :func:`body_digest`.
    """
    for cls, extract in _IDENTITY_EXTRACTORS:
        if isinstance(entity, cls):
            return extract(entity)
    if isinstance(entity, Grant | Approval | RegistryResolution):
        return body_digest(entity).value
    return None


def comparison_digest(entity: Entity | Party) -> str | None:
    """Identity digest if defined, else the diff-body digest; ``None`` only when undigestable."""
    d = identity_digest(entity)
    if d is not None:
        return d
    return body_digest(entity).value


def edge_leaf_id(edge: Edge) -> str:
    """Stable Merkle-leaf id for an edge."""
    return f"{edge.type.value}:{edge.from_ref}->{edge.to_ref}:{edge.scope.value}"


def flag_leaf_id(flag: Flag) -> str:
    """Stable Merkle-leaf id for a derived flag."""
    return f"{flag.flag.value}:{flag.subject_ref}"


__all__ = [
    "CLAIM_NOISE_KEYS",
    "DIFF_EXCLUDED_FIELDS",
    "ENTITY_BODY_KIND",
    "body_digest",
    "comparison_digest",
    "diff_body",
    "edge_leaf_id",
    "flag_leaf_id",
    "identity_digest",
    "leaf_body",
]
