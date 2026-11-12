"""Every digest of a native inventory's bytes: file, canonical (runtime) and content.

Kept apart from ``core.content_digest`` because it validates through ``core.aibom``,
which imports ``core.content_digest`` to derive serial numbers.
"""

from __future__ import annotations

from dataclasses import dataclass

from nexus_symbiote.core.aibom import AIBOM, parse_native_bytes
from nexus_symbiote.core.content_digest import (
    NESTED_TOO_DEEPLY,
    NOT_AN_INVENTORY,
    inventory_content_digest,
)
from nexus_symbiote.core.hashing import hash_bytes

OUTSIDE_SNAPSHOT_BUDGET = (
    "It has no canonical digest: a runtime snapshot binds a document only when its compact "
    "JSON, with every character outside ASCII escaped and each number counted as 24 bytes, "
    "is at most 16 MiB, it holds at most 1,000,000 values and no value is nested more than "
    "64 levels deep."
)
NO_CONTENT_DIGEST = (
    "It has no content digest, which is defined only for a document that states a components list."
)
TOO_DEEP_FOR_CONTENT_DIGEST = "It has no content digest: it nests too deeply to canonicalize."
_CONTENT_REFUSALS = {
    NOT_AN_INVENTORY: NO_CONTENT_DIGEST,
    NESTED_TOO_DEEPLY: TOO_DEEP_FOR_CONTENT_DIGEST,
}


@dataclass(frozen=True)
class InventoryDigests:
    """What ``nexus-symbiote digest`` prints for the exact bytes of one native inventory.

    A digest that is undefined for the document is None, and ``unavailable`` says why
    in fixed text, one sentence for each.
    """

    file_sha256: str
    canonical_digest: str | None
    content_digest: str | None
    spec_version: str
    components: int
    unavailable: tuple[str, ...] = ()


def inventory_digests(raw: bytes) -> InventoryDigests:
    """Parse the bytes of a native inventory once and digest them three ways.

    ``file_sha256`` covers the exact bytes. ``canonical_digest`` is
    ``runtime.bom_digest`` of the parsed document, the digest a signed runtime snapshot
    binds; it is None outside the snapshot budget. ``content_digest`` is
    ``inventory_content_digest``; it is None for a document without a components list,
    or one too deep to canonicalize. Each digest is computed whether or not the other is
    defined.
    Raises ``NativeFormatError`` when the bytes are not a native inventory this build
    reads.
    """
    # Imported here: core.aibom imports this module to derive serial numbers.
    from nexus_symbiote.runtime import AuthorizationError, bom_digest

    document = parse_native_bytes(raw)
    bom = AIBOM.from_native(document)
    unavailable: list[str] = []
    canonical: str | None = None
    content: str | None = None
    try:
        canonical = bom_digest(document)
    except AuthorizationError as exc:
        # Strict parsing has already refused every value outside the canonical JSON
        # domain, so the budget is the only refusal left; anything else is a defect.
        if exc.reason != "bom-too-large":
            raise
        unavailable.append(OUTSIDE_SNAPSHOT_BUDGET)
    try:
        content = inventory_content_digest(document)
    except ValueError as exc:
        if str(exc) not in _CONTENT_REFUSALS:
            raise
        unavailable.append(_CONTENT_REFUSALS[str(exc)])
    return InventoryDigests(
        file_sha256=hash_bytes(raw),
        canonical_digest=canonical,
        content_digest=content,
        spec_version=bom.metadata.spec_version,
        components=len(bom.components),
        unavailable=tuple(unavailable),
    )
