"""Cross-cutting property suite over the sealed-document lifecycle (WP16).

Each property pins one of the spec invariants (``spec/agentbom-profile.md §6``) across the whole
stack — model → digest → snapshot — using the shared strategies in ``tests/strategies``.
"""

from __future__ import annotations

import json

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from symbiote.digest import canonical_bytes
from symbiote.model.enums import SnapshotKind
from symbiote.snapshot import (
    ChainConflictError,
    ChainStore,
    diff,
    finalize,
    redact_entities,
    verify_document,
)
from tests.strategies import FIXED_NOW, draft_documents, json_values, nonces, sealed_documents

SETTINGS = settings(max_examples=40, deadline=None)


@SETTINGS
@given(sealed_documents())
def test_i7_sealed_documents_verify_and_bind_digest_to_root(bom) -> None:
    assert bom.merkle is not None
    assert bom.snapshot.digest == bom.merkle.root
    assert bom.snapshot.id == f"snap:{bom.snapshot.serial}:{bom.snapshot.digest[7:19]}"
    assert verify_document(bom)


@SETTINGS
@given(draft_documents(), nonces)
def test_i7_finalize_is_deterministic(draft, nonce) -> None:
    one = finalize(draft, nonce=nonce).model_dump_json(by_alias=True)
    two = finalize(draft, nonce=nonce).model_dump_json(by_alias=True)
    assert one == two


@SETTINGS
@given(draft_documents(), nonces)
def test_i8_diff_ignores_resealing(draft, nonce) -> None:
    """Identical content sealed under different nonces produces an empty delta (digests decide)."""
    a = finalize(draft, nonce=nonce)
    b = finalize(draft, nonce=bytes(reversed(nonce)))
    assert diff(a, b).events == []


@SETTINGS
@given(sealed_documents(), st.data())
def test_i6_redaction_keeps_the_root_verifiable(bom, data) -> None:
    candidates = [t.id for t in bom.tools] + [i.id for i in bom.instructions]
    assume(candidates)
    chosen = set(data.draw(st.lists(st.sampled_from(candidates), min_size=1, unique=True)))
    redacted = redact_entities(bom, chosen, redaction_class="tool-text", applied_by="tests")
    assert verify_document(redacted)
    assert redacted.merkle is not None and redacted.merkle.nonce is None
    withheld = {leaf.id for leaf in redacted.merkle.leaves if leaf.salt is None}
    assert chosen <= withheld
    assert redacted.redactions and redacted.redactions[-1].count == len(chosen)


@SETTINGS
@given(json_values)
def test_jcs_canonicalization_is_idempotent(value) -> None:
    first = canonical_bytes(value)
    assert canonical_bytes(json.loads(first)) == first


@SETTINGS
@given(
    st.lists(
        st.tuples(st.integers(min_value=1, max_value=6), st.integers(min_value=0, max_value=2)), max_size=8
    )
)
def test_chain_store_never_accepts_a_regression(tmp_path_factory, walk) -> None:
    store = ChainStore(tmp_path_factory.mktemp("chain"))
    head: tuple[int, str] | None = None
    from symbiote.model.snapshot import Snapshot

    for serial, seed in walk:
        digest = "sha256:" + ("%02x" % (seed * 16 + serial % 16)) * 32
        snap = Snapshot(
            id=f"snap:{serial}:{digest[7:19]}",
            kind=SnapshotKind.DECLARED,
            digest=digest,
            serial=serial,
            agent_ref="agent:root",
            produced_at=FIXED_NOW,
        )
        should_accept = head is None or serial > head[0] or (serial, digest) == head
        try:
            store.commit(snap)
            accepted = True
        except ChainConflictError:
            accepted = False
        assert accepted == should_accept, (walk, head, serial, digest)
        if accepted and (head is None or serial > head[0]):
            head = (serial, digest)
    recorded = store.peek("agent:root", SnapshotKind.DECLARED)
    assert (recorded is None) == (head is None)
    if head is not None and recorded is not None:
        assert (recorded.serial, recorded.digest) == head
