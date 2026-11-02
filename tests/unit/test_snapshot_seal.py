"""seal_with_chain: chain-allocated sealing over commit.finalize (WP5 ∘ foundation)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from symbiote.model import Producer
from symbiote.model import enums as E
from symbiote.model.entities import Agent
from symbiote.snapshot import (
    ChainConflictError,
    ChainStore,
    new_document,
    seal_with_chain,
    verify_document,
)

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
NONCE1 = bytes.fromhex("11" * 32)
NONCE2 = bytes.fromhex("22" * 32)


def draft(version: str = "1.0.0"):
    agent = Agent(id="agent:triager", version=version, role=E.AgentRole.ROOT)
    return new_document(
        subject="agent:triager",
        producer=Producer(version="0.1.0"),
        kind=E.SnapshotKind.DECLARED,
        produced_at=NOW,
        agents=[agent],
    )


def test_seal_allocates_serial_and_chains(tmp_path) -> None:
    store = ChainStore(tmp_path)
    first, issues1 = seal_with_chain(draft(), store, nonce=NONCE1)
    assert issues1 == []
    assert (first.snapshot.serial, first.snapshot.prev) == (1, None)
    assert verify_document(first)
    second, issues2 = seal_with_chain(draft("1.0.1"), store, nonce=NONCE2)
    assert issues2 == []
    assert second.snapshot.serial == 2
    assert second.snapshot.prev == first.snapshot.digest
    assert verify_document(second)


def test_seal_is_deterministic_under_fixed_nonce(tmp_path) -> None:
    a, _ = seal_with_chain(draft(), ChainStore(tmp_path / "a"), nonce=NONCE1)
    b, _ = seal_with_chain(draft(), ChainStore(tmp_path / "b"), nonce=NONCE1)
    assert a.model_dump_json(by_alias=True) == b.model_dump_json(by_alias=True)


def test_seal_reseals_an_already_finalized_document(tmp_path) -> None:
    store = ChainStore(tmp_path)
    sealed, _ = seal_with_chain(draft(), store, nonce=NONCE1)
    resealed, issues = seal_with_chain(sealed, store, nonce=NONCE2)
    assert resealed.snapshot.serial == 2
    assert resealed.snapshot.prev == sealed.snapshot.digest
    assert issues == []
    assert verify_document(resealed)


def test_fork_detection_raises(tmp_path) -> None:
    store = ChainStore(tmp_path)
    seal_with_chain(draft(), store, nonce=NONCE1)
    # manually rewind the chain head to force a fork on the next commit
    head = store.peek("agent:triager", E.SnapshotKind.DECLARED)
    assert head is not None
    with pytest.raises(ChainConflictError):
        store.commit(
            # same serial, different digest
            seal_with_chain(draft("9.9.9"), ChainStore(tmp_path / "other"), nonce=NONCE2)[0].snapshot
        )


def test_sealing_a_redacted_view_is_refused(tmp_path) -> None:
    from symbiote.snapshot import redact_entities

    store = ChainStore(tmp_path)
    sealed, _ = seal_with_chain(draft(), store, nonce=NONCE1)
    redacted = redact_entities(sealed, {"agent:triager"}, redaction_class="identity-ref", applied_by="tests")
    with pytest.raises(ValueError, match="redacted view"):
        seal_with_chain(redacted, store, nonce=NONCE2)
