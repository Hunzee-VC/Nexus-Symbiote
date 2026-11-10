from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote.lineage import DataVersion, HostedModelIdentity, LineageIndex
from nexus_symbiote.runtime import HostedModelAttestation, digest, key_id, sign_contract

NOW = datetime.now(UTC)
HASH = "sha256:" + "a" * 64


def version(name, kind="source", parents=(), **changes):
    return DataVersion(
        id=name,
        kind=kind,
        tenant="acme",
        content_digest=HASH,
        parents=parents,
        acl_revision="v1",
        allowed_principals=("reader",),
        **changes,
    )


def test_withdrawal_invalidates_all_descendants():
    index = LineageIndex(
        "acme",
        (
            version("source"),
            version("chunk", "chunk", ("source",)),
            version("index", "index", ("chunk",)),
            version("memory", "memory", ("index",), writer="agent"),
        ),
    )
    record = index.retrieve(
        ("memory",),
        principal="reader",
        acl_revision="v1",
        observed_at=NOW,
        read_watermark="commit:4",
    )
    assert record.source_versions == ("memory",) and record.source_digests == (HASH,)
    assert set(index.withdraw("source")) == {"source", "chunk", "index", "memory"}
    with pytest.raises(PermissionError):
        index.retrieve(
            ("memory",),
            principal="reader",
            acl_revision="v1",
            observed_at=NOW,
            read_watermark="commit:5",
        )


def test_acl_revocation_applies_through_derived_records():
    index = LineageIndex("acme", (version("source"), version("chunk", "chunk", ("source",))))
    index.update_acl("source", revision="v2", principals=())
    with pytest.raises(PermissionError):
        index.retrieve(
            ("chunk",),
            principal="reader",
            acl_revision="v1",
            observed_at=NOW,
            read_watermark="commit:2",
        )


def test_cross_tenant_and_missing_ancestry_rejected():
    with pytest.raises(ValueError):
        LineageIndex("other", (version("source"),))
    with pytest.raises(ValueError):
        LineageIndex("acme", (version("chunk", "chunk", ("missing",)),))


def test_alias_is_not_cryptographically_pinned_and_attestation_must_verify():
    identity = HostedModelIdentity(
        provider="provider",
        endpoint="https://models.example.test",
        requested_alias="latest",
        observed_at=NOW,
    )
    assert not identity.immutable_identity_established
    key = Ed25519PrivateKey.generate()
    statement = HostedModelAttestation(
        provider=identity.provider,
        endpoint=identity.endpoint,
        requested_alias="latest",
        resolved_revision="rev123",
        not_before=NOW - timedelta(seconds=1),
        not_after=NOW + timedelta(hours=1),
    )
    envelope = sign_contract(statement, "model", (key,))
    claimed = HostedModelIdentity(
        **{
            **identity.model_dump(),
            "identity_assurance": "provider-attested",
            "revision": "rev123",
            "evidence_digest": digest(envelope.model_dump(mode="json", by_alias=True)),
        }
    )
    assert not claimed.immutable_identity_established
    claimed.verify_attestation(envelope, {key_id(key.public_key()): key.public_key()}, now=NOW)
    assert claimed.immutable_identity_established
    assert not claimed.model_copy(update={"revision": "rev999"}).immutable_identity_established
    assert not claimed.identity_is_verified(now=NOW + timedelta(hours=2))
    restored = HostedModelIdentity.model_validate(claimed.model_dump(mode="json"))
    assert not restored.immutable_identity_established
    with pytest.raises(ValueError):
        claimed.verify_attestation(envelope, {}, now=NOW)
    assert not claimed.immutable_identity_established


def _chain(depth: int) -> list[DataVersion]:
    versions = [version("v0")]
    versions += [version(f"v{i}", "memory", (f"v{i - 1}",)) for i in range(1, depth)]
    return versions


def test_deep_append_only_lineage_stays_usable():
    depth = 5_000
    index = LineageIndex("acme", tuple(reversed(_chain(depth))))
    record = index.retrieve(
        (f"v{depth - 1}",),
        principal="reader",
        acl_revision="v1",
        observed_at=NOW,
        read_watermark="commit:1",
    )
    assert record.source_versions == (f"v{depth - 1}",)
    assert len(index.withdraw("v0")) == depth
    with pytest.raises(PermissionError):
        index.retrieve(
            (f"v{depth - 1}",),
            principal="reader",
            acl_revision="v1",
            observed_at=NOW,
            read_watermark="commit:2",
        )


def test_cycles_and_self_parents_are_rejected():
    with pytest.raises(ValueError):
        LineageIndex("acme", (version("a", "chunk", ("b",)), version("b", "chunk", ("a",))))
    with pytest.raises(ValueError):
        LineageIndex("acme", (version("a"), version("b", "chunk", ("b",))))
    with pytest.raises(ValueError):
        LineageIndex("acme", (version("a"), version("a")))


def test_an_earlier_acl_revision_cannot_be_restored():
    index = LineageIndex("acme", (version("source"),))
    index.update_acl("source", revision="v2", principals=())
    with pytest.raises(ValueError, match="already used"):
        index.update_acl("source", revision="v1", principals=("reader",))
    with pytest.raises(PermissionError):
        index.retrieve(
            ("source",),
            principal="reader",
            acl_revision="v1",
            observed_at=NOW,
            read_watermark="commit:3",
        )
