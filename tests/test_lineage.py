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
    index = LineageIndex.from_new_versions(
        "acme", (version("source"), version("chunk", "chunk", ("source",)))
    )
    index.update_acl("source", revision="v2", principals=())
    index.update_acl("chunk", revision="v2", principals=("reader",))
    with pytest.raises(PermissionError):
        index.retrieve(
            ("chunk",),
            principal="reader",
            acl_revision="v2",
            observed_at=NOW,
            read_watermark="commit:2",
        )


def test_a_principal_outside_the_allowed_set_is_refused_at_the_current_revision():
    index = LineageIndex("acme", (version("source"), version("chunk", "chunk", ("source",))))
    with pytest.raises(PermissionError):
        index.retrieve(
            ("chunk",),
            principal="intruder",
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
    now = datetime.now(UTC)
    identity = HostedModelIdentity(
        provider="provider",
        endpoint="https://models.example.test",
        requested_alias="latest",
        observed_at=now,
    )
    assert not identity.immutable_identity_established
    key = Ed25519PrivateKey.generate()
    statement = HostedModelAttestation(
        provider=identity.provider,
        endpoint=identity.endpoint,
        requested_alias="latest",
        resolved_revision="rev123",
        not_before=now - timedelta(seconds=1),
        not_after=now + timedelta(hours=1),
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
    claimed.verify_attestation(envelope, {key_id(key.public_key()): key.public_key()}, now=now)
    assert claimed.immutable_identity_established
    assert not claimed.model_copy(update={"revision": "rev999"}).immutable_identity_established
    assert not claimed.identity_is_verified(now=now + timedelta(hours=2))
    restored = HostedModelIdentity.model_validate(claimed.model_dump(mode="json"))
    assert not restored.immutable_identity_established
    with pytest.raises(ValueError):
        claimed.verify_attestation(envelope, {}, now=now)
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
    index = LineageIndex.from_new_versions("acme", (version("source"),))
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


def test_a_lineage_rebuilt_after_a_withdrawal_keeps_it():
    index = LineageIndex("acme", (version("source"), version("chunk", "chunk", ("source",))))
    index.withdraw("source")
    rebuilt = LineageIndex("acme", tuple(reversed(index.versions.values())))
    assert rebuilt.versions == index.versions
    with pytest.raises(PermissionError):
        rebuilt.retrieve(
            ("chunk",),
            principal="reader",
            acl_revision="v1",
            observed_at=NOW,
            read_watermark="commit:6",
        )
    with pytest.raises(ValueError, match="withdrawn"):
        rebuilt.add(version("memory", "memory", ("chunk",)))
    with pytest.raises(ValueError, match="withdrawn"):
        LineageIndex("acme", (index.versions["source"], version("chunk", "chunk", ("source",))))


def test_snapshot_round_trip_preserves_history_and_ancestor_revocation():
    index = LineageIndex.from_new_versions(
        "acme", (version("chunk", "chunk", ("source",)), version("source"))
    )
    index.update_acl("source", revision="v2", principals=())
    index.update_acl("chunk", revision="v2", principals=("reader",))
    # Exercise the persisted JSON representation and a fresh instance.
    import json

    state = json.loads(index.snapshot().model_dump_json())
    rebuilt = LineageIndex.from_snapshot(state)
    assert rebuilt.snapshot() == index.snapshot()
    for name in ("source", "chunk"):
        with pytest.raises(ValueError, match="already used"):
            rebuilt.update_acl(name, revision="v1", principals=("reader",))
    with pytest.raises(PermissionError):
        rebuilt.retrieve(
            ("chunk",),
            principal="reader",
            acl_revision="v2",
            observed_at=NOW,
            read_watermark="commit:2",
        )
    rebuilt.update_acl("source", revision="v3", principals=("reader",))
    rebuilt.update_acl("chunk", revision="v3", principals=("reader",))
    assert rebuilt.retrieve(
        ("chunk",),
        principal="reader",
        acl_revision="v3",
        observed_at=NOW,
        read_watermark="commit:3",
    ).source_versions == ("chunk",)


def test_versions_only_import_and_its_snapshot_keep_history_unknown():
    original = LineageIndex.from_new_versions("acme", (version("source"),))
    original.update_acl("source", revision="v2", principals=())
    legacy = LineageIndex("acme", tuple(original.versions.values()))
    for restored in (legacy, LineageIndex.from_snapshot(legacy.snapshot())):
        assert restored.snapshot().acl_revisions["source"] is None
        for revision in ("v1", "v3"):
            with pytest.raises(ValueError, match="history is unknown"):
                restored.update_acl("source", revision=revision, principals=("reader",))
        with pytest.raises(PermissionError):
            restored.retrieve(
                ("source",),
                principal="reader",
                acl_revision="v2",
                observed_at=NOW,
                read_watermark="commit:2",
            )


def test_migration_requires_complete_explicit_histories():
    original = LineageIndex.from_new_versions("acme", (version("source"),))
    original.update_acl("source", revision="v2", principals=())
    versions = tuple(original.versions.values())
    migrated = LineageIndex.from_legacy_versions(
        "acme", versions, acl_revisions={"source": ("v1", "v2")}
    )
    with pytest.raises(ValueError, match="already used"):
        migrated.update_acl("source", revision="v1", principals=("reader",))
    for history in (
        {},
        {"source": ("v1",)},
        {"source": ("v2", "v2")},
        {"source": ("v2",), "extra": ("v1",)},
        {"source": None},
    ):
        with pytest.raises(ValueError):
            LineageIndex.from_legacy_versions("acme", versions, acl_revisions=history)


def test_new_records_and_withdrawals_survive_a_snapshot():
    index = LineageIndex("acme")
    index.add(version("source"))
    index.add(version("chunk", "chunk", ("source",)))
    index.update_acl("source", revision="v2", principals=())
    index.withdraw("source")
    rebuilt = LineageIndex.from_snapshot(index.snapshot())
    assert rebuilt.versions["chunk"].withdrawn
    with pytest.raises(ValueError, match="already used"):
        rebuilt.update_acl("source", revision="v1", principals=("reader",))
    with pytest.raises(PermissionError):
        rebuilt.retrieve(
            ("chunk",),
            principal="reader",
            acl_revision="v1",
            observed_at=NOW,
            read_watermark="commit:3",
        )


def test_mixed_known_and_unknown_histories_survive_restart():
    legacy = LineageIndex("acme", (version("source"),))
    legacy.add(version("chunk", "chunk", ("source",)))
    rebuilt = LineageIndex.from_snapshot(legacy.snapshot().model_dump(mode="json"))
    assert rebuilt.snapshot().acl_revisions == {"source": None, "chunk": ("v1",)}
    with pytest.raises(ValueError, match="history is unknown"):
        rebuilt.update_acl("source", revision="v2", principals=())
    rebuilt.update_acl("chunk", revision="v2", principals=("reader",))
    with pytest.raises(ValueError, match="already used"):
        rebuilt.update_acl("chunk", revision="v1", principals=("reader",))


def test_old_snapshot_is_not_rollback_protected():
    index = LineageIndex.from_new_versions("acme", (version("source"),))
    old = index.snapshot()
    index.update_acl("source", revision="v2", principals=())
    restored = LineageIndex.from_snapshot(old)
    assert restored.retrieve(
        ("source",),
        principal="reader",
        acl_revision="v1",
        observed_at=NOW,
        read_watermark="old",
    ).source_versions == ("source",)


def test_invalid_snapshots_cannot_initialize_a_trusted_history():
    index = LineageIndex.from_new_versions("acme", (version("source"),))
    document = index.snapshot().model_dump(mode="json")
    for change in (
        {"format": "legacy"},
        {"tenant": "other"},
        {"acl_revisions": {}},
        {"acl_revisions": {"source": ["v0"]}},
        {"acl_revisions": {"source": ["v1", "v1"]}},
        {"acl_revisions": {"source": ["v1"], "other": ["v1"]}},
    ):
        with pytest.raises(ValueError):
            LineageIndex.from_snapshot({**document, **change})


@pytest.mark.parametrize(
    "change", [{"kind": "unrecognized"}, {"parents": 4}, {"allowed_principals": "reader"}]
)
@pytest.mark.parametrize("construction", ["copy", "construct"])
def test_every_lineage_entry_point_revalidates_nested_models(change, construction):
    original = version("source")
    invalid = (
        original.model_copy(update=change)
        if construction == "copy"
        else DataVersion.model_construct(**{**original.model_dump(mode="python"), **change})
    )
    initial = LineageIndex.from_new_versions("acme", (original,))
    snapshot = initial.snapshot()
    mapped = {**snapshot.model_dump(mode="python"), "versions": (invalid,)}
    copied = snapshot.model_copy(update={"versions": (invalid,)})
    for build in (
        lambda: LineageIndex("acme", (invalid,)),
        lambda: LineageIndex.from_new_versions("acme", (invalid,)),
        lambda: LineageIndex.from_legacy_versions(
            "acme", (invalid,), acl_revisions={"source": ("v1",)}
        ),
        lambda: LineageIndex.from_snapshot(mapped),
        lambda: LineageIndex.from_snapshot(copied),
    ):
        with pytest.raises(ValueError):
            build()
    empty = LineageIndex("acme")
    with pytest.raises(ValueError):
        empty.add(invalid)
    assert not empty.versions
    empty.add(original)
    assert empty.versions["source"] == original


@pytest.mark.parametrize(
    ("revision", "principals"),
    [("v2", ("reader", None)), (None, ("reader",)), (["v2"], ("reader",))],
)
def test_invalid_acl_update_is_atomic_and_does_not_consume_revision(revision, principals):
    index = LineageIndex.from_new_versions("acme", (version("source"),))
    before = index.snapshot()
    with pytest.raises(ValueError):
        index.update_acl("source", revision=revision, principals=principals)
    assert index.snapshot() == before
    index.update_acl("source", revision="v2", principals=())
    assert index.versions["source"].acl_revision == "v2"
    with pytest.raises(ValueError, match="already used"):
        index.update_acl("source", revision="v1", principals=("reader",))
