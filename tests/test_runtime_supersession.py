"""A newer snapshot retires older ones as soon as it is registered or presented."""

from __future__ import annotations

import sqlite3
import time
from datetime import timedelta

import pytest

from nexus_symbiote.runtime import (
    AuthorizationError,
    ReferenceGateway,
    StateStore,
    digest,
    sign_contract,
)
from tests.test_runtime_authorization import NOW, fixture, invoke


def reissued(values, serial, nonce, **update):
    """Return inputs for a re-issued snapshot and an approval bound to it."""
    values = list(values)
    values[3] = values[3].model_copy(update={"serial": serial, **update})
    values[5] = values[5].model_copy(
        update={"snapshot_digest": digest(values[3].model_dump(mode="json")), "nonce": nonce}
    )
    return values


def register(values, snapshot=None, statuses=None):
    gateway, _, _, current, status, _, release, _, trust_key, _ = values
    return gateway.register_snapshot(
        sign_contract(snapshot or current, "snapshot", (release,)),
        trust=sign_contract(statuses or status, "trust", (trust_key,)),
    )


def test_newer_snapshot_retires_older_even_when_its_own_call_is_denied(tmp_path):
    values = list(fixture(tmp_path))
    current = reissued(values, 2, "a" * 32)
    with pytest.raises(AuthorizationError) as denied:
        invoke(current, approval=None)
    assert denied.value.reason == "approval-required"
    with pytest.raises(AuthorizationError, match="superseded") as old:
        invoke(values)
    assert old.value.reason == "snapshot-superseded"
    assert invoke(current) == "executed"
    assert len(values[-1]) == 1


def test_registered_snapshot_withdraws_a_grant_before_any_call_presents_it(tmp_path):
    # Serial 10 lets the agent send to the admin mailbox without approval. The operator
    # removes that by issuing serial 11 and registering it; the agent keeps presenting 10.
    values = list(fixture(tmp_path, serial=10))
    gateway, call, _, snapshot, _, _, _, _, _, executed = values
    grant = snapshot.tools[0].model_copy(
        update={"require_approval": False, "resources": ("mailbox:team", "mailbox:admin")}
    )
    broad = snapshot.model_copy(update={"tools": (grant,)})
    narrow = snapshot.model_copy(update={"serial": 11})
    values[3] = broad
    values[1] = call.model_copy(
        update={"arguments": {"to": "admin@example.test"}, "resource": "mailbox:admin"}
    )
    assert invoke(values, approval=None) == "executed"
    registered = register(values, snapshot=narrow)
    assert registered.serial == 11
    with pytest.raises(AuthorizationError) as superseded:
        invoke(values, approval=None)
    assert superseded.value.reason == "snapshot-superseded"
    assert len(executed) == 1


def test_registration_applies_to_every_gateway_sharing_the_state_file(tmp_path):
    values = list(fixture(tmp_path))
    register(values, snapshot=values[3].model_copy(update={"serial": 2}))
    values[0].state = StateStore(tmp_path / "state.sqlite")
    with pytest.raises(AuthorizationError) as superseded:
        invoke(values)
    assert superseded.value.reason == "snapshot-superseded"


@pytest.mark.parametrize("failure", ["wrong-signer", "revoked", "expired", "other-tenant"])
def test_registration_refuses_snapshots_that_could_not_be_admitted(tmp_path, failure):
    values = list(fixture(tmp_path))
    gateway, _, _, snapshot, statuses, _, release, human, trust_key, _ = values
    newer = snapshot.model_copy(update={"serial": 2})
    signer, status = release, statuses
    if failure == "wrong-signer":
        signer = human
    elif failure == "revoked":
        status = statuses.model_copy(
            update={"revoked_snapshots": (digest(newer.model_dump(mode="json")),)}
        )
    elif failure == "expired":
        newer = newer.model_copy(
            update={"not_before": NOW - timedelta(hours=3), "not_after": NOW - timedelta(hours=2)}
        )
    else:
        status = statuses.model_copy(update={"tenant": "globex"})
    expected = {
        "wrong-signer": "signers-insufficient",
        "revoked": "snapshot-revoked",
        "expired": "snapshot-expired",
        "other-tenant": "trust-tenant-mismatch",
    }[failure]
    with pytest.raises(AuthorizationError) as refused:
        gateway.register_snapshot(
            sign_contract(newer, "snapshot", (signer,)),
            trust=sign_contract(status, "trust", (trust_key,)),
        )
    assert refused.value.reason == expected
    if failure != "revoked":
        # The head did not move, so serial 1 is still current.
        assert invoke(values) == "executed"


def test_same_serial_with_other_content_is_a_fork(tmp_path):
    values = list(fixture(tmp_path))
    assert invoke(values) == "executed"
    forked = reissued(values, 1, "b" * 32, not_after=NOW + timedelta(hours=2))
    with pytest.raises(AuthorizationError, match="rollback/fork") as fork:
        invoke(forked)
    assert fork.value.reason == "snapshot-fork"


def test_snapshot_registered_during_an_inflight_call_denies_it_and_keeps_the_nonce(tmp_path):
    values = list(fixture(tmp_path))
    gateway, *_, executed = values
    describe = gateway.describe
    second = StateStore(tmp_path / "state.sqlite")
    newer = values[3].model_copy(update={"serial": 2})

    def register_newer_meanwhile(server, tool):
        second.advance_snapshot(
            "snapshot:" + digest(["acme", "prod", "agent:triage"]),
            2,
            digest(newer.model_dump(mode="json")),
        )
        return describe(server, tool)

    gateway.describe = register_newer_meanwhile
    with pytest.raises(AuthorizationError) as superseded:
        invoke(values)
    assert superseded.value.reason == "snapshot-superseded"
    assert executed == []
    gateway.describe = describe
    current = reissued(values, 2, values[5].nonce)
    assert invoke(current) == "executed"


def test_superseded_snapshot_is_refused_without_taking_the_write_lock(tmp_path):
    # Anyone holding an old, still valid snapshot must not be able to make every
    # request wait for the store-wide write lock before it is refused.
    values = list(fixture(tmp_path))
    register(values, snapshot=values[3].model_copy(update={"serial": 2}))
    with sqlite3.connect(tmp_path / "state.sqlite", isolation_level=None) as holder:
        holder.execute("BEGIN IMMEDIATE")
        try:
            started = time.monotonic()
            with pytest.raises(AuthorizationError) as superseded:
                invoke(values)
            assert time.monotonic() - started < 5
        finally:
            holder.execute("ROLLBACK")
    assert superseded.value.reason == "snapshot-superseded"


def test_registrar_registers_without_adapters_for_every_gateway_sharing_the_store(tmp_path):
    values = list(fixture(tmp_path))
    gateway, call, bom, snapshot, status, _, release, _, trust_key, executed = values
    registrar = ReferenceGateway.registrar(
        snapshot_keys=gateway.snapshot_keys,
        trust_keys=gateway.trust_keys,
        approval_keys=gateway.approval_keys,
        state=StateStore(tmp_path / "state.sqlite"),
        clock=lambda: NOW,
    )
    newer = snapshot.model_copy(update={"serial": 2})
    trust = sign_contract(status, "trust", (trust_key,))
    assert registrar.register_snapshot(sign_contract(newer, "snapshot", (release,)), trust=trust)
    with pytest.raises(AuthorizationError) as superseded:
        invoke(values)
    assert superseded.value.reason == "snapshot-superseded"
    assert executed == []
    with pytest.raises(AuthorizationError) as refused:
        registrar.invoke(
            call, snapshot=sign_contract(newer, "snapshot", (release,)), trust=trust, bom=bom
        )
    assert refused.value.reason == "configuration-invalid"


def test_registrar_checks_its_configuration_like_a_gateway(tmp_path):
    values = fixture(tmp_path)
    keys = values[0].snapshot_keys
    with pytest.raises(AuthorizationError) as shared:
        ReferenceGateway.registrar(
            snapshot_keys=keys, trust_keys=keys, state=StateStore(tmp_path / "state.sqlite")
        )
    assert shared.value.reason == "configuration-invalid"
