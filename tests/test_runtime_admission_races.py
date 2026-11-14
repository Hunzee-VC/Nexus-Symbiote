"""Authorization state and schema are checked at the boundary that uses them."""

from __future__ import annotations

from datetime import timedelta

import pytest

from nexus_symbiote.runtime import (
    AuthorizationError,
    ServedTool,
    SignerScope,
    digest,
    key_id,
    sign_contract,
    tool_definition_digest,
)
from tests.test_runtime_authorization import NOW, fixture, invoke


@pytest.mark.parametrize("purpose,index", [("snapshot", 6), ("approval", 7), ("trust", 8)])
def test_signer_scope_must_remain_valid_at_final_admission(tmp_path, purpose, index):
    values = list(fixture(tmp_path))
    gateway = values[0]
    gateway.signer_scopes[key_id(values[index].public_key())] = SignerScope(
        not_after=NOW + timedelta(seconds=1)
    )
    times = iter((NOW, NOW, NOW, NOW + timedelta(seconds=2)))
    gateway.clock = lambda: next(times)
    with pytest.raises(AuthorizationError) as denied:
        invoke(values)
    assert denied.value.reason == "signers-out-of-scope"
    assert values[-1] == []
    gateway.clock = lambda: NOW
    assert invoke(values) == "executed"  # denial did not consume the nonce


@pytest.mark.parametrize("purpose,index", [("snapshot", 6), ("trust", 8)])
def test_signer_scope_must_remain_valid_when_advancing_snapshot(tmp_path, purpose, index):
    values = list(fixture(tmp_path))
    gateway = values[0]
    gateway.signer_scopes[key_id(values[index].public_key())] = SignerScope(
        not_after=NOW + timedelta(seconds=1)
    )
    times = iter((NOW, NOW, NOW + timedelta(seconds=2)))
    gateway.clock = lambda: next(times)
    with pytest.raises(AuthorizationError) as denied:
        invoke(values)
    assert denied.value.reason == "signers-out-of-scope"
    assert gateway.state._head("snapshot:" + digest(["acme", "prod", "agent:triage"])) is None
    assert values[-1] == []


@pytest.mark.parametrize("mode", ["invoke", "register"])
def test_revocation_interleaved_before_snapshot_advance_does_not_retire_old_snapshot(
    tmp_path, mode
):
    values = list(fixture(tmp_path))
    gateway, old_snapshot, key = values[0], values[3], values[8]
    trust1 = sign_contract(values[4], "trust", (key,))
    gateway.register_snapshot(sign_contract(old_snapshot, "snapshot", (values[6],)), trust=trust1)
    new_snapshot = old_snapshot.model_copy(update={"serial": 2})
    new_digest = digest(new_snapshot.model_dump(mode="json"))
    values[3] = new_snapshot
    values[5] = values[5].model_copy(update={"snapshot_digest": new_digest})
    trust2_status = values[4].model_copy(update={"serial": 2, "revoked_snapshots": (new_digest,)})
    trust2 = sign_contract(trust2_status, "trust", (key,))
    original = gateway._accept_trust

    def interleaved(envelope, tenant, timestamp):
        result = original(envelope, tenant, timestamp)
        original(trust2, tenant, timestamp)  # another gateway commits here
        return result

    gateway._accept_trust = interleaved
    with pytest.raises(AuthorizationError) as denied:
        if mode == "invoke":
            invoke(values)
        else:
            gateway.register_snapshot(
                sign_contract(new_snapshot, "snapshot", (values[6],)), trust=trust1
            )
    assert denied.value.reason == "trust-superseded"
    gateway._accept_trust = original
    assert gateway.register_snapshot(
        sign_contract(old_snapshot, "snapshot", (values[6],)), trust=trust2
    )
    assert values[-1] == []


def test_validation_uses_the_same_served_descriptor_that_was_digested(tmp_path):
    values = list(fixture(tmp_path))
    gateway = values[0]
    descriptor = {
        "name": "send",
        "description": "Send a message",
        "inputSchema": {"type": "object", "properties": {"to": {"const": "different"}}},
    }
    grant = (
        values[3]
        .tools[0]
        .model_copy(update={"definition_digest": tool_definition_digest(descriptor)})
    )
    values[3] = values[3].model_copy(update={"tools": (grant,)})
    values[5] = values[5].model_copy(
        update={"snapshot_digest": digest(values[3].model_dump(mode="json"))}
    )
    gateway.describe = lambda *_: ServedTool(
        endpoint_identity=grant.endpoint_identity, definition=descriptor
    )
    original = gateway._check_approval

    def mutate_after_digest(*args, **kwargs):
        result = original(*args, **kwargs)
        descriptor["inputSchema"]["properties"] = {}
        return result

    gateway._check_approval = mutate_after_digest
    with pytest.raises(AuthorizationError) as denied:
        invoke(values)
    assert denied.value.reason == "arguments-invalid"
    assert values[-1] == []


def test_expiring_one_approver_cannot_leave_a_two_person_quorum_of_two_keys(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from tests.test_runtime_quorums import configured_gateway

    values = list(fixture(tmp_path))
    old = values[0]
    same_person, second_person = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    same_id, second_id = key_id(same_person.public_key()), key_id(second_person.public_key())
    values[0] = configured_gateway(
        old,
        approval_keys={
            **old.approval_keys,
            same_id: same_person.public_key(),
            second_id: second_person.public_key(),
        },
        approval_threshold=2,
        approval_actors={**old.approval_actors, same_id: "approver", second_id: "other"},
        signer_scopes={second_id: SignerScope(not_after=NOW + timedelta(seconds=1))},
    )
    times = iter((NOW, NOW, NOW, NOW + timedelta(seconds=2)))
    values[0].clock = lambda: next(times)
    approval = sign_contract(values[5], "approval", (values[7], same_person, second_person))
    with pytest.raises(AuthorizationError) as denied:
        invoke(values, approval=approval)
    assert denied.value.reason == "approval-quorum-not-met"
    assert values[-1] == []


def test_trust_transition_intersects_prior_revocations_and_current_scopes(tmp_path):
    values = fixture(tmp_path)
    store, status = values[0].state, values[4]
    a, b, c = "a" * 64, "b" * 64, "c" * 64
    previous = status.model_copy(update={"revoked_signers": (a,)})
    store.accept_trust_status(previous, {b, c}, threshold=2)
    proposed = status.model_copy(update={"serial": 2})
    with pytest.raises(AuthorizationError) as denied:
        store.accept_trust_status(proposed, {a, b, c}, threshold=2, check_time=lambda: {a, c})
    assert denied.value.reason == "trust-signer-revoked"
    assert store._head("trust:acme")[0] == 1


@pytest.mark.parametrize("index", [3, 4])
def test_contract_must_remain_valid_when_advancing_snapshot(tmp_path, index):
    values = list(fixture(tmp_path))
    values[index] = values[index].model_copy(update={"not_after": NOW + timedelta(seconds=1)})
    times = iter((NOW, NOW, NOW + timedelta(seconds=2)))
    values[0].clock = lambda: next(times)
    with pytest.raises(AuthorizationError) as denied:
        invoke(values)
    assert denied.value.reason == ("snapshot-expired" if index == 3 else "trust-expired")
    assert values[0].state._head("snapshot:" + digest(["acme", "prod", "agent:triage"])) is None
    assert values[-1] == []


@pytest.mark.parametrize("expiry", ["contract", "scope"])
def test_trust_status_must_still_be_valid_when_committed(tmp_path, expiry):
    values = list(fixture(tmp_path))
    gateway = values[0]
    if expiry == "contract":
        values[4] = values[4].model_copy(update={"not_after": NOW + timedelta(seconds=1)})
    else:
        gateway.signer_scopes[key_id(values[8].public_key())] = SignerScope(
            not_after=NOW + timedelta(seconds=1)
        )
    times = iter((NOW, NOW + timedelta(seconds=2)))
    gateway.clock = lambda: next(times)
    with pytest.raises(AuthorizationError) as denied:
        invoke(values)
    assert denied.value.reason == (
        "trust-expired" if expiry == "contract" else "signers-out-of-scope"
    )
    assert gateway.state._head("trust:acme") is None
    assert values[-1] == []
