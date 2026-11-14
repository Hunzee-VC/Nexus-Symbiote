"""Approval quorums count people, signer authority can be scoped, decisions are auditable."""

from __future__ import annotations

from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote.live.session import invoke_pinned_stdio
from nexus_symbiote.runtime import (
    AuthorizationError,
    SignerScope,
    key_id,
    request_digest,
    sign_contract,
)
from tests.test_runtime_authorization import NOW, fixture, invoke
from tests.test_runtime_quorums import configured_gateway
from tests.test_runtime_stdio_session import launcher, signed_inputs


def ring(*keys):
    return {key_id(key.public_key()): key.public_key() for key in keys}


def two_person_gateway(values):
    """Approval ring: alice holds two keys (one is the fixture's), bob holds one."""
    gateway, *_ = values
    human = values[7]
    alice2, bob = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    actors = {
        key_id(human.public_key()): "alice",
        key_id(alice2.public_key()): "alice",
        key_id(bob.public_key()): "bob",
    }
    values[0] = configured_gateway(
        gateway,
        approval_keys=ring(human, alice2, bob),
        approval_actors=actors,
        approval_threshold=2,
    )
    values[5] = values[5].model_copy(update={"actor": "alice"})
    return alice2, bob


def test_two_keys_of_one_approver_do_not_meet_a_two_person_quorum(tmp_path):
    values = list(fixture(tmp_path))
    alice2, _ = two_person_gateway(values)
    approval = sign_contract(values[5], "approval", (values[7], alice2))
    with pytest.raises(AuthorizationError, match="distinct approvers") as denied:
        invoke(values, approval=approval)
    assert denied.value.reason == "approval-quorum-not-met"
    assert values[-1] == []


def test_two_different_approvers_meet_a_two_person_quorum(tmp_path):
    values = list(fixture(tmp_path))
    _, bob = two_person_gateway(values)
    approval = sign_contract(values[5], "approval", (values[7], bob))
    assert invoke(values, approval=approval) == "executed"


def test_named_actor_must_be_one_of_the_approvers(tmp_path):
    values = list(fixture(tmp_path))
    alice2, bob = two_person_gateway(values)
    values[5] = values[5].model_copy(update={"actor": "carol"})
    approval = sign_contract(values[5], "approval", (alice2, bob))
    with pytest.raises(AuthorizationError) as denied:
        invoke(values, approval=approval)
    assert denied.value.reason == "approval-actor-unbound"


def test_quorum_larger_than_the_number_of_approvers_is_a_configuration_error(tmp_path):
    values = fixture(tmp_path)
    human, alice2 = values[7], Ed25519PrivateKey.generate()
    actors = {key_id(human.public_key()): "alice", key_id(alice2.public_key()): "alice"}
    with pytest.raises(AuthorizationError, match="distinct approvers") as refused:
        configured_gateway(
            values[0],
            approval_keys=ring(human, alice2),
            approval_actors=actors,
            approval_threshold=2,
        )
    assert refused.value.reason == "configuration-invalid"


def test_snapshot_key_of_another_tenant_cannot_grant_this_tenant(tmp_path):
    # One gateway serves acme and globex. globex's release key signs a snapshot for
    # acme's triage agent; scoping that key to globex keeps it out of acme's grants.
    values = list(fixture(tmp_path))
    gateway, release, globex = values[0], values[6], Ed25519PrivateKey.generate()
    scopes = {
        key_id(release.public_key()): SignerScope(tenants=frozenset({"acme"})),
        key_id(globex.public_key()): SignerScope(tenants=frozenset({"globex"})),
    }
    values[0] = configured_gateway(
        gateway, snapshot_keys=ring(release, globex), signer_scopes=scopes
    )
    snapshot = sign_contract(values[3], "snapshot", (globex,))
    with pytest.raises(AuthorizationError, match="authorized for this tenant") as denied:
        invoke(values, snapshot=snapshot)
    assert denied.value.reason == "signers-out-of-scope"
    assert invoke(values) == "executed"


@pytest.mark.parametrize(
    ("purpose", "scope", "admitted"),
    [
        (
            "snapshot",
            SignerScope(
                tenants=frozenset({"acme"}),
                deployments=frozenset({"prod"}),
                agents=frozenset({"agent:triage"}),
                tools=frozenset({("server:mail", "send")}),
            ),
            True,
        ),
        ("snapshot", SignerScope(deployments=frozenset({"staging"})), False),
        ("snapshot", SignerScope(agents=frozenset({"agent:other"})), False),
        ("snapshot", SignerScope(tools=frozenset({("server:mail", "other")})), False),
        ("snapshot", SignerScope(not_after=NOW - timedelta(seconds=1)), False),
        ("snapshot", SignerScope(not_before=NOW + timedelta(seconds=1)), False),
        ("trust", SignerScope(tenants=frozenset({"acme"})), True),
        # A trust status covers the whole tenant, so a narrower key cannot sign one.
        ("trust", SignerScope(deployments=frozenset({"prod"})), False),
        ("approval", SignerScope(tools=frozenset({("server:mail", "send")})), True),
        ("approval", SignerScope(tools=frozenset({("server:mail", "other")})), False),
        ("approval", SignerScope(tenants=frozenset({"globex"})), False),
    ],
)
def test_signer_scope_limits_what_each_key_may_authorize(tmp_path, purpose, scope, admitted):
    values = list(fixture(tmp_path))
    signer = {"snapshot": values[6], "approval": values[7], "trust": values[8]}[purpose]
    values[0] = configured_gateway(values[0], signer_scopes={key_id(signer.public_key()): scope})
    if admitted:
        assert invoke(values) == "executed"
        return
    with pytest.raises(AuthorizationError) as denied:
        invoke(values)
    assert denied.value.reason == "signers-out-of-scope"
    assert values[-1] == []


def test_a_trust_status_revoking_its_own_signer_is_refused_before_signer_scopes(tmp_path):
    # Verification order, step 3: the status's own revocations come before scopes.
    values = list(fixture(tmp_path))
    trust_key = key_id(values[8].public_key())
    narrow = SignerScope(tenants=frozenset({"globex"}))
    values[0] = configured_gateway(values[0], signer_scopes={trust_key: narrow})
    values[4] = values[4].model_copy(update={"revoked_signers": (trust_key,)})
    with pytest.raises(AuthorizationError) as denied:
        invoke(values)
    assert denied.value.reason == "trust-signer-revoked"
    assert values[-1] == []


def test_scope_for_a_key_outside_every_ring_is_a_configuration_error(tmp_path):
    gateway = fixture(tmp_path)[0]
    stranger = key_id(Ed25519PrivateKey.generate().public_key())
    with pytest.raises(AuthorizationError, match="in no ring") as refused:
        configured_gateway(gateway, signer_scopes={stranger: SignerScope()})
    assert refused.value.reason == "configuration-invalid"


@pytest.mark.parametrize(("first", "second"), [("snapshot", "approval"), ("trust", "snapshot")])
def test_one_key_in_two_purpose_rings_is_refused_unless_allowed(tmp_path, first, second):
    values = fixture(tmp_path)
    gateway = values[0]
    shared = {"snapshot": values[6], "approval": values[7], "trust": values[8]}[first]
    keys = {**getattr(gateway, second + "_keys"), **ring(shared)}
    actors = {**gateway.approval_actors, key_id(shared.public_key()): "approver"}
    options = {second + "_keys": keys, "approval_actors": actors}
    with pytest.raises(AuthorizationError, match="more than one purpose ring") as refused:
        configured_gateway(gateway, **options)
    assert refused.value.reason == "configuration-invalid"
    assert configured_gateway(gateway, allow_shared_keys=True, **options).allow_shared_keys


def test_every_decision_is_reported_without_argument_values(tmp_path):
    values = list(fixture(tmp_path))
    decisions = []
    values[0] = configured_gateway(values[0], on_decision=decisions.append)
    gateway, call, *_ = values
    human, release, trust = values[7], values[6], values[8]
    assert invoke(values) == "executed"
    with pytest.raises(AuthorizationError):
        invoke(values)
    admitted, replayed = decisions
    assert admitted.admitted and admitted.reason == "admitted"
    assert (admitted.tenant, admitted.deployment_id, admitted.agent_id) == (
        "acme",
        "prod",
        "agent:triage",
    )
    assert admitted.request_digest == request_digest(call)
    assert admitted.approval_actor == "approver"
    assert admitted.approval_signers == (key_id(human.public_key()),)
    assert admitted.snapshot_signers == (key_id(release.public_key()),)
    assert admitted.trust_signers == (key_id(trust.public_key()),)
    assert (admitted.snapshot_serial, admitted.trust_serial) == (1, 1)
    assert admitted.store_id == gateway.state.store_id
    assert not replayed.admitted and replayed.reason == "approval-replayed"
    assert "team@example.test" not in repr(decisions)


def test_adapter_exception_is_reported_and_propagates_unchanged(tmp_path):
    values = list(fixture(tmp_path))
    decisions = []

    def unavailable(server, tool):
        raise ConnectionError("upstream unavailable")

    values[0] = configured_gateway(values[0], describe=unavailable, on_decision=decisions.append)
    with pytest.raises(ConnectionError):
        invoke(values)
    assert [decision.reason for decision in decisions] == ["adapter-error"]
    assert values[-1] == []


def test_pinned_stdio_keeps_signer_scopes_and_decision_reports(tmp_path):
    values = fixture(tmp_path)
    decisions = []
    release = values[6]
    gateway = configured_gateway(
        values[0],
        signer_scopes={key_id(release.public_key()): SignerScope(tenants=frozenset({"globex"}))},
        on_decision=decisions.append,
    )
    path, pin, log = launcher(tmp_path)
    with pytest.raises(AuthorizationError) as denied:
        invoke_pinned_stdio(
            gateway, values[1], command=str(path), sha256=pin, **signed_inputs(values, pin)
        )
    assert denied.value.reason == "signers-out-of-scope"
    assert [decision.reason for decision in decisions] == ["signers-out-of-scope"]
    assert not log.exists() or "tools/call" not in log.read_text()


def test_validation_worker_self_check_passes(tmp_path):
    fixture(tmp_path)[0].check_validation_worker()
