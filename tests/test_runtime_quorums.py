from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote.live.session import invoke_pinned_stdio
from nexus_symbiote.runtime import AuthorizationError, ReferenceGateway, key_id, sign_contract
from tests.test_runtime_authorization import fixture
from tests.test_runtime_stdio_session import launcher, signed_inputs


def configured_gateway(gateway, **overrides):
    options = {
        "snapshot_keys": gateway.snapshot_keys,
        "approval_keys": gateway.approval_keys,
        "trust_keys": gateway.trust_keys,
        "state": gateway.state,
        "authenticate": gateway.authenticate,
        "describe": gateway.describe,
        "resolve_scope": gateway.resolve_scope,
        "execute": gateway.execute,
        "approval_actors": gateway.approval_actors,
        "clock": gateway.clock,
    }
    options.update(overrides)
    return ReferenceGateway(**options)


@pytest.mark.parametrize("purpose", ["snapshot", "approval", "trust"])
def test_each_admission_quorum_requires_distinct_authorized_signers(tmp_path, purpose):
    values = fixture(tmp_path)
    gateway, call, bom, snapshot, status, approval, release, human, trust, executed = values
    other = Ed25519PrivateKey.generate()
    keys = dict(getattr(gateway, purpose + "_keys"))
    keys[key_id(other.public_key())] = other.public_key()
    actors = {**gateway.approval_actors, key_id(other.public_key()): "approver"}
    gateway = configured_gateway(
        gateway,
        **{purpose + "_keys": keys, purpose + "_threshold": 2, "approval_actors": actors},
    )
    contracts = {"snapshot": snapshot, "approval": approval, "trust": status}
    signers = {"snapshot": release, "approval": human, "trust": trust}
    kwargs = {
        "bom": bom,
        "snapshot": sign_contract(snapshot, "snapshot", (release,)),
        "approval": sign_contract(approval, "approval", (human,)),
        "trust": sign_contract(status, "trust", (trust,)),
    }
    for signing_keys in [(signers[purpose],), (signers[purpose], signers[purpose])]:
        kwargs[purpose] = sign_contract(contracts[purpose], purpose, signing_keys)
        with pytest.raises(AuthorizationError, match="insufficient distinct trusted signers"):
            gateway.invoke(call, **kwargs)
        assert executed == []
    kwargs[purpose] = sign_contract(contracts[purpose], purpose, (signers[purpose], other))
    assert gateway.invoke(call, **kwargs) == "executed"
    assert len(executed) == 1


@pytest.mark.parametrize("purpose", ["snapshot", "approval", "trust"])
@pytest.mark.parametrize("threshold", [True, False, 0, -1, 1.5, "2", 33])
def test_gateway_rejects_invalid_quorum_configuration(tmp_path, purpose, threshold):
    with pytest.raises(AuthorizationError, match="quorum threshold"):
        configured_gateway(fixture(tmp_path)[0], **{purpose + "_threshold": threshold})


@pytest.mark.parametrize("purpose", ["snapshot", "approval", "trust"])
def test_quorum_cannot_exceed_distinct_correctly_indexed_keys(tmp_path, purpose):
    gateway = fixture(tmp_path)[0]
    keys = dict(getattr(gateway, purpose + "_keys"))
    keys["same-public-key-alias"] = next(iter(keys.values()))
    with pytest.raises(AuthorizationError, match="exceeds distinct authorized"):
        configured_gateway(gateway, **{purpose + "_keys": keys, purpose + "_threshold": 2})


def test_default_quorum_keeps_unused_empty_approval_ring_disabled(tmp_path):
    gateway = configured_gateway(fixture(tmp_path)[0], approval_keys={})
    assert gateway.approval_threshold == 1
    with pytest.raises(AuthorizationError, match="exceeds distinct authorized"):
        configured_gateway(gateway, approval_threshold=2)


@pytest.mark.parametrize("purpose", ["snapshot", "approval", "trust"])
def test_pinned_stdio_preserves_gateway_quorum_policy(tmp_path, purpose):
    values = fixture(tmp_path)
    gateway = values[0]
    other = Ed25519PrivateKey.generate()
    keys = dict(getattr(gateway, purpose + "_keys"))
    keys[key_id(other.public_key())] = other.public_key()
    gateway = configured_gateway(gateway, **{purpose + "_keys": keys, purpose + "_threshold": 2})
    path, pin, log = launcher(tmp_path)
    with pytest.raises(AuthorizationError, match="insufficient distinct trusted signers"):
        invoke_pinned_stdio(
            gateway, values[1], command=str(path), sha256=pin, **signed_inputs(values, pin)
        )
    assert not log.exists() or "tools/call" not in log.read_text()
