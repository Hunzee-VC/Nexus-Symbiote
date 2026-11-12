"""Regression tests for PR 1 runtime, cryptographic, mode, and state hardening."""

from __future__ import annotations

import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote import limits, modes
from nexus_symbiote.cli import main as cli
from nexus_symbiote.runtime import (
    AuthorizationError,
    ServedTool,
    StateStore,
    key_id,
    request_digest,
    sign_contract,
    tool_definition_digest,
)
from tests.test_runtime_authorization import fixture


def test_default_gateway_canonicalizes_and_blocks_exponential_integral_float(
    tmp_path: Path,
) -> None:
    """NS-CRIT-01: canonical_arguments defaults to True and >=1e21 integral floats fail closed."""
    values = list(fixture(tmp_path))
    gateway, call, bom, snapshot, statuses, approval, release, human, authority, executed = values
    assert gateway.canonical_arguments is True

    schema = {
        "type": "object",
        "properties": {"amount": {"type": "integer", "maximum": 2.0**70}},
        "required": ["amount"],
    }
    definition = {"name": "send", "description": "Send", "inputSchema": schema}
    endpoint = snapshot.tools[0].endpoint_identity
    gateway.describe = lambda *_: ServedTool(endpoint_identity=endpoint, definition=definition)
    grant = snapshot.tools[0].model_copy(
        update={"definition_digest": tool_definition_digest(definition)}
    )
    values[3] = snapshot.model_copy(update={"tools": (grant,)})

    for canonical_flag in (True, False):
        gateway.canonical_arguments = canonical_flag
        bad_call = call.model_copy(update={"arguments": {"amount": 2.0**70}})
        with pytest.raises(AuthorizationError) as exc_info:
            request_digest(bad_call)
        assert exc_info.value.reason == "arguments-number-out-of-range"
        with pytest.raises(AuthorizationError) as invoke_exc:
            gateway.invoke(
                bad_call,
                snapshot=sign_contract(values[3], "snapshot", (release,)),
                trust=sign_contract(statuses, "trust", (authority,)),
                bom=bom,
                approval=sign_contract(approval, "approval", (human,)),
            )
        assert invoke_exc.value.reason == "arguments-number-out-of-range"
    assert executed == []


def test_appended_revoked_or_unbound_outer_signature_cannot_grief_valid_quorum(
    tmp_path: Path,
) -> None:
    """NS-HIGH-03: outer DSSE signatures are unauthenticated; extra revoked/unbound sigs do not grief."""
    values = list(fixture(tmp_path))
    gateway, call, bom, snapshot, statuses, approval, release, human, authority, executed = values

    revoked_snap = Ed25519PrivateKey.generate()
    revoked_trust = Ed25519PrivateKey.generate()
    revoked_approver = Ed25519PrivateKey.generate()
    unbound_approver = Ed25519PrivateKey.generate()

    for priv, ring in (
        (revoked_snap, gateway.snapshot_keys),
        (revoked_trust, gateway.trust_keys),
        (revoked_approver, gateway.approval_keys),
        (unbound_approver, gateway.approval_keys),
    ):
        ring[key_id(priv.public_key())] = priv.public_key()

    statuses = statuses.model_copy(
        update={
            "revoked_signers": tuple(
                sorted(
                    {
                        key_id(revoked_snap.public_key()),
                        key_id(revoked_trust.public_key()),
                        key_id(revoked_approver.public_key()),
                    }
                )
            )
        }
    )

    snap_env = sign_contract(snapshot, "snapshot", (release, revoked_snap))
    trust_env = sign_contract(statuses, "trust", (authority, revoked_trust))
    approval_env = sign_contract(approval, "approval", (human, revoked_approver, unbound_approver))

    result = gateway.invoke(
        call, snapshot=snap_env, trust=trust_env, bom=bom, approval=approval_env
    )
    assert result == "executed"
    assert len(executed) == 1


def test_previously_revoked_trust_signer_cannot_grief_subsequent_trust_advance(
    tmp_path: Path,
) -> None:
    """NS-HIGH-03: a signer revoked in serial N cannot grief serial N+1 by appending its sig."""
    values = list(fixture(tmp_path))
    gateway, call, bom, snapshot, statuses, approval, release, human, authority, executed = values

    compromised = Ed25519PrivateKey.generate()
    comp_id = key_id(compromised.public_key())
    gateway.trust_keys[comp_id] = compromised.public_key()

    s2 = statuses.model_copy(update={"serial": 2, "revoked_signers": (comp_id,)})
    gateway.state.accept_trust_status(s2, {key_id(authority.public_key())})

    # Serial 3 signed by valid authority + appended signature from previously revoked key:
    s3 = statuses.model_copy(update={"serial": 3, "revoked_signers": (comp_id,)})
    trust_env = sign_contract(s3, "trust", (authority, compromised))
    result = gateway.invoke(
        call,
        snapshot=sign_contract(snapshot, "snapshot", (release,)),
        trust=trust_env,
        bom=bom,
        approval=sign_contract(approval, "approval", (human,)),
    )
    assert result == "executed"
    assert len(executed) == 1


def test_offline_guard_stays_active_across_overlapping_threads() -> None:
    """NS-MED-05: exiting enforce(OFFLINE) on one thread keeps concurrent offline threads guarded."""
    t1_entered = threading.Event()
    t2_entered = threading.Event()
    t1_exited = threading.Event()
    outcomes: list[bool] = []

    def worker_one() -> None:
        with modes.enforce(modes.Mode.OFFLINE):
            t1_entered.set()
            assert t2_entered.wait(timeout=5)
        t1_exited.set()

    def worker_two() -> None:
        assert t1_entered.wait(timeout=5)
        with modes.enforce(modes.Mode.OFFLINE):
            t2_entered.set()
            assert t1_exited.wait(timeout=5)
            assert modes.current() is modes.Mode.OFFLINE
            try:
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except modes.OfflineViolation:
                outcomes.append(True)
            else:
                outcomes.append(False)

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(worker_one)
        f2 = pool.submit(worker_two)
        f1.result(timeout=5)
        f2.result(timeout=5)

    assert outcomes == [True]
    assert modes.current() is None


def test_collection_limits_are_isolated_per_context() -> None:
    """NS-MED-05: limits.applied uses ContextVar so concurrent threads do not bleed limits."""
    barrier = threading.Barrier(2)
    seen: dict[str, int] = {}

    def run_with_depth(name: str, depth: int) -> None:
        custom = limits.CollectionLimits(depth=depth)
        with limits.applied(custom):
            barrier.wait(timeout=5)
            barrier.wait(timeout=5)
            seen[name] = limits.current().depth

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(run_with_depth, "a", 5)
        b = pool.submit(run_with_depth, "b", 99)
        a.result(timeout=5)
        b.result(timeout=5)

    assert seen == {"a": 5, "b": 99}
    assert limits.current() == limits.DEFAULTS


def test_state_store_detects_in_place_database_swap(tmp_path: Path) -> None:
    """NS-LOW-05: swapping the SQLite file behind an open StateStore fails closed."""
    db_path = tmp_path / "state.sqlite"
    replacement = tmp_path / "replacement.sqlite"
    store = StateStore.initialize(db_path)
    StateStore.initialize(replacement)
    os.replace(replacement, db_path)

    with pytest.raises(AuthorizationError) as exc_info:
        store.record((), "nonce-after-swap-0000")
    assert exc_info.value.reason == "state-invalid"


def test_keygen_refuses_symlinked_parent_and_preserves_dangling_symlinks(tmp_path: Path) -> None:
    """NS-LOW-05: runtime keygen refuses parent symlinks and never unlinks existing symlinks."""
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    linked_dir = tmp_path / "linked"
    linked_dir.symlink_to(real_dir, target_is_directory=True)

    runner = CliRunner()
    res = runner.invoke(
        cli,
        [
            "runtime",
            "keygen",
            "--private-key",
            str(linked_dir / "key.pem"),
            "--public-key",
            str(linked_dir / "key.pub"),
        ],
    )
    assert res.exit_code != 0
    assert list(real_dir.iterdir()) == []

    dangling = real_dir / "dangling.pub"
    dangling.symlink_to(real_dir / "nonexistent")
    res2 = runner.invoke(
        cli,
        [
            "runtime",
            "keygen",
            "--private-key",
            str(real_dir / "priv.pem"),
            "--public-key",
            str(dangling),
        ],
    )
    assert res2.exit_code != 0
    assert dangling.is_symlink()
