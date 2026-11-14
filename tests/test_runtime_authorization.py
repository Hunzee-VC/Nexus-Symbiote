from __future__ import annotations

import base64
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from threading import Event

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.runtime import (
    PREDICATES,
    REASONS,
    STATEMENT_TYPE,
    ActionApproval,
    ApprovedSnapshot,
    AuthorizationError,
    Envelope,
    EnvelopeSignature,
    ExecutionContext,
    ReferenceGateway,
    ServedTool,
    StateStore,
    ToolCall,
    ToolGrant,
    TrustStatus,
    _pae,
    canonical_bytes,
    digest,
    key_id,
    sign_contract,
    strict_json,
    verify_contract,
)
from nexus_symbiote.runtime_validation import MAX_ARGUMENT_BYTES

NOW = datetime(2026, 11, 1, tzinfo=UTC)
POLICY = "sha256:" + "a" * 64
DEFINITION = {"name": "send", "description": "Send a message", "inputSchema": {"type": "object"}}


def fixture(tmp_path: Path, *, serial: int = 1):
    release, human, status = (Ed25519PrivateKey.generate() for _ in range(3))
    context = ExecutionContext(
        agent_id="agent:triage",
        deployment_id="prod",
        tenant="acme",
        workload_identity="spiffe://acme/triage",
        policy_digest=POLICY,
    )
    call = ToolCall(
        server_id="server:mail",
        tool_name="send",
        action="send",
        resource="mailbox:team",
        arguments={"to": "team@example.test"},
    )
    bom = {"agent": "triage", "tools": ["send"]}
    grant = ToolGrant(
        server_id="server:mail",
        endpoint_identity="https://mail.example.test/mcp",
        tool_name="send",
        definition_digest=hash_tool_definition(
            "send", DEFINITION["description"], DEFINITION["inputSchema"]
        ),
        actions=("send",),
        resources=("mailbox:team",),
    )
    snapshot = ApprovedSnapshot(
        **context.model_dump(),
        serial=serial,
        bom_digest=digest(bom),
        tools=(grant,),
        not_before=NOW - timedelta(seconds=1),
        not_after=NOW + timedelta(hours=1),
    )
    statuses = TrustStatus(
        tenant="acme",
        serial=1,
        not_before=NOW - timedelta(seconds=1),
        not_after=NOW + timedelta(minutes=30),
    )
    approval = ActionApproval(
        snapshot_digest=digest(snapshot.model_dump(mode="json")),
        context_digest=digest(context.model_dump(mode="json")),
        request_digest=digest(call.model_dump(mode="json")),
        nonce="c3f1b0a7d9e24f6b8a1c5d7e9f0b2a4c",
        actor="approver",
        not_before=NOW - timedelta(seconds=1),
        not_after=NOW + timedelta(minutes=1),
    )
    executed = []
    gateway = ReferenceGateway(
        snapshot_keys={key_id(release.public_key()): release.public_key()},
        approval_keys={key_id(human.public_key()): human.public_key()},
        trust_keys={key_id(status.public_key()): status.public_key()},
        state=StateStore.initialize(tmp_path / "state.sqlite"),
        authenticate=lambda: context,
        describe=lambda *_: ServedTool(
            endpoint_identity=grant.endpoint_identity, definition=DEFINITION
        ),
        execute=lambda c: executed.append(c) or "executed",
        approval_actors={key_id(human.public_key()): "approver"},
        clock=lambda: NOW,
        resolve_scope=lambda c: (
            "send",
            "mailbox:team" if c.arguments.get("to") == "team@example.test" else "mailbox:admin",
        ),
    )
    return gateway, call, bom, snapshot, statuses, approval, release, human, status, executed


def invoke(values, **changes):
    gateway, call, bom, snapshot, statuses, approval, release, human, status, _ = values
    kwargs = {
        "snapshot": sign_contract(snapshot, "snapshot", (release,)),
        "trust": sign_contract(statuses, "trust", (status,)),
        "approval": sign_contract(approval, "approval", (human,)),
        "bom": bom,
    }
    kwargs.update(changes)
    if "now" in kwargs:
        clock_value = kwargs.pop("now")
        gateway.clock = lambda: clock_value
    return gateway.invoke(call, **kwargs)


def test_gateway_executes_approved_call_and_consumes_approval(tmp_path):
    values = fixture(tmp_path)
    assert invoke(values) == "executed"
    with pytest.raises(AuthorizationError, match="already been used") as replayed:
        invoke(values)
    assert replayed.value.reason == "approval-replayed"
    assert len(values[-1]) == 1


def test_a_not_yet_valid_approval_is_admitted_once_its_window_opens(tmp_path):
    # The reference lists *-not-yet-valid codes as clearing for the same evidence.
    values = list(fixture(tmp_path))
    window = {"not_before": NOW + timedelta(seconds=30), "not_after": NOW + timedelta(minutes=2)}
    values[5] = values[5].model_copy(update=window)
    approval = sign_contract(values[5], "approval", (values[7],))
    with pytest.raises(AuthorizationError) as early:
        invoke(values, approval=approval)
    assert early.value.reason == "approval-not-yet-valid"
    assert invoke(values, approval=approval, now=NOW + timedelta(seconds=30)) == "executed"


def test_scope_resolver_cannot_modify_request_during_resolution(tmp_path):
    values = fixture(tmp_path)
    gateway = values[0]

    def mutate(call):
        call.arguments["to"] = "admin@example.test"
        return "send", "mailbox:team"

    gateway.resolve_scope = mutate
    with pytest.raises(AuthorizationError, match="resolver modified") as modified:
        invoke(values)
    assert modified.value.reason == "resolver-modified-request"
    assert values[-1] == []


def test_scope_resolver_cannot_mutate_request_after_approval_check(tmp_path):
    values = fixture(tmp_path)
    gateway, original, _, _, _, _, _, _, _, executed = values
    context = gateway.authenticate()
    retained = []
    auth_calls = 0

    def resolve(call):
        retained.append(call)
        return "send", "mailbox:team"

    def authenticate():
        nonlocal auth_calls
        auth_calls += 1
        if auth_calls == 2:
            retained[0].arguments["to"] = "admin@example.test"
        return context

    gateway.resolve_scope = resolve
    gateway.authenticate = authenticate
    assert invoke(values) == "executed"
    assert executed[0].arguments == {"to": "team@example.test"}
    assert original.arguments == {"to": "team@example.test"}


def sign_unchecked(contract, kind, key):
    """Sign without sign_contract's own refusals, as another DSSE signer could."""
    body = contract.model_dump(mode="json")
    statement = {
        "_type": STATEMENT_TYPE,
        "predicateType": PREDICATES[kind],
        "subject": [{"name": kind, "digest": {"sha256": digest(body).split(":", 1)[1]}}],
        "predicate": body,
    }
    payload = canonical_bytes(statement)
    signature = EnvelopeSignature(
        key_id=key_id(key.public_key()),
        signature=base64.b64encode(key.sign(_pae(payload))).decode(),
    )
    return Envelope(payload=base64.b64encode(payload).decode(), signatures=(signature,))


def autonomous(values):
    grant = values[3].tools[0].model_copy(update={"require_approval": False})
    values[3] = values[3].model_copy(update={"tools": (grant,)})


def _denial_setup(values, failure):
    gateway, call, bom, snapshot, statuses, approval, release, human, status, executed = values
    context = gateway.authenticate()
    grant = snapshot.tools[0]
    changes = {}
    if failure == "missing-approval":
        changes["approval"] = None
    elif failure == "changed-args-same-scope":
        # The resolver still derives mailbox:team, so only the request binding stops it.
        arguments = {"to": "team@example.test", "body": "wire the funds"}
        values[1] = call.model_copy(update={"arguments": arguments})
    elif failure == "changed-args-other-scope":
        values[1] = call.model_copy(update={"arguments": {"to": "attacker@example.test"}})
    elif failure == "wrong-resource-label":
        values[1] = call.model_copy(update={"resource": "mailbox:admin"})
    elif failure == "out-of-grant-resource":
        autonomous(values)
        values[1] = call.model_copy(
            update={"arguments": {"to": "admin@example.test"}, "resource": "mailbox:admin"}
        )
        changes["approval"] = None
    elif failure == "ungranted-action":
        values[1] = call.model_copy(update={"action": "delete"})
        gateway.resolve_scope = lambda c: ("delete", "mailbox:team")
    elif failure == "ungranted-tool":
        values[1] = call.model_copy(update={"tool_name": "delete"})
        gateway.describe = lambda *_: ServedTool(
            endpoint_identity=grant.endpoint_identity, definition={**DEFINITION, "name": "delete"}
        )
    elif failure in {"wrong-deployment", "wrong-agent", "wrong-workload", "wrong-policy"}:
        field = {
            "wrong-deployment": ("deployment_id", "staging"),
            "wrong-agent": ("agent_id", "agent:other"),
            "wrong-workload": ("workload_identity", "spiffe://acme/other"),
            "wrong-policy": ("policy_digest", "sha256:" + "b" * 64),
        }[failure]
        gateway.authenticate = lambda: context.model_copy(update=dict([field]))
    elif failure == "wrong-tenant":
        gateway.authenticate = lambda: context.model_copy(update={"tenant": "other"})
    elif failure == "identity-changed":
        identities = iter([context, context.model_copy(update={"workload_identity": "x"})])
        gateway.authenticate = lambda: next(identities)
    elif failure == "wrong-endpoint":
        gateway.describe = lambda *_: ServedTool(
            endpoint_identity="https://attacker.example.test", definition=DEFINITION
        )
    elif failure == "wrong-served-name":
        gateway.describe = lambda *_: ServedTool(
            endpoint_identity=grant.endpoint_identity, definition={**DEFINITION, "name": "other"}
        )
    elif failure == "changed-description":
        gateway.describe = lambda *_: ServedTool(
            endpoint_identity=grant.endpoint_identity,
            definition={**DEFINITION, "description": "Steal secrets"},
        )
    elif failure == "unsupported-descriptor-field":
        gateway.describe = lambda *_: ServedTool(
            endpoint_identity=grant.endpoint_identity, definition={**DEFINITION, "icons": []}
        )
    elif failure == "revoked-tool":
        values[4] = statuses.model_copy(update={"revoked_tools": (grant.definition_digest,)})
    elif failure == "revoked-endpoint":
        values[4] = statuses.model_copy(update={"revoked_endpoints": (grant.endpoint_identity,)})
    elif failure == "revoked-snapshot":
        revoked = (digest(snapshot.model_dump(mode="json")),)
        values[4] = statuses.model_copy(update={"revoked_snapshots": revoked})
    elif failure == "revoked-snapshot-signer":
        values[4] = statuses.model_copy(update={"revoked_signers": (key_id(release.public_key()),)})
    elif failure == "revoked-approver":
        values[4] = statuses.model_copy(update={"revoked_signers": (key_id(human.public_key()),)})
    elif failure == "revoked-trust-signer":
        values[4] = statuses.model_copy(update={"revoked_signers": (key_id(status.public_key()),)})
    elif failure == "trust-expired":
        changes["now"] = NOW + timedelta(minutes=40)
    elif failure == "trust-other-tenant":
        values[4] = statuses.model_copy(update={"tenant": "globex"})
    elif failure == "trust-too-long":
        long = statuses.model_copy(update={"not_after": NOW + timedelta(hours=2)})
        changes["trust"] = sign_unchecked(long, "trust", status)
    elif failure == "trust-purpose":
        changes["trust"] = sign_contract(snapshot, "snapshot", (status,))
    elif failure == "snapshot-expired":
        window = {"not_before": NOW - timedelta(hours=2), "not_after": NOW - timedelta(hours=1)}
        values[3] = snapshot.model_copy(update=window)
    elif failure == "snapshot-not-yet-valid":
        values[3] = snapshot.model_copy(update={"not_before": NOW + timedelta(minutes=1)})
    elif failure == "snapshot-too-long":
        long = snapshot.model_copy(update={"not_after": NOW + timedelta(hours=25)})
        changes["snapshot"] = sign_unchecked(long, "snapshot", release)
    elif failure == "wrong-snapshot-signer":
        changes["snapshot"] = sign_contract(snapshot, "snapshot", (human,))
    elif failure == "bom-tampered":
        changes["bom"] = {**bom, "tools": ["send", "steal"]}
    elif failure == "approval-expired":
        changes["now"] = NOW + timedelta(minutes=2)
    elif failure == "approval-not-yet-valid":
        window = {
            "not_before": NOW + timedelta(seconds=30),
            "not_after": NOW + timedelta(minutes=2),
        }
        values[5] = approval.model_copy(update=window)
    elif failure == "approval-too-long":
        long = approval.model_copy(update={"not_after": NOW + timedelta(hours=1)})
        changes["approval"] = sign_unchecked(long, "approval", human)
    elif failure == "approval-signed-by-snapshot-key":
        changes["approval"] = sign_contract(approval, "approval", (release,))
    elif failure == "approval-actor":
        values[5] = approval.model_copy(update={"actor": "other-approver"})
    elif failure == "approval-other-snapshot":
        newer = snapshot.model_copy(update={"serial": 2})
        values[5] = approval.model_copy(
            update={"snapshot_digest": digest(newer.model_dump(mode="json"))}
        )
    elif failure == "approval-other-context":
        other = context.model_copy(update={"workload_identity": "spiffe://acme/other"})
        values[5] = approval.model_copy(
            update={"context_digest": digest(other.model_dump(mode="json"))}
        )
    elif failure == "integer-out-of-range":
        values[1] = call.model_copy(update={"arguments": {"to": "team@example.test", "id": 2**53}})
    elif failure == "lone-surrogate-argument":
        values[1] = call.model_copy(update={"arguments": {"to": "team@example.test\ud800"}})
    elif failure == "oversized-arguments":
        values[1] = call.model_copy(
            update={"arguments": {"to": "team@example.test", "pad": "x" * MAX_ARGUMENT_BYTES}}
        )
    elif failure == "arguments-invalid":
        values[1] = call.model_copy(update={"arguments": {"to": 7}})
        gateway.resolve_scope = lambda c: ("send", "mailbox:team")
        schema = {"type": "object", "properties": {"to": {"type": "string"}}}
        definition = {**DEFINITION, "inputSchema": schema}
        autonomous(values)
        values[3] = values[3].model_copy(
            update={
                "tools": (
                    values[3]
                    .tools[0]
                    .model_copy(
                        update={
                            "definition_digest": hash_tool_definition(
                                "send", definition["description"], schema
                            )
                        }
                    ),
                )
            }
        )
        gateway.describe = lambda *_: ServedTool(
            endpoint_identity=grant.endpoint_identity, definition=definition
        )
        changes["approval"] = None
    else:
        raise AssertionError(failure)
    return changes


DENIALS = [
    ("missing-approval", "approval-required", "operation-bound approval required"),
    ("changed-args-same-scope", "approval-request-mismatch", "does not cover this operation"),
    ("changed-args-other-scope", "scope-mismatch", "actual tool arguments"),
    ("wrong-resource-label", "scope-mismatch", "actual tool arguments"),
    ("out-of-grant-resource", "capability-denied", "outside approved capability"),
    ("ungranted-action", "capability-denied", "outside approved capability"),
    ("ungranted-tool", "tool-not-granted", "does not grant"),
    ("wrong-deployment", "context-mismatch", "mismatch"),
    ("wrong-agent", "context-mismatch", "mismatch"),
    ("wrong-workload", "context-mismatch", "mismatch"),
    ("wrong-policy", "context-mismatch", "mismatch"),
    ("wrong-tenant", "trust-tenant-mismatch", "tenant mismatch"),
    ("identity-changed", "identity-changed", "identity changed"),
    ("wrong-endpoint", "endpoint-mismatch", "endpoint differs"),
    ("wrong-served-name", "descriptor-name-mismatch", "tool name differs"),
    ("changed-description", "descriptor-changed", "changed since approval"),
    ("unsupported-descriptor-field", "descriptor-unsupported", "rfc8785-jcs-v2"),
    ("revoked-tool", "tool-revoked", "tool is revoked"),
    ("revoked-endpoint", "endpoint-revoked", "endpoint is revoked"),
    ("revoked-snapshot", "snapshot-revoked", "snapshot is revoked"),
    ("revoked-snapshot-signer", "signer-revoked", "signer is revoked"),
    ("revoked-approver", "approver-revoked", "approver is revoked"),
    ("revoked-trust-signer", "trust-signer-revoked", "unrevoked signers"),
    ("trust-expired", "trust-expired", "expired"),
    ("trust-other-tenant", "trust-tenant-mismatch", "tenant mismatch"),
    ("trust-too-long", "trust-lifetime-exceeds-policy", "exceeds local policy"),
    ("trust-purpose", "statement-purpose-mismatch", "purpose mismatch"),
    ("snapshot-expired", "snapshot-expired", "expired"),
    ("snapshot-not-yet-valid", "snapshot-not-yet-valid", "not yet valid"),
    ("snapshot-too-long", "snapshot-lifetime-exceeds-policy", "exceeds local policy"),
    ("wrong-snapshot-signer", "signers-insufficient", "insufficient distinct trusted signers"),
    ("bom-tampered", "bom-mismatch", "companion BOM"),
    ("approval-expired", "approval-expired", "expired"),
    ("approval-not-yet-valid", "approval-not-yet-valid", "not yet valid"),
    ("approval-too-long", "approval-lifetime-exceeds-policy", "exceeds local policy"),
    ("approval-signed-by-snapshot-key", "signers-insufficient", "insufficient distinct"),
    ("approval-actor", "approval-actor-unbound", "actor"),
    ("approval-other-snapshot", "approval-snapshot-mismatch", "does not cover this operation"),
    ("approval-other-context", "approval-context-mismatch", "does not cover this operation"),
    ("integer-out-of-range", "arguments-number-out-of-range", "pass it as a string"),
    ("lone-surrogate-argument", "arguments-not-json", "canonical JSON domain"),
    ("oversized-arguments", "arguments-too-large", "JSON budget"),
    ("arguments-invalid", "arguments-invalid", "offline input schema"),
]


@pytest.mark.parametrize(("failure", "reason", "message"), DENIALS, ids=[d[0] for d in DENIALS])
def test_gateway_denies_with_a_specific_reason_and_no_side_effects(
    tmp_path, failure, reason, message
):
    values = list(fixture(tmp_path))
    changes = _denial_setup(values, failure)
    with pytest.raises(AuthorizationError, match=message) as denied:
        invoke(values, **changes)
    assert denied.value.reason == reason
    assert reason in REASONS
    assert values[-1] == []


def test_an_admitted_decision_names_only_the_snapshot_signers_that_counted(tmp_path):
    values = list(fixture(tmp_path))
    gateway, statuses, release = values[0], values[4], values[6]
    revoked = Ed25519PrivateKey.generate()
    gateway.snapshot_keys = {
        **gateway.snapshot_keys,
        key_id(revoked.public_key()): revoked.public_key(),
    }
    decisions = []
    gateway.on_decision = decisions.append
    values[4] = statuses.model_copy(update={"revoked_signers": (key_id(revoked.public_key()),)})
    signed = sign_contract(values[3], "snapshot", (release, revoked))
    assert invoke(values, snapshot=signed) == "executed"
    assert decisions[-1].admitted
    assert decisions[-1].snapshot_signers == (key_id(release.public_key()),)


def test_threshold_counts_distinct_authorized_keys(tmp_path):
    values = fixture(tmp_path)
    snapshot, key = values[3], values[6]
    envelope = sign_contract(snapshot, "snapshot", (key,))
    duplicate = envelope.model_copy(update={"signatures": envelope.signatures * 2})
    ring = {key_id(key.public_key()): key.public_key()}
    with pytest.raises(AuthorizationError):
        verify_contract(duplicate, "snapshot", ring, threshold=2)
    other = Ed25519PrivateKey.generate()
    ring[key_id(other.public_key())] = other.public_key()
    verified, accepted = verify_contract(
        sign_contract(snapshot, "snapshot", (key, other)), "snapshot", ring, threshold=2
    )
    assert verified == snapshot and len(accepted) == 2
    with pytest.raises(AuthorizationError):
        verify_contract(envelope, "snapshot", ring, threshold=0)


def test_statement_type_and_payload_tampering_rejected(tmp_path):
    values = fixture(tmp_path)
    key = values[6]
    envelope = sign_contract(values[3], "snapshot", (key,))
    ring = {key_id(key.public_key()): key.public_key()}
    with pytest.raises(AuthorizationError):
        verify_contract(envelope, "approval", ring)
    statement = json.loads(base64.b64decode(envelope.payload))
    statement["predicate"]["serial"] = 900
    altered = envelope.model_copy(
        update={"payload": base64.b64encode(json.dumps(statement).encode()).decode()}
    )
    with pytest.raises(AuthorizationError):
        verify_contract(altered, "snapshot", ring)
    wire = envelope.model_dump(mode="json", by_alias=True)
    assert "payloadType" in wire and "keyid" in wire["signatures"][0]
    assert Envelope.model_validate(wire) == envelope


def test_verifier_records_high_water_mark_and_rejects_fork(tmp_path):
    store = StateStore.initialize(tmp_path / "state.sqlite")
    store.record((("snapshot:acme/prod", 10, "digest10"),))
    reopened = StateStore(tmp_path / "state.sqlite")
    with pytest.raises(AuthorizationError) as older:
        reopened.record((("snapshot:acme/prod", 9, "digest9"),))
    assert older.value.reason == "snapshot-superseded"
    with pytest.raises(AuthorizationError) as fork:
        reopened.record((("snapshot:acme/prod", 10, "other"),))
    assert fork.value.reason == "snapshot-fork"
    reopened.record((("snapshot:acme/prod", 11, "digest11"),))


def test_failed_authorization_does_not_poison_state(tmp_path):
    values = fixture(tmp_path)
    with pytest.raises(AuthorizationError):
        invoke(values, approval=None)
    assert invoke(values) == "executed"


def test_actual_argument_scope_cannot_bypass_autonomous_grant(tmp_path):
    values = list(fixture(tmp_path))
    grant = values[3].tools[0].model_copy(update={"require_approval": False})
    values[3] = values[3].model_copy(update={"tools": (grant,)})
    values[1] = values[1].model_copy(update={"arguments": {"to": "admin@example.test"}})
    with pytest.raises(AuthorizationError, match="actual tool arguments"):
        invoke(values, approval=None)
    assert values[-1] == []


def test_new_revocation_is_remembered_even_when_call_is_denied(tmp_path):
    values = list(fixture(tmp_path))
    old_status = values[4]
    values[4] = old_status.model_copy(
        update={"serial": 2, "revoked_tools": (values[3].tools[0].definition_digest,)}
    )
    with pytest.raises(AuthorizationError, match="revoked") as revoked:
        invoke(values)
    assert revoked.value.reason == "tool-revoked"
    values[4] = old_status
    with pytest.raises(AuthorizationError, match="rollback") as rollback:
        invoke(values)
    assert rollback.value.reason == "trust-rollback"
    assert values[-1] == []


def test_revoked_trust_signer_cannot_reinstate_itself(tmp_path):
    values = list(fixture(tmp_path))
    gateway, _, _, snapshot, status, _, _, _, authority, executed = values
    other = Ed25519PrivateKey.generate()
    other_id = key_id(other.public_key())
    gateway.trust_keys[other_id] = other.public_key()
    revoked = status.model_copy(
        update={
            "serial": 2,
            "revoked_signers": (other_id,),
            "revoked_tools": (snapshot.tools[0].definition_digest,),
        }
    )
    with pytest.raises(AuthorizationError, match="tool is revoked"):
        invoke(values, trust=sign_contract(revoked, "trust", (authority,)))
    gateway.state = StateStore(tmp_path / "state.sqlite")
    clear = status.model_copy(update={"serial": 3})
    with pytest.raises(AuthorizationError, match="previously revoked"):
        invoke(values, trust=sign_contract(clear, "trust", (other,)))
    assert executed == []

    # A still-authorized issuer may restore B. B can then issue a later status.
    with pytest.raises(AuthorizationError, match="operation-bound approval required"):
        invoke(values, trust=sign_contract(clear, "trust", (authority,)), approval=None)
    later = status.model_copy(update={"serial": 4})
    assert invoke(values, trust=sign_contract(later, "trust", (other,))) == "executed"
    assert len(executed) == 1


def test_legacy_trust_head_requires_exact_status_for_migration(tmp_path):
    values = fixture(tmp_path)
    gateway, _, _, _, status, _, _, _, authority, _ = values
    legacy = tmp_path / "legacy.sqlite"
    other = Ed25519PrivateKey.generate()
    other_id = key_id(other.public_key())
    gateway.trust_keys[other_id] = other.public_key()
    expired = status.model_copy(
        update={
            "revoked_signers": (other_id,),
            "not_before": NOW - timedelta(hours=2),
            "not_after": NOW - timedelta(hours=1),
        }
    )
    db = sqlite3.connect(legacy)
    with db:
        db.execute("CREATE TABLE heads (scope TEXT PRIMARY KEY, serial INTEGER, digest TEXT)")
        db.execute(
            "INSERT INTO heads VALUES (?, ?, ?)",
            ("trust:acme", expired.serial, digest(expired.model_dump(mode="json"))),
        )
        db.execute("CREATE TABLE nonces (nonce TEXT PRIMARY KEY)")
        db.execute("INSERT INTO nonces VALUES ('legacy-consumed-nonce')")
    db.close()

    gateway.state = StateStore(legacy)
    next_status = status.model_copy(update={"serial": 2})
    with pytest.raises(AuthorizationError, match="restore the recorded trust status"):
        invoke(values, trust=sign_contract(next_status, "trust", (other,)))
    with pytest.raises(AuthorizationError, match="does not match"):
        gateway.state.restore_trust_status(status)
    gateway.state.restore_trust_status(expired)
    with pytest.raises(AuthorizationError, match="expired"):
        invoke(values, trust=sign_contract(expired, "trust", (authority,)))
    with pytest.raises(AuthorizationError, match="previously revoked"):
        invoke(values, trust=sign_contract(next_status, "trust", (other,)))
    with pytest.raises(AuthorizationError, match="already been used"):
        gateway.state.record((), "legacy-consumed-nonce")
    assert invoke(values, trust=sign_contract(next_status, "trust", (authority,))) == "executed"


def test_concurrent_trust_advance_rejects_inflight_call_without_consuming_nonce(tmp_path):
    values = fixture(tmp_path)
    gateway, _, _, _, status, _, _, _, authority, executed = values
    second = StateStore(tmp_path / "state.sqlite")
    other_id = key_id(Ed25519PrivateKey.generate().public_key())
    revoked = status.model_copy(update={"serial": 2, "revoked_signers": (other_id,)})
    describe = gateway.describe

    def observe_new_status(server, tool):
        second.accept_trust_status(revoked, {key_id(authority.public_key())})
        return describe(server, tool)

    gateway.describe = observe_new_status
    with pytest.raises(AuthorizationError, match="rollback/fork"):
        invoke(values)
    assert executed == []
    gateway.describe = describe
    assert invoke(values, trust=sign_contract(revoked, "trust", (authority,))) == "executed"


def test_revocation_during_final_authentication_denies_pending_invocation(tmp_path):
    values = fixture(tmp_path)
    gateway, _, _, snapshot, status, _, _, _, authority, executed = values
    context = gateway.authenticate()
    first_auth = True
    final_auth_started = Event()
    resume_final_auth = Event()

    def authenticate():
        nonlocal first_auth
        if first_auth:
            first_auth = False
        else:
            final_auth_started.set()
            assert resume_final_auth.wait(timeout=5)
        return context

    gateway.authenticate = authenticate
    second = StateStore(tmp_path / "state.sqlite")
    revoked = status.model_copy(
        update={"serial": 2, "revoked_tools": (snapshot.tools[0].definition_digest,)}
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(invoke, values)
        try:
            assert final_auth_started.wait(timeout=5)
            second.accept_trust_status(revoked, {key_id(authority.public_key())})
        finally:
            resume_final_auth.set()
        with pytest.raises(AuthorizationError, match="rollback/fork"):
            pending.result(timeout=5)
    assert executed == []
    # Preserve the original approval when admission fails.
    restored = status.model_copy(update={"serial": 3})
    assert invoke(values, trust=sign_contract(restored, "trust", (authority,))) == "executed"


def test_expiry_is_rechecked_after_slow_adapter(tmp_path):
    values = fixture(tmp_path)
    gateway = values[0]
    describe = gateway.describe

    def delayed(server, tool):
        gateway.clock = lambda: NOW + timedelta(hours=2)
        return describe(server, tool)

    gateway.describe = delayed
    with pytest.raises(AuthorizationError, match="expired"):
        invoke(values)
    assert values[-1] == []


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "object", "required": ["amount"]},
        {"$ref": "https://attacker.example.test/schema"},
        # Python semantics read this deny-list as not matching "team@example.test":
        # its backreference names a group that did not take part.
        {"properties": {"to": {"not": {"pattern": r"""^(['"])?team\1@"""}}}},
        # A subschema's own $schema would switch evaluation to draft-04, which has no const.
        {
            "properties": {
                "to": {"$schema": "http://json-schema.org/draft-04/schema#", "const": "ops"}
            }
        },
    ],
)
def test_invalid_or_external_schema_cannot_execute(tmp_path, schema):
    values = list(fixture(tmp_path))
    definition = {**DEFINITION, "inputSchema": schema}
    grant = (
        values[3]
        .tools[0]
        .model_copy(
            update={
                "definition_digest": hash_tool_definition(
                    "send", definition["description"], schema
                ),
                "require_approval": False,
            }
        )
    )
    values[3] = values[3].model_copy(update={"tools": (grant,)})
    values[0].describe = lambda *_: ServedTool(
        endpoint_identity=grant.endpoint_identity, definition=definition
    )
    with pytest.raises(AuthorizationError, match="offline input schema"):
        invoke(values, approval=None)
    assert values[-1] == []


def test_approval_actor_must_match_authorized_key(tmp_path):
    values = list(fixture(tmp_path))
    values[5] = values[5].model_copy(update={"actor": "other-approver"})
    with pytest.raises(AuthorizationError, match="actor"):
        invoke(values)
    assert values[-1] == []


@pytest.mark.parametrize(
    "raw",
    [
        '{"a":1,"a":2}',
        '{"n":NaN}',
        '{"n":Infinity}',
        '\ufeff{"a":1}',
        b'\xef\xbb\xbf{"a":1}',
        '{"a":1}'.encode("utf-16"),
        '{"a":1}'.encode("utf-16-le"),
        '{"a":1}'.encode("utf-32"),
        b'{"a":"\xff"}',
    ],
)
def test_noncanonical_input_rejected(raw):
    with pytest.raises(AuthorizationError) as refused:
        strict_json(raw)
    assert refused.value.reason == "json-invalid"


def test_utf8_input_is_accepted_as_bytes_or_text():
    assert strict_json(b'{"a":"\xc3\xa9"}') == strict_json('{"a":"\u00e9"}') == {"a": "\u00e9"}


def test_a_state_database_that_fails_to_initialize_can_be_initialized_again(tmp_path, monkeypatch):
    import sqlite3

    from nexus_symbiote import runtime

    def failing(db):
        raise sqlite3.OperationalError("disk I/O error")

    path = tmp_path / "state.sqlite"
    with monkeypatch.context() as patch:
        patch.setattr(runtime, "_migrate", failing)
        with pytest.raises(AuthorizationError) as failed:
            StateStore.initialize(path)
    assert failed.value.reason == "state-unavailable"
    assert not path.exists()
    StateStore.initialize(path)
    assert path.is_file()


def test_nonces_are_scoped_by_tenant_and_legacy_rows_stay_consumed(tmp_path):
    store = StateStore.initialize(tmp_path / "state.sqlite")
    store.record((), "shared-nonce", tenant="acme")
    store.record((), "shared-nonce", tenant="globex")
    with pytest.raises(AuthorizationError, match="already been used"):
        store.record((), "shared-nonce", tenant="acme")
    with sqlite3.connect(tmp_path / "state.sqlite") as db:
        db.execute("INSERT INTO nonces VALUES ('legacy-consumed-nonce')")
    for tenant in ("acme", "globex", None):
        with pytest.raises(AuthorizationError, match="already been used"):
            store.record((), "legacy-consumed-nonce", tenant=tenant)
    with pytest.raises(AuthorizationError, match="already been used"):
        store.record((), "shared-nonce")


def test_library_validation_errors_name_fields_without_values(tmp_path):
    values = fixture(tmp_path)
    key = values[6]
    envelope = sign_contract(values[3], "snapshot", (key,))
    ring = {key_id(key.public_key()): key.public_key()}
    statement = json.loads(base64.b64decode(envelope.payload))
    statement["predicate"]["not_before"] = "2026-10-31T23:59:59"
    statement["predicate"]["unexpected_key"] = "SECRET-VALUE-0001"
    payload = canonical_bytes(statement)
    altered = Envelope(
        payload=base64.b64encode(payload).decode(),
        signatures=(
            EnvelopeSignature(
                key_id=key_id(key.public_key()),
                signature=base64.b64encode(key.sign(_pae(payload))).decode(),
            ),
        ),
    )
    with pytest.raises(AuthorizationError) as excinfo:
        verify_contract(altered, "snapshot", ring)
    message = str(excinfo.value)
    assert "SECRET-VALUE-0001" not in message and "23:59:59" not in message
    assert "not_before" in message and "unsupported field" in message


def test_non_canonical_predicate_is_rejected_so_one_contract_has_one_digest(tmp_path):
    values = fixture(tmp_path)
    snapshot, key = values[3], values[6]
    envelope = sign_contract(snapshot, "snapshot", (key,))
    ring = {key_id(key.public_key()): key.public_key()}
    statement = json.loads(base64.b64decode(envelope.payload))
    canonical = digest(snapshot.model_dump(mode="json"))
    assert "sha256:" + statement["subject"][0]["digest"]["sha256"] == canonical
    # The same contract encoded differently, as another DSSE signer may emit it.
    predicate = {
        name: value[:-1] + "+00:00" if isinstance(value, str) and value.endswith("Z") else value
        for name, value in statement["predicate"].items()
    }
    assert ApprovedSnapshot.model_validate(predicate) == snapshot
    assert digest(predicate) != canonical
    statement["predicate"] = predicate
    statement["subject"] = [
        {"name": "snapshot", "digest": {"sha256": digest(predicate).split(":", 1)[1]}}
    ]
    payload = canonical_bytes(statement)
    signature = EnvelopeSignature(
        key_id=key_id(key.public_key()),
        signature=base64.b64encode(key.sign(_pae(payload))).decode(),
    )
    altered = Envelope(payload=base64.b64encode(payload).decode(), signatures=(signature,))
    with pytest.raises(AuthorizationError, match="canonical"):
        verify_contract(altered, "snapshot", ring)
    contract, _ = verify_contract(envelope, "snapshot", ring)
    assert digest(contract.model_dump(mode="json")) == canonical


def test_sign_contract_refuses_a_contract_that_is_not_in_canonical_form(tmp_path):
    values = fixture(tmp_path)
    snapshot, key = values[3], values[6]
    ring = {key_id(key.public_key()): key.public_key()}
    # model_copy skips validation, so the copy keeps a non-UTC offset the validator would convert.
    pacific = timezone(timedelta(hours=-8))
    local = snapshot.model_copy(
        update={"serial": 2, "not_after": (NOW + timedelta(hours=2)).astimezone(pacific)}
    )
    with pytest.raises(AuthorizationError, match="not in canonical form"):
        sign_contract(local, "snapshot", (key,))
    renewed = snapshot.model_copy(update={"serial": 2, "not_after": NOW + timedelta(hours=2)})
    contract, _ = verify_contract(sign_contract(renewed, "snapshot", (key,)), "snapshot", ring)
    assert digest(contract.model_dump(mode="json")) == digest(renewed.model_dump(mode="json"))


def test_sign_contract_refuses_a_copy_that_does_not_validate(tmp_path):
    values = fixture(tmp_path)
    snapshot, key = values[3], values[6]
    inverted = snapshot.model_copy(update={"not_after": snapshot.not_before})
    with pytest.raises(AuthorizationError, match="does not validate"):
        sign_contract(inverted, "snapshot", (key,))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("revoked_snapshots", "a" * 64),
        ("revoked_snapshots", "SHA256:" + "A" * 64),
        ("revoked_snapshots", "sha256:" + "A" * 64),
        ("revoked_tools", "a" * 64),
        ("revoked_signers", "sha256:" + "a" * 64),
        ("revoked_signers", "A" * 64),
    ],
)
def test_malformed_revocation_entries_are_rejected_instead_of_ignored(field, value):
    window = {"not_before": NOW, "not_after": NOW + timedelta(minutes=5)}
    with pytest.raises(ValidationError):
        TrustStatus(tenant="acme", serial=1, **window, **{field: (value,)})
    canonical = "sha256:" + "a" * 64 if field != "revoked_signers" else "a" * 64
    assert getattr(TrustStatus(tenant="acme", serial=1, **window, **{field: (canonical,)}), field)


def test_out_of_range_timestamp_is_a_validation_error_not_an_overflow(tmp_path):
    values = fixture(tmp_path)
    status, key = values[4], values[8]
    # Representable locally, but past datetime.max once converted to UTC.
    far = datetime(9999, 12, 31, 23, 0, tzinfo=timezone(timedelta(hours=-8)))
    with pytest.raises(ValidationError, match="out of range"):
        TrustStatus(tenant="acme", serial=1, not_before=NOW, not_after=far)
    with pytest.raises(AuthorizationError, match="does not validate"):
        sign_contract(status.model_copy(update={"not_after": far}), "trust", (key,))
