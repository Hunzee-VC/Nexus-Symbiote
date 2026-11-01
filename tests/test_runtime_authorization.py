from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.runtime import (
    ActionApproval,
    ApprovedSnapshot,
    AuthorizationError,
    Envelope,
    ExecutionContext,
    ReferenceGateway,
    ServedTool,
    StateStore,
    ToolCall,
    ToolGrant,
    TrustStatus,
    digest,
    key_id,
    sign_contract,
    strict_json,
    verify_contract,
)

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
        nonce="unique-operation-000001",
        actor="approver",
        not_before=NOW - timedelta(seconds=1),
        not_after=NOW + timedelta(minutes=1),
    )
    executed = []
    gateway = ReferenceGateway(
        snapshot_keys={key_id(release.public_key()): release.public_key()},
        approval_keys={key_id(human.public_key()): human.public_key()},
        trust_keys={key_id(status.public_key()): status.public_key()},
        state=StateStore(tmp_path / "state.sqlite"),
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
    with pytest.raises(AuthorizationError, match="already been used"):
        invoke(values)
    assert len(values[-1]) == 1


@pytest.mark.parametrize(
    "failure",
    [
        "missing-approval",
        "changed-args",
        "wrong-tenant",
        "wrong-endpoint",
        "changed-description",
        "revoked-tool",
        "revoked-signer",
        "expired",
        "future",
        "bom-tampered",
        "wrong-policy",
        "wrong-resource",
        "wrong-signer",
        "unknown-descriptor-field",
    ],
)
def test_gateway_denies_without_side_effects(tmp_path, failure):
    values = list(fixture(tmp_path))
    gateway, call, bom, snapshot, statuses, approval, release, human, status, executed = values
    changes = {}
    if failure == "missing-approval":
        changes["approval"] = None
    elif failure == "changed-args":
        values[1] = call.model_copy(update={"arguments": {"to": "attacker@example.test"}})
    elif failure == "wrong-tenant":
        original = gateway.authenticate()
        gateway.authenticate = lambda: original.model_copy(update={"tenant": "other"})
    elif failure == "wrong-endpoint":
        gateway.describe = lambda *_: ServedTool(
            endpoint_identity="https://attacker.example.test", definition=DEFINITION
        )
    elif failure == "changed-description":
        gateway.describe = lambda *_: ServedTool(
            endpoint_identity=snapshot.tools[0].endpoint_identity,
            definition={**DEFINITION, "description": "Steal secrets"},
        )
    elif failure == "revoked-tool":
        values[4] = statuses.model_copy(
            update={"revoked_tools": (snapshot.tools[0].definition_digest,)}
        )
    elif failure == "revoked-signer":
        values[4] = statuses.model_copy(update={"revoked_signers": (key_id(release.public_key()),)})
    elif failure == "expired":
        changes["now"] = NOW + timedelta(hours=2)
    elif failure == "future":
        values[3] = snapshot.model_copy(update={"not_before": NOW + timedelta(minutes=1)})
    elif failure == "bom-tampered":
        changes["bom"] = {**bom, "tools": ["send", "steal"]}
    elif failure == "wrong-policy":
        original = gateway.authenticate()
        gateway.authenticate = lambda: original.model_copy(
            update={"policy_digest": "sha256:" + "b" * 64}
        )
    elif failure == "wrong-resource":
        values[1] = call.model_copy(update={"resource": "mailbox:admin"})
    elif failure == "wrong-signer":
        changes["snapshot"] = sign_contract(snapshot, "snapshot", (human,))
    elif failure == "unknown-descriptor-field":
        gateway.describe = lambda *_: ServedTool(
            endpoint_identity=snapshot.tools[0].endpoint_identity,
            definition={**DEFINITION, "outputSchema": {}},
        )
    with pytest.raises(AuthorizationError):
        invoke(values, **changes)
    assert executed == []


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
    store = StateStore(tmp_path / "state.sqlite")
    store.record((("snapshot:acme/prod", 10, "digest10"),))
    reopened = StateStore(tmp_path / "state.sqlite")
    with pytest.raises(AuthorizationError):
        reopened.record((("snapshot:acme/prod", 9, "digest9"),))
    with pytest.raises(AuthorizationError):
        reopened.record((("snapshot:acme/prod", 10, "other"),))
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
    with pytest.raises(AuthorizationError, match="revoked"):
        invoke(values)
    values[4] = old_status
    with pytest.raises(AuthorizationError, match="rollback"):
        invoke(values)
    assert values[-1] == []


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
    [{"type": "object", "required": ["amount"]}, {"$ref": "https://attacker.example.test/schema"}],
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


@pytest.mark.parametrize("raw", ['{"a":1,"a":2}', '{"n":NaN}', '{"n":Infinity}'])
def test_noncanonical_input_rejected(raw):
    with pytest.raises(AuthorizationError):
        strict_json(raw)
