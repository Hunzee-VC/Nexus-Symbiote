"""Reference call admission for exact-resource grants, with operator-owned keys and durable state."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar

from pydantic import AwareDatetime, Field, StringConstraints

from symbiote.attest.dsse import Envelope, KeyRing, PrivateKey, key_id, sign_envelope, verify_envelope
from symbiote.digest.envelope import digest_str
from symbiote.digest.jcs import canonical_bytes, parse_json_strict
from symbiote.digest.tooldef import tooldef_digest
from symbiote.enforce.gab import check_served_tool, gab_from_document
from symbiote.model.base import SymbioteModel
from symbiote.model.common import DigestStr
from symbiote.model.document import AgentBOM
from symbiote.model.entities import Grant
from symbiote.model.enums import ApprovalGate, CapabilityClass, GrantLayer, SnapshotKind
from symbiote.snapshot.commit import verify_document

BUNDLE = "application/vnd.symbiote.gateway-bundle.v1+json"
APPROVAL = "application/vnd.symbiote.call-approval.v1+json"
RECEIPT = "application/vnd.symbiote.call-decision.v1+json"
DEFAULT_MAX_TRUST_AGE = timedelta(hours=24)
Name = Annotated[str, StringConstraints(min_length=1, max_length=1024)]
Verdict = Literal["allow", "deny", "approval-required"]


class Binding(SymbioteModel):
    agent: Name
    deployment: Name
    tenant: Name
    workload: Name
    actor: Name


class CallIntent(SymbioteModel):
    """Built by the authenticated gateway, after authoritative resource and argument resolution."""

    binding: Binding
    request_id: Name
    server: Name
    peer_digest: DigestStr
    tool: Name
    action: CapabilityClass
    resource: Name
    arguments_digest: DigestStr


class SignedPolicy(SymbioteModel):
    binding: Binding
    policy_digest: DigestStr
    gab: dict[str, Any]


class CallApproval(SymbioteModel):
    intent_digest: DigestStr
    bundle_digest: DigestStr
    not_before: AwareDatetime
    expires: AwareDatetime


class CallReceipt(SymbioteModel):
    intent: CallIntent
    intent_digest: DigestStr
    bundle_digest: DigestStr
    snapshot_digest: DigestStr
    policy_digest: DigestStr
    descriptor_digest: DigestStr | None
    trust_serial: int
    decided_at: AwareDatetime
    decision: Verdict
    reason: str
    approval_key_ids: list[str] = Field(default_factory=list)


def _digest(value: Any) -> str:
    return digest_str(canonical_bytes(value))


def _verified(envelope: Envelope, keys: KeyRing, expected_type: str) -> tuple[Any, list[str]]:
    if envelope.payload_type != expected_type:
        raise ValueError("unexpected signed payload type")
    payload, signers = verify_envelope(envelope, keys)
    return parse_json_strict(payload), signers


def sign_gateway_bundle(bom: AgentBOM, binding: Binding, key: PrivateKey) -> Envelope:
    """An admission-policy authority explicitly approves this deployment and actor."""
    if bom.redacted or bom.snapshot.kind != SnapshotKind.APPROVED or not verify_document(bom):
        raise ValueError("a verified, approved snapshot is required")
    deployment = next((d for d in bom.deployments if d.id == binding.deployment), None)
    if (
        not deployment
        or bom.snapshot.deployment_ref != binding.deployment
        or bom.subject != binding.agent
        or deployment.agent_ref != binding.agent
        or deployment.tenant != binding.tenant
        or deployment.workload_identity_ref != binding.workload
        or not {binding.workload, binding.actor}.issubset(
            i.id for i in bom.identities if i.tenant == binding.tenant and i.issuer
        )
    ):
        raise ValueError("snapshot/deployment/tenant/workload binding mismatch")
    policy = bom.snapshot.policy_bundle
    if not policy or not policy.value:
        raise ValueError("missing approved policy digest")
    window = bom.snapshot.validity
    if (
        not window.not_before
        or not window.not_after
        or not window.not_before.tzinfo
        or not window.not_after.tzinfo
    ):
        raise ValueError("bounded snapshot validity with timezone required")
    if not bom.trust_status or any(
        not t.expires or not t.expires.tzinfo or not t.decided_at.tzinfo or t.expires <= t.decided_at
        for t in bom.trust_status
    ):
        raise ValueError("bounded trust status required")
    if len({t.serial for t in bom.trust_status}) != 1:
        raise ValueError("publish a single complete trust generation; mixed trust serials are ambiguous")
    operations = [(tool.server_ref, tool.tool_name) for tool in bom.tools]
    if len(set(operations)) != len(operations):
        raise ValueError("ambiguous duplicate tool name on a server")
    gab = gab_from_document(bom)
    gab["trustStatus"]["oldestDecision"] = min(t.decided_at for t in bom.trust_status).isoformat()
    gab["trustStatus"]["issued"] = max(t.decided_at for t in bom.trust_status).isoformat()
    body = SignedPolicy(binding=binding, policy_digest=policy.value, gab=gab)
    return sign_envelope(canonical_bytes(body.to_json_dict()), BUNDLE, key)


def approve_call(
    bundle: Envelope, intent: CallIntent, key: PrivateKey, *, now: datetime, expires: datetime
) -> Envelope:
    """Sign one intent against the exact bundle payload; the approval key is separately configured."""
    if expires <= now:
        raise ValueError("approval must expire after issuance")
    approval = CallApproval(
        intent_digest=_digest(intent.to_json_dict()),
        bundle_digest=digest_str(bundle.payload_bytes),
        not_before=now,
        expires=expires,
    )
    return sign_envelope(canonical_bytes(approval.to_json_dict()), APPROVAL, key)


def _current(gab: dict[str, Any], now: datetime, max_age: timedelta) -> bool:
    snapshot, trust = gab["snapshot"], gab["trustStatus"]
    if snapshot["kind"] != "approved" or snapshot["serial"] < 1 or trust["serial"] < 1:
        return False
    start, end, issued, expires = (
        datetime.fromisoformat(s)
        for s in (snapshot["notBefore"], snapshot["notAfter"], trust["issued"], trust["expires"])
    )
    oldest = datetime.fromisoformat(trust["oldestDecision"])
    return start <= now < end and oldest <= issued <= now < min(expires, oldest + max_age)


def _authority_matches(
    grant: Grant, intent: CallIntent, rule: dict[str, Any], credentials: dict[str, Any], now: datetime
) -> bool:
    """Verify tenant-qualified actor → workload → target, with explicit scope and delegation bounds."""
    if not grant.credential_binding_ref or grant.subject_ref not in (rule["id"], intent.server):
        return False
    credential = credentials.get(grant.credential_binding_ref)
    if (
        not credential
        or credential["identity"] != intent.binding.workload
        or credential["subject"] != grant.subject_ref
    ):
        return False
    needed, granted = rule.get("requiredScopes"), credential.get("scopes")
    if not needed or not granted or not set(needed).issubset(granted):
        return False
    if intent.binding.actor == intent.binding.workload:
        return not grant.delegation_chain and credential["kind"] == "ephemeral-task-scoped"
    if credential["kind"] != "obo-token" or len(grant.delegation_chain) != 1:
        return False
    hop = grant.delegation_chain[0]
    return (
        hop.protocol.value == "obo"
        and hop.from_ref == intent.binding.actor
        and hop.to_ref == intent.binding.workload
        and hop.audience == intent.server
        and hop.expires is not None
        and hop.expires.tzinfo is not None
        and now < hop.expires
        and set(needed).issubset(hop.scopes)
        and not hop.constraints
    )


def _grant_gate(
    grants: list[Grant], intent: CallIntent, policy: SignedPolicy, rule: dict[str, Any], now: datetime
) -> tuple[Verdict, str]:
    matched: list[Grant] = []
    for grant in grants:
        if grant.capability != intent.action:
            continue
        if not grant.scope.resources or any(
            any(char in resource for char in "*?[]") for resource in grant.scope.resources
        ):
            return "deny", "unrepresentable-resource-scope"
        if intent.resource not in grant.scope.resources:
            continue
        if not _authority_matches(grant, intent, rule, policy.gab["credentials"], now):
            continue
        if not grant.policy_ref or grant.policy_ref.bundle_digest != policy.policy_digest:
            return "deny", "grant-policy-mismatch"
        # Conditions, delegation and quantitative controls require an external PDP.
        if (
            grant.conditions
            or grant.scope.egress
            or grant.scope.data_classes
            or grant.scope.spend_ceiling
            or grant.scope.rate_limit
            or grant.gate_ref
        ):
            return "deny", "unsupported-grant-constraint"
        start, end = grant.validity.not_before, grant.validity.not_after
        if grant.layer == GrantLayer.EFFECTIVE and (
            not start or not end or not start.tzinfo or not end.tzinfo
        ):
            return "deny", "unbounded-effective-authority"
        if (start and now < start) or (end and now >= end):
            continue
        matched.append(grant)
    if not matched:
        return "deny", "no-applicable-grant"
    if any(g.approval_gate not in (ApprovalGate.NONE, ApprovalGate.REQUIRED) for g in matched):
        return "deny", "unresolved-approval-condition"
    if any(g.approval_gate == ApprovalGate.REQUIRED for g in matched):
        return "approval-required", "scoped-grant-requires-approval"
    return "allow", "scoped-grant"


def _evaluate(
    policy: SignedPolicy, intent: CallIntent, descriptor: dict[str, Any], now: datetime
) -> tuple[Verdict, str]:
    gab = policy.gab
    if intent.binding != policy.binding or descriptor.get("name") != intent.tool:
        return "deny", "identity-or-tool-mismatch"
    decision = check_served_tool(gab, intent.server, descriptor, now=now)
    if decision.action != "allow":
        return "deny", decision.reason
    server = gab["servers"][intent.server]
    identity = server["identity"]
    if intent.peer_digest != identity.get("digest"):
        return "deny", "authenticated-peer-mismatch"
    signer = identity.get("signer") or {}
    if signer.get("status") != "verified" or not signer.get("identity") or not signer.get("issuer"):
        return "deny", "unverified-publisher"
    required_publishers = {signer["identity"], identity.get("publisher") or signer["identity"]}
    if not required_publishers.issubset(gab["trustStatus"].get("allowlistedPublishers", [])):
        return "deny", "publisher-trust-unknown"
    entry = server["tools"][intent.tool]
    # This adapter supports one exact operation class per tool. Ambiguous effects need a richer adapter.
    if entry["capabilities"] != [intent.action.value]:
        return "deny", "ambiguous-or-unapproved-action"
    grants = [Grant.model_validate(g) for g in entry["grants"]]
    verdict, reason = _grant_gate(
        [g for g in grants if g.layer == GrantLayer.DECLARED], intent, policy, entry, now
    )
    effective = [g for g in grants if g.layer == GrantLayer.EFFECTIVE]
    if not effective:
        return "deny", "effective-authority-unknown"
    if verdict != "deny":
        eff_verdict, eff_reason = _grant_gate(effective, intent, policy, entry, now)
        if eff_verdict == "deny" or (eff_verdict == "approval-required" and verdict == "allow"):
            verdict, reason = eff_verdict, eff_reason
    gate = entry["toolGate"]
    if verdict == "allow" and gate == "required":
        return "approval-required", "tool-requires-approval"
    if gate not in ("none", "required"):
        return "deny", "unresolved-tool-gate"
    return verdict, reason


def _advance(db: sqlite3.Connection, scope: str, policy: SignedPolicy) -> bool:
    """Reject snapshot and trust rollback and equivocation under the same deployment scope."""
    snap, trust = policy.gab["snapshot"], policy.gab["trustStatus"]
    # The Merkle root covers bodies. Also commit the signed header, policy digest and projected rules.
    signed_config = {k: v for k, v in policy.gab.items() if k != "trustStatus"}
    row = (snap["serial"], _digest([signed_config, policy.policy_digest]), trust["serial"], _digest(trust))
    old = db.execute("SELECT sn, sd, tn, td FROM heads WHERE scope=?", (scope,)).fetchone()
    if old and (
        row[0] < old[0]
        or row[2] < old[2]
        or (row[0] == old[0] and row[1] != old[1])
        or (row[2] == old[2] and row[3] != old[3])
    ):
        return False
    db.execute("INSERT OR REPLACE INTO heads VALUES(?,?,?,?,?)", (scope, *row))
    return True


def admit_call(
    bundle: Envelope,
    intent: CallIntent,
    descriptor: dict[str, Any],
    *,
    bundle_keys: KeyRing,
    receipt_key: PrivateKey,
    state_db: Path,
    approval: Envelope | None = None,
    approval_keys: KeyRing | None = None,
    now: datetime | None = None,
    max_trust_age: timedelta = DEFAULT_MAX_TRUST_AGE,
) -> Envelope:
    """Verify policy, evaluate and persist a signed receipt before allowing external execution.

    Authentication/parse failures raise; callers must not dispatch. The state directory must be trusted.
    An offline receipt is audit evidence and cannot be used as permission for a later call.
    """
    obj, policy_keys = _verified(bundle, bundle_keys, BUNDLE)
    policy = SignedPolicy.model_validate(obj)
    if (now is not None and now.tzinfo is None) or max_trust_age <= timedelta(0):
        raise ValueError("invalid clock or trust freshness policy")
    if key_id(receipt_key.public_key()) in policy_keys:
        raise ValueError("policy and receipt keys must be distinct")
    digest = _digest(intent.to_json_dict())
    bundle_digest = digest_str(bundle.payload_bytes)
    snapshot, trust = policy.gab["snapshot"], policy.gab["trustStatus"]
    scope = _digest([policy.binding.tenant, policy.binding.deployment, policy.binding.agent])
    with closing(sqlite3.connect(state_db, isolation_level=None)) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS heads(scope TEXT PRIMARY KEY,sn INTEGER,sd TEXT,tn INTEGER,td TEXT)"
        )
        db.execute("CREATE TABLE IF NOT EXISTS consumed(scope TEXT, id TEXT, PRIMARY KEY(scope,id))")
        db.execute("CREATE TABLE IF NOT EXISTS audit(receipt TEXT NOT NULL)")
        db.execute("BEGIN IMMEDIATE")
        now = now or datetime.now(UTC)
        approvers: list[str] = []
        if not _current(policy.gab, now, max_trust_age):
            verdict, reason = "deny", "stale-or-invalid-policy"
        elif not _advance(db, scope, policy):
            verdict, reason = "deny", "rollback-or-equivocation"
        else:
            verdict, reason = _evaluate(policy, intent, descriptor, now)
        if verdict == "approval-required" and approval is not None and approval_keys is not None:
            body, approvers = _verified(approval, approval_keys, APPROVAL)
            ticket = CallApproval.model_validate(body)
            if (
                ticket.intent_digest == digest
                and ticket.bundle_digest == bundle_digest
                and ticket.not_before <= now < ticket.expires
                and not set(approvers).intersection(policy_keys)
                and key_id(receipt_key.public_key()) not in approvers
            ):
                verdict, reason = "allow", "signed-call-approval"
            else:
                verdict, reason = "deny", "invalid-approval-binding"
        if verdict == "allow":
            updated = db.execute(
                "INSERT OR IGNORE INTO consumed VALUES(?,?)", (scope, intent.request_id)
            ).rowcount
            if not updated:
                verdict, reason = "deny", "request-already-consumed"
        receipt = CallReceipt(
            intent=intent,
            intent_digest=digest,
            bundle_digest=bundle_digest,
            policy_digest=policy.policy_digest,
            snapshot_digest=snapshot["digest"],
            trust_serial=trust["serial"],
            descriptor_digest=tooldef_digest(descriptor).value,
            decided_at=now,
            decision=verdict,
            reason=reason,
            approval_key_ids=approvers,
        )
        signed = sign_envelope(canonical_bytes(receipt.to_json_dict()), RECEIPT, receipt_key)
        db.execute("INSERT INTO audit VALUES(?)", (signed.model_dump_json(by_alias=True),))
        db.commit()
    return signed


def verify_receipt(receipt: Envelope, keys: KeyRing) -> CallReceipt:
    payload, _ = _verified(receipt, keys, RECEIPT)
    result = CallReceipt.model_validate(payload)
    if _digest(result.intent.to_json_dict()) != result.intent_digest:
        raise ValueError("receipt intent digest mismatch")
    return result


ResponseT = TypeVar("ResponseT")


def dispatch_call(
    bundle: Envelope,
    intent: CallIntent,
    descriptor: dict[str, Any],
    arguments: dict[str, Any],
    *,
    resolve_resource: Callable[[dict[str, Any]], str],
    invoke: Callable[[dict[str, Any]], ResponseT],
    bundle_keys: KeyRing,
    receipt_key: PrivateKey,
    state_db: Path,
    approval: Envelope | None = None,
    approval_keys: KeyRing | None = None,
    now: datetime | None = None,
    max_trust_age: timedelta = DEFAULT_MAX_TRUST_AGE,
) -> tuple[Envelope, ResponseT | None]:
    """Adapter boundary. Isolate exact arguments and derive their resource before any dispatch."""
    encoded = canonical_bytes(arguments)
    call_args = parse_json_strict(encoded)
    if (
        digest_str(encoded) != intent.arguments_digest
        or resolve_resource(parse_json_strict(encoded)) != intent.resource
    ):
        raise ValueError("arguments or resource differ from the authenticated call intent")
    signed = admit_call(
        bundle,
        intent,
        descriptor,
        bundle_keys=bundle_keys,
        receipt_key=receipt_key,
        state_db=state_db,
        approval=approval,
        approval_keys=approval_keys,
        now=now,
        max_trust_age=max_trust_age,
    )
    decision = verify_receipt(signed, KeyRing.from_public_keys([receipt_key.public_key()]))
    return signed, invoke(call_args) if decision.decision == "allow" else None
