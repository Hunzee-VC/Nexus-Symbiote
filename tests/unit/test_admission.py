"""A real reference enforcement adapter records a signed decision before a harmless tool call."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from symbiote.attest.dsse import KeyRing, generate_signing_key, sign_envelope
from symbiote.digest.envelope import digest_str
from symbiote.digest.jcs import canonical_bytes
from symbiote.enforce.admission import (
    APPROVAL,
    BUNDLE,
    Binding,
    CallIntent,
    admit_call,
    approve_call,
    dispatch_call,
    sign_gateway_bundle,
    verify_receipt,
)
from symbiote.enforce.gab import check_served_tool, export_allowlist, gab_from_document
from symbiote.model.common import Claim, Validity
from symbiote.model.entities import (
    CredentialBinding,
    Deployment,
    Grant,
    Identity,
    RegistryResolution,
    TrustStatus,
)
from symbiote.model.ids import snapshot_id
from symbiote.snapshot import finalize
from tests.unit.test_enforce import RAW2, approved_doc

NOW = datetime(2026, 11, 1, tzinfo=UTC)
BINDING = Binding(
    agent="agent:triager",
    deployment="deploy:web",
    tenant="tenant:acme",
    workload="ident:triager",
    actor="ident:alice",
)
PEER = digest_str(b"verified-server-image")
POLICY = digest_str(b"release-policy-v1")


def fixture_bom(*, serial=1, trust_serial=1, revoke=False, reverse=False, prev=None):
    bom = approved_doc()
    deployment = Deployment(
        id=BINDING.deployment,
        agent_ref=bom.subject,
        environment={"kind": "k8s"},
        tenant=BINDING.tenant,
        workload_identity_ref=BINDING.workload,
    )
    trust = TrustStatus(
        id="trust:publisher",
        subject_kind="publisher-identity",
        subject_key="publisher:tools",
        status="revoked" if revoke else "allowlisted",
        reason="test",
        decided_by_ref=bom.subject,
        decided_at=NOW,
        expires=NOW + timedelta(hours=1),
        serial=trust_serial,
    )
    resolution = RegistryResolution(
        id="res:git",
        requested={"kind": "oci", "ref": "registry.example/git"},
        resolved={"digest": PEER},
        resolved_at=NOW,
        resolver="trusted-provider",
        signer={
            "issuer": "https://issuer.example",
            "identity": "publisher:tools",
            "status": "verified",
            "outcome": "verified",
        },
    )
    server = bom.tool_servers[0].replace(digest=PEER, registry_resolution_ref=resolution.id)
    tool = next(t for t in bom.tools if t.tool_name == RAW2["name"]).replace(
        approval_gate="none", required_scopes=Claim.declared(["pull:write"])
    )
    grants = [
        Grant(
            id="grant:" + i,
            layer="declared",
            subject_ref=tool.id,
            capability="write",
            scope={"resources": [r]},
            approval_gate=gate,
            policy_ref={"bundleDigest": POLICY},
            credential_binding_ref="cred:tool",
            delegation_chain=[
                {
                    "from": BINDING.actor,
                    "to": BINDING.workload,
                    "protocol": "obo",
                    "audience": server.id,
                    "scopes": ["pull:write"],
                    "expires": NOW + timedelta(hours=1),
                }
            ],
            validity=Validity(not_before=NOW - timedelta(minutes=1), not_after=NOW + timedelta(hours=1)),
        )
        for i, r, gate in zip(
            ("z", "a") if reverse else ("a", "z"), ("prod", "dev"), ("required", "none"), strict=True
        )
    ]
    header = bom.snapshot.replace(
        id=snapshot_id(serial, bom.snapshot.digest),
        serial=serial,
        prev=prev,
        deployment_ref=deployment.id,
        policy_bundle=Claim.declared(POLICY),
        validity=Validity(not_before=NOW - timedelta(minutes=1), not_after=NOW + timedelta(days=1)),
    )
    return finalize(
        bom.replace(
            snapshot=header,
            deployments=[deployment],
            resolutions=[resolution],
            tool_servers=[server],
            tools=[tool],
            edges=[],
            grants=[*grants, *(g.replace(id=g.id + "-effective", layer="effective") for g in grants)],
            credential_bindings=[
                CredentialBinding(
                    id="cred:tool",
                    subject_ref=tool.id,
                    identity_ref=BINDING.workload,
                    kind="obo-token",
                    scopes_granted=Claim.declared(["pull:write"]),
                )
            ],
            trust_status=[trust],
            identities=[
                Identity(id=BINDING.actor, kind="human", ref="alice", tenant=BINDING.tenant, issuer="idp"),
                Identity(id="ident:bob", kind="human", ref="bob", tenant=BINDING.tenant, issuer="idp"),
                Identity(
                    id=BINDING.workload,
                    kind="spiffe",
                    ref="spiffe://example/workload",
                    tenant=BINDING.tenant,
                    issuer="ca",
                ),
            ],
        ),
        nonce=bytes(32),
    )


def intent(repo, request):
    return CallIntent(
        binding=BINDING,
        request_id=request,
        action="write",
        resource=repo,
        tool=RAW2["name"],
        server="server:github",
        peer_digest=PEER,
        arguments_digest=digest_str(canonical_bytes({"repo": repo})),
    )


def ring(key):
    return KeyRing.from_public_keys([key.public_key()])


@pytest.mark.parametrize("reverse", [False, True])
def test_dispatch_signed_policy_approval_revocation_and_replay(tmp_path: Path, reverse: bool):
    signer, gateway, approver = [generate_signing_key("ed25519") for _ in range(3)]
    bom = fixture_bom(reverse=reverse)
    bundle = sign_gateway_bundle(bom, BINDING, signer)
    store = tmp_path / "decisions.sqlite"
    calls = []

    def dispatch(policy, call, *, ticket=None, desc=RAW2, now=NOW):
        actual = {"repo": call.resource}
        signed, _ = dispatch_call(
            policy,
            call,
            desc,
            actual,
            resolve_resource=lambda args: args["repo"],
            invoke=lambda args: calls.append(args["repo"]),
            approval=ticket,
            approval_keys=ring(approver),
            bundle_keys=ring(signer),
            receipt_key=gateway,
            state_db=store,
            now=now,
        )
        return verify_receipt(signed, ring(gateway))

    d = dispatch(bundle, intent("dev", "1"))
    assert (d.decision, d.intent.binding, d.policy_digest, d.snapshot_digest) == (
        "allow",
        BINDING,
        POLICY,
        bom.snapshot.digest,
    )
    prod = intent("prod", "2")
    assert dispatch(bundle, prod).decision == "approval-required"
    ticket = approve_call(bundle, prod, approver, now=NOW, expires=NOW + timedelta(minutes=1))
    assert dispatch(bundle, prod.replace(request_id="3"), ticket=ticket).decision == "deny"
    assert dispatch(bundle, prod, ticket=ticket).decision == "allow"
    assert dispatch(bundle, prod, ticket=ticket).reason == "request-already-consumed"
    assert dispatch(bundle, intent("dev", "4"), desc={**RAW2, "description": "changed"}).decision == "deny"
    assert dispatch(bundle, intent("dev", "5"), now=NOW + timedelta(hours=2)).decision == "deny"
    assert (
        dispatch(bundle, intent("dev", "6").replace(binding=BINDING.replace(tenant="other"))).decision
        == "deny"
    )
    assert dispatch(bundle, intent("dev", "7").replace(peer_digest=digest_str(b"other"))).decision == "deny"
    revoked = sign_gateway_bundle(
        fixture_bom(serial=2, trust_serial=2, revoke=True, prev=bom.snapshot.digest), BINDING, signer
    )
    assert dispatch(revoked, intent("dev", "8")).reason == "publisher-revoked-or-quarantined"
    assert dispatch(revoked, intent("prod", "9")).decision == "deny"
    assert dispatch(bundle, intent("dev", "10")).reason == "rollback-or-equivocation"
    assert calls == ["dev", "prod"]


def test_invalid_signature_wrong_type_and_legacy_exports(tmp_path):
    signer, other, gateway = [generate_signing_key("ed25519") for _ in range(3)]
    bom = fixture_bom()
    assert len(gab_from_document(bom)["servers"]["server:github"]["tools"][RAW2["name"]]["grants"]) == 4
    with pytest.raises(ValueError, match="cannot preserve"):
        export_allowlist(bom, "mcp-gateway-generic")
    revoked = fixture_bom(revoke=True)
    assert (
        check_served_tool(gab_from_document(revoked, trust_status=[]), "server:github", RAW2, now=NOW).action
        == "block"
    )
    bundle = sign_gateway_bundle(bom, BINDING, signer)
    for malformed, err in [
        (sign_envelope(bundle.payload_bytes, BUNDLE, other), InvalidSignature),
        (sign_envelope(bundle.payload_bytes, APPROVAL, signer), ValueError),
    ]:
        with pytest.raises(err):
            admit_call(
                malformed,
                intent("dev", "n"),
                RAW2,
                bundle_keys=ring(signer),
                receipt_key=gateway,
                state_db=tmp_path / "s.db",
                now=NOW,
            )
    with pytest.raises(ValueError, match="arguments or resource"):
        dispatch_call(
            bundle,
            intent("dev", "2"),
            RAW2,
            {"repo": "prod"},
            resolve_resource=lambda args: args["repo"],
            invoke=lambda _: pytest.fail("dispatched"),
            bundle_keys=ring(signer),
            receipt_key=gateway,
            state_db=tmp_path / "s.db",
            now=NOW,
        )


def test_missing_or_unrelated_trust_and_constraints_deny(tmp_path):
    bom = fixture_bom()
    signer, gateway = [generate_signing_key("ed25519") for _ in range(2)]

    def check(candidate, request):
        signed = sign_gateway_bundle(finalize(candidate, nonce=bytes(32)), BINDING, signer)
        receipt = admit_call(
            signed,
            intent("dev", request),
            RAW2,
            bundle_keys=ring(signer),
            receipt_key=gateway,
            state_db=tmp_path / (request + ".db"),
            now=NOW,
        )
        return verify_receipt(receipt, ring(gateway))

    with pytest.raises(ValueError, match="bounded trust"):
        check(bom.replace(trust_status=[]), "empty")
    other = bom.trust_status[0].replace(subject_key="publisher:someone-else")
    assert check(bom.replace(trust_status=[other]), "unrelated").decision == "deny"
    conditional = [g.replace(conditions=[{"kind": "tenant", "expr": "internal"}]) for g in bom.grants]
    assert check(bom.replace(grants=conditional), "condition").reason == "unsupported-grant-constraint"
    revoked = bom.trust_status[0].replace(
        id="trust:digest", subject_kind="tool-digest", status="revoked", subject_key=bom.tools[0].digest.value
    )
    assert check(bom.replace(trust_status=[*bom.trust_status, revoked]), "digest").decision == "deny"


def test_cli_sign_then_verify_persisted_receipt(tmp_path):
    import json

    from typer.testing import CliRunner

    from symbiote.attest.dsse import Envelope, save_private_key, save_public_key
    from symbiote.cli import app

    signer, gateway = [generate_signing_key("ed25519") for _ in range(2)]
    bom = fixture_bom()
    (tmp_path / "companion").write_text(json.dumps(bom.to_json_dict()))
    (tmp_path / "binding").write_text(BINDING.model_dump_json(by_alias=True))
    save_private_key(signer, tmp_path / "policy.key")
    save_public_key(gateway.public_key(), tmp_path / "gateway.pub")
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "admission",
            "sign",
            str(tmp_path / "companion"),
            str(tmp_path / "binding"),
            "--key",
            str(tmp_path / "policy.key"),
        ],
    )
    assert result.exit_code == 0, result.output
    bundle = Envelope.model_validate_json(result.stdout)
    rec = admit_call(
        bundle,
        intent("dev", "cli"),
        RAW2,
        bundle_keys=ring(signer),
        receipt_key=gateway,
        state_db=tmp_path / "state",
        now=NOW,
    )
    (tmp_path / "receipt").write_text(rec.model_dump_json(by_alias=True))
    result = runner.invoke(
        app,
        ["admission", "verify-receipt", str(tmp_path / "receipt"), "--key", str(tmp_path / "gateway.pub")],
    )
    assert result.exit_code == 0 and json.loads(result.stdout)["decision"] == "allow"


def test_exact_effective_authority_and_cross_actor_rollback(tmp_path):
    signer, gateway = [generate_signing_key("ed25519") for _ in range(2)]
    bom = fixture_bom()

    def issue(doc, binding=BINDING):
        return sign_gateway_bundle(finalize(doc, nonce=bytes(32)), binding, signer)

    def decide(bundle, path, request=None):
        rec = admit_call(
            bundle,
            request or intent("dev", "test"),
            RAW2,
            bundle_keys=ring(signer),
            receipt_key=gateway,
            state_db=tmp_path / path,
            now=NOW,
        )
        return verify_receipt(rec, ring(gateway))

    declared = [g for g in bom.grants if g.layer.value == "declared"]
    effective = [g for g in bom.grants if g.layer.value == "effective"]
    assert decide(issue(bom.replace(grants=declared)), "missing").reason == "effective-authority-unknown"
    assert decide(issue(bom.replace(grants=effective)), "only").decision == "deny"
    assert (
        decide(
            issue(bom.replace(grants=[*declared, *(g.replace(validity=Validity()) for g in effective)])),
            "unbounded",
        ).reason
        == "unbounded-effective-authority"
    )
    assert (
        decide(
            issue(
                bom.replace(
                    grants=[*declared, *(g.replace(scope={"resources": ["prod"]}) for g in effective)]
                )
            ),
            "scoped",
        ).decision
        == "deny"
    )
    wrong = bom.credential_bindings[0].replace(subject_ref="tool:other")
    assert decide(issue(bom.replace(credential_bindings=[wrong])), "subject").decision == "deny"
    bob = BINDING.replace(actor="ident:bob")
    assert decide(issue(bom, bob), "bob", intent("dev", "bob").replace(binding=bob)).decision == "deny"
    newer = issue(fixture_bom(serial=2, trust_serial=2, revoke=True))
    assert decide(newer, "shared").decision == "deny"
    assert (
        decide(issue(bom, bob), "shared", intent("dev", "bob").replace(binding=bob)).reason
        == "rollback-or-equivocation"
    )


def test_freshness_checks_every_trust_entry(tmp_path):
    bom = fixture_bom()
    signer, gateway = [generate_signing_key("ed25519") for _ in range(2)]
    original = bom.trust_status[0]

    def plus(entry):
        return finalize(
            bom.replace(trust_status=[original, entry.replace(id="trust:second")]), nonce=bytes(32)
        )

    for entry in [
        original.replace(decided_at=NOW - timedelta(days=2)),
        original.replace(decided_at=NOW + timedelta(minutes=1)),
        original.replace(decided_at=NOW - timedelta(hours=2), expires=NOW - timedelta(hours=1)),
    ]:
        policy = sign_gateway_bundle(plus(entry), BINDING, signer)
        rec = admit_call(
            policy,
            intent("dev", "t"),
            RAW2,
            bundle_keys=ring(signer),
            receipt_key=gateway,
            state_db=tmp_path / "fresh",
            now=NOW,
        )
        assert verify_receipt(rec, ring(gateway)).reason == "stale-or-invalid-policy"
    for entry in [original.replace(expires=None), original.replace(serial=2)]:
        with pytest.raises(ValueError):
            sign_gateway_bundle(plus(entry), BINDING, signer)


def test_dispatch_rejects_cached_trust_at_operator_deadline(tmp_path):
    signer, gateway = [generate_signing_key("ed25519") for _ in range(2)]
    bundle = sign_gateway_bundle(fixture_bom(), BINDING, signer)
    calls = []
    for seconds, expected in [(29, "allow"), (30, "deny")]:
        signed, _ = dispatch_call(
            bundle,
            intent("dev", f"fresh-{seconds}"),
            RAW2,
            {"repo": "dev"},
            resolve_resource=lambda a: a["repo"],
            invoke=calls.append,
            bundle_keys=ring(signer),
            receipt_key=gateway,
            state_db=tmp_path / "cache.sqlite",
            now=NOW + timedelta(seconds=seconds),
            max_trust_age=timedelta(seconds=30),
        )
        decision = verify_receipt(signed, ring(gateway))
        assert decision.decision == expected
        if expected == "deny":
            assert decision.reason == "stale-or-invalid-policy"
    assert calls == [{"repo": "dev"}]


def test_forward_serial_jump_must_chain_onto_the_admitted_snapshot(tmp_path):
    """A validly signed bundle with a far-forward serial but no ``prev`` link cannot lock the scope (audit §6.1)."""
    signer, gateway = [generate_signing_key("ed25519") for _ in range(2)]
    first = fixture_bom()

    def decide(doc, request_id):
        bundle = sign_gateway_bundle(doc, BINDING, signer)
        rec = admit_call(
            bundle,
            intent("dev", request_id),
            RAW2,
            bundle_keys=ring(signer),
            receipt_key=gateway,
            state_db=tmp_path / "chain.sqlite",
            now=NOW,
        )
        return verify_receipt(rec, ring(gateway))

    assert decide(first, "1").decision == "allow"
    jump = fixture_bom(serial=1000, trust_serial=1000)  # no prev: not a successor of the admitted snapshot
    assert decide(jump, "2").reason == "rollback-or-equivocation"
    successor = fixture_bom(serial=2, trust_serial=2, prev=first.snapshot.digest)
    assert decide(successor, "3").decision == "allow"  # the legitimate chain still advances


def test_serial_steps_are_bounded(tmp_path):
    """Even with a correct prev link, one admission cannot jump the snapshot or trust serial out of reach."""
    from symbiote.enforce.admission import MAX_SERIAL_STEP

    signer, gateway = [generate_signing_key("ed25519") for _ in range(2)]

    def decide(doc, request_id):
        rec = admit_call(
            sign_gateway_bundle(doc, BINDING, signer),
            intent("dev", request_id),
            RAW2,
            bundle_keys=ring(signer),
            receipt_key=gateway,
            state_db=tmp_path / "steps.sqlite",
            now=NOW,
        )
        return verify_receipt(rec, ring(gateway))

    first = fixture_bom()
    assert decide(first, "1").decision == "allow"
    huge = fixture_bom(serial=2, trust_serial=MAX_SERIAL_STEP + 5, prev=first.snapshot.digest)
    assert decide(huge, "2").reason == "rollback-or-equivocation"  # trust serial step too large
    far = fixture_bom(serial=MAX_SERIAL_STEP + 5, trust_serial=2, prev=first.snapshot.digest)
    assert decide(far, "3").reason == "rollback-or-equivocation"  # snapshot serial step too large
