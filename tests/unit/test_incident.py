from datetime import UTC, datetime, timedelta

import pytest
from cryptography.exceptions import InvalidSignature
from typer.testing import CliRunner

from symbiote.attest import (
    PAYLOAD_TYPE,
    Envelope,
    KeyRing,
    generate_signing_key,
    sign_envelope,
    snapshot_statement,
    trust_status_statement,
    verify_envelope,
)
from symbiote.attest.dsse import save_private_key, save_public_key
from symbiote.cli import app
from symbiote.digest import bytes_digest, canonical_bytes, parse_json_strict
from symbiote.export.companion import companion_bytes
from symbiote.incident import EXECUTION_TYPE, REPORT_TYPE, Execution, incident_query
from symbiote.model import Edge
from symbiote.model.common import Validity
from symbiote.model.entities import CredentialBinding, Deployment, Grant, Identity, TrustStatus
from symbiote.snapshot import finalize
from tests.unit.test_enforce import approved_doc

NOW = datetime(2026, 11, 1, tzinfo=UTC)
END = NOW + timedelta(hours=1)


def fixture(tenant, *keys, declared=False):
    doc = approved_doc()
    validity = Validity(not_before=NOW, not_after=END)
    tool = doc.tools[0].replace(state="served")
    server = tool.server_ref
    dep = Deployment(
        id="deploy:one",
        agent_ref=doc.subject,
        tenant=tenant,
        workload_identity_ref="ident:work",
        environment={"kind": "k8s"},
    )
    ident = Identity(id="ident:work", kind="spiffe", ref="spiffe://example/work", tenant=tenant)
    cred = CredentialBinding(
        id="cred:one", subject_ref=tool.id, identity_ref=ident.id, kind="service-account"
    )
    grant = Grant(
        id="grant:one",
        layer="effective",
        subject_ref=tool.id,
        credential_binding_ref=cred.id,
        capability="read",
        scope={"resources": ["bucket:a"]},
        approval_gate="required",
        validity=validity,
    )
    props = {
        "assurance": "declared" if declared else "observed",
        "evidence": [{"digest": bytes_digest(b"collector")}],
    }
    edges = [
        Edge(type="providesTool", from_ref=server, to_ref=tool.id, **props),
        Edge(type="dependsOn", from_ref=doc.subject, to_ref=server, **props),
    ]
    doc = finalize(
        doc.replace(
            snapshot=doc.snapshot.replace(kind="deployed", deployment_ref=dep.id, validity=validity),
            tools=[tool],
            deployments=[dep],
            identities=[ident],
            credential_bindings=[cred],
            grants=[grant],
            edges=edges,
        ),
        nonce=bytes(32),
    )
    raw = companion_bytes(doc)
    sig = sign_envelope(
        canonical_bytes(snapshot_statement(doc, companion_digest=bytes_digest(raw))), PAYLOAD_TYPE, list(keys)
    )
    return doc, raw, sig


def ring(k):
    return KeyRing.from_public_keys([k.public_key()])


def test_scope_roles_and_independent_execution():
    deploy, policy, observer = [generate_signing_key("ed25519") for _ in range(3)]
    doc, raw, sig = fixture("acme", deploy, policy)
    _, raw2, sig2 = fixture("other", deploy, policy)
    tool = doc.tools[0]
    args = {
        "tenant": "acme",
        "descriptor_digest": tool.digest.value,
        "start": NOW,
        "end": END,
        "deployment_keys": ring(deploy),
    }
    item = incident_query([(raw, sig), (raw2, sig2)], **args)["deployments"]
    assert len(item) == 1 and item[0]["deployed"]["status"] == "evidenced"
    assert item[0]["effectivePermission"]["status"] == item[0]["observedExecution"]["status"] == "unknown"
    event = Execution(
        event_id="trace:1",
        tenant="acme",
        deployment="deploy:one",
        agent=doc.subject,
        workload="ident:work",
        actor="alice",
        tool=tool.id,
        server=tool.server_ref,
        descriptor_digest=tool.digest.value,
        companion_digest=bytes_digest(raw),
        snapshot_digest=doc.snapshot.digest,
        evidence_digest=bytes_digest(b"trace"),
        observed_at=NOW,
        outcome="completed",
    )

    def sign(e, k):
        return sign_envelope(canonical_bytes(e.to_json_dict()), EXECUTION_TYPE, k)

    result = incident_query(
        [(raw, sig), (raw2, sig2)],
        **args,
        policy_keys=ring(policy),
        observer_keys=ring(observer),
        observations=[
            sign(event, observer),
            sign(event.replace(tenant="other"), observer),
            sign(event.replace(event_id="excluded", observed_at=END), observer),
        ],
    )
    row = result["deployments"][0]
    assert row["effectivePermission"]["grants"][0]["grant"]["approvalGate"] == "required"
    assert [e["event"]["eventId"] for e in row["observedExecution"]["events"]] == ["trace:1"]
    with pytest.raises(InvalidSignature):
        incident_query([(raw, sig)], **args, observer_keys=ring(observer), observations=[sign(event, deploy)])
    with pytest.raises(ValueError):
        incident_query([(raw + b" ", sig)], **args)
    _, rd, sd = fixture("acme", deploy, declared=True)
    assert incident_query([(rd, sd)], **args)["deployedStatus"] == "unknown"


def test_signed_revocation_and_report_through_cli(tmp_path):
    deploy, trust, report = [generate_signing_key("ed25519") for _ in range(3)]
    doc, raw, env = fixture("acme", deploy)
    descriptor = doc.tools[0].digest.value
    since = NOW + timedelta(minutes=15)
    entry = TrustStatus(
        id="trust:one",
        subject_kind="tool-digest",
        subject_key=descriptor,
        status="revoked",
        reason="compromised",
        decided_by_ref="agent:triager",
        decided_at=since,
        expires=END,
        serial=8,
    )
    stmt = trust_status_statement("acme", [entry], serial=8, expires=END.isoformat(), decided_by=doc.subject)
    signal = sign_envelope(canonical_bytes(stmt), PAYLOAD_TYPE, trust)

    def f(name):
        return str(tmp_path / name)

    (tmp_path / "companion").write_bytes(raw)
    (tmp_path / "env").write_text(env.model_dump_json(by_alias=True))
    (tmp_path / "revoke").write_text(signal.model_dump_json(by_alias=True))
    save_public_key(deploy.public_key(), tmp_path / "deploy.pub")
    save_public_key(trust.public_key(), tmp_path / "trust.pub")
    save_private_key(report, tmp_path / "report.key")
    args = [
        "incident",
        "query",
        "--tenant",
        "acme",
        "--from",
        NOW.isoformat(),
        "--until",
        END.isoformat(),
        "--descriptor",
        descriptor,
        "--companion",
        f("companion"),
        "--envelope",
        f("env"),
        "--deployment-key",
        f("deploy.pub"),
        "--revocation",
        f("revoke"),
        "--trust-key",
        f("trust.pub"),
        "--report-key",
        f("report.key"),
    ]
    run = CliRunner().invoke(app, args)
    assert run.exit_code == 0, (run.output, run.exception)
    signed = Envelope.model_validate_json(run.stdout)
    assert signed.payload_type == REPORT_TYPE
    payload, _ = verify_envelope(signed, ring(report))
    result = parse_json_strict(payload)
    assert result["revocation"]["serial"] == 8 and result["from"] == since.isoformat()
    args[args.index("acme")] = "other"
    assert CliRunner().invoke(app, args).exit_code != 0


def test_publisher_requires_verified_digest_issuer_and_independent_authority():
    from symbiote.model.entities import RegistryResolution

    deploy, provenance = [generate_signing_key("ed25519") for _ in range(2)]
    doc, _, _ = fixture("acme", deploy)
    artifact = bytes_digest(b"server")
    resolution = RegistryResolution(
        id="res:server",
        requested={"kind": "oci", "ref": "registry.test/server"},
        resolved={"digest": artifact},
        resolved_at=NOW,
        resolver="registry",
        signer={
            "issuer": "https://issuer.test",
            "identity": "team:release",
            "status": "verified",
            "outcome": "verified",
            "bundleDigest": bytes_digest(b"bundle"),
        },
    )

    def query(r, **target):
        snap = finalize(
            doc.replace(
                tool_servers=[doc.tool_servers[0].replace(digest=artifact, registry_resolution_ref=r.id)],
                resolutions=[r],
            ),
            nonce=bytes(32),
        )
        raw = companion_bytes(snap)
        env = sign_envelope(
            canonical_bytes(snapshot_statement(snap, companion_digest=bytes_digest(raw))),
            PAYLOAD_TYPE,
            [deploy, provenance],
        )
        return incident_query(
            [(raw, env)], tenant="acme", start=NOW, end=END, deployment_keys=ring(deploy), **target
        )

    policy = {
        "publisher": "team:release",
        "issuer": "https://issuer.test",
        "provenance_keys": ring(provenance),
    }
    assert query(resolution, **policy)["deployedStatus"] == "evidenced"
    assert query(resolution, **{**policy, "issuer": "https://other.test"})["deployedStatus"] == "unknown"
    assert (
        query(resolution.replace(resolved={"digest": bytes_digest(b"other")}), **policy)["deployedStatus"]
        == "unknown"
    )
    assert query(resolution, artifact_digest=artifact)["deployedStatus"] == "evidenced"
    with pytest.raises(ValueError):
        query(resolution, **{**policy, "provenance_keys": ring(deploy)})
