from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from typer.testing import CliRunner

from symbiote.attest import (
    PAYLOAD_TYPE,
    Envelope,
    KeyRing,
    generate_signing_key,
    key_id,
    pae,
    sign_envelope,
    snapshot_statement,
    verify_envelope,
)
from symbiote.attest.dsse import save_private_key, save_public_key
from symbiote.attest.statements import statement_bytes
from symbiote.cli import app
from symbiote.export.companion import (
    CompanionValidationError,
    companion_bytes,
    load_companion,
    validate_companion,
)
from symbiote.model import AgentBOM, Claim, DigestResult, Edge, Producer
from symbiote.model import enums as E
from symbiote.model.entities import Agent, Authentication, ToolDefinition, ToolServer
from symbiote.snapshot import finalize, new_document, redact_entities, verify_document

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
NONCE = bytes(range(32))


def build(kind: E.SnapshotKind = E.SnapshotKind.DECLARED) -> AgentBOM:
    agent = Agent(id="agent:triager", name="triager", version="1.0.0", role=E.AgentRole.ROOT)
    server = ToolServer(
        id="server:github",
        kind=E.ToolServerKind.MCP,
        transport=Claim.declared(E.Transport.STDIO),
        authentication=Claim.declared(Authentication(mode=E.AuthMode.API_KEY)),
        crosses_trust_boundary=Claim.declared(True),
    )
    tool = ToolDefinition(
        id="tool:github/get_issue",
        server_ref="server:github",
        tool_name="get_issue",
        input_schema={"type": "object"},
        digest=DigestResult(algorithm="tooldef/v1", value="sha256:" + "ab" * 32),
        source=E.ToolSource.DECLARED_CONFIG,
    )
    doc = new_document(
        subject="agent:triager",
        producer=Producer(version="0.1.0"),
        kind=kind,
        produced_at=NOW,
        agents=[agent],
        tool_servers=[server],
        tools=[tool],
        edges=[
            Edge(type=E.EdgeType.PROVIDES_TOOL, **{"from": "server:github", "to": "tool:github/get_issue"})
        ],
    )
    return finalize(doc, nonce=NONCE)


def test_finalize_is_deterministic_and_verifiable() -> None:
    a, b = build(), build()
    assert a.snapshot.digest == b.snapshot.digest
    assert a.snapshot.id.startswith("snap:1:")
    assert a.merkle is not None and a.merkle.leaf_count == 5  # 3 entities + 1 edge + coverage
    assert verify_document(a)
    assert companion_bytes(a) == companion_bytes(b)
    c = finalize(build(), nonce=b"\x07" * 32)
    assert c.snapshot.digest != a.snapshot.digest


def test_redacted_companion_still_verifies() -> None:
    bom = build()
    assert bom.merkle is not None
    redacted = redact_entities(
        bom, {"tool:github/get_issue"}, redaction_class="tool-text", applied_by="test", applied_at=NOW
    )
    # the tool body is gone, its salt is withheld, the edge still resolves to the placeholder, and the root recomputes
    assert redacted.tools == [] and redacted.redacted[0].id == "tool:github/get_issue"
    assert redacted.snapshot.digest == bom.snapshot.digest
    assert verify_document(redacted)
    assert redacted.merkle is not None and redacted.merkle.nonce is None
    assert redacted.redactions[0].count == 1
    assert validate_companion(json.loads(companion_bytes(redacted))) == []
    assert load_companion(companion_bytes(redacted)) == redacted
    tampered = bom.replace(tools=[bom.tools[0].replace(tool_name="get_issue_evil")])
    assert not verify_document(tampered)


def test_companion_bytes_validate_and_round_trip() -> None:
    bom = build()
    raw = companion_bytes(bom)
    data = json.loads(raw)
    assert validate_companion(data) == []
    assert load_companion(raw) == bom
    data["unexpected"] = 1
    assert validate_companion(data)
    with pytest.raises(CompanionValidationError):
        load_companion(json.dumps(data))


def test_dsse_pae_and_signatures() -> None:
    assert pae("application/vnd.in-toto+json", b"{}") == b"DSSEv1 28 application/vnd.in-toto+json 2 {}"
    k1, k2 = generate_signing_key("ecdsa-p256"), generate_signing_key("ed25519")
    bom = build()
    stmt = snapshot_statement(bom)
    payload = statement_bytes(stmt)
    env = sign_envelope(payload, PAYLOAD_TYPE, [k1, k2])
    assert len(env.signatures) == 2 and env.payload_bytes == payload
    ring = KeyRing.from_public_keys([k1.public_key()])
    got, accepted = verify_envelope(env, ring)
    assert json.loads(got)["predicateType"].endswith("/attestation/agentbom-snapshot/v1") and accepted == [
        key_id(k1.public_key())
    ]
    with pytest.raises(InvalidSignature):
        verify_envelope(env, KeyRing())
    with pytest.raises(InvalidSignature):
        verify_envelope(env, ring, threshold=2)
    forged = Envelope.model_validate({**env.to_json(), "payload": env.payload[:-4] + "AAAA"})
    with pytest.raises(InvalidSignature):
        verify_envelope(forged, ring)
    # statement subjects bind the Merkle root
    assert stmt["subject"][0]["digest"]["sha256"] == bom.snapshot.digest.split(":", 1)[1]
    assert stmt["predicate"]["leafCount"] == 5


def test_cli_end_to_end(tmp_path: Path) -> None:
    runner = CliRunner()
    bom = build()
    companion = tmp_path / "agentbom.json"
    companion.write_bytes(companion_bytes(bom))
    key = generate_signing_key()
    save_private_key(key, tmp_path / "key.pem")
    save_public_key(key.public_key(), tmp_path / "key.pub")
    r = runner.invoke(app, ["validate", str(companion), "--json"])
    assert r.exit_code == 0, r.output
    assert json.loads(r.stdout)[0]["ok"] is True
    r = runner.invoke(app, ["merkle", "verify", str(companion), "--json"])
    assert r.exit_code == 0 and json.loads(r.stdout)["verified"] is True
    env_path = tmp_path / "snap.dsse.json"
    r = runner.invoke(
        app, ["attest", "snapshot", str(companion), "--key", str(tmp_path / "key.pem"), "-o", str(env_path)]
    )
    assert r.exit_code == 0, r.output
    r = runner.invoke(
        app,
        [
            "verify",
            str(env_path),
            "--public-key",
            str(tmp_path / "key.pub"),
            "--companion",
            str(companion),
            "--json",
        ],
    )
    assert r.exit_code == 0, r.output
    assert json.loads(r.stdout)["outcome"] == "verified-constrained"
    # a different companion fails the binding
    other = tmp_path / "other.json"
    other.write_bytes(companion_bytes(finalize(build(), nonce=b"\x09" * 32)))
    r = runner.invoke(
        app,
        [
            "verify",
            str(env_path),
            "--public-key",
            str(tmp_path / "key.pub"),
            "--companion",
            str(other),
            "--json",
        ],
    )
    assert r.exit_code == 4
    tool = tmp_path / "tool.json"
    tool.write_text(json.dumps({"name": "x", "inputSchema": {"type": "object"}}))
    r = runner.invoke(app, ["digest", "tooldef", str(tool), "--json"])
    assert r.exit_code == 0 and json.loads(r.stdout)["status"] == "ok"
    r = runner.invoke(app, ["version", "--json"])
    assert json.loads(r.stdout)["agentbomSpecVersion"] == "0.1"
