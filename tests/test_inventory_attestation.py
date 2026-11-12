"""Detached attestations bind trusted signers to the exact bytes of an inventory file."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote.attestation import (
    MAX_INVENTORY_BYTES,
    PREDICATE_TYPE,
    sign_inventory,
    verify_inventory,
)
from nexus_symbiote.cli import main
from nexus_symbiote.runtime import (
    PREDICATES,
    STATEMENT_TYPE,
    AuthorizationError,
    Envelope,
    TrustStatus,
    _pae,
    canonical_bytes,
    key_id,
    sign_contract,
)

CONTENT = b'{"metadata": {"spec_version": "1.1.0"}, "components": []}\n'


def _ring(*keys: Ed25519PrivateKey) -> dict:
    return {key_id(key.public_key()): key.public_key() for key in keys}


def _reason(content: bytes, envelope: Envelope, ring: dict, **kwargs) -> str:
    with pytest.raises(AuthorizationError) as caught:
        verify_inventory(content, envelope, ring, **kwargs)
    return caught.value.reason


def _envelope(statement: dict, key: Ed25519PrivateKey) -> Envelope:
    payload = canonical_bytes(statement)
    return Envelope.model_validate(
        {
            "payload": base64.b64encode(payload).decode(),
            "signatures": [
                {
                    "keyid": key_id(key.public_key()),
                    "sig": base64.b64encode(key.sign(_pae(payload))).decode(),
                }
            ],
        }
    )


def _statement(envelope: Envelope) -> dict:
    return json.loads(base64.b64decode(envelope.payload))


def test_signed_bytes_verify_and_report_their_signers():
    first, second = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    now = datetime(2026, 11, 12, tzinfo=UTC)
    envelope = sign_inventory(CONTENT, [first, second], name="agentbom.json", now=now)
    attestation, accepted = verify_inventory(CONTENT, envelope, _ring(first, second), threshold=2)
    assert accepted == set(_ring(first, second))
    assert attestation.signed_at == now
    statement = _statement(envelope)
    assert statement["_type"] == STATEMENT_TYPE
    assert statement["predicateType"] == PREDICATE_TYPE
    assert statement["subject"][0]["name"] == "agentbom.json"


def test_statement_is_deterministic_for_one_time():
    key = Ed25519PrivateKey.generate()
    now = datetime(2026, 11, 12, tzinfo=UTC)
    assert sign_inventory(CONTENT, [key], now=now) == sign_inventory(CONTENT, [key], now=now)


@pytest.mark.parametrize(
    "changed", [CONTENT + b" ", CONTENT[:-1], CONTENT.replace(b"1.1.0", b"1.1.1"), b""]
)
def test_any_changed_byte_is_a_subject_mismatch(changed):
    key = Ed25519PrivateKey.generate()
    envelope = sign_inventory(CONTENT, [key])
    assert _reason(changed, envelope, _ring(key)) == "subject-mismatch"


def test_untrusted_or_too_few_signers_fail_before_the_payload_is_read():
    signer, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    envelope = sign_inventory(CONTENT, [signer])
    assert _reason(CONTENT, envelope, _ring(other)) == "signers-insufficient"
    assert _reason(CONTENT, envelope, _ring(signer, other), threshold=2) == "signers-insufficient"
    assert _reason(CONTENT, envelope, {}) == "configuration-invalid"
    assert _reason(CONTENT, envelope, _ring(signer), threshold=0) == "configuration-invalid"


def test_one_key_signing_twice_counts_once():
    key = Ed25519PrivateKey.generate()
    envelope = sign_inventory(CONTENT, [key, key])
    assert _reason(CONTENT, envelope, _ring(key), threshold=2) == "signers-insufficient"


def test_a_tampered_payload_loses_its_signatures():
    key = Ed25519PrivateKey.generate()
    envelope = sign_inventory(CONTENT, [key])
    statement = _statement(envelope)
    statement["subject"][0]["digest"]["sha256"] = "0" * 64
    forged = envelope.model_copy(
        update={"payload": base64.b64encode(canonical_bytes(statement)).decode()}
    )
    assert _reason(CONTENT, forged, _ring(key)) == "signers-insufficient"


def test_a_runtime_contract_is_not_an_inventory_attestation_and_the_reverse():
    key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    status = TrustStatus(
        tenant="acme", serial=1, not_before=now, not_after=now + timedelta(minutes=5)
    )
    contract = sign_contract(status, "trust", [key])
    assert _reason(CONTENT, contract, _ring(key)) == "statement-purpose-mismatch"
    assert PREDICATE_TYPE not in PREDICATES.values()


@pytest.mark.parametrize(
    "mutate, reason",
    [
        (lambda s: s.update(extra=1), "statement-invalid"),
        (lambda s: s.pop("predicate"), "statement-invalid"),
        (
            lambda s: s.update(_type="https://in-toto.io/Statement/v0.1"),
            "statement-purpose-mismatch",
        ),
        (lambda s: s["predicate"].update(unknown=True), "contract-invalid"),
        (lambda s: s["predicate"].update(signed_at="2026-11-12T00:00:00"), "contract-invalid"),
        (lambda s: s.update(subject=[]), "subject-mismatch"),
        (lambda s: s.update(subject=s["subject"] * 2), "subject-mismatch"),
        (lambda s: s.update(subject=[{"name": "x"}]), "subject-mismatch"),
        (lambda s: s.update(subject=[{"name": "x", "digest": {"sha256": 7}}]), "subject-mismatch"),
        (lambda s: s.update(subject="inventory"), "subject-mismatch"),
    ],
)
def test_validly_signed_but_malformed_statements_are_refused(mutate, reason):
    key = Ed25519PrivateKey.generate()
    statement = _statement(sign_inventory(CONTENT, [key]))
    mutate(statement)
    assert _reason(CONTENT, _envelope(statement, key), _ring(key)) == reason


def test_a_signed_payload_that_is_not_json_is_refused():
    key = Ed25519PrivateKey.generate()
    payload = b"not json"
    envelope = Envelope.model_validate(
        {
            "payload": base64.b64encode(payload).decode(),
            "signatures": [{"sig": base64.b64encode(key.sign(_pae(payload))).decode()}],
        }
    )
    assert _reason(CONTENT, envelope, _ring(key)) == "statement-invalid"


def test_signing_refuses_bad_configuration():
    key = Ed25519PrivateKey.generate()

    class Wrong:
        def sign(self, data: bytes) -> bytes:
            return b"\0" * 64

        def public_key(self):
            return key.public_key()

    for keys, kwargs in (
        ([], {}),
        ([key] * 33, {}),
        ([key], {"name": ""}),
        ([key], {"name": "n" * 256}),
    ):
        with pytest.raises(AuthorizationError):
            sign_inventory(CONTENT, keys, **kwargs)
    with pytest.raises(AuthorizationError) as caught:
        sign_inventory(CONTENT, [Wrong()])
    assert caught.value.reason == "configuration-invalid"
    with pytest.raises(AuthorizationError) as caught:
        sign_inventory(b"x" * (MAX_INVENTORY_BYTES + 1), [key])
    assert caught.value.reason == "json-budget-exceeded"


def _keygen(runner: CliRunner, directory: Path, name: str) -> tuple[Path, Path]:
    private, public = directory / f"{name}.pem", directory / f"{name}.pub"
    result = runner.invoke(
        main, ["runtime", "keygen", "--private-key", str(private), "--public-key", str(public)]
    )
    assert result.exit_code == 0, result.output
    return private, public


def test_cli_attests_a_scanned_inventory_and_detects_an_edit(runner, tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Be helpful.\n")
    inventory, signed = tmp_path / "agentbom.json", tmp_path / "agentbom.intoto.json"
    runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(inventory)])
    assert inventory.is_file()
    private, public = _keygen(runner, tmp_path, "signer")
    _, stranger = _keygen(runner, tmp_path, "stranger")

    result = runner.invoke(
        main, ["attest", str(inventory), "--key", str(private), "--out", str(signed)]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["signed"] is True
    assert set(json.loads(signed.read_text())) == {"payloadType", "payload", "signatures"}

    verify = ["verify-attestation", str(inventory), str(signed), "--public-key"]
    result = runner.invoke(main, [*verify, str(public)])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["attestation_verified"] is True and report["content_verified"] is False
    assert len(report["accepted_signers"]) == 1

    result = runner.invoke(main, [*verify, str(stranger)])
    assert result.exit_code == 1 and "signers-insufficient" in result.output
    result = runner.invoke(main, [*verify, str(public), "--threshold", "2"])
    assert result.exit_code == 1 and "signers-insufficient" in result.output

    inventory.write_text(inventory.read_text().replace("CLAUDE.md", "AGENTS.md"))
    result = runner.invoke(main, [*verify, str(public)])
    assert result.exit_code == 1 and "subject-mismatch" in result.output

    result = runner.invoke(
        main, ["attest", str(inventory), "--key", str(private), "--out", str(signed)]
    )
    assert result.exit_code == 1, "an existing attestation must not be overwritten"


def test_cli_errors_never_echo_file_content(runner, tmp_path):
    planted = "sk-live-do-not-print"
    inventory = tmp_path / "bom.json"
    inventory.write_text("{}")
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"payload": planted, "signatures": [], "note": planted}))
    _, public = _keygen(runner, tmp_path, "k")
    result = runner.invoke(
        main, ["verify-attestation", str(inventory), str(bad), "--public-key", str(public)]
    )
    assert result.exit_code == 1
    assert planted not in result.output
