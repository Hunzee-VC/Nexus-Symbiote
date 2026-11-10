from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta

import click
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization

from nexus_symbiote.runtime import (
    ApprovedSnapshot,
    ExecutionContext,
    ToolCall,
    ToolGrant,
    TrustStatus,
    bom_digest,
    contract_digest,
    key_id,
    request_digest,
    sign_contract,
    tool_definition_digest,
)
from nexus_symbiote.runtime_cli import register_runtime_commands


def test_cli_sign_verify_and_wrong_purpose(tmp_path):
    main = click.Group()
    register_runtime_commands(main)
    runner = CliRunner()
    private, public = tmp_path / "key.pem", tmp_path / "key.pub"
    result = runner.invoke(
        main, ["runtime", "keygen", "--private-key", str(private), "--public-key", str(public)]
    )
    assert result.exit_code == 0, result.output
    now = datetime.now(UTC)
    contract = TrustStatus(
        tenant="acme",
        serial=1,
        not_before=now - timedelta(seconds=1),
        not_after=now + timedelta(minutes=5),
    )
    body, signed = tmp_path / "status.json", tmp_path / "signed.json"
    body.write_text(contract.model_dump_json())
    result = runner.invoke(
        main,
        [
            "runtime",
            "sign",
            str(body),
            "--kind",
            "trust",
            "--key",
            str(private),
            "--out",
            str(signed),
        ],
    )
    assert result.exit_code == 0, result.output
    result = runner.invoke(
        main, ["runtime", "verify", str(signed), "--kind", "trust", "--public-key", str(public)]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["invocation_authorized"] is False
    result = runner.invoke(
        main, ["runtime", "verify", str(signed), "--kind", "snapshot", "--public-key", str(public)]
    )
    assert result.exit_code != 0
    result = runner.invoke(
        main, ["runtime", "keygen", "--private-key", str(private), "--public-key", str(public)]
    )
    assert result.exit_code != 0


def test_keygen_creates_both_key_files_owner_only(tmp_path):
    main = click.Group()
    register_runtime_commands(main)
    private, public = tmp_path / "key.pem", tmp_path / "key.pub"
    previous = os.umask(0)
    try:
        result = CliRunner().invoke(
            main, ["runtime", "keygen", "--private-key", str(private), "--public-key", str(public)]
        )
    finally:
        os.umask(previous)
    assert result.exit_code == 0, result.output
    # Even with a permissive umask, neither file is group- or world-accessible.
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert stat.S_IMODE(public.stat().st_mode) == 0o600


def run(*args):
    main = click.Group()
    register_runtime_commands(main)
    result = CliRunner().invoke(main, ["runtime", *map(str, args)])
    # A refused input ends with a plain error, never a Python traceback.
    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    return result


def keypair(tmp_path, name, *extra):
    private, public = tmp_path / f"{name}.pem", tmp_path / f"{name}.pub"
    result = run("keygen", "--private-key", private, "--public-key", public, *extra)
    assert result.exit_code == 0, result.output
    return private, public


def write(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(value if isinstance(value, str) else value.model_dump_json())
    return path


def current_snapshot(bom, **update):
    now = datetime.now(UTC)
    grant = ToolGrant(
        server_id="server:mail",
        endpoint_identity="https://mail.example.test/mcp",
        tool_name="send",
        definition_digest="sha256:" + "0" * 64,
        actions=("send",),
        resources=("mailbox:team",),
    )
    fields = {
        "agent_id": "agent:triage",
        "deployment_id": "prod",
        "tenant": "acme",
        "workload_identity": "spiffe://acme/triage",
        "policy_digest": "sha256:" + "a" * 64,
        "serial": 1,
        "bom_digest": bom_digest(bom),
        "tools": (grant,),
        "not_before": now - timedelta(seconds=1),
        "not_after": now + timedelta(hours=1),
    }
    return ApprovedSnapshot(**{**fields, **update})


def test_snapshot_verification_requires_its_exact_companion_bom(tmp_path):
    private, public = keypair(tmp_path, "snapshot")
    bom = {"components": [{"name": "send"}]}
    snapshot = current_snapshot(bom)
    signed = tmp_path / "snapshot.dsse.json"
    contract = write(tmp_path, "snapshot.json", snapshot)
    result = run("sign", contract, "--kind", "snapshot", "--key", private, "--out", signed)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["digest"] == contract_digest(snapshot)
    matching = write(tmp_path, "bom.json", json.dumps(bom))
    verified = run(
        "verify", signed, "--kind", "snapshot", "--public-key", public, "--bom", matching
    )
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.stdout)["digest"] == contract_digest(snapshot)
    other = write(tmp_path, "other.json", json.dumps({"components": []}))
    mismatched = run("verify", signed, "--kind", "snapshot", "--public-key", public, "--bom", other)
    assert mismatched.exit_code == 1 and "(bom-mismatch)" in mismatched.output
    missing = run("verify", signed, "--kind", "snapshot", "--public-key", public)
    assert missing.exit_code == 1 and "(bom-required)" in missing.output


def test_threshold_requires_distinct_trusted_signers(tmp_path):
    first, first_pub = keypair(tmp_path, "first")
    second, second_pub = keypair(tmp_path, "second")
    now = datetime.now(UTC)
    status = TrustStatus(
        tenant="acme", serial=1, not_before=now, not_after=now + timedelta(minutes=30)
    )
    contract = write(tmp_path, "status.json", status)
    both, one = tmp_path / "both.json", tmp_path / "one.json"
    assert run("sign", contract, "--kind", "trust", "--key", first, "--key", second, "--out", both)
    assert run("sign", contract, "--kind", "trust", "--key", first, "--out", one)
    ring = ["--public-key", first_pub, "--public-key", second_pub, "--threshold", "2"]
    accepted = run("verify", both, "--kind", "trust", *ring)
    assert accepted.exit_code == 0, accepted.output
    assert len(json.loads(accepted.stdout)["accepted_signers"]) == 2
    refused = run("verify", one, "--kind", "trust", *ring)
    assert refused.exit_code == 1 and "(signers-insufficient)" in refused.output
    too_many = run("verify", both, "--kind", "trust", *ring[:-1], "33")
    assert too_many.exit_code == 2


def test_verify_names_the_expired_window(tmp_path):
    private, public = keypair(tmp_path, "trust")
    then = datetime.now(UTC) - timedelta(hours=3)
    expired = TrustStatus(
        tenant="acme", serial=1, not_before=then, not_after=then + timedelta(hours=1)
    )
    key = serialization.load_pem_private_key(private.read_bytes(), password=None)
    envelope = sign_contract(expired, "trust", (key,))
    signed = write(tmp_path, "expired.dsse.json", json.dumps(envelope.model_dump(by_alias=True)))
    result = run("verify", signed, "--kind", "trust", "--public-key", public)
    assert result.exit_code == 1 and "(trust-expired)" in result.output


@pytest.mark.parametrize(
    ("kind", "lifetime", "reason"),
    [
        ("snapshot", timedelta(hours=25), "snapshot-lifetime-exceeds-policy"),
        ("trust", timedelta(hours=2), "trust-lifetime-exceeds-policy"),
        ("trust", timedelta(minutes=-90), "trust-expired"),
    ],
)
def test_sign_refuses_contracts_that_can_never_verify(tmp_path, kind, lifetime, reason):
    private, _ = keypair(tmp_path, "key")
    now = datetime.now(UTC)
    if lifetime < timedelta(0):
        window = {"not_before": now + lifetime - timedelta(minutes=30), "not_after": now + lifetime}
    else:
        window = {"not_before": now - timedelta(seconds=1), "not_after": now + lifetime}
    if kind == "snapshot":
        contract = current_snapshot({}, **window)
    else:
        contract = TrustStatus(tenant="acme", serial=1, **window)
    out = tmp_path / "signed.json"
    path = write(tmp_path, "contract.json", contract)
    result = run("sign", path, "--kind", kind, "--key", private, "--out", out)
    assert result.exit_code == 1 and f"({reason})" in result.output
    assert not out.exists()


@pytest.mark.parametrize(
    ("change", "label"),
    [
        ("inverted", "contract rule: validity window"),
        ("duplicate", "contract rule: duplicate tool grant"),
        ("endpoint", "tools.endpoint_identity"),
    ],
)
def test_contract_rule_errors_are_labelled_without_values(tmp_path, change, label):
    private, _ = keypair(tmp_path, "key")
    document = json.loads(current_snapshot({}).model_dump_json())
    if change == "inverted":
        document["not_before"], document["not_after"] = (
            document["not_after"],
            document["not_before"],
        )
    elif change == "duplicate":
        document["tools"] = document["tools"] * 2
    else:
        document["tools"][0]["endpoint_identity"] = "https://SECRET-HOST.example.test/"
    path = write(tmp_path, "contract.json", json.dumps(document))
    result = run("sign", path, "--kind", "snapshot", "--key", private, "--out", tmp_path / "o")
    assert result.exit_code == 1 and "runtime-input-error" in result.output
    assert label in result.output and "unsupported field" not in result.output
    assert "SECRET-HOST" not in result.output


def test_deeply_nested_inputs_end_without_a_traceback(tmp_path):
    private, public = keypair(tmp_path, "key")
    nested = write(tmp_path, "nested.json", "[" * 100_000 + "]" * 100_000)
    for args in (
        ("sign", nested, "--kind", "trust", "--key", private, "--out", tmp_path / "o"),
        ("verify", nested, "--kind", "trust", "--public-key", public),
        ("digest", nested, "--kind", "bom"),
    ):
        result = run(*args)
        assert result.exit_code == 1 and "(json-invalid)" in result.output, args
    snapshot_key, snapshot_pub = keypair(tmp_path, "snapshot")
    signed = tmp_path / "snapshot.dsse.json"
    contract = write(tmp_path, "snapshot.json", current_snapshot({}))
    assert run("sign", contract, "--kind", "snapshot", "--key", snapshot_key, "--out", signed)
    result = run(
        "verify", signed, "--kind", "snapshot", "--public-key", snapshot_pub, "--bom", nested
    )
    assert result.exit_code == 1 and "(json-invalid)" in result.output


def test_encrypted_private_keys_need_their_passphrase(tmp_path):
    passphrase = write(tmp_path, "passphrase.txt", "correct horse battery staple\n")
    private, public = keypair(tmp_path, "key", "--passphrase-file", passphrase)
    assert private.read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    now = datetime.now(UTC)
    status = TrustStatus(
        tenant="acme", serial=1, not_before=now, not_after=now + timedelta(minutes=5)
    )
    contract = write(tmp_path, "status.json", status)
    missing = run("sign", contract, "--kind", "trust", "--key", private, "--out", tmp_path / "a")
    assert missing.exit_code == 1 and "encrypted" in missing.output
    assert "runtime-key-error" in missing.output
    wrong = write(tmp_path, "wrong.txt", "not the passphrase\n")
    refused = run(
        "sign",
        contract,
        "--kind",
        "trust",
        "--key",
        private,
        "--out",
        tmp_path / "b",
        "--passphrase-file",
        wrong,
    )
    assert refused.exit_code == 1 and "runtime-key-error" in refused.output
    signed = tmp_path / "c"
    accepted = run(
        "sign",
        contract,
        "--kind",
        "trust",
        "--key",
        private,
        "--out",
        signed,
        "--passphrase-file",
        passphrase,
    )
    assert accepted.exit_code == 0, accepted.output
    assert run("verify", signed, "--kind", "trust", "--public-key", public).exit_code == 0


def test_private_key_readable_by_others_is_refused(tmp_path):
    private, _ = keypair(tmp_path, "key")
    private.chmod(0o640)
    now = datetime.now(UTC)
    status = TrustStatus(
        tenant="acme", serial=1, not_before=now, not_after=now + timedelta(minutes=5)
    )
    contract = write(tmp_path, "status.json", status)
    result = run("sign", contract, "--kind", "trust", "--key", private, "--out", tmp_path / "o")
    assert result.exit_code == 1 and "group or others" in result.output


def test_keygen_failure_is_reported_and_leaves_no_partial_pair(tmp_path):
    public = tmp_path / "key.pub"
    result = run(
        "keygen", "--private-key", tmp_path / "missing" / "key.pem", "--public-key", public
    )
    assert result.exit_code == 1 and "runtime-io-error" in result.output
    assert not public.exists()


def test_digest_and_key_id_commands_match_the_library(tmp_path):
    _, public = keypair(tmp_path, "key")
    bom = {"components": [{"name": "send", "version": 1.0}]}
    snapshot = current_snapshot(
        bom,
        not_before=datetime(2020, 1, 1, tzinfo=UTC),
        not_after=datetime(2020, 1, 1, 1, tzinfo=UTC),
    )
    context = ExecutionContext(
        agent_id="agent:triage",
        deployment_id="prod",
        tenant="acme",
        workload_identity="spiffe://acme/triage",
        policy_digest="sha256:" + "a" * 64,
    )
    call = ToolCall(
        server_id="server:mail",
        tool_name="send",
        action="send",
        resource="mailbox:team",
        arguments={"to": "team@example.test", "n": 1.0},
    )
    tool = {"name": "send", "description": "Send", "inputSchema": {"type": "object"}, "title": "S"}
    cases = [
        ("snapshot", snapshot.model_dump_json(), contract_digest(snapshot)),
        ("context", context.model_dump_json(), contract_digest(context)),
        ("request", call.model_dump_json(), request_digest(call)),
        ("tool", json.dumps(tool), tool_definition_digest(tool)),
        ("bom", json.dumps(bom), bom_digest(bom)),
    ]
    for kind, text, expected in cases:
        result = run("digest", write(tmp_path, f"{kind}.json", text), "--kind", kind)
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout) == {"kind": kind, "digest": expected}
    unsupported = write(tmp_path, "icons.json", json.dumps({**tool, "icons": []}))
    refused = run("digest", unsupported, "--kind", "tool")
    assert refused.exit_code == 1 and "(descriptor-unsupported)" in refused.output
    loaded = serialization.load_pem_public_key(public.read_bytes())
    assert json.loads(run("key-id", public).stdout) == {"key_id": key_id(loaded)}
    private_as_public = run("key-id", tmp_path / "key.pem")
    assert private_as_public.exit_code == 1 and "runtime-key-error" in private_as_public.output
    assert stat.S_IMODE(os.stat(public).st_mode) == 0o600
