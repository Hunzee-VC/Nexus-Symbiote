"""Regression tests for PR 1 security audit remediations (runtime, crypto, policy, confinement)."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import resource
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from nexus_symbiote import attestation
from nexus_symbiote.cli import main
from nexus_symbiote.core.hashing import (
    MAX_JSON_NESTING,
    hash_bytes,
    hash_canonical,
    hash_file,
    hash_tool_definition,
    open_directory_nofollow,
    parse_json_strict,
)
from nexus_symbiote.policy import (
    MAX_POLICY_ENTRY_CHARS,
    MAX_POLICY_LIST_ITEMS,
    PolicyError,
    load_policy,
    parse_yaml_mapping,
    weakened_settings,
)
from nexus_symbiote.runtime import (
    MAX_STRICT_JSON_DEPTH,
    ActionApproval,
    ApprovedSnapshot,
    AuthorizationError,
    ExecutionContext,
    ReferenceGateway,
    ServedTool,
    SignerScope,
    StateStore,
    ToolCall,
    ToolGrant,
    TrustStatus,
    digest,
    key_id,
    sign_contract,
    strict_json,
)
from nexus_symbiote.runtime_validation import (
    WORKER_STARTUP_CPU_SECONDS,
    ValidationBudgetError,
    validate_arguments,
)
from nexus_symbiote.signature_policy import SignaturePolicyError, load_signature_policies
from nexus_symbiote.utils.confined import ConfinedCollection, LimitExceededError
from nexus_symbiote.utils.crypto import (
    DSSE_UNSUPPORTED,
    TRUST_ROOT_ENV,
    TRUST_ROOT_SHA256_ENV,
    _read_explicit_trust_root,
    _read_sigstore_cache,
    verify_sigstore_bundle,
    verify_sigstore_digest,
)
from nexus_symbiote.utils.files import write_output_file
from nexus_symbiote.utils.terminal import json_text

# ---------------------------------------------------------------------------
# NS-AUD-H01 & NS-AUD-I03: Runtime JSON Schema $vocabulary & worker CPU limits
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vocabulary",
    [
        {
            "https://json-schema.org/draft/2020-12/vocab/core": True,
            "https://json-schema.org/draft/2020-12/vocab/applicator": True,
            "https://json-schema.org/draft/2020-12/vocab/validation": True,
            "https://json-schema.org/draft/2020-12/vocab/format-assertion": True,
        },
        {
            "https://json-schema.org/draft/2020-12/vocab/core": True,
            "https://json-schema.org/draft/2020-12/vocab/content": True,
        },
        {
            "https://json-schema.org/draft/2019-09/vocab/core": True,
            "https://json-schema.org/draft/2019-09/vocab/format": True,
        },
        {
            "https://json-schema.org/draft/2020-12/vocab/core": True,
            "https://attacker.example/vocab/custom": True,
        },
    ],
)
def test_schema_requiring_unasserted_vocabulary_fails_closed(
    vocabulary: dict[str, bool],
) -> None:
    dialect = (
        "https://json-schema.org/draft/2019-09/schema"
        if any("2019-09" in uri for uri in vocabulary)
        else "https://json-schema.org/draft/2020-12/schema"
    )
    schema = {
        "$schema": dialect,
        "$vocabulary": vocabulary,
        "type": "object",
        "properties": {"target": {"type": "string", "format": "ipv4"}},
    }
    with pytest.raises(ValidationBudgetError) as caught:
        validate_arguments(schema, {"target": "not-an-ip"})
    assert caught.value.reason == "schema-invalid"


def test_schema_with_supported_or_optional_vocabulary_passes_and_subschema_vocab_fails() -> None:
    valid_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$vocabulary": {
            "https://json-schema.org/draft/2020-12/vocab/core": True,
            "https://json-schema.org/draft/2020-12/vocab/validation": True,
            "https://json-schema.org/draft/2020-12/vocab/format-annotation": True,
            "https://json-schema.org/draft/2020-12/vocab/format-assertion": False,
        },
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    }
    validate_arguments(valid_schema, {"name": "ok"})

    subschema_vocab = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "nested": {
                "$vocabulary": {"https://json-schema.org/draft/2020-12/vocab/core": True},
                "type": "string",
            }
        },
    }
    with pytest.raises(ValidationBudgetError) as caught:
        validate_arguments(subschema_vocab, {"nested": "x"})
    assert caught.value.reason == "schema-invalid"


def test_worker_cpu_hard_limit_is_finite(monkeypatch: pytest.MonkeyPatch) -> None:
    from nexus_symbiote import runtime_validation

    recorded: dict[int, tuple[int, int]] = {}
    monkeypatch.setattr(
        resource,
        "getrlimit",
        lambda kind: (resource.RLIM_INFINITY, resource.RLIM_INFINITY),
    )
    monkeypatch.setattr(
        resource,
        "setrlimit",
        lambda kind, limits_pair: recorded.__setitem__(kind, limits_pair),
    )
    runtime_validation._apply_worker_limits()
    assert recorded[resource.RLIMIT_CPU] == (
        WORKER_STARTUP_CPU_SECONDS,
        WORKER_STARTUP_CPU_SECONDS,
    )


# ---------------------------------------------------------------------------
# NS-AUD-H10 & NS-AUD-L10: Policy YAML anchors/aliases, root exclusion, venv
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw_yaml",
    [
        "a: &anchor [docs]\nexclude_paths: *anchor\n",
        "exclude_paths: &anchor [docs]\n",
        'exclude_paths:\n  - "\\uD800"\n',
    ],
)
def test_policy_yaml_rejects_anchors_aliases_and_escaped_surrogates(raw_yaml: str) -> None:
    with pytest.raises(PolicyError):
        parse_yaml_mapping(raw_yaml)
    with pytest.raises(PolicyError, match="YAML complexity exceeds policy budget"):
        parse_yaml_mapping("a: 1\nb: 2\nc: 3\n", max_nodes=3)


@pytest.mark.parametrize(
    "bad_excludes",
    [
        ["."],
        ["./"],
        ["a/.."],
        [f"dir_{i}" for i in range(MAX_POLICY_LIST_ITEMS + 1)],
        ["a" * (MAX_POLICY_ENTRY_CHARS + 1)],
    ],
)
def test_policy_rejects_root_exclusion_and_unbounded_lists(
    tmp_path: Path, bad_excludes: list[str]
) -> None:
    policy_file = tmp_path / ".nexus-symbiote.yaml"
    policy_file.write_text(json.dumps({"scan": {"exclude_paths": bad_excludes}}), encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(tmp_path)


def test_policy_venv_exclusion_is_not_flagged_as_weakened(tmp_path: Path) -> None:
    policy_file = tmp_path / ".nexus-symbiote.yaml"
    policy_file.write_text("scan:\n  exclude_paths:\n    - venv\n    - .venv\n", encoding="utf-8")
    loaded = load_policy(tmp_path)
    assert loaded is not None
    assert weakened_settings(loaded) == []


# ---------------------------------------------------------------------------
# NS-AUD-M01, NS-AUD-L03, NS-AUD-L04, NS-AUD-L05: Confinement, hashing, JSON
# ---------------------------------------------------------------------------


def test_open_directory_nofollow_uses_o_path_on_execute_only_intermediate_dir(
    tmp_path: Path,
) -> None:
    traverse = tmp_path / "exec_only"
    target = traverse / "workspace"
    target.mkdir(parents=True)
    traverse.chmod(0o711)
    try:
        fd = open_directory_nofollow(target)
        try:
            assert os.fstat(fd).st_ino == target.stat().st_ino
        finally:
            os.close(fd)
    finally:
        traverse.chmod(0o700)


def test_confined_collection_rejects_cross_device_mount_and_two_hop_walk_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "real_target").mkdir()
    (tmp_path / "real_target" / "ok.txt").write_text("ok", encoding="utf-8")
    (tmp_path / "real_target" / "hop2.txt").symlink_to("ok.txt")
    (tmp_path / "hop1").symlink_to("real_target", target_is_directory=True)

    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        walked = [p.as_posix() for p in files.iter_files("hop1")]
    assert walked == ["real_target/ok.txt"]
    assert any("symlink reached through another symlink" in item for item in failures)

    mount_failures: list[str] = []
    with ConfinedCollection(tmp_path, mount_failures) as files:
        files._root_dev = -999
        assert files.read_text("real_target/ok.txt") is None
        assert list(files.iter_files()) == []
    assert mount_failures


def test_confined_has_exact_name_enforces_max_entries(tmp_path: Path) -> None:
    for idx in range(6):
        (tmp_path / f"f{idx}.txt").write_text("x", encoding="utf-8")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=3) as files:
        assert files._root_fd is not None
        with pytest.raises(LimitExceededError):
            # Trailing space triggers full directory scan in _has_exact_name
            files._has_exact_name(files._root_fd, "probe ")


def test_hash_functions_reject_weak_algorithms_and_mid_read_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = tmp_path / "artifact.bin"
    sample.write_bytes(b"payload")
    for weak in ("md5", "sha1"):
        with pytest.raises(ValueError, match="Unsupported security hash algorithm"):
            hash_file(sample, algorithm=weak)
        with pytest.raises(ValueError, match="Unsupported security hash algorithm"):
            hash_bytes(b"payload", algorithm=weak)
        with pytest.raises(ValueError, match="Unsupported security hash algorithm"):
            hash_canonical({"a": 1}, algorithm=weak)

    real_open = open_regular_file_target = sample
    from nexus_symbiote.core import hashing as hashing_mod

    orig_open = hashing_mod.open_regular_file

    def swapping_open(path: Path) -> Any:
        stream = orig_open(path)
        replacement = tmp_path / "swapped.bin"
        replacement.write_bytes(b"tampered")
        os.replace(replacement, real_open)
        return stream

    monkeypatch.setattr(hashing_mod, "open_regular_file", swapping_open)
    with pytest.raises(OSError, match="File changed during hashing"):
        hash_file(open_regular_file_target)


def test_json_depth_guards_reject_deep_nesting_before_recursion() -> None:
    deep = "[" * (MAX_JSON_NESTING + 5) + "0" + "]" * (MAX_JSON_NESTING + 5)
    with pytest.raises(RecursionError, match="depth limit"):
        parse_json_strict(deep)

    deep_runtime = "[" * (MAX_STRICT_JSON_DEPTH + 5) + "0" + "]" * (MAX_STRICT_JSON_DEPTH + 5)
    with pytest.raises(AuthorizationError) as auth_err:
        strict_json(deep_runtime)
    assert auth_err.value.reason == "json-invalid"

    deep_native = "[" * (attestation.MAX_NATIVE_DEPTH + 5) + "]" * (
        attestation.MAX_NATIVE_DEPTH + 5
    )
    assert attestation._native_facts(deep_native.encode("utf-8")) is None


def test_write_output_file_fallback_when_hardlinks_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_hardlink(*_args: object, **_kwargs: object) -> None:
        raise OSError(errno.EOPNOTSUPP, "Operation not supported")

    monkeypatch.setattr(os, "link", no_hardlink)
    out = tmp_path / "report.json"
    write_output_file(out, '{"ok": true}\n', overwrite=False)
    assert out.read_text(encoding="utf-8") == '{"ok": true}\n'
    with pytest.raises(FileExistsError):
        write_output_file(out, '{"ok": false}\n', overwrite=False)
    assert out.read_text(encoding="utf-8") == '{"ok": true}\n'


def test_json_text_escapes_bidi_c1_and_line_separators() -> None:
    payload = chr(0x202E) + chr(0x009B) + chr(0x2028) + chr(0xFE0F) + chr(0xE0020)
    raw = '{"msg":"' + payload + '"}'
    sanitized = json_text(raw)
    for ch in payload:
        assert ch not in sanitized
    assert "\\u202e" in sanitized
    assert "\\u009b" in sanitized
    assert "\\u2028" in sanitized
    assert "\\ufe0f" in sanitized
    assert "\\udb40\\udc20" in sanitized
    assert json.loads(sanitized)["msg"] == payload


# ---------------------------------------------------------------------------
# NS-AUD-M02, NS-AUD-L02, NS-AUD-M14: Real Sigstore verification & trust roots
# ---------------------------------------------------------------------------


def test_real_sigstore_bundle_verification_and_dsse_snake_case_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
    monkeypatch.delenv(TRUST_ROOT_ENV, raising=False)
    monkeypatch.delenv(TRUST_ROOT_SHA256_ENV, raising=False)

    fixtures = Path(__file__).parent / "fixtures" / "sigstore-python"
    subject = fixtures / "rfc8785-0.1.2-py3-none-any.whl.subject"
    bundle = fixtures / "bundle_v3_github.whl.sigstore"
    identity = (
        "https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml@refs/tags/v0.1.2"
    )
    issuer = "https://token.actions.githubusercontent.com"

    verified = verify_sigstore_bundle(subject, bundle, identity, issuer)
    assert verified.verified is True, verified.error

    wrong_signer = verify_sigstore_bundle(
        subject, bundle, "https://attacker.example/workflow", issuer
    )
    assert wrong_signer.verified is False

    tampered = tmp_path / "tampered.whl"
    data = bytearray(subject.read_bytes())
    data[0] ^= 0x01
    tampered.write_bytes(bytes(data))
    assert verify_sigstore_bundle(tampered, bundle, identity, issuer).verified is False

    snake_dsse = verify_sigstore_digest(
        hashlib.sha256(b"x").hexdigest(),
        b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","dsse_envelope":{}}',
        identity,
        issuer,
    )
    assert snake_dsse.verified is False
    assert snake_dsse.error == DSSE_UNSUPPORTED


def test_seeded_sigstore_cache_refreshes_on_embedded_upgrade_without_clobbering_operator_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sigstore._utils as sigstore_utils

    cache = tmp_path / "cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
    monkeypatch.delenv(TRUST_ROOT_ENV, raising=False)
    monkeypatch.delenv(TRUST_ROOT_SHA256_ENV, raising=False)

    monkeypatch.setattr(sigstore_utils, "read_embedded", lambda *_a, **_k: b'{"v": 1}')
    path, content, err = _read_sigstore_cache()
    assert err is None and path is not None and content == b'{"v": 1}'

    monkeypatch.setattr(sigstore_utils, "read_embedded", lambda *_a, **_k: b'{"v": 2}')
    path2, content2, err2 = _read_sigstore_cache()
    assert err2 is None and path2 == path and content2 == b'{"v": 2}'
    assert path.read_bytes() == b'{"v": 2}'

    # Operator-customized root does not match the seeded sidecar and must not be clobbered.
    path.write_bytes(b'{"operator": true}')
    monkeypatch.setattr(sigstore_utils, "read_embedded", lambda *_a, **_k: b'{"v": 3}')
    _, content3, err3 = _read_sigstore_cache()
    assert err3 is None and content3 == b'{"operator": true}'


def test_unpinned_explicit_trust_root_rejects_hardlinks_and_unsafe_ancestors(
    tmp_path: Path,
) -> None:
    priv = tmp_path / "priv"
    priv.mkdir(mode=0o700)
    root = priv / "trusted_root.json"
    root.write_bytes(b"{}")
    root.chmod(0o600)
    hard = tmp_path / "hardlink.json"
    os.link(root, hard)
    _, content, _, error = _read_explicit_trust_root(root, None)
    assert content is None and error is not None and "hard links" in error
    os.unlink(hard)

    shared_anc = tmp_path / "world_writable_no_sticky"
    shared_anc.mkdir()
    shared_anc.chmod(0o777)
    inner = shared_anc / "inner"
    inner.mkdir(mode=0o700)
    nested_root = inner / "trusted_root.json"
    nested_root.write_bytes(b"{}")
    nested_root.chmod(0o600)
    _, content2, _, error2 = _read_explicit_trust_root(nested_root, None)
    assert content2 is None and error2 is not None and "world-writable" in error2


def test_signature_policy_rejects_enclosing_git_tree_and_world_writable_dir(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "monorepo"
    (repo / ".git").mkdir(parents=True)
    project = repo / "services" / "agent"
    project.mkdir(parents=True)
    (project / "model.bin").write_bytes(b"weights")
    sibling_policy = repo / "policies" / "sig-policy.json"
    sibling_policy.parent.mkdir(parents=True)
    digest = "sha256:" + hashlib.sha256(b"weights").hexdigest()
    payload = json.dumps(
        {
            "version": 2,
            "artifacts": [
                {"kind": "digest-pin", "artifact_path": "model.bin", "expected_sha256": digest}
            ],
        }
    )
    sibling_policy.write_text(payload, encoding="utf-8")
    with pytest.raises(SignaturePolicyError, match="outside the scanned project"):
        load_signature_policies(sibling_policy, project)

    world_dir = tmp_path / "world_policy"
    world_dir.mkdir()
    world_dir.chmod(0o777)
    world_policy = world_dir / "sig-policy.json"
    world_policy.write_text(payload, encoding="utf-8")
    with pytest.raises(SignaturePolicyError):
        load_signature_policies(world_policy, project)


def test_verify_attestation_rejects_world_writable_trusted_key(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from nexus_symbiote.attestation import MAX_NATIVE_DEPTH, build_statement

    # Deeply nested JSON (> MAX_NATIVE_DEPTH and > MAX_JSON_NESTING) returns subject_format 'other'
    for depth in (MAX_NATIVE_DEPTH + 2, MAX_JSON_NESTING + 5):
        stmt = build_statement(
            b"[" * depth + b"]" * depth,
            name="deep.json",
            purpose="reviewed",
            signed_at=datetime(2026, 11, 14, 12, 0, tzinfo=UTC),
            source_revision=None,
        )
        assert stmt["predicate"]["subject_format"] == "other"

    runner = CliRunner()
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir(mode=0o700)
    priv = keys_dir / "signer.key"
    pub = keys_dir / "signer.pub"
    assert (
        runner.invoke(
            main, ["runtime", "keygen", "--private-key", str(priv), "--public-key", str(pub)]
        ).exit_code
        == 0
    )
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    subject = work / "item.txt"
    subject.write_text("hello\n", encoding="utf-8")
    env = work / "item.att"
    assert (
        runner.invoke(
            main,
            [
                "attest",
                str(subject),
                "--key",
                str(priv),
                "--purpose",
                "reviewed",
                "--out",
                str(env),
            ],
        ).exit_code
        == 0
    )

    def _verify_with(key_path: Path) -> Any:
        return runner.invoke(
            main,
            [
                "verify-attestation",
                str(subject),
                str(env),
                "--trusted-key",
                str(key_path),
                "--purpose",
                "reviewed",
            ],
        )

    pub.chmod(0o666)
    res = _verify_with(pub)
    assert res.exit_code == 1
    assert "permission, or link checks" in res.output
    pub.chmod(0o600)

    ww_dir = tmp_path / "ww_keys"
    ww_dir.mkdir()
    ww_dir.chmod(0o777)
    ww_pub = ww_dir / "signer.pub"
    ww_pub.write_bytes(pub.read_bytes())
    ww_pub.chmod(0o600)
    res_dir = _verify_with(ww_pub)
    assert res_dir.exit_code == 1
    assert "world-writable" in res_dir.output

    oversized_pub = keys_dir / "oversized.pub"
    oversized_pub.write_bytes(b"A" * 70_000)
    oversized_pub.chmod(0o600)
    assert _verify_with(oversized_pub).exit_code == 1

    bad_pub = keys_dir / "bad.pub"
    bad_pub.write_bytes(b"not a pem key")
    bad_pub.chmod(0o600)
    assert _verify_with(bad_pub).exit_code == 1

    ec_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    ec_pub = keys_dir / "ec.pub"
    ec_pub.write_bytes(
        ec_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    ec_pub.chmod(0o600)
    res_ec = _verify_with(ec_pub)
    assert res_ec.exit_code == 1
    assert "Ed25519" in res_ec.output


# ---------------------------------------------------------------------------
# NS-AUD-M02: Runtime SignerScope window, approval_actors, StateStore binding
# ---------------------------------------------------------------------------


def _runtime_fixture(tmp_path: Path) -> tuple[Any, ...]:
    now = datetime(2026, 11, 1, tzinfo=UTC)
    release = Ed25519PrivateKey.generate()
    human = Ed25519PrivateKey.generate()
    trust_key = Ed25519PrivateKey.generate()
    definition = {
        "name": "send",
        "description": "Send a message",
        "inputSchema": {"type": "object"},
    }
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
        arguments={"to": "team@example.test"},
    )
    bom = {"agent": "triage", "tools": ["send"]}
    grant = ToolGrant(
        server_id="server:mail",
        endpoint_identity="https://mail.example.test/mcp",
        tool_name="send",
        definition_digest=hash_tool_definition(
            "send", definition["description"], definition["inputSchema"]
        ),
        actions=("send",),
        resources=("mailbox:team",),
    )
    snapshot = ApprovedSnapshot(
        **context.model_dump(),
        serial=1,
        bom_digest=digest(bom),
        tools=(grant,),
        not_before=now - timedelta(seconds=1),
        not_after=now + timedelta(hours=1),
    )
    statuses = TrustStatus(
        tenant="acme",
        serial=1,
        not_before=now - timedelta(seconds=1),
        not_after=now + timedelta(minutes=30),
    )
    approval = ActionApproval(
        snapshot_digest=digest(snapshot.model_dump(mode="json")),
        context_digest=digest(context.model_dump(mode="json")),
        request_digest=digest(call.model_dump(mode="json")),
        nonce="c3f1b0a7d9e24f6b8a1c5d7e9f0b2a4c",
        actor="approver",
        not_before=now - timedelta(seconds=1),
        not_after=now + timedelta(minutes=1),
    )
    executed: list[ToolCall] = []
    base_kwargs: dict[str, Any] = {
        "snapshot_keys": {key_id(release.public_key()): release.public_key()},
        "approval_keys": {key_id(human.public_key()): human.public_key()},
        "trust_keys": {key_id(trust_key.public_key()): trust_key.public_key()},
        "state": StateStore.initialize(tmp_path / "state.sqlite"),
        "authenticate": lambda: context,
        "describe": lambda *_: ServedTool(
            endpoint_identity=grant.endpoint_identity, definition=definition
        ),
        "execute": lambda c: executed.append(c) or "executed",
        "approval_actors": {key_id(human.public_key()): "approver"},
        "clock": lambda: now,
        "resolve_scope": lambda _c: ("send", "mailbox:team"),
    }
    return (
        now,
        base_kwargs,
        call,
        bom,
        snapshot,
        statuses,
        approval,
        release,
        human,
        trust_key,
        executed,
    )


def test_signer_scope_window_and_final_time_expiry_and_empty_approval_actors(
    tmp_path: Path,
) -> None:
    t0 = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
    with pytest.raises(ValidationError):
        SignerScope(not_before=t0, not_after=t0)
    with pytest.raises(ValidationError):
        SignerScope(not_before=t0 + timedelta(seconds=10), not_after=t0)

    (
        now,
        base_kwargs,
        call,
        bom,
        snapshot,
        statuses,
        approval,
        release,
        human,
        trust_key,
        executed,
    ) = _runtime_fixture(tmp_path)
    with pytest.raises(AuthorizationError) as actor_err:
        ReferenceGateway(**{**base_kwargs, "approval_actors": {}})
    assert actor_err.value.reason == "configuration-invalid"

    # Clock advances past SignerScope.not_after before StateStore.record check_time runs
    ticks = iter([now, now + timedelta(minutes=2)])
    scoped_gateway = ReferenceGateway(
        **{
            **base_kwargs,
            "clock": lambda: next(ticks, now + timedelta(minutes=2)),
            "signer_scopes": {
                key_id(release.public_key()): SignerScope(
                    tenants=frozenset({"acme"}),
                    not_before=now - timedelta(minutes=1),
                    not_after=now + timedelta(seconds=30),
                )
            },
        }
    )
    with pytest.raises(AuthorizationError) as expired_scope:
        scoped_gateway.invoke(
            call,
            bom=bom,
            snapshot=sign_contract(snapshot, "snapshot", (release,)),
            trust=sign_contract(statuses, "trust", (trust_key,)),
            approval=sign_contract(approval, "approval", (human,)),
        )
    assert expired_scope.value.reason == "signers-out-of-scope"
    assert executed == []


def test_statestore_refuses_symlinked_or_world_writable_parent_and_runtime_symlink_swap(
    tmp_path: Path,
) -> None:
    real_dir = tmp_path / "real_state"
    real_dir.mkdir(mode=0o700)
    linked_dir = tmp_path / "linked_state"
    linked_dir.symlink_to(real_dir, target_is_directory=True)
    with pytest.raises(AuthorizationError) as sym_init:
        StateStore.initialize(linked_dir / "state.sqlite")
    assert sym_init.value.reason == "state-invalid"

    world_dir = tmp_path / "world_state"
    world_dir.mkdir()
    world_dir.chmod(0o777)
    with pytest.raises(AuthorizationError) as world_init:
        StateStore.initialize(world_dir / "state.sqlite")
    assert world_init.value.reason == "state-invalid"

    db_path = real_dir / "state.sqlite"
    store = StateStore.initialize(db_path)
    other_db = real_dir / "other.sqlite"
    shutil.copyfile(db_path, other_db)
    db_path.unlink()
    db_path.symlink_to(other_db)
    with pytest.raises(AuthorizationError) as swapped:
        store.record(())
    assert swapped.value.reason == "state-invalid"
