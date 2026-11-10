"""Explicit signing and contract verification commands; no implicit admission."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import click
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError

from nexus_symbiote.core.hashing import open_regular_file
from nexus_symbiote.runtime import (
    CONTRACTS,
    MAX_LIFETIMES,
    REASONS,
    ApprovedSnapshot,
    AuthorizationError,
    Envelope,
    ExecutionContext,
    Kind,
    ToolCall,
    _window,
    bom_digest,
    contract_digest,
    key_id,
    request_digest,
    sign_contract,
    strict_json,
    tool_definition_digest,
    validation_fields,
    verify_contract,
)

MAX_KEY_BYTES = 65536
_CONTRACT_KINDS = ["snapshot", "approval", "trust", "model"]
_DIGEST_KINDS = [*_CONTRACT_KINDS, "context", "request", "tool", "bom"]


class _KeyFileError(Exception):
    """A key or passphrase file was refused; the message is fixed text, never file content."""


_HANDLED = (ValueError, TypeError, RecursionError, OSError, UnsupportedAlgorithm, _KeyFileError)


def _safe_error(exc: BaseException, operation: str) -> str:
    """Describe an operator error without echoing contract values or extra keys."""
    if isinstance(exc, ValidationError):
        fields = validation_fields(exc)
        return f"runtime input validation failed; review fields: {fields} (runtime-input-error)"
    if isinstance(exc, AuthorizationError):
        description = REASONS.get(exc.reason, REASONS["denied"])
        return f"runtime {operation} failed: {description} ({exc.reason})"
    if isinstance(exc, _KeyFileError):
        return f"runtime {operation} failed: {exc} (runtime-key-error)"
    if isinstance(exc, OSError):
        return f"runtime {operation} files could not be accessed safely (runtime-io-error)"
    if isinstance(exc, RecursionError):
        return f"runtime {operation} input is nested too deeply (runtime-input-error)"
    return (
        f"runtime {operation} failed; review the selected contract, Ed25519 keys, "
        "signer policy and validity (runtime-contract-error)"
    )


def _read(path: Path, maximum: int = 24 * 1024 * 1024) -> bytes:
    with open_regular_file(path) as stream:
        if os.fstat(stream.fileno()).st_size > maximum:
            raise click.ClickException("input exceeds size limit")
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise click.ClickException("input exceeds size limit")
    return raw


def _write_new(path: Path, content: bytes, mode: int = 0o600) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode), "wb") as stream:
        stream.write(content)


def _passphrase(path: Path | None) -> bytes | None:
    if path is None:
        return None
    lines = _read(path, 4096).splitlines()
    if not lines or not lines[0]:
        raise _KeyFileError("passphrase file is empty")
    return lines[0]


def _load_private(path: Path, passphrase: bytes | None) -> Ed25519PrivateKey:
    with open_regular_file(path) as stream:
        info = os.fstat(stream.fileno())
        if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
            raise _KeyFileError("private key file must not be accessible to group or others")
        if info.st_size > MAX_KEY_BYTES:
            raise click.ClickException("input exceeds size limit")
        pem = stream.read(MAX_KEY_BYTES + 1)
    if len(pem) > MAX_KEY_BYTES:
        raise click.ClickException("input exceeds size limit")
    encrypted = pem.lstrip().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    if encrypted and passphrase is None:
        raise _KeyFileError("private key is encrypted; pass --passphrase-file")
    try:
        private = serialization.load_pem_private_key(
            pem, password=passphrase if encrypted else None
        )
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise _KeyFileError(
            "private key could not be loaded; check the file and passphrase"
        ) from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise _KeyFileError("only Ed25519 signing keys are supported")
    return private


def _load_public(path: Path) -> Ed25519PublicKey:
    try:
        public = serialization.load_pem_public_key(_read(path, MAX_KEY_BYTES))
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise _KeyFileError("public key could not be loaded") from exc
    if not isinstance(public, Ed25519PublicKey):
        raise _KeyFileError("only Ed25519 public keys are supported")
    return public


@click.group("runtime")
def runtime_group() -> None:
    """Sign and verify purpose-specific contracts for mediated tool integrations."""


@runtime_group.command("keygen")
@click.option(
    "--private-key",
    type=click.Path(path_type=Path),
    required=True,
    help="New PEM private key file, created with mode 0600; must not exist.",
)
@click.option(
    "--public-key",
    type=click.Path(path_type=Path),
    required=True,
    help="New PEM public key file, created with mode 0600; must not exist.",
)
@click.option(
    "--passphrase-file",
    type=click.Path(path_type=Path),
    help="Encrypt the private key with the passphrase on the first line of this file.",
)
def keygen(private_key: Path, public_key: Path, passphrase_file: Path | None) -> None:
    """Create an Ed25519 key pair without overwriting existing files.

    Use one key pair per purpose: snapshot, approval and trust rings must not share keys.
    """
    if private_key.exists() or public_key.exists() or private_key == public_key:
        raise click.ClickException("choose distinct, nonexistent key paths")
    try:
        passphrase = _passphrase(passphrase_file)
        key = Ed25519PrivateKey.generate()
        encryption: serialization.KeySerializationEncryption = (
            serialization.NoEncryption()
            if passphrase is None
            else serialization.BestAvailableEncryption(passphrase)
        )
        _write_new(
            public_key,
            key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
        )
        try:
            _write_new(
                private_key,
                key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
                ),
            )
        except OSError:
            public_key.unlink(missing_ok=True)
            raise
        result = {"key_id": key_id(key.public_key()), "encrypted": passphrase is not None}
        click.echo(json.dumps(result))
    except _HANDLED as exc:
        raise click.ClickException(_safe_error(exc, "key generation")) from None


@runtime_group.command("sign")
@click.argument("contract_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--kind",
    type=click.Choice(_CONTRACT_KINDS),
    required=True,
    help="Contract purpose; a signature is valid only for this purpose.",
)
@click.option(
    "--key",
    "keys",
    multiple=True,
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Ed25519 private key PEM with mode 0600; repeat for multiple signers.",
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    required=True,
    help="Signed envelope file to create; must not exist.",
)
@click.option(
    "--passphrase-file",
    type=click.Path(path_type=Path),
    help="Passphrase for encrypted private keys, on the first line of this file.",
)
def sign(
    contract_path: Path,
    kind: str,
    keys: tuple[Path, ...],
    out: Path,
    passphrase_file: Path | None,
) -> None:
    """Sign an explicit contract; signatures do not establish unmeasured facts.

    A contract that could never verify, because its validity window is longer than
    its purpose allows or has already ended, is refused. Prints the contract digest
    that approvals and revocation lists use.
    """
    purpose = cast(Kind, kind)
    try:
        contract = CONTRACTS[purpose].model_validate(strict_json(_read(contract_path)))
        if contract.not_after - contract.not_before > MAX_LIFETIMES[purpose]:
            raise AuthorizationError(
                "contract validity exceeds its purpose's maximum lifetime",
                reason=f"{purpose}-lifetime-exceeds-policy",
            )
        if contract.not_after <= datetime.now(UTC):
            raise AuthorizationError("contract has expired", reason=f"{purpose}-expired")
        passphrase = _passphrase(passphrase_file)
        loaded = tuple(_load_private(path, passphrase) for path in keys)
        envelope = sign_contract(contract, purpose, loaded)
        _write_new(
            out,
            (json.dumps(envelope.model_dump(mode="json", by_alias=True), indent=2) + "\n").encode(),
        )
        result = {
            "out": str(out),
            "predicate": kind,
            "digest": contract_digest(contract),
            "signers": sorted({key_id(private.public_key()) for private in loaded}),
            "signed": True,
        }
        click.echo(json.dumps(result))
    except _HANDLED as exc:
        raise click.ClickException(_safe_error(exc, "signing")) from None


@runtime_group.command("verify")
@click.argument("envelope_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--kind",
    type=click.Choice(_CONTRACT_KINDS),
    required=True,
    help="Expected contract purpose; a contract signed for another purpose is rejected.",
)
@click.option(
    "--public-key",
    "keys",
    multiple=True,
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Trusted Ed25519 public key PEM; repeat to build the trusted key ring.",
)
@click.option(
    "--threshold",
    type=click.IntRange(min=1, max=32),
    default=1,
    help="Minimum number of distinct trusted signatures (default: 1).",
)
@click.option(
    "--bom",
    type=click.Path(exists=True, path_type=Path),
    help="The exact companion BOM; required for snapshot contracts.",
)
def verify(
    envelope_path: Path, kind: str, keys: tuple[Path, ...], threshold: int, bom: Path | None
) -> None:
    """Verify purpose, signer, subject and time; invocation uses ReferenceGateway.

    Revocation, signer scopes, approver identities and an approval's bindings are
    checked only by the gateway.
    """
    purpose = cast(Kind, kind)
    try:
        ring = {}
        for path in keys:
            public = _load_public(path)
            ring[key_id(public)] = public
        envelope = Envelope.model_validate(strict_json(_read(envelope_path)))
        contract, accepted = verify_contract(envelope, purpose, ring, threshold=threshold)
        _window(contract, datetime.now(UTC), MAX_LIFETIMES[purpose], purpose)
        if isinstance(contract, ApprovedSnapshot):
            if bom is None:
                raise AuthorizationError(
                    "snapshot verification requires its exact companion BOM",
                    reason="bom-required",
                )
            document = strict_json(_read(bom))
            if not isinstance(document, dict) or bom_digest(document) != contract.bom_digest:
                raise AuthorizationError(
                    "companion BOM does not match approved digest", reason="bom-mismatch"
                )
        result: dict[str, Any] = {
            "contract_verified": True,
            "kind": kind,
            "digest": contract_digest(contract),
            "accepted_signers": sorted(accepted),
            "invocation_authorized": False,
        }
        click.echo(json.dumps(result, indent=2))
    except _HANDLED as exc:
        raise click.ClickException(_safe_error(exc, "verification")) from None


@runtime_group.command("digest")
@click.argument("input_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--kind",
    type=click.Choice(_DIGEST_KINDS),
    required=True,
    help="What the file holds: an unsigned contract, an execution context, a tool call, "
    "a served tool descriptor or a companion BOM.",
)
def digest_command(input_path: Path, kind: str) -> None:
    """Print the canonical digest that contracts, approvals and revocations bind.

    It verifies nothing and works for contracts that are not yet valid or expired.
    """
    try:
        document = strict_json(_read(input_path))
        if kind in CONTRACTS:
            value = contract_digest(CONTRACTS[kind].model_validate(document))
        elif kind == "context":
            value = contract_digest(ExecutionContext.model_validate(document))
        elif kind == "request":
            value = request_digest(ToolCall.model_validate(document))
        elif not isinstance(document, dict):
            raise AuthorizationError("input must be a JSON object", reason="json-invalid")
        elif kind == "tool":
            value = tool_definition_digest(document)
        else:
            value = bom_digest(document)
        click.echo(json.dumps({"kind": kind, "digest": value}))
    except _HANDLED as exc:
        raise click.ClickException(_safe_error(exc, "digest")) from None


@runtime_group.command("key-id")
@click.argument("public_key", type=click.Path(exists=True, path_type=Path))
def key_id_command(public_key: Path) -> None:
    """Print the key ID that envelopes, key rings and revocation lists use."""
    try:
        click.echo(json.dumps({"key_id": key_id(_load_public(public_key))}))
    except _HANDLED as exc:
        raise click.ClickException(_safe_error(exc, "key ID")) from None


def register_runtime_commands(main: click.Group) -> None:
    main.add_command(runtime_group)
