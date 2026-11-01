"""Explicit signing and contract verification commands; no implicit admission."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

import click
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from nexus_symbiote.runtime import (
    ActionApproval,
    ApprovedSnapshot,
    Envelope,
    HostedModelAttestation,
    TrustStatus,
    _window,
    digest,
    key_id,
    sign_contract,
    strict_json,
    verify_contract,
)

Purpose = Literal["snapshot", "approval", "trust", "model"]


def _read(path: Path, maximum: int = 24 * 1024 * 1024) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise click.ClickException("input exceeds size limit")
    return raw


def _write_new(path: Path, content: bytes, mode: int = 0o600) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode), "wb") as stream:
        stream.write(content)


@click.group("runtime")
def runtime_group() -> None:
    """Sign and verify purpose-specific contracts for mediated tool integrations."""


@runtime_group.command("keygen")
@click.option("--private-key", type=click.Path(path_type=Path), required=True)
@click.option("--public-key", type=click.Path(path_type=Path), required=True)
def keygen(private_key: Path, public_key: Path) -> None:
    """Create an Ed25519 key pair without overwriting existing files."""
    if private_key.exists() or public_key.exists() or private_key == public_key:
        raise click.ClickException("choose distinct, nonexistent key paths")
    key = Ed25519PrivateKey.generate()
    _write_new(
        private_key,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    _write_new(
        public_key,
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        0o644,
    )
    click.echo(json.dumps({"key_id": key_id(key.public_key())}))


@runtime_group.command("sign")
@click.argument("contract_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--kind", type=click.Choice(["snapshot", "approval", "trust", "model"]), required=True
)
@click.option(
    "--key", "keys", multiple=True, required=True, type=click.Path(exists=True, path_type=Path)
)
@click.option("--out", type=click.Path(path_type=Path), required=True)
def sign(contract_path: Path, kind: str, keys: tuple[Path, ...], out: Path) -> None:
    """Sign an explicit contract; signatures do not establish unmeasured facts."""
    try:
        raw = strict_json(_read(contract_path))
        contract: ApprovedSnapshot | ActionApproval | TrustStatus | HostedModelAttestation
        if kind == "snapshot":
            contract = ApprovedSnapshot.model_validate(raw)
        elif kind == "approval":
            contract = ActionApproval.model_validate(raw)
        elif kind == "trust":
            contract = TrustStatus.model_validate(raw)
        else:
            contract = HostedModelAttestation.model_validate(raw)
        loaded = []
        for path in keys:
            private = serialization.load_pem_private_key(_read(path, 65536), password=None)
            if not isinstance(private, Ed25519PrivateKey):
                raise ValueError("only Ed25519 signing keys are supported")
            loaded.append(private)
        envelope = sign_contract(contract, cast(Purpose, kind), tuple(loaded))
        _write_new(
            out,
            (json.dumps(envelope.model_dump(mode="json", by_alias=True), indent=2) + "\n").encode(),
        )
        click.echo(json.dumps({"out": str(out), "predicate": kind, "signed": True}))
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc


@runtime_group.command("verify")
@click.argument("envelope_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--kind", type=click.Choice(["snapshot", "approval", "trust", "model"]), required=True
)
@click.option(
    "--public-key",
    "keys",
    multiple=True,
    required=True,
    type=click.Path(exists=True, path_type=Path),
)
@click.option("--threshold", type=click.IntRange(min=1), default=1)
@click.option("--bom", type=click.Path(exists=True, path_type=Path))
def verify(
    envelope_path: Path, kind: str, keys: tuple[Path, ...], threshold: int, bom: Path | None
) -> None:
    """Verify purpose, signer, subject and time; invocation uses ReferenceGateway."""
    try:
        ring = {}
        for path in keys:
            public = serialization.load_pem_public_key(_read(path, 65536))
            if not isinstance(public, Ed25519PublicKey):
                raise ValueError("expected Ed25519 public key")
            ring[key_id(public)] = public
        envelope = Envelope.model_validate(strict_json(_read(envelope_path)))
        contract, accepted = verify_contract(
            envelope, cast(Purpose, kind), ring, threshold=threshold
        )
        maximum = (
            timedelta(minutes=5)
            if kind == "approval"
            else timedelta(hours=1 if kind == "trust" else 24)
        )
        _window(contract, datetime.now(UTC), maximum)
        if isinstance(contract, ApprovedSnapshot):
            if bom is None or digest(strict_json(_read(bom))) != contract.bom_digest:
                raise ValueError("snapshot verification requires its exact companion BOM")
        result: dict[str, Any] = {
            "contract_verified": True,
            "kind": kind,
            "accepted_signers": sorted(accepted),
            "invocation_authorized": False,
        }
        click.echo(json.dumps(result, indent=2))
    except (ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc


def register_runtime_commands(main: click.Group) -> None:
    main.add_command(runtime_group)
