"""Incident evidence queries using local artifacts and operator-pinned public keys."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from cryptography.exceptions import InvalidSignature

from symbiote.attest import Envelope, KeyRing, load_private_key, load_public_key, sign_envelope
from symbiote.cli import exit_codes
from symbiote.digest import canonical_bytes, parse_json_strict
from symbiote.incident import REPORT_TYPE, incident_query

incident_app = typer.Typer(help="Query signed incident evidence offline.")


def _ring(path: Path) -> KeyRing:
    return KeyRing.from_public_keys([load_public_key(path)])


def _envelope(path: Path) -> Envelope:
    return Envelope.model_validate(parse_json_strict(path.read_bytes()))


@incident_app.command("query")
def query(
    tenant: Annotated[str, typer.Option("--tenant")],
    since: Annotated[str, typer.Option("--from", help="Inclusive ISO 8601 timestamp with timezone.")],
    until: Annotated[str, typer.Option("--until", help="Exclusive ISO 8601 timestamp with timezone.")],
    companion: Annotated[list[Path], typer.Option("--companion", help="Repeat once per snapshot.")],
    envelope: Annotated[list[Path], typer.Option("--envelope", help="Match --companion order.")],
    deployment_key: Annotated[Path, typer.Option("--deployment-key")],
    descriptor: Annotated[str | None, typer.Option("--descriptor")] = None,
    publisher: Annotated[str | None, typer.Option("--publisher")] = None,
    issuer: Annotated[str | None, typer.Option("--issuer")] = None,
    artifact: Annotated[str | None, typer.Option("--artifact")] = None,
    provenance_key: Annotated[Path | None, typer.Option("--provenance-key")] = None,
    policy_key: Annotated[Path | None, typer.Option("--policy-key")] = None,
    observer_key: Annotated[Path | None, typer.Option("--observer-key")] = None,
    observation: Annotated[list[Path] | None, typer.Option("--observation")] = None,
    revocation: Annotated[
        Path | None, typer.Option("--revocation", help="Signed trust-status for this descriptor.")
    ] = None,
    trust_key: Annotated[Path | None, typer.Option("--trust-key")] = None,
    report_key: Annotated[
        Path | None, typer.Option("--report-key", help="Emit a DSSE-signed report.")
    ] = None,
    deployment: Annotated[str | None, typer.Option("--deployment", help="Exact deployment ID.")] = None,
) -> None:
    """Join deployed descriptors to independently evidenced effective grants and execution events."""
    try:
        pairs = [(c.read_bytes(), _envelope(e)) for c, e in zip(companion, envelope, strict=True)]
        report = incident_query(
            pairs,
            tenant=tenant,
            descriptor_digest=descriptor,
            publisher=publisher,
            issuer=issuer,
            artifact_digest=artifact,
            provenance_keys=_ring(provenance_key) if provenance_key else None,
            start=datetime.fromisoformat(since),
            end=datetime.fromisoformat(until),
            deployment=deployment,
            deployment_keys=_ring(deployment_key),
            policy_keys=_ring(policy_key) if policy_key else None,
            observer_keys=_ring(observer_key) if observer_key else None,
            revocation=_envelope(revocation) if revocation else None,
            trust_keys=_ring(trust_key) if trust_key else None,
            observations=[_envelope(p) for p in observation or []],
        )
        if report_key:
            signed = sign_envelope(canonical_bytes(report), REPORT_TYPE, load_private_key(report_key))
            typer.echo(signed.model_dump_json(by_alias=True))
            return
    except InvalidSignature:
        typer.echo("Untrusted incident evidence signature", err=True)
        raise typer.Exit(exit_codes.VERIFICATION) from None
    except (ValueError, OSError, LookupError) as exc:
        typer.echo(f"Invalid incident evidence: {exc}", err=True)
        raise typer.Exit(exit_codes.VERIFICATION) from None
    typer.echo(json.dumps(report, indent=2, sort_keys=True))
