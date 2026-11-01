"""Offline gateway policy issuance, approval and decision exercises."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer

from symbiote.attest.dsse import Envelope, KeyRing, load_private_key, load_public_key
from symbiote.cli import exit_codes
from symbiote.digest.jcs import parse_json_strict
from symbiote.enforce.admission import (
    Binding,
    CallIntent,
    admit_call,
    approve_call,
    sign_gateway_bundle,
    verify_receipt,
)
from symbiote.export.companion import load_companion

app = typer.Typer(help="Issue signed deployment policies and evaluate exact-resource call intents offline.")


def _json(path: Path) -> Any:
    return parse_json_strict(path.read_bytes())


@app.command("sign")
def sign(companion: Path, binding: Path, key: Annotated[Path, typer.Option("--key")]) -> None:
    """Sign a gateway bundle for the actor and verified deployment described by the binding."""
    signed = sign_gateway_bundle(
        load_companion(companion), Binding.model_validate(_json(binding)), load_private_key(key)
    )
    typer.echo(signed.model_dump_json(by_alias=True))


@app.command("approve")
def approve(
    bundle: Path,
    intent: Path,
    key: Annotated[Path, typer.Option("--key")],
    expires: Annotated[str, typer.Option("--expires", help="Timezone-aware ISO 8601 expiration.")],
) -> None:
    """The approval authority signs the reviewed bundle and exact one-use invocation intent."""
    signed = approve_call(
        Envelope.model_validate(_json(bundle)),
        CallIntent.model_validate(_json(intent)),
        load_private_key(key),
        now=datetime.now(UTC),
        expires=datetime.fromisoformat(expires),
    )
    typer.echo(signed.model_dump_json(by_alias=True))


@app.command("decide")
def decide(
    bundle: Path,
    intent: Path,
    descriptor: Path,
    policy_key: Annotated[Path, typer.Option("--policy-key")],
    receipt_key: Annotated[Path, typer.Option("--receipt-key")],
    state: Annotated[Path, typer.Option("--state")],
    approval: Annotated[Path | None, typer.Option("--approval")] = None,
    approval_key: Annotated[Path | None, typer.Option("--approval-key")] = None,
) -> None:
    """Evaluate a trusted adapter's request; print the signed decision and return nonzero on denial."""
    signing = load_private_key(receipt_key)
    signed = admit_call(
        Envelope.model_validate(_json(bundle)),
        CallIntent.model_validate(_json(intent)),
        _json(descriptor),
        bundle_keys=KeyRing.from_public_keys([load_public_key(policy_key)]),
        receipt_key=signing,
        state_db=state,
        approval=Envelope.model_validate(_json(approval)) if approval else None,
        approval_keys=KeyRing.from_public_keys([load_public_key(approval_key)]) if approval_key else None,
    )
    typer.echo(signed.model_dump_json(by_alias=True))
    if verify_receipt(signed, KeyRing.from_public_keys([signing.public_key()])).decision != "allow":
        raise typer.Exit(exit_codes.FINDINGS)


@app.command("verify-receipt")
def check_receipt(receipt: Path, key: Annotated[Path, typer.Option("--key")]) -> None:
    """Verify a persisted audit receipt against the gateway's trusted public key."""
    result = verify_receipt(
        Envelope.model_validate(_json(receipt)), KeyRing.from_public_keys([load_public_key(key)])
    )
    typer.echo(result.model_dump_json(by_alias=True))
