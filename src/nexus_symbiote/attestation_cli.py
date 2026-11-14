"""Commands that attest the exact bytes of a file and verify those attestations.

Signing is an explicit operator step with keys the operator holds; no command signs a
scan result on its own. Verification takes operator-supplied public keys and refuses one
kept where the change under review could have written it: inside a git working tree that
holds the subject, the envelope or the current directory. That catches misplacement; it
does not authenticate a key.
"""

from __future__ import annotations

import functools
import json
import os
import re
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypeVar, cast

import click

from nexus_symbiote.runtime_cli import (
    _InputTooLargeError,
    _KeyFileError,
    _load_private,
    _load_public,
    _passphrase,
    _read,
)
from nexus_symbiote.supply_chain_cli import _refuse_source_overwrite
from nexus_symbiote.utils.terminal import echo_line, json_text, write_cli_output

MAX_SUBJECT_BYTES = 64 * 1024 * 1024
MAX_AGE_DAYS = 36500
_PURPOSES = ["generated", "reviewed"]
_REVISION = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_MISPLACED = (
    "a --trusted-key file must lie outside every git working tree that holds SUBJECT, "
    "ENVELOPE or the current directory; this catches misplacement, it does not "
    "authenticate the key"
)
_LINKED = (
    "a --trusted-key file must not have other hard links: another name for it could lie "
    "inside such a working tree"
)
T = TypeVar("T")


def _failure(operation: str, reason: str, detail: str) -> click.ClickException:
    return click.ClickException(f"attestation {operation} failed: {detail} ({reason})")


def _load(operation: str, role: str, load: Callable[[], T]) -> T:
    """Run one bounded, no-follow file read; a refusal names the file's role, never content."""
    try:
        return load()
    except _KeyFileError as exc:
        raise _failure(operation, "key-invalid", str(exc)) from None
    except _InputTooLargeError:
        raise _failure(operation, "input-too-large", f"the {role} exceeds its size limit") from None
    except OSError:
        raise _failure(
            operation,
            "input-unreadable",
            f"the {role} is not a readable regular file reached without symbolic links",
        ) from None


def _revision(_ctx: click.Context, _param: click.Parameter, value: str | None) -> str | None:
    if value is not None and not _REVISION.fullmatch(value):
        raise click.BadParameter("use a git commit ID of 40 or 64 lowercase hexadecimal characters")
    return value


def _working_trees(directories: Iterable[Path]) -> list[Path]:
    """Every directory at or above these that holds a ``.git`` entry, nested ones included."""
    found: list[Path] = []
    for directory in directories:
        for candidate in (directory, *directory.parents):
            if candidate not in found and os.path.lexists(candidate / ".git"):
                found.append(candidate)
    return found


def _identity(path: Path) -> tuple[int, int]:
    info = os.stat(path)
    return info.st_dev, info.st_ino


def _check_trust_anchors(keys: tuple[Path, ...], inputs: tuple[Path, ...]) -> None:
    """Refuse a trusted key that a change to a working tree around the inputs could supply."""
    try:
        trees = _working_trees([*(path.resolve().parent for path in inputs), Path.cwd().resolve()])
        untrusted = {_identity(tree) for tree in trees}
        for key in keys:
            resolved = key.resolve()
            # Device and inode also find the tree directory itself under a name the path
            # text misses, such as a case variant or a bind mount of the tree. A mount of
            # a directory or file inside a tree gives the key another location: not found.
            ancestors = {_identity(parent) for parent in resolved.parents}
            if any(resolved.is_relative_to(tree) for tree in trees) or ancestors & untrusted:
                raise click.UsageError(_MISPLACED)
            if os.stat(resolved).st_nlink != 1:
                raise click.UsageError(_LINKED)
    except (OSError, RuntimeError):
        raise click.UsageError("the location of a --trusted-key file cannot be inspected") from None


@click.command("attest")
@click.argument("subject", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--key",
    "keys",
    multiple=True,
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Ed25519 private key PEM that you own and only you can read; repeat for each signer.",
)
@click.option(
    "--purpose",
    type=click.Choice(_PURPOSES),
    required=True,
    help="generated: you produced SUBJECT; reviewed: you reviewed SUBJECT as a baseline.",
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    required=True,
    help="Envelope file to create with mode 0600; must not exist.",
)
@click.option(
    "--passphrase-file",
    type=click.Path(path_type=Path),
    help="Passphrase for encrypted private keys, on the first line of this file, "
    "which you own and only you may read.",
)
@click.option(
    "--source-revision",
    callback=_revision,
    help="Git commit ID SUBJECT was produced from, 40 or 64 lowercase hexadecimal "
    "characters; recorded as your claim and never checked.",
)
def attest(
    subject: Path,
    keys: tuple[Path, ...],
    purpose: str,
    out: Path,
    passphrase_file: Path | None,
    source_revision: str | None,
) -> None:
    """Sign the exact bytes of SUBJECT for one purpose; an explicit operator step.

    The attestation binds the SHA-256 of SUBJECT and, for a native inventory this build
    reads, its content digest. It records who signed and why, not that the file is
    accurate, complete or safe.
    """
    from nexus_symbiote.attestation import (
        AttestationError,
        Purpose,
        build_statement,
        sign_statement,
    )
    from nexus_symbiote.runtime import key_id

    _refuse_source_overwrite(out, subject)
    passphrase = _load(
        "signing", "passphrase file", functools.partial(_passphrase, passphrase_file)
    )
    signers = [
        _load("signing", "signing key file", functools.partial(_load_private, path, passphrase))
        for path in keys
    ]
    names = [key_id(signer.public_key()) for signer in signers]
    if len(set(names)) != len(names):
        raise click.BadParameter("each --key must be a different signing key", param_hint="'--key'")
    data = _load("signing", "subject file", functools.partial(_read, subject, MAX_SUBJECT_BYTES))
    try:
        statement = build_statement(
            data,
            name=subject.name,
            purpose=cast(Purpose, purpose),
            signed_at=datetime.now(UTC).replace(microsecond=0),
            source_revision=source_revision,
        )
        envelope = sign_statement(statement, signers)
    except AttestationError as exc:
        raise _failure("signing", exc.reason, str(exc)) from None
    text = json.dumps(envelope.model_dump(mode="json", by_alias=True), indent=2) + "\n"
    write_cli_output(out, text, overwrite=False)
    predicate = statement["predicate"]
    result = {
        "out": str(out),
        "subject_sha256": statement["subject"][0]["digest"]["sha256"],
        "subject_format": predicate["subject_format"],
        **(
            {"content_digest": predicate["content_digest"]} if "content_digest" in predicate else {}
        ),
        "purpose": purpose,
        "signers": sorted(names),
        "signed": True,
    }
    click.echo(json_text(json.dumps(result)))


@click.command("verify-attestation")
@click.argument("subject", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("envelope", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--trusted-key",
    "trusted_keys",
    multiple=True,
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Trusted Ed25519 public key PEM; repeat to build the ring. It must lie outside every "
    "git working tree that holds SUBJECT, ENVELOPE or the current directory, which catches "
    "misplacement but does not authenticate the key.",
)
@click.option(
    "--purpose",
    type=click.Choice(_PURPOSES),
    required=True,
    help="Purpose the attestation must have been signed for. Any trusted key can sign either "
    "purpose, so trust only keys that may sign for this one.",
)
@click.option(
    "--threshold",
    type=click.IntRange(min=1, max=32),
    default=1,
    help="Minimum number of distinct trusted keys that must have signed, at most the "
    "number of distinct trusted keys (default: 1).",
)
@click.option(
    "--match",
    "match",
    type=click.Choice(["bytes", "content"]),
    default="bytes",
    help="bytes (default): SUBJECT is the attested file. content: SUBJECT is a native "
    "inventory with the attested content digest, such as a later collection of the "
    "same content.",
)
@click.option(
    "--max-age-days",
    type=click.IntRange(min=1, max=MAX_AGE_DAYS),
    help="Refuse an attestation signed more than this many days ago.",
)
@click.option("--json-output", is_flag=True, help="Print the verified facts as JSON.")
def verify_attestation(
    subject: Path,
    envelope: Path,
    trusted_keys: tuple[Path, ...],
    purpose: str,
    threshold: int,
    match: str,
    max_age_days: int | None,
    json_output: bool,
) -> None:
    """Verify that trusted keys attested SUBJECT for a purpose; exit 1 when they did not.

    A verified attestation establishes who signed which bytes or content for which
    purpose and when, by the signer's clock. It does not establish that SUBJECT is
    accurate, complete or safe, or that it is the newest file the signers attested.
    """
    from nexus_symbiote import attestation
    from nexus_symbiote.runtime import key_id

    _check_trust_anchors(trusted_keys, (subject, envelope))
    ring = {}
    for path in trusted_keys:
        public = _load("verification", "trusted key file", functools.partial(_load_public, path))
        ring[key_id(public)] = public
    if threshold > len(ring):
        raise click.BadParameter(
            f"must be at most the number of distinct trusted keys ({len(ring)})",
            param_hint="'--threshold'",
        )
    raw = _load(
        "verification",
        "envelope file",
        functools.partial(_read, envelope, attestation.MAX_ENVELOPE_BYTES),
    )
    data = _load(
        "verification", "subject file", functools.partial(_read, subject, MAX_SUBJECT_BYTES)
    )
    try:
        verified = attestation.verify_attestation(
            attestation.parse_envelope(raw),
            data,
            trusted_keys=ring,
            purpose=cast(attestation.Purpose, purpose),
            threshold=threshold,
            match=cast(attestation.Match, match),
            max_age=None if max_age_days is None else timedelta(days=max_age_days),
        )
    except attestation.AttestationError as exc:
        raise _failure("verification", exc.reason, str(exc)) from None
    predicate = verified.predicate
    facts: dict[str, object] = {
        "attestation_verified": True,
        "purpose": predicate.purpose,
        "signers": list(verified.signers),
        "match": verified.match,
        "subject_sha256": verified.subject_sha256,
        "attested_sha256": verified.attested_sha256,
        "subject_format": predicate.subject_format,
        **predicate.model_dump(
            mode="json",
            include={"spec_version", "content_digest", "content_profile"},
            exclude_none=True,
        ),
        "signed_at": predicate.model_dump(mode="json")["signed_at"],
        **predicate.model_dump(mode="json", include={"source_revision"}, exclude_none=True),
    }
    if json_output:
        click.echo(json_text(json.dumps(facts, indent=2)))
        return
    count = len(verified.signers)
    echo_line(
        "Attestation verified: ",
        f"purpose {predicate.purpose}, {count} trusted key{'' if count == 1 else 's'}. It "
        "does not establish that the file is accurate, complete or safe.",
    )
    for name in verified.signers:
        echo_line("Signer key ID: ", name)
    echo_line("Subject SHA-256: ", verified.subject_sha256)
    if verified.match == "content":
        echo_line("Match: content; the attested file's SHA-256 is ", verified.attested_sha256)
    else:
        echo_line("Match: bytes")
    if predicate.content_digest is None:
        echo_line("Subject format: ", predicate.subject_format, " (no content digest)")
    else:
        echo_line("Subject format: ", predicate.subject_format, " ", predicate.spec_version)
        echo_line(
            "Content digest: ", predicate.content_digest, " (", predicate.content_profile, ")"
        )
    echo_line("Signed at (signer's clock): ", facts["signed_at"])
    if predicate.source_revision is not None:
        echo_line("Source revision claimed by the signer, not checked: ", predicate.source_revision)


def register_attestation_commands(main: click.Group) -> None:
    main.add_command(attest)
    main.add_command(verify_attestation)
