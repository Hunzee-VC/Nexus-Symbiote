"""Inventory digests, and the collection time that ``SOURCE_DATE_EPOCH`` pins.

``nexus-symbiote digest`` reads one native inventory once and prints the SHA-256 of
its bytes, the canonical digest a signed runtime snapshot binds and the content digest
of ``core.content_digest``, which leaves out when and in which run the inventory was
collected. Equal content digests mean equal recorded content; they say nothing about
who produced either file or whether what it records is safe.

With ``SOURCE_DATE_EPOCH`` set, ``scan`` (and so ``baseline``) and ``import-shadowscan``
record that instant as the collection time; without it they record none. The serial
number does not depend on it: ``core.aibom.prepare`` derives a missing one from the
content digest. Equal inputs give byte-identical native JSON and CycloneDX either
way, and byte-identical SPDX, whose schema requires a creation time, only with it.
Nothing else reads the variable: gate decisions, such as whether a suppression has
expired, keep using the clock.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path

import click

from nexus_symbiote.utils.terminal import echo_line, json_text, neutralize

_EPOCH = re.compile(r"[0-9]{1,12}")
MALFORMED_EPOCH = (
    "SOURCE_DATE_EPOCH must be a whole number of seconds since 1970-01-01T00:00:00Z: "
    "1 to 12 ASCII digits, at most 253402300799 (9999-12-31T23:59:59Z)"
)
UNAVAILABLE = "unavailable"


def source_date_epoch() -> datetime | None:
    """The instant ``SOURCE_DATE_EPOCH`` pins as the collection time; None when unset.

    Any other value is a usage error whose message does not repeat it.
    """
    value = os.environ.get("SOURCE_DATE_EPOCH")
    if value is None:
        return None
    if _EPOCH.fullmatch(value) is None:
        raise click.UsageError(MALFORMED_EPOCH)
    try:
        return datetime.fromtimestamp(int(value), UTC)
    except (OverflowError, OSError, ValueError):
        raise click.UsageError(MALFORMED_EPOCH) from None


@click.command("digest")
@click.argument("inventory_path", type=click.Path(exists=True, path_type=Path))
@click.option("--json-output", is_flag=True, help="Print the digests as one JSON object.")
def digest_command(inventory_path: Path, json_output: bool) -> None:
    """Print the file, canonical and content digests of a native inventory.

    Two inventories of the same content have the same content digest, whenever and
    wherever each was collected; equal digests say nothing about who produced either.
    A digest that is undefined for the inventory is printed as unavailable (null in
    JSON), and the command exits 1.
    """
    from nexus_symbiote.core.aibom import NativeFormatError, read_native_bytes
    from nexus_symbiote.core.content_digest import INVENTORY_CONTENT_PROFILE
    from nexus_symbiote.core.inventory_digests import inventory_digests

    try:
        digests = inventory_digests(read_native_bytes(inventory_path))
    except NativeFormatError as exc:
        raise click.ClickException(
            f"{neutralize(inventory_path)} is not a valid native AIBOM file. {neutralize(exc)}"
        ) from exc
    document = {
        "file_sha256": digests.file_sha256,
        "canonical_digest": digests.canonical_digest,
        "content_digest": digests.content_digest,
        "content_profile": INVENTORY_CONTENT_PROFILE,
        "spec_version": digests.spec_version,
        "components": digests.components,
    }
    if json_output:
        click.echo(json_text(json.dumps(document, indent=2)))
    else:
        for name, value in document.items():
            echo_line(f"{name}: ", UNAVAILABLE if value is None else value)
    if digests.unavailable:
        raise click.ClickException(
            " ".join(
                (
                    f"{neutralize(inventory_path)} is a valid native AIBOM file, but not every "
                    "digest is defined for it.",
                    *digests.unavailable,
                )
            )
        )


def register_digest_commands(main: click.Group) -> None:
    main.add_command(digest_command)
