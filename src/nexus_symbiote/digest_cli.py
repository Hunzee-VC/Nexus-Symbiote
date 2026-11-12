"""Inventory digests, and the collection time that ``SOURCE_DATE_EPOCH`` pins.

``nexus-symbiote digest`` reads one native inventory once and prints the SHA-256 of
its bytes, the canonical digest a signed runtime snapshot binds and the content digest
of ``core.content_digest``, which leaves out when and in which run the inventory was
collected. Equal content digests mean equal recorded content; they say nothing about
who produced either file or whether what it records is safe.

With ``SOURCE_DATE_EPOCH`` set, ``scan`` (and so ``baseline``) and ``import-shadowscan``
record that instant instead of the clock, and a serial number derived from the content
digest, so equal inputs give byte-identical files. Nothing else reads the variable:
gate decisions, such as whether a suppression has expired, keep using the clock.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import click

from nexus_symbiote.utils.terminal import echo_line, json_text, neutralize

if TYPE_CHECKING:
    from nexus_symbiote.core.aibom import AIBOM

_EPOCH = re.compile(r"[0-9]{1,12}")
MALFORMED_EPOCH = (
    "SOURCE_DATE_EPOCH must be a whole number of seconds since 1970-01-01T00:00:00Z: "
    "1 to 12 ASCII digits, at most 253402300799 (9999-12-31T23:59:59Z)"
)
UNAVAILABLE = "unavailable"
NO_REPRODUCIBLE_SERIAL = (
    "Inventory not written. SOURCE_DATE_EPOCH derives the serial number from the content "
    "digest, which cannot be computed: the inventory records a value outside the I-JSON "
    "range, such as a lone surrogate, or nests too deeply."
)


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


def set_content_serial_number(aibom: AIBOM) -> None:
    """Name a finished inventory by its content: a UUIDv5 of its content digest.

    The serial number is not content, so setting it leaves the digest unchanged. It can
    be recomputed from the native JSON file. An export carries the same serial number
    but embeds a sorted copy of the native document, whose content digest differs.
    """
    from nexus_symbiote.core.content_digest import inventory_content_digest
    from nexus_symbiote.generators._common import NAMESPACE

    try:
        digest = inventory_content_digest(aibom.to_dict())
    except (ValueError, RecursionError) as exc:
        raise click.ClickException(NO_REPRODUCIBLE_SERIAL) from exc
    aibom.metadata.serial_number = f"urn:uuid:{uuid.uuid5(NAMESPACE, digest)}"


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
    from nexus_symbiote.core.content_digest import INVENTORY_CONTENT_PROFILE, inventory_digests

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
