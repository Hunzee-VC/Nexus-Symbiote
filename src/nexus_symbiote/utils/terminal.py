"""Neutralize untrusted text and report output failures for the command-line tools."""

from __future__ import annotations

import re
from pathlib import Path

import click

from nexus_symbiote.utils.files import write_output_file

# C0/C1 controls move the cursor or rewrite earlier output; bidirectional and
# invisible format characters (every Unicode format character, category Cf, as of
# Unicode 15.1) disguise text. Inventory and checkout data may contain any of them.
# Line breaks are included: a file name or component name containing one could
# forge whole output lines, and in CI a line starting with "::" is a workflow command.
UNSAFE_TEXT = re.compile(
    r"[\x00-\x08\x0a-\x1f\x7f-\x9f­؀-؅؜۝܏࢐࢑࣢"
    r"᠎​-‏  ‪-‮⁠-⁤⁦-⁯﻿"
    r"￹-￻\U000110bd\U000110cd\U00013430-\U0001343f\U0001bca0-\U0001bca3"
    r"\U0001d173-\U0001d17a\U000e0001\U000e0020-\U000e007f]"
)

OUTPUT_REFUSED = (
    "Cannot write the output file: its directory must exist and no directory on the "
    "path may be a symbolic link, and the file itself must not be a directory."
)


def neutralize(value: object) -> str:
    """Replace every character that can rewrite or disguise terminal and CI output."""
    return UNSAFE_TEXT.sub("�", str(value))


def write_cli_output(path: Path, data: str, *, overwrite: bool = True) -> None:
    """Write a selected output file, turning any refusal into a plain command error."""
    try:
        write_output_file(path, data, overwrite=overwrite)
    except (OSError, ValueError) as exc:
        raise click.ClickException(OUTPUT_REFUSED) from exc
