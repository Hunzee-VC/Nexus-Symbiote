"""Neutralize untrusted text and report output failures for the command-line tools."""

from __future__ import annotations

import errno
import os
import re
from pathlib import Path

import click

from nexus_symbiote.utils.files import OutputRefusedError, write_output_file

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
    "Cannot write the output file: its directory must exist, no directory on the path "
    "may be a symbolic link, and an existing output must not be a directory, device, "
    "FIFO or socket, or a link to one."
)


def neutralize(value: object) -> str:
    """Replace every character that can rewrite or disguise terminal and CI output."""
    return UNSAFE_TEXT.sub("�", str(value))


# What the output rules themselves produce: a missing directory, a link or file on
# the path (O_NOFOLLOW gives ELOOP, ENOTDIR or, on BSD, EMLINK), or a directory as
# the target; a special file is OutputRefusedError. Anything else, such as EACCES, ENOSPC
# or a kernel EINVAL, is reported by its system message.
_REFUSALS = frozenset({errno.ENOENT, errno.ELOOP, errno.EMLINK, errno.ENOTDIR, errno.EISDIR})


def output_failure(exc: BaseException) -> click.ClickException:
    """A plain command error for an output that was not written; never names the path."""
    if (
        isinstance(exc, OSError)
        and not isinstance(exc, OutputRefusedError)
        and exc.errno is not None
        and exc.errno not in _REFUSALS
    ):
        return click.ClickException(f"Cannot write the output file: {os.strerror(exc.errno)}.")
    return click.ClickException(OUTPUT_REFUSED)


def write_cli_output(path: Path, data: str, *, overwrite: bool = True) -> None:
    """Write a selected output file, turning any failure into a plain command error."""
    try:
        write_output_file(path, data, overwrite=overwrite)
    except (OSError, ValueError) as exc:
        raise output_failure(exc) from exc
