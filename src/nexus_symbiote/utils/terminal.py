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
# Unicode 15.1) disguise text, and so does every other default-ignorable code point
# (Default_Ignorable_Code_Point, assigned or not), which renders as nothing or as a
# blank: variation selectors, which encode hidden bytes as U+E0100 + b, Hangul and
# Khmer fillers, the combining grapheme joiner and U+2065, U+FFF0 to U+FFF8 and
# U+E0000 to U+E0FFF. Inventory and checkout data may contain any of them.
# Line breaks are included: a file name or component name containing one could
# forge whole output lines, and in CI a line starting with "::" is a workflow command.
# Such text must not start a line either; safe_line() gives every line a fixed prefix.
# The noncharacters U+FFFE and U+FFFF are included: unassigned for ever, some
# terminals drop them. A tab (U+0009) is not: it becomes one space (neutralize), so a
# name stays readable but cannot line text up under a later column.
UNSAFE_TEXT = re.compile(
    r"[\x00-\x08\x0a-\x1f\x7f-\x9f\xad\u034f\u0600-\u0605\u061c\u06dd\u070f\u0890\u0891"
    r"\u08e2\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u2028\u2029\u202a-\u202e"
    r"\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\ufff9-\ufffb\ufffe\uffff"
    r"\U000110bd\U000110cd\U00013430-\U0001343f\U0001bca0-\U0001bca3\U0001d173-\U0001d17a"
    r"\U000e0000-\U000e0fff]"
)

OUTPUT_REFUSED = (
    "Cannot write the output file: its directory must exist, no directory on the path "
    "may be a symbolic link, and an existing output must not be a directory, device, "
    "FIFO or socket, or a link to one."
)


# CI runners act on a "##name[" introducer anywhere in a line, not only at its start:
# GitHub Actions' legacy "##[command]" form, Azure Pipelines' "##vso[" and TeamCity's
# "##teamcity[". A replacement character after the "##" breaks each one visibly.
LOG_COMMAND = re.compile(r"##(?=[A-Za-z]*\[)")
_JSON_LOG_COMMAND = re.compile(r"(##[A-Za-z]*)\[")


def neutralize(value: object) -> str:
    """Replace every character that can rewrite or disguise terminal and CI output.

    Apply it to a whole output line, not to its pieces: two harmless pieces, such as a
    name ending in "##" and a following "[", can join into a CI log command. A tab
    becomes one space, every other such character U+FFFD.
    """
    return LOG_COMMAND.sub("##\ufffd", UNSAFE_TEXT.sub("\ufffd", str(value).replace("\t", " ")))


def safe_line(prefix: str, *values: object) -> str:
    """One neutralized output line that starts with a fixed, visible prefix.

    Inventory and checkout text must never begin a line: GitHub Actions treats a line
    that starts with "::", after leading white space, as a workflow command.
    """
    if not prefix.strip():
        raise ValueError("an output line needs a visible fixed prefix")
    return neutralize(prefix + "".join(map(str, values)))


def echo_line(prefix: str, *values: object, err: bool = False) -> None:
    """Print safe_line(prefix, *values) as plain text, without markup or wrapping.

    Plain text is printed as it is, so untrusted text never passes through a markup
    parser, a highlighter or a line wrapper, any of which can rewrite it, split it onto
    a new line or take time quadratic in its length.
    """
    click.echo(safe_line(prefix, *values), err=err)


def json_text(text: str) -> str:
    """JSON text in which no CI runner can find a "##name[" log command.

    In valid JSON, "##" occurs only inside a string, where the escape "\\u005b" stands
    for the same "[": the document parses to exactly the same value.
    """
    return _JSON_LOG_COMMAND.sub(lambda match: match.group(1) + "\\u005b", text)


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
