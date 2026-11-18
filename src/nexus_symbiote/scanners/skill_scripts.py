"""A bundled shell script that runs a network download in a shell or interpreter.

The script is read as text and never run. Its commands are rated by the download shapes
of the hook command classifier (``runs_download``), once what is not a command of the
script is set aside: comments, here-document bodies and the text of quoted strings.
Nothing follows a variable, a function, a saved file or what a string holds: this is one
shape, not an analysis.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import RiskAssessment
from nexus_symbiote.scanners.ide_agents import runs_download
from nexus_symbiote.utils.terminal import neutralize

CATEGORY = "script_download_execution"

_SHELL_SUFFIXES = frozenset({".sh", ".bash", ".zsh", ".ksh"})
_SHELLS = frozenset({"sh", "bash", "zsh", "ksh", "dash", "ash"})
# A `#!` line is read this far for the program it names.
_SHEBANG_CHARACTERS = 256
# A here-document's delimiter: quoted, or a name. A name must start with a letter or `_`,
# so that an arithmetic shift such as `1 << 2` is not read as one.
_HERE_DOCUMENT = re.compile(r"<<(-?)[ \t]*(?:'([^'\n]*)'|\"([^\"\n]*)\"|\\?([A-Za-z_][\w.-]*))")
# What ends a word, so that a `#` after it starts a comment.
_WORD_BREAKS = frozenset(" \t;|&()<>")
# The rest of a double-quoted string, up to its closing quote.
_DOUBLE_QUOTED = re.compile(r'(?:[^"\\]|\\.)*+')
# What separates or starts commands. Inside a string that holds no substitution these are
# text, as in `grep -E 'curl|sh'`, and must not reach the classifier as operators.
_OPERATORS = str.maketrans(dict.fromkeys("|;&()<>`", " "))
# A command can match only when it holds a pipe or opens a substitution.
_CANDIDATE = re.compile(r"[|(`]")
_LISTED_LINES = 5


def is_shell_script(path: str, text: str) -> bool:
    """Whether a bundled file is a shell script: by its suffix, or by the program its
    ``#!`` line names, also through ``env``."""
    if PurePosixPath(path).suffix.lower() in _SHELL_SUFFIXES:
        return True
    if not text.startswith("#!"):
        return False
    words = text[2:_SHEBANG_CHARACTERS].split("\n", 1)[0].split()
    if words and PurePosixPath(words[0]).name == "env":
        words = [word for word in words[1:] if not word.startswith("-") and "=" not in word]
    return bool(words) and PurePosixPath(words[0]).name in _SHELLS


def _text_string(line: str, start: int) -> tuple[str, bool] | None:
    """The string that opens at ``start`` with its operators blanked, and whether it
    closes on this line; None when it is double-quoted and holds a substitution, whose
    commands the classifier reads."""
    quote = line[start]
    if quote == "'":
        end = line.find(quote, start + 1)
    else:
        found = _DOUBLE_QUOTED.match(line, start + 1)
        end = found.end() if found is not None and line.startswith(quote, found.end()) else -1
    closed = end != -1
    content = line[start + 1 : end if closed else len(line)]
    if quote == '"' and ("$(" in content or "`" in content):
        return None
    return quote + content.translate(_OPERATORS) + quote * closed, closed


def _scan_line(line: str, quote: str, strings: bool) -> tuple[str, str, list[tuple[str, bool]]]:
    """One line without its comment, the quote still open at its end, and each
    here-document that starts on it: its delimiter, and whether ``<<-`` strips tabs.

    Unless ``strings``, a string is text: its operators are blanked unless a substitution
    in it holds commands, and what continues a string from an earlier line is left out up
    to the quote that closes it. Between ``((`` and ``))`` a ``<<`` is a shift.
    """
    kept: list[str] = []
    documents: list[tuple[str, bool]] = []
    index, length = 0, len(line)
    word_start = True
    carried = bool(quote) and not strings
    arithmetic = 0
    while index < length:
        char = line[index]
        step = 1
        if quote:
            if char == "\\" and quote == '"':
                step = 2
            elif char == quote:
                quote = ""
            if carried and quote:
                index += step
                continue
            carried = False
        elif char == "\\":
            step = 2
        elif char in "'\"":
            text = None if strings else _text_string(line, index)
            if text is not None:
                kept.append(text[0])
                quote = "" if text[1] else char
                index += len(text[0])
                word_start = False
                continue
            quote = char
        elif char == "#" and word_start:
            break
        elif line.startswith(("((", "))"), index):
            arithmetic = max(0, arithmetic + (1 if char == "(" else -1))
            step = 2
        elif line.startswith("<<", index):
            # `<<<` gives a string, not a document.
            plain = arithmetic or line.startswith("<<<", index)
            found = None if plain else _HERE_DOCUMENT.match(line, index)
            if found is not None:
                delimiter = found.group(2) or found.group(3) or found.group(4) or ""
                documents.append((delimiter, bool(found.group(1))))
            step = 2 if found is None else found.end() - index
        kept.append(line[index : index + step])
        word_start = step == 1 and not quote and char in _WORD_BREAKS
        index += step
    return "".join(kept), quote, documents


def _read(text: str, strings: bool) -> tuple[list[tuple[str, bool]], bool]:
    """Each line as ``_scan_line`` leaves it, with whether a quote is still open at its
    end, and whether the quotes of the whole text balance. The lines of a here-document
    body are empty, so that every line keeps its number.

    A body is set aside only when its delimiter line follows: a shell would read an
    unclosed one to the end of the file, and a ``<<`` that is no here-document must not
    hide what follows it.
    """
    lines = text.split("\n")
    plain = [line.rstrip("\r") for line in lines]
    last = {line: number for number, line in enumerate(plain)}
    last_untabbed = {line.lstrip("\t"): number for number, line in enumerate(plain)}
    kept: list[tuple[str, bool]] = []
    quote = ""
    number = 0
    while number < len(lines):
        line, quote, documents = _scan_line(lines[number], quote, strings)
        kept.append((line, bool(quote) and not strings))
        number += 1
        for delimiter, strip_tabs in documents:
            if (last_untabbed if strip_tabs else last).get(delimiter, -1) < number:
                continue
            while (plain[number].lstrip("\t") if strip_tabs else plain[number]) != delimiter:
                kept.append(("", False))
                number += 1
            kept.append(("", False))
            number += 1
    return kept, not quote


def command_lines(text: str) -> list[tuple[str, bool]]:
    """The lines of a shell script that hold its commands, each with whether a quoted
    string runs on into the next line.

    Comments, here-document bodies and the text of quoted strings, such as a usage
    message or a search pattern, are not commands. When the quotes of the script do not
    balance, they were not read as its shell reads them, and strings are kept as written.
    """
    lines, balanced = _read(text, strings=False)
    return lines if balanced else _read(text, strings=True)[0]


def download_lines(text: str) -> list[int]:
    """The line each command starts on that pipes a download into a shell or interpreter,
    or has one run a substitution that downloads.

    The classifier reads a newline as the end of a command, except after a backslash and
    after a pipe, where blank lines may follow too. The lines of one command are given to
    it together, so the line reported is the one the command starts on.
    """
    lines = command_lines(text)
    found: list[int] = []
    start = 0
    command: list[str] = []
    piped = False
    for number, (line, in_string) in enumerate(lines, 1):
        if not command:
            start = number
        command.append(line)
        ending = line.rstrip()
        pipe = ending.endswith("|&") or (ending.endswith("|") and not ending.endswith("||"))
        piped = pipe or (piped and not ending)
        if in_string:
            command.append(" ")
        elif (piped or ending.endswith("\\")) and number < len(lines):
            command.append("\n")
        else:
            joined = "".join(command)
            command, piped = [], False
            if _CANDIDATE.search(joined) and runs_download(joined):
                found.append(start)
    return found


def _listed(lines: list[int]) -> str:
    if len(lines) == 1:
        return f"line {lines[0]}"
    shown = lines[:_LISTED_LINES]
    if len(lines) > _LISTED_LINES:
        return f"lines {', '.join(map(str, shown))} and {len(lines) - _LISTED_LINES} more"
    return f"lines {', '.join(map(str, shown[:-1]))} and {shown[-1]}"


def script_risks(path: str, text: str) -> list[RiskAssessment]:
    """The finding of one bundled file: high when it is a shell script and a command in
    it runs a download in a shell or interpreter. By shape, so never critical."""
    lines = download_lines(text) if is_shell_script(path, text) else []
    if not lines:
        return []
    return [
        RiskAssessment(
            severity=RiskSeverity.HIGH,
            category=CATEGORY,
            detail=(
                f"'{neutralize(path)}' runs a network download in a shell or interpreter, "
                f"through a pipe or a substitution, on {_listed(lines)}. What runs is "
                "whatever the address serves at that moment; no digest in the repository "
                "binds it. The commands are not recorded here."
            ),
            recommendation=(
                "Bundle the code the script needs, or download it to a file, check its "
                "digest and run that file."
            ),
        )
    ]
