"""MCP and agent SDK references in Python, TypeScript and JavaScript, found without running it.

Only files that contain an SDK marker are parsed: the MCP SDK, or for Python one of
the agent frameworks whose tools are collected. Finding them is a streaming search
under the collector's source budget, so unrelated source files, however large or
many, never fail the collector and appear nowhere in the inventory. Python source is
searched as CPython reads it: decoded as its encoding declaration says, also as
``python -x`` reads it, with identifiers compared in NFKC form. A declaration whose
decoding static reading cannot follow is a failure. TypeScript and JavaScript are
searched as tsc reads them: UTF-16 after a UTF-16 byte order mark, otherwise UTF-8.
A file is listed as a scanned surface only when it produced a component, a gap or a
failure. Every limit that stops collection is a scan failure naming the limit.
"""

from __future__ import annotations

import ast
import codecs
import functools
import io
import re
import tokenize
import unicodedata
import warnings
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from nexus_symbiote import limits
from nexus_symbiote.core.enums import TrustTier
from nexus_symbiote.core.models import MCPClientComponent
from nexus_symbiote.scanners.base import ScanResult, SourceBudget, parse_python
from nexus_symbiote.scanners.mcp import _SDK_IMPORT, without_js_comments
from nexus_symbiote.scanners.python_tools import (
    _AGENT_FACTORIES,
    _DECORATOR_IMPORTS,
    PYTHON_TOOL_HINTS,
    collect_python_tools,
)
from nexus_symbiote.scanners.ts_tools import (
    SERVER_MARKERS,
    UTF16_BYTE_ORDER_MARKS,
    collect_typescript_source,
    is_server_source,
    source_text,
)
from nexus_symbiote.utils.confined import CollectionError, ConfinedCollection

# Test, build output, documentation and example trees are not searched, so code
# that only illustrates an SDK never fails the collector.
_EXCLUDED_DIRECTORIES = frozenset(
    {"tests", "test", "dist", "build", "docs", "benchmarks", "examples"}
)
_TEST_SCRIPTS = (".d.ts", ".spec.ts", ".test.ts", ".spec.js", ".test.js")
_PYTHON_MARKERS = (*PYTHON_TOOL_HINTS, "MCPClient")
# Imports the tool collector reads from the syntax tree once a marker is present.
_FRAMEWORK_IMPORTS = frozenset({*_DECORATOR_IMPORTS, *_AGENT_FACTORIES})
_PYTHON_NEEDLES = frozenset(marker.encode() for marker in _PYTHON_MARKERS)
_CLIENT_MARKER = b"@modelcontextprotocol/sdk"
_NEEDLES = (*_PYTHON_NEEDLES, *SERVER_MARKERS, _CLIENT_MARKER)
_OVERLAP = max(len(needle) for needle in _NEEDLES) - 1
_SCRIPT_SUFFIXES = frozenset({".ts", ".js"})
_SCRIPT_MARKERS = {needle.decode(): needle for needle in (*SERVER_MARKERS, _CLIENT_MARKER)}
_TEXT_OVERLAP = max(len(marker) for marker in _SCRIPT_MARKERS) - 1
_CHUNK_BYTES = 1024 * 1024
_LINE = re.compile(rb"([^\r\n]*)(\r\n|\r|\n)?")
_MAY_DECLARE = re.compile(rb"[ \t\f]*(?:#|\Z)")
_LINE_END = re.compile(rb"[\r\n]")
# tokenize's declaration expression; bytes patterns match ASCII names only, as CPython does.
_COOKIE = re.compile(rb"[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")
_LATIN_1 = ("latin-1", "iso-8859-1", "iso-latin-1")
# Longer than any codec name or alias. A lookup costs time per character, and the
# codec registry keeps every name it failed to find for the life of the process.
_MAX_CODEC_NAME = 64
_FOLD_SLICE = 4096
_FOLD_TAIL = max(len(marker) for marker in _PYTHON_MARKERS) - 1
# A codec that decodes each probe to its ASCII reading has no shift state (UTF-7,
# ISO-2022, HZ), escape syntax (unicode_escape), label syntax (IDNA, punycode) or
# non-ASCII byte order (UTF-16, EBCDIC). The stdlib codecs that pass are single-byte
# code pages and stateless multibyte codecs, all linear, line-independent C decoders.
_ASCII_PROBES = (
    b"+AG0-",
    b"\\x6d\\u006d\\155",
    b"\x1b$B#M\x1b(B",
    b"\x1b$)C\x0e#M\x0f",
    b"~{#M~}",
    b"xn--ls8h",
    bytes(range(128)),
)
_INVALID_UTF8 = "invalid UTF-8"
_INVALID_DECLARED = "invalid text for its declared source encoding"
_UNSUPPORTED_ENCODING = "unsupported source encoding declaration"


class _UnreadableError(ValueError):
    """A source cannot be read the way Python would read it; the message names why."""


class _BudgetSpentError(Exception):
    """The source budget ran out during a read; the budget recorded the one gap."""


@functools.cache
def _keeps_ascii(codec: str) -> bool:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return all(probe.decode(codec) == probe.decode("ascii") for probe in _ASCII_PROBES)
        except (LookupError, ValueError):
            return False


def _declaration_lines(head: bytes, *, complete: bool) -> list[bytes]:
    """The lines CPython searches for an encoding declaration, split by universal newlines.

    CPython reads a second line only after a blank or comment first line. When
    ``head`` is only the start of a file and a declaration could still follow
    beyond it, the codec is unknown and the file is refused.
    """
    lines: list[bytes] = []
    position = 0
    while len(lines) < 2:
        match = _LINE.match(head, position)
        if match is None:
            break
        text = match.group(1)
        may_declare = bool(_MAY_DECLARE.match(text.removeprefix(codecs.BOM_UTF8)))
        if match.group(2) is None and not complete and may_declare:
            raise _UnreadableError(limits.bound("file-bytes").exceeded())
        if match.end() == position:
            break
        lines.append(text + b"\n")
        position = match.end()
        if not may_declare:
            break
    return lines


@dataclass(frozen=True)
class _Skipped:
    """The line ``python -x`` searches for a declaration, and whether all of it was read.

    The option skips through the first line feed, whatever the file's line endings,
    and reads what follows as a second line, so that line can declare a codec even
    after a first line of code.
    """

    line: bytes
    whole: bool


def _skipped_line(content: bytes) -> _Skipped | None:
    """The ``python -x`` declaration line of a complete file; None when -x skips all of it."""
    start = content.find(b"\n") + 1
    if not start:
        return None
    match = _LINE.match(content, start)
    return _Skipped(b"" if match is None else match.group(1), True)


def _declared_codec(line: bytes) -> str | None:
    """The codec name one line declares, normalized as CPython normalizes it, or None."""
    match = _COOKIE.match(line)
    if match is None:
        return None
    name = match.group(1).decode("ascii")
    folded = name[:12].lower().replace("_", "-")
    if folded == "utf-8" or folded.startswith("utf-8-"):
        return "utf-8"
    if folded in _LATIN_1 or folded.startswith(tuple(f"{prefix}-" for prefix in _LATIN_1)):
        return "iso-8859-1"
    if len(name) > _MAX_CODEC_NAME:
        raise _UnreadableError(_UNSUPPORTED_ENCODING)
    return name


def _followed(encoding: str) -> str:
    """The codec's canonical name when static reading follows it; any other is refused."""
    try:
        name = codecs.lookup(encoding).name
    except LookupError:
        raise _UnreadableError(_UNSUPPORTED_ENCODING) from None
    if not _keeps_ascii(name):
        raise _UnreadableError(_UNSUPPORTED_ENCODING)
    return "utf-8" if name == "utf-8-sig" else name


def _source_encoding(
    head: bytes, *, complete: bool, skipped: _Skipped | None
) -> tuple[str, str | None]:
    """The codecs CPython decodes a Python source with, when static reading can follow them.

    The first decodes the file when it is imported or run; the second, a canonical
    name, decodes what ``python -x`` runs, and is None when that option leaves
    nothing. Only codecs that read ASCII as ASCII are followed. A script run
    directly and a module imported then decode the file alike, so the text searched
    and parsed here is the text CPython runs; any other declaration is refused.
    """
    lines = _declaration_lines(head, complete=complete)
    if skipped is not None and not skipped.whole and _MAY_DECLARE.match(skipped.line):
        raise _UnreadableError(limits.bound("file-bytes").exceeded())
    # Refuse a name too long to be a codec before anything looks it up.
    for index, line in enumerate(lines):
        _declared_codec(line.removeprefix(codecs.BOM_UTF8) if index == 0 else line)
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(b"".join(lines)).readline)
    except SyntaxError:
        try:
            b"".join(lines).decode("utf-8")
        except UnicodeDecodeError:
            raise _UnreadableError(_INVALID_UTF8) from None
        raise _UnreadableError(_UNSUPPORTED_ENCODING) from None
    _followed(encoding)
    if skipped is None:
        return encoding, None
    return encoding, _followed(_declared_codec(skipped.line) or "utf-8")


def _python_text(content: bytes) -> str:
    """The text CPython compiles from one complete Python source file."""
    encoding, skipped = _source_encoding(content, complete=True, skipped=_skipped_line(content))
    try:
        text = content.decode(encoding)
    except UnicodeDecodeError:
        utf8 = encoding in {"utf-8", "utf-8-sig"}
        raise _UnreadableError(_INVALID_UTF8 if utf8 else _INVALID_DECLARED) from None
    if skipped is None or skipped == _followed(encoding):
        return text
    rest = content[content.index(b"\n") :]
    if rest.isascii():
        return text
    # python -x decodes the rest in another codec. A second reading that names the
    # SDK could declare servers and tools this text does not show.
    try:
        other = rest.decode(skipped)
    except UnicodeDecodeError:
        return text
    if _names_sdk(other):
        raise _UnreadableError(_UNSUPPORTED_ENCODING)
    return text


def _names_sdk(text: str) -> bool:
    """Whether Python could read an SDK marker in this text, folding identifiers to NFKC.

    Every run of ASCII letters that NFKC gives an identifier is already adjacent in
    the NFKD form, which neither moves nor merges letters. Decomposing a slice at a
    time keeps a hostile character's expansion (up to 18 characters each) to one
    slice instead of the whole text.
    """
    if any(marker in text for marker in _PYTHON_MARKERS):
        return True
    if text.isascii() or unicodedata.is_normalized("NFKC", text):
        return False
    tail = ""
    for start in range(0, len(text), _FOLD_SLICE):
        window = tail + unicodedata.normalize("NFKD", text[start : start + _FOLD_SLICE])
        if any(marker in window for marker in _PYTHON_MARKERS):
            return True
        tail = window[-_FOLD_TAIL:]
    return False


def _client_reference(text: str) -> bool:
    # A bounded syntax hint, never a claim that an SDK is installed or deployed.
    return bool(_SDK_IMPORT.search(without_js_comments(text)))


def _python_client(tree: ast.Module) -> bool:
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module is not None
        and node.module.split(".")[0] == "mcp"
        and any("Client" in alias.name for alias in node.names)
        for node in ast.walk(tree)
    ) or any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "MCPClient"
        for node in ast.walk(tree)
    )


def _server_module(name: str) -> bool:
    parts = name.split(".")
    return parts[0] == "fastmcp" or parts[:2] == ["mcp", "server"]


@dataclass(frozen=True)
class _Source:
    """What one streaming search found: the file's first bytes, its size and its markers.

    ``error`` says why a root-level script that is not a candidate still fails.
    """

    head: bytes
    size: int
    found: frozenset[bytes]
    ascii: bool
    skipped: _Skipped | None = None
    error: str | None = None

    @property
    def complete(self) -> bool:
        return len(self.head) == self.size


class _Markers:
    """The SDK markers in one source stream, searched in the text its tools read.

    Python is searched by bytes, and the line ``python -x`` would search for a
    declaration is kept, up to ``keep`` bytes. A script that starts with a UTF-16
    byte order mark is searched in its decoded text, as tsc reads it: a lone
    surrogate stays and a trailing odd byte is ignored. Any other root-level script
    is checked to be valid UTF-8, as earlier releases required.
    """

    def __init__(self, path: Path, keep: int) -> None:
        script = path.suffix in _SCRIPT_SUFFIXES
        self.found: set[bytes] = set()
        self.ascii = True
        self.utf8 = True
        self._keep = keep
        self._python = path.suffix == ".py"
        self._start: bytes | None = b"" if script else None
        self._tail = b""
        self._text: codecs.IncrementalDecoder | None = None
        self._text_tail = ""
        root_script = script and len(path.parts) == 1
        self._utf8 = codecs.getincrementaldecoder("utf-8")() if root_script else None
        self._after_line_feed = False
        self._skipped = bytearray()
        self._skipped_end = False
        self._skipped_whole = True

    def feed(self, chunk: bytes) -> None:
        self.ascii = self.ascii and chunk.isascii()
        if self._python:
            self._skip(chunk)
        if self._start is not None:
            # The first two bytes decide how the whole script is read.
            self._start += chunk
            if len(self._start) < 2:
                return
            chunk, self._start = self._start, None
            encoding = UTF16_BYTE_ORDER_MARKS.get(chunk[:2])
            if encoding is not None:
                self._text = codecs.getincrementaldecoder(encoding)("surrogatepass")
                self._utf8 = None
                chunk = chunk[2:]
        if self._text is not None:
            text = self._text_tail + self._text.decode(chunk)
            self.found.update(
                needle for marker, needle in _SCRIPT_MARKERS.items() if marker in text
            )
            self._text_tail = text[-_TEXT_OVERLAP:]
            return
        window = self._tail + chunk
        self.found.update(needle for needle in _NEEDLES if needle in window)
        self._tail = window[-_OVERLAP:]
        if self._utf8 is not None:
            try:
                self._utf8.decode(chunk)
            except UnicodeDecodeError:
                self.utf8 = False
                self._utf8 = None

    def close(self) -> None:
        if self._start:
            # Too short to hold a byte order mark.
            start, self._start = self._start, None
            self.feed(start)
        if self._utf8 is not None:
            try:
                self._utf8.decode(b"", final=True)
            except UnicodeDecodeError:
                self.utf8 = False

    def skipped(self) -> _Skipped | None:
        if not self._after_line_feed:
            return None
        return _Skipped(bytes(self._skipped), self._skipped_whole)

    def _skip(self, chunk: bytes) -> None:
        if self._skipped_end:
            return
        if not self._after_line_feed:
            index = chunk.find(b"\n")
            if index < 0:
                return
            self._after_line_feed = True
            chunk = chunk[index + 1 :]
        end = _LINE_END.search(chunk)
        piece = chunk if end is None else chunk[: end.start()]
        room = self._keep - len(self._skipped)
        self._skipped += piece[:room]
        if end is not None or len(piece) > room:
            self._skipped_end = True
            self._skipped_whole = len(piece) <= room


def _search(files: ConfinedCollection, path: Path, keep: int, budget: SourceBudget) -> _Source:
    """Read a file in chunks, keeping its first ``keep`` bytes and noting each marker.

    Every chunk is charged to the source budget. A file larger than the whole budget
    is refused alone before it is read, so it does not spend the budget.
    """
    head = bytearray()
    size = 0
    markers = _Markers(path, keep)
    with files.open_regular(path, max_bytes=budget.bound) as stream:
        while chunk := stream.read(_CHUNK_BYTES):
            if not budget.admit(len(chunk), path):
                raise _BudgetSpentError
            size += len(chunk)
            if len(head) < keep:
                head += chunk[: keep - len(head)]
            markers.feed(chunk)
    markers.close()
    return _Source(
        bytes(head),
        size,
        frozenset(markers.found),
        markers.ascii,
        markers.skipped(),
        None if markers.utf8 else _INVALID_UTF8,
    )


def _names_sdk_when_skipped(content: bytes) -> bool:
    """Whether what ``python -x`` reads after the first line feed names an SDK marker."""
    skipped = _skipped_line(content)
    if skipped is None:
        return False
    codec = _followed(_declared_codec(skipped.line) or "utf-8")
    try:
        other = content[content.index(b"\n") :].decode(codec)
    except UnicodeDecodeError:
        return False
    return _names_sdk(other)


def _python_candidate(path: Path, source: _Source) -> bool:
    if source.found & _PYTHON_NEEDLES:
        return True
    if source.ascii:
        # ASCII reads as itself in every codec followed, so the byte search was exact.
        _source_encoding(source.head, complete=source.complete, skipped=source.skipped)
        return False
    if not source.complete:
        raise _UnreadableError(limits.bound("file-bytes").exceeded())
    try:
        return _names_sdk(_python_text(source.head))
    except _UnreadableError as exc:
        if len(path.parts) == 1 or str(exc) != _INVALID_UTF8:
            raise
    # Python cannot import or run this nested file, which declares no codec and is not
    # UTF-8, so it is an unrelated module and no failure; unless python -x, which
    # skips the first line, would read a reference in the rest.
    if _names_sdk_when_skipped(source.head):
        raise _UnreadableError(_INVALID_UTF8)
    return False


def _server_candidate(path: Path, source: _Source) -> bool:
    return all(marker in source.found for marker in SERVER_MARKERS)


def _client_candidate(path: Path, source: _Source) -> bool:
    return _CLIENT_MARKER in source.found


@dataclass
class _Kind:
    """One kind of source reference: which files qualify and which are candidates."""

    eligible: Callable[[Path], bool]
    candidate: Callable[[Path, _Source], bool]
    selected: list[tuple[Path, bytes]] = field(default_factory=list)


def _python_source(path: Path) -> bool:
    return path.suffix == ".py" and not _EXCLUDED_DIRECTORIES.intersection(path.parts)


def _script_source(suffix: str) -> Callable[[Path], bool]:
    def eligible(path: Path) -> bool:
        return (
            path.suffix == suffix
            and not _EXCLUDED_DIRECTORIES.intersection(path.parts)
            and not path.name.endswith(_TEST_SCRIPTS)
        )

    return eligible


def _server_import(tree: ast.Module) -> bool:
    return any(
        (
            isinstance(node, ast.ImportFrom)
            and node.module is not None
            and _server_module(node.module)
        )
        or (isinstance(node, ast.Import) and any(_server_module(a.name) for a in node.names))
        for node in ast.walk(tree)
    )


def _framework_import(tree: ast.Module) -> bool:
    return any(
        isinstance(node, ast.ImportFrom)
        and not node.level
        and any((node.module, alias.name) in _FRAMEWORK_IMPORTS for alias in node.names)
        for node in ast.walk(tree)
    )


def _hidden_import(text: str, tree: ast.Module) -> str | None:
    """The gap for an import the tool collector cannot see, or None.

    The tool collector reads a file only when one of its names appears literally,
    while Python folds identifiers to NFKC, so an import spelled only with
    compatibility characters would otherwise drop its servers and tools silently.
    """
    if any(hint in text for hint in PYTHON_TOOL_HINTS):
        return None
    if _server_import(tree):
        return (
            "Python MCP server import spelled with compatibility characters; "
            "its servers and tools are not collected"
        )
    if _framework_import(tree):
        return (
            "Python agent framework tool import spelled with compatibility characters; "
            "its tools are not collected"
        )
    return None


def _outcome(result: ScanResult) -> tuple[int, int, int]:
    return len(result.components), len(result.surfaces_excluded), len(result.scan_failures)


def collect_source_references(
    files: ConfinedCollection, result: ScanResult, sources: Sequence[Path], budget: SourceBudget
) -> None:
    """Inventory MCP servers, MCP clients and agent tools declared in source.

    ``sources`` is the collector's walk of the root. Every eligible file is searched
    as a stream, root files first, and ``budget`` bounds the text read: running out
    of it is the budget's one named gap, and nothing after it is read.
    """
    settings = limits.current()
    servers = _Kind(is_server_source, _server_candidate)
    python = _Kind(_python_source, _python_candidate)
    typescript = _Kind(_script_source(".ts"), _client_candidate)
    javascript = _Kind(_script_source(".js"), _client_candidate)
    kinds = (servers, python, typescript, javascript)
    eligible = [path for path in sources if any(kind.eligible(path) for kind in kinds)]
    # Root files first, as before, so what a lowered budget reads stays predictable.
    eligible.sort(key=lambda path: len(path.parts) > 1)
    failed: set[Path] = set()

    def fail(path: Path, reason: str) -> None:
        if path not in failed:
            failed.add(path)
            files._fail(path.as_posix(), reason)

    # Every eligible file can fail, so past the listing bound the failures of the
    # search are summarized by reason instead of growing the inventory without end.
    with files.bounded_failures():
        for path in eligible:
            try:
                source = _search(files, path, settings.file_bytes, budget)
            except _BudgetSpentError:
                break
            except (OSError, CollectionError):
                # The confined reader recorded why. Once the collection's own byte
                # budget is spent, no later file can be read either.
                if files.bytes_exhausted:
                    break
                continue
            candidate = False
            for kind in kinds:
                if not kind.eligible(path):
                    continue
                try:
                    if not kind.candidate(path, source):
                        continue
                except _UnreadableError as exc:
                    fail(path, str(exc))
                    continue
                candidate = True
                if source.size > settings.syntax_bytes:
                    fail(path, limits.bound("syntax-bytes").exceeded())
                elif not source.complete:
                    fail(path, limits.bound("file-bytes").exceeded())
                else:
                    kind.selected.append((path, source.head))
            if not candidate and source.error is not None:
                # tsc would read the file, replacing what is not UTF-8, but another
                # runtime could decode it differently; earlier releases failed it too.
                fail(path, source.error)

    surfaces: list[str] = []
    detected: list[str] = []
    for path, content in servers.selected:
        before = _outcome(result)
        collect_typescript_source(path, content, result)
        if _outcome(result) != before:
            surfaces.append(path.as_posix())
    for path, content in python.selected:
        location = path.as_posix()
        before = _outcome(result)
        client = False
        try:
            text = _python_text(content)
        except _UnreadableError as exc:
            fail(path, str(exc))
            continue
        try:
            tree = parse_python(text)
        except (SyntaxError, ValueError, RecursionError):
            fail(path, "invalid Python syntax")
        else:
            collect_python_tools(tree, text, path, result)
            client = _python_client(tree)
            if client:
                detected.append(location)
            gap = _hidden_import(text, tree)
            if gap is not None:
                result.surfaces_excluded.append(f"{location}: {gap}")
        if _outcome(result) != before or client:
            surfaces.append(location)
    for path, content in (*typescript.selected, *javascript.selected):
        try:
            text = source_text(content)
        except ValueError as exc:
            fail(path, str(exc))
            continue
        if _client_reference(text):
            detected.append(path.as_posix())
            surfaces.append(path.as_posix())
    result.surfaces_scanned.extend(dict.fromkeys(surfaces))
    if detected:
        result.components.append(
            MCPClientComponent(
                bom_ref="mcp-client:sdk",
                name="MCP SDK client (code-detected)",
                host_application="sdk",
                source_path=detected[0],
                trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                properties={
                    "collection_mode": "static-source-reference",
                    "source_paths": detected,
                },
            )
        )
