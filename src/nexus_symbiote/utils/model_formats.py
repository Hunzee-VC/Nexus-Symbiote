"""Bounded, non-executing readers for the parts of model files that name other content.

ONNX graphs can keep tensor bytes in files they name (external data); GGUF files
embed Jinja chat templates. These readers stream the artifact once, never import
a model library and never evaluate a template. Error messages are fixed text.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

Read = Callable[[int], bytes]

_CHUNK = 65536
# Structure units (protobuf fields, GGUF keys and array items) that one scan may
# spend across all files, so many hostile files cannot add up to a long scan.
MAX_INSPECTION_UNITS = 16_000_000


class FormatError(ValueError):
    """A bounded reader could not establish the structure it needs."""


class InspectionBudget:
    """Structure units shared by every bounded format reader in one collection."""

    def __init__(self, units: int | None = None) -> None:
        self.remaining = MAX_INSPECTION_UNITS if units is None else units

    def charge(self, units: int, error: str) -> None:
        self.remaining -= units
        if self.remaining < 0:
            raise FormatError(error)


class _Reader:
    """Forward-only buffered reader with exact reads and skips."""

    def __init__(self, read: Read, error: str) -> None:
        self._read = read
        self._buffer = b""
        self._pos = 0
        self.offset = 0
        self.error = error

    def _chunk(self) -> bytes:
        return self._read(_CHUNK)

    def _fill(self) -> bool:
        chunk = self._chunk()
        if not chunk:
            return False
        self._buffer = self._buffer[self._pos :] + chunk
        self._pos = 0
        return True

    def exhausted(self) -> bool:
        return self._pos >= len(self._buffer) and not self._fill()

    def drain(self) -> None:
        self._buffer, self._pos = b"", 0
        while self._chunk():
            pass

    def byte(self) -> int:
        if self._pos >= len(self._buffer) and not self._fill():
            raise FormatError(self.error)
        value = self._buffer[self._pos]
        self._pos += 1
        self.offset += 1
        return value

    def take(self, count: int) -> bytes:
        if len(self._buffer) - self._pos >= count:
            data = self._buffer[self._pos : self._pos + count]
            self._pos += count
            self.offset += count
            return data
        parts = [self._buffer[self._pos :]]
        have = len(parts[0])
        while have < count:
            chunk = self._chunk()
            if not chunk:
                raise FormatError(self.error)
            parts.append(chunk)
            have += len(chunk)
        joined = b"".join(parts)
        self._buffer, self._pos = joined[count:], 0
        self.offset += count
        return joined[:count]

    def skip(self, count: int) -> None:
        while count > 0:
            if self._pos >= len(self._buffer) and not self._fill():
                raise FormatError(self.error)
            step = min(count, len(self._buffer) - self._pos)
            self._pos += step
            self.offset += step
            count -= step

    def uint(self, width: int) -> int:
        return int.from_bytes(self.take(width), "little")


# ONNX ------------------------------------------------------------------------

ONNX_UNREADABLE = "ONNX graph could not be parsed; external weight files are unknown"
ONNX_LIMIT = "ONNX graph exceeds the inspection limits; external weight files are unknown"
ONNX_UNEXPLAINED = (
    "ONNX file holds an external-data key outside the parsed graph; "
    "external weight files are unknown"
)
MAX_ONNX_DEPTH = 64
MAX_ONNX_FIELDS = 4_000_000
MAX_ONNX_LOCATION_BYTES = 4096
_EXTERNAL = 1

_MODEL, _GRAPH, _NODE, _ATTRIBUTE, _TENSOR, _SPARSE, _FUNCTION, _TRAINING, _ENTRY = range(9)
# onnx.proto: the length-delimited fields that can hold a tensor, a subgraph or a
# StringStringEntryProto. Other fields are skipped by wire type, as protobuf does.
_SCHEMA: dict[int, dict[int, int]] = {
    _MODEL: {7: _GRAPH, 14: _ENTRY, 20: _TRAINING, 25: _FUNCTION},
    _GRAPH: {1: _NODE, 5: _TENSOR, 15: _SPARSE, 16: _ENTRY},
    _NODE: {5: _ATTRIBUTE, 9: _ENTRY},
    _ATTRIBUTE: {5: _TENSOR, 6: _GRAPH, 10: _TENSOR, 11: _GRAPH, 22: _SPARSE, 23: _SPARSE},
    _TENSOR: {13: _ENTRY, 16: _ENTRY},
    _SPARSE: {1: _TENSOR, 2: _TENSOR},
    _FUNCTION: {7: _NODE, 11: _ATTRIBUTE, 14: _ENTRY},
    _TRAINING: {1: _GRAPH, 2: _GRAPH, 3: _ENTRY, 4: _ENTRY},
    _ENTRY: {},
}
_KEY = b"location"


def _varints(value: int) -> list[bytes]:
    """Every encoding a protobuf parser accepts for ``value`` < 128, minimal first."""
    return [bytes([value])] + [bytes([value | 0x80]) + b"\x80" * n + b"\x00" for n in range(9)]


_KEY_TAGS = _varints(0x0A)
_KEY_LENGTHS = _varints(len(_KEY))


def _key_marker_at(window: bytes, index: int) -> bool:
    """Whether ``location`` at ``index`` is preceded by field 1, length 8, in any encoding."""
    for length in _KEY_LENGTHS:
        start = index - len(length)
        if start < 0 or window[start:index] != length:
            continue
        if any(start >= len(tag) and window[start - len(tag) : start] == tag for tag in _KEY_TAGS):
            return True
    return False


class _OnnxReader(_Reader):
    """Counts every encoded ``location`` key in the raw bytes, parsed or not."""

    _TAIL = len(_KEY) + 20

    def __init__(self, read: Read) -> None:
        super().__init__(read, ONNX_UNREADABLE)
        self.markers = 0
        self._tail = b""

    def _chunk(self) -> bytes:
        chunk = self._read(_CHUNK)
        window = self._tail + chunk
        index = window.find(_KEY)
        while index != -1:
            if index + len(_KEY) > len(self._tail) and _key_marker_at(window, index):
                self.markers += 1
            index = window.find(_KEY, index + 1)
        self._tail = window[-self._TAIL :]
        return chunk

    def varint(self) -> int:
        buffer, start = self._buffer, self._pos
        if start < len(buffer) and buffer[start] < 0x80:
            self._pos += 1
            self.offset += 1
            return buffer[start]
        result = 0
        for shift in range(0, 70, 7):
            byte = self.byte()
            result |= (byte & 0x7F) << shift
            if byte < 0x80:
                return result & 0xFFFFFFFFFFFFFFFF
        raise FormatError(ONNX_UNREADABLE)


@dataclass
class _OnnxState:
    budget: InspectionBudget
    fields: int = 0
    explained: int = 0
    locations: list[str] = field(default_factory=list)

    def count(self) -> None:
        self.fields += 1
        self.budget.charge(1, ONNX_LIMIT)
        if self.fields > MAX_ONNX_FIELDS:
            raise FormatError(ONNX_LIMIT)


def _skip_value(reader: _OnnxReader, wire: int, field_number: int, state: _OnnxState) -> None:
    if wire == 0:
        reader.varint()
    elif wire == 1:
        reader.skip(8)
    elif wire == 2:
        reader.skip(reader.varint())
    elif wire == 5:
        reader.skip(4)
    elif wire == 3:
        _skip_group(reader, field_number, state)
    else:
        raise FormatError(ONNX_UNREADABLE)


def _skip_group(reader: _OnnxReader, group: int, state: _OnnxState) -> None:
    depth = 1
    stack = [group]
    while stack:
        state.count()
        if depth > MAX_ONNX_DEPTH:
            raise FormatError(ONNX_LIMIT)
        tag = reader.varint()
        number, wire = tag >> 3, tag & 7
        if number == 0 or tag >= 2**32:
            raise FormatError(ONNX_UNREADABLE)
        if wire == 4:
            if stack.pop() != number:
                raise FormatError(ONNX_UNREADABLE)
            depth -= 1
        elif wire == 3:
            stack.append(number)
            depth += 1
        else:
            _skip_value(reader, wire, number, state)


def _message(
    reader: _OnnxReader, end: int | None, kind: int, depth: int, state: _OnnxState
) -> tuple[bytes | None, bytes | None]:
    """Parse one message; an entry returns its final key and value."""
    if depth > MAX_ONNX_DEPTH:
        raise FormatError(ONNX_LIMIT)
    location = 0
    externals: list[bytes | None] = []
    key: bytes | None = None
    value: bytes | None = None
    while (reader.offset < end) if end is not None else not reader.exhausted():
        state.count()
        tag = reader.varint()
        number, wire = tag >> 3, tag & 7
        if number == 0 or tag >= 2**32:
            raise FormatError(ONNX_UNREADABLE)
        if wire == 0 and kind == _TENSOR and number == 14:
            location = reader.varint()
            continue
        if wire != 2:
            _skip_value(reader, wire, number, state)
            continue
        length = reader.varint()
        stop = reader.offset + length
        if end is not None and stop > end:
            raise FormatError(ONNX_UNREADABLE)
        if kind == _ENTRY and number in (1, 2):
            if length > MAX_ONNX_LOCATION_BYTES:
                reader.skip(length)
                text = None
            else:
                text = reader.take(length)
            if number == 1:
                key = text
                state.explained += text == _KEY
            else:
                value = text
            continue
        child = _SCHEMA[kind].get(number)
        if child is None:
            reader.skip(length)
            continue
        entry_key, entry_value = _message(reader, stop, child, depth + 1, state)
        if kind == _TENSOR and number == 13 and entry_key == _KEY:
            externals.append(entry_value)
    if end is not None and reader.offset != end:
        raise FormatError(ONNX_UNREADABLE)
    # A runtime reads external data only for tensors stored as EXTERNAL.
    if kind == _TENSOR and location == _EXTERNAL:
        for raw in externals:
            if raw is None:
                raise FormatError(ONNX_UNREADABLE)
            try:
                state.locations.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                raise FormatError(ONNX_UNREADABLE) from None
    return key, value


def onnx_external_data(read: Read, budget: InspectionBudget | None = None) -> tuple[str, ...]:
    """Return the external-data locations an ONNX runtime would open, as written.

    Tensors in graphs, subgraphs, node attributes, functions and training graphs
    are followed. A runtime opens external data only through an entry whose key is
    the literal ``location``, and those bytes appear in the file whatever field
    holds them. So every encoded ``location`` key must belong to a parsed entry,
    and a file that the parser cannot read fails only when it holds such a key:
    without one it cannot name external data, whatever else it contains.
    """
    reader = _OnnxReader(read)
    state = _OnnxState(budget or InspectionBudget())
    try:
        _message(reader, None, _MODEL, 0, state)
    except (FormatError, RecursionError) as exc:
        reader.drain()
        if reader.markers:
            raise FormatError(str(exc) if isinstance(exc, FormatError) else ONNX_LIMIT) from None
        return ()
    if reader.markers > state.explained:
        raise FormatError(ONNX_UNEXPLAINED)
    return tuple(sorted(set(state.locations)))


# GGUF ------------------------------------------------------------------------

GGUF_UNREADABLE = "GGUF metadata could not be read"
GGUF_LIMIT = "GGUF metadata exceeds the inspection limits"
MAX_GGUF_KEYS = 65536
MAX_GGUF_STRING_BYTES = 16 * 1024 * 1024
MAX_GGUF_ARRAY_ITEMS = 1 << 21
MAX_GGUF_METADATA_BYTES = 128 * 1024 * 1024
_GGUF_SCALARS = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
_GGUF_STRING = 8
_GGUF_ARRAY = 9
_ARCHITECTURE = re.compile(rb"[a-z0-9][a-z0-9_.-]{0,63}")


@dataclass(frozen=True)
class GGUFMetadata:
    architecture: str | None
    chat_templates: tuple[tuple[str, bytes], ...]


def _gguf_string(reader: _Reader) -> bytes:
    length = reader.uint(8)
    if length > MAX_GGUF_STRING_BYTES:
        raise FormatError(GGUF_LIMIT)
    return reader.take(length)


def _skip_gguf_value(reader: _Reader, kind: int, depth: int, budget: InspectionBudget) -> None:
    budget.charge(1, GGUF_LIMIT)
    if kind in _GGUF_SCALARS:
        reader.skip(_GGUF_SCALARS[kind])
    elif kind == _GGUF_STRING:
        length = reader.uint(8)
        if length > MAX_GGUF_STRING_BYTES:
            raise FormatError(GGUF_LIMIT)
        reader.skip(length)
    elif kind == _GGUF_ARRAY and depth < 2:
        item = reader.uint(4)
        count = reader.uint(8)
        if count > MAX_GGUF_ARRAY_ITEMS:
            raise FormatError(GGUF_LIMIT)
        if item in _GGUF_SCALARS:
            reader.skip(count * _GGUF_SCALARS[item])
            return
        for _ in range(count):
            _skip_gguf_value(reader, item, depth + 1, budget)
            if reader.offset > MAX_GGUF_METADATA_BYTES:
                raise FormatError(GGUF_LIMIT)
    else:
        raise FormatError(GGUF_UNREADABLE)


def gguf_metadata(read: Read, budget: InspectionBudget | None = None) -> GGUFMetadata:
    """Read the architecture and chat templates from a GGUF v2 or v3 header."""
    budget = budget or InspectionBudget()
    reader = _Reader(read, GGUF_UNREADABLE)
    if reader.take(4) != b"GGUF" or reader.uint(4) not in (2, 3):
        raise FormatError(GGUF_UNREADABLE)
    reader.uint(8)
    count = reader.uint(8)
    if count > MAX_GGUF_KEYS:
        raise FormatError(GGUF_LIMIT)
    architecture: str | None = None
    templates: list[tuple[str, bytes]] = []
    for _ in range(count):
        budget.charge(1, GGUF_LIMIT)
        key = _gguf_string(reader)
        kind = reader.uint(4)
        template = key == b"tokenizer.chat_template" or key.startswith(b"tokenizer.chat_template.")
        if kind == _GGUF_STRING and (template or key == b"general.architecture"):
            value = _gguf_string(reader)
            if template:
                templates.append((key.decode("ascii", "replace"), value))
            elif _ARCHITECTURE.fullmatch(value):
                architecture = value.decode("ascii")
        else:
            _skip_gguf_value(reader, kind, 0, budget)
        if reader.offset > MAX_GGUF_METADATA_BYTES:
            raise FormatError(GGUF_LIMIT)
    return GGUFMetadata(architecture, tuple(templates))


# Chat templates ----------------------------------------------------------------

# Jinja sandbox escapes reach Python internals through dunder attributes, by
# name or through the attr filter. Ordinary chat templates do neither.
_TEMPLATE_ESCAPE = re.compile(
    rb"\.\s*__[A-Za-z0-9_]+__|\[\s*['\"]__[A-Za-z0-9_]+__['\"]\s*\]|(?<![A-Za-z0-9_])attr\s*\("
)


def template_escape_markers(template: bytes) -> bool:
    """Whether a template carries the attribute access that Jinja sandbox escapes use."""
    return _TEMPLATE_ESCAPE.search(template) is not None
