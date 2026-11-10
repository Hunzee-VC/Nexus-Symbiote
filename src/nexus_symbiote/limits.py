"""Operator-set bounds on what one command collects from a checkout.

Every bound fails closed: a collector that reaches one records a scan failure
naming the limit, its value, the root-relative path where it was reached and how
to raise it, so the gates fail. Changing a limit moves where collection stops; it
never decides whether a stop is reported. Limits come only from the operator,
through the ``--limit NAME=VALUE`` root option and the ``NEXUS_SYMBIOTE_LIMITS``
environment variable. Nothing in the scanned checkout, its policy file included,
can change them.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace

ENV_VAR = "NEXUS_SYMBIOTE_LIMITS"
OPTION = "--limit"

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB
TIB = 1024 * GIB

_SUFFIXES = {"kib": KIB, "mib": MIB, "gib": GIB}
_VALUE = re.compile(r"([0-9]{1,20})[ \t]*([KkMmGg][Ii][Bb])?")


class LimitError(ValueError):
    """A limit setting is malformed, unknown, repeated or out of range."""


@dataclass(frozen=True)
class LimitSpec:
    """One operator-settable limit: its name, unit, accepted range and meaning."""

    name: str
    unit: str
    maximum: int
    summary: str

    @property
    def attribute(self) -> str:
        return self.name.replace("-", "_")


SPECS: dict[str, LimitSpec] = {
    spec.name: spec
    for spec in (
        LimitSpec(
            "file-bytes",
            "bytes",
            GIB,
            "Size of one file a collector reads into memory: configuration, "
            "manifests, instructions and candidate source files.",
        ),
        LimitSpec(
            "total-bytes",
            "bytes",
            64 * GIB,
            "Bytes one collector reads in total, except model weights and MCP source scanning.",
        ),
        LimitSpec(
            "entries",
            "count",
            10_000_000,
            "Directory entries one collector lists while it walks the project.",
        ),
        LimitSpec(
            "depth",
            "count",
            256,
            "Directory nesting below the project root that a walk descends into.",
        ),
        LimitSpec(
            "model-bytes",
            "bytes",
            TIB,
            "Size of one model weight or tokenizer file that is inspected and hashed.",
        ),
        LimitSpec(
            "model-total-bytes",
            "bytes",
            16 * TIB,
            "Bytes the model collector reads in total, weights included.",
        ),
        LimitSpec(
            "source-files",
            "count",
            100_000,
            "Python, TypeScript or JavaScript files containing an MCP SDK reference "
            "that the mcp collector parses, counted for each language separately.",
        ),
        LimitSpec(
            "source-scan-bytes",
            "bytes",
            64 * GIB,
            "Bytes of Python, TypeScript and JavaScript source the mcp collector reads "
            "to find files that contain an MCP SDK reference.",
        ),
        LimitSpec(
            "syntax-bytes",
            "bytes",
            64 * MIB,
            "Size of one source file the mcp collector parses.",
        ),
        LimitSpec(
            "ts-nodes",
            "count",
            10_000_000,
            "Syntax nodes in one TypeScript MCP server file.",
        ),
    )
}


@dataclass(frozen=True)
class CollectionLimits:
    """The limits one command collects under; defaults apply unless the operator sets one."""

    file_bytes: int = 4 * MIB
    total_bytes: int = 32 * MIB
    entries: int = 100_000
    depth: int = 32
    model_bytes: int = 64 * GIB
    model_total_bytes: int = 256 * GIB
    source_files: int = 50
    source_scan_bytes: int = 256 * MIB
    syntax_bytes: int = 256 * KIB
    ts_nodes: int = 20_000

    def value(self, name: str) -> int:
        value: int = getattr(self, SPECS[name].attribute)
        return value


DEFAULTS = CollectionLimits()


def format_value(name: str, value: int) -> str:
    """Render a limit value the way an operator would write it."""
    spec = SPECS.get(name)
    if spec is None or spec.unit != "bytes":
        return str(value)
    for suffix, size in (("GiB", GIB), ("MiB", MIB), ("KiB", KIB)):
        if value >= size and value % size == 0:
            return f"{value // size} {suffix}"
    return f"{value} bytes"


@dataclass(frozen=True)
class Bound:
    """A bound one collection enforces, and whether the operator can raise it."""

    value: int
    name: str
    configurable: bool = True

    def exceeded(self) -> str:
        shown = format_value(self.name, self.value)
        if self.configurable:
            return f"{self.name} limit of {shown} exceeded; raise it with {OPTION} {self.name}=N"
        return f"{self.name} limit of {shown} exceeded; this limit is fixed for this input"


def _parse_value(spec: LimitSpec, text: str) -> int:
    match = _VALUE.fullmatch(text.strip())
    if match is None or (match.group(2) and spec.unit != "bytes"):
        expected = (
            "a whole number of bytes, optionally followed by KiB, MiB or GiB"
            if spec.unit == "bytes"
            else "a whole number"
        )
        raise LimitError(f"{spec.name} needs {expected}")
    value = int(match.group(1)) * _SUFFIXES.get((match.group(2) or "").lower(), 1)
    if not 1 <= value <= spec.maximum:
        raise LimitError(
            f"{spec.name} must be between 1 and {format_value(spec.name, spec.maximum)}"
        )
    return value


def parse_setting(text: str) -> tuple[str, int]:
    """Parse one ``NAME=VALUE`` setting; error messages never repeat what was supplied."""
    name, separator, value = text.partition("=")
    name = name.strip().lower().replace("_", "-")
    if not separator:
        raise LimitError(
            f"limit settings take the form NAME=VALUE, for example {OPTION} entries=200000"
        )
    spec = SPECS.get(name)
    if spec is None:
        close = difflib.get_close_matches(name, SPECS, n=1)
        hint = f"; did you mean {close[0]}?" if close else "."
        raise LimitError(f"unknown limit name{hint} Known limits: " + ", ".join(SPECS))
    return name, _parse_value(spec, value)


def _settings(items: Iterable[str], source: str) -> dict[str, int]:
    settings: dict[str, int] = {}
    for item in items:
        if not item.strip():
            continue
        name, value = parse_setting(item)
        if name in settings:
            raise LimitError(f"{name} is set more than once in {source}")
        settings[name] = value
    return settings


def resolve(options: Iterable[str], environ: Mapping[str, str]) -> CollectionLimits:
    """Combine the environment and ``--limit`` options; an option wins for its name."""
    settings = _settings(environ.get(ENV_VAR, "").split(","), ENV_VAR)
    settings.update(_settings(options, OPTION))
    return replace(DEFAULTS, **{SPECS[name].attribute: value for name, value in settings.items()})


_current = DEFAULTS


def current() -> CollectionLimits:
    """The limits in force for this process; collectors read them when they run."""
    return _current


def bound(name: str) -> Bound:
    """The operator-settable bound ``name`` as currently in force."""
    return Bound(current().value(name), name)


@contextmanager
def applied(limits: CollectionLimits) -> Iterator[CollectionLimits]:
    """Use ``limits`` for the duration of one command, then restore the previous ones."""
    global _current
    previous = _current
    _current = limits
    try:
        yield limits
    finally:
        _current = previous
