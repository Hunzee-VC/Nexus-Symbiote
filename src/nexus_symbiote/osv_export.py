"""Read saved OSV exports and evaluate whether an exact version is affected.

An export is what https://osv.dev publishes for offline use (an ecosystem's
``all.zip``), a directory of OSV JSON records, or one JSON file holding a
record, a list of records or a ``{"vulns": [...]}`` query response. Reading
never follows a symbolic link and is bounded per record, per file count and in
total. A version is affected when an ``affected`` entry lists it in
``versions`` or an ``ECOSYSTEM`` or ``SEMVER`` range includes it, evaluated as
the OSV schema specifies. Anything that cannot be evaluated is reported as
undetermined rather than as unaffected.

Specification: https://ossf.github.io/osv-schema/
"""

from __future__ import annotations

import os
import re
import stat
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from nexus_symbiote.core.hashing import open_regular_file, parse_json_strict

MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_FILES = 1_000_000
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_AFFECTED = 10_000
MAX_LISTED_VERSIONS = 200_000
RECORD_ID = re.compile(r"[A-Za-z0-9_.:-]{1,200}")
_SEMVER = re.compile(
    r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


class ExportError(ValueError):
    """The export is unreadable, malformed or over a limit."""


@dataclass
class _Budget:
    files: int = 0
    total: int = 0

    def take(self, size: int) -> None:
        self.files += 1
        self.total += size
        if self.files > MAX_FILES or self.total > MAX_TOTAL_BYTES:
            raise ExportError("OSV export exceeds the file-count or byte limit")


def _records(document: Any) -> list[Any]:
    if isinstance(document, list):
        return document
    if (
        isinstance(document, dict)
        and "id" not in document
        and isinstance(document.get("vulns"), list)
    ):
        return list(document["vulns"])
    return [document]


def _parse(data: bytes, limit: int) -> list[Any]:
    try:
        return _records(parse_json_strict(data, max_bytes=limit))
    except (ValueError, RecursionError) as exc:
        raise ExportError("OSV export contains invalid JSON") from exc


def _read_file(path: Path, budget: _Budget, limit: int) -> bytes:
    with open_regular_file(path) as stream:
        size = os.fstat(stream.fileno()).st_size
        if size > limit:
            raise ExportError("OSV export file exceeds the byte limit")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ExportError("OSV export file exceeds the byte limit")
    budget.take(len(data))
    return data


def _from_zip(path: Path, budget: _Budget) -> Iterator[Any]:
    with open_regular_file(path) as stream, zipfile.ZipFile(stream) as archive:
        members = archive.infolist()
        if len(members) > MAX_FILES:
            raise ExportError("OSV export exceeds the file-count limit")
        for member in members:
            if member.is_dir():
                continue
            if not member.filename.endswith(".json") or member.file_size > MAX_RECORD_BYTES:
                raise ExportError("OSV archive member is not a bounded JSON record")
            with archive.open(member) as entry:
                data = entry.read(MAX_RECORD_BYTES + 1)
            if len(data) > MAX_RECORD_BYTES:
                raise ExportError("OSV archive member exceeds the byte limit")
            budget.take(len(data))
            yield from _parse(data, MAX_RECORD_BYTES)


def _from_directory(path: Path, budget: _Budget) -> Iterator[Any]:
    for directory, subdirectories, names in os.walk(path, followlinks=False):
        subdirectories.sort()
        for name in sorted(names):
            if not name.endswith(".json"):
                continue
            candidate = Path(directory) / name
            if stat.S_ISLNK(os.lstat(candidate).st_mode):
                raise ExportError("OSV export contains a symbolic link")
            yield from _parse(_read_file(candidate, budget, MAX_RECORD_BYTES), MAX_RECORD_BYTES)


def iter_records(path: Path) -> Iterator[dict[str, Any]]:
    """Yield validated OSV records from a zip archive, a directory or a JSON file."""
    budget = _Budget()
    try:
        mode = os.lstat(path).st_mode
    except OSError as exc:
        raise ExportError("OSV export is unreadable") from exc
    if stat.S_ISLNK(mode):
        raise ExportError("OSV export must not be a symbolic link")
    try:
        if stat.S_ISDIR(mode):
            raw: Iterator[Any] = _from_directory(path, budget)
        elif path.suffix.lower() == ".zip":
            raw = _from_zip(path, budget)
        else:
            raw = iter(_parse(_read_file(path, budget, MAX_FILE_BYTES), MAX_FILE_BYTES))
        for record in raw:
            yield _validated(record)
    except (OSError, zipfile.BadZipFile, EOFError, RuntimeError) as exc:
        raise ExportError("OSV export is unreadable or not a valid archive") from exc


def _validated(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict) or not isinstance(record.get("id"), str):
        raise ExportError("OSV record without a string id")
    if RECORD_ID.fullmatch(record["id"]) is None:
        raise ExportError("OSV record id is invalid")
    affected = record.get("affected", [])
    if not isinstance(affected, list) or len(affected) > MAX_AFFECTED:
        raise ExportError("OSV record has an invalid affected list")
    for entry in affected:
        package = entry.get("package") if isinstance(entry, dict) else None
        if not isinstance(package, dict) or not all(
            isinstance(package.get(key), str) for key in ("ecosystem", "name")
        ):
            raise ExportError("OSV affected entry without a package identity")
        versions = entry.get("versions", [])
        if (
            not isinstance(versions, list)
            or len(versions) > MAX_LISTED_VERSIONS
            or not all(isinstance(value, str) for value in versions)
        ):
            raise ExportError("OSV affected entry has invalid versions")
        if not isinstance(entry.get("ranges", []), list):
            raise ExportError("OSV affected entry has invalid ranges")
    return record


def pypi_version(value: str) -> Version:
    try:
        return Version(value)
    except InvalidVersion as exc:
        raise ValueError("not a PEP 440 version") from exc


def semver_key(value: str) -> tuple[Any, ...]:
    """SemVer 2.0.0 precedence: build metadata ignored, prerelease below release."""
    match = _SEMVER.fullmatch(value)
    if match is None:
        raise ValueError("not a SemVer 2.0.0 version")
    release = tuple(int(part) for part in match.groups()[:3])
    prerelease = match.group(4)
    if prerelease is None:
        return (*release, (1,))
    identifiers = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part) for part in prerelease.split(".")
    )
    return (*release, (0, identifiers))


def _range_includes(version: Any, events: Any, parse: Callable[[str], Any]) -> bool:
    """Evaluate one range as the OSV schema specifies: walk events in version order."""
    if not isinstance(events, list) or not events:
        raise ValueError("range without events")
    from_zero = False
    bounded: list[tuple[Any, str]] = []
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise ValueError("invalid range event")
        ((kind, value),) = event.items()
        if kind not in {"introduced", "fixed", "last_affected"} or not isinstance(value, str):
            raise ValueError("unsupported range event")
        if kind == "introduced" and value == "0":
            from_zero = True
        else:
            bounded.append((parse(value), kind))
    affected = from_zero
    for bound, kind in sorted(bounded, key=lambda item: item[0]):
        if kind == "introduced" and version >= bound:
            affected = True
        elif (kind == "fixed" and version >= bound) or (
            kind == "last_affected" and version > bound
        ):
            affected = False
    return affected


def affects(entry: dict[str, Any], ecosystem: str, version: str) -> bool | None:
    """True when affected, False when not, None when the entry cannot be evaluated."""
    parse: Callable[[str], Any] = pypi_version if ecosystem == "PyPI" else semver_key
    try:
        parsed = parse(version)
    except ValueError:
        return None
    listed = entry.get("versions", [])
    for value in listed:
        if value == version:
            return True
        try:
            if parse(value) == parsed:
                return True
        except ValueError:
            continue
    ranges = entry.get("ranges", [])
    if not listed and not ranges:
        return None
    evaluable = [
        r for r in ranges if isinstance(r, dict) and r.get("type") in {"ECOSYSTEM", "SEMVER"}
    ]
    if len(evaluable) != len(ranges) and not listed:
        return None
    try:
        return any(_range_includes(parsed, r.get("events"), parse) for r in evaluable)
    except ValueError:
        return None
