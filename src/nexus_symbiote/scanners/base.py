"""Abstract scanner interface for discovering agent supply chain components."""

from __future__ import annotations

import fnmatch
import json
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from nexus_symbiote.core.models import AnyComponent
from nexus_symbiote.utils.fsio import (
    MAX_CONFIG_BYTES,
    MAX_MODEL_BYTES,
    hash_regular_file,
    open_regular,
    read_regular_text,
)

# Kept as module attributes so scanner modules and existing callers keep working.
_open_regular = open_regular

__all__ = [
    "DEFAULT_EXCLUDE_PATHS",
    "MAX_CONFIG_BYTES",
    "MAX_MODEL_BYTES",
    "ScanResult",
    "Scanner",
    "hash_regular_file",
    "matched_exclusion",
    "read_regular_text",
    "relative_posix",
    "sanitized_origin",
]

DEFAULT_EXCLUDE_PATHS: tuple[str, ...] = ("node_modules", ".git", "__pycache__", ".venv")


def relative_posix(path: Path, root: Path) -> str:
    """Project-relative POSIX path. Falls back to the given path if it lies outside root."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def matched_exclusion(path: Path, root: Path, patterns: Iterable[str]) -> str | None:
    """Return the first exclusion pattern that matches ``path``, or None.

    A pattern without a slash matches any path component. A pattern with a slash is
    matched against the project-relative path.
    """
    rel = relative_posix(path, root)
    parts = rel.split("/")
    for pattern in patterns:
        if "/" in pattern:
            if fnmatch.fnmatch(rel, pattern):
                return pattern
        elif any(fnmatch.fnmatch(part, pattern) for part in parts):
            return pattern
    return None


def sanitized_origin(value: str) -> str:
    """Retain only a URL's origin; paths, userinfo, query and fragment may be secrets."""
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
        if not parsed.scheme or not host:
            return "[redacted]"
        host = f"[{host}]" if ":" in host else host
        return f"{parsed.scheme.lower()}://{host}" + (f":{port}" if port else "")
    except ValueError:
        return "[redacted]"


@dataclass
class ScanResult:
    """The output of a single scanner pass.

    ``surfaces_scanned`` lists what was examined, including locations that were checked
    and found empty. ``surfaces_excluded`` lists only real exclusions: policy exclusions,
    unreadable or unsafe inputs, and unsupported platforms. ``scan_failures`` lists
    errors that make the result incomplete.
    """

    scanner_name: str
    components: list[AnyComponent] = field(default_factory=list)
    surfaces_scanned: list[str] = field(default_factory=list)
    surfaces_excluded: list[str] = field(default_factory=list)
    scan_failures: list[str] = field(default_factory=list)

    def record_absent(self, surface: str, checked: Iterable[str]) -> None:
        """Record that the documented locations were checked and nothing was present."""
        locations = ", ".join(checked)
        self.surfaces_scanned.append(f"{surface} (checked {locations}; none present)")

    def record_excluded(self, surface: str, reason: str) -> None:
        """Record a real exclusion. An excluded surface is not evidence of absence."""
        self.surfaces_excluded.append(f"{surface} ({reason})")

    def record_failure(self, message: str) -> None:
        self.scan_failures.append(message)


class Scanner(ABC):
    """Base class for all component scanners."""

    name: str = "base"
    exclude_paths: tuple[str, ...] = DEFAULT_EXCLUDE_PATHS

    def __init__(self, exclude_paths: Iterable[str] | None = None) -> None:
        if exclude_paths is not None:
            self.exclude_paths = tuple(exclude_paths)

    @abstractmethod
    def scan(self, project_root: Path) -> ScanResult:
        """Scan a project directory and return discovered components."""
        ...

    def _safe_read_json(self, path: Path) -> dict[str, Any] | list[Any] | None:
        try:
            data: object = json.loads(read_regular_text(path))
            return data if isinstance(data, (dict, list)) else None
        except (json.JSONDecodeError, UnicodeError, OSError):
            return None
