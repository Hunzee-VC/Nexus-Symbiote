"""Abstract scanner interface for discovering agent supply chain components."""

from __future__ import annotations

import hashlib
import os
import stat
from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from symbiote.core.models import AnyComponent

MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_MODEL_BYTES = 1024 * 1024 * 1024


@contextmanager
def _open_regular(path: Path, max_bytes: int) -> Iterator[int]:
    """Open a regular file without following links and check for read-time changes.

    Fail closed if descriptor-relative no-follow opens are unavailable. This protects
    scanner reads on POSIX; callers must surface failures as incomplete coverage.
    """
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
    ):
        raise OSError("secure descriptor-relative file access is unavailable")
    absolute = Path(os.path.abspath(path))
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    directory = os.open(absolute.anchor, flags | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:-1]:
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(absolute.name, flags | getattr(os, "O_NONBLOCK", 0), dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
                raise OSError("not a regular file or exceeds scanner size limit")
            yield fd
            after = os.fstat(fd)
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise OSError("file changed during scanner read")
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def read_regular_text(path: Path, *, max_bytes: int = MAX_CONFIG_BYTES) -> str:
    """Read bounded UTF-8 text without following symlinks."""
    with _open_regular(path, max_bytes) as fd:
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise OSError("file exceeds scanner size limit")
        return data.decode("utf-8")


def hash_regular_file(path: Path, *, max_bytes: int = MAX_MODEL_BYTES) -> str:
    """Hash a bounded regular file incrementally without following symlinks."""
    with _open_regular(path, max_bytes) as fd:
        digest = hashlib.sha256()
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
        if remaining == 0:
            raise OSError("file exceeds scanner size limit")
        return "sha256:" + digest.hexdigest()


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
    """The output of a single scanner pass."""

    scanner_name: str
    components: list[AnyComponent] = field(default_factory=list)
    surfaces_scanned: list[str] = field(default_factory=list)
    surfaces_excluded: list[str] = field(default_factory=list)
    scan_failures: list[str] = field(default_factory=list)


class Scanner(ABC):
    """Base class for all component scanners."""

    name: str = "base"

    @abstractmethod
    def scan(self, project_root: Path) -> ScanResult:
        """Scan a project directory and return discovered components."""
        ...

    def _safe_read_json(self, path: Path) -> dict[str, Any] | list[Any] | None:
        import json

        try:
            data: object = json.loads(read_regular_text(path))
            return data if isinstance(data, (dict, list)) else None
        except (json.JSONDecodeError, UnicodeError, OSError):
            return None
