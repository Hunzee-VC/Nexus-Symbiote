"""Bounded hashing of untrusted BOM paths beneath a trusted project root."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from nexus_symbiote.utils.fsio import MAX_MODEL_BYTES

MAX_HASH_BYTES = MAX_MODEL_BYTES
ALLOWED_HASHES = {"sha256", "sha384", "sha512"}


def hash_confined_file(root: Path, source: str, algorithm: str = "sha256") -> str:
    """Hash a regular file using no-follow, descriptor-relative opens.

    Absolute paths are accepted only if lexically inside root. A trusted root
    may itself be a symlink; untrusted descendant symlinks are never followed.
    Platforms without these primitives fail closed.
    """
    if algorithm not in ALLOWED_HASHES:
        raise OSError("unsupported digest algorithm")
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
    ):
        raise OSError("secure descriptor-relative file access unavailable")
    root = Path(os.path.abspath(root))
    candidate = Path(source)
    if ".." in candidate.parts:
        raise OSError("parent traversal is not permitted")
    if candidate.is_absolute():
        try:
            candidate = candidate.relative_to(root)
        except ValueError as exc:
            raise OSError("path is outside the project root") from exc
    if not candidate.parts:
        raise OSError("file path is empty")

    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    try:
        for part in candidate.parts[:-1]:
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(candidate.parts[-1], flags | getattr(os, "O_NONBLOCK", 0), dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_HASH_BYTES:
                raise OSError("not a regular file or exceeds hash limit")
            h = hashlib.new(algorithm)
            remaining = MAX_HASH_BYTES + 1
            while remaining:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
            if remaining == 0:
                raise OSError("file exceeds hash limit")
            after = os.fstat(fd)
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise OSError("file changed while hashing")
            return f"{algorithm}:{h.hexdigest()}"
        finally:
            os.close(fd)
    finally:
        os.close(directory)
