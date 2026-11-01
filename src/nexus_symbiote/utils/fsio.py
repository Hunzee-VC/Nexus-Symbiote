"""Bounded, no-follow reads of untrusted inputs, and safe writes of outputs.

Reads never follow symbolic links, refuse anything that is not a regular file, and
enforce a size limit. Writes never go through a symbolic link at the destination, go
to a temporary file first, and replace the target atomically.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

MAX_CONFIG_BYTES = 4 * 1024 * 1024
# Model weights are hashed as a stream, so this is a sanity bound and not a memory
# bound. Real checkpoints can be many gigabytes, and a 1 GiB cap made them unscannable.
MAX_MODEL_BYTES = 256 * 1024 * 1024 * 1024
# Owner read and write only: generated inventories can name local paths and hosts.
DEFAULT_OUTPUT_MODE = 0o600


@contextmanager
def open_regular(path: Path, max_bytes: int) -> Iterator[int]:
    """Open a regular file without following links, and detect changes during the read.

    Fails closed when descriptor-relative no-follow opens are unavailable. Callers must
    surface the failure as incomplete coverage.
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
                raise OSError("not a regular file or exceeds the size limit")
            yield fd
            after = os.fstat(fd)
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise OSError("file changed during the read")
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def read_regular_text(path: Path, *, max_bytes: int = MAX_CONFIG_BYTES) -> str:
    """Read bounded UTF-8 text without following symbolic links."""
    with open_regular(path, max_bytes) as fd:
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise OSError("file exceeds the size limit")
        return data.decode("utf-8")


def hash_regular_file(path: Path, *, max_bytes: int = MAX_MODEL_BYTES) -> str:
    """Hash a regular file as a stream, without following symbolic links.

    Returns "sha256:<hex>". The size limit is a sanity bound and does not affect memory.
    """
    with open_regular(path, max_bytes) as fd:
        digest = hashlib.sha256()
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
        if remaining == 0:
            raise OSError("file exceeds the size limit")
        return "sha256:" + digest.hexdigest()


def write_text_safely(
    path: Path | str,
    text: str,
    *,
    mode: int = DEFAULT_OUTPUT_MODE,
    overwrite: bool = True,
) -> Path:
    """Write text to a path without following a symbolic link at the destination.

    The text goes to a temporary file in the same directory, which then replaces the
    target atomically. Refuses to write through a symbolic link, and refuses to replace
    an existing file when ``overwrite`` is False.
    """
    target = Path(path)
    if target.is_symlink():
        raise OSError(f"refusing to write through a symbolic link: {target}")
    if not overwrite and target.exists():
        raise FileExistsError(f"refusing to overwrite an existing file: {target}")
    directory = target.parent if str(target.parent) else Path(".")
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise
    return target
