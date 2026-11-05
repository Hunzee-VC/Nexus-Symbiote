"""Descriptor-based I/O for files in an explicitly selected directory."""

from __future__ import annotations

import contextlib
import errno
import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class OutputRefusedError(OSError):
    """The destination is one the output rules never replace."""


def _relative(root: Path, path: Path, *, allow_parent: bool = False) -> Path:
    relative = path.relative_to(root) if path.is_absolute() else path
    if (
        not relative.parts
        or relative.anchor
        or relative.name in ("", "..")
        or (".." in relative.parts and not allow_parent)
    ):
        raise ValueError("Expected a file beneath the selected directory")
    return relative


@contextmanager
def _parent(root: Path, relative: Path, create_parents: bool) -> Iterator[int]:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(root, flags)
    try:
        for part in relative.parts[:-1]:
            try:
                # ".." of a directory opened without following links is its real
                # parent, so this reaches exactly what the kernel resolves.
                child = os.open(part, flags, dir_fd=parent)
            except FileNotFoundError:
                if not create_parents:
                    raise
                os.mkdir(part, mode=0o700, dir_fd=parent)
                child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        yield parent
    finally:
        os.close(parent)


def write_output_file(
    path: Path,
    data: str,
    *,
    root: Path | None = None,
    create_parents: bool = False,
    overwrite: bool = True,
) -> None:
    """Replace the destination atomically without writing through an existing link."""
    if root is None:
        # An explicitly selected output may lie anywhere, but never traverse a link.
        path = path.absolute()
        root = Path(path.anchor)
        relative = _relative(root, path, allow_parent=True)
    else:
        relative = _relative(root, path)
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise OSError("Secure output requires descriptor-relative no-symlink file operations")
    with _parent(root, relative, create_parents) as parent:
        # A link is replaced, never followed, but a device, FIFO, socket or directory,
        # named directly or through that link, is never replaced by a report.
        for follow in (False, True):
            try:
                mode = os.stat(relative.name, dir_fd=parent, follow_symlinks=follow).st_mode
            except FileNotFoundError:
                break
            except OSError:
                if follow:
                    # A link whose target cannot be reached is itself replaced.
                    break
                raise
            if not (stat.S_ISREG(mode) or (stat.S_ISLNK(mode) and not follow)):
                raise OutputRefusedError(errno.EINVAL, "output must be a regular file")
        temp = f".nexus-symbiote-{secrets.token_hex(16)}.tmp"
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if overwrite:
                os.replace(temp, relative.name, src_dir_fd=parent, dst_dir_fd=parent)
            else:
                os.link(
                    temp, relative.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False
                )
        finally:
            # After a rename the name is gone; in a directory that forbids removal
            # (append-only) the temporary file stays. Neither replaces the outcome.
            with contextlib.suppress(OSError):
                os.unlink(temp, dir_fd=parent)
