"""Descriptor-based I/O for files in an explicitly selected directory."""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def _relative(root: Path, path: Path) -> Path:
    relative = path.relative_to(root) if path.is_absolute() else path
    if not relative.parts or ".." in relative.parts or relative.anchor:
        raise ValueError("Expected a file beneath the selected directory")
    return relative


@contextmanager
def _parent(root: Path, relative: Path) -> Iterator[int]:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(root, flags)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        yield parent
    finally:
        os.close(parent)


def write_output_file(path: Path, data: str, *, root: Path | None = None) -> None:
    """Replace the destination atomically without writing through an existing link."""
    if root is None:
        # An explicitly selected absolute output may lie anywhere, but never traverse a link.
        path = path.absolute()
        root = Path(path.anchor)
    relative = _relative(root, path)
    if os.name == "nt":
        # A directory hierarchy with reparse points cannot be locked with os.replace on Windows.
        # In security-sensitive CI (an explicit workspace root), refuse this unsupported mode.
        if len(root.parts) != 1:
            raise OSError("Secure workspace output requires directory-relative file replacement")
        import tempfile

        target = root / relative
        if target.parent.resolve(strict=True) != target.parent:
            raise OSError("Redirected output directory")
        with tempfile.NamedTemporaryFile(
            dir=target.parent, mode="w", encoding="utf-8", delete=False
        ) as f:
            tmp = Path(f.name)
            f.write(data)
        try:
            os.replace(tmp, target)
        finally:
            tmp.unlink(missing_ok=True)
        return
    with _parent(root, relative) as parent:
        temp = f".symbote-{secrets.token_hex(16)}.tmp"
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(data)
            os.replace(temp, relative.name, src_dir_fd=parent, dst_dir_fd=parent)
        finally:
            try:
                os.unlink(temp, dir_fd=parent)
            except FileNotFoundError:
                pass
