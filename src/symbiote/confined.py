"""Filesystem access for untrusted checkouts. Pin directories before opening their children."""

from __future__ import annotations

import os
import secrets
import stat
import sys
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path
from typing import BinaryIO


@contextmanager
def _windows_pin(path: Path, *, directory: bool) -> Iterator[int]:
    """Open the entry itself and deny concurrent write/delete (including replacement by a junction)."""
    if sys.platform != "win32":  # Keep the platform-specific handle API isolated.
        raise OSError("Windows file handles require Windows")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    open_handle = kernel.CreateFileW
    open_handle.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    open_handle.restype = wintypes.HANDLE
    # GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, OPEN_REPARSE_POINT | BACKUP_SEMANTICS
    handle = open_handle(str(path), 0x80000000, 1, None, 3, 0x00200000 | 0x02000000, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle(wintypes.HANDLE(handle))
        raise
    try:
        # The pin holds this exact directory entry stable while inspecting and using it.
        info = os.lstat(path)
        if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError("refusing filesystem reparse point")
        if directory != stat.S_ISDIR(info.st_mode):
            raise OSError("unexpected filesystem entry type")
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _directory(root: Path, parts: tuple[str, ...], *, create: bool = False) -> Iterator[int | None]:
    if ".." in parts:
        raise OSError("parent traversal is outside the scan scope")
    with ExitStack() as stack:
        if os.name == "nt":
            current = root
            for part in (".", *parts):
                current = current / part
                if create and part != ".":
                    current.mkdir(mode=0o700, exist_ok=True)
                stack.enter_context(_windows_pin(current, directory=True))
            yield None
        else:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            fd = os.open(root, flags)
            stack.callback(os.close, fd)
            for part in parts:
                if create:
                    with suppress(FileExistsError):
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                fd = os.open(part, flags, dir_fd=fd)
                stack.callback(os.close, fd)
            yield fd


@contextmanager
def open_scoped_file(root: Path, path: Path) -> Iterator[BinaryIO]:
    relative = path.relative_to(root)
    with _directory(root, relative.parts[:-1]) as parent, ExitStack() as stack:
        if parent is None:
            fd = stack.enter_context(_windows_pin(path, directory=False))
        else:
            fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            stack.callback(os.close, fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("expected a regular file")
        yield stack.enter_context(os.fdopen(fd, "rb", closefd=False))


def write_scan_output(path: Path, data: bytes) -> None:
    """Replace an output atomically; never truncate the object targeted by an existing link."""
    root = Path(path.anchor) if path.is_absolute() else Path(".")
    parts = path.relative_to(root).parts
    with _directory(root, parts[:-1], create=True) as parent:
        name = ".symbiote-" + secrets.token_hex(16)
        temp = path.parent / name if parent is None else Path(name)
        dest = path if parent is None else Path(parts[-1])
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(temp, flags, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            os.replace(temp, dest, src_dir_fd=parent, dst_dir_fd=parent)
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temp, dir_fd=parent)
