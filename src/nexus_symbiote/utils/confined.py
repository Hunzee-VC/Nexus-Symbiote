"""Bounded local collection with descriptor-relative, no-symlink reads.

This is an offline collector boundary, not a process sandbox. It requires POSIX
``dir_fd`` and ``O_NOFOLLOW`` support and fails closed where unavailable.
"""

from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import stat
import unicodedata
from collections.abc import Collection, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, cast

from nexus_symbiote.core.hashing import descriptor_binding

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 20_000
MAX_DEPTH = 32
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_HASH_BYTES = 5 * 1024 * 1024 * 1024
DEFAULT_EXCLUDES = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv"})


class CollectionError(ValueError):
    """A collection input exceeded the supported safe boundary."""


class _LinkRefusedError(CollectionError):
    """A symlink that cannot be covered through an in-root target; the reason is recorded."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# An O_NOFOLLOW open reports a symlink as ELOOP (EMLINK on FreeBSD), and a symlinked
# parent opened with O_DIRECTORY as ENOTDIR.
_LINK_ERRNOS = frozenset({errno.ELOOP, errno.EMLINK, errno.ENOTDIR})
_MAX_CASE_VARIANTS = 16
# The format characters HFS+ ignores when it compares names.
_IGNORED_IN_NAMES = dict.fromkeys(
    [*range(0x200C, 0x2010), *range(0x202A, 0x202F), *range(0x206A, 0x2070), 0xFEFF]
)


def fold_name(name: str) -> str:
    """A file name as case-insensitive file systems compare it.

    Case and Unicode normalisation are folded, as on APFS, HFS+ and NTFS; so are the
    format characters HFS+ ignores and the trailing dots and spaces Windows drops.
    """
    folded = unicodedata.normalize("NFD", unicodedata.normalize("NFD", name).casefold())
    return folded.translate(_IGNORED_IN_NAMES).rstrip(". ")


def _lexical_target(directory: Path, text: str) -> Path:
    """Resolve a link's text against its directory without following anything.

    ``..`` may only lead the text: the directory holds no symlink, so leading parent
    steps resolve as the kernel resolves them, while one after a name could pass
    through a symlink and reach a different file than this lexical answer.
    """
    if not text or os.path.isabs(text):
        raise _LinkRefusedError("symlink target is absolute")
    parts = list(directory.parts)
    named = False
    for part in PurePosixPath(text).parts:
        if part == "..":
            if named:
                raise _LinkRefusedError("symlink target is not a plain relative path")
            if not parts:
                raise _LinkRefusedError("symlink target is outside the collection root")
            parts.pop()
        elif part != ".":
            named = True
            parts.append(part)
    return Path(*parts)


def hash_confined_file(root: Path, source_path: str | Path, algorithm: str = "sha256") -> str:
    """Compatibility hash API for a BOM-supplied path beneath a caller root."""
    if algorithm not in {"sha256", "sha384", "sha512"}:
        raise OSError("unsupported security hash algorithm")
    try:
        with (
            ConfinedCollection(root, [], max_total_bytes=MAX_HASH_BYTES) as files,
            files.open_regular(source_path, max_bytes=MAX_HASH_BYTES) as stream,
        ):
            digest = hashlib.new(algorithm)
            while chunk := stream.read(65536):
                digest.update(chunk)
            return f"{algorithm}:{digest.hexdigest()}"
    except (CollectionError, ValueError) as exc:
        raise OSError("confined artifact hash refused") from exc


class _BoundedReader(io.RawIOBase):
    """Explicit-size reads only; enforce both stream and collection budgets."""

    def __init__(self, fd: int, owner: ConfinedCollection, path: Path, limit: int) -> None:
        self._fd = fd
        self._owner = owner
        self._path = path
        self._limit = limit
        self._read = 0

    def readable(self) -> bool:
        return True

    def fileno(self) -> int:
        return self._fd

    def read(self, size: int = -1) -> bytes:
        if self.closed:
            raise ValueError("read of closed collection stream")
        if not 0 <= size <= MAX_FILE_BYTES:
            raise CollectionError("explicit bounded read size required")
        raw = os.read(self._fd, min(size, self._limit + 1 - self._read))
        self._read += len(raw)
        self._owner._bytes_read += len(raw)
        if self._read > self._limit or self._owner._bytes_read > self._owner.max_total_bytes:
            self._owner._fail(self._path, "stream byte limit exceeded")
            raise CollectionError("stream byte limit exceeded")
        return raw

    def close(self) -> None:
        if not self.closed:
            os.close(self._fd)
        super().close()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CollectionError("duplicate JSON key")
        result[key] = value
    return result


class ConfinedCollection:
    """Read regular files beneath a pinned root without following symlinks.

    Limits cover individual file bytes, directory entries over the complete walk,
    and directory depth. A directory exceeding the entry budget is not partially
    returned. Within those bounds traversal is lexical and deterministic.
    """

    def __init__(
        self,
        root: Path,
        failures: list[str],
        exclusions: list[str] | None = None,
        *,
        exclude_paths: Iterable[str | Path] = (),
        max_file_bytes: int = MAX_FILE_BYTES,
        max_entries: int = MAX_ENTRIES,
        max_depth: int = MAX_DEPTH,
        max_total_bytes: int = MAX_TOTAL_BYTES,
    ) -> None:
        self.root = Path(os.path.abspath(root))
        self.failures = failures
        self.exclusions = exclusions if exclusions is not None else []
        self.max_file_bytes = max_file_bytes
        self.max_entries = max_entries
        self.max_depth = max_depth
        self.max_total_bytes = max_total_bytes
        self._bytes_read = 0
        self._entry_budget = [max_entries]
        self._root_fd: int | None = None
        self._links: dict[str, str] = {}
        self._listings: dict[Path, list[str] | None] = {}
        self._excluded: list[Path] = []
        self._invalid_policy = False
        for value in exclude_paths:
            path = Path(value)
            candidate = path if path.is_absolute() else self.root / path
            candidate = Path(os.path.abspath(candidate))
            try:
                candidate.relative_to(self.root)
            except ValueError:
                self._fail(".", "excluded path is outside collection root")
                self._invalid_policy = True
                continue
            self._excluded.append(candidate)

    def __enter__(self) -> ConfinedCollection:
        if self._invalid_policy:
            return self
        if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
            self._fail(".", "no-follow descriptor-relative collection unsupported")
            return self
        current: int | None = None
        try:
            current = os.open(self.root.anchor, os.O_RDONLY | os.O_DIRECTORY)
            for part in self.root.parts[1:]:
                next_fd = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current
                )
                os.close(current)
                current = next_fd
            self._root_fd = current
        except OSError:
            if current is not None:
                os.close(current)
            self._fail(".", "root unavailable or contains a symlink")
        return self

    def __exit__(self, *args: object) -> None:
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def _fail(self, path: str | Path, reason: str) -> None:
        message = f"{path!s}: {reason}"
        if message not in self.failures:
            self.failures.append(message)

    def _relative(self, path: str | Path) -> Path:
        candidate = Path(path)
        if candidate.is_absolute():
            try:
                candidate = candidate.relative_to(self.root)
            except ValueError as exc:
                raise CollectionError("path is outside collection root") from exc
        if ".." in candidate.parts:
            raise CollectionError("parent traversal is not allowed")
        return candidate

    def excluded(self, path: str | Path) -> bool:
        relative = self._relative(path)
        absolute = self.root / relative
        # Dependency caches, virtual environments and Git internals are outside
        # the documented static scope. The BOM records these patterns. Any
        # further omission within that scope is a blocking coverage gap.
        if any(part in DEFAULT_EXCLUDES for part in relative.parts):
            return True
        denied = any(absolute == value or value in absolute.parents for value in self._excluded)
        if denied:
            message = f"{relative}: excluded by collection policy"
            if message not in self.exclusions:
                self.exclusions.append(message)
        return denied

    def _open_parent(self, relative: Path) -> int:
        if self._root_fd is None:
            raise CollectionError("collection root unavailable")
        fd = os.dup(self._root_fd)
        try:
            for part in relative.parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read_bytes(
        self, path: str | Path, *, missing_ok: bool = False, variants_read: Collection[str] = ()
    ) -> bytes | None:
        """Read a confined regular file, through at most one in-root symlink.

        A symlink whose lexical target is a regular file beneath the root, not
        excluded and reached without a further symlink is read through its target
        (``link_target`` names it); any other symlink is a recorded failure. With
        ``missing_ok`` an absent file is not a failure, but a case or normalisation
        variant of its name is, unless the caller reads it separately and names it
        in ``variants_read``: case-insensitive file systems open that variant.
        """
        relative: Path | str = str(path)
        try:
            relative = self._relative(path)
            if self.excluded(relative):
                return None
            if not relative.parts:
                raise CollectionError("expected a regular file")
            fd, opened = self._open_file(relative)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode):
                    raise CollectionError("not a regular file")
                if before.st_size > self.max_file_bytes:
                    raise CollectionError("file byte limit exceeded")
                if before.st_size > self.max_total_bytes - self._bytes_read:
                    raise CollectionError("total byte limit exceeded")
                chunks: list[bytes] = []
                length = 0
                while length <= self.max_file_bytes:
                    chunk = os.read(fd, min(65536, self.max_file_bytes + 1 - length))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    length += len(chunk)
                    self._bytes_read += len(chunk)
                    if self._bytes_read > self.max_total_bytes:
                        raise CollectionError("total byte limit exceeded")
                if length > self.max_file_bytes:
                    raise CollectionError("file byte limit exceeded")
                after = os.fstat(fd)
                if descriptor_binding(before) != descriptor_binding(after) or not (
                    self._resolves_to(opened, after) and self._same_link(relative, opened)
                ):
                    raise CollectionError("file changed during collection")
                return b"".join(chunks)
            finally:
                os.close(fd)
        except FileNotFoundError:
            if not missing_ok:
                self._fail(relative, "file unavailable during collection")
            elif isinstance(relative, Path):
                self._report_case_variants(relative, variants_read)
        except _LinkRefusedError as exc:
            self._fail(relative, exc.reason)
        except (OSError, CollectionError):
            # Do not echo exception payloads: malformed input may contain secrets.
            self._fail(relative, "read refused (symlink, nonregular file, limit, or I/O error)")
        return None

    def read_text(
        self, path: str | Path, *, missing_ok: bool = False, variants_read: Collection[str] = ()
    ) -> str | None:
        raw = self.read_bytes(path, missing_ok=missing_ok, variants_read=variants_read)
        if raw is None:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            self._fail(path, "invalid UTF-8")
            return None

    @contextmanager
    def open_regular(self, path: str | Path, *, max_bytes: int | None = None) -> Iterator[BinaryIO]:
        """Yield a confined regular stream or raise OSError after recording failure.

        ``max_bytes`` bounds the artifact size and bytes read; reads require an
        explicit chunk size (at most four MiB). Collection-wide budget still
        applies. The trusted consumer must not bypass read() with fileno().
        """
        relative = self._relative(path)
        limit = self.max_file_bytes if max_bytes is None else max_bytes
        try:
            if self.excluded(relative) or not relative.parts:
                raise CollectionError("file excluded by policy")
            parent = self._open_parent(relative)
            try:
                fd = os.open(
                    relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
                )
            finally:
                os.close(parent)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                    raise CollectionError("nonregular file or byte limit exceeded")
            except BaseException:
                os.close(fd)
                raise
        except (OSError, CollectionError) as exc:
            self._fail(relative, "stream refused (symlink, nonregular file, limit, or I/O error)")
            raise OSError("confined stream unavailable") from exc
        stream = _BoundedReader(fd, self, relative, limit)
        try:
            yield cast(BinaryIO, stream)
            after = os.fstat(fd)
            if descriptor_binding(before) != descriptor_binding(after) or not self._resolves_to(
                relative, after
            ):
                self._fail(relative, "file changed during collection")
                raise OSError("artifact changed during collection")
        finally:
            stream.close()

    def path_identity(self, path: str | Path) -> tuple[int, int] | None:
        """Return the device and inode a confined pathname resolves to now.

        Resolution is descriptor-relative from the pinned root and never follows
        a symlink, so a symlink at the pathname reports its own identity and
        cannot match a stream opened with ``O_NOFOLLOW``. ``None`` means the
        pathname is unavailable, excluded by policy or outside the collection
        boundary; treat it as a failed observation, never as a match.
        """
        try:
            relative = self._relative(path)
            if self.excluded(relative) or not relative.parts:
                return None
            parent = self._open_parent(relative)
            try:
                info = os.stat(relative.name, dir_fd=parent, follow_symlinks=False)
            finally:
                os.close(parent)
        except (OSError, CollectionError):
            return None
        return (info.st_dev, info.st_ino)

    def _resolves_to(self, relative: Path, info: os.stat_result) -> bool:
        # The descriptor's own status cannot reveal a replaced inode that is never
        # unlinked (an overlayfs lower layer) or an A-B-A swap during the read.
        return self.path_identity(relative) == (info.st_dev, info.st_ino)

    def hash_file(self, path: str | Path, *, max_bytes: int | None = None) -> str | None:
        """Stream SHA-256 beneath the root, with explicit individual/total bounds.

        Model collectors can choose a larger per-file limit while retaining the
        collection-wide byte budget. No artifact is deserialized or imported.
        """
        relative: Path | str = str(path)
        try:
            relative = self._relative(path)
            if self.excluded(relative):
                return None
            parent = self._open_parent(relative)
            try:
                fd = os.open(
                    relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
                )
            finally:
                os.close(parent)
            try:
                before = os.fstat(fd)
                limit = self.max_file_bytes if max_bytes is None else max_bytes
                if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                    raise CollectionError("nonregular file or byte limit exceeded")
                if before.st_size > self.max_total_bytes - self._bytes_read:
                    raise CollectionError("total byte limit exceeded")
                digest = hashlib.sha256()
                length = 0
                while length <= limit:
                    chunk = os.read(fd, min(65536, limit + 1 - length))
                    if not chunk:
                        break
                    length += len(chunk)
                    self._bytes_read += len(chunk)
                    if length > limit or self._bytes_read > self.max_total_bytes:
                        raise CollectionError("byte limit exceeded")
                    digest.update(chunk)
                after = os.fstat(fd)
                if descriptor_binding(before) != descriptor_binding(after) or not self._resolves_to(
                    relative, after
                ):
                    raise CollectionError("file changed during collection")
                return "sha256:" + digest.hexdigest()
            finally:
                os.close(fd)
        except (OSError, CollectionError):
            self._fail(relative, "hash refused (symlink, nonregular file, limit, or I/O error)")
            return None

    def read_json(
        self, path: str | Path, *, missing_ok: bool = False, variants_read: Collection[str] = ()
    ) -> Any:
        content = self.read_text(path, missing_ok=missing_ok, variants_read=variants_read)
        if content is None:
            return None
        try:
            value = json.loads(
                content,
                object_pairs_hook=_unique_object,
                parse_constant=lambda _: (_ for _ in ()).throw(CollectionError("nonfinite JSON")),
            )
            if value is None:
                raise CollectionError("null configuration")
            return value
        except (ValueError, RecursionError):
            self._fail(path, "invalid JSON or duplicate keys")
            return None

    def root_entries(self) -> list[str]:
        """Sorted names directly beneath the pinned root; nothing is opened or followed."""
        if self._root_fd is None:
            return []
        try:
            return sorted(os.listdir(self._root_fd))
        except OSError:
            self._fail(".", "root directory cannot be listed")
            return []

    def iter_files(self, directory: str | Path = ".") -> Iterator[Path]:
        """Yield root-relative file paths, never following directory symlinks.

        A ``directory`` reached through one in-root symlink is walked under its
        target's name. Inside the walk, a symlink to a regular file beneath the root
        is yielded under its own name and read through its target; one to a
        directory beneath the root is skipped, because that directory is walked
        under its own name. Every other symlink is a recorded failure.
        """
        try:
            relative = self._relative(directory)
        except CollectionError:
            self._fail(directory, "directory is outside collection root")
            return
        if self.excluded(relative) or self._root_fd is None:
            return
        try:
            fd, walked = self._open_directory(relative)
        except FileNotFoundError:
            if relative.parts:
                self._report_case_variants(relative, ())
            return
        except _LinkRefusedError as exc:
            self._fail(relative, exc.reason)
            return
        except (OSError, CollectionError):
            self._fail(relative, "directory unavailable or contains a symlink")
            return
        try:
            yield from self._walk(fd, walked, 0, self._entry_budget)
        finally:
            os.close(fd)

    def _walk(
        self, directory_fd: int, relative: Path, depth: int, budget: list[int]
    ) -> Iterator[Path]:
        if depth > self.max_depth:
            self._fail(relative, "directory depth limit exceeded")
            return
        entries: list[str] = []
        try:
            with os.scandir(directory_fd) as stream:
                for entry in stream:
                    if len(entries) >= budget[0]:
                        self._fail(relative, "directory entry limit exceeded")
                        budget[0] = 0
                        return
                    entries.append(entry.name)
            budget[0] -= len(entries)
            for name in sorted(entries):
                child = relative / name
                if self.excluded(child):
                    continue
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    try:
                        if self._walked_link(directory_fd, child):
                            yield child
                    except _LinkRefusedError as exc:
                        self._fail(child, exc.reason)
                elif stat.S_ISDIR(metadata.st_mode):
                    child_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=directory_fd,
                    )
                    try:
                        yield from self._walk(child_fd, child, depth + 1, budget)
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(metadata.st_mode):
                    yield child
                else:
                    self._fail(child, "nonregular file excluded")
        except OSError:
            self._fail(relative, "directory changed or could not be read")

    def link_target(self, path: str | Path) -> str | None:
        """The in-root target that a read of ``path`` followed, or ``None``."""
        try:
            return self._links.get(self._relative(path).as_posix())
        except CollectionError:
            return None

    def in_root_target(self, path: str | Path) -> Path | None:
        """The regular file ``path`` names, through at most one in-root symlink.

        Returns the root-relative path that holds the bytes, which is ``path`` itself
        when no symlink is involved, or ``None`` when no such regular file exists.
        Nothing is recorded.
        """
        try:
            relative = self._relative(path)
            if self._root_fd is None or not relative.parts or self.excluded(relative):
                return None
            fd, opened = self._open_file(relative)
        except (OSError, CollectionError):
            return None
        try:
            return opened if stat.S_ISREG(os.fstat(fd).st_mode) else None
        finally:
            os.close(fd)

    def is_directory(self, path: str | Path) -> bool:
        """Whether ``path`` is a directory, reached through at most one in-root symlink.

        Nothing is recorded: a caller that goes on to read or walk the path records
        any refusal then.
        """
        try:
            relative = self._relative(path)
            if self._root_fd is None or not relative.parts or self.excluded(relative):
                return False
            fd, _ = self._open_directory(relative)
        except (OSError, CollectionError):
            return False
        os.close(fd)
        return True

    def _open_no_follow(self, relative: Path) -> int:
        parent = self._open_parent(relative)
        try:
            return os.open(
                relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
            )
        finally:
            os.close(parent)

    def _open_file(self, relative: Path) -> tuple[int, Path]:
        """Open a file without following links, or through one in-root symlink."""
        try:
            return self._open_no_follow(relative), relative
        except OSError as exc:
            if exc.errno not in _LINK_ERRNOS:
                raise
            target = self._link_target(relative)
            if target is None:
                raise
        try:
            fd = self._open_no_follow(target)
        except FileNotFoundError as exc:
            raise _LinkRefusedError("symlink target is unavailable") from exc
        except OSError as exc:
            if exc.errno in _LINK_ERRNOS:
                raise _LinkRefusedError(
                    "symlink target is or passes through another symlink"
                ) from exc
            raise
        self._links[relative.as_posix()] = target.as_posix()
        return fd, target

    def _open_directory(self, relative: Path) -> tuple[int, Path]:
        """Open a directory without following links, or through one in-root symlink."""
        if self._root_fd is None:
            raise CollectionError("collection root unavailable")
        try:
            return self._open_directory_no_follow(relative), relative
        except OSError as exc:
            if exc.errno not in _LINK_ERRNOS:
                raise
            target = self._link_target(relative)
            if target is None:
                raise
        try:
            fd = self._open_directory_no_follow(target)
        except FileNotFoundError as exc:
            raise _LinkRefusedError("symlink target is unavailable") from exc
        except OSError as exc:
            if exc.errno in _LINK_ERRNOS:
                raise _LinkRefusedError(
                    "symlink target is not a directory, or is or passes through another symlink"
                ) from exc
            raise
        self._links[relative.as_posix()] = target.as_posix()
        return fd, target

    def _open_directory_no_follow(self, relative: Path) -> int:
        assert self._root_fd is not None
        fd = os.dup(self._root_fd)
        try:
            for part in relative.parts:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _link_target(self, relative: Path) -> Path | None:
        """Lexically resolve the first symlink on a confined path, or ``None`` if none.

        Every component before the link is a directory opened without following
        links, so the link's own directory holds no symlink. Raises ``_LinkRefusedError``
        when the link cannot be covered through a target beneath the root.
        """
        if self._root_fd is None:
            return None
        fd = os.dup(self._root_fd)
        try:
            for index, part in enumerate(relative.parts):
                info = os.stat(part, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    text = os.readlink(part, dir_fd=fd)
                    target = _lexical_target(Path(*relative.parts[:index]), text)
                    target = target.joinpath(*relative.parts[index + 1 :])
                    if not target.parts:
                        raise _LinkRefusedError("symlink target is the collection root")
                    if self.excluded(target):
                        raise _LinkRefusedError("symlink target is excluded from collection")
                    return target
                if index + 1 == len(relative.parts) or not stat.S_ISDIR(info.st_mode):
                    return None
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            return None
        except FileNotFoundError:
            return None
        finally:
            os.close(fd)

    def _same_link(self, relative: Path, opened: Path) -> bool:
        """Whether a followed link still names the target that was read."""
        return opened == relative or self._link_target(relative) == opened

    def _walked_link(self, directory_fd: int, child: Path) -> bool:
        """Whether a walked symlink is yielded (a file) or skipped (a directory).

        Raises ``_LinkRefusedError`` for a symlink that is not covered through an in-root
        regular file or directory reached without a further symlink.
        """
        target = _lexical_target(child.parent, os.readlink(child.name, dir_fd=directory_fd))
        if target.parts and self.excluded(target):
            raise _LinkRefusedError("symlink target is excluded from collection")
        if not target.parts:
            return False
        try:
            parent = self._open_parent(target)
            try:
                info = os.stat(target.name, dir_fd=parent, follow_symlinks=False)
            finally:
                os.close(parent)
        except FileNotFoundError as exc:
            raise _LinkRefusedError("symlink target is unavailable") from exc
        except OSError as exc:
            raise _LinkRefusedError("symlink target passes through another symlink") from exc
        if stat.S_ISREG(info.st_mode):
            return True
        if stat.S_ISDIR(info.st_mode):
            return False
        if stat.S_ISLNK(info.st_mode):
            raise _LinkRefusedError("symlink target is another symlink")
        raise _LinkRefusedError("symlink target is not a regular file or directory")

    def _names(self, fd: int, directory: Path) -> list[str] | None:
        """Entry names of an open directory, listed once per collection and bounded."""
        if directory in self._listings:
            return self._listings[directory]
        names: list[str] | None = []
        try:
            with os.scandir(fd) as stream:
                for entry in stream:
                    assert names is not None
                    if len(names) >= self.max_entries:
                        self._fail(directory, "directory entry limit exceeded")
                        names = None
                        break
                    names.append(entry.name)
        except OSError:
            self._fail(directory, "directory changed or could not be read")
            names = None
        self._listings[directory] = names
        return names

    def case_variants(self, path: str | Path) -> list[Path]:
        """Existing paths that differ from ``path`` only by case or normalisation.

        Case-insensitive file systems, the default on macOS and Windows, open such a
        variant when ``path`` itself is absent. Listings are descriptor-relative and
        no symlink is followed; a symlinked directory variant is reported as found.
        """
        try:
            relative = self._relative(path)
        except CollectionError:
            return []
        if self._root_fd is None or not relative.parts:
            return []
        found: list[Path] = []
        parts = relative.parts

        def descend(fd: int, prefix: tuple[str, ...], exact: bool) -> None:
            index = len(prefix)
            names = self._names(fd, Path(*prefix))
            wanted = fold_name(parts[index])
            for name in names or ():
                if len(found) >= _MAX_CASE_VARIANTS or fold_name(name) != wanted:
                    continue
                same = exact and name == parts[index]
                if index + 1 == len(parts):
                    if not same:
                        found.append(Path(*prefix, name))
                    continue
                try:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except OSError:
                    try:
                        linked = stat.S_ISLNK(
                            os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode
                        )
                    except OSError:
                        linked = False
                    if linked and not same:
                        found.append(Path(*prefix, name, *parts[index + 1 :]))
                    continue
                try:
                    descend(child, (*prefix, name), same)
                finally:
                    os.close(child)

        fd = os.dup(self._root_fd)
        try:
            descend(fd, (), True)
        finally:
            os.close(fd)
        return found

    def _report_case_variants(self, relative: Path, variants_read: Collection[str]) -> None:
        for variant in self.case_variants(relative):
            if variant.as_posix() in variants_read or self.excluded(variant):
                continue
            self._fail(
                variant,
                f"case variant of {relative.as_posix()} is the active file on "
                "case-insensitive file systems and is not inventoried",
            )
