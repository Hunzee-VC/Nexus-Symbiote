"""Bounded local collection with descriptor-relative, no-symlink reads.

This is an offline collector boundary, not a process sandbox. It requires POSIX
``dir_fd`` and ``O_NOFOLLOW`` support and fails closed where unavailable. Its
size, entry and depth bounds are the operator limits in ``nexus_symbiote.limits``
unless a caller passes a fixed bound for a particular input.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
import stat
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO, cast

from nexus_symbiote import limits
from nexus_symbiote.core.hashing import descriptor_binding
from nexus_symbiote.limits import Bound

# Defaults only: a collection reads the operator's current limits when it is created.
MAX_FILE_BYTES = limits.DEFAULTS.file_bytes
MAX_ENTRIES = limits.DEFAULTS.entries
MAX_DEPTH = limits.DEFAULTS.depth
MAX_TOTAL_BYTES = limits.DEFAULTS.total_bytes
MAX_HASH_BYTES = limits.DEFAULTS.model_bytes
DEFAULT_EXCLUDES = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv"})
_MAX_CHUNK_BYTES = 4 * 1024 * 1024


class CollectionError(ValueError):
    """A collection input exceeded the supported safe boundary."""


class LimitExceededError(CollectionError):
    """A read would pass one of the collection's bounds."""

    def __init__(self, bound: Bound) -> None:
        super().__init__(bound.exceeded())
        self.bound = bound


def _bound(value: int | Bound | None, name: str) -> Bound:
    if value is None:
        return limits.bound(name)
    if isinstance(value, Bound):
        return value
    return Bound(value, name, configurable=False)


class ByteBudget:
    """Bytes read so far against one named total bound."""

    def __init__(self, bound: Bound) -> None:
        self.bound = bound
        self.used = 0
        self.exhausted = False

    def remaining(self) -> int:
        return self.bound.value - self.used

    def refuse(self) -> LimitExceededError:
        self.exhausted = True
        return LimitExceededError(self.bound)

    def charge(self, count: int) -> None:
        self.used += count
        if self.used > self.bound.value:
            raise self.refuse()


class _MessageLog:
    """Appends each message once to a caller's list, at constant cost per message.

    A walk can record one message per entry, so a membership test on the list
    itself would make a large tree quadratic. Entries the caller appends to the
    list directly are taken into account before the next message.
    """

    def __init__(self, messages: list[str]) -> None:
        self.messages = messages
        self._seen = set(messages)
        self._synced = len(messages)

    def add(self, message: str) -> None:
        if len(self.messages) < self._synced:
            self._seen = set(self.messages)
        else:
            self._seen.update(self.messages[self._synced :])
        if message not in self._seen:
            self._seen.add(message)
            self.messages.append(message)
        self._synced = len(self.messages)


def _undecodable(name: str) -> bool:
    return any("\ud800" <= character <= "\udfff" for character in name)


def _escaped(name: str) -> str:
    """Show the bytes a non-UTF-8 name was decoded from, without lone surrogates."""
    return "".join(
        f"\\x{ord(character) - 0xDC00:02x}"
        if "\udc80" <= character <= "\udcff"
        else f"\\u{ord(character):04x}"
        if "\ud800" <= character <= "\udfff"
        else character
        for character in name
    )


def _refuse_constant(_: str) -> Any:
    raise CollectionError("nonfinite JSON")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise CollectionError("nonfinite JSON")
    return value


def hash_confined_file(root: Path, source_path: str | Path, algorithm: str = "sha256") -> str:
    """Compatibility hash API for a BOM-supplied path beneath a caller root."""
    if algorithm not in {"sha256", "sha384", "sha512"}:
        raise OSError("unsupported security hash algorithm")
    model_bytes = limits.bound("model-bytes")
    try:
        with (
            ConfinedCollection(root, [], max_total_bytes=model_bytes) as files,
            files.open_regular(source_path, max_bytes=model_bytes) as stream,
        ):
            digest = hashlib.new(algorithm)
            while chunk := stream.read(65536):
                digest.update(chunk)
            return f"{algorithm}:{digest.hexdigest()}"
    except (CollectionError, ValueError) as exc:
        raise OSError("confined artifact hash refused") from exc


class _BoundedReader(io.RawIOBase):
    """Explicit-size reads only; enforce both stream and collection budgets."""

    def __init__(
        self, fd: int, owner: ConfinedCollection, path: Path, limit: Bound, budget: ByteBudget
    ) -> None:
        self._fd = fd
        self._owner = owner
        self._path = path
        self._limit = limit
        self._budget = budget
        self._read = 0

    def readable(self) -> bool:
        return True

    def fileno(self) -> int:
        return self._fd

    def read(self, size: int = -1) -> bytes:
        if self.closed:
            raise ValueError("read of closed collection stream")
        if not 0 <= size <= _MAX_CHUNK_BYTES:
            raise CollectionError("explicit bounded read size required")
        try:
            raw = os.read(self._fd, min(size, self._limit.value + 1 - self._read))
        except OSError:
            self._owner._fail(self._path, "stream read failed (I/O error)")
            raise
        self._read += len(raw)
        try:
            if self._read > self._limit.value:
                raise LimitExceededError(self._limit)
            self._budget.charge(len(raw))
        except LimitExceededError as exc:
            self._owner._fail(self._path, exc.bound.exceeded())
            raise
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

    Limits cover individual file bytes, the bytes read in total, directory entries
    over the complete walk, and directory depth. A limit left unset is the
    operator's current one (``nexus_symbiote.limits``); an integer is a fixed bound
    for this input. Reaching any limit records a failure that names it. A
    directory exceeding the entry budget is not partially returned. Within those
    bounds traversal is lexical and deterministic.
    """

    def __init__(
        self,
        root: Path,
        failures: list[str],
        exclusions: list[str] | None = None,
        *,
        exclude_paths: Iterable[str | Path] = (),
        max_file_bytes: int | Bound | None = None,
        max_entries: int | Bound | None = None,
        max_depth: int | Bound | None = None,
        max_total_bytes: int | Bound | None = None,
    ) -> None:
        requested = Path(root)
        # Kept unnormalized so ".." is walked through the real parent, as the kernel
        # resolves it, instead of being collapsed textually past a symlink.
        self._requested_root = requested if requested.is_absolute() else Path.cwd() / requested
        self.root = Path(os.path.abspath(self._requested_root))
        self.failures = failures
        self.exclusions = exclusions if exclusions is not None else []
        self._failure_log = _MessageLog(self.failures)
        self._exclusion_log = _MessageLog(self.exclusions)
        self._file_bound = _bound(max_file_bytes, "file-bytes")
        self._entry_bound = _bound(max_entries, "entries")
        self._depth_bound = _bound(max_depth, "depth")
        self._budget = ByteBudget(_bound(max_total_bytes, "total-bytes"))
        self.max_file_bytes = self._file_bound.value
        self.max_entries = self._entry_bound.value
        self.max_depth = self._depth_bound.value
        self.max_total_bytes = self._budget.bound.value
        self._entry_budget = [self.max_entries]
        self._entries_exhausted = False
        self._root_fd: int | None = None
        self._excluded: set[tuple[str, ...]] = set()
        self._invalid_policy = False
        root_text = str(self.root)
        prefix = root_text.rstrip(os.sep) + os.sep
        for value in exclude_paths:
            # String operations keep a long exclusion list linear and cheap to load.
            candidate = os.path.abspath(os.path.join(root_text, os.fspath(value)))
            if candidate == root_text:
                self._excluded.add(())
            elif candidate.startswith(prefix):
                self._excluded.add(tuple(candidate[len(prefix) :].split(os.sep)))
            else:
                self._fail(".", "excluded path is outside collection root")
                self._invalid_policy = True

    def __enter__(self) -> ConfinedCollection:
        if self._invalid_policy:
            return self
        if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
            self._fail(".", "no-follow descriptor-relative collection unsupported")
            return self
        current: int | None = None
        try:
            current = os.open(self._requested_root.anchor, os.O_RDONLY | os.O_DIRECTORY)
            for part in self._requested_root.parts[1:]:
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
        self._failure_log.add(f"{path!s}: {reason}")

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
        parts = relative.parts
        # Dependency caches, virtual environments and Git internals are outside
        # the documented static scope. The BOM records these patterns. Any
        # further omission within that scope is a blocking coverage gap.
        if any(part in DEFAULT_EXCLUDES for part in parts):
            return True
        denied = bool(self._excluded) and any(
            parts[:index] in self._excluded for index in range(len(parts) + 1)
        )
        if denied:
            self._exclusion_log.add(f"{relative}: excluded by collection policy")
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

    def read_bytes(self, path: str | Path, *, missing_ok: bool = False) -> bytes | None:
        relative: Path | str = str(path)
        try:
            relative = self._relative(path)
            if self.excluded(relative):
                return None
            if not relative.parts:
                raise CollectionError("expected a regular file")
            parent = self._open_parent(relative)
            try:
                fd = os.open(
                    relative.name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=parent,
                )
            finally:
                os.close(parent)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode):
                    raise CollectionError("not a regular file")
                limit = self._file_bound
                budget = self._budget
                if before.st_size > limit.value:
                    raise LimitExceededError(limit)
                if before.st_size > budget.remaining():
                    raise budget.refuse()
                chunks: list[bytes] = []
                length = 0
                while length <= limit.value:
                    chunk = os.read(fd, min(65536, limit.value + 1 - length))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    length += len(chunk)
                    budget.charge(len(chunk))
                if length > limit.value:
                    raise LimitExceededError(limit)
                after = os.fstat(fd)
                if descriptor_binding(before) != descriptor_binding(after) or not self._resolves_to(
                    relative, after
                ):
                    raise CollectionError("file changed during collection")
                return b"".join(chunks)
            finally:
                os.close(fd)
        except FileNotFoundError:
            if not missing_ok:
                self._fail(relative, "file unavailable during collection")
        except LimitExceededError as exc:
            self._fail(relative, exc.bound.exceeded())
        except (OSError, CollectionError):
            # Do not echo exception payloads: malformed input may contain secrets.
            self._fail(relative, "read refused (symlink, nonregular file or I/O error)")
        return None

    def read_text(self, path: str | Path, *, missing_ok: bool = False) -> str | None:
        raw = self.read_bytes(path, missing_ok=missing_ok)
        if raw is None:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            self._fail(path, "invalid UTF-8")
            return None

    @contextmanager
    def separate_budget(self, bound: Bound) -> Iterator[ByteBudget]:
        """Charge reads inside the block to their own named budget, not the collection's."""
        previous = self._budget
        self._budget = ByteBudget(bound)
        try:
            yield self._budget
        finally:
            self._budget = previous

    @contextmanager
    def open_regular(
        self, path: str | Path, *, max_bytes: int | Bound | None = None
    ) -> Iterator[BinaryIO]:
        """Yield a confined regular stream or raise OSError after recording failure.

        ``max_bytes`` bounds the artifact size and bytes read; reads require an
        explicit chunk size (at most four MiB). Collection-wide budget still
        applies. The trusted consumer must not bypass read() with fileno().
        """
        relative = self._relative(path)
        limit = self._file_bound if max_bytes is None else _bound(max_bytes, "file-bytes")
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
                if not stat.S_ISREG(before.st_mode):
                    raise CollectionError("nonregular file")
                if before.st_size > limit.value:
                    raise LimitExceededError(limit)
            except BaseException:
                os.close(fd)
                raise
        except LimitExceededError as exc:
            self._fail(relative, exc.bound.exceeded())
            raise OSError("confined stream unavailable") from exc
        except (OSError, CollectionError) as exc:
            self._fail(relative, "stream refused (symlink, nonregular file or I/O error)")
            raise OSError("confined stream unavailable") from exc
        stream = _BoundedReader(fd, self, relative, limit, self._budget)
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

    def hash_file(self, path: str | Path, *, max_bytes: int | Bound | None = None) -> str | None:
        """Stream SHA-256 beneath the root, with explicit individual/total bounds.

        Model collectors can choose a larger per-file limit while retaining the
        collection-wide byte budget. No artifact is deserialized or imported.
        """
        relative: Path | str = str(path)
        limit = self._file_bound if max_bytes is None else _bound(max_bytes, "file-bytes")
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
                budget = self._budget
                if not stat.S_ISREG(before.st_mode):
                    raise CollectionError("nonregular file")
                if before.st_size > limit.value:
                    raise LimitExceededError(limit)
                if before.st_size > budget.remaining():
                    raise budget.refuse()
                digest = hashlib.sha256()
                length = 0
                while length <= limit.value:
                    chunk = os.read(fd, min(65536, limit.value + 1 - length))
                    if not chunk:
                        break
                    length += len(chunk)
                    if length > limit.value:
                        raise LimitExceededError(limit)
                    budget.charge(len(chunk))
                    digest.update(chunk)
                after = os.fstat(fd)
                if descriptor_binding(before) != descriptor_binding(after) or not self._resolves_to(
                    relative, after
                ):
                    raise CollectionError("file changed during collection")
                return "sha256:" + digest.hexdigest()
            finally:
                os.close(fd)
        except LimitExceededError as exc:
            self._fail(relative, exc.bound.exceeded())
            return None
        except (OSError, CollectionError):
            self._fail(relative, "hash refused (symlink, nonregular file or I/O error)")
            return None

    def read_json(self, path: str | Path, *, missing_ok: bool = False) -> Any:
        content = self.read_text(path, missing_ok=missing_ok)
        if content is None:
            return None
        try:
            value = json.loads(
                content,
                object_pairs_hook=_unique_object,
                parse_constant=_refuse_constant,
                parse_float=_finite_float,
            )
            if value is None:
                raise CollectionError("null configuration")
            return value
        except (ValueError, RecursionError):
            self._fail(path, "invalid JSON or duplicate keys")
            return None

    def root_entries(self) -> list[str]:
        """Sorted names directly beneath the pinned root; nothing is opened or followed.

        The listing is charged to the same entry budget as a walk.
        """
        if self._root_fd is None:
            return []
        names: list[str] = []
        if self._entries_exhausted:
            return []
        try:
            with os.scandir(self._root_fd) as stream:
                for entry in stream:
                    if len(names) >= self._entry_budget[0]:
                        self._entries_exceeded(Path("."))
                        return []
                    names.append(entry.name)
        except OSError:
            self._fail(".", "root directory cannot be listed")
            return []
        self._entry_budget[0] -= len(names)
        return sorted(names)

    def _entries_exceeded(self, relative: Path) -> None:
        # One failure names where the walk stopped; later listings stop silently.
        self._fail(relative, self._entry_bound.exceeded())
        self._entry_budget[0] = 0
        self._entries_exhausted = True

    def iter_files(self, directory: str | Path = ".") -> Iterator[Path]:
        """Yield root-relative file paths, never following directory symlinks."""
        try:
            relative = self._relative(directory)
        except CollectionError:
            self._fail(directory, "directory is outside collection root")
            return
        if self.excluded(relative) or self._root_fd is None:
            return
        fd = os.dup(self._root_fd)
        try:
            for part in relative.parts:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            yield from self._walk(fd, relative, 0, self._entry_budget)
        except FileNotFoundError:
            return
        except OSError:
            self._fail(relative, "directory unavailable or contains a symlink")
        finally:
            os.close(fd)

    def _walk(
        self, directory_fd: int, relative: Path, depth: int, budget: list[int]
    ) -> Iterator[Path]:
        if depth > self.max_depth:
            self._fail(relative, self._depth_bound.exceeded())
            return
        if self._entries_exhausted:
            return
        entries: list[str] = []
        try:
            with os.scandir(directory_fd) as stream:
                for entry in stream:
                    if len(entries) >= budget[0]:
                        self._entries_exceeded(relative)
                        return
                    entries.append(entry.name)
            budget[0] -= len(entries)
            for name in sorted(entries):
                if _undecodable(name):
                    # A surrogate-escaped name cannot be written to, or read back from,
                    # an inventory; the entry and anything beneath it are a gap.
                    self._fail(relative / _escaped(name), "name is not valid UTF-8; not collected")
                    continue
                child = relative / name
                if self.excluded(child):
                    continue
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    self._fail(child, "symlink excluded")
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
