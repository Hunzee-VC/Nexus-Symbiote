"""Fail a PR above the line cap outside tests, benchmarks and reviewed binary assets.

Measure insertions plus deletions between immutable event base/head commit IDs.
Saved listings must use Git's --numstat -z --no-renames format. Rename records
are accepted only when they do not cross an excluded-tree boundary.
Unexpected binary changes fail closed: .gitattributes cannot hide source edits.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

SKIP_PREFIXES = (b"tests/", b"benchmarks/")
BINARY_ASSET_SUFFIXES = (b".jpg", b".jpeg", b".png", b".gif", b".webp", b".ico")
DEFAULT_LIMIT = 1500
MAX_NUMSTAT_BYTES = 64 * 1024 * 1024
COMMIT = re.compile(r"[0-9a-f]{40}")


def _validate_path(path: bytes) -> None:
    if any(part in (b"", b".", b"..") for part in path.split(b"/")):
        raise ValueError(f"non-canonical path in numstat record: {path!r}")


def changed_lines(numstat: bytes) -> int:
    """Read the NUL protocol without interpreting quotes, tabs or newlines in paths."""
    if not numstat:
        return 0
    if not numstat.endswith(b"\0"):
        raise ValueError("expected a complete git diff --numstat -z listing")
    records = iter(numstat[:-1].split(b"\0"))
    total = 0
    for record in records:
        fields = record.split(b"\t", 2)
        if len(fields) != 3:
            raise ValueError("malformed numstat record")
        added, deleted, path = fields
        paths: tuple[bytes, ...]
        if path:
            paths = (path,)
        else:
            try:
                paths = (next(records), next(records))
            except StopIteration as exc:
                raise ValueError("incomplete numstat rename record") from exc
            if not all(paths):
                raise ValueError("empty path in numstat rename record")
        for candidate in paths:
            _validate_path(candidate)
        binary = added == deleted == b"-"
        if not binary and not (added.isdigit() and deleted.isdigit()):
            raise ValueError("invalid numstat line counts")
        excluded = [candidate.startswith(SKIP_PREFIXES) for candidate in paths]
        if all(excluded):
            continue
        if any(excluded):
            raise ValueError("cross-boundary rename needs whole-file counts; use --no-renames")
        if binary:
            if all(
                candidate.startswith(b"docs/assets/") and candidate.endswith(BINARY_ASSET_SUFFIXES)
                for candidate in paths
            ):
                continue
            raise ValueError(
                f"unexpected binary change: {paths!r}; source changes must be countable"
            )
        total += int(added) + int(deleted)
    return total


def _from_git(base: str, head: str) -> bytes:
    if not COMMIT.fullmatch(base) or not COMMIT.fullmatch(head):
        raise ValueError("--base and --head must be full immutable commit IDs")
    git = shutil.which("git")
    if git is None:
        raise ValueError("git executable is unavailable")
    result = subprocess.run(  # noqa: S603 - resolved git executable, fixed flags and validated 40-hex commit IDs
        [
            git,
            "diff",
            "--numstat",
            "-z",
            "--no-renames",
            "--no-relative",
            "--no-ext-diff",
            "--no-textconv",
            base,
            head,
            "--",
        ],
        check=False,
        capture_output=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise ValueError(
            result.stderr.decode("utf-8", errors="replace").strip() or "git diff failed"
        )
    return result.stdout


def _read_numstat_file(path: Path) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(MAX_NUMSTAT_BYTES + 1)
    if len(data) > MAX_NUMSTAT_BYTES:
        raise ValueError(f"numstat listing exceeds {MAX_NUMSTAT_BYTES} bytes")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="Full immutable PR event base commit ID")
    parser.add_argument("--head", help="Full immutable PR event head commit ID")
    parser.add_argument("--numstat-file", type=Path, help="A saved git diff --numstat -z listing")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    args = parser.parse_args(argv)
    if args.limit < 0:
        parser.error("--limit must be nonnegative")
    if args.numstat_file is not None:
        if args.base is not None or args.head is not None:
            parser.error("--numstat-file cannot be combined with --base or --head")
    elif args.base is None or args.head is None:
        parser.error("pass both --base and --head, or --numstat-file")
    try:
        if args.numstat_file is not None:
            listing = _read_numstat_file(args.numstat_file)
        else:
            assert args.base is not None and args.head is not None
            listing = _from_git(args.base, args.head)
        total = changed_lines(listing)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"pull request size check failed: {exc}", file=sys.stderr)
        return 1
    print(f"pull request changes {total} lines outside tests/ and benchmarks/ (limit {args.limit})")
    return 1 if total > args.limit else 0


if __name__ == "__main__":
    raise SystemExit(main())
