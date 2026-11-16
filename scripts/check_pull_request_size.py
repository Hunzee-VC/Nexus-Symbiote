"""Fail a pull request that changes more than the cap outside tests and benchmarks.

The count is insertions plus deletions. ``tests/`` and ``benchmarks/`` are excluded
so a regression suite can be large. A binary file, which git reports as ``-``, is
not counted in a tree where binaries are expected, and fails the check anywhere else,
since its change cannot be measured. Run it in CI against the pull request's base, or
pass ``--numstat-file`` for a review of a saved ``git diff --numstat`` listing.

The pull request controls its own ``.gitattributes``, which would let ``src/** -diff``
report every source change as binary, so git reads attributes from the base instead;
renames are not detected, so a move out of ``tests/`` counts at its destination.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

SKIP_PREFIXES = ("tests/", "benchmarks/")
# Trees whose binary files, such as images and model fixtures, are expected.
BINARY_PREFIXES = (*SKIP_PREFIXES, "docs/assets/", "examples/")
DEFAULT_LIMIT = 1500


class UnmeasuredChangeError(ValueError):
    """A binary change outside the trees where binaries are expected."""


def changed_lines(numstat: str, *, skip_prefixes: tuple[str, ...] = SKIP_PREFIXES) -> int:
    """Sum insertions and deletions, skipping test trees and binary rows."""
    total = 0
    for line in numstat.splitlines():
        if not line.strip():
            continue
        added, deleted, path = line.split("\t", 2)
        if path.startswith(skip_prefixes):
            continue
        if added == "-" or deleted == "-":
            if not path.startswith(BINARY_PREFIXES):
                raise UnmeasuredChangeError(
                    f"binary change outside {', '.join(BINARY_PREFIXES)}: {path!r}"
                )
            continue
        total += int(added) + int(deleted)
    return total


def _from_git(base: str) -> str:
    result = subprocess.run(  # noqa: S603
        ["git", f"--attr-source={base}", "diff", "--numstat", "--no-renames", base, "HEAD"],  # noqa: S607
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(result.stderr.strip() or "git diff failed")
    return result.stdout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="Git ref to diff HEAD against, such as origin/main")
    parser.add_argument("--numstat-file", type=Path, help="A saved git diff --numstat listing")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    args = parser.parse_args(argv)
    if (args.base is None) == (args.numstat_file is None):
        parser.error("pass exactly one of --base and --numstat-file")
    listing = (
        args.numstat_file.read_text(encoding="utf-8") if args.numstat_file else _from_git(args.base)
    )
    try:
        total = changed_lines(listing)
    except UnmeasuredChangeError as exc:
        print(f"pull request size cannot be measured: {exc}")
        return 1
    print(f"pull request changes {total} lines outside tests/ and benchmarks/ (limit {args.limit})")
    return 1 if total > args.limit else 0


if __name__ == "__main__":
    raise SystemExit(main())
