"""No Python source, tests included, holds a character a reviewer cannot see.

`make hygiene` refuses a literal bidirectional or zero-width character outside `tests/`
and `benchmarks/`. Tests held them too, where a reversed or hidden run of text in an
assertion reads as something else; they are written as escapes, and the linter refuses
a literal one in every Python file it checks.
"""

from __future__ import annotations

import shutil
import subprocess
import tomllib
import unicodedata
from pathlib import Path

import pytest

from tests.support import ROOT


def test_the_linter_refuses_bidirectional_and_invisible_control_characters():
    selected = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["ruff"][
        "lint"
    ]["select"]
    assert {"PLE2502", "PLE2510", "PLE2512", "PLE2513", "PLE2514", "PLE2515"} <= set(selected)


def test_no_tracked_python_file_holds_a_literal_format_or_separator_character():
    if not (ROOT / ".git").exists():
        pytest.skip("needs a Git checkout; an unpacked sdist has no tracked-file list")
    listing = subprocess.run(  # noqa: S603 - fixed read-only Git operation
        [shutil.which("git") or "git", "-C", str(ROOT), "ls-files", "-z", "*.py"],
        capture_output=True,
        check=True,
        timeout=30,
    )
    found = []
    for name in filter(None, listing.stdout.decode().split("\0")):
        lines = (ROOT / name).read_text(encoding="utf-8").split("\n")
        for number, line in enumerate(lines, 1):
            points = sorted(
                {f"U+{ord(c):04X}" for c in line if unicodedata.category(c) in {"Cf", "Zl", "Zp"}}
            )
            if points:
                found.append(f"{Path(name)}:{number}: {', '.join(points)}")
    assert found == []
