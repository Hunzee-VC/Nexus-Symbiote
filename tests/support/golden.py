"""Byte-identical golden files (I7): compare exactly, regenerate explicitly.

Usage::

    from tests.support import assert_golden, assert_golden_json

    assert_golden("companion/minimal.agentbom.json", sealed.model_dump_json(by_alias=True, indent=2))

Regenerate after an intentional output change::

    UPDATE_GOLDENS=1 python -m pytest tests -q   # then review the diff and commit the goldens

A missing golden fails with instructions rather than silently creating one: goldens enter the
repository through a reviewed commit, never through a green CI run.
"""

from __future__ import annotations

import difflib
import json
import os
from pathlib import Path
from typing import Any

GOLDEN_ROOT = Path(__file__).resolve().parent.parent / "golden"
_UPDATE_ENV = "UPDATE_GOLDENS"


def golden_path(relpath: str) -> Path:
    path = (GOLDEN_ROOT / relpath).resolve()
    if GOLDEN_ROOT not in path.parents and path != GOLDEN_ROOT:
        raise ValueError(f"golden path escapes {GOLDEN_ROOT}: {relpath!r}")
    return path


def _updating() -> bool:
    return os.environ.get(_UPDATE_ENV, "") not in ("", "0", "false")


def assert_golden(relpath: str, content: bytes | str) -> None:
    """Compare ``content`` byte-for-byte against the golden at ``tests/golden/<relpath>``."""
    data = content.encode("utf-8") if isinstance(content, str) else content
    if not data.endswith(b"\n"):
        data += b"\n"
    path = golden_path(relpath)
    if _updating():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return
    if not path.exists():
        raise AssertionError(
            f"golden file missing: {path}\n"
            f"Run `UPDATE_GOLDENS=1 python -m pytest {_caller_hint()}`, review the new file, commit it."
        )
    expected = path.read_bytes()
    if expected == data:
        return
    try:
        diff = "\n".join(
            difflib.unified_diff(
                expected.decode("utf-8").splitlines(),
                data.decode("utf-8").splitlines(),
                fromfile=f"golden/{relpath}",
                tofile="actual",
                lineterm="",
                n=3,
            )
        )
    except UnicodeDecodeError:
        diff = f"binary mismatch: {len(expected)} golden bytes vs {len(data)} actual bytes"
    raise AssertionError(
        f"output differs from golden {relpath} (intentional? UPDATE_GOLDENS=1, review, commit):\n{diff}"
    )


def assert_golden_json(relpath: str, obj: Any) -> None:
    """Golden comparison for JSON-able data with a canonical, review-friendly rendering."""
    assert_golden(relpath, json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False))


def _caller_hint() -> str:
    return "tests -q"


__all__ = ["GOLDEN_ROOT", "assert_golden", "assert_golden_json", "golden_path"]
