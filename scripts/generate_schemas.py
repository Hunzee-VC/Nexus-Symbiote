"""Generate the published JSON Schemas from the Pydantic models.

The files under ``schemas/`` are derived artifacts: never edit them by hand.
Run ``python scripts/generate_schemas.py --write`` after changing a model, and
``--check`` (as the test suite does) to prove the committed files are current.
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.evidence import DeploymentProfile

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS: dict[str, tuple[Callable[[], dict[str, Any]], bool]] = {
    "schemas/nexus-symbiote-aibom-1.0.schema.json": (AIBOM.model_json_schema, False),
    "schemas/deployment-profile-1.0.schema.json": (DeploymentProfile.model_json_schema, True),
}


def render(relative: str) -> str:
    factory, sort_keys = SCHEMAS[relative]
    return json.dumps(factory(), indent=2, sort_keys=sort_keys) + "\n"


def stale(root: Path = ROOT) -> dict[str, str]:
    """Map each out-of-date schema path to a unified diff against the generated text."""
    result: dict[str, str] = {}
    for relative in SCHEMAS:
        path = root / relative
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        expected = render(relative)
        if current != expected:
            result[relative] = "".join(
                difflib.unified_diff(
                    current.splitlines(keepends=True),
                    expected.splitlines(keepends=True),
                    f"{relative} (committed)",
                    f"{relative} (generated)",
                )
            )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="rewrite stale schema files")
    mode.add_argument("--check", action="store_true", help="exit 1 when a schema file is stale")
    args = parser.parse_args(argv)
    differences = stale()
    if args.write:
        for relative in differences:
            (ROOT / relative).write_text(render(relative), encoding="utf-8")
            print(f"wrote {relative}")
        return 0
    for diff in differences.values():
        sys.stdout.write(diff)
    return int(bool(differences))


if __name__ == "__main__":
    raise SystemExit(main())
