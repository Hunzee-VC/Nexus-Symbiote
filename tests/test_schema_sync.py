"""The published JSON Schemas are exactly what the Pydantic models generate."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "generate_schemas", ROOT / "scripts" / "generate_schemas.py"
)
assert SPEC is not None and SPEC.loader is not None
generate_schemas = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generate_schemas)


def test_committed_schemas_match_the_models() -> None:
    differences = generate_schemas.stale()
    assert not differences, (
        "schemas are stale; run python scripts/generate_schemas.py --write\n"
        + "\n".join(differences.values())
    )


def test_stale_schema_is_detected(tmp_path: Path) -> None:
    (tmp_path / "schemas").mkdir()
    for relative in generate_schemas.SCHEMAS:
        (tmp_path / relative).write_text(generate_schemas.render(relative), encoding="utf-8")
    assert generate_schemas.stale(tmp_path) == {}
    target = next(iter(generate_schemas.SCHEMAS))
    (tmp_path / target).write_text("{}\n", encoding="utf-8")
    assert list(generate_schemas.stale(tmp_path)) == [target]
