"""Emit and validate the companion document."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from symbiote.digest.envelope import digest_str
from symbiote.model.document import AgentBOM
from symbiote.model.entities import LossReport
from symbiote.model.schema import companion_json_schema

COMPANION_SCHEMA_PATH = "schemas/agentbom/agentbom-0.1.schema.json"


class CompanionValidationError(ValueError):
    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("; ".join(errors[:5]) + (f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""))


@lru_cache(maxsize=1)
def load_companion_schema() -> dict[str, Any]:
    """The committed schema shipped in the wheel; falls back to the generated one if the resource is missing."""
    try:
        text = resources.files("symbiote").joinpath(COMPANION_SCHEMA_PATH).read_text(encoding="utf-8")
        return json.loads(text)
    except (FileNotFoundError, OSError):  # pragma: no cover - defensive for odd installs
        return companion_json_schema()


def validate_companion(data: dict[str, Any]) -> list[str]:
    """Return schema violations (empty when valid)."""
    validator = Draft202012Validator(load_companion_schema())
    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '$'}: {e.message}"
        for e in sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
    ]


def companion_bytes(bom: AgentBOM, *, indent: int | None = 2, validate: bool = True) -> bytes:
    """Deterministic companion JSON: sorted collections, sorted keys, UTF-8, trailing newline."""
    data = bom.sorted().to_json_dict()
    if validate:
        errors = validate_companion(data)
        if errors:
            raise CompanionValidationError(errors)
    text = json.dumps(
        data,
        indent=indent,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ": ") if indent else (",", ":"),
    )
    return (text + "\n").encode("utf-8")


def companion_digest(data: bytes) -> str:
    return digest_str(data)


def export_companion(bom: AgentBOM) -> tuple[bytes, LossReport]:
    """The companion is the model itself, so the loss report is always empty."""
    payload = companion_bytes(bom)
    report = LossReport(
        direction="model→companion",
        source_format="agentbom-model",
        target_format="agentbom-companion",
        model_digest=bom.snapshot.digest,
    )
    return payload, report


def load_companion(source: bytes | str | Path) -> AgentBOM:
    """Parse and validate a companion document (bytes, JSON text or path)."""
    if isinstance(source, Path):
        raw = source.read_bytes()
    elif isinstance(source, str):
        raw = source.encode("utf-8") if source.lstrip().startswith("{") else Path(source).read_bytes()
    else:
        raw = source
    data = json.loads(raw.decode("utf-8"))
    errors = validate_companion(data)
    if errors:
        raise CompanionValidationError(errors)
    return AgentBOM.model_validate(data)


__all__ = [
    "COMPANION_SCHEMA_PATH",
    "CompanionValidationError",
    "companion_bytes",
    "companion_digest",
    "export_companion",
    "load_companion",
    "load_companion_schema",
    "validate_companion",
]
