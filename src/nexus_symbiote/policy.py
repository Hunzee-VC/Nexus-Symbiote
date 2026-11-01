"""Policy configuration — explicit policy files, discovery, and defaults."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator
from pydantic_core import PydanticCustomError

from nexus_symbiote.core.vocab import SCANNER_NAMES
from nexus_symbiote.scanners.base import DEFAULT_EXCLUDE_PATHS
from nexus_symbiote.utils.fsio import MAX_CONFIG_BYTES, read_regular_text

_POLICY_FILE_NAMES = (".nexus-symbiote.yaml", ".nexus-symbiote.yml")
_MAX_DISCOVERY_LEVELS = 20


class PolicyError(ValueError):
    """A policy file could not be read, parsed, or validated. Messages never quote its contents."""


class ScanPolicy(BaseModel):
    model_config = {"extra": "forbid"}

    scanners: list[str] = Field(default_factory=lambda: list(SCANNER_NAMES))
    exclude_paths: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDE_PATHS))

    @field_validator("scanners")
    @classmethod
    def known_scanners(cls, value: list[str]) -> list[str]:
        if any(name not in SCANNER_NAMES for name in value):
            raise PydanticCustomError("unknown_scanner", "scanner name is not registered")
        return value


class RiskPolicy(BaseModel):
    model_config = {"extra": "forbid"}

    fail_threshold: float = Field(default=50.0, ge=0, le=100)
    warn_threshold: float = Field(default=25.0, ge=0, le=100)
    ignore_categories: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def warn_within_fail(self) -> RiskPolicy:
        if self.warn_threshold > self.fail_threshold:
            raise PydanticCustomError("threshold_order", "warn_threshold exceeds fail_threshold")
        return self


class ValidatePolicy(BaseModel):
    model_config = {"extra": "forbid"}

    require_completeness: bool = True
    require_integrity: bool = True
    minimum_assurance_level: Literal["declared", "observed", "verified"] = "declared"


class OutputPolicy(BaseModel):
    model_config = {"extra": "forbid"}

    default_format: Literal["json", "cyclonedx", "spdx", "sarif"] = "json"


class Policy(BaseModel):
    model_config = {"populate_by_name": True, "extra": "forbid"}

    version: str = "1.0"
    scan: ScanPolicy = Field(default_factory=ScanPolicy)
    risk: RiskPolicy = Field(default_factory=RiskPolicy)
    validation: ValidatePolicy = Field(default_factory=ValidatePolicy, alias="validate")
    output: OutputPolicy = Field(default_factory=OutputPolicy)


def default_policy() -> Policy:
    return Policy()


def load_policy_file(path: Path) -> Policy:
    """Load an explicit policy file. Symbolic links and oversized files are refused."""
    try:
        import yaml
    except ImportError as exc:
        raise PolicyError("requires PyYAML: install nexus-symbiote[yaml]") from exc

    try:
        text = read_regular_text(path, max_bytes=MAX_CONFIG_BYTES)
    except (OSError, UnicodeError):
        raise PolicyError(
            f"cannot read policy file {path}: not a regular UTF-8 file within the size limit"
        ) from None

    try:
        data: Any = yaml.safe_load(text)
    except yaml.YAMLError:
        raise PolicyError(f"policy file {path} is not valid YAML") from None
    if not isinstance(data, dict):
        raise PolicyError(f"policy file {path} must contain a mapping at the top level")

    try:
        return Policy.model_validate(data)
    except ValidationError as exc:
        failures = "; ".join(_describe_error(error) for error in exc.errors())
        raise PolicyError(f"invalid policy file {path}: {failures}") from None


def discover_policy(start: Path) -> Path | None:
    """Return the nearest policy file at or above start. The file is not loaded."""
    current = start.resolve()
    for _ in range(_MAX_DISCOVERY_LEVELS):
        for name in _POLICY_FILE_NAMES:
            candidate = current / name
            if _is_regular_file(candidate):
                return candidate
        if current.parent == current:
            break
        current = current.parent
    return None


def _is_regular_file(path: Path) -> bool:
    try:
        return not path.is_symlink() and path.is_file()
    except OSError:
        return False


def _describe_error(error: Mapping[str, Any]) -> str:
    location = ".".join(str(part) for part in error.get("loc", ())) or "policy"
    return f"{location}: {error.get('type', 'invalid')}"


DEFAULT_POLICY_YAML = """\
# Nexus SymBiote policy configuration
# https://github.com/aisecnomad/nexus-symbiote
version: "1.0"

scan:
  scanners: ["a2a", "ide_agents", "mcp", "model", "prompt", "rag", "registry", "shadowscan"]
  exclude_paths: ["node_modules", ".git", "__pycache__", ".venv"]

risk:
  fail_threshold: 50.0
  warn_threshold: 25.0
  ignore_categories: []

validate:
  require_completeness: true
  require_integrity: true
  minimum_assurance_level: "declared"

output:
  default_format: "json"
"""
