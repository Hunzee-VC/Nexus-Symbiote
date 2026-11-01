"""Policy configuration — .symbiote.yaml loading and defaults."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ScanPolicy(BaseModel):
    model_config = {"extra": "forbid"}

    scanners: list[str] = Field(
        default=["mcp", "model", "prompt", "rag", "registry"],
    )
    exclude_paths: list[str] = Field(
        default=["node_modules", ".git", "__pycache__", ".venv"],
    )


class RiskPolicy(BaseModel):
    model_config = {"extra": "forbid"}

    fail_threshold: float = 50.0
    warn_threshold: float = 25.0
    ignore_categories: list[str] = Field(default_factory=list)


class ValidatePolicy(BaseModel):
    model_config = {"extra": "forbid"}

    require_completeness: bool = True
    require_integrity: bool = True
    minimum_assurance_level: str = "declared"


class OutputPolicy(BaseModel):
    model_config = {"extra": "forbid"}

    default_format: str = "json"


class Policy(BaseModel):
    model_config = {"populate_by_name": True, "extra": "forbid"}

    version: str = "1.0"
    scan: ScanPolicy = Field(default_factory=ScanPolicy)
    risk: RiskPolicy = Field(default_factory=RiskPolicy)
    validation: ValidatePolicy = Field(default_factory=ValidatePolicy, alias="validate")
    output: OutputPolicy = Field(default_factory=OutputPolicy)


def default_policy() -> Policy:
    return Policy()


def load_policy(project_root: Path) -> Policy | None:
    current = project_root.resolve()
    for _ in range(20):
        candidate = current / ".symbiote.yaml"
        if candidate.exists():
            return _parse_policy(candidate)
        candidate = current / ".symbiote.yml"
        if candidate.exists():
            return _parse_policy(candidate)
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def _parse_policy(path: Path) -> Policy:
    """Parse a configured policy strictly; never fall back to defaults on failure."""
    try:
        import yaml
    except ImportError as exc:
        raise ValueError("Policy file requires PyYAML; install symbiote[yaml]") from exc
    try:
        data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("policy must be a mapping")
        return Policy.model_validate(data)
    except Exception as exc:
        raise ValueError(f"Invalid policy {path}: {exc}") from exc


DEFAULT_POLICY_YAML = """\
# SymBiote policy configuration
# https://github.com/aisecnomad/SymBiote
version: "1.0"

scan:
  scanners: ["mcp", "model", "prompt", "rag", "registry", "a2a", "ide_agents"]
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
