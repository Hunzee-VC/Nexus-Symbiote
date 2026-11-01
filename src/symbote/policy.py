"""Policy configuration — .symbote.yaml loading and defaults."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ScanPolicy(BaseModel):
    scanners: list[str] = Field(
        default=["mcp", "model", "prompt", "rag", "registry"],
    )
    exclude_paths: list[str] = Field(
        default=["node_modules", ".git", "__pycache__", ".venv"],
    )


class RiskPolicy(BaseModel):
    fail_threshold: float = 50.0
    warn_threshold: float = 25.0
    ignore_categories: list[str] = Field(default_factory=list)


class ValidatePolicy(BaseModel):
    require_completeness: bool = True
    require_integrity: bool = True
    minimum_assurance_level: str = "declared"


class OutputPolicy(BaseModel):
    default_format: str = "json"


class Policy(BaseModel):
    model_config = {"populate_by_name": True}

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
        candidate = current / ".symbote.yaml"
        if candidate.exists():
            return _parse_policy(candidate)
        candidate = current / ".symbote.yml"
        if candidate.exists():
            return _parse_policy(candidate)
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def _parse_policy(path: Path) -> Policy | None:
    try:
        import yaml
    except ImportError:
        return _parse_policy_fallback(path)

    try:
        text = path.read_text(encoding="utf-8")
        data: Any = yaml.safe_load(text)
        if not isinstance(data, dict):
            return None
        return Policy.model_validate(data)
    except Exception:
        return None


def _parse_policy_fallback(path: Path) -> Policy | None:
    """Minimal YAML-like parsing when PyYAML is not installed."""
    import re

    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None

    data: dict[str, Any] = {}
    section: str | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        if indent == 0 and ":" in stripped:
            key, _, val = stripped.partition(":")
            val = val.strip().strip('"').strip("'")
            if val:
                data[key.strip()] = val
            else:
                section = key.strip()
                data.setdefault(section, {})
        elif indent > 0 and section and ":" in stripped:
            key, _, val = stripped.partition(":")
            val = val.strip().strip('"').strip("'")
            if val.startswith("[") and val.endswith("]"):
                items = [s.strip().strip('"').strip("'") for s in val[1:-1].split(",") if s.strip()]
                data[section][key.strip()] = items
            elif val.lower() in ("true", "false"):
                data[section][key.strip()] = val.lower() == "true"
            elif re.match(r"^[\d.]+$", val):
                data[section][key.strip()] = float(val)
            elif val:
                data[section][key.strip()] = val

    try:
        return Policy.model_validate(data)
    except Exception:
        return None


DEFAULT_POLICY_YAML = """\
# SymBiote policy configuration
# https://github.com/aisecnomad/SymBiote
version: "1.0"

scan:
  scanners: ["mcp", "model", "prompt", "rag", "registry"]
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
