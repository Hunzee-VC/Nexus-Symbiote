"""Marker operands, arbitrary-equality versions and Compose defaults are recorded redacted."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_symbiote.scanners.registry import RegistryScanner

# Assembled at run time so the source holds no token-shaped literal.
TOKEN = "".join(("gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"))
ASSIGNMENT = "password=Secret4567"  # noqa: S105 - synthetic fixture
VALUES = {"token": TOKEN, "assignment": ASSIGNMENT}


def _scan(root: Path, filename: str, content: str):
    root.mkdir(parents=True, exist_ok=True)
    (root / filename).write_text(content)
    result = RegistryScanner().scan(root)
    text = json.dumps(
        [c.model_dump(mode="json") for c in result.components]
        + result.scan_failures
        + result.surfaces_excluded
    )
    return result, text


@pytest.mark.parametrize("shape", sorted(VALUES))
def test_quoted_marker_operands_are_redacted(tmp_path, shape):
    value = VALUES[shape]
    result, text = _scan(
        tmp_path, "requirements.txt", f'openai==1.0.0; sys_platform == "{value}"\n'
    )
    (component,) = [c for c in result.components if c.bom_ref == "registry:pypi/openai"]
    assert "Secret4567" not in text
    assert TOKEN not in text
    assert "***" in component.properties["requested_requirement"]


@pytest.mark.parametrize("shape", sorted(VALUES))
def test_arbitrary_equality_versions_are_redacted(tmp_path, shape):
    value = VALUES[shape]
    result, text = _scan(tmp_path, "requirements.txt", f"openai==={value}\n")
    (component,) = [c for c in result.components if c.bom_ref == "registry:pypi/openai"]
    assert "Secret4567" not in text
    assert TOKEN not in text
    assert component.version is not None and "***" in component.version
    assert component.package_url is None


@pytest.mark.parametrize("shape", sorted(VALUES))
def test_compose_variable_defaults_are_redacted(tmp_path, shape):
    value = VALUES[shape]
    result, text = _scan(
        tmp_path,
        "docker-compose.yml",
        f"services:\n  app:\n    image: ${{IMAGE:-reg.example/ollama/{value}:1}}\n",
    )
    (component,) = [c for c in result.components if c.bom_ref.startswith("registry:docker/")]
    assert "Secret4567" not in text
    assert TOKEN not in text
    assert "***" in component.name
