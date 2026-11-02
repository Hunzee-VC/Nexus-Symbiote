"""The version is single-sourced and agrees everywhere it is repeated."""

from __future__ import annotations

from importlib.metadata import version
from pathlib import Path

import yaml

import nexus_symbiote

ROOT = Path(__file__).resolve().parents[1]


def test_installed_metadata_matches_package_version() -> None:
    assert version("nexus-symbiote") == nexus_symbiote.__version__


def test_citation_file_matches_package_version() -> None:
    citation = yaml.safe_load((ROOT / "CITATION.cff").read_text(encoding="utf-8"))
    assert citation["version"] == nexus_symbiote.__version__


def test_pyproject_does_not_duplicate_the_version() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in pyproject
    assert 'path = "src/nexus_symbiote/__init__.py"' in pyproject
