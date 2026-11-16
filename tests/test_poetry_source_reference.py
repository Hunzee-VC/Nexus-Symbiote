"""A poetry.lock record's origin is the source its reference names, as Poetry reads it."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_symbiote.scanners.registry import RegistryScanner

MANIFEST = '[project]\ndependencies = ["openai>=1.0"]\n'
GAP = "poetry.lock: package source reference is unverified"


def _scan(root: Path, sources: str, record_source: str):
    (root / "pyproject.toml").write_text(MANIFEST + sources)
    (root / "poetry.lock").write_text(
        f'[[package]]\nname = "openai"\nversion = "1.0.0"\n{record_source}\n'
    )
    result = RegistryScanner().scan(root)
    (component,) = [c for c in result.components if c.name == "openai"]
    return result, component


EVIL = '\n[[tool.poetry.source]]\nname = "evil"\nurl = "http://evil.example/simple"\npriority = "explicit"\n'


@pytest.mark.parametrize(
    ("sources", "record"),
    [
        # Poetry installs from evil.example, whatever url the record shows.
        (EVIL, 'source = { type = "legacy", url = "https://pypi.org/simple", reference = "evil" }'),
        # pyproject.toml declares no such source, so Poetry has none to download from.
        ("", 'source = { type = "legacy", url = "https://pypi.org/simple", reference = "evil" }'),
        (EVIL, 'source = { type = "legacy", url = "https://pypi.org/simple", reference = 7 }'),
    ],
    ids=["explicit-source-elsewhere", "undeclared-source", "reference-not-text"],
)
def test_a_record_whose_reference_and_url_disagree_binds_no_origin(
    tmp_path: Path, sources: str, record: str
) -> None:
    result, component = _scan(tmp_path, sources, record)
    assert GAP in result.surfaces_excluded
    assert component.package_url is None
    assert component.registry_uri is None


def test_a_record_that_names_the_cleartext_source_it_came_from_is_a_high_finding(
    tmp_path: Path,
) -> None:
    record = 'source = { type = "legacy", url = "http://evil.example/simple", reference = "evil" }'
    result, component = _scan(tmp_path, EVIL, record)
    assert GAP not in result.surfaces_excluded
    assert component.registry_uri == "http://evil.example"
    assert {r.category: r.severity.value for r in component.risks}["registry_origin"] == "high"


def test_a_record_that_names_pypi_keeps_the_public_identity(tmp_path: Path) -> None:
    record = 'source = { type = "legacy", url = "https://pypi.org/simple", reference = "PyPI" }'
    result, component = _scan(tmp_path, "", record)
    assert GAP not in result.surfaces_excluded
    assert component.package_url == "pkg:pypi/openai@1.0.0"
