"""Offline hygiene checks retain provenance and reject merge and documentation regressions."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "repository_hygiene", Path(__file__).parents[1] / "scripts/check_repository_hygiene.py"
)
assert SPEC and SPEC.loader
hygiene = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hygiene)


def test_committed_merge_conflicts_are_reported(tmp_path):
    path = tmp_path / "source.py"
    path.write_text("<<<<<<< HEAD\na = 1\n=======\na = 2\n>>>>>>> feature\n")
    assert "merge conflict" in hygiene.source_issues(tmp_path, [Path("source.py")])[0]


def test_local_links_resolve_from_document_and_ignore_examples_and_web(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text("Root")
    doc = tmp_path / "docs" / "guide.md"
    doc.write_text(
        "[root](../README.md#anchor)\n[web](https://example.invalid/unfetched)\n"
        "```md\n[example](nonexistent.md)\n```\n"
    )
    assert hygiene.source_issues(tmp_path, [Path("docs/guide.md")]) == []
    doc.write_text("[broken](missing.md)\n[escape](../../outside.md)\n")
    assert len(hygiene.source_issues(tmp_path, [Path("docs/guide.md")])) == 2


def test_source_symlink_is_not_read(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.write_text("source")
    (tmp_path / "source.py").symlink_to(outside)
    assert "unsafe" in hygiene.source_issues(tmp_path, [Path("source.py")])[0]


def test_declared_versions_match_without_importing_project_code(tmp_path):
    package = tmp_path / "src/nexus_symbiote"
    package.mkdir(parents=True)
    marker = tmp_path / "executed"
    (package / "__init__.py").write_text(
        f'__version__ = "0.1.0"\nraise RuntimeError({str(marker)!r})\n'
    )
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.1.0"\n')
    assert hygiene.version_issues(tmp_path) == [] and not marker.exists()
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.2.0"\n')
    assert hygiene.version_issues(tmp_path)


@pytest.mark.parametrize("mutation", ["modified", "unlisted", "duplicate", "traversal"])
def test_vendored_schema_provenance_cannot_silently_drift(tmp_path, mutation):
    vendor = tmp_path / hygiene.VENDOR
    vendor.mkdir(parents=True)
    schema = b'{"type":"object"}'
    (vendor / "example.json").write_bytes(schema)
    record = {"file": "example.json", "sha256": hashlib.sha256(schema).hexdigest()}
    manifest = {"files": [record]}
    source = vendor / "SOURCES.json"
    source.write_text(json.dumps(manifest))
    assert hygiene.vendor_issues(tmp_path) == []
    if mutation == "modified":
        (vendor / "example.json").write_text('{"type":"string"}')
    elif mutation == "unlisted":
        (vendor / "extra.json").write_text("{}")
    elif mutation == "duplicate":
        manifest["files"].append(record)
    else:
        record["file"] = "../outside.json"
    source.write_text(json.dumps(manifest))
    assert hygiene.vendor_issues(tmp_path)
