"""RAG identifier fields and plain-path locators never carry credential-shaped text."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.core.models import RAGSourceComponent
from nexus_symbiote.scanners.rag import RAGScanner

BASE: dict[str, Any] = {
    "name": "kb",
    "type": "vector-store",
    "sanitization": True,
    "source_uris": ["docs/notes.md"],
}
USER_PASSWORD = "nspass:NsSecret00"  # noqa: S105 - synthetic fixture
ASSIGNMENT = "qdrant pass=CollSecret44"  # noqa: S105 - synthetic fixture
BEARER = "Bearer AbCdEf0123456789XYZ"  # noqa: S105 - synthetic fixture
# Assembled at run time so the source holds no token-shaped literal.
GITHUB_TOKEN = "".join(("gh", "p_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"))
BARE_TOKEN = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # noqa: S105 - synthetic fixture


def _source(root: Path, source: dict[str, Any]) -> RAGSourceComponent:
    root.mkdir(parents=True, exist_ok=True)
    (root / "rag_config.json").write_text(json.dumps({"sources": [source]}))
    result = RAGScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    (component,) = [c for c in result.components if c.bom_ref.startswith("rag:")]
    assert isinstance(component, RAGSourceComponent)
    return component


@pytest.mark.parametrize("field", ["index_name", "collection", "collection_name", "namespace"])
@pytest.mark.parametrize("value", [USER_PASSWORD, ASSIGNMENT, BEARER, GITHUB_TOKEN])
def test_identity_fields_export_credential_shapes_as_a_marker(tmp_path, field, value):
    component = _source(tmp_path, {**BASE, field: value})
    assert component.properties["index_identities"] == {field: "[redacted]"}
    assert value.split()[-1].rsplit("=", 1)[-1] not in component.model_dump_json()
    (gap,) = [r for r in component.risks if r.category == "completeness"]
    assert "redaction markers" in gap.detail


@pytest.mark.parametrize("value", [USER_PASSWORD, ASSIGNMENT, BEARER, GITHUB_TOKEN])
def test_store_type_and_model_fields_export_credential_shapes_as_a_marker(tmp_path, value):
    component = _source(
        tmp_path,
        {
            **BASE,
            "store_type": value,
            "embedding_model": value,
            "embeddings": {"model": value},
            "chunking_strategy": value,
        },
    )
    text = component.model_dump_json()
    assert value.split()[-1].rsplit("=", 1)[-1] not in text
    assert component.properties["store_type"] == "[redacted]"
    assert component.embedding_model_name == "[redacted]"
    assert component.chunking_strategy == "[redacted]"


@pytest.mark.parametrize("value", [USER_PASSWORD, ASSIGNMENT, BEARER, GITHUB_TOKEN])
def test_corpus_type_exports_credential_shapes_as_a_marker(tmp_path, value):
    component = _source(tmp_path, {**BASE, "type": value})
    assert component.corpus_type == "[redacted]"
    assert value.split()[-1].rsplit("=", 1)[-1] not in component.model_dump_json()


def test_ordinary_identifiers_are_exported_as_written(tmp_path):
    component = _source(
        tmp_path,
        {
            **BASE,
            "store_type": "qdrant",
            "embedding_model": "text-embedding-3-large",
            "chunking_strategy": "recursive (512)",
            "collection": "support_docs-v2",
            "namespace": "team/eu",
        },
    )
    assert component.properties["store_type"] == "qdrant"
    assert component.embedding_model_name == "text-embedding-3-large"
    assert component.chunking_strategy == "recursive (512)"
    assert component.properties["index_identities"] == {
        "collection": "support_docs-v2",
        "namespace": "team/eu",
    }
    assert not [r for r in component.risks if r.category == "completeness"]


def test_a_bare_token_is_not_exported_as_a_plain_path(tmp_path):
    component = _source(tmp_path, {**BASE, "source_uris": [BARE_TOKEN, "corpus"]})
    assert BARE_TOKEN not in component.model_dump_json()
    assert component.source_uris == ["[redacted]", "[redacted]"]
    (gap,) = [r for r in component.risks if r.category == "completeness"]
    assert "beyond their exported origins" in gap.detail


def test_plain_paths_name_a_file_or_directory(tmp_path):
    paths = ["docs/notes.md", "notes.md", "./corpus/", "~/kb", "../shared/kb"]
    component = _source(tmp_path, {**BASE, "source_uris": paths})
    assert component.source_uris == paths
    assert not [r for r in component.risks if r.category == "completeness"]
