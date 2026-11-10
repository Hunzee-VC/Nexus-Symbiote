"""RAG records bind their configuration, never export content or credentials, and
treat Python sources as a best-effort heuristic."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import RAGSourceComponent
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV
from nexus_symbiote.scanners.rag import SOURCE_STRUCTURE_PROFILE, RAGScanner

KEY = "rag-binding-key-" + "0123456789abcdef" * 2


@pytest.fixture(autouse=True)
def _no_ambient_key(monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)


def _source(
    root: Path, source: dict[str, Any], name: str = "rag_config.json"
) -> RAGSourceComponent:
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(json.dumps({"sources": [source]}))
    result = RAGScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    (component,) = [
        c for c in result.components if c.bom_ref.startswith("rag:") and "import" not in c.bom_ref
    ]
    assert isinstance(component, RAGSourceComponent)
    return component


BASE = {
    "name": "kb",
    "type": "vector-store",
    "sanitization": True,
    "source_uris": ["https://raw.githubusercontent.com/acme/kb/main/notes.md"],
}


def _scan_and_diff(tmp_path: Path, before: dict[str, Any], after: dict[str, Any]):
    project = tmp_path / "project"
    project.mkdir()
    outputs = []
    for index, source in enumerate((before, after)):
        (project / "rag_config.json").write_text(json.dumps({"sources": [source]}))
        output = tmp_path / f"{index}.json"
        run = CliRunner().invoke(
            main,
            [
                "scan",
                str(project),
                "--no-project-policy",
                "--report-only",
                "--scanner",
                "rag",
                "-o",
                str(output),
            ],
        )
        assert run.exit_code == 0, run.output
        outputs.append(str(output))
    return CliRunner().invoke(main, ["diff", *outputs, "--json-output", "--fail-on-alert"])


def test_same_origin_repoint_is_unbound_without_a_key_and_alerts_with_one(tmp_path, monkeypatch):
    moved = {**BASE, "source_uris": ["https://raw.githubusercontent.com/evil/kb/main/notes.md"]}
    before = _source(tmp_path / "a", BASE)
    after = _source(tmp_path / "b", moved)
    assert before.source_uris == after.source_uris == ["https://raw.githubusercontent.com"]
    (gap,) = [r for r in before.risks if r.category == "completeness"]
    assert "source URIs beyond their exported origins" in gap.detail
    assert SOURCE_BINDING_KEY_ENV in gap.recommendation
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    run = _scan_and_diff(tmp_path, BASE, moved)
    assert run.exit_code == 1, run.output
    assert "rag:kb" in run.output
    keyed = _source(tmp_path / "c", BASE)
    assert keyed.properties["source_values_bound"] is True
    assert not any(r.category == "completeness" for r in keyed.risks)


@pytest.mark.parametrize(
    "after",
    [
        {**BASE, "sanitization": "off"},
        {**BASE, "sanitization": False},
        {**BASE, "source_uris": ["https://raw.githubusercontent.com/acme/kb/main/a/b/notes.md"]},
        {**BASE, "index_url": "https://evil.example/index"},
        {**BASE, "embedding_model": "text-embedding-3-large"},
        {**BASE, "collection": "incoming"},
    ],
)
def test_configuration_changes_fail_the_drift_gate_without_a_key(tmp_path, after):
    run = _scan_and_diff(tmp_path, BASE, after)
    assert run.exit_code == 1, run.output
    assert "rag:kb" in run.output


@pytest.mark.parametrize(
    ("value", "state"),
    [
        (True, "enabled"),
        (False, "disabled"),
        ("off", "unrecognized"),
        ("strict", "unrecognized"),
        ({"enabled": True}, "enabled"),
        ({"enabled": "yes"}, "unrecognized"),
    ],
)
def test_only_a_boolean_true_declares_a_control(tmp_path, value, state):
    component = _source(tmp_path, {**BASE, "sanitization": value})
    assert component.properties["declared_controls"]["sanitization"] == state
    flagged = any("content filtering" in r.detail for r in component.risks)
    assert flagged is (state != "enabled")


def test_inline_documents_are_counted_and_digested_never_exported(tmp_path):
    canary = "CANARY customer ACME contract terms"
    source = {"name": "kb", "documents": [canary, "second document"], "sanitization": True}
    component = _source(tmp_path / "a", source)
    assert component.document_count == 2
    assert component.source_uris == []
    assert component.properties["inline_documents_hash"].startswith("sha256:")
    assert canary not in component.model_dump_json()
    edited = _source(tmp_path / "b", {**source, "documents": [canary + "!", "second document"]})
    assert (
        edited.properties["inline_documents_hash"] != component.properties["inline_documents_hash"]
    )


@pytest.mark.parametrize("output_format", ["json", "cyclonedx", "spdx", "sarif"])
def test_document_text_and_connection_strings_never_reach_any_export(tmp_path, output_format):
    project = tmp_path / "project"
    project.mkdir()
    (project / "knowledge_base.json").write_text(
        json.dumps({"ids": ["1"], "documents": ["CANARY-DOC private text"], "metadatas": [{}]})
    )
    (project / "rag_config.json").write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "name": "azure",
                        "type": "postgres://user:CANARY-TYPE@db.example/vectors",
                        "source_uris": [
                            "DefaultEndpointsProtocol=https;AccountName=kb;"
                            "AccountKey=CANARY-KEY==;EndpointSuffix=core.windows.net",
                            "Driver={ODBC Driver 18};Server=tcp:db,1433;Uid=rag;Pwd=CANARY-PWD",
                            "rag:CANARY-USERINFO@db.internal:5432/vectors",
                            "password=CANARY-ASSIGN",
                        ],
                    }
                ]
            }
        )
    )
    output = tmp_path / "out"
    run = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--no-project-policy",
            "--report-only",
            "--scanner",
            "rag",
            "-f",
            output_format,
            "-o",
            str(output),
        ],
    )
    assert run.exit_code == 0, run.output
    assert "CANARY" not in output.read_text()


def test_credential_shaped_locators_are_redacted(tmp_path):
    component = _source(
        tmp_path,
        {
            **BASE,
            "type": "postgres://user:pw@host/db",
            "source_uris": [
                "AccountName=kb;AccountKey=secret==",
                "rag:secret@db.internal:5432/vectors",
                "docs/handbook/",
                "s3://bucket/reviewed/",
                "https://evil.example\\@docs.example.com/kb",
            ],
        },
    )
    assert component.corpus_type == "[redacted]"
    assert component.source_uris == [
        "[redacted-connection-string]",
        "[redacted]",
        "docs/handbook/",
        "s3://bucket",
        "[redacted-url]",
    ]
    assert component.properties["source_credentials_omitted"] is True


@pytest.mark.parametrize(
    ("uri", "severity"),
    [
        (" http://kb.example/docs", "high"),
        ("ws://kb.example/stream", "high"),
        ("git://kb.example/repo", "high"),
        ("redis://cache.example:6379", "high"),
        ("postgres://db.example/kb", "low"),
        ("https://kb.example/docs", None),
        ("s3://bucket/key", None),
    ],
)
def test_transport_check_reads_the_scheme(tmp_path, uri, severity):
    component = _source(tmp_path, {**BASE, "source_uris": [uri]})
    transport = [
        r.severity.value
        for r in component.risks
        if "unencrypted" in r.detail or "not shown to be encrypted" in r.detail
    ]
    assert transport == ([] if severity is None else [severity])
    assert all("kb.example/" not in r.detail for r in component.risks)


def test_data_file_named_like_a_knowledge_base_is_not_a_configuration(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "knowledge_base.json").write_text(json.dumps([{"title": "x"}]))
    result = RAGScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not result.components
    assert "data/knowledge_base.json" not in result.surfaces_scanned


def test_unnamed_sources_in_two_configurations_do_not_collide(tmp_path):
    for folder in ("a", "b"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "rag_config.json").write_text(json.dumps({"type": folder}))
    result = RAGScanner().scan(tmp_path)
    assert not result.scan_failures
    assert sorted(c.bom_ref for c in result.components) == [
        "rag:a/rag_config.json#0",
        "rag:b/rag_config.json#0",
    ]


def test_both_source_list_names_are_read(tmp_path):
    (tmp_path / "rag_config.json").write_text(
        json.dumps(
            {
                "sources": [],
                "knowledge_bases": [{"name": "kb", "source_uris": ["http://evil.example/p"]}],
            }
        )
    )
    result = RAGScanner().scan(tmp_path)
    (component,) = result.components
    assert component.name == "kb"
    assert any(r.severity.value == "high" for r in component.risks)


def test_structure_digest_names_its_profile(tmp_path):
    component = _source(tmp_path, BASE)
    assert component.properties["static_config_hash_profile"] == SOURCE_STRUCTURE_PROFILE
    assert component.properties["static_config_hash"].startswith("sha256:")
    assert component.properties["source_values_bound"] is False


def test_overlong_name_is_a_failure_and_names_are_neutralised(tmp_path):
    (tmp_path / "rag_config.json").write_text(json.dumps({"name": "n" * 300}))
    assert RAGScanner().scan(tmp_path).scan_failures
    component = _source(tmp_path / "b", {**BASE, "name": "kb‮\nx", "source_uris": ["http://h/x"]})
    assert all("‮" not in r.detail and "\n" not in r.detail for r in component.risks)


def test_python_heuristic_never_fails_the_collector(tmp_path):
    (tmp_path / "legacy.py").write_text('import chromadb\nprint "python 2"\n')
    (tmp_path / "deep.py").write_text("import faiss\nx = " + "-" * 100_000 + "1\n")
    (tmp_path / "big.py").write_text("import pinecone\n" + "x = 1\n" * 50_000)
    (tmp_path / "latin.py").write_bytes(b"import lancedb  # \xff\n")
    (tmp_path / "{{cookiecutter.slug}}").mkdir()
    (tmp_path / "{{cookiecutter.slug}}" / "main.py").write_text("import {{ module }}\n")
    (tmp_path / "ok.py").write_text("import qdrant_client\n")
    result = RAGScanner().scan(tmp_path)
    assert not result.scan_failures and not result.surfaces_excluded
    (component,) = result.components
    assert component.bom_ref == "rag:import-qdrant"
    assert component.source_path == "ok.py"


def test_unrelated_python_file_does_not_change_the_inventory(tmp_path):
    (tmp_path / "app.py").write_text("import chromadb\n")
    (tmp_path / "rag_config.json").write_text(json.dumps(BASE))
    first = RAGScanner().scan(tmp_path)
    (tmp_path / "util.py").write_text("def helper():\n    return 1\n")
    second = RAGScanner().scan(tmp_path)
    assert first.surfaces_scanned == second.surfaces_scanned
    assert first.components == second.components
    assert not any(entry.endswith(".py") for entry in second.surfaces_scanned)


def test_env_file_with_undecodable_bytes_is_read_for_key_names(tmp_path):
    (tmp_path / ".env").write_bytes(b"PINECONE_API_KEY=\xff\xfe\n")
    result = RAGScanner().scan(tmp_path)
    assert not result.scan_failures
    assert [c.bom_ref for c in result.components] == ["rag:env-pinecone"]
    assert result.components[0].source_path == ".env"


def test_inventory_is_identical_when_scanned_at_two_locations(tmp_path):
    for root in (tmp_path / "one", tmp_path / "two" / "nested"):
        (root / "configs").mkdir(parents=True)
        (root / "configs" / "rag_config.json").write_text(json.dumps(BASE))
        (root / "app.py").write_text("import chromadb\n")
    first = RAGScanner().scan(tmp_path / "one")
    second = RAGScanner().scan(tmp_path / "two" / "nested")
    assert first.components == second.components
    assert first.surfaces_scanned == second.surfaces_scanned
    assert str(tmp_path) not in repr(first)


def test_configuration_read_through_an_in_root_link_names_its_target(tmp_path):
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "rag.json").write_text(json.dumps(BASE))
    (tmp_path / "rag_config.json").symlink_to("configs/rag.json")
    result = RAGScanner().scan(tmp_path)
    assert not result.scan_failures
    (component,) = result.components
    assert component.source_path == "rag_config.json"
    assert component.properties["symlink_target"] == "configs/rag.json"


def _scan_config(root: Path, config: dict[str, Any]) -> list[RAGSourceComponent]:
    root.mkdir(parents=True, exist_ok=True)
    (root / "rag_config.json").write_text(json.dumps(config))
    result = RAGScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    return [c for c in result.components if isinstance(c, RAGSourceComponent)]


@pytest.mark.parametrize(
    ("field", "before", "after"),
    [
        (
            "vector_store",
            {"url": "https://qdrant.corp.example/kb"},
            {"url": "https://evil.example/kb"},
        ),
        (
            "embeddings",
            {"model": "m", "api_base": "https://api.openai.com/v1"},
            {"model": "m", "api_base": "https://evil.example/v1"},
        ),
        ("vector_store", "https://qdrant.corp.example/kb", "https://qdrant.corp.example/a/b"),
    ],
)
def test_nested_endpoint_changes_alter_the_record_without_a_key(tmp_path, field, before, after):
    first = _source(tmp_path / "a", {**BASE, field: before})
    second = _source(tmp_path / "b", {**BASE, field: after})
    assert first.properties["static_config_hash"] != second.properties["static_config_hash"]
    run = _scan_and_diff(tmp_path, {**BASE, field: before}, {**BASE, field: after})
    assert run.exit_code == 1, run.output


def test_unexported_nested_values_are_unbound_without_a_key_and_bound_with_one(
    tmp_path, monkeypatch
):
    before = {**BASE, "sanitization": None, "content_filter": {"enabled": True, "mode": "block"}}
    after = {**before, "content_filter": {"enabled": True, "mode": "log-only"}}
    first, second = _source(tmp_path / "a", before), _source(tmp_path / "b", after)
    assert first == second
    (gap,) = [r for r in first.risks if r.category == "completeness"]
    assert "field values that the record does not export" in gap.detail
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    run = _scan_and_diff(tmp_path, before, after)
    assert run.exit_code == 1, run.output


def test_nested_cleartext_endpoint_is_a_transport_finding(tmp_path):
    component = _source(
        tmp_path, {**BASE, "vector_store": {"url": "http://qdrant.corp.example:6333/kb"}}
    )
    (finding,) = [r for r in component.risks if r.severity.value == "high"]
    assert finding.detail == (
        "RAG source 'kb' declares an unencrypted endpoint: http://qdrant.corp.example:6333"
    )
    assert component.properties["endpoint_origins"] == ["http://qdrant.corp.example:6333"]


def test_fields_beside_the_source_lists_are_digested_bound_and_checked(tmp_path, monkeypatch):
    def config(endpoint: str) -> dict[str, Any]:
        return {
            "retriever": {"endpoint": endpoint, "top_k": 5},
            "sources": [BASE, {**BASE, "name": "kb2"}],
        }

    first = _scan_config(tmp_path / "a", config("https://a.example/x"))
    moved = _scan_config(tmp_path / "b", config("https://evil.example/x"))
    assert [c.properties["static_config_hash"] for c in first] != [
        c.properties["static_config_hash"] for c in moved
    ]
    assert first[1].properties["configuration_endpoint_origins"] == ["https://a.example"]
    assert any(
        r.category == "completeness" and "RAG configuration 'rag_config.json'" in r.detail
        for r in first[0].risks
    )
    cleartext = _scan_config(tmp_path / "c", config("http://a.example/x"))
    findings = [r for c in cleartext for r in c.risks if r.severity.value == "high"]
    assert [r.detail for r in findings] == [
        "RAG configuration 'rag_config.json' declares an unencrypted endpoint: http://a.example"
    ]
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    keyed = _scan_config(tmp_path / "d", config("https://a.example/x"))
    rekeyed = _scan_config(tmp_path / "e", config("https://a.example/y"))
    assert (
        keyed[0].properties["static_value_binding"] != rekeyed[0].properties["static_value_binding"]
    )
    assert not any(r.category == "completeness" for c in keyed for r in c.risks)


def test_empty_source_list_beside_source_fields_is_read_as_one_source(tmp_path):
    (component,) = _scan_config(tmp_path, {"sources": [], "source_uris": ["http://evil.example/p"]})
    assert component.bom_ref == "rag:rag_config.json#0"
    assert component.source_uris == ["http://evil.example"]
    assert any(r.severity.value == "high" for r in component.risks)


def test_case_variant_of_a_configuration_name_is_a_failure(tmp_path):
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "Rag_Config.json").write_text(json.dumps(BASE))
    (tmp_path / "Knowledge_Base.json").write_text(json.dumps([{"title": "data"}]))
    result = RAGScanner().scan(tmp_path)
    assert result.scan_failures == [
        "configs/Rag_Config.json: case variant of configs/rag_config.json is the active file "
        "on case-insensitive file systems and is not inventoried"
    ]


def test_uri_shown_in_findings_is_neutralised(tmp_path):
    component = _source(
        tmp_path, {**BASE, "source_uris": ["http://moc.elpmaxe\u202e.evil.example/x"]}
    )
    assert all("\u202e" not in r.detail for r in component.risks)
