"""Recognized credentials in static display fields never reach inventories or exports."""

from __future__ import annotations

import json
from urllib.parse import quote

import pytest

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import AgentComponent, ModelComponent, RAGSourceComponent
from nexus_symbiote.generators.recovery import recover_export
from nexus_symbiote.generators.validation import (
    validate_cyclonedx,
    validate_sarif,
    validate_spdx,
)
from nexus_symbiote.graph import assemble_repository_agent
from nexus_symbiote.policy import PolicyError
from nexus_symbiote.scanners.rag import RAGScanner
from nexus_symbiote.scanners.source_binding import SOURCE_BINDING_KEY_ENV

HF_TOKEN = "hf_" + "A1" * 18
NPM_TOKEN = "npm_" + "B2" * 18
PASSWORD = "synthetic-static-password-12345"  # noqa: S105 - synthetic sentinel
SECRET_TEXT = (HF_TOKEN, NPM_TOKEN, f"password: {PASSWORD}")
MANIFEST_FIELDS = ("name", "version", "framework", "owner", "purpose")
RAG_FIELDS = (
    "type",
    "store_type",
    "embedding_model",
    "embeddings",
    "chunking_strategy",
    "chunk_size",
    "index_name",
    "collection",
    "collection_name",
    "namespace",
)


@pytest.mark.parametrize("text", SECRET_TEXT)
def test_manifest_display_fields_mask_recognized_credentials(tmp_path, text):
    (tmp_path / "agent.yaml").write_text(json.dumps(dict.fromkeys(MANIFEST_FIELDS, text)))
    bom = AIBOM()
    agent = assemble_repository_agent(bom, tmp_path)
    assert text not in bom.model_dump_json()
    for field in ("name", "version", "framework", "supplier", "description"):
        assert "***" in getattr(agent, field)


@pytest.mark.parametrize("field", RAG_FIELDS)
@pytest.mark.parametrize("text", SECRET_TEXT)
def test_rag_identifiers_mask_recognized_credentials_and_report_unbound_values(
    tmp_path, field, text
):
    source = {"name": "knowledge", "sanitization": True}
    if field == "chunk_size":
        source["chunking_strategy"] = "fixed"
    source[field] = {"model": text} if field == "embeddings" else text
    (tmp_path / "rag_config.json").write_text(json.dumps(source))
    result = RAGScanner().scan(tmp_path)
    assert not result.scan_failures
    (component,) = [c for c in result.components if isinstance(c, RAGSourceComponent)]
    assert text not in component.model_dump_json()
    assert "[redacted]" in component.model_dump_json()
    assert any(risk.category == "completeness" for risk in component.risks)


@pytest.mark.parametrize("token", [HF_TOKEN, NPM_TOKEN])
def test_credential_shaped_plain_path_is_redacted(tmp_path, token):
    source = {"name": "knowledge", "source_uris": [token], "sanitization": True}
    (tmp_path / "rag_config.json").write_text(json.dumps(source))
    result = RAGScanner().scan(tmp_path)
    assert not result.scan_failures
    (component,) = [c for c in result.components if isinstance(c, RAGSourceComponent)]
    assert component.source_uris == ["[redacted]"]
    assert token not in component.model_dump_json()
    assert any(risk.category == "completeness" for risk in component.risks)


def test_manifest_names_keep_ordinary_token_shapes_and_purpose_does_not(tmp_path):
    # Identity fields use the identifier rule, which keeps names such as an sk- prefix.
    name = "sk-research-assistant-agent"
    declaration = {"name": name, "owner": name, "purpose": f"key {name}-0123456789"}
    (tmp_path / "agent.yaml").write_text(json.dumps(declaration))
    agent = assemble_repository_agent(AIBOM(), tmp_path)
    assert agent.name == name and agent.supplier == name
    assert agent.description is not None and "***" in agent.description


def test_ordinary_manifest_and_rag_values_are_preserved(tmp_path):
    declaration = {
        "name": "knowledge-agent",
        "version": "1.2.3",
        "framework": "custom",
        "owner": "Research team",
        "purpose": "Answer questions from reviewed notes",
    }
    (tmp_path / "agent.yaml").write_text(json.dumps(declaration))
    agent = assemble_repository_agent(AIBOM(), tmp_path)
    assert agent.name == declaration["name"] and agent.version == declaration["version"]
    assert agent.framework == declaration["framework"] and agent.supplier == declaration["owner"]
    assert agent.description == declaration["purpose"]
    source = {
        "name": "knowledge",
        "embedding_model": "sentence-transformers/all-MiniLM-L6-v2",
        "namespace": "notes-v1",
        "source_uris": ["docs/reference.md"],
        "sanitization": True,
    }
    (tmp_path / "rag_config.json").write_text(json.dumps(source))
    result = RAGScanner().scan(tmp_path)
    assert not result.scan_failures
    (component,) = [c for c in result.components if isinstance(c, RAGSourceComponent)]
    assert component.embedding_model_name == source["embedding_model"]
    assert component.source_uris == source["source_uris"]
    assert component.properties["index_identities"] == {"namespace": "notes-v1"}
    assert not any(risk.category == "completeness" for risk in component.risks)


def test_keyed_binding_still_detects_a_redacted_rag_identifier_change(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "static-export-binding-key-0123456789abcdef")
    records = []
    for token in (HF_TOKEN, "hf_" + "C3" * 18):
        (tmp_path / "rag_config.json").write_text(
            json.dumps({"name": "knowledge", "embedding_model": token, "sanitization": True})
        )
        result = RAGScanner().scan(tmp_path)
        assert not result.scan_failures
        (component,) = [c for c in result.components if isinstance(c, RAGSourceComponent)]
        assert component.embedding_model_name == "[redacted]"
        assert not any(risk.category == "completeness" for risk in component.risks)
        records.append(component)
    before, after = records
    assert before.properties["static_config_hash"] == after.properties["static_config_hash"]
    assert before.properties["static_value_binding"] != after.properties["static_value_binding"]


@pytest.mark.parametrize("output_format", ["json", "cyclonedx", "spdx", "sarif"])
@pytest.mark.parametrize("keyed", [False, True])
def test_static_credentials_reach_no_cli_export(
    tmp_path, runner, monkeypatch, output_format, keyed
):
    if keyed:
        monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "static-export-binding-key-0123456789abcdef")
    project = tmp_path / "project"
    project.mkdir()
    (project / "agent.yaml").write_text(
        json.dumps({"name": "knowledge-agent", "purpose": f"Authorization: Bearer {HF_TOKEN}"})
    )
    (project / "rag_config.json").write_text(
        json.dumps(
            {
                "name": "knowledge",
                "embedding_model": HF_TOKEN,
                "namespace": f"password: {PASSWORD}",
                "source_uris": [NPM_TOKEN],
                "sanitization": True,
            }
        )
    )
    output = tmp_path / "inventory.json"
    result = runner.invoke(
        main,
        ["scan", str(project), "--no-project-policy", "-f", output_format, "-o", str(output)],
    )
    assert result.exit_code == 0, result.output
    exported = output.read_text()
    assert all(secret not in exported + result.output for secret in (HF_TOKEN, NPM_TOKEN, PASSWORD))
    document = json.loads(exported)
    if output_format == "sarif":
        assert validate_sarif(document) == []
        return
    if output_format == "json":
        bom = AIBOM.model_validate(document)
    else:
        validator = validate_cyclonedx if output_format == "cyclonedx" else validate_spdx
        assert validator(document) == []
        bom = recover_export(exported)
    agent = next(c for c in bom.components if isinstance(c, AgentComponent))
    rag = next(c for c in bom.components if isinstance(c, RAGSourceComponent))
    assert agent.description == "Authorization: Bearer ***"
    assert rag.embedding_model_name == "[redacted]"
    assert rag.source_uris == ["[redacted]"]
    assert rag.properties["source_values_bound"] is keyed
    assert any(risk.category == "completeness" for risk in rag.risks) is not keyed


GITHUB_TOKEN = "ghp_" + "D4" * 18
OPENAI_KEY = "sk-proj-" + "E5" * 20
ANTHROPIC_KEY = "sk-ant-api03-" + "F6" * 20
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJlZmFrZQ"
MODEL_SECRETS = (HF_TOKEN, NPM_TOKEN, GITHUB_TOKEN, OPENAI_KEY, ANTHROPIC_KEY, JWT)


def _hosted(tmp_path, models, failures=None):
    (tmp_path / "agent.yaml").write_text(json.dumps({"name": "demo", "models": models}))
    bom = AIBOM()
    assemble_repository_agent(bom, tmp_path, failures=failures)
    return bom, [c for c in bom.components if isinstance(c, ModelComponent)]


@pytest.mark.parametrize("field", ["provider", "requested_ref"])
@pytest.mark.parametrize("secret", MODEL_SECRETS)
def test_hosted_model_fields_mask_recognized_credentials(tmp_path, field, secret):
    declaration = {"provider": "openai", "requested_ref": "gpt-4o", field: secret}
    bom, (model,) = _hosted(tmp_path, {"planner": declaration})
    assert secret not in bom.model_dump_json()
    shown = model.provider if field == "provider" else model.requested_alias
    assert shown == "***"
    assert model.name == model.requested_alias


@pytest.mark.parametrize("secret", MODEL_SECRETS)
@pytest.mark.parametrize(
    ("spelling", "locator"),
    [("{}", "%2A%2A%2A"), ("primary/{}", "primary%2F%2A%2A%2A"), ("a {} b", "a%20%2A%2A%2A%20b")],
)
@pytest.mark.parametrize(
    "declaration",
    [{"provider": "openai", "requested_ref": "gpt-4o"}, {"path": "models/x.safetensors"}],
    ids=["hosted", "local"],
)
def test_a_model_key_holding_a_credential_names_no_component_or_failure(
    tmp_path, secret, spelling, locator, declaration
):
    failures: list[str] = []
    models = {spelling.format(secret): declaration, "fallback": declaration}
    bom, models_found = _hosted(tmp_path, models, failures)
    text = bom.model_dump_json() + json.dumps(failures)
    assert secret not in text
    assert f"agent.yaml#/models/{locator}: the key holds a recognized credential" in failures
    assert [model.bom_ref.rsplit("/", 1)[1] for model in models_found] in ([], ["fallback"])
    with pytest.raises(PolicyError) as raised:
        _hosted(tmp_path, models)
    assert secret not in str(raised.value)


def test_ordinary_hosted_model_names_are_preserved(tmp_path):
    models = {
        "planner": {"provider": "openai", "requested_ref": "gpt-4o-2024-08-06"},
        "pplx-7b-online": {"provider": "perplexity", "requested_ref": "pplx-7b-online"},
        "claude": {
            "provider": "bedrock",
            "requested_ref": "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
        },
        "meta-llama/Llama-3.1-8B-Instruct": {
            "provider": "huggingface",
            "requested_ref": "meta-llama/Llama-3.1-8B-Instruct",
        },
        "sk-research-assistant": {"provider": "azure-openai", "requested_ref": "ft:gpt-4o:acme"},
    }
    failures: list[str] = []
    _bom, found = _hosted(tmp_path, models, failures)
    assert failures == []
    shown = {(m.provider, m.requested_alias, m.name) for m in found}
    assert shown == {
        (v["provider"], v["requested_ref"], v["requested_ref"]) for v in models.values()
    }
    assert {m.bom_ref.rsplit("/hosted/", 1)[1] for m in found} == {
        quote(key, safe="") for key in models
    }


@pytest.mark.parametrize("output_format", ["json", "cyclonedx", "spdx", "sarif"])
def test_hosted_model_credentials_reach_no_cli_export(tmp_path, runner, output_format):
    project = tmp_path / "project"
    project.mkdir()
    models = {
        GITHUB_TOKEN: {"provider": "openai", "requested_ref": "gpt-4o"},
        "planner": {"provider": ANTHROPIC_KEY, "requested_ref": OPENAI_KEY},
    }
    (project / "agent.yaml").write_text(json.dumps({"name": "demo", "models": models}))
    output = tmp_path / "inventory.out"
    result = runner.invoke(
        main,
        ["scan", str(project), "--no-project-policy", "-f", output_format, "-o", str(output)],
    )
    exported = output.read_text()
    for secret in (GITHUB_TOKEN, ANTHROPIC_KEY, OPENAI_KEY):
        assert secret not in exported + result.output
        assert secret[:12] not in exported + result.output
    if output_format == "sarif":
        return
    document = json.loads(exported)
    if output_format == "json":
        bom = AIBOM.model_validate(document)
    else:
        validator = validate_cyclonedx if output_format == "cyclonedx" else validate_spdx
        assert validator(document) == []
        bom = recover_export(exported)
    (model,) = [c for c in bom.components if isinstance(c, ModelComponent)]
    assert (model.provider, model.requested_alias) == ("***", "***")
    assert model.bom_ref.endswith("/hosted/planner")
