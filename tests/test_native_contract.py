from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import AgentComponent, CapabilityDeclaration


def test_native_schema_matches_runtime_and_preserves_unknowns():
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas/nexus-symbiote-aibom-1.0.schema.json").read_text()
    )
    assert schema == AIBOM.model_json_schema()
    bom = AIBOM(components=[AgentComponent(bom_ref="agent:one", name="one", autonomy_level=None)])
    document = bom.to_dict()
    assert not list(Draft202012Validator(schema).iter_errors(document))
    assert AIBOM.model_validate(document).components[0].autonomy_level is None
    document["components"][0]["unrecognized_authority"] = {"admin": True}
    assert list(Draft202012Validator(schema).iter_errors(document))
    with pytest.raises(ValidationError):
        AIBOM.model_validate(document)


def test_published_examples_match_schema_and_runtime():
    schemas = Path(__file__).parents[1] / "schemas"
    validator = Draft202012Validator(
        json.loads((schemas / "nexus-symbiote-aibom-1.0.schema.json").read_text())
    )
    examples = sorted((schemas / "examples").glob("*.json"))
    assert examples
    for example in examples:
        document = json.loads(example.read_text())
        assert not list(validator.iter_errors(document)), example.name
        AIBOM.model_validate(document)


def test_nested_capability_unknown_semantics_rejected():
    with pytest.raises(ValidationError):
        CapabilityDeclaration.model_validate({"unrecognized_approval_bypass": True})


def test_loader_rejects_duplicate_keys_and_limits(tmp_path):
    path = tmp_path / "bom.json"
    path.write_text('{"components":[],"components":[]}')
    with pytest.raises(ValueError):
        AIBOM.load(path)


def test_signature_policy_cli_requires_explicit_project(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text('{"version":1,"artifacts":[]}')
    path = tmp_path / "bom.json"
    AIBOM().save(path)
    result = CliRunner().invoke(main, ["validate", str(path), "--signature-policy", str(policy)])
    assert result.exit_code != 0 and "requires --project" in result.output
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "--signature-policy", str(policy)])
    assert result.exit_code != 0


def _schema_validator() -> Draft202012Validator:
    return Draft202012Validator(
        json.loads(
            (Path(__file__).parents[1] / "schemas/nexus-symbiote-aibom-1.0.schema.json").read_text()
        )
    )


def test_dependency_edges_reject_unknown_fields_in_schema_and_model():
    edge = {
        "source_ref": "agent:a",
        "target_ref": "agent:a",
        "relationship": "depends-on",
        "condition": "only after human approval",
    }
    document = AIBOM(components=[AgentComponent(bom_ref="agent:a", name="a")]).to_dict()
    document["dependencies"] = [edge]
    assert list(_schema_validator().iter_errors(document))
    with pytest.raises(ValidationError):
        AIBOM.model_validate(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [("trust_remote_code", "no"), ("trust_remote_code", 0), ("tool_count", "3"), ("timestamp", 1)],
)
def test_scalars_are_as_strict_as_the_published_schema(field, value):
    document = AIBOM().to_dict()
    if field == "timestamp":
        document["metadata"]["timestamp"] = value
    elif field == "tool_count":
        document["components"] = [
            {"bom_ref": "s", "component_type": "mcp-server", "name": "s", field: value}
        ]
    else:
        document["components"] = [
            {"bom_ref": "m", "component_type": "model", "name": "m", field: value}
        ]
    assert list(_schema_validator().iter_errors(document))
    with pytest.raises(ValidationError):
        AIBOM.model_validate(document)


@pytest.mark.parametrize(
    ("version", "shown"),
    [("2.0.0", "version 2.0.0"), ("1.2.0", "version 1.2.0"), ("\x1b[2Jx", "an unrecognised")],
)
def test_unsupported_native_versions_fail_with_the_supported_versions(tmp_path, version, shown):
    from nexus_symbiote.core.aibom import NativeFormatError

    document = AIBOM().to_dict()
    document["metadata"]["spec_version"] = version
    document["metadata"]["future_field"] = True
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(document))
    with pytest.raises(NativeFormatError, match="supported: 1.0.x, 1.1.x") as raised:
        AIBOM.load(path)
    assert shown in str(raised.value) and "\x1b" not in str(raised.value)
    result = CliRunner().invoke(main, ["summary", str(path)])
    assert result.exit_code == 1 and "supported: 1.0.x, 1.1.x" in result.output


def test_format_1_0_documents_still_load_and_new_documents_are_1_1(tmp_path):
    example = Path(__file__).parents[1] / "schemas/examples/minimal-aibom.json"
    assert AIBOM.load(example).metadata.spec_version == "1.0.0"
    assert AIBOM().to_dict()["metadata"]["spec_version"] == "1.1.0"


def test_loader_refuses_links_and_special_files_without_blocking(tmp_path):
    import os
    import threading

    from nexus_symbiote.core.aibom import NativeFormatError

    real = tmp_path / "real.json"
    AIBOM().save(real)
    (tmp_path / "link.json").symlink_to(real)
    with pytest.raises(NativeFormatError, match="symbolic link"):
        AIBOM.load(tmp_path / "link.json")
    (tmp_path / "linked").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(NativeFormatError, match="symbolic link"):
        AIBOM.load(tmp_path / "linked" / "real.json")
    with pytest.raises(NativeFormatError, match="not a regular file"):
        AIBOM.load(tmp_path)
    with pytest.raises(NativeFormatError, match="does not exist"):
        AIBOM.load(tmp_path / "missing.json")
    fifo = tmp_path / "pipe.json"
    os.mkfifo(fifo)
    outcome: list[BaseException] = []
    reader = threading.Thread(
        target=lambda: outcome.append(pytest.raises(NativeFormatError, AIBOM.load, fifo).value)
    )
    reader.start()
    reader.join(timeout=10)
    assert not reader.is_alive() and outcome
    assert "not a regular file" in str(outcome[0])


def test_cli_names_why_an_inventory_could_not_be_opened(tmp_path):
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    (tmp_path / "real").mkdir()
    AIBOM().save(tmp_path / "real" / "bom.json")
    (tmp_path / "linked").symlink_to(tmp_path / "real", target_is_directory=True)
    result = CliRunner().invoke(main, ["summary", str(tmp_path / "linked" / "bom.json")])
    assert result.exit_code == 1
    assert "pass the real path" in result.output
    assert "Not a directory" not in result.output and "Errno" not in result.output


def test_save_replaces_a_link_instead_of_writing_through_it(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    target = tmp_path / "bom.json"
    target.symlink_to(victim)
    AIBOM().save(target)
    assert victim.read_text() == "keep"
    assert not target.is_symlink() and AIBOM.load(target).components == []


def test_writer_and_reader_share_one_size_limit(tmp_path, monkeypatch):
    from nexus_symbiote.core import aibom as module
    from nexus_symbiote.core.aibom import NativeFormatError

    bom = AIBOM(components=[AgentComponent(bom_ref=f"agent:{i}", name="a") for i in range(40)])
    indented, compact = bom.to_json(), json.dumps(bom.to_dict(), separators=(",", ":"))
    monkeypatch.setattr(module, "MAX_NATIVE_BYTES", len(compact.encode()))
    assert len(indented) > len(compact)
    path = tmp_path / "bom.json"
    bom.save(path)
    assert path.read_text() == compact and len(AIBOM.load(path).components) == 40
    monkeypatch.setattr(module, "MAX_NATIVE_BYTES", len(compact.encode()) - 1)
    with pytest.raises(NativeFormatError, match="limit that native readers accept"):
        bom.to_native_json()
    with pytest.raises(NativeFormatError, match="native inventory limit"):
        AIBOM.load(path)


def test_overlong_references_are_refused():
    from nexus_symbiote.core.models import MAX_REFERENCE_CHARS

    with pytest.raises(ValidationError):
        AgentComponent(bom_ref="a" * (MAX_REFERENCE_CHARS + 1), name="a")
