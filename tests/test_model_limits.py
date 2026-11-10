"""Model and tokenizer files are hashed under the operator's model limits, which name themselves."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from nexus_symbiote import limits
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import ModelComponent
from nexus_symbiote.graph import assemble_repository_agent
from nexus_symbiote.policy import PolicyError
from nexus_symbiote.scanners.model import ModelScanner, safetensors_fingerprint
from nexus_symbiote.utils.confined import hash_confined_file


def _safetensors(path: Path, data: bytes = b"abcd") -> None:
    header = json.dumps(
        {"weight": {"dtype": "U8", "shape": [len(data)], "data_offsets": [0, len(data)]}},
        separators=(",", ":"),
    ).encode()
    header += b" " * (-len(header) % 8)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(len(header).to_bytes(8, "little") + header + data)


def test_a_tokenizer_larger_than_the_file_limit_is_hashed_as_a_model_file(tmp_path):
    _safetensors(tmp_path / "llm" / "model.safetensors")
    tokenizer = b'{"model": {"vocab": "' + b"t" * (5 * limits.MIB) + b'"}}'
    (tmp_path / "llm" / "tokenizer.json").write_bytes(tokenizer)
    result = ModelScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert result.components[0].tokenizer_hash == "sha256:" + hashlib.sha256(tokenizer).hexdigest()


def test_the_aggregate_model_budget_names_itself(tmp_path):
    _safetensors(tmp_path / "a" / "model.safetensors", b"x" * 400)
    _safetensors(tmp_path / "b" / "model.safetensors", b"y" * 400)
    with limits.applied(replace(limits.DEFAULTS, model_total_bytes=600)):
        result = ModelScanner().scan(tmp_path)
    by_ref = {component.bom_ref: component for component in result.components}
    assert by_ref["model:a/model.safetensors"].hashes
    assert by_ref["model:b/model.safetensors"].hashes == {}
    assert (
        "b/model.safetensors: model-total-bytes limit of 600 bytes exceeded; "
        "raise it with --limit model-total-bytes=N"
    ) in [failure.replace(str(tmp_path) + "/", "") for failure in result.scan_failures]


def test_the_per_file_model_limit_names_itself(tmp_path):
    _safetensors(tmp_path / "model.safetensors", b"x" * 400)
    with limits.applied(replace(limits.DEFAULTS, model_bytes=256)):
        result = ModelScanner().scan(tmp_path)
    assert result.components[0].hashes == {}
    assert (
        "model.safetensors: model-bytes limit of 256 bytes exceeded; "
        "raise it with --limit model-bytes=N"
    ) in [failure.replace(str(tmp_path) + "/", "") for failure in result.scan_failures]
    assert result.components[0].hashes == {}


def test_every_model_hash_path_follows_the_same_limit(tmp_path):
    _safetensors(tmp_path / "model.safetensors", b"x" * 400)
    small = replace(limits.DEFAULTS, model_bytes=256)
    with limits.applied(small), pytest.raises(OSError):
        hash_confined_file(tmp_path, "model.safetensors")
    with limits.applied(small), pytest.raises(OSError):
        safetensors_fingerprint(Path("model.safetensors"), root=tmp_path)
    assert hash_confined_file(tmp_path, "model.safetensors").startswith("sha256:")
    assert safetensors_fingerprint(Path("model.safetensors"), root=tmp_path)


def test_agent_manifest_models_follow_the_model_limit(tmp_path):
    _safetensors(tmp_path / "models" / "weights.safetensors", b"x" * 400)
    (tmp_path / "agent.yaml").write_text("name: test\nmodels: {local: {path: models}}\n")

    def assemble() -> None:
        bom = AIBOM(
            components=[
                ModelComponent(
                    bom_ref="model:local",
                    name="local",
                    source_path="models/weights.safetensors",
                )
            ]
        )
        assemble_repository_agent(bom, tmp_path)

    assemble()
    with limits.applied(replace(limits.DEFAULTS, model_bytes=256)), pytest.raises(PolicyError):
        assemble()
