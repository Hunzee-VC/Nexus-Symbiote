"""A model directory's metadata files linked to a file named as holding credentials."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.scanners.model import ModelScanner

SECRET = b"OPENAI_API_KEY=sk-synthetic-000000\n"


def _safetensors(path: Path) -> None:
    header = json.dumps({"w": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}}).encode()
    header += b" " * (-len(header) % 8)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<Q", len(header)) + header + b"abcd")


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("config.json", "../../.env"),
        ("generation_config.json", "../../secrets/model.json"),
        ("tokenizer.json", "../../.env"),
        ("chat_template.jinja", "../../.env.local"),
    ],
)
def test_a_model_file_linked_to_a_credential_file_is_a_gap_not_a_digest(tmp_path, name, target):
    (tmp_path / "secrets").mkdir()
    (tmp_path / ".env").write_bytes(SECRET)
    (tmp_path / ".env.local").write_bytes(SECRET)
    (tmp_path / "secrets/model.json").write_bytes(SECRET)
    _safetensors(tmp_path / "models/m/model.safetensors")
    (tmp_path / "models/m" / name).symlink_to(target)
    result = ModelScanner().scan(tmp_path)
    published = json.dumps([c.model_dump(mode="json") for c in result.components])
    assert hash_bytes(SECRET) not in published
    assert hash_bytes(SECRET).removeprefix("sha256:") not in published
    assert any(
        entry.startswith(f"models/m/{name}: a symlink leads to")
        and "whose name says it holds credentials" in entry
        for entry in result.surfaces_excluded
    ), result.surfaces_excluded
    assert len(result.components) == 1


def test_a_model_config_linked_to_an_ordinary_file_is_digested(tmp_path):
    (tmp_path / "shared").mkdir()
    config = b'{"model_type": "llama"}'
    (tmp_path / "shared/config.json").write_bytes(config)
    _safetensors(tmp_path / "models/m/model.safetensors")
    (tmp_path / "models/m/config.json").symlink_to("../../shared/config.json")
    result = ModelScanner().scan(tmp_path)
    assert not result.surfaces_excluded, result.surfaces_excluded
    (component,) = result.components
    assert hash_bytes(config).removeprefix("sha256:") in json.dumps(
        component.model_dump(mode="json")
    ) or hash_bytes(config) in json.dumps(component.model_dump(mode="json"))
