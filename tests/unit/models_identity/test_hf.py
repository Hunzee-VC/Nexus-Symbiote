"""Tests for local model-directory analysis (trust_remote_code, chat templates, typed lineage)."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from symbiote.models_identity.hf import analyze_model_dir, huggingface_purl

P2_SYSTEM = b"\x80\x02cposix\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03."


def _safetensors(path: Path) -> None:
    raw = json.dumps({"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    path.write_bytes(struct.pack("<Q", len(raw)) + raw + b"\x00" * 4)


def test_clean_safetensors_snapshot(tmp_path: Path) -> None:
    _safetensors(tmp_path / "model.safetensors")
    (tmp_path / "config.json").write_text(json.dumps({"architectures": ["LlamaForCausalLM"]}))
    result = analyze_model_dir(tmp_path)
    assert result.formats == ("safetensors",)
    assert result.risk_class == "none"
    assert result.trust_remote_code is False
    assert "config.json" in result.config_digests
    assert not result.malicious_indicators


def test_remote_code_template_and_lineage(tmp_path: Path) -> None:
    _safetensors(tmp_path / "model.safetensors")
    (tmp_path / "config.json").write_text(
        json.dumps(
            {
                "_name_or_path": "org/base-7b",
                "auto_map": {"AutoModelForCausalLM": "modeling_custom.CustomLM"},
                "quantization_config": {"quant_method": "gptq", "bits": 4, "group_size": 128},
            }
        )
    )
    (tmp_path / "modeling_custom.py").write_text("print('custom')\n")
    (tmp_path / "tokenizer_config.json").write_text(
        json.dumps({"chat_template": "{{ messages[0]['content'] }}"})
    )
    (tmp_path / "README.md").write_text(
        "---\nlicense: apache-2.0\nbase_model: org/base-7b\nbase_model_relation: quantized\n---\n# card\n"
    )
    (tmp_path / "model.sig").write_text("{}")
    result = analyze_model_dir(tmp_path)
    assert result.trust_remote_code is True
    assert result.risk_class == "code-exec-on-load"
    assert result.custom_code_files == ("modeling_custom.py",)
    assert result.chat_template_executable
    assert result.signature_bundles == ("model.sig",)
    kinds = {(d.kind, d.parent) for d in result.derivations}
    assert ("quantizationOf", "org/base-7b") in kinds
    quant = next(d for d in result.derivations if d.kind == "quantizationOf")
    assert quant.parameters["quant_method"] == "gptq"
    assert quant.parameters_digest.startswith("sha256:")
    assert result.card["license"] == "apache-2.0"


def test_adapter_lineage(tmp_path: Path) -> None:
    _safetensors(tmp_path / "adapter_model.safetensors")
    (tmp_path / "adapter_config.json").write_text(
        json.dumps(
            {
                "base_model_name_or_path": "org/base-7b",
                "peft_type": "LORA",
                "r": 16,
                "lora_alpha": 32,
                "target_modules": ["q_proj", "v_proj"],
            }
        )
    )
    result = analyze_model_dir(tmp_path)
    adapter = next(d for d in result.derivations if d.kind == "adapterOf")
    assert adapter.parent == "org/base-7b"
    assert adapter.parameters["r"] == 16


def test_disguised_pickle_is_found(tmp_path: Path) -> None:
    (tmp_path / "weights.dat").write_bytes(P2_SYSTEM)
    result = analyze_model_dir(tmp_path)
    assert result.risk_class == "code-exec-on-load"
    assert result.malicious_indicators
    assert any("non-model extension" in w for w in result.warnings)


def test_huggingface_purl_pinning() -> None:
    purl, pinned = huggingface_purl("microsoft/deberta-v3-base", "559062ad13d311b87b2c455e67dcd5f1c8f65111")
    assert purl == "pkg:huggingface/microsoft/deberta-v3-base@559062ad13d311b87b2c455e67dcd5f1c8f65111"
    assert pinned
    purl_main, pinned_main = huggingface_purl("microsoft/deberta-v3-base", "main")
    assert purl_main.endswith("@main")
    assert not pinned_main
    assert huggingface_purl("gpt2") == ("pkg:huggingface/gpt2", False)
