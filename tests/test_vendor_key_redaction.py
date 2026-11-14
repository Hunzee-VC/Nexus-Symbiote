"""AI-vendor API keys are redacted wherever free text, locators or specifiers are exported."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_symbiote.scanners.rag import RAGScanner
from nexus_symbiote.scanners.registry import RegistryScanner
from nexus_symbiote.utils.secrets import REDACTED, redact_text, secret_like

# Assembled at run time so the source holds no token-shaped literal. Each body has the
# alphabet and length of the vendor's real keys.
VENDOR_KEYS = {
    "pinecone": "".join(("pc", "sk_", "7Hq2Lm_", "9ZxK3pQwRtYuIoPaSdFgHjKlZxCvBnMq")),
    "groq": "".join(("g", "sk_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6")),
    "replicate": "".join(("r", "8_", "Qw3Er5Ty7Ui9Op1As3Df5Gh7Jk9Lz1Xc3Vb5N")),
    "perplexity": "".join(
        ("pp", "lx-", "4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e")
    ),
    "xai": "".join(("x", "ai-", "Hk3Lm9Np2Qr6St8Uv1Wx4Yz7Ab0Cd3Ef6Gh9Ij2Kl5Mn8Op1Qr4St7Uv0Wx3Yz6")),
    "langsmith-personal": "".join(
        ("lsv2", "_pt_", "3f9a1c7e5b2d8f4a6c0e2b9d7f1a3c5e", "_9b7d5f3a1c")
    ),
    "langsmith-service": "".join(
        ("lsv2", "_sk_", "3f9a1c7e5b2d8f4a6c0e2b9d7f1a3c5e", "_9b7d5f3a1c")
    ),
    "tavily": "".join(("tv", "ly-", "dev-", "Qm3Xz7Lp1Rk9Tb5Vn2Wc8Yd4Hf6Jg0Ks")),
    "fireworks": "".join(("f", "w_", "3ZPvB4kQ9mN7xR2tL8wY5cH1")),
}
# Ordinary names that share a vendor prefix: model names, module names, short ids.
ORDINARY_NAMES = [
    "pplx-7b-online",
    "xai-grok-beta",
    "tvly-search-tool",
    "fw_config_loader",
    "fw_" + "a" * 19,
    "r8_short_name",
    "gsk_abc123",
    "pcsk_" + "a" * 12,
    "lsv2_pt_short",
    "lsv2_other_" + "a" * 30,
]


@pytest.mark.parametrize("vendor", sorted(VENDOR_KEYS))
def test_vendor_key_is_redacted_from_free_text_and_identifiers(vendor):
    key = VENDOR_KEYS[vendor]
    assert redact_text(f"connect with {key} first") == f"connect with {REDACTED} first"
    assert redact_text(f"X_{key}", identifier=True) == f"X_{REDACTED}"
    assert secret_like("CONFIG", key)


@pytest.mark.parametrize("name", ORDINARY_NAMES)
def test_ordinary_names_with_a_vendor_prefix_are_kept(name):
    assert redact_text(name) == name
    assert redact_text(name, identifier=True) == name


def _rag_source(root: Path, source: dict[str, object]):
    root.mkdir(parents=True, exist_ok=True)
    (root / "rag_config.json").write_text(json.dumps({"sources": [source]}))
    result = RAGScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    (component,) = [c for c in result.components if c.bom_ref.startswith("rag:")]
    return component


@pytest.mark.parametrize("vendor", sorted(VENDOR_KEYS))
def test_vendor_key_never_reaches_a_rag_record(tmp_path, vendor):
    key = VENDOR_KEYS[vendor]
    component = _rag_source(
        tmp_path,
        {
            "name": f"kb-{key}",
            "type": "vector-store",
            "sanitization": True,
            "source_uris": [key, f"docs/{key}/notes.md"],
            "collection": key,
            "namespace": f"team-{key}",
        },
    )
    text = component.model_dump_json()
    assert key not in text
    assert component.name == f"kb-{REDACTED}"
    assert component.source_uris == ["[redacted]", "[redacted]"]
    assert component.properties["index_identities"] == {
        "collection": "[redacted]",
        "namespace": "[redacted]",
    }


@pytest.mark.parametrize("vendor", sorted(VENDOR_KEYS))
def test_vendor_key_in_a_package_json_specifier_is_redacted(tmp_path, vendor):
    key = VENDOR_KEYS[vendor]
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"openai": key, "@openai/agents": f"npm:{key}@1.0.0"}})
    )
    result = RegistryScanner().scan(tmp_path)
    components = [c for c in result.components if c.bom_ref.startswith("registry:npm/")]
    assert components
    for component in components:
        text = component.model_dump_json()
        assert key not in text
        assert REDACTED in text
    assert key not in json.dumps(result.scan_failures + result.surfaces_excluded)
