"""models-local collector: manifests, serialization evidence, lineage and indicator tags."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from symbiote.collect.base import CollectContext, run_collectors
from symbiote.collect.models_local import ModelsLocalCollector
from symbiote.model.entities import Evidence, Model
from symbiote.model.enums import (
    CoverageStatus,
    DerivationKind,
    ModelKind,
    SerializationFormat,
    SerializationRisk,
    SignatureStatus,
    Surface,
    TriState,
    ValueState,
)

P2_SYSTEM = b"\x80\x02cposix\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03."


def _safetensors(path: Path, *, bad: bool = False) -> None:
    header = {"w": {"dtype": "F32", "shape": [2 if bad else 1], "data_offsets": [0, 4]}}
    raw = json.dumps(header).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<Q", len(raw)) + raw + b"\x00" * 4)


def _models(result: object) -> dict[str, Model]:
    return {e.id: e for e in result.entities if isinstance(e, Model)}  # type: ignore[attr-defined]


def test_clean_and_malicious_models(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    clean = repo / "models" / "clean"
    _safetensors(clean / "model.safetensors")
    (clean / "config.json").write_text(json.dumps({"architectures": ["X"]}))
    (clean / "model.sig").write_text("{}")
    bad = repo / "models" / "bad"
    bad.mkdir(parents=True)
    (bad / "pytorch_model.bin").write_bytes(P2_SYSTEM)
    (bad / "config.json").write_text(json.dumps({"auto_map": {"AutoModel": "m.M"}}))
    _safetensors(bad / "extra.safetensors", bad=True)
    adapter = repo / "models" / "lora"
    _safetensors(adapter / "adapter_model.safetensors")
    (adapter / "adapter_config.json").write_text(
        json.dumps({"base_model_name_or_path": "org/base", "peft_type": "LORA", "r": 8})
    )
    ctx = CollectContext(root=repo, platform="linux", agent_id="agent:a")
    result = run_collectors(ctx, [ModelsLocalCollector()])[0]
    models = _models(result)
    assert set(models) == {"model:models-bad", "model:models-clean", "model:models-lora"}

    good = models["model:models-clean"]
    assert good.model_kind is ModelKind.WEIGHTS
    assert good.weights is not None and good.weights.value is not None
    assert good.weights.value.formats == [SerializationFormat.SAFETENSORS]
    assert good.manifest is not None and good.manifest.root == good.weights.value.manifest_root
    assert good.serialization is not None and good.serialization.value is not None
    assert good.serialization.value.risk_class is SerializationRisk.NONE
    assert good.signature is not None and good.signature.status is SignatureStatus.CLAIMED

    evil = models["model:models-bad"]
    assert evil.serialization is not None and evil.serialization.value is not None
    assert evil.serialization.value.risk_class is SerializationRisk.CODE_EXEC_ON_LOAD
    assert evil.serialization.value.trust_remote_code is TriState.TRUE
    assert "malicious-indicator:pickle-global:posix.system" in evil.tags
    assert any(t.startswith("format-anomaly:size-mismatch") for t in evil.tags)
    assert "trust-remote-code" in evil.tags
    report_digest = evil.serialization.value.scanner_report_digest
    assert any(isinstance(e, Evidence) and e.digest == report_digest for e in result.evidence)

    lora = models["model:models-lora"]
    assert lora.model_kind is ModelKind.ADAPTER
    assert lora.derivations[0].kind is DerivationKind.ADAPTER_OF and lora.derivations[0].parent == "org/base"
    assert result.coverage[Surface.CODE].status is CoverageStatus.QUERIED


def test_hash_budget_marks_identity_unknown(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _safetensors(repo / "m" / "model.safetensors")
    ctx = CollectContext(root=repo, platform="linux", options={"models_hash_budget_bytes": 1})
    result = run_collectors(ctx, [ModelsLocalCollector()])[0]
    model = next(iter(_models(result).values()))
    assert model.weights is not None and model.weights.state is ValueState.UNKNOWN
    assert model.manifest is None
    assert result.coverage[Surface.CODE].status is CoverageStatus.PARTIAL


def test_hf_cache_pins_revision(tmp_path: Path) -> None:
    home = tmp_path / "home"
    commit = "a" * 40
    snap = home / ".cache" / "huggingface" / "hub" / "models--org--tiny" / "snapshots" / commit
    _safetensors(snap / "model.safetensors")
    ctx = CollectContext(root=tmp_path / "repo", home=home, platform="linux", options={"hf_cache": True})
    (tmp_path / "repo").mkdir()
    result = run_collectors(ctx, [ModelsLocalCollector()])[0]
    model = _models(result)["model:org-tiny"]
    assert model.weights is not None and model.weights.value is not None
    assert model.weights.value.purl == f"pkg:huggingface/org/tiny@{commit}"


def test_empty_repo_queried(tmp_path: Path) -> None:
    result = run_collectors(CollectContext(root=tmp_path, platform="linux"), [ModelsLocalCollector()])[0]
    assert not _models(result)
    assert result.coverage[Surface.CODE].status is CoverageStatus.QUERIED


def test_explicit_path_embedding_and_symlink_fail_closed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside-models" / "emb"
    _safetensors(outside / "model.safetensors")
    (outside / "modules.json").write_text("[]")
    linked = repo / "linked"
    _safetensors(linked / "model.safetensors")
    (linked / "alias.safetensors").symlink_to(linked / "model.safetensors")
    ctx = CollectContext(root=repo, platform="linux", options={"models": [str(outside)]})
    result = run_collectors(ctx, [ModelsLocalCollector()])[0]
    models = _models(result)
    emb = next(m for m in models.values() if m.name == "emb")
    assert emb.model_kind is ModelKind.EMBEDDING
    sym = models["model:linked"]
    assert sym.weights is not None and sym.weights.state is ValueState.UNKNOWN
    assert any(s.error_class == "undigestable" for s in result.coverage[Surface.CODE].sources)
