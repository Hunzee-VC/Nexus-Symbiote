"""Local model-directory analysis: serialization risk, executable code paths and typed lineage (WP3).

Reads a Hugging Face-style snapshot directory (or any directory of model files) **statically**:
configuration JSON/YAML is parsed with safe loaders, weights are only sniffed and header-parsed by
:mod:`symbiote.models_identity.serialization`, and no repository code is imported. Output feeds the
``Model(kind=weights)`` entity of ``spec/agentbom-profile.md`` §3.8 (serialization, derivations,
signature facts, tokenizer/chat-template references) through the collector adapter.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal

import yaml
from packageurl import PackageURL

from symbiote.models_identity.serialization import (
    ChatTemplateFinding,
    FileAssessment,
    RiskClass,
    assess_file,
    iter_model_files,
    max_risk,
    scan_chat_template,
    sniff_format,
)

__all__ = [
    "Derivation",
    "ModelDirAnalysis",
    "analyze_model_dir",
    "huggingface_purl",
]

DerivationKind = Literal[
    "fineTuneOf", "adapterOf", "quantizationOf", "mergeOf", "distillationOf", "conversionOf"
]

#: File names/extensions treated as model artefacts (everything else is still sniffed by magic bytes).
WEIGHT_SUFFIXES: Final = frozenset(
    {
        ".safetensors",
        ".bin",
        ".pt",
        ".pth",
        ".ckpt",
        ".pkl",
        ".pickle",
        ".joblib",
        ".dill",
        ".gguf",
        ".ggml",
        ".onnx",
        ".ort",
        ".h5",
        ".hdf5",
        ".keras",
        ".npy",
        ".npz",
        ".msgpack",
        ".tflite",
        ".mlmodel",
        ".pb",
        ".7z",
        ".mar",
    }
)
_TEXT_SUFFIXES: Final = frozenset(
    {".md", ".txt", ".json", ".yaml", ".yml", ".jinja", ".py", ".model", ".tiktoken"}
)
_SIGNATURE_NAMES: Final = ("model.sig", "model.sigstore.json")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_MAX_JSON: Final = 32 * 1024 * 1024
_HF_RELATION: Final[dict[str, DerivationKind]] = {
    "adapter": "adapterOf",
    "merge": "mergeOf",
    "quantized": "quantizationOf",
    "finetune": "fineTuneOf",
}


@dataclass(frozen=True, slots=True)
class Derivation:
    """A typed lineage edge with its parameters (``Model.derivations`` in the profile)."""

    kind: DerivationKind
    parent: str
    parameters: Mapping[str, object]
    locator: str
    inferred: bool = False

    @property
    def parameters_digest(self) -> str:
        canonical = json.dumps(self.parameters, sort_keys=True, separators=(",", ":"), default=str)
        return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ModelDirAnalysis:
    root: str
    files: tuple[FileAssessment, ...]
    formats: tuple[str, ...]
    risk_class: RiskClass
    trust_remote_code: bool | None
    trust_remote_code_reasons: tuple[str, ...]
    custom_code_files: tuple[str, ...]
    chat_templates: tuple[ChatTemplateFinding, ...]
    derivations: tuple[Derivation, ...]
    card: Mapping[str, object]
    config_digests: Mapping[str, str]
    signature_bundles: tuple[str, ...]
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def chat_template_executable(self) -> bool:
        return bool(self.chat_templates)

    @property
    def malicious_indicators(self) -> bool:
        return any(f.malicious_indicators for f in self.files) or any(
            t.ssti_indicators for t in self.chat_templates
        )


def huggingface_purl(repo_id: str, revision: str | None = None) -> tuple[str, bool]:
    """Build a ``pkg:huggingface`` purl; returns ``(purl, pinned)``.

    Only a full 40-hex commit id pins a Hugging Face repository; branch or tag names float (I8: the name is a
    locator, the digest is the identity).
    """
    namespace, _, name = repo_id.rpartition("/")
    version = revision.lower() if revision else None
    purl = PackageURL(type="huggingface", namespace=namespace or None, name=name, version=version)
    return purl.to_string(), bool(version and _HEX40.match(version))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _load_json(path: Path, warnings: list[str]) -> dict[str, object] | None:
    try:
        if path.stat().st_size > _MAX_JSON:
            warnings.append(f"{path.name}: larger than {_MAX_JSON} bytes, not parsed")
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        warnings.append(f"{path.name}: unreadable JSON ({type(exc).__name__})")
        return None
    return data if isinstance(data, dict) else None


def _card_frontmatter(readme: Path, warnings: list[str]) -> dict[str, object]:
    try:
        text = readme.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    match = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", text, re.S)
    if not match:
        return {}
    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError:
        warnings.append("README.md: model-card frontmatter is not valid YAML")
        return {}
    return data if isinstance(data, dict) else {}


def _as_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, (str, int, float))]
    return []


def analyze_model_dir(root: Path, *, max_files: int = 100_000) -> ModelDirAnalysis:
    """Analyze a local model directory without executing or deserializing anything."""
    warnings: list[str] = []
    files: list[FileAssessment] = []
    custom_code: list[str] = []
    templates: list[ChatTemplateFinding] = []
    derivations: list[Derivation] = []
    config_digests: dict[str, str] = {}
    signatures: list[str] = []
    trc_reasons: list[str] = []

    for path in iter_model_files(root, max_files=max_files):
        rel = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        if path.name in _SIGNATURE_NAMES or path.name.endswith(".sigstore.json"):
            signatures.append(rel)
            continue
        if suffix == ".py":
            custom_code.append(rel)
            continue
        if suffix in WEIGHT_SUFFIXES:
            files.append(assess_file(path, display=rel))
        elif suffix not in _TEXT_SUFFIXES and sniff_format(path) != "other":
            # disguised artefact: magic bytes say "model file" despite an innocuous extension
            assessment = assess_file(path, display=rel)
            files.append(assessment)
            warnings.append(f"{rel}: {assessment.format} content behind a non-model extension")
        if path.name in {
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
            "generation_config.json",
            "special_tokens_map.json",
            "adapter_config.json",
            "chat_template.jinja",
            "chat_template.json",
            "tokenizer.model",
            "preprocessor_config.json",
        }:
            config_digests[rel] = _sha256_file(path)

    config = _load_json(root / "config.json", warnings) if (root / "config.json").is_file() else None
    if config is not None:
        auto_map = config.get("auto_map")
        if isinstance(auto_map, dict) and auto_map:
            trc_reasons.append(
                "config.json auto_map: " + ", ".join(f"{k}={v}" for k, v in sorted(auto_map.items()))
            )
        quant = config.get("quantization_config")
        if isinstance(quant, dict):
            method = str(quant.get("quant_method", "unknown"))
            parent = str(config.get("_name_or_path", "unknown"))
            derivations.append(
                Derivation(
                    "quantizationOf",
                    parent,
                    {"quant_method": method, **_scalar_items(quant)},
                    "config.json#/quantization_config",
                    inferred=parent == "unknown",
                )
            )

    tok = (
        _load_json(root / "tokenizer_config.json", warnings)
        if (root / "tokenizer_config.json").is_file()
        else None
    )
    if tok is not None:
        auto_map_t = tok.get("auto_map")
        if isinstance(auto_map_t, dict) and auto_map_t:
            trc_reasons.append("tokenizer_config.json auto_map (custom tokenizer code)")
        chat = tok.get("chat_template")
        if isinstance(chat, str):
            templates.append(scan_chat_template("tokenizer_config.json#/chat_template", "default", chat))
        elif isinstance(chat, list):
            for i, item in enumerate(chat):
                if isinstance(item, dict) and isinstance(item.get("template"), str):
                    templates.append(
                        scan_chat_template(
                            f"tokenizer_config.json#/chat_template/{i}",
                            str(item.get("name", i)),
                            item["template"],
                        )
                    )
    for jinja in sorted(
        [root / "chat_template.jinja", *sorted((root / "additional_chat_templates").glob("*.jinja"))]
    ):
        if jinja.is_file():
            text = jinja.read_text(encoding="utf-8", errors="replace")[: 4 * 1024 * 1024]
            templates.append(scan_chat_template(jinja.relative_to(root).as_posix(), jinja.stem, text))
    chat_json = root / "chat_template.json"
    if chat_json.is_file():
        data = _load_json(chat_json, warnings)
        if data and isinstance(data.get("chat_template"), str):
            templates.append(
                scan_chat_template("chat_template.json#/chat_template", "default", str(data["chat_template"]))
            )
    for assessment in files:
        templates.extend(assessment.chat_templates)

    adapter = (
        _load_json(root / "adapter_config.json", warnings)
        if (root / "adapter_config.json").is_file()
        else None
    )
    if adapter is not None:
        base = adapter.get("base_model_name_or_path")
        params: dict[str, object] = {
            k: adapter[k]
            for k in ("peft_type", "task_type", "r", "lora_alpha", "lora_dropout", "target_modules")
            if k in adapter
        }
        derivations.append(
            Derivation(
                "adapterOf",
                str(base or "unknown"),
                params,
                "adapter_config.json#/base_model_name_or_path",
                inferred=not base,
            )
        )

    for merge_name in ("mergekit_config.yml", "mergekit_config.yaml"):
        merge_path = root / merge_name
        if merge_path.is_file():
            try:
                merge = yaml.safe_load(merge_path.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError):
                warnings.append(f"{merge_name}: unreadable")
                continue
            if isinstance(merge, dict):
                method = merge.get("merge_method", "unknown")
                parents: list[str] = []
                for entry in merge.get("models", []) or []:
                    if isinstance(entry, dict) and "model" in entry:
                        parents.append(str(entry["model"]))
                if merge.get("base_model"):
                    parents.append(str(merge["base_model"]))
                for parent in dict.fromkeys(parents):
                    derivations.append(
                        Derivation("mergeOf", parent, {"merge_method": method}, f"{merge_name}#/models")
                    )

    card = _card_frontmatter(root / "README.md", warnings) if (root / "README.md").is_file() else {}
    relation = card.get("base_model_relation")
    for parent in _as_list(card.get("base_model")):
        kind = _HF_RELATION.get(str(relation)) if relation else None
        inferred = kind is None
        if kind is None:
            kind = (
                "adapterOf"
                if adapter is not None
                else "quantizationOf"
                if config and isinstance(config.get("quantization_config"), dict)
                else "mergeOf"
                if any(d.kind == "mergeOf" for d in derivations)
                else "fineTuneOf"
            )
        if not any(d.parent == parent and d.kind == kind for d in derivations):
            derivations.append(Derivation(kind, parent, {}, "README.md#/base_model", inferred=inferred))

    for assessment in files:
        if assessment.gguf is not None:
            source = assessment.gguf.values.get("general.source.huggingface.repository")
            if isinstance(source, str) and source:
                derivations.append(
                    Derivation(
                        "conversionOf",
                        source,
                        {"format": "gguf"},
                        f"{assessment.path}#general.source.huggingface.repository",
                    )
                )
            for base in assessment.gguf.base_models:
                parent = base.get("repo_url") or base.get("name", "unknown")
                derivations.append(
                    Derivation("fineTuneOf", parent, dict(base), f"{assessment.path}#general.base_model")
                )

    trust_remote_code: bool | None
    if trc_reasons:
        trust_remote_code = True
    elif config is None and not files:
        trust_remote_code = None
    else:
        trust_remote_code = False
    if custom_code and not trc_reasons:
        warnings.append(
            "Python files present without auto_map: not loaded automatically, but shipped with the model"
        )

    risks: list[RiskClass] = [f.risk_class for f in files]
    if trust_remote_code:
        risks.append("code-exec-on-load")
    if templates:
        risks.append("template-execution")
    card_view: dict[str, object] = {
        k: card[k]
        for k in ("license", "pipeline_tag", "library_name", "datasets", "tags", "language")
        if k in card
    }
    return ModelDirAnalysis(
        root=root.as_posix(),
        files=tuple(files),
        formats=tuple(sorted({f.format for f in files})),
        risk_class=max_risk(risks),
        trust_remote_code=trust_remote_code,
        trust_remote_code_reasons=tuple(trc_reasons),
        custom_code_files=tuple(custom_code),
        chat_templates=tuple(_dedupe_templates(templates)),
        derivations=tuple(derivations),
        card=card_view,
        config_digests=dict(sorted(config_digests.items())),
        signature_bundles=tuple(signatures),
        warnings=tuple(warnings),
    )


def _scalar_items(mapping: Mapping[str, object]) -> dict[str, object]:
    return {
        k: v for k, v in mapping.items() if isinstance(v, (str, int, float, bool)) and k != "quant_method"
    }


def _dedupe_templates(templates: list[ChatTemplateFinding]) -> list[ChatTemplateFinding]:
    seen: set[tuple[str, str]] = set()
    out: list[ChatTemplateFinding] = []
    for t in templates:
        key = (t.source, t.digest)
        if key not in seen:
            seen.add(key)
            out.append(t)
    return out
