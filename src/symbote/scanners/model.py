"""Model weight scanner.

Discovers ML models in a project, classifies serialization format safety,
checks for model signing, and computes weight hashes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from symbote.core.enums import (
    SERIALIZATION_FORMAT_SAFETY,
    RiskSeverity,
    SerializationSafety,
    TrustTier,
)
from symbote.core.hashing import hash_file
from symbote.core.models import ModelComponent, RiskAssessment
from symbote.scanners.base import Scanner, ScanResult

MODEL_EXTENSIONS = {
    ".safetensors": ("safetensors", "safe-tensors"),
    ".onnx": ("onnx", "onnx"),
    ".pt": ("pt", "pytorch"),
    ".pth": ("pth", "pytorch"),
    ".bin": ("bin", "pytorch-legacy"),
    ".pickle": ("pickle", "pickle"),
    ".pkl": ("pickle", "pickle"),
    ".joblib": ("joblib", "scikit-learn"),
    ".gguf": ("gguf", "llama.cpp"),
    ".ggml": ("ggml", "llama.cpp-legacy"),
}

MODEL_CONFIG_FILES = [
    "config.json",
    "model_config.json",
    "adapter_config.json",
    "tokenizer_config.json",
    "generation_config.json",
    "quantize_config.json",
]

SIGNING_FILES = [
    "model.sig",
    "model.sigstore",
    ".sigstore",
    "signature.json",
    "model.intoto.jsonl",
]

MAX_HASH_SIZE = 5 * 1024 * 1024 * 1024


class ModelScanner(Scanner):
    name = "model"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        model_dirs = self._find_model_directories(project_root)

        if not model_dirs:
            result.surfaces_excluded.append("model-weights (no model files found)")
            return result

        for model_dir in model_dirs:
            result.surfaces_scanned.append(str(model_dir))
            comps = self._scan_model_directory(model_dir)
            result.components.extend(comps)

        return result

    def _find_model_directories(self, root: Path) -> list[Path]:
        dirs: set[Path] = set()
        for ext in MODEL_EXTENSIONS:
            for f in root.rglob(f"*{ext}"):
                if ".git" in f.parts or "node_modules" in f.parts or "__pycache__" in f.parts:
                    continue
                dirs.add(f.parent)
        return sorted(dirs)

    def _scan_model_directory(self, model_dir: Path) -> list[ModelComponent]:
        components: list[ModelComponent] = []
        model_name = model_dir.name

        config = self._read_model_config(model_dir)
        signing_status, signing_identity = self._check_signing(model_dir)
        tokenizer_hash = self._hash_tokenizer(model_dir)
        chat_template_hash = self._hash_chat_template(model_dir, config)

        for path in sorted(model_dir.iterdir()):
            if not path.is_file():
                continue
            ext = path.suffix.lower()
            if ext not in MODEL_EXTENSIONS:
                continue

            fmt_key, fmt_name = MODEL_EXTENSIONS[ext]
            safety = SERIALIZATION_FORMAT_SAFETY.get(fmt_key, SerializationSafety.UNKNOWN)

            weight_hash = None
            if path.stat().st_size <= MAX_HASH_SIZE:
                try:
                    weight_hash = hash_file(path)
                except OSError:
                    pass

            risks = self._assess_model_risks(path, fmt_key, safety, signing_status, config)

            trust_tier = TrustTier.UNKNOWN
            if signing_status == "sigstore-signed":
                trust_tier = TrustTier.THIRD_PARTY_SIGNED
            elif safety == SerializationSafety.SAFE:
                trust_tier = TrustTier.THIRD_PARTY_UNSIGNED

            model_type = self._infer_model_type(config, path)
            derivation = config.get("peft_type") if config else None
            quant = (config.get("quantization_method") or config.get("quant_method")) if config else None
            trust_remote_code = bool(config.get("trust_remote_code")) if config else False

            comp = ModelComponent(
                bom_ref=f"model:{model_name}/{path.name}",
                name=f"{model_name}/{path.name}",
                serialization_format=fmt_name,
                serialization_safety=safety,
                signing_status=signing_status,
                signing_identity=signing_identity,
                model_type=model_type,
                derivation_type=derivation,
                quantization_method=quant,
                trust_remote_code=trust_remote_code,
                tokenizer_hash=tokenizer_hash,
                chat_template_hash=chat_template_hash,
                hashes={"sha256": weight_hash} if weight_hash else {},
                source_path=str(path),
                trust_tier=trust_tier,
                risks=risks,
            )
            components.append(comp)

        return components

    def _read_model_config(self, model_dir: Path) -> dict[str, Any] | None:
        for cfg_name in MODEL_CONFIG_FILES:
            cfg_path = model_dir / cfg_name
            if cfg_path.exists():
                data = self._safe_read_json(cfg_path)
                if isinstance(data, dict):
                    return data
        return None

    def _check_signing(self, model_dir: Path) -> tuple[str, str | None]:
        for sig_file in SIGNING_FILES:
            sig_path = model_dir / sig_file
            if sig_path.exists():
                return "sigstore-signed", str(sig_path)
        return "unsigned", None

    def _hash_tokenizer(self, model_dir: Path) -> str | None:
        for name in ("tokenizer.json", "tokenizer.model", "spiece.model"):
            path = model_dir / name
            if path.exists():
                try:
                    return hash_file(path)
                except OSError:
                    pass
        return None

    def _hash_chat_template(self, model_dir: Path, config: dict[str, Any] | None) -> str | None:
        if config and "chat_template" in config:
            from symbote.core.hashing import hash_bytes
            template = config["chat_template"]
            if isinstance(template, str):
                return hash_bytes(template.encode("utf-8"))
        jinja_path = model_dir / "chat_template.jinja2"
        if jinja_path.exists():
            try:
                return hash_file(jinja_path)
            except OSError:
                pass
        return None

    def _infer_model_type(self, config: dict[str, Any] | None, path: Path) -> str:
        if config:
            if config.get("peft_type") or config.get("adapter_config"):
                return "adapter"
            if config.get("quantization_method") or config.get("quant_method"):
                return "quantized"
        name_lower = path.name.lower()
        if "adapter" in name_lower or "lora" in name_lower:
            return "adapter"
        if "embed" in name_lower:
            return "embedding"
        return "foundation"

    def _assess_model_risks(
        self, path: Path, fmt_key: str, safety: SerializationSafety,
        signing_status: str, config: dict[str, Any] | None,
    ) -> list[RiskAssessment]:
        risks: list[RiskAssessment] = []

        if safety == SerializationSafety.UNSAFE_CODE_EXECUTION:
            risks.append(RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="serialization_format",
                detail=f"Model '{path.name}' uses {fmt_key} format — arbitrary code execution on deserialization.",
                recommendation="Convert to SafeTensors. Block pickle/pt/pth in production.",
                references=["https://huggingface.co/blog/safetensors-security-audit"],
            ))

        if safety == SerializationSafety.UNSAFE_TEMPLATE_INJECTION:
            risks.append(RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="serialization_format",
                detail=f"Model '{path.name}' uses GGUF; chat template metadata vulnerable to Jinja2 SSTI (CVE-2024-34359).",
                recommendation="Validate chat template content. Use llama-cpp-python >= 0.2.72.",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2024-34359"],
            ))

        if signing_status == "unsigned":
            risks.append(RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="signing_status",
                detail=f"Model '{path.name}' has no cryptographic signature.",
                recommendation="Sign with OpenSSF Model Signing (Sigstore).",
                references=["https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/"],
            ))

        if config and config.get("trust_remote_code"):
            risks.append(RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="code_execution",
                detail="trust_remote_code=True allows arbitrary code from the model repository.",
                recommendation="Audit remote code or use a model that does not require it.",
            ))

        return risks
