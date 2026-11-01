"""Model weight scanner.

Discovers ML models in a project, classifies serialization format safety,
checks for model signing, and computes weight hashes. Weights are hashed as
streams and are never deserialised or loaded.
"""

from __future__ import annotations

import stat
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import (
    SERIALIZATION_FORMAT_SAFETY,
    RiskSeverity,
    SerializationSafety,
    TrustTier,
)
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import ModelComponent, RiskAssessment
from nexus_symbiote.core.vocab import SIGNING_NOT_FOUND, SIGNING_PRESENT_UNVERIFIED
from nexus_symbiote.scanners.base import (
    Scanner,
    ScanResult,
    hash_regular_file,
    matched_exclusion,
    relative_posix,
)

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
    # These formats have no entry in SERIALIZATION_FORMAT_SAFETY, so they are reported as unclassified.
    ".h5": ("h5", "hdf5"),
    ".keras": ("keras", "keras"),
    ".ckpt": ("ckpt", "checkpoint"),
    ".npz": ("npz", "numpy-archive"),
    ".tflite": ("tflite", "tflite"),
    ".mlmodel": ("mlmodel", "coreml"),
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


class ModelScanner(Scanner):
    name = "model"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        weights = self._discover_weights(project_root, result)

        if not weights:
            if not result.surfaces_excluded and not result.scan_failures:
                result.record_absent("model-weights", ["project tree (recursive)"])
            return result

        for model_dir in sorted(weights):
            result.surfaces_scanned.append(relative_posix(model_dir, project_root))
            result.components.extend(
                self._scan_model_directory(model_dir, weights[model_dir], project_root, result)
            )

        return result

    def _discover_weights(self, root: Path, result: ScanResult) -> dict[Path, list[Path]]:
        """Find every weight file with one walk and one predicate, grouped by directory."""
        weights: dict[Path, list[Path]] = {}
        excluded_roots: set[str] = set()
        for path in sorted(root.rglob("*")):
            if path.suffix.lower() not in MODEL_EXTENSIONS:
                continue
            blocked = _excluded_root(path, root, self.exclude_paths)
            if blocked is not None:
                excluded_roots.add(relative_posix(blocked, root))
                continue
            rel = relative_posix(path, root)
            try:
                mode = path.lstat().st_mode
            except OSError:
                result.record_failure(f"Failed to inspect {rel}")
                continue
            if stat.S_ISLNK(mode):
                result.record_failure(f"Model weight {rel} is a symbolic link and was not followed")
            elif stat.S_ISREG(mode):
                weights.setdefault(path.parent, []).append(path)
            elif not stat.S_ISDIR(mode):
                result.record_failure(f"Model weight {rel} is not a regular file")
        for rel in sorted(excluded_roots):
            result.record_excluded(rel, "excluded by policy")
        return weights

    def _scan_model_directory(
        self,
        model_dir: Path,
        weights: list[Path],
        root: Path,
        result: ScanResult,
    ) -> list[ModelComponent]:
        rel_dir = relative_posix(model_dir, root)
        config = self._read_model_config(model_dir, root, result)
        signing_status, signing_identity = self._check_signing(model_dir)
        tokenizer_hash = self._hash_tokenizer(model_dir, root, result)
        chat_template_hash = self._hash_chat_template(model_dir, root, config, result)
        derivation = _config_text(config, "peft_type", rel_dir, result)
        quant = _config_text(config, "quantization_method", rel_dir, result)
        quant = quant or _config_text(config, "quant_method", rel_dir, result)
        # This is a declaration in a local config, not the runtime loader argument.
        # An absent or non-boolean value cannot establish the effective setting.
        configured_remote_code = config.get("trust_remote_code") if config else None
        trust_remote_code = (
            configured_remote_code if isinstance(configured_remote_code, bool) else None
        )
        # Signing and remote-code risks describe the directory, so they are attached once.
        directory_risks = self._directory_risks(rel_dir, signing_status, config)

        components: list[ModelComponent] = []
        for index, path in enumerate(sorted(weights)):
            fmt_key, fmt_name = MODEL_EXTENSIONS[path.suffix.lower()]
            safety = SERIALIZATION_FORMAT_SAFETY.get(fmt_key, SerializationSafety.UNKNOWN)
            rel_file = relative_posix(path, root)

            weight_hash: str | None = None
            try:
                weight_hash = hash_regular_file(path)
            except OSError:
                result.record_failure(f"Failed to hash {rel_file}")

            risks = self._file_risks(path, fmt_key, safety)
            if index == 0:
                risks.extend(directory_risks)

            # A signature filename and serialization format do not establish trust.
            trust_tier = TrustTier.UNKNOWN

            components.append(
                ModelComponent(
                    bom_ref=f"model:{rel_dir}/{path.name}",
                    name=rel_file,
                    serialization_format=fmt_name,
                    serialization_safety=safety,
                    signing_status=signing_status,
                    signing_identity=signing_identity,
                    model_type=self._infer_model_type(config, path),
                    derivation_type=derivation,
                    quantization_method=quant,
                    trust_remote_code=trust_remote_code,
                    tokenizer_hash=tokenizer_hash,
                    chat_template_hash=chat_template_hash,
                    hashes={"sha256": weight_hash} if weight_hash else {},
                    source_path=rel_file,
                    trust_tier=trust_tier,
                    risks=risks,
                )
            )

        return components

    def _read_model_config(
        self, model_dir: Path, root: Path, result: ScanResult
    ) -> dict[str, Any] | None:
        for cfg_name in MODEL_CONFIG_FILES:
            cfg_path = model_dir / cfg_name
            if cfg_path.exists() or cfg_path.is_symlink():
                data = self._safe_read_json(cfg_path)
                if isinstance(data, dict):
                    return data
                result.record_failure(f"Failed to parse {relative_posix(cfg_path, root)}")
        return None

    def _check_signing(self, model_dir: Path) -> tuple[str, str | None]:
        for sig_file in SIGNING_FILES:
            sig_path = model_dir / sig_file
            if sig_path.exists():
                # A filename alone cannot establish format, subject or signer.
                return SIGNING_PRESENT_UNVERIFIED, None
        # Search is directory-local; it cannot prove that no signature exists.
        return SIGNING_NOT_FOUND, None

    def _hash_tokenizer(self, model_dir: Path, root: Path, result: ScanResult) -> str | None:
        for name in ("tokenizer.json", "tokenizer.model", "spiece.model"):
            path = model_dir / name
            if path.exists() or path.is_symlink():
                try:
                    return hash_regular_file(path)
                except OSError:
                    result.record_failure(f"Failed to hash {relative_posix(path, root)}")
        return None

    def _hash_chat_template(
        self,
        model_dir: Path,
        root: Path,
        config: dict[str, Any] | None,
        result: ScanResult,
    ) -> str | None:
        if config and "chat_template" in config:
            template = config["chat_template"]
            if isinstance(template, str):
                try:
                    return hash_bytes(template.encode("utf-8"))
                except UnicodeEncodeError:
                    result.record_failure(
                        f"chat_template in {relative_posix(model_dir, root)} is not valid Unicode"
                    )
                    return None
        jinja_path = model_dir / "chat_template.jinja2"
        if jinja_path.exists() or jinja_path.is_symlink():
            try:
                return hash_regular_file(jinja_path)
            except OSError:
                result.record_failure(f"Failed to hash {relative_posix(jinja_path, root)}")
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

    def _file_risks(
        self, path: Path, fmt_key: str, safety: SerializationSafety
    ) -> list[RiskAssessment]:
        risks: list[RiskAssessment] = []

        if safety == SerializationSafety.UNSAFE_CODE_EXECUTION:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.CRITICAL,
                    category="serialization_format",
                    detail=f"Model '{path.name}' uses {fmt_key} format — arbitrary code execution on deserialization.",
                    recommendation="Convert to SafeTensors. Block pickle/pt/pth in production.",
                    references=["https://huggingface.co/blog/safetensors-security-audit"],
                )
            )

        if safety == SerializationSafety.UNSAFE_TEMPLATE_INJECTION:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="serialization_format",
                    detail=f"Model '{path.name}' uses GGUF; chat template metadata vulnerable to Jinja2 SSTI (CVE-2024-34359).",
                    recommendation="Validate chat template content. Use llama-cpp-python >= 0.2.72.",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2024-34359"],
                )
            )

        if fmt_key not in SERIALIZATION_FORMAT_SAFETY:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="format-unclassified",
                    detail=f"Model '{path.name}' uses {fmt_key} format, which has no safety classification.",
                    recommendation="Confirm that loading this format cannot execute code before use.",
                )
            )

        return risks

    def _directory_risks(
        self, rel_dir: str, signing_status: str, config: dict[str, Any] | None
    ) -> list[RiskAssessment]:
        risks: list[RiskAssessment] = []

        if signing_status in {SIGNING_NOT_FOUND, SIGNING_PRESENT_UNVERIFIED}:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="signing_status",
                    detail=(
                        f"Model directory '{rel_dir}' has no verified authorized signature "
                        f"({signing_status})."
                    ),
                    recommendation="Verify a signature against the model and an explicit signer policy.",
                    references=[
                        "https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/"
                    ],
                )
            )

        if config is not None and "trust_remote_code" in config:
            declared: object = config["trust_remote_code"]
            if declared is True:
                risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.CRITICAL,
                        category="code_execution",
                        detail="trust_remote_code=True allows arbitrary code from the model repository.",
                        recommendation="Audit remote code or use a model that does not require it.",
                    )
                )
            elif not isinstance(declared, bool):
                risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.MEDIUM,
                        category="trust-remote-code-unknown",
                        detail=(
                            f"trust_remote_code in '{rel_dir}' is not a boolean, so the effective "
                            "setting cannot be established."
                        ),
                        recommendation="Declare trust_remote_code as true or false, and audit any remote code it enables.",
                    )
                )

        return risks


def _config_text(
    config: dict[str, Any] | None, key: str, rel_dir: str, result: ScanResult
) -> str | None:
    value: object = config.get(key) if config else None
    if value is None or isinstance(value, str):
        return value
    result.record_failure(f"'{key}' in {rel_dir} is not a string; ignored")
    return None


def _excluded_root(path: Path, root: Path, patterns: tuple[str, ...]) -> Path | None:
    """Return the shallowest directory, or the file itself, that a policy pattern excludes."""
    parts = path.relative_to(root).parts
    for depth in range(1, len(parts) + 1):
        candidate = root.joinpath(*parts[:depth])
        if matched_exclusion(candidate, root, patterns):
            return candidate
    return None
