"""Model weight scanner.

Discovers ML models in a project, classifies serialization format safety,
checks for model signing, and computes weight hashes.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO

from safetensors import SafetensorError, safe_open

from nexus_symbiote.core.enums import (
    SERIALIZATION_FORMAT_SAFETY,
    RiskSeverity,
    SerializationSafety,
    TrustTier,
)
from nexus_symbiote.core.models import ModelComponent, RiskAssessment
from nexus_symbiote.scanners.base import (
    MAX_MODEL_BYTES,
    Scanner,
    ScanResult,
    _open_regular,
    hash_regular_file,
    read_regular_text,
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


@contextmanager
def _library_path(stream: BinaryIO) -> Iterator[Path]:
    # The Rust SafeTensors reader takes a filename. Hand it the already-open file.
    for base in ("/proc/self/fd", "/dev/fd"):
        alias = Path(base, str(stream.fileno()))
        if alias.exists():
            yield alias
            return
    # Windows has no descriptor pathname. Parse a private, bounded copy.
    stream.seek(0)
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp, "weights")
        total = 0
        with copy.open("wb") as out:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_MODEL_BYTES:
                    raise ValueError("model exceeds scan limit")
                out.write(chunk)
        yield copy


def _inspect_file(path: Path) -> tuple[str, SerializationSafety, str]:
    ext_format = MODEL_EXTENSIONS[path.suffix.lower()][0]
    with _open_regular(path, MAX_MODEL_BYTES) as fd, os.fdopen(fd, "rb", closefd=False) as stream:
        stat_before = os.fstat(stream.fileno())
        if stat_before.st_size > MAX_MODEL_BYTES:
            raise ValueError("model exceeds scan limit")
        head = stream.read(9)
        fmt = ext_format
        safety = SERIALIZATION_FORMAT_SAFETY.get(fmt, SerializationSafety.UNKNOWN)
        if head.startswith(b"\x80") and len(head) > 1 and head[1] <= 5:
            fmt, safety = "pickle", SerializationSafety.UNSAFE_CODE_EXECUTION
        elif head.startswith(b"GGUF"):
            fmt, safety = "gguf", SerializationSafety.UNSAFE_TEMPLATE_INJECTION
        elif fmt == "safetensors" or (len(head) == 9 and head[-1:] == b"{"):
            safety = SerializationSafety.UNKNOWN
            header_len = int.from_bytes(head[:8], "little")
            if (
                len(head) == 9
                and head[-1:] == b"{"
                and header_len <= min(stat_before.st_size - 8, 16 * 1024 * 1024)
            ):
                with _library_path(stream) as name:
                    try:
                        with safe_open(name, framework="numpy") as tensors:
                            tensors.keys()
                    except SafetensorError:
                        pass
                    else:
                        fmt, safety = "safetensors", SerializationSafety.SAFE
        elif safety == SerializationSafety.SAFE:
            # No format parser for ONNX/GGML here. A filename alone proves nothing.
            safety = SerializationSafety.UNKNOWN
        digest = hashlib.sha256()
        total = 0
        stream.seek(0)
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_MODEL_BYTES:
                raise ValueError("model exceeds scan limit")
            digest.update(chunk)
        stat_after = os.fstat(stream.fileno())
        if total != stat_before.st_size or stat_after.st_ctime_ns != stat_before.st_ctime_ns:
            raise ValueError("model changed while being read")
    return fmt, safety, "sha256:" + digest.hexdigest()


class ModelScanner(Scanner):
    name = "model"

    def __init__(
        self, expected_identity: str | None = None, expected_issuer: str | None = None
    ) -> None:
        if bool(expected_identity) != bool(expected_issuer):
            raise ValueError("Model verification requires both signer and issuer")
        self.expected_identity = expected_identity
        self.expected_issuer = expected_issuer

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        model_dirs = self._find_model_directories(project_root)

        if not model_dirs:
            result.surfaces_excluded.append("model-weights (no model files found)")
            return result

        for model_dir in model_dirs:
            result.surfaces_scanned.append(str(model_dir))
            comps = self._scan_model_directory(project_root, model_dir, result)
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

    def _scan_model_directory(
        self, root: Path, model_dir: Path, result: ScanResult
    ) -> list[ModelComponent]:
        components: list[ModelComponent] = []
        model_name = model_dir.relative_to(root).as_posix()

        config = self._read_model_config(model_dir, result)
        tokenizer_hash = self._hash_tokenizer(model_dir, result)
        chat_template_hash = self._hash_chat_template(model_dir, config, result)

        for path in sorted(model_dir.iterdir()):
            ext = path.suffix.lower()
            if ext not in MODEL_EXTENSIONS:
                continue

            fmt_key, fmt_name = MODEL_EXTENSIONS[ext]
            safety = SerializationSafety.UNKNOWN

            weight_hash = None
            try:
                fmt_key, safety, weight_hash = _inspect_file(path)
                fmt_name = MODEL_EXTENSIONS.get("." + fmt_key, (fmt_key, fmt_key))[1]
            except (OSError, ValueError):
                result.scan_failures.append(f"Failed to inspect {path}")
            signing_status, signing_identity = self._check_signing(path, weight_hash)

            risks = self._assess_model_risks(path, fmt_key, safety, signing_status, config)

            # A signature filename and serialization format do not establish trust.
            trust_tier = TrustTier.THIRD_PARTY_SIGNED if signing_identity else TrustTier.UNKNOWN

            model_type = self._infer_model_type(config, path)
            derivation = config.get("peft_type") if config else None
            quant = (
                (config.get("quantization_method") or config.get("quant_method"))
                if config
                else None
            )
            # This is a declaration in a local config, not the runtime loader argument.
            # An absent or non-boolean value cannot establish the effective setting.
            configured_remote_code = config.get("trust_remote_code") if config else None
            trust_remote_code = (
                configured_remote_code if isinstance(configured_remote_code, bool) else None
            )

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

    def _read_model_config(self, model_dir: Path, result: ScanResult) -> dict[str, Any] | None:
        for cfg_name in MODEL_CONFIG_FILES:
            cfg_path = model_dir / cfg_name
            if cfg_path.exists() or cfg_path.is_symlink():
                data = self._safe_read_json(cfg_path)
                if isinstance(data, dict):
                    return data
                result.scan_failures.append(f"Failed to parse {cfg_path}")
        return None

    def _check_signing(self, path: Path, digest: str | None) -> tuple[str, str | None]:
        names = [path.name + ".sigstore.json", path.name + ".sigstore", *SIGNING_FILES]
        found = False
        for name in names:
            bundle = path.with_name(name)
            if not bundle.exists() and not bundle.is_symlink():
                continue
            found = True
            if digest and self.expected_identity and self.expected_issuer:
                from nexus_symbiote.utils.crypto import verify_sigstore_digest

                try:
                    bundle_json = read_regular_text(bundle).encode()
                except (OSError, ValueError):
                    continue
                result = verify_sigstore_digest(
                    digest.removeprefix("sha256:"),
                    bundle_json,
                    self.expected_identity,
                    self.expected_issuer,
                )
                if result.verified:
                    return "sigstore-signed", self.expected_identity
        return ("signature-present-unverified" if found else "signature-not-found"), None

    def _hash_tokenizer(self, model_dir: Path, result: ScanResult) -> str | None:
        for name in ("tokenizer.json", "tokenizer.model", "spiece.model"):
            path = model_dir / name
            if path.exists() or path.is_symlink():
                try:
                    return hash_regular_file(path)
                except OSError:
                    result.scan_failures.append(f"Failed to hash {path}")
        return None

    def _hash_chat_template(
        self, model_dir: Path, config: dict[str, Any] | None, result: ScanResult
    ) -> str | None:
        if config and "chat_template" in config:
            from nexus_symbiote.core.hashing import hash_bytes

            template = config["chat_template"]
            if isinstance(template, str):
                return hash_bytes(template.encode("utf-8"))
        jinja_path = model_dir / "chat_template.jinja2"
        if jinja_path.exists() or jinja_path.is_symlink():
            try:
                return hash_regular_file(jinja_path)
            except OSError:
                result.scan_failures.append(f"Failed to hash {jinja_path}")
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
        self,
        path: Path,
        fmt_key: str,
        safety: SerializationSafety,
        signing_status: str,
        config: dict[str, Any] | None,
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

        if signing_status in {"unsigned", "signature-not-found", "signature-present-unverified"}:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="signing_status",
                    detail=f"Model '{path.name}' has no verified authorized signature ({signing_status}).",
                    recommendation="Verify a signature against the model and an explicit signer policy.",
                    references=[
                        "https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/"
                    ],
                )
            )

        if config and config.get("trust_remote_code") is True:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.CRITICAL,
                    category="code_execution",
                    detail="trust_remote_code=True allows arbitrary code from the model repository.",
                    recommendation="Audit remote code or use a model that does not require it.",
                )
            )

        return risks
