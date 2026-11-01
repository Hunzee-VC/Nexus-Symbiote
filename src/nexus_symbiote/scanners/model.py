"""Model weight scanner.

Discovers ML models in a project, classifies serialization format safety,
checks for model signing, and computes weight hashes.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from contextlib import nullcontext
from pathlib import Path
from typing import Any, BinaryIO

from nexus_symbiote.core.enums import (
    RiskSeverity,
    SerializationSafety,
    TrustTier,
)
from nexus_symbiote.core.hashing import open_regular_file, parse_json_strict
from nexus_symbiote.core.models import ModelComponent, RiskAssessment
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.utils.crypto import SigstoreArtifactPolicy, verify_sigstore_bundle

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

MAX_MODEL_HEADER_BYTES = 1024 * 1024
_DTYPE_BYTES = {
    "BOOL": 1,
    "U8": 1,
    "I8": 1,
    "F8_E4M3": 1,
    "F8_E4M3FN": 1,
    "F8_E5M2": 1,
    "I16": 2,
    "U16": 2,
    "F16": 2,
    "BF16": 2,
    "I32": 4,
    "U32": 4,
    "F32": 4,
    "I64": 8,
    "U64": 8,
    "F64": 8,
}
_UNSAFE_SUFFIXES = {".pickle", ".pkl", ".pt", ".pth", ".bin", ".joblib"}


def inspect_model_format(
    path: Path, *, stream: BinaryIO | None = None
) -> tuple[SerializationSafety, str]:
    """Inspect bounded structure without deserializing a model or running code.

    SAFE means the checked file has a supported non-executable tensor container
    layout. It is not a claim about model behavior, parser vulnerabilities,
    adjacent repository code, or the safety of the eventual loader.
    """
    if path.suffix.lower() in _UNSAFE_SUFFIXES:
        return SerializationSafety.UNSAFE_CODE_EXECUTION, "Potential code-executing loader format"
    if path.suffix.lower() != ".safetensors":
        return SerializationSafety.UNKNOWN, "No bounded structural validator for this format/loader"
    try:
        context = nullcontext(stream) if stream is not None else open_regular_file(path)
        with context as opened:
            size = os.fstat(opened.fileno()).st_size
            prefix = opened.read(8)
            if len(prefix) != 8:
                raise ValueError("Missing SafeTensors header length")
            length = int.from_bytes(prefix, "little")
            if not 2 <= length <= MAX_MODEL_HEADER_BYTES or length > size - 8:
                raise ValueError("Invalid or over-limit SafeTensors header length")
            raw_header = opened.read(length)
            if len(raw_header) != length or not raw_header.startswith(b"{"):
                raise ValueError("Invalid SafeTensors header")
            header = parse_json_strict(raw_header, max_bytes=MAX_MODEL_HEADER_BYTES)
            if not isinstance(header, dict):
                raise ValueError("SafeTensors header must be an object")
            data_bytes = size - 8 - length
            spans: list[tuple[int, int]] = []
            for name, entry in header.items():
                if name == "__metadata__":
                    if not isinstance(entry, dict) or not all(
                        isinstance(k, str) and isinstance(v, str) for k, v in entry.items()
                    ):
                        raise ValueError("Invalid SafeTensors metadata")
                    continue
                if not isinstance(entry, dict) or set(entry) != {"dtype", "shape", "data_offsets"}:
                    raise ValueError("Invalid tensor descriptor")
                dtype, shape, offsets = entry["dtype"], entry["shape"], entry["data_offsets"]
                if not isinstance(dtype, str) or dtype not in _DTYPE_BYTES:
                    raise ValueError("Unsupported tensor dtype")
                if (
                    not isinstance(shape, list)
                    or len(shape) > 64
                    or not all(type(n) is int and n >= 0 for n in shape)
                ):
                    raise ValueError("Invalid tensor shape")
                if (
                    not isinstance(offsets, list)
                    or len(offsets) != 2
                    or not all(type(n) is int and 0 <= n <= data_bytes for n in offsets)
                ):
                    raise ValueError("Invalid tensor offsets")
                start, end = offsets
                elements = 1
                for dim in shape:
                    elements *= dim
                if end < start or end - start != elements * _DTYPE_BYTES[dtype]:
                    raise ValueError("Tensor shape and offsets disagree")
                spans.append((start, end))
            cursor = 0
            for start, end in sorted(spans):
                if start != cursor:
                    raise ValueError("Tensor buffer contains holes or overlaps")
                cursor = end
            if cursor != data_bytes:
                raise ValueError("Tensor buffer is not fully indexed")
        return SerializationSafety.SAFE, "Bounded SafeTensors header, shapes and offsets checked"
    except (OSError, ValueError, RecursionError, UnicodeError):
        return SerializationSafety.UNKNOWN, "Malformed or unsupported SafeTensors structure"


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

    def __init__(self, signature_policies: Sequence[SigstoreArtifactPolicy] = ()) -> None:
        self._signature_policies = {p.artifact_path.resolve(): p for p in signature_policies}
        self._discovered_paths: tuple[Path, ...] = ()
        if len(self._signature_policies) != len(signature_policies):
            raise ValueError("Duplicate artifact signature policies")

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        # One deterministic walk and one aggregate budget for all model/config
        # reads. Large weights are streamed; metadata remains capped at four MiB.
        with self._collection(
            project_root, result, max_total_bytes=MAX_HASH_SIZE + 32 * 1024 * 1024
        ) as files:
            self._discovered_paths = tuple(files.root / path for path in files.iter_files())
            model_dirs = sorted(
                {
                    path.parent
                    for path in self._discovered_paths
                    if path.suffix.lower() in MODEL_EXTENSIONS
                }
            )
            if not model_dirs:
                result.surfaces_excluded.append("model-weights (no model files found)")
            for model_dir in model_dirs:
                result.surfaces_scanned.append(str(model_dir))
                result.components.extend(self._scan_model_directory(model_dir))
        return result

    def _scan_model_directory(self, model_dir: Path) -> list[ModelComponent]:
        components: list[ModelComponent] = []
        model_name = model_dir.relative_to(root).as_posix()

        config = self._read_model_config(model_dir)
        tokenizer_hash = self._hash_tokenizer(model_dir)
        chat_template_hash = self._hash_chat_template(model_dir, config)

        assert self._files is not None
        for path in self._discovered_paths:
            if path.parent != model_dir:
                continue
            ext = path.suffix.lower()
            if ext not in MODEL_EXTENSIONS:
                continue

            fmt_key, fmt_name = MODEL_EXTENSIONS[ext]
            try:
                with self._files.open_regular(path, max_bytes=MAX_HASH_SIZE) as stream:
                    safety, format_evidence = inspect_model_format(path, stream=stream)
            except (OSError, ValueError):
                safety, format_evidence = (
                    SerializationSafety.UNKNOWN,
                    "Artifact could not be inspected",
                )
            weight_hash = self._files.hash_file(path, max_bytes=MAX_HASH_SIZE)

            signing_status, signing_identity = self._check_signing(path, weight_hash)
            risks = self._assess_model_risks(path, fmt_key, safety, signing_status, config)

            trust_tier = TrustTier.UNKNOWN
            if signing_status == "sigstore-signed":
                trust_tier = TrustTier.THIRD_PARTY_SIGNED

            component_hashes: dict[str, str] = {}
            if fmt_key == "safetensors":
                component_hashes.update(safetensors_fingerprint(path) or {})
            if weight_hash:
                component_hashes["sha256"] = weight_hash

            model_type = self._infer_model_type(config, path)
            derivation = config.get("peft_type") if config else None
            quant = (
                (config.get("quantization_method") or config.get("quant_method"))
                if config
                else None
            )
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
                properties={"format_inspection": format_evidence},
                model_type=model_type,
                derivation_type=derivation,
                quantization_method=quant,
                trust_remote_code=trust_remote_code,
                tokenizer_hash=tokenizer_hash,
                chat_template_hash=chat_template_hash,
                hashes=component_hashes,
                source_path=str(path),
                trust_tier=trust_tier,
                risks=risks,
            )
            comp.tensor_inventory_hash = comp.hashes.get("tensor_inventory_sha256")
            comp.safetensors_header_hash = comp.hashes.get("safetensors_header_sha256")
            components.append(comp)

        return components

    def _read_model_config(self, model_dir: Path) -> dict[str, Any] | None:
        for cfg_name in MODEL_CONFIG_FILES:
            cfg_path = model_dir / cfg_name
            if cfg_path in self._discovered_paths:
                data = self._safe_read_json(cfg_path)
                if isinstance(data, dict):
                    return data
        return None

    def _check_signing(self, artifact: Path, weight_hash: str | None) -> tuple[str, str | None]:
        policy = self._signature_policies.get(artifact.resolve())
        if policy is not None:
            if weight_hash is None:
                return "verification-failed", None
            result = verify_sigstore_bundle(
                artifact, policy.bundle_path, policy.expected_identity, policy.expected_issuer
            )
            if (
                result.verified
                and result.identity == policy.expected_identity
                and result.issuer == policy.expected_issuer
                and result.details
                and result.details.get("artifact_digest") == weight_hash
            ):
                return "sigstore-signed", result.identity
            return "verification-failed", None
        # An adjacent file is a discovery fact, never proof of a signature.
        if any(artifact.parent / name in self._discovered_paths for name in SIGNING_FILES):
            return "signature-present-unverified", None
        # A directory-local search cannot prove the absence of external signatures.
        return "signature-not-found", None

    def _hash_tokenizer(self, model_dir: Path) -> str | None:
        for name in ("tokenizer.json", "tokenizer.model", "spiece.model"):
            path = model_dir / name
            if path in self._discovered_paths and self._files is not None:
                return self._files.hash_file(path)
        return None

    def _hash_chat_template(self, model_dir: Path, config: dict[str, Any] | None) -> str | None:
        if config and "chat_template" in config:
            from nexus_symbiote.core.hashing import hash_bytes

            template = config["chat_template"]
            if isinstance(template, str):
                return hash_bytes(template.encode("utf-8"))
        jinja_path = model_dir / "chat_template.jinja2"
        if jinja_path in self._discovered_paths and self._files is not None:
            return self._files.hash_file(jinja_path)
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

        if safety == SerializationSafety.UNKNOWN:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="serialization_format_unknown",
                    detail=f"Model '{path.name}' format/loader safety could not be established.",
                    recommendation="Validate the actual container and the specific loader before admission.",
                )
            )

        if signing_status != "sigstore-signed":
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="signing_status",
                    detail=f"Model '{path.name}' has no verified artifact-bound signature ({signing_status}).",
                    recommendation="Sign with OpenSSF Model Signing (Sigstore).",
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
