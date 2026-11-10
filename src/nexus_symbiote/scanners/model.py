"""Model weight collector.

Discovers model files in a project and classifies serialization format safety
without loading anything. It binds by digest the other files a loader reads
with the weights: ONNX external data, SavedModel variables and assets, shard
indexes, configuration, tokenizer files, chat templates and declared custom
code. Weight files count as signed only under an operator signature policy.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import pickletools
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, cast

from nexus_symbiote.core.enums import (
    AssuranceLevel,
    RiskSeverity,
    SerializationSafety,
    TrustTier,
)
from nexus_symbiote.core.hashing import (
    descriptor_binding,
    hash_bytes,
    hash_canonical,
    open_regular_file,
)
from nexus_symbiote.core.models import ClaimEvidence, ModelComponent, RiskAssessment
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.shadowscan import REPORT_PATHS
from nexus_symbiote.utils.confined import MAX_HASH_BYTES, ConfinedCollection
from nexus_symbiote.utils.crypto import (
    POLICY_REF_PREFIX,
    SIGNING_EVIDENCE_CLAIM,
    SIGSTORE_MISSING,
    VERIFIED_SIGNING_STATUSES,
    ArtifactPolicy,
    DigestPinPolicy,
    SigningStatus,
    SigstoreArtifactPolicy,
    VerificationResult,
    policy_entries,
    verify_sigstore_bundle,
)
from nexus_symbiote.utils.model_formats import (
    GGUF_LIMIT,
    FormatError,
    InspectionBudget,
    gguf_metadata,
    onnx_external_data,
    template_escape_markers,
)
from nexus_symbiote.utils.tensors import HeaderLimitError, fingerprint_stream, read_header

MODEL_EXTENSIONS = {
    ".safetensors": ("safetensors", "safe-tensors"),
    ".onnx": ("onnx", "onnx"),
    ".pt": ("pt", "pytorch"),
    ".pth": ("pth", "pytorch"),
    ".bin": ("bin", "pytorch-legacy"),
    ".pickle": ("pickle", "pickle"),
    ".pkl": ("pickle", "pickle"),
    ".pck": ("pickle", "pickle"),
    ".dill": ("pickle", "dill"),
    ".joblib": ("joblib", "scikit-learn"),
    ".gguf": ("gguf", "llama.cpp"),
    ".ggml": ("ggml", "llama.cpp-legacy"),
    ".ckpt": ("ckpt", "pytorch-checkpoint"),
    ".pdparams": ("pdparams", "paddlepaddle"),
    ".h5": ("hdf5", "keras-hdf5"),
    ".hdf5": ("hdf5", "keras-hdf5"),
    ".keras": ("keras", "keras"),
    ".tflite": ("tflite", "tensorflow-lite"),
    ".mlmodel": ("mlmodel", "core-ml"),
    ".pte": ("pte", "executorch"),
}
# Generic protobuf files are not models; only the SavedModel graph names are.
NAMED_MODEL_FILES = {
    "saved_model.pb": ("pb", "tensorflow-savedmodel"),
    "saved_model.pbtxt": ("pbtxt", "tensorflow-savedmodel"),
}

MODEL_CONFIG_FILES = [
    "config.json",
    "model_config.json",
    "adapter_config.json",
    "tokenizer_config.json",
    "generation_config.json",
    "quantize_config.json",
    "preprocessor_config.json",
    "processor_config.json",
    "chat_template.json",
]
TOKENIZER_FILES = [
    "tokenizer.json",
    "tokenizer.model",
    "spiece.model",
    "sentencepiece.bpe.model",
    "vocab.json",
    "vocab.txt",
    "merges.txt",
    "special_tokens_map.json",
    "added_tokens.json",
]
CHAT_TEMPLATE_FILES = ["chat_template.jinja", "chat_template.jinja2"]
CHAT_TEMPLATE_DIRECTORY = "additional_chat_templates"
SAVEDMODEL_DIRECTORIES = ["variables", "assets", "assets.extra"]
SAVEDMODEL_FILES = ["fingerprint.pb", "keras_metadata.pb"]

SIGNING_FILES = [
    "model.sig",
    "model.sigstore",
    ".sigstore",
    "signature.json",
    "model.intoto.jsonl",
]
SIGNING_SUFFIXES = [".sig", ".sigstore", ".sigstore.json"]

MAX_HASH_SIZE = 5 * 1024 * 1024 * 1024

MAX_MODEL_HEADER_BYTES = 1024 * 1024
MAX_PICKLE_INSPECTION_BYTES = 65536
_UNSAFE_SUFFIXES = {
    ".pickle",
    ".pkl",
    ".pck",
    ".dill",
    ".pt",
    ".pth",
    ".bin",
    ".joblib",
    ".ckpt",
    ".pdparams",
}
# Archive and compression suffixes do not change what a pickle loader unpickles.
_PICKLE_WRAPPERS = {".tar", ".gz", ".bz2", ".xz", ".lzma", ".zst"}
_TEXT_PICKLE_START = frozenset(b"(cNILFSV}])KJMUTX")
_INDEX = re.compile(r"(?P<base>.+?)\.index(?:\.[A-Za-z0-9_-]+)?\.json", re.IGNORECASE)
_CODE_REFERENCE = re.compile(
    r"(?:[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*--)?"
    r"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*"
)
_HUB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,95})?")
_CONFIG_STRING_FIELDS = ("peft_type", "quantization_method", "quant_method")
SIGSTORE_METHOD = "sigstore-message-signature"
DIGEST_PIN_METHOD = "digest-pin"
DOCUMENTATION = "https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/docs/model-integrity.md"
UNUSED_ENTRY = "signature policy entry names no collected model weight file"
REPORT_ENTRY_KIND = (
    "the ShadowScan report needs a sigstore-message-signature entry; "
    "a digest pin does not authenticate its producer"
)
UNREAD_REPORT_ENTRY = (
    "signature policy entry names a ShadowScan report location that the importer does not read"
)
OUTSIDE_ENTRY = "signature policy entry names an artifact outside the root"
BUDGET_EXHAUSTED = "validation byte budget exhausted"

Verify = Callable[[Path, Path, str | None, str | None], VerificationResult]


def _pickle_family(path: Path) -> bool:
    suffixes = [suffix.lower() for suffix in path.suffixes]
    if suffixes and suffixes[-1] in _UNSAFE_SUFFIXES:
        return True
    return (
        len(suffixes) > 1 and suffixes[-1] in _PICKLE_WRAPPERS and suffixes[-2] in _UNSAFE_SUFFIXES
    )


def model_format(path: Path) -> tuple[str, str] | None:
    """Return the (format key, format name) of a supported model file, or ``None``."""
    detected = MODEL_EXTENSIONS.get(path.suffix.lower()) or NAMED_MODEL_FILES.get(path.name.lower())
    if detected is None and _pickle_family(path):
        return ("pickle", "pickle-archive")
    return detected


def _index_base(path: Path) -> Path | None:
    """The weight file a shard index such as ``model.safetensors.index.json`` describes."""
    match = _INDEX.fullmatch(path.name)
    if match is None or model_format(Path(match["base"])) is None:
        return None
    return path.with_name(match["base"])


def manifest_digest(entries: Iterable[tuple[str, str]]) -> str:
    """SHA-256 of RFC 8785 ``{"files": [{"path": p, "sha256": d}, ...]}``, sorted by path."""
    return hash_canonical(
        {"files": [{"path": path, "sha256": digest} for path, digest in sorted(entries)]}
    )


def _recognized_pickle(stream: BinaryIO, prefix: bytes, size: int) -> str | None:
    """Recognize bounded pickle instructions without loading objects.

    PROTO alone is insufficient: valid tensor header lengths can have the same
    first byte. Static opcode/stack checks must reach STOP within local limits.
    This intentionally leaves unsupported, truncated and large samples unknown.
    """
    binary = len(prefix) >= 2 and prefix[0] == 0x80 and 2 <= prefix[1] <= 5
    if not binary and (not prefix or prefix[0] not in _TEXT_PICKLE_START):
        return None
    sample = prefix + stream.read(max(0, min(size, MAX_PICKLE_INSPECTION_BYTES) - len(prefix)))
    try:
        marks = 0
        for count, (opcode, _, _) in enumerate(pickletools.genops(sample), start=1):
            marks += opcode.name == "MARK"
            if count > 4096 or marks > 64:
                return None
        # dis() only checks opcode stack/memo consistency; it never resolves
        # globals, imports artifact code, invokes reducers or constructs objects.
        pickletools.dis(sample, out=io.StringIO())
    except (ValueError, UnicodeError, OverflowError, RecursionError):
        return None
    kind = "binary" if binary else "text-protocol"
    return f"Recognized {kind} pickle opcode stream; object loading can execute code"


def _recognized_code_container(stream: BinaryIO, prefix: bytes, size: int) -> str | None:
    if prefix[:4] == b"PK\x03\x04":
        # torch.save writes its pickle as the first ZIP member.
        header = prefix + stream.read(22)
        if len(header) == 30:
            name_length = int.from_bytes(header[26:28], "little")
            if 0 < name_length <= 4096 and stream.read(name_length).lower().endswith(b".pkl"):
                return "ZIP archive whose first member is a pickle; torch.load unpickles it"
        return None
    return _recognized_pickle(stream, prefix, size)


def inspect_model_format(
    path: Path, *, stream: BinaryIO | None = None
) -> tuple[SerializationSafety, str]:
    """Inspect bounded structure without deserializing a model or running code.

    SAFE means the checked file has a supported non-executable tensor container
    layout. It is not a claim about model behavior, parser vulnerabilities,
    adjacent repository code, or the safety of the eventual loader.
    """
    if _pickle_family(path):
        return SerializationSafety.UNSAFE_CODE_EXECUTION, "Potential code-executing loader format"
    try:
        context = nullcontext(stream) if stream is not None else open_regular_file(path)
        with context as opened:
            size = os.fstat(opened.fileno()).st_size
            prefix = opened.read(8)
            length = int.from_bytes(prefix, "little")
            safetensors = path.suffix.lower() == ".safetensors"
            tensor_candidate = (
                safetensors
                and len(prefix) == 8
                and 2 <= length <= min(MAX_MODEL_HEADER_BYTES, size - 8)
            )
            if not tensor_candidate:
                container = _recognized_code_container(opened, prefix, size)
                if container is not None:
                    return SerializationSafety.UNSAFE_CODE_EXECUTION, container
            if not safetensors:
                return (
                    SerializationSafety.UNKNOWN,
                    "No bounded structural validator for this format/loader",
                )
            read_header(opened, size, prefix=prefix, max_header_bytes=MAX_MODEL_HEADER_BYTES)
        return SerializationSafety.SAFE, "Bounded SafeTensors header, shapes and offsets checked"
    except HeaderLimitError:
        return SerializationSafety.UNKNOWN, "SafeTensors header exceeds the inspection limit"
    except (OSError, ValueError, RecursionError, UnicodeError):
        return SerializationSafety.UNKNOWN, "Malformed or unsupported SafeTensors structure"


class _HashingModelReader:
    """Hash the inspected prefix and remaining bytes from one pinned stream."""

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self.digest = hashlib.sha256()
        self.bytes_read = 0
        self.prefix = bytearray()

    def fileno(self) -> int:
        return self.stream.fileno()

    def read(self, size: int) -> bytes:
        if self.bytes_read > MAX_HASH_SIZE:
            raise OSError("model artifact exceeds the hash byte limit")
        content = self.stream.read(min(size, MAX_HASH_SIZE + 1 - self.bytes_read))
        self.bytes_read += len(content)
        if self.bytes_read > MAX_HASH_SIZE:
            raise OSError("model artifact exceeds the hash byte limit")
        self.digest.update(content)
        self.prefix.extend(content[: max(0, MAX_MODEL_HEADER_BYTES + 8 - len(self.prefix))])
        return content


class _ReplayReader:
    """Re-read from the start of a hashed stream: the inspected prefix, then the rest."""

    def __init__(self, observed: _HashingModelReader) -> None:
        if observed.bytes_read > len(observed.prefix):
            raise OSError("inspection consumed more than the retained prefix")
        self._replay = bytes(observed.prefix[: observed.bytes_read])
        self._observed = observed

    def read(self, size: int) -> bytes:
        if self._replay:
            data, self._replay = self._replay[:size], self._replay[size:]
            return data
        return self._observed.read(size)


@dataclass(frozen=True)
class ModelArtifactObservation:
    """One bounded, non-executing observation of one opened model artifact."""

    safety: SerializationSafety
    explanation: str
    digest: str
    fingerprint: dict[str, str] = field(default_factory=dict)
    external_data: tuple[str, ...] | None = None
    onnx_error: str | None = None
    chat_templates: tuple[tuple[str, str], ...] = ()
    gguf_architecture: str | None = None
    gguf_error: str | None = None


def observe_model_artifact(
    path: Path, *, stream: BinaryIO, budget: InspectionBudget | None = None
) -> ModelArtifactObservation:
    """Bind structural inspection, format metadata and SHA-256 to one opened artifact.

    The caller must hold a confined regular-file context.
    A pathname replacement cannot substitute different bytes between inspection
    and hashing because neither operation reopens that pathname. The confined
    stream also refuses the observation unless the pathname still resolves to
    this descriptor when the caller's read ends, so the verdict and digest are
    never attributed to a pathname that now names other bytes.
    """
    before = os.fstat(stream.fileno())
    if before.st_size > MAX_HASH_SIZE:
        raise OSError("model artifact exceeds the hash byte limit")
    observed = _HashingModelReader(stream)
    safety, explanation = inspect_model_format(path, stream=cast(BinaryIO, observed))
    detected = model_format(path)
    key = detected[0] if detected is not None else None
    extra: dict[str, Any] = {}
    if safety == SerializationSafety.SAFE:
        extra["fingerprint"] = fingerprint_stream(
            io.BytesIO(bytes(observed.prefix)),
            artifact_size=before.st_size,
            max_header_bytes=MAX_MODEL_HEADER_BYTES,
        )
    elif safety != SerializationSafety.UNSAFE_CODE_EXECUTION and key == "onnx":
        try:
            extra["external_data"] = onnx_external_data(_ReplayReader(observed).read, budget)
        except FormatError as exc:
            extra["onnx_error"] = str(exc)
    elif safety != SerializationSafety.UNSAFE_CODE_EXECUTION and key == "gguf":
        try:
            metadata = gguf_metadata(_ReplayReader(observed).read, budget)
        except FormatError as exc:
            extra["gguf_error"] = str(exc)
        else:
            extra["gguf_architecture"] = metadata.architecture
            extra["chat_templates"] = tuple(
                (f"{path.as_posix()}#{name}", hash_bytes(text))
                for name, text in metadata.chat_templates
            )
            if any(template_escape_markers(text) for _, text in metadata.chat_templates):
                safety = SerializationSafety.UNSAFE_TEMPLATE_INJECTION
                explanation = (
                    "Embedded chat template reaches Python internals through dunder "
                    "attributes, as Jinja sandbox escapes do"
                )
    while observed.read(65536):
        pass
    after = os.fstat(stream.fileno())
    if descriptor_binding(before) != descriptor_binding(after):
        raise OSError("model artifact changed during inspection and hashing")
    return ModelArtifactObservation(
        safety, explanation, "sha256:" + observed.digest.hexdigest(), **extra
    )


def inspect_model_artifact(
    path: Path, *, stream: BinaryIO, metadata: dict[str, str] | None = None
) -> tuple[SerializationSafety, str, str]:
    """Bind structural inspection and SHA-256 to the same opened artifact."""
    observation = observe_model_artifact(path, stream=stream)
    if metadata is not None:
        metadata.update(observation.fingerprint)
    return observation.safety, observation.explanation, observation.digest


def safetensors_fingerprint(
    path: Path, *, root: Path, expected_digest: str | None = None
) -> dict[str, str]:
    """Bind metadata and complete-file hash to one confined artifact observation."""
    metadata: dict[str, str] = {}
    with (
        ConfinedCollection(root, [], max_total_bytes=MAX_HASH_BYTES) as files,
        files.open_regular(path, max_bytes=MAX_HASH_BYTES) as stream,
    ):
        safety, _, digest = inspect_model_artifact(path, stream=stream, metadata=metadata)
    if safety != SerializationSafety.SAFE or not metadata:
        raise ValueError("SafeTensors metadata could not be corroborated")
    if expected_digest is not None and expected_digest != digest:
        raise ValueError("Tensor metadata belongs to different artifact bytes")
    return metadata


class ModelTree:
    """Root-relative files from one confined walk, indexed by directory."""

    def __init__(self, files: Iterable[Path]) -> None:
        self.files = tuple(files)
        self.paths = frozenset(self.files)
        self.children: dict[Path, list[Path]] = {}
        self._subdirs: dict[Path, set[Path]] = {}
        for path in self.files:
            self.children.setdefault(path.parent, []).append(path)
            child = path.parent
            while child != child.parent:
                siblings = self._subdirs.setdefault(child.parent, set())
                if child in siblings:
                    break
                siblings.add(child)
                child = child.parent

    def below(self, directory: Path) -> list[Path]:
        found = list(self.children.get(directory, ()))
        for subdirectory in sorted(self._subdirs.get(directory, ())):
            found.extend(self.below(subdirectory))
        return found


def _json_document(raw: bytes) -> Any:
    """Configuration JSON as loaders read it: UTF-8, unique keys and finite numbers."""

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, value in pairs:
            if key in document:
                raise ValueError("duplicate JSON key")
            document[key] = value
        return document

    def nonfinite(_: str) -> None:
        raise ValueError("nonfinite JSON number")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=nonfinite)


def _local_reference(directory: Path, reference: str) -> Path | None:
    """A forward-slash reference that stays inside ``directory``, or ``None``."""
    if not reference or "\\" in reference or "\0" in reference or reference.startswith("/"):
        return None
    parts = PurePosixPath(reference).parts
    if not parts or ".." in parts:
        return None
    return directory.joinpath(*parts)


def index_references(
    files: ConfinedCollection,
    tree: ModelTree,
    directory: Path,
    digests: dict[Path, str | None],
    read: Callable[[Path], bytes | None] | None = None,
) -> dict[Path, list[Path]]:
    """Map each weight file to the shard indexes in ``directory`` that list it.

    A shard index decides which files a loader opens, so a reference to a missing
    file, a file outside the directory or a file that is not a collected model
    file is a collection failure, not an omission. ``read`` replaces the
    collection's own bounded read.
    """
    references: dict[Path, list[Path]] = {}
    for index in tree.children.get(directory, ()):
        if _index_base(index) is None:
            continue
        raw = (read or files.read_bytes)(index)
        if raw is None:
            continue
        digests[index] = hash_bytes(raw)
        try:
            document = _json_document(raw)
        except (ValueError, RecursionError):
            files._fail(index, "invalid JSON or duplicate keys")
            continue
        weight_map = document.get("weight_map") if isinstance(document, dict) else None
        if not isinstance(weight_map, dict) or not all(
            isinstance(value, str) for value in weight_map.values()
        ):
            files._fail(index, "model index must map tensor names to weight files")
            continue
        for name in sorted(set(weight_map.values())):
            shard = _local_reference(directory, name)
            if (
                shard is None
                or shard.parent != directory
                or shard not in tree.paths
                or model_format(shard) is None
            ):
                files._fail(
                    index,
                    "model index references a missing, unrecognised or out-of-directory "
                    "weight file",
                )
                continue
            references.setdefault(shard, []).append(index)
    return references


def bound_weight_files(
    tree: ModelTree,
    path: Path,
    observation: ModelArtifactObservation | None,
    index_refs: Mapping[Path, Sequence[Path]],
    fail: Callable[[str], None],
) -> list[Path]:
    """Return the other files a loader reads as this model's weights."""
    directory = path.parent
    detected = model_format(path)
    bound: set[Path] = set(index_refs.get(path, ()))
    if observation is not None and observation.onnx_error is not None:
        fail(observation.onnx_error)
    locations = observation.external_data if observation is not None else None
    for location in locations or ():
        target = _local_reference(directory, location)
        if target is None or target not in tree.paths:
            fail("ONNX external data reference is missing or outside the model directory")
            continue
        bound.add(target)
    if detected is not None and detected[1] == "tensorflow-savedmodel":
        for name in SAVEDMODEL_DIRECTORIES:
            bound.update(tree.below(directory / name))
        bound.update(
            directory / name for name in SAVEDMODEL_FILES if directory / name in tree.paths
        )
    bound.discard(path)
    return sorted(bound)


@dataclass(frozen=True)
class ModelPackage:
    """A model file's observation and its weight files, the main file first."""

    observation: ModelArtifactObservation | None
    weight_files: tuple[tuple[Path, str | None], ...]
    complete: bool
    budget_exhausted: bool = False


def memoized(verify: Verify, results: dict[tuple[Any, ...], VerificationResult]) -> Verify:
    """``verify`` that runs once per policy entry while ``results`` lives.

    Several models can bind one weight file, so without this one shared file
    would be read and verified again for every model that names it.
    """

    def cached(
        artifact: Path, bundle: Path, identity: str | None, issuer: str | None
    ) -> VerificationResult:
        key = (artifact, bundle, identity, issuer)
        if key not in results:
            results[key] = verify(artifact, bundle, identity, issuer)
        return results[key]

    return cached


class ModelPackages:
    """Re-observe model files and their bound weight files beneath one root, as a scan does.

    One instance serves one validation. Each directory is walked once, each file
    is inspected or hashed once, and every read is charged to one byte budget the
    size of a scan's, so a BOM that lists many models, or many models that share
    one weight file, cannot multiply the work of the scan that produced it.
    """

    def __init__(self, root: Path, *, byte_budget: int | None = None) -> None:
        self.root = root
        self.covered: set[Path] = set()
        self.verified: dict[tuple[Any, ...], VerificationResult] = {}
        # The scan's aggregate budget for the same files.
        self._remaining = MAX_HASH_SIZE + 32 * 1024 * 1024 if byte_budget is None else byte_budget
        self._refused: set[Path] = set()
        self._budget = InspectionBudget()
        self._trees: dict[Path, tuple[ModelTree, bool]] = {}
        self._indexes: dict[Path, tuple[dict[Path, list[Path]], list[Path], bool]] = {}
        self._observations: dict[Path, ModelArtifactObservation | None] = {}
        self._digests: dict[Path, str | None] = {}

    def observe(self, path: Path) -> ModelPackage:
        """Observe root-relative ``path`` and every weight file a loader reads with it."""
        failures: list[str] = []
        directory = path.parent
        with ConfinedCollection(
            self.root, failures, max_total_bytes=MAX_HASH_SIZE + 32 * 1024 * 1024
        ) as files:
            tree, walked = self._tree(files, directory)
            observation = self._observe(files, path)
            index_refs, indexes, indexed = self._index_references(files, tree, directory)
            weights = [(path, observation.digest if observation is not None else None)]
            for companion in bound_weight_files(
                tree, path, observation, index_refs, lambda reason: files._fail(path, reason)
            ):
                weights.append((companion, self._hash(files, companion)))
        self.covered.update(weight for weight, _ in weights)
        read = {weight for weight, _ in weights}.union(indexes)
        return ModelPackage(
            observation,
            tuple(weights),
            walked and indexed and not failures and all(digest for _, digest in weights),
            bool(read & self._refused),
        )

    def observation(self, path: Path) -> ModelArtifactObservation | None:
        """The observation of root-relative ``path``, made now unless already made."""
        if path not in self._observations:
            with ConfinedCollection(
                self.root, [], max_total_bytes=MAX_HASH_SIZE + 32 * 1024 * 1024
            ) as files:
                self._observe(files, path)
        return self._observations.get(path)

    def _tree(self, files: ConfinedCollection, directory: Path) -> tuple[ModelTree, bool]:
        # A walk of an ancestor that met no failure lists exactly what a walk of
        # ``directory`` would; a walk with failures says nothing about this one.
        for ancestor in (directory, *directory.parents):
            cached = self._trees.get(ancestor)
            if cached is not None and (ancestor == directory or cached[1]):
                return cached
        before = len(files.failures)
        tree = ModelTree(files.iter_files(directory))
        self._trees[directory] = (tree, len(files.failures) == before)
        return self._trees[directory]

    def _charge(self, files: ConfinedCollection, path: Path, stream: BinaryIO) -> None:
        size = os.fstat(stream.fileno()).st_size
        if size > self._remaining:
            self._refused.add(path)
            files._fail(path, BUDGET_EXHAUSTED)
            raise OSError(BUDGET_EXHAUSTED)
        self._remaining -= size

    def _observe(self, files: ConfinedCollection, path: Path) -> ModelArtifactObservation | None:
        if path not in self._observations:
            observation: ModelArtifactObservation | None = None
            try:
                with files.open_regular(path, max_bytes=MAX_HASH_SIZE) as stream:
                    self._charge(files, path, stream)
                    observed = observe_model_artifact(path, stream=stream, budget=self._budget)
                # Commit only after the confined stream confirmed the pathname still
                # names the bytes that were read.
                observation = observed
                self._digests[path] = observed.digest
            except (OSError, ValueError):
                files._fail(path, "model inspection or hashing failed")
            self._observations[path] = observation
        return self._observations[path]

    def _read(self, files: ConfinedCollection, path: Path) -> bytes | None:
        try:
            with files.open_regular(path) as stream:
                self._charge(files, path, stream)
                content = bytearray()
                while chunk := stream.read(65536):
                    content += chunk
        except (OSError, ValueError):
            files._fail(path, "read refused")
            return None
        return bytes(content)

    def _hash(self, files: ConfinedCollection, path: Path) -> str | None:
        if path not in self._digests:
            digest: str | None = None
            try:
                with files.open_regular(path, max_bytes=MAX_HASH_SIZE) as stream:
                    self._charge(files, path, stream)
                    hasher = hashlib.sha256()
                    while chunk := stream.read(65536):
                        hasher.update(chunk)
                digest = "sha256:" + hasher.hexdigest()
            except (OSError, ValueError):
                files._fail(path, "hash refused")
            self._digests[path] = digest
        return self._digests[path]

    def _index_references(
        self, files: ConfinedCollection, tree: ModelTree, directory: Path
    ) -> tuple[dict[Path, list[Path]], list[Path], bool]:
        """The directory's shard references, its index files and whether all were read."""
        if directory not in self._indexes:
            before = len(files.failures)
            references = index_references(
                files, tree, directory, self._digests, read=lambda index: self._read(files, index)
            )
            indexes = [path for path in tree.children.get(directory, ()) if _index_base(path)]
            self._indexes[directory] = (references, indexes, len(files.failures) == before)
        return self._indexes[directory]


def unused_policy_entries(
    files: ConfinedCollection, policies: Mapping[Path, ArtifactPolicy], covered: Iterable[Path]
) -> list[tuple[str, str]]:
    """Operator entries that no check verifies, as (root-relative path, reason) pairs.

    The model checks verify the weight files in ``covered`` (root-relative). The
    discovery producer check verifies the ShadowScan report the importer reads,
    the first of its locations that exists, and only under a Sigstore entry.
    """
    if not policies:
        return []
    used = {(files.root / path).resolve() for path in covered}
    locations = [files.path_identity(location) for location in REPORT_PATHS]
    found = [identity for identity in locations if identity is not None]
    report = found[0] if found else None
    unused: list[tuple[str, str]] = []
    for key, policy in sorted(policies.items()):
        if key in used:
            continue
        try:
            relative = key.relative_to(files.root)
        except ValueError:
            unused.append((".", OUTSIDE_ENTRY))
            continue
        identity = files.path_identity(relative)
        if identity is not None and identity == report:
            if isinstance(policy, SigstoreArtifactPolicy):
                continue
            unused.append((relative.as_posix(), REPORT_ENTRY_KIND))
        elif identity is not None and identity in found:
            unused.append((relative.as_posix(), UNREAD_REPORT_ENTRY))
        else:
            unused.append((relative.as_posix(), UNUSED_ENTRY))
    return unused


@dataclass(frozen=True)
class WeightVerification:
    """The operator-policy outcome for all weight files of one model."""

    status: SigningStatus | None
    identity: str | None
    evidence: ClaimEvidence | None
    issues: tuple[tuple[str, str, str], ...]
    signatures_checked: int
    signatures_verified: int
    pins_verified: int


def _label(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def verify_weight_files(
    weight_files: Sequence[tuple[Path, str | None]],
    root: Path,
    policies: Mapping[Path, ArtifactPolicy],
    *,
    verify: Callable[[Path, Path, str | None, str | None], VerificationResult],
) -> WeightVerification:
    """Verify every weight file against its operator policy entry, main file first.

    ``weight_files`` pairs root-relative paths with the SHA-256 observed through
    the confined reader. A file verifies when its digest pin matches, or when its
    Sigstore bundle verifies over exactly that digest under the entry's identity
    and issuer (and its ``expected_sha256``, if set). The model counts as signed
    only when every weight file verifies.
    """
    methods: dict[Path, str] = {}
    refs: set[str] = set()
    failures: list[str] = []
    issues: list[tuple[str, str, str]] = []
    uncovered: list[str] = []
    attempted: list[str] = []
    unavailable = rejected = False
    checked = signatures = pins = 0
    for path, digest in weight_files:
        label = path.as_posix()
        policy = policies.get((root / path).resolve())
        if policy is None:
            uncovered.append(label)
            continue
        if policy.policy_digest is not None:
            refs.add(POLICY_REF_PREFIX + policy.policy_digest)
        attempted.append(
            DIGEST_PIN_METHOD if isinstance(policy, DigestPinPolicy) else SIGSTORE_METHOD
        )
        if digest is None:
            rejected = True
            reason = "Artifact could not be hashed through the confined reader"
            failures.append(f"{label}: {reason}")
            issues.append(("signature_verification_failed", reason, "error"))
            continue
        if isinstance(policy, DigestPinPolicy):
            if hmac.compare_digest(digest, policy.expected_sha256):
                pins += 1
                methods[path] = DIGEST_PIN_METHOD
                refs.add(f"{DIGEST_PIN_METHOD}:{label}@{digest}")
            else:
                rejected = True
                reason = "Artifact differs from the operator digest pin"
                failures.append(f"{label}: {reason}")
                issues.append(("signature_verification_failed", reason, "error"))
            continue
        checked += 1
        result = verify(
            policy.artifact_path,
            policy.bundle_path,
            policy.expected_identity,
            policy.expected_issuer,
        )
        details = result.details or {}
        if result.error == SIGSTORE_MISSING:
            unavailable = True
            failures.append(f"{label}: {SIGSTORE_MISSING}")
            issues.append(("signature_verification_failed", SIGSTORE_MISSING, "error"))
            continue
        pinned = policy.expected_sha256 is None or hmac.compare_digest(
            digest, policy.expected_sha256
        )
        if (
            result.verified
            and result.identity == policy.expected_identity
            and result.issuer == policy.expected_issuer
            and details.get("artifact_digest") == digest
            and pinned
        ):
            signatures += 1
            methods[path] = SIGSTORE_METHOD
            refs.update(
                {
                    f"{SIGSTORE_METHOD}:{label}@{digest}",
                    f"identity:{policy.expected_identity}",
                    f"issuer:{policy.expected_issuer}",
                }
            )
            bundle_digest = details.get("bundle_digest")
            if isinstance(bundle_digest, str):
                refs.add(f"bundle:{_label(policy.bundle_path, root)}@{bundle_digest}")
            continue
        rejected = True
        reason = (
            "Signed artifact differs from the operator digest pin"
            if result.verified and not pinned
            else result.error or "Signature verification failed"
        )
        failures.append(f"{label}: {reason}")
        issues.append(("signature_verification_failed", reason, "error"))
    if not attempted:
        return WeightVerification(None, None, None, (), 0, 0, 0)
    main = weight_files[0][0]
    status: SigningStatus
    if rejected:
        status = SigningStatus.VERIFICATION_FAILED
    elif unavailable:
        status = SigningStatus.VERIFICATION_UNAVAILABLE
    elif uncovered:
        status = SigningStatus.PARTIALLY_VERIFIED
        issues.extend(
            (
                "unverified_signature",
                f"No trusted signer policy entry covers weight file {label}",
                "unknown",
            )
            for label in uncovered
        )
    elif methods.get(main) == SIGSTORE_METHOD:
        status = SigningStatus.SIGSTORE_SIGNED
    else:
        status = SigningStatus.DIGEST_PINNED
    verified = status.value in VERIFIED_SIGNING_STATUSES
    reasons = failures + [f"{label}: no signer policy entry" for label in uncovered]
    evidence = ClaimEvidence(
        assurance=AssuranceLevel.VERIFIED if verified else AssuranceLevel.OBSERVED,
        method=methods.get(main, attempted[0]),
        scope="operator-signature-policy",
        collector="model",
        locator=main.as_posix(),
        evidence_refs=sorted(refs),
        unknown_reason=None if verified else "; ".join(sorted(reasons)),
    )
    policy = policies.get((root / main).resolve())
    identity = (
        policy.expected_identity
        if status == SigningStatus.SIGSTORE_SIGNED and isinstance(policy, SigstoreArtifactPolicy)
        else None
    )
    return WeightVerification(status, identity, evidence, tuple(issues), checked, signatures, pins)


@dataclass
class _DirectoryContext:
    config: dict[str, Any]
    trust_remote_code: bool | None
    config_files: list[tuple[Path, str]]
    tokenizer_files: list[tuple[Path, str]]
    chat_templates: list[tuple[str, str]]
    custom_code: dict[str, Any] | None
    index_refs: dict[Path, list[Path]]
    base_model: str | None


def _checked_config(files: ConfinedCollection, path: Path, data: dict[str, Any]) -> dict[str, Any]:
    invalid_fields = [
        key
        for key in _CONFIG_STRING_FIELDS
        if data.get(key) is not None and not isinstance(data[key], str)
    ]
    if data.get("trust_remote_code") is not None and not isinstance(
        data["trust_remote_code"], bool
    ):
        invalid_fields.append("trust_remote_code")
    if invalid_fields:
        files._fail(
            path,
            "invalid model configuration field type: " + ", ".join(sorted(invalid_fields)),
        )
        # Retain the artifact inventory while refusing the invalid
        # claims. Diagnostics contain schema field names only.
        data = {k: v for k, v in data.items() if k not in invalid_fields}
    return data


def _code_references(data: dict[str, Any]) -> tuple[bool, list[str]]:
    """Whether a configuration declares repository code, and its well-formed references."""
    declared = False
    references: list[str] = []
    auto_map = data.get("auto_map")
    if auto_map is not None and auto_map != {}:
        declared = True
        for value in auto_map.values() if isinstance(auto_map, dict) else ():
            for item in value if isinstance(value, list) else [value]:
                if isinstance(item, str) and _CODE_REFERENCE.fullmatch(item):
                    references.append(item)
    pipelines = data.get("custom_pipelines")
    if pipelines is not None and pipelines != {}:
        declared = True
        for spec in pipelines.values() if isinstance(pipelines, dict) else ():
            impl = spec.get("impl") if isinstance(spec, dict) else None
            if isinstance(impl, str) and _CODE_REFERENCE.fullmatch(impl):
                references.append(impl)
    return declared, references


class ModelScanner(Scanner):
    name = "model"

    def __init__(
        self,
        signature_policies: Sequence[SigstoreArtifactPolicy] = (),
        *,
        digest_pins: Sequence[DigestPinPolicy] = (),
    ) -> None:
        self._policies: dict[Path, ArtifactPolicy] = {
            policy.artifact_path.resolve(): policy
            for policy in policy_entries(signature_policies, digest_pins)
        }
        self._tree = ModelTree(())
        self._digests: dict[Path, str | None] = {}
        self._read: set[Path] = set()
        self._budget = InspectionBudget()
        self._verified: dict[tuple[Any, ...], VerificationResult] = {}

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        # One deterministic walk and one aggregate budget for all model/config
        # reads. Large weights are streamed; metadata remains capped at four MiB.
        with self._collection(
            project_root, result, max_total_bytes=MAX_HASH_SIZE + 32 * 1024 * 1024
        ) as files:
            self._tree = tree = ModelTree(files.iter_files())
            self._digests, self._read, self._budget = {}, set(), InspectionBudget()
            self._verified = {}
            model_dirs = sorted(
                {
                    path.parent
                    for path in tree.files
                    if model_format(path) is not None or _index_base(path) is not None
                }
            )
            if not model_dirs and not result.scan_failures and not result.surfaces_excluded:
                result.surfaces_scanned.append("model-weights (no model files found)")
            covered: set[Path] = set()
            for model_dir in model_dirs:
                context = self._directory_context(files, model_dir)
                for path in tree.children.get(model_dir, ()):
                    detected = model_format(path)
                    if detected is not None:
                        component, weight_files = self._scan_model_file(
                            files, path, detected, context
                        )
                        result.components.append(component)
                        covered.update(weight_files)
            # An operator entry that no check verifies must not look enforced.
            for label, reason in unused_policy_entries(files, self._policies, covered):
                files._fail(label, reason)
            result.surfaces_scanned.extend(sorted(path.as_posix() for path in self._read))
        return result

    def _digest(self, files: ConfinedCollection, path: Path) -> str | None:
        if path not in self._digests:
            self._read.add(path)
            self._digests[path] = files.hash_file(path, max_bytes=MAX_HASH_SIZE)
        return self._digests[path]

    def _directory_context(self, files: ConfinedCollection, model_dir: Path) -> _DirectoryContext:
        tree = self._tree
        configs: list[tuple[Path, dict[str, Any]]] = []
        config_files: list[tuple[Path, str]] = []
        for name in MODEL_CONFIG_FILES:
            path = model_dir / name
            if path not in tree.paths:
                continue
            self._read.add(path)
            raw = files.read_bytes(path)
            if raw is None:
                continue
            config_files.append((path, hash_bytes(raw)))
            try:
                data = _json_document(raw)
            except (ValueError, RecursionError):
                files._fail(path, "invalid JSON or duplicate keys")
                continue
            if not isinstance(data, dict):
                files._fail(path, "model configuration must be an object")
                continue
            configs.append((path, _checked_config(files, path, data)))

        merged: dict[str, Any] = {}
        remote: list[bool] = []
        templates: list[tuple[str, str]] = []
        declared_in: list[str] = []
        references: list[str] = []
        base_model: str | None = None
        for path, data in configs:
            for key in _CONFIG_STRING_FIELDS:
                if key not in merged and isinstance(data.get(key), str):
                    merged[key] = data[key]
            nested = data.get("quantization_config")
            if isinstance(nested, dict) and isinstance(nested.get("quant_method"), str):
                merged.setdefault("quant_method", nested["quant_method"])
            if data.get("adapter_config"):
                merged.setdefault("adapter_config", True)
            if isinstance(data.get("trust_remote_code"), bool):
                remote.append(data["trust_remote_code"])
            declared, found = _code_references(data)
            if declared:
                declared_in.append(path.as_posix())
                references.extend(found)
            candidate = data.get("base_model_name_or_path")
            if path.name == "adapter_config.json" and isinstance(candidate, str):
                base_model = candidate if _HUB_ID.fullmatch(candidate) else None
            templates.extend(self._config_templates(files, path, data.get("chat_template")))

        for name in CHAT_TEMPLATE_FILES:
            if model_dir / name in tree.paths:
                digest = self._digest(files, model_dir / name)
                if digest is not None:
                    templates.append(((model_dir / name).as_posix(), digest))
        for path in tree.children.get(model_dir / CHAT_TEMPLATE_DIRECTORY, ()):
            if path.suffix == ".jinja":
                digest = self._digest(files, path)
                if digest is not None:
                    templates.append((path.as_posix(), digest))

        tokenizer_files = [
            (model_dir / name, digest)
            for name in TOKENIZER_FILES
            if model_dir / name in tree.paths
            and (digest := self._digest(files, model_dir / name)) is not None
        ]
        custom_code = None
        if declared_in:
            python_files = [
                {"path": path.as_posix(), "sha256": digest}
                for path in tree.children.get(model_dir, ())
                if path.suffix == ".py" and (digest := self._digest(files, path)) is not None
            ]
            custom_code = {
                "declared_in": declared_in,
                "references": sorted(set(references)),
                "cross_repository": any("--" in reference for reference in references),
                "python_files": python_files,
            }
        self._read.update(path for path in tree.children.get(model_dir, ()) if _index_base(path))
        index_refs = index_references(files, tree, model_dir, self._digests)
        return _DirectoryContext(
            config=merged,
            trust_remote_code=True if True in remote else False if remote else None,
            config_files=config_files,
            tokenizer_files=tokenizer_files,
            chat_templates=templates,
            custom_code=custom_code,
            index_refs=index_refs,
            base_model=base_model,
        )

    @staticmethod
    def _config_templates(
        files: ConfinedCollection, path: Path, value: object
    ) -> list[tuple[str, str]]:
        """Chat templates from a configuration: one string, or a list of named templates."""
        if value is None:
            return []
        locator = f"{path.as_posix()}#chat_template"
        if isinstance(value, str):
            return [(locator, hash_bytes(value.encode("utf-8", "surrogatepass")))]
        if isinstance(value, list) and all(
            isinstance(item, dict) and isinstance(item.get("template"), str) for item in value
        ):
            return [
                (
                    f"{locator}/{index}",
                    hash_bytes(item["template"].encode("utf-8", "surrogatepass")),
                )
                for index, item in enumerate(value)
            ]
        files._fail(path, "chat_template must be a string or a list of named templates")
        return []

    def _scan_model_file(
        self,
        files: ConfinedCollection,
        path: Path,
        detected: tuple[str, str],
        context: _DirectoryContext,
    ) -> tuple[ModelComponent, list[Path]]:
        fmt_key, fmt_name = detected
        self._read.add(path)
        observation: ModelArtifactObservation | None = None
        try:
            with files.open_regular(path, max_bytes=MAX_HASH_SIZE) as stream:
                observed = observe_model_artifact(path, stream=stream, budget=self._budget)
            # Commit only after the confined stream confirmed the pathname still
            # names the bytes that were read.
            observation = observed
        except (OSError, ValueError):
            files._fail(path, "model inspection or hashing failed")
        if observation is not None:
            safety, format_evidence = observation.safety, observation.explanation
            weight_hash: str | None = observation.digest
        elif _pickle_family(path):
            # The name alone rates these formats; an unreadable file keeps that rating.
            safety = SerializationSafety.UNSAFE_CODE_EXECUTION
            format_evidence = (
                "Potential code-executing loader format (artifact could not be hashed)"
            )
            weight_hash = None
        else:
            safety, format_evidence = SerializationSafety.UNKNOWN, "Artifact could not be inspected"
            weight_hash = None
        self._digests[path] = weight_hash

        companions = bound_weight_files(
            self._tree,
            path,
            observation,
            context.index_refs,
            lambda reason: files._fail(path, reason),
        )
        weight_files = [(path, weight_hash), *((c, self._digest(files, c)) for c in companions)]
        verification = verify_weight_files(
            weight_files,
            files.root,
            self._policies,
            verify=memoized(verify_sigstore_bundle, self._verified),
        )
        status = verification.status or self._unverified_status(path)
        if status == SigningStatus.VERIFICATION_UNAVAILABLE:
            files._fail(path, SIGSTORE_MISSING)
        trust_tier = {
            SigningStatus.SIGSTORE_SIGNED: TrustTier.THIRD_PARTY_SIGNED,
            SigningStatus.DIGEST_PINNED: TrustTier.INTERNAL_VERIFIED,
        }.get(status, TrustTier.UNKNOWN)

        templates = [*context.chat_templates, *(observation.chat_templates if observation else ())]
        properties: dict[str, Any] = {"format_inspection": format_evidence}
        if companions:
            properties["weight_files"] = [
                {"path": companion.as_posix(), "sha256": digest}
                for companion, digest in weight_files[1:]
                if digest is not None
            ]
        if context.config_files:
            properties["config_files"] = [
                {"path": config.as_posix(), "sha256": digest}
                for config, digest in context.config_files
            ]
        if context.tokenizer_files:
            properties["tokenizer_files"] = [
                {"path": tokenizer.as_posix(), "sha256": digest}
                for tokenizer, digest in context.tokenizer_files
            ]
        if templates:
            properties["chat_templates"] = [
                {"source": source, "sha256": digest} for source, digest in sorted(templates)
            ]
        if context.custom_code is not None:
            properties["custom_code"] = context.custom_code
        if context.base_model is not None:
            properties["base_model"] = context.base_model
        if observation is not None and observation.gguf_architecture is not None:
            properties["gguf_architecture"] = observation.gguf_architecture
        if observation is not None and observation.gguf_error is not None:
            properties["gguf_metadata"] = f"not inspected: {observation.gguf_error}"
            if observation.gguf_error == GGUF_LIMIT:
                # A template behind more metadata than the bounds allow was not checked.
                gap = f"{path.as_posix()}: GGUF chat templates not inspected: {GGUF_LIMIT}"
                if gap not in files.exclusions:
                    files.exclusions.append(gap)

        config = context.config
        name = path.as_posix()
        component = ModelComponent(
            bom_ref=f"model:{name}",
            name=name,
            serialization_format=fmt_name,
            serialization_safety=safety,
            signing_status=status.value,
            signing_identity=verification.identity,
            properties=properties,
            model_type=self._infer_model_type(config, path),
            derivation_type=config.get("peft_type"),
            quantization_method=config.get("quantization_method") or config.get("quant_method"),
            trust_remote_code=context.trust_remote_code,
            tokenizer_hash=(
                manifest_digest((p.as_posix(), d) for p, d in context.tokenizer_files)
                if context.tokenizer_files
                else None
            ),
            chat_template_hash=manifest_digest(templates) if templates else None,
            tensor_inventory_hash=(
                observation.fingerprint.get("tensor_inventory_sha256") if observation else None
            ),
            safetensors_header_hash=(
                observation.fingerprint.get("safetensors_header_sha256") if observation else None
            ),
            hashes={"sha256": weight_hash} if weight_hash else {},
            source_path=name,
            trust_tier=trust_tier,
            risks=self._assess_model_risks(path, fmt_key, safety, status.value, context),
            claims=(
                {SIGNING_EVIDENCE_CLAIM: verification.evidence}
                if verification.evidence is not None
                else {}
            ),
        )
        return component, [weight for weight, _ in weight_files]

    def _unverified_status(self, artifact: Path) -> SigningStatus:
        adjacent = [artifact.parent / name for name in SIGNING_FILES]
        adjacent += [artifact.with_name(artifact.name + suffix) for suffix in SIGNING_SUFFIXES]
        # An adjacent file is a discovery fact, never proof of a signature.
        if any(path in self._tree.paths for path in adjacent):
            return SigningStatus.SIGNATURE_PRESENT_UNVERIFIED
        # A directory-local search cannot prove the absence of external signatures.
        return SigningStatus.SIGNATURE_NOT_FOUND

    def _infer_model_type(self, config: dict[str, Any], path: Path) -> str:
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
        context: _DirectoryContext,
    ) -> list[RiskAssessment]:
        risks: list[RiskAssessment] = []

        if safety == SerializationSafety.UNSAFE_CODE_EXECUTION:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.CRITICAL,
                    category="serialization_format",
                    detail=f"Model '{path.name}' has evidence of a potentially code-executing serialization or loader.",
                    recommendation="Convert to SafeTensors. Block pickle/pt/pth in production.",
                    references=["https://huggingface.co/blog/safetensors-security-audit"],
                )
            )

        if safety == SerializationSafety.UNSAFE_TEMPLATE_INJECTION:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.CRITICAL,
                    category="serialization_format",
                    detail=f"Model '{path.name}' embeds a chat template that reaches Python internals, as Jinja2 sandbox escapes such as CVE-2024-34359 do.",
                    recommendation="Remove the template or replace it with a reviewed one; render templates only in a sandboxed Jinja2 environment (llama-cpp-python >= 0.2.72).",
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

        if signing_status not in VERIFIED_SIGNING_STATUSES:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="signing_status",
                    detail=f"Model '{path.name}' has no verified artifact-bound signature ({signing_status}).",
                    recommendation=(
                        "Pin the SHA-256 of every weight file in an operator signature policy, or "
                        "sign each one with a Sigstore message signature (sigstore sign) and name "
                        "its bundle and signer there. OpenSSF Model Signing (DSSE) bundles are "
                        "not verified yet."
                    ),
                    references=[DOCUMENTATION],
                )
            )

        if context.trust_remote_code is True:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.CRITICAL,
                    category="code_execution",
                    detail="trust_remote_code=True allows arbitrary code from the model repository.",
                    recommendation="Audit remote code or use a model that does not require it.",
                )
            )

        if context.custom_code is not None:
            elsewhere = (
                " Some references name code in another repository."
                if context.custom_code["cross_repository"]
                else ""
            )
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="custom_code",
                    detail=(
                        f"Model '{path.name}' declares custom code (auto_map or custom_pipelines); "
                        "loading it requires trust_remote_code and runs that Python code."
                        + elsewhere
                    ),
                    recommendation=(
                        "Review the declared modules before loading; their digests are recorded "
                        "so a change raises a drift alert."
                    ),
                    references=[DOCUMENTATION],
                )
            )

        return risks
