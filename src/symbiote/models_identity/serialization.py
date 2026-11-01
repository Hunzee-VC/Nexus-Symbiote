"""Static serialization-risk analysis for model artefacts (WP3).

Nothing in this module ever deserializes, imports or executes the artefacts it inspects. Every reader is
bounded (header sizes, member sizes, entry counts) so a hostile file cannot exhaust memory, and every
parse failure is reported as a finding instead of being swallowed.

Implements the classification rules of ``spec/digests.md`` §6 ("Serialization risk class per file,
aggregated per model") using extension **and** magic bytes, and adds evidence the spec asks scanners to
provide (``Model.serialization.scanner``): the imported callables a pickle stream would resolve, the
Jinja chat templates embedded in GGUF metadata, and structural anomalies in safetensors headers.

Threats addressed (see ``docs/research/gap-register-attack-lens.json`` ATTACK-04/05):

* pickle ``GLOBAL``/``STACK_GLOBAL`` imports of ``os``/``subprocess``/``builtins.exec`` and friends
  (malicious Hugging Face models, JFrog 2024);
* *nullifAI*-style evasion (ReversingLabs, Feb 2025): a payload placed before a deliberately broken opcode
  executes in ``pickle.load`` but crashes scanners that only report on a complete stream. We report every
  import seen **before** the parse error and flag the stream as malformed;
* *Sleepy Pickle*-style in-memory tampering: any non-allow-listed callable in a checkpoint is reported;
* Jinja server-side template injection through chat templates (CVE-2024-34359, GGUF metadata);
* Keras ``Lambda`` layers and NumPy object arrays that require pickle on load.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import pickletools
import re
import struct
import zipfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Final, Literal

__all__ = [
    "RISK_ORDER",
    "ChatTemplateFinding",
    "FileAssessment",
    "GgufMetadata",
    "PickleGlobal",
    "PickleScan",
    "SafetensorsHeader",
    "assess_file",
    "classify_global",
    "max_risk",
    "read_gguf_metadata",
    "read_safetensors_header",
    "scan_chat_template",
    "scan_pickle_bytes",
    "sniff_format",
]

# ---------------------------------------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------------------------------------

FileFormat = Literal[
    "safetensors",
    "onnx",
    "gguf",
    "pickle",
    "torch-zip",
    "torchscript",
    "tf-savedmodel",
    "keras-h5",
    "keras-v3",
    "joblib",
    "npy",
    "npz",
    "mlflow-pyfunc",
    "archive-7z",
    "other",
]
RiskClass = Literal["none", "low", "template-execution", "code-exec-on-load"]

#: Total order used to aggregate per-file risk into a model risk (higher index = worse).
RISK_ORDER: Final[tuple[RiskClass, ...]] = ("none", "low", "template-execution", "code-exec-on-load")

GlobalVerdict = Literal["safe", "dangerous", "unknown"]

#: Upper bounds that keep every reader O(bounded) on hostile input.
MAX_PICKLE_BYTES: Final = 64 * 1024 * 1024
MAX_SAFETENSORS_HEADER: Final = 100 * 1024 * 1024
MAX_GGUF_KV: Final = 1_000_000
MAX_GGUF_STRING: Final = 64 * 1024 * 1024
MAX_GGUF_ARRAY: Final = 50_000_000
MAX_TEMPLATE_BYTES: Final = 4 * 1024 * 1024
MAX_SNIFF_BYTES: Final = 64
MAX_KERAS_CONFIG: Final = 32 * 1024 * 1024
MAX_H5_SEARCH: Final = 64 * 1024 * 1024

_PICKLE_EXTS: Final = frozenset({".pkl", ".pickle", ".dill", ".cloudpickle"})
_TORCH_EXTS: Final = frozenset({".pt", ".pth", ".bin", ".ckpt", ".pkl", ".mar"})
_JOBLIB_EXTS: Final = frozenset({".joblib"})


def max_risk(risks: Iterable[RiskClass]) -> RiskClass:
    """Return the most severe risk class in ``risks`` (``"none"`` for an empty iterable)."""
    worst = 0
    for risk in risks:
        worst = max(worst, RISK_ORDER.index(risk))
    return RISK_ORDER[worst]


# ---------------------------------------------------------------------------------------------------------
# Pickle opcode scanning (never unpickles)
# ---------------------------------------------------------------------------------------------------------

#: Callables routinely referenced by benign PyTorch / NumPy / scikit-learn checkpoints.
_SAFE_GLOBALS: Final = frozenset(
    {
        "collections.OrderedDict",
        "collections.defaultdict",
        "torch._utils._rebuild_tensor",
        "torch._utils._rebuild_tensor_v2",
        "torch._utils._rebuild_tensor_v3",
        "torch._utils._rebuild_parameter",
        "torch._utils._rebuild_parameter_with_state",
        "torch._utils._rebuild_qtensor",
        "torch._utils._rebuild_sparse_tensor",
        "torch._utils._rebuild_device_tensor_from_numpy",
        "torch._utils._rebuild_meta_tensor_no_storage",
        "torch._utils._rebuild_wrapper_subclass",
        "torch._tensor._rebuild_from_type_v2",
        "torch.serialization._get_layout",
        "torch.Size",
        "torch.device",
        "torch.dtype",
        "numpy.core.multiarray._reconstruct",
        "numpy._core.multiarray._reconstruct",
        "numpy.core.multiarray.scalar",
        "numpy._core.multiarray.scalar",
        "numpy.ndarray",
        "numpy.dtype",
        "_codecs.encode",
        "builtins.set",
        "builtins.frozenset",
        "builtins.slice",
        "builtins.complex",
        "builtins.bytearray",
        "builtins.int",
        "builtins.float",
        "builtins.str",
        "builtins.list",
        "builtins.dict",
        "builtins.tuple",
        "builtins.bool",
        "__builtin__.set",
        "__builtin__.frozenset",
        "__builtin__.slice",
        "__builtin__.complex",
        "argparse.Namespace",
        "datetime.datetime",
        "datetime.date",
        "datetime.timedelta",
        "decimal.Decimal",
        "uuid.UUID",
    }
)
#: torch storage and dtype names (``torch.FloatStorage``, ``torch.bfloat16`` ...).
_SAFE_TORCH_ATTR = re.compile(
    r"^torch\.(?:[A-Za-z0-9]*Storage|float(?:16|32|64)|bfloat16|half|double|int(?:8|16|32|64)|uint(?:8|16|32|64)"
    r"|bool|complex(?:32|64|128)|float8_[a-z0-9]+|qint8|quint8|qint32|long|short|cfloat|cdouble)$"
)

#: Modules whose import from a model artefact is a strong indicator of a malicious payload.
_DANGEROUS_MODULES: Final = frozenset(
    {
        "os",
        "posix",
        "nt",
        "subprocess",
        "sys",
        "shutil",
        "socket",
        "pty",
        "commands",
        "popen2",
        "runpy",
        "webbrowser",
        "requests",
        "httpx",
        "urllib",
        "urllib2",
        "urllib3",
        "http",
        "httplib",
        "ftplib",
        "telnetlib",
        "smtplib",
        "asyncio",
        "multiprocessing",
        "ctypes",
        "cffi",
        "importlib",
        "imp",
        "code",
        "codeop",
        "pdb",
        "bdb",
        "timeit",
        "marshal",
        "pickle",
        "_pickle",
        "cPickle",
        "dill",
        "cloudpickle",
        "joblib",
        "shelve",
        "zipimport",
        "pkgutil",
        "distutils",
        "setuptools",
        "pip",
        "venv",
        "signal",
        "tempfile",
        "glob",
        "pathlib",
        "io",
        "_io",
        "fcntl",
        "resource",
    }
)
_DANGEROUS_BUILTINS: Final = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "open",
        "__import__",
        "getattr",
        "setattr",
        "delattr",
        "globals",
        "locals",
        "vars",
        "input",
        "breakpoint",
        "apply",
        "execfile",
        "file",
        "reload",
    }
)
_DANGEROUS_QUALIFIED: Final = frozenset(
    {
        "operator.attrgetter",
        "operator.methodcaller",
        "operator.itemgetter",
        "functools.partial",
        "functools.reduce",
        "types.FunctionType",
        "types.CodeType",
        "types.MethodType",
        "types.LambdaType",
        "copyreg._reconstructor",
        "copy_reg._reconstructor",
        "torch.load",
        "torch.serialization.load",
        "torch.storage._load_from_bytes",
        "torch.hub.load",
        "torch.jit.load",
        "torch.package.package_importer.PackageImporter",
        "numpy.load",
        "numpy.testing._private.utils.runstring",
        "pandas.read_pickle",
        "pandas.io.pickle.read_pickle",
    }
)

#: Opcodes that call a callable or ``__setstate__`` during unpickling.
_EXEC_OPCODES: Final = frozenset({"REDUCE", "BUILD", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX"})
_STRING_OPCODES: Final = frozenset(
    {"STRING", "BINSTRING", "SHORT_BINSTRING", "UNICODE", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8"}
)
_GET_OPCODES: Final = frozenset({"GET", "BINGET", "LONG_BINGET"})
_PUT_OPCODES: Final = frozenset({"PUT", "BINPUT", "LONG_BINPUT"})
_NON_PUSHING: Final = frozenset({"MEMOIZE", "PROTO", "FRAME", "STOP", "MARK", "POP", "POP_MARK"})


def classify_global(module: str, name: str) -> GlobalVerdict:
    """Classify an imported callable referenced by a pickle stream.

    ``safe`` means the callable is routinely present in benign checkpoints, not that loading is safe:
    any pickle stream is still ``code-exec-on-load`` by construction.
    """
    qualified = f"{module}.{name}"
    root = module.split(".", 1)[0]
    if qualified in _DANGEROUS_QUALIFIED:
        return "dangerous"
    if root in {"builtins", "__builtin__", "__builtins__"} and name in _DANGEROUS_BUILTINS:
        return "dangerous"
    if root in _DANGEROUS_MODULES:
        return "dangerous"
    if qualified in _SAFE_GLOBALS or _SAFE_TORCH_ATTR.match(qualified):
        return "safe"
    return "unknown"


@dataclass(frozen=True, slots=True)
class PickleGlobal:
    """A callable a pickle stream would import when loaded."""

    module: str
    name: str
    verdict: GlobalVerdict
    position: int
    opcode: str

    @property
    def qualified(self) -> str:
        return f"{self.module}.{self.name}"


@dataclass(frozen=True, slots=True)
class PickleScan:
    """Result of a static opcode walk over a pickle stream."""

    protocol: int | None
    globals: tuple[PickleGlobal, ...]
    exec_opcodes: tuple[str, ...]
    unresolved_stack_globals: int
    malformed: bool
    error: str | None
    bytes_scanned: int
    truncated: bool

    @property
    def dangerous(self) -> tuple[PickleGlobal, ...]:
        return tuple(g for g in self.globals if g.verdict == "dangerous")

    @property
    def unknown(self) -> tuple[PickleGlobal, ...]:
        return tuple(g for g in self.globals if g.verdict == "unknown")

    @property
    def verdict(self) -> Literal["malicious-indicators", "suspicious", "no-indicators"]:
        """Scanner verdict; ``no-indicators`` still means *code executes on load*."""
        if self.dangerous:
            return "malicious-indicators"
        if self.unknown or self.malformed or self.unresolved_stack_globals or self.truncated:
            return "suspicious"
        return "no-indicators"

    def to_report(self) -> dict[str, object]:
        """A JSON-serialisable report (stable key order is applied by the caller's canonicaliser)."""
        return {
            "protocol": self.protocol,
            "globals": [
                {
                    "module": g.module,
                    "name": g.name,
                    "verdict": g.verdict,
                    "position": g.position,
                    "opcode": g.opcode,
                }
                for g in self.globals
            ],
            "execOpcodes": list(self.exec_opcodes),
            "unresolvedStackGlobals": self.unresolved_stack_globals,
            "malformed": self.malformed,
            "error": self.error,
            "bytesScanned": self.bytes_scanned,
            "truncated": self.truncated,
            "verdict": self.verdict,
        }


def scan_pickle_bytes(data: bytes, *, truncated: bool = False) -> PickleScan:
    """Walk the opcodes of ``data`` with :func:`pickletools.genops` and report imported callables.

    The walk never builds Python objects. ``STACK_GLOBAL`` operands are resolved from the most recent string
    pushes, following memo ``PUT``/``GET`` indirections, the same heuristic picklescan uses. On a parse error
    every import seen so far is still reported and ``malformed`` is set (nullifAI evasion).
    """
    found: list[PickleGlobal] = []
    exec_ops: set[str] = set()
    protocol: int | None = None
    memo: dict[int, str | None] = {}
    string_pushes: list[str | None] = []
    last_value: str | None = None
    unresolved = 0
    error: str | None = None
    position = 0
    seen: set[tuple[str, str]] = set()

    def record(module: str, name: str, pos: int, opcode: str) -> None:
        key = (module, name)
        if key in seen:
            return
        seen.add(key)
        found.append(PickleGlobal(module, name, classify_global(module, name), pos, opcode))

    try:
        for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
            position = pos if pos is not None else position
            op = opcode.name
            if op == "PROTO" and isinstance(arg, int):
                protocol = arg
            if op in _EXEC_OPCODES:
                exec_ops.add(op)
            if op in {"GLOBAL", "INST"} and isinstance(arg, str):
                module, _, name = arg.partition(" ")
                record(module, name, position, op)
                last_value = None
                continue
            if op == "STACK_GLOBAL":
                if (
                    len(string_pushes) >= 2
                    and string_pushes[-1] is not None
                    and string_pushes[-2] is not None
                ):
                    name_s = string_pushes.pop()
                    module_s = string_pushes.pop()
                    assert name_s is not None and module_s is not None
                    record(module_s, name_s, position, op)
                else:
                    unresolved += 1
                last_value = None
                continue
            if op in _STRING_OPCODES:
                value = arg.decode("latin-1") if isinstance(arg, bytes) else str(arg)
                string_pushes.append(value)
                last_value = value
                continue
            if op in _GET_OPCODES and isinstance(arg, int):
                value_g = memo.get(arg)
                string_pushes.append(value_g)
                last_value = value_g
                continue
            if op == "MEMOIZE":
                memo[len(memo)] = last_value
                continue
            if op in _PUT_OPCODES and isinstance(arg, int):
                memo[arg] = last_value
                continue
            if op not in _NON_PUSHING:
                last_value = None
    except Exception as exc:  # every parse failure is a finding, never a crash
        error = f"{type(exc).__name__}: {exc}"

    malformed = error is not None
    return PickleScan(
        protocol=protocol,
        globals=tuple(found),
        exec_opcodes=tuple(sorted(exec_ops)),
        unresolved_stack_globals=unresolved,
        malformed=malformed,
        error=error,
        bytes_scanned=len(data),
        truncated=truncated,
    )


def _read_bounded(stream: IO[bytes], limit: int) -> tuple[bytes, bool]:
    data = stream.read(limit + 1)
    if len(data) > limit:
        return data[:limit], True
    return data, False


# ---------------------------------------------------------------------------------------------------------
# safetensors header validation
# ---------------------------------------------------------------------------------------------------------

_SAFETENSORS_DTYPE_BYTES: Final = {
    "BOOL": 1,
    "U8": 1,
    "I8": 1,
    "F8_E5M2": 1,
    "F8_E4M3": 1,
    "F8_E8M0": 1,
    "I16": 2,
    "U16": 2,
    "F16": 2,
    "BF16": 2,
    "I32": 4,
    "U32": 4,
    "F32": 4,
    "C64": 8,
    "F64": 8,
    "I64": 8,
    "U64": 8,
}


@dataclass(frozen=True, slots=True)
class SafetensorsHeader:
    header_length: int
    tensor_count: int
    metadata_keys: tuple[str, ...]
    data_bytes: int
    anomalies: tuple[str, ...]


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def read_safetensors_header(path: Path) -> SafetensorsHeader:
    """Parse and structurally validate a safetensors header without touching tensor data."""
    size = path.stat().st_size
    anomalies: list[str] = []
    with path.open("rb") as fh:
        raw_len = fh.read(8)
        if len(raw_len) != 8:
            return SafetensorsHeader(0, 0, (), 0, ("truncated-header-length",))
        (header_len,) = struct.unpack("<Q", raw_len)
        if header_len < 2 or header_len > MAX_SAFETENSORS_HEADER or header_len > size - 8:
            return SafetensorsHeader(header_len, 0, (), 0, ("header-length-out-of-bounds",))
        raw = fh.read(header_len)
    try:
        header = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except ValueError as exc:
        reason = "duplicate-keys" if "duplicate key" in str(exc) else "header-not-json"
        return SafetensorsHeader(header_len, 0, (), 0, (reason,))
    if not isinstance(header, dict):
        return SafetensorsHeader(header_len, 0, (), 0, ("header-not-object",))
    data_region = size - 8 - header_len
    metadata = header.pop("__metadata__", None)
    metadata_keys: tuple[str, ...] = ()
    if metadata is not None:
        if not isinstance(metadata, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in metadata.items()
        ):
            anomalies.append("metadata-not-string-map")
        else:
            metadata_keys = tuple(sorted(metadata))
    spans: list[tuple[int, int]] = []
    for name, info in header.items():
        if not isinstance(info, dict):
            anomalies.append(f"tensor-entry-not-object:{name}")
            continue
        dtype = info.get("dtype")
        shape = info.get("shape")
        offsets = info.get("data_offsets")
        if dtype not in _SAFETENSORS_DTYPE_BYTES:
            anomalies.append(f"unknown-dtype:{name}")
        if not (isinstance(shape, list) and all(isinstance(d, int) and d >= 0 for d in shape)):
            anomalies.append(f"bad-shape:{name}")
            continue
        if not (
            isinstance(offsets, list)
            and len(offsets) == 2
            and all(isinstance(o, int) and o >= 0 for o in offsets)
            and offsets[0] <= offsets[1]
        ):
            anomalies.append(f"bad-offsets:{name}")
            continue
        begin, end = offsets
        if end > data_region:
            anomalies.append(f"offset-out-of-bounds:{name}")
        if isinstance(dtype, str) and dtype in _SAFETENSORS_DTYPE_BYTES:
            elements = 1
            for dim in shape:
                elements *= dim
            if elements * _SAFETENSORS_DTYPE_BYTES[dtype] != end - begin:
                anomalies.append(f"size-mismatch:{name}")
        spans.append((begin, end))
    spans.sort()
    cursor = 0
    for begin, end in spans:
        if begin < cursor:
            anomalies.append("overlapping-tensors")
            break
        if begin > cursor:
            anomalies.append("gap-between-tensors")
            break
        cursor = end
    if spans and cursor != data_region and "overlapping-tensors" not in anomalies:
        anomalies.append("trailing-bytes" if cursor < data_region else "data-region-short")
    return SafetensorsHeader(
        header_length=header_len,
        tensor_count=len(spans),
        metadata_keys=metadata_keys,
        data_bytes=data_region,
        anomalies=tuple(dict.fromkeys(anomalies)),
    )


# ---------------------------------------------------------------------------------------------------------
# Chat templates (Jinja) — server-side template injection indicators
# ---------------------------------------------------------------------------------------------------------

#: Constructs with no legitimate use in a chat template; each is a known SSTI gadget step.
_SSTI_PATTERNS: Final = (
    ("dunder-class-walk", re.compile(r"__(?:class|base|bases|mro|subclasses)__")),
    ("dunder-globals", re.compile(r"__(?:globals|builtins|import|init|getattribute|code)__")),
    ("os-or-subprocess", re.compile(r"\b(?:os|subprocess|popen|system)\b\s*[.(]")),
    ("jinja-global-gadget", re.compile(r"\b(?:lipsum|cycler|joiner|namespace)\s*\.\s*__")),
    ("attr-filter-dunder", re.compile(r"\|\s*attr\s*\(\s*['\"]_")),
    ("request-or-config", re.compile(r"\b(?:request|config)\s*\.\s*(?:application|__)")),
)


@dataclass(frozen=True, slots=True)
class ChatTemplateFinding:
    """A Jinja chat template found in model metadata. The text itself is never retained."""

    source: str
    name: str
    digest: str
    size: int
    ssti_indicators: tuple[str, ...]


def scan_chat_template(source: str, name: str, template: str) -> ChatTemplateFinding:
    """Digest a chat template and report server-side-template-injection indicators."""
    encoded = template.encode("utf-8", "surrogatepass")
    indicators = tuple(label for label, pattern in _SSTI_PATTERNS if pattern.search(template))
    return ChatTemplateFinding(
        source=source,
        name=name,
        digest="sha256:" + hashlib.sha256(encoded).hexdigest(),
        size=len(encoded),
        ssti_indicators=indicators,
    )


# ---------------------------------------------------------------------------------------------------------
# GGUF metadata (bounded reader; tensor-info parsing is out of scope here)
# ---------------------------------------------------------------------------------------------------------

_GGUF_SCALARS: Final = {
    0: "<B",
    1: "<b",
    2: "<H",
    3: "<h",
    4: "<I",
    5: "<i",
    6: "<f",
    7: "<?",
    10: "<Q",
    11: "<q",
    12: "<d",
}
_GGUF_STRING = 8
_GGUF_ARRAY = 9
#: Metadata keys whose string values are retained (all other strings are skipped, not stored).
_GGUF_KEEP_PREFIXES: Final = ("general.", "tokenizer.chat_template")
_GGUF_KEEP_MAX: Final = 4096


@dataclass(frozen=True, slots=True)
class GgufMetadata:
    version: int | None
    tensor_count: int | None
    kv_count: int | None
    values: dict[str, str | int | float | bool]
    chat_templates: tuple[ChatTemplateFinding, ...]
    base_models: tuple[dict[str, str], ...]
    error: str | None


class _GgufReader:
    def __init__(self, fh: IO[bytes], size: int, version: int) -> None:
        self.fh = fh
        self.size = size
        self.len_fmt = "<I" if version == 1 else "<Q"
        self.len_size = struct.calcsize(self.len_fmt)

    def _read(self, n: int) -> bytes:
        if n < 0 or self.fh.tell() + n > self.size:
            raise ValueError("read past end of file")
        data = self.fh.read(n)
        if len(data) != n:
            raise ValueError("short read")
        return data

    def unpack(self, fmt: str) -> int | float | bool:
        (value,) = struct.unpack(fmt, self._read(struct.calcsize(fmt)))
        return value  # type: ignore[no-any-return]

    def length(self, limit: int) -> int:
        value = int(self.unpack(self.len_fmt))
        if value > limit:
            raise ValueError(f"length {value} exceeds limit {limit}")
        return value

    def string(self, keep: bool) -> str | None:
        n = self.length(MAX_GGUF_STRING)
        if not keep:
            self.fh.seek(n, io.SEEK_CUR)
            if self.fh.tell() > self.size:
                raise ValueError("string past end of file")
            return None
        return self._read(n).decode("utf-8", "replace")

    def value(self, vtype: int, keep: bool) -> str | int | float | bool | None:
        if vtype in _GGUF_SCALARS:
            return self.unpack(_GGUF_SCALARS[vtype])
        if vtype == _GGUF_STRING:
            return self.string(keep)
        if vtype == _GGUF_ARRAY:
            elem_type = int(self.unpack("<I"))
            count = self.length(MAX_GGUF_ARRAY)
            if elem_type in _GGUF_SCALARS:
                self.fh.seek(count * struct.calcsize(_GGUF_SCALARS[elem_type]), io.SEEK_CUR)
                if self.fh.tell() > self.size:
                    raise ValueError("array past end of file")
            elif elem_type == _GGUF_STRING:
                for _ in range(count):
                    self.string(False)
            else:
                raise ValueError(f"unsupported array element type {elem_type}")
            return None
        raise ValueError(f"unknown value type {vtype}")


def read_gguf_metadata(path: Path) -> GgufMetadata:
    """Read GGUF (v1-v3, little-endian) metadata keys, retaining ``general.*`` and chat templates only."""
    size = path.stat().st_size
    values: dict[str, str | int | float | bool] = {}
    templates: list[ChatTemplateFinding] = []
    version: int | None = None
    tensor_count: int | None = None
    kv_count: int | None = None
    try:
        with path.open("rb") as fh:
            if fh.read(4) != b"GGUF":
                return GgufMetadata(None, None, None, {}, (), (), "not-gguf")
            (version,) = struct.unpack("<I", fh.read(4))
            if version not in (1, 2, 3):
                return GgufMetadata(version, None, None, {}, (), (), "unsupported-version-or-big-endian")
            reader = _GgufReader(fh, size, version)
            tensor_count = int(reader.unpack(reader.len_fmt))
            kv_count = reader.length(MAX_GGUF_KV)
            for _ in range(kv_count):
                key = reader.string(True) or ""
                vtype = int(reader.unpack("<I"))
                keep = key.startswith(_GGUF_KEEP_PREFIXES)
                value = reader.value(vtype, keep)
                if value is None:
                    continue
                if key.startswith("tokenizer.chat_template") and isinstance(value, str):
                    name = key.removeprefix("tokenizer.chat_template").lstrip(".") or "default"
                    templates.append(scan_chat_template("gguf-metadata", name, value))
                elif keep and not (isinstance(value, str) and len(value) > _GGUF_KEEP_MAX):
                    values[key] = value
    except (OSError, ValueError, struct.error) as exc:
        return GgufMetadata(
            version, tensor_count, kv_count, values, tuple(templates), _gguf_bases(values), str(exc)
        )
    return GgufMetadata(version, tensor_count, kv_count, values, tuple(templates), _gguf_bases(values), None)


def _gguf_bases(values: dict[str, str | int | float | bool]) -> tuple[dict[str, str], ...]:
    count = values.get("general.base_model.count")
    if not isinstance(count, int) or isinstance(count, bool):
        return ()
    bases: list[dict[str, str]] = []
    for i in range(min(count, 64)):
        entry = {
            field_name: str(values[f"general.base_model.{i}.{field_name}"])
            for field_name in ("name", "organization", "version", "repo_url", "url")
            if f"general.base_model.{i}.{field_name}" in values
        }
        if entry:
            bases.append(entry)
    return tuple(bases)


# ---------------------------------------------------------------------------------------------------------
# Format sniffing and per-file assessment
# ---------------------------------------------------------------------------------------------------------

_MAGIC_ZIP: Final = b"PK\x03\x04"
_MAGIC_7Z: Final = b"7z\xbc\xaf\x27\x1c"
_MAGIC_HDF5: Final = b"\x89HDF\r\n\x1a\n"
_MAGIC_NPY: Final = b"\x93NUMPY"
_MAGIC_GGUF: Final = b"GGUF"


def _looks_like_safetensors(head: bytes, size: int) -> bool:
    if len(head) < 9:
        return False
    (header_len,) = struct.unpack("<Q", head[:8])
    return 2 <= header_len <= min(MAX_SAFETENSORS_HEADER, size - 8) and head[8:9] == b"{"


def _looks_like_pickle(head: bytes) -> bool:
    return len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5


_MAGIC_TABLE: Final[tuple[tuple[bytes, FileFormat], ...]] = (
    (_MAGIC_GGUF, "gguf"),
    (_MAGIC_7Z, "archive-7z"),
    (_MAGIC_HDF5, "keras-h5"),
    (_MAGIC_NPY, "npy"),
)


def sniff_format(path: Path) -> FileFormat:
    """Identify the serialization format of ``path`` from magic bytes, then extension."""
    if path.is_dir():
        return _sniff_dir(path)
    size = path.stat().st_size
    with path.open("rb") as fh:
        head = fh.read(MAX_SNIFF_BYTES)
    for magic, fmt in _MAGIC_TABLE:
        if head.startswith(magic):
            return fmt
    if _looks_like_safetensors(head, size):
        return "safetensors"
    if head.startswith(_MAGIC_ZIP):
        return _sniff_zip(path, path.suffix.lower())
    return _sniff_by_extension(head, path)


def _sniff_dir(path: Path) -> FileFormat:
    if (path / "saved_model.pb").exists() or (path / "saved_model.pbtxt").exists():
        return "tf-savedmodel"
    return "mlflow-pyfunc" if (path / "MLmodel").exists() else "other"


def _sniff_by_extension(head: bytes, path: Path) -> FileFormat:
    suffix = path.suffix.lower()
    fmt: FileFormat = "other"
    if _looks_like_pickle(head) or suffix in _PICKLE_EXTS or suffix in _JOBLIB_EXTS:
        # protocol 0/1 pickles and compressed joblib carry no reliable magic; trust the extension
        fmt = "joblib" if suffix in _JOBLIB_EXTS else "pickle"
    elif suffix == ".onnx" or (suffix == ".ort" and head[:1] == b"\x08"):
        fmt = "onnx"
    elif path.name == "MLmodel":
        fmt = "mlflow-pyfunc"
    return fmt


def _sniff_zip(path: Path, suffix: str) -> FileFormat:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return "other"
    has_pkl = any(n.endswith(".pkl") for n in names)
    rules: tuple[tuple[bool, FileFormat], ...] = (
        (
            suffix == ".keras" or ("config.json" in names and any(n.endswith(".weights.h5") for n in names)),
            "keras-v3",
        ),
        (suffix == ".npz", "npz"),
        (has_pkl and any(n.split("/", 1)[-1].startswith("code/") for n in names), "torchscript"),
        (has_pkl, "torch-zip"),
    )
    return next((fmt for matched, fmt in rules if matched), "other")


@dataclass(frozen=True, slots=True)
class FileAssessment:
    """Serialization assessment of one file or directory inside a model artefact."""

    path: str
    format: FileFormat
    risk_class: RiskClass
    reasons: tuple[str, ...]
    pickle_scans: tuple[tuple[str, PickleScan], ...] = ()
    safetensors: SafetensorsHeader | None = None
    gguf: GgufMetadata | None = None
    chat_templates: tuple[ChatTemplateFinding, ...] = field(default_factory=tuple)

    @property
    def malicious_indicators(self) -> bool:
        return any(scan.dangerous for _, scan in self.pickle_scans) or any(
            t.ssti_indicators for t in self.chat_templates
        )


def _scan_zip_pickles(path: Path) -> tuple[tuple[str, PickleScan], ...]:
    scans: list[tuple[str, PickleScan]] = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".pkl"):
                continue
            with zf.open(info) as member:
                data, truncated = _read_bounded(member, MAX_PICKLE_BYTES)
            scans.append((info.filename, scan_pickle_bytes(data, truncated=truncated)))
    return tuple(scans)


def _npy_header(stream: IO[bytes]) -> dict[str, object] | None:
    if stream.read(6) != _MAGIC_NPY:
        return None
    version = stream.read(2)
    if len(version) != 2:
        return None
    major = version[0]
    if major == 1:
        (hlen,) = struct.unpack("<H", stream.read(2))
    elif major in (2, 3):
        (hlen,) = struct.unpack("<I", stream.read(4))
    else:
        return None
    if hlen > 1024 * 1024:
        return None
    try:
        header = ast.literal_eval(stream.read(hlen).decode("latin-1"))
    except (ValueError, SyntaxError):
        return None
    return header if isinstance(header, dict) else None


def _npy_requires_pickle(header: dict[str, object] | None) -> bool | None:
    if header is None:
        return None
    descr = header.get("descr")
    return "O" in repr(descr)


def _keras_config_has_lambda(config_text: str) -> bool:
    return (
        bool(re.search(r'"class_name"\s*:\s*"Lambda"', config_text)) or '"module": "builtins"' in config_text
    )


def assess_file(path: Path, *, display: str | None = None) -> FileAssessment:
    """Assess one model file (or SavedModel/MLflow directory). Never raises on hostile content."""
    shown = display or path.name
    try:
        fmt = sniff_format(path)
    except OSError as exc:
        return FileAssessment(shown, "other", "none", (f"unreadable: {exc}",))
    try:
        return _assess(path, shown, fmt)
    except (OSError, zipfile.BadZipFile, ValueError, struct.error) as exc:
        return FileAssessment(shown, fmt, _FORMAT_BASE_RISK.get(fmt, "none"), (f"parse-error: {exc}",))


_FORMAT_BASE_RISK: Final[dict[str, RiskClass]] = {
    "safetensors": "none",
    "onnx": "none",
    "gguf": "none",
    "npz": "none",
    "npy": "none",
    "tf-savedmodel": "low",
    "keras-h5": "low",
    "keras-v3": "low",
    "pickle": "code-exec-on-load",
    "torch-zip": "code-exec-on-load",
    "torchscript": "code-exec-on-load",
    "joblib": "code-exec-on-load",
    "mlflow-pyfunc": "code-exec-on-load",
    "archive-7z": "code-exec-on-load",
    "other": "none",
}


def _assess_pickle(path: Path, shown: str, fmt: FileFormat) -> FileAssessment:
    with path.open("rb") as fh:
        data, truncated = _read_bounded(fh, MAX_PICKLE_BYTES)
    scan = scan_pickle_bytes(data, truncated=truncated)
    reasons = [f"format:{fmt}", "pickle deserialization executes code on load"]
    if scan.malformed:
        reasons.append("malformed pickle stream (scanner-evasion indicator)")
    return FileAssessment(shown, fmt, _FORMAT_BASE_RISK[fmt], tuple(reasons), pickle_scans=(("", scan),))


def _assess_torch(path: Path, shown: str, fmt: FileFormat) -> FileAssessment:
    scans = _scan_zip_pickles(path)
    reasons = [
        f"format:{fmt}",
        "PyTorch archive with embedded pickle (torch.load executes code unless weights_only)",
    ]
    if fmt == "torchscript":
        reasons.append("TorchScript code/ entries present")
    if any(scan.malformed for _, scan in scans):
        reasons.append("malformed pickle stream (scanner-evasion indicator)")
    return FileAssessment(shown, fmt, _FORMAT_BASE_RISK[fmt], tuple(reasons), pickle_scans=scans)


def _assess_7z(path: Path, shown: str, fmt: FileFormat) -> FileAssessment:
    del path
    reasons = (
        f"format:{fmt}",
        "opaque 7z archive in model artefact: contents cannot be scanned (nullifAI-style evasion)",
    )
    return FileAssessment(shown, fmt, _FORMAT_BASE_RISK[fmt], reasons)


def _assess_safetensors(path: Path, shown: str, fmt: FileFormat) -> FileAssessment:
    header = read_safetensors_header(path)
    reasons = [f"format:{fmt}"]
    if header.anomalies:
        reasons.append("header anomalies: " + ", ".join(header.anomalies[:8]))
    return FileAssessment(shown, fmt, _FORMAT_BASE_RISK[fmt], tuple(reasons), safetensors=header)


def _assess_gguf(path: Path, shown: str, fmt: FileFormat) -> FileAssessment:
    meta = read_gguf_metadata(path)
    templates = meta.chat_templates
    risk: RiskClass = _FORMAT_BASE_RISK[fmt]
    reasons = [f"format:{fmt}"]
    if templates:
        risk = "template-execution"
        reasons.append("Jinja chat template in GGUF metadata (rendered by the inference engine)")
    if any(t.ssti_indicators for t in templates):
        reasons.append("server-side template injection indicators in chat template (CVE-2024-34359 class)")
    if meta.error:
        reasons.append(f"gguf-metadata-error: {meta.error}")
    return FileAssessment(shown, fmt, risk, tuple(reasons), gguf=meta, chat_templates=templates)


def _assess_npy(path: Path, shown: str, fmt: FileFormat) -> FileAssessment:
    with path.open("rb") as fh:
        needs_pickle = _npy_requires_pickle(_npy_header(fh))
    reasons = [f"format:{fmt}"]
    risk: RiskClass = _FORMAT_BASE_RISK[fmt]
    if needs_pickle:
        risk = "code-exec-on-load"
        reasons.append("object dtype requires allow_pickle=True")
    elif needs_pickle is None:
        reasons.append("unreadable npy header")
    return FileAssessment(shown, fmt, risk, tuple(reasons))


def _assess_npz(path: Path, shown: str, fmt: FileFormat) -> FileAssessment:
    reasons = [f"format:{fmt}"]
    risk: RiskClass = _FORMAT_BASE_RISK[fmt]
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.filename.endswith(".npy"):
                with zf.open(info) as member:
                    if _npy_requires_pickle(_npy_header(member)):
                        risk = "code-exec-on-load"
                        reasons.append(f"{info.filename}: object dtype requires allow_pickle=True")
    return FileAssessment(shown, fmt, risk, tuple(reasons))


def _assess_keras_v3(path: Path, shown: str, fmt: FileFormat) -> FileAssessment:
    with zipfile.ZipFile(path) as zf, zf.open("config.json") as member:
        text, _ = _read_bounded(member, MAX_KERAS_CONFIG)
    reasons = [f"format:{fmt}"]
    risk: RiskClass = _FORMAT_BASE_RISK[fmt]
    if _keras_config_has_lambda(text.decode("utf-8", "replace")):
        risk = "code-exec-on-load"
        reasons.append("Keras Lambda layer / builtins module in config (code execution unless safe_mode)")
    return FileAssessment(shown, fmt, risk, tuple(reasons))


def _assess_keras_h5(path: Path, shown: str, fmt: FileFormat) -> FileAssessment:
    with path.open("rb") as fh:
        blob, _ = _read_bounded(fh, MAX_H5_SEARCH)
    reasons = [f"format:{fmt}"]
    risk: RiskClass = _FORMAT_BASE_RISK[fmt]
    if b'"class_name": "Lambda"' in blob or b'"class_name":"Lambda"' in blob:
        risk = "code-exec-on-load"
        reasons.append("Keras Lambda layer in HDF5 model_config (heuristic byte search)")
    return FileAssessment(shown, fmt, risk, tuple(reasons))


def _assess_savedmodel(path: Path, shown: str, fmt: FileFormat) -> FileAssessment:
    reasons = [f"format:{fmt}"]
    graph = path / "saved_model.pb"
    if graph.exists():
        with graph.open("rb") as fh:
            blob, _ = _read_bounded(fh, MAX_H5_SEARCH)
        io_ops = sorted({op.decode() for op in (b"WriteFile", b"ReadFile", b"MatchingFiles") if op in blob})
        if io_ops:
            reasons.append("graph contains file-I/O ops: " + ", ".join(io_ops))
    return FileAssessment(shown, fmt, _FORMAT_BASE_RISK[fmt], tuple(reasons))


def _assess_mlflow(path: Path, shown: str, fmt: FileFormat) -> FileAssessment:
    del path
    reasons = (f"format:{fmt}", "MLflow pyfunc flavour loads a pickled/cloudpickled model")
    return FileAssessment(shown, fmt, _FORMAT_BASE_RISK[fmt], reasons)


def _assess_default(path: Path, shown: str, fmt: FileFormat) -> FileAssessment:
    del path
    return FileAssessment(shown, fmt, _FORMAT_BASE_RISK[fmt], (f"format:{fmt}",))


_HANDLERS: Final[dict[str, Callable[[Path, str, FileFormat], FileAssessment]]] = {
    "pickle": _assess_pickle,
    "joblib": _assess_pickle,
    "torch-zip": _assess_torch,
    "torchscript": _assess_torch,
    "archive-7z": _assess_7z,
    "safetensors": _assess_safetensors,
    "gguf": _assess_gguf,
    "npy": _assess_npy,
    "npz": _assess_npz,
    "keras-v3": _assess_keras_v3,
    "keras-h5": _assess_keras_h5,
    "tf-savedmodel": _assess_savedmodel,
    "mlflow-pyfunc": _assess_mlflow,
}


def _assess(path: Path, shown: str, fmt: FileFormat) -> FileAssessment:
    return _HANDLERS.get(fmt, _assess_default)(path, shown, fmt)


def iter_model_files(root: Path, *, max_files: int = 100_000) -> Iterator[Path]:
    """Yield regular files under ``root`` in sorted order, skipping ``.git`` and symlinks."""
    count = 0
    for candidate in sorted(root.rglob("*")):
        if ".git" in candidate.parts or candidate.is_symlink() or not candidate.is_file():
            continue
        count += 1
        if count > max_files:
            return
        yield candidate
