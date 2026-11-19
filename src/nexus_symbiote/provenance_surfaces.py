"""Model forensics depth, alias/registry provenance, guardrail/memory provenance, and training lineage.

Implements roadmap items:
- R1.1-4: Pickle safe-global allow-list with opcode and byte-offset evidence, GGUF general.*
  metadata key allow-list, and CR-10 loader-safety binding.
- R1.3-5: Alias indirection (LiteLLM, vLLM, Modelfile, CR-2) with routes-to edges,
  model_alias_mutable, model_alias_retargeted, and floating_registry_reference.
- R1.3-6: GuardrailComponent (guard.config, eval.promptfoo, CR-9) with config_hash,
  MemoryStoreComponent declarations, data[].classification, and pii_data_reaches_exposed_agent.
- R1.4-2: Training-lineage ingestion from in-toto/SLSA/dataset attestations, .dvc manifests,
  and CR-4 claims (DataSourceComponent, training-run, trained-on, fine-tuned-from, produces,
  floating_dataset_revision, lineage_unpinned, lineage_conflict).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import (
    AssuranceLevel,
    ComponentType,
    RiskSeverity,
    SerializationSafety,
    TrustTier,
)
from nexus_symbiote.core.hashing import open_regular_file, parse_json_strict
from nexus_symbiote.core.models import (
    AgentComponent,
    ClaimEvidence,
    DataSourceComponent,
    GuardrailComponent,
    MemoryStoreComponent,
    ModelComponent,
    RAGSourceComponent,
    RiskAssessment,
)
from nexus_symbiote.policy import PolicyError, parse_yaml_mapping
from nexus_symbiote.scanners.credential_files import credential_gap, credential_shaped
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import redact_text
from nexus_symbiote.utils.terminal import neutralize

FORMAT = "nexus-symbiote/provenance-surfaces/v1"
MAX_CLAIM_FILE_BYTES = 4 * 1024 * 1024
MAX_YAML_NODES = 4096
MAX_PICKLE_OPCODES = 65536
MAX_GGUF_HEADER_KEYS = 4096


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


def _rec(**kw: Any) -> dict[str, Any]:
    return kw


_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MD5_RE = re.compile(r"^[0-9a-f]{32}$")
_FLOATING_REFS = _words("latest main master production staging dev head trunk default")
_SENSITIVE_CLASSIFICATIONS = _words("pii phi confidential restricted secret")

SAFE_PICKLE_GLOBALS: frozenset[tuple[str, str]] = frozenset(
    tuple(pair.split(":", 1))  # type: ignore[misc]
    for pair in _words(
        "torch._utils:_rebuild_tensor torch._utils:_rebuild_tensor_v2 "
        "torch._utils:_rebuild_tensor_v3 torch._utils:_rebuild_parameter "
        "torch.storage:_load_from_bytes torch:FloatStorage torch:HalfStorage "
        "torch:BFloat16Storage torch:DoubleStorage torch:IntStorage torch:LongStorage "
        "torch:ByteStorage torch:CharStorage torch:ShortStorage torch:BoolStorage "
        "torch:Size torch:device torch:dtype collections:OrderedDict builtins:getattr "
        "numpy.core.multiarray:_reconstruct numpy._core.multiarray:_reconstruct "
        "numpy.core.multiarray:scalar numpy._core.multiarray:scalar "
        "numpy:ndarray numpy:dtype _codecs:encode codecs:encode"
    )
)

_CRITICAL_PICKLE_MODULES: frozenset[str] = _words(
    "os posix nt subprocess builtins __builtin__ sys importlib runpy pty socket "
    "shutil ctypes marshal types operator functools pickle _pickle webbrowser tempfile"
)

ALLOWED_GGUF_GENERAL_KEYS: frozenset[str] = _words(
    "general.architecture general.quantization_version general.alignment general.name "
    "general.author general.version general.organization general.basename general.finetune "
    "general.description general.quantized_by general.size_label general.license "
    "general.license.name general.license.link general.url general.doi general.uuid "
    "general.repo_url general.tags general.languages general.datasets general.file_type "
    "general.source.url general.source.huggingface.repository general.base_model.count"
)

_GGUF_SCALAR_WIDTHS: dict[int, int] = dict(
    zip((0, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12), (1, 1, 2, 2, 4, 4, 4, 1, 8, 8, 8), strict=True)
)
_GGUF_STRING = 8
_GGUF_ARRAY = 9


class ProvenanceInputError(ValueError):
    """Raised when an input to provenance inspection is malformed or unsafe."""


@dataclass(frozen=True)
class PickleGlobalEvidence:
    opcode: str
    module: str
    attr: str
    byte_offset: int
    allowed: bool

    @property
    def global_name(self) -> str:
        return f"{self.module}.{self.attr}"


@dataclass(frozen=True)
class GGUFKeyEvidence:
    key: str
    byte_offset: int
    allowed: bool
    string_value: str | None = None


@dataclass
class ProvenanceFinding:
    category: str
    severity: str
    component_ref: str
    detail: str
    locator: str | None = None
    byte_offset: int | None = None
    opcode: str | None = None
    global_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "category": _clean(self.category),
            "severity": self.severity,
            "component_ref": _clean(self.component_ref),
            "detail": _clean(self.detail),
        }
        if self.locator is not None:
            res["locator"] = _clean(self.locator)
        if self.byte_offset is not None:
            res["byte_offset"] = self.byte_offset
        if self.opcode is not None:
            res["opcode"] = self.opcode
        if self.global_name is not None:
            res["global_name"] = _clean(self.global_name)
        return res


@dataclass
class ProvenanceSummary:
    bom: AIBOM = field(default_factory=AIBOM)
    findings: list[ProvenanceFinding] = field(default_factory=list)
    pickle_inspections: list[dict[str, Any]] = field(default_factory=list)
    gguf_inspections: list[dict[str, Any]] = field(default_factory=list)
    alias_routes: list[dict[str, Any]] = field(default_factory=list)
    registry_references: list[dict[str, Any]] = field(default_factory=list)
    guardrails: list[dict[str, Any]] = field(default_factory=list)
    memory_stores: list[dict[str, Any]] = field(default_factory=list)
    lineage_edges: list[dict[str, Any]] = field(default_factory=list)
    dvc_verifications: list[dict[str, Any]] = field(default_factory=list)
    unread_gaps: list[str] = field(default_factory=list)

    def flag(
        self,
        category: str,
        sev: RiskSeverity,
        ref: str,
        detail: str,
        loc: str | None = None,
        offset: int | None = None,
        op: str | None = None,
        glob: str | None = None,
    ) -> None:
        self.findings.append(
            ProvenanceFinding(category, sev.value, ref, detail, loc, offset, op, glob)
        )
        comp = self.bom.get_component(ref)
        if comp is not None:
            risk = RiskAssessment(severity=sev, category=category, detail=_clean(detail))
            if risk not in comp.risks:
                comp.risks.append(risk)

    def edge(self, src: str, dst: str, rel: str, loc: str) -> None:
        native: Any = "configured-with" if rel == "produces" else rel
        cond = "produces" if rel == "produces" else None
        dep = DependencyEdge(
            source_ref=src,
            target_ref=dst,
            relationship=native,
            assurance_level="declared",
            conditions=cond,
        )
        if dep not in self.bom.dependencies:
            self.bom.add_dependency(dep)
        self.lineage_edges.append(
            {"source_ref": src, "target_ref": dst, "relationship": rel, "locator": loc}
        )

    def model(
        self,
        ref: str,
        name: str,
        mtype: str = "foundation",
        path: str | None = None,
        assurance: AssuranceLevel = AssuranceLevel.DECLARED,
    ) -> ModelComponent:
        existing = self.bom.get_component(ref)
        if isinstance(existing, ModelComponent):
            return existing
        comp = ModelComponent(bom_ref=ref, name=name, model_type=mtype, source_path=path)
        comp.assurance_level = assurance
        comp.trust_tier = TrustTier.UNKNOWN
        self.bom.add_component(comp)
        return comp

    def dataset(
        self,
        ref: str,
        name: str,
        uri: str | None = None,
        digest: str | None = None,
        path: str | None = None,
    ) -> DataSourceComponent:
        existing = self.bom.get_component(ref)
        if isinstance(existing, DataSourceComponent):
            return existing
        comp = DataSourceComponent(bom_ref=ref, name=name, dataset_type="fine-tuning")
        comp.source_uri = uri
        comp.content_hash = digest
        comp.source_path = path
        comp.assurance_level = AssuranceLevel.DECLARED
        comp.trust_tier = TrustTier.UNKNOWN
        self.bom.add_component(comp)
        return comp


def _clean(value: object) -> str:
    return neutralize(redact_text(str(value)))


def _is_pinned_revision(rev: str | None) -> bool:
    if not rev:
        return False
    cleaned = rev.strip()
    if cleaned.lower() in _FLOATING_REFS:
        return False
    return bool(_HEX40_RE.fullmatch(cleaned) or _SHA256_RE.fullmatch(cleaned))


_FIXED_SKIP_OPCODES: dict[int, int] = dict(
    zip((0x80, 0x95, ord("K"), ord("M"), ord("J"), ord("G")), (1, 8, 1, 2, 4, 8), strict=True)
)
_COUNTED_BYTES_OPCODES: dict[int, tuple[int, bool]] = {
    0x8A: (1, False),
    0x8B: (4, True),
    ord("C"): (1, False),
    ord("B"): (4, False),
}
_COUNTED_STR_OPCODES: dict[int, tuple[int, str, bool]] = {
    0x8C: (1, "utf-8", False),
    0x8D: (4, "utf-8", False),
    0x8E: (8, "utf-8", False),
    ord("U"): (1, "latin-1", False),
    ord("T"): (4, "latin-1", True),
}
_NOARG_STACK_OPCODES: frozenset[int] = frozenset(
    b"N(]})RbQ0euas" + bytes((0x88, 0x89, 0x8F, 0x81, 0x85, 0x86, 0x87, 0x90, 0x91, 0x92))
)


def inspect_pickle_globals(
    raw: bytes, *, max_opcodes: int = MAX_PICKLE_OPCODES
) -> tuple[list[PickleGlobalEvidence], bool]:
    """Bounded, non-executing pickle opcode scanner checking globals against SAFE_PICKLE_GLOBALS."""
    pos, size, opcodes, memo_counter = 0, len(raw), 0, 0
    stack: list[str | None] = []
    memo: dict[int, str | None] = {}
    results: list[PickleGlobalEvidence] = []

    def _read_line() -> str | None:
        nonlocal pos
        nl = raw.find(b"\n", pos)
        if nl < 0:
            return None
        line = raw[pos:nl].rstrip(b"\r").decode("utf-8", "replace")
        pos = nl + 1
        return line

    def _read_count(width: int, signed: bool) -> int | None:
        nonlocal pos
        if pos + width > size:
            return None
        val = int.from_bytes(raw[pos : pos + width], "little", signed=signed)
        pos += width
        return val if val >= 0 and pos + val <= size else None

    while pos < size:
        if opcodes >= max_opcodes:
            return results, True
        opcodes += 1
        op_offset, op = pos, raw[pos]
        pos += 1

        if op in _FIXED_SKIP_OPCODES:
            step = _FIXED_SKIP_OPCODES[op]
            if pos + step > size:
                return results, True
            pos += step
            if op not in (0x80, 0x95):
                stack.append(None)
        elif op == ord("."):
            stack.clear()
        elif op in (ord("c"), ord("i")):
            module = _read_line()
            attr = _read_line() if module is not None else None
            if module is None or attr is None:
                return results, True
            opcode_name = "GLOBAL" if op == ord("c") else "INST"
            allowed = (module, attr) in SAFE_PICKLE_GLOBALS and op == ord("c")
            results.append(PickleGlobalEvidence(opcode_name, module, attr, op_offset, allowed))
            stack.append(f"{module}.{attr}")
        elif op == 0x93:  # STACK_GLOBAL
            if len(stack) < 2:
                return results, True
            attr_val, mod_val = stack.pop(), stack.pop()
            module = mod_val if isinstance(mod_val, str) and mod_val else "<dynamic>"
            attr = attr_val if isinstance(attr_val, str) and attr_val else "<dynamic>"
            allowed = (module, attr) in SAFE_PICKLE_GLOBALS
            results.append(PickleGlobalEvidence("STACK_GLOBAL", module, attr, op_offset, allowed))
            stack.append(f"{module}.{attr}")
        elif op in (0x82, 0x83, 0x84):  # EXT1, EXT2, EXT4
            width = 1 if op == 0x82 else (2 if op == 0x83 else 4)
            if pos + width > size:
                return results, True
            code = int.from_bytes(raw[pos : pos + width], "little")
            pos += width
            op_name = {0x82: "EXT1", 0x83: "EXT2", 0x84: "EXT4"}[op]
            results.append(
                PickleGlobalEvidence(op_name, "copyreg", f"extension_{code}", op_offset, False)
            )
            stack.append(None)
        elif op in _COUNTED_STR_OPCODES:
            width, enc, signed = _COUNTED_STR_OPCODES[op]
            length = _read_count(width, signed)
            if length is None:
                return results, True
            stack.append(raw[pos : pos + length].decode(enc, "replace"))
            pos += length
        elif op in _COUNTED_BYTES_OPCODES:
            width, signed = _COUNTED_BYTES_OPCODES[op]
            length = _read_count(width, signed)
            if length is None:
                return results, True
            pos += length
            stack.append(None)
        elif op in (ord("S"), ord("V")):
            text = _read_line()
            if text is None:
                return results, True
            stack.append(text.strip("'\""))
        elif op == 0x94:  # MEMOIZE
            memo[memo_counter] = stack[-1] if stack else None
            memo_counter += 1
        elif op in (ord("q"), ord("r"), ord("h"), ord("j")):
            width = 1 if op in (ord("q"), ord("h")) else 4
            if pos + width > size:
                return results, True
            idx = int.from_bytes(raw[pos : pos + width], "little")
            pos += width
            if op in (ord("q"), ord("r")):
                memo[idx] = stack[-1] if stack else None
                memo_counter = max(memo_counter, idx + 1)
            else:
                stack.append(memo.get(idx))
        elif op in (ord("p"), ord("g")):
            line = _read_line()
            if line is None or not line.lstrip("-").isdigit():
                return results, True
            idx = int(line)
            if op == ord("p"):
                memo[idx] = stack[-1] if stack else None
            else:
                stack.append(memo.get(idx))
        elif op in (ord("I"), ord("L"), ord("F"), ord("P")):
            if _read_line() is None:
                return results, True
            stack.append(None)
        elif op in _NOARG_STACK_OPCODES:
            stack.append(None)
        else:
            return results, True
    return results, False


def inspect_gguf_general_keys(raw: bytes) -> tuple[list[GGUFKeyEvidence], str | None, bool]:
    """Bounded GGUF v2/v3 header scanner inspecting ``general.*`` keys against an allow-list."""
    if len(raw) < 24 or raw[:4] != b"GGUF":
        return [], None, True
    (version, _tensor_count, kv_count) = struct.unpack("<IQQ", raw[4:24])
    if version not in (2, 3) or kv_count > MAX_GGUF_HEADER_KEYS:
        return [], None, True
    pos, size = 24, len(raw)
    keys: list[GGUFKeyEvidence] = []
    license_val: str | None = None

    def _read_str() -> str | None:
        nonlocal pos
        if pos + 8 > size:
            return None
        (length,) = struct.unpack("<Q", raw[pos : pos + 8])
        pos += 8
        if length > 4 * 1024 * 1024 or pos + length > size:
            return None
        raw_bytes = raw[pos : pos + length]
        pos += length
        return raw_bytes.split(b"\x00", 1)[0].decode("utf-8", "replace")

    def _skip_val(kind: int, depth: int = 0) -> bool:
        nonlocal pos
        if kind in _GGUF_SCALAR_WIDTHS:
            w = _GGUF_SCALAR_WIDTHS[kind]
            if pos + w > size:
                return False
            pos += w
            return True
        if kind == _GGUF_STRING:
            return _read_str() is not None
        if kind == _GGUF_ARRAY and depth < 2 and pos + 12 <= size:
            (item_kind, count) = struct.unpack("<IQ", raw[pos : pos + 12])
            pos += 12
            if count > 262144:
                return False
            if item_kind in _GGUF_SCALAR_WIDTHS:
                step = count * _GGUF_SCALAR_WIDTHS[item_kind]
                if pos + step > size:
                    return False
                pos += step
                return True
            return all(_skip_val(item_kind, depth + 1) for _ in range(count))
        return False

    for _ in range(kv_count):
        key_offset, key = pos, _read_str()
        if key is None or pos + 4 > size:
            return keys, license_val, True
        (kind,) = struct.unpack("<I", raw[pos : pos + 4])
        pos += 4
        str_val: str | None = None
        if kind == _GGUF_STRING and key.startswith("general."):
            str_val = _read_str()
            if str_val is None:
                return keys, license_val, True
            if key in ("general.license", "general.license.name") and str_val.strip():
                license_val = _clean(str_val.strip())
        elif not _skip_val(kind):
            return keys, license_val, True
        if key.startswith("general."):
            allowed = key in ALLOWED_GGUF_GENERAL_KEYS or key.startswith("general.base_model.")
            keys.append(
                GGUFKeyEvidence(key, key_offset, allowed, _clean(str_val) if str_val else None)
            )
    return keys, license_val, False


def _safe_read_bytes(
    files: ConfinedCollection, rel_path: str, summary: ProvenanceSummary
) -> bytes | None:
    if credential_shaped(rel_path):
        summary.unread_gaps.append(f"{rel_path}: its name says it holds credentials")
        return None
    raw = files.read_bytes(rel_path, missing_ok=True)
    if raw is None:
        return None
    gap = credential_gap(rel_path, files.link_target(rel_path))
    if gap is not None:
        summary.unread_gaps.append(f"{rel_path}: {gap}")
        return None
    return raw


def _safe_read_yaml(
    files: ConfinedCollection, rel_path: str, summary: ProvenanceSummary
) -> tuple[dict[str, Any], bytes] | None:
    raw = _safe_read_bytes(files, rel_path, summary)
    if raw is None:
        return None
    try:
        return parse_yaml_mapping(raw.decode("utf-8"), max_nodes=MAX_YAML_NODES), raw
    except (UnicodeDecodeError, PolicyError) as exc:
        summary.unread_gaps.append(f"{rel_path}: {_clean(exc)}")
        return None


def _load_external_json_list(paths: tuple[Path, ...]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in paths:
        try:
            with open_regular_file(path) as stream:
                raw = stream.read(MAX_CLAIM_FILE_BYTES + 1)
        except OSError as exc:
            raise ProvenanceInputError(f"cannot safely open {neutralize(path)}") from exc
        if len(raw) > MAX_CLAIM_FILE_BYTES:
            raise ProvenanceInputError(f"{neutralize(path)} exceeds {MAX_CLAIM_FILE_BYTES} bytes")
        try:
            parsed = parse_json_strict(raw, max_bytes=MAX_CLAIM_FILE_BYTES)
        except (ValueError, UnicodeError, RecursionError) as exc:
            msg = f"{neutralize(path)} is not valid strict UTF-8 JSON"
            raise ProvenanceInputError(msg) from exc
        if isinstance(parsed, dict):
            items = parsed.get("claims") or parsed.get("findings")
            records.extend(
                [i for i in items if isinstance(i, dict)] if isinstance(items, list) else [parsed]
            )
        elif isinstance(parsed, list):
            records.extend(i for i in parsed if isinstance(i, dict))
        else:
            raise ProvenanceInputError(f"{neutralize(path)} must contain a JSON object or array")
    return records


def _inspect_model_forensics(
    files: ConfinedCollection,
    rel_paths: list[str],
    claims: list[dict[str, Any]],
    s: ProvenanceSummary,
) -> None:
    pickle_suffixes = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".joblib"}
    for rel_str in rel_paths:
        suffix = PurePosixPath(rel_str).suffix.lower()
        if suffix in pickle_suffixes:
            raw = _safe_read_bytes(files, rel_str, s)
            if not raw or not (
                (raw.startswith(b"\x80") and len(raw) >= 2 and 1 <= raw[1] <= 5)
                or raw[:1] in (b"c", b"(", b"i")
            ):
                continue
            comp_ref = f"model:{rel_str}"
            evidences, truncated = inspect_pickle_globals(raw)
            disallowed = [e for e in evidences if not e.allowed]
            is_unsafe = bool(disallowed or truncated)
            comp = s.model(
                comp_ref,
                PurePosixPath(rel_str).name,
                "foundation",
                rel_str,
                AssuranceLevel.OBSERVED,
            )
            comp.hashes["sha256"] = hashlib.sha256(raw).hexdigest()
            comp.serialization_format = "pickle"
            comp.serialization_safety = (
                SerializationSafety.UNSAFE_CODE_EXECUTION if is_unsafe else SerializationSafety.SAFE
            )
            globs = [
                {
                    "opcode": e.opcode,
                    "global": _clean(e.global_name),
                    "byte_offset": e.byte_offset,
                    "allowed": e.allowed,
                }
                for e in evidences
            ]
            rec = _rec(source_path=rel_str, component_ref=comp_ref, globals_count=len(evidences))
            rec.update(disallowed_count=len(disallowed), truncated=truncated, globals=globs)
            s.pickle_inspections.append(rec)
            for ev in disallowed:
                top_mod = ev.module.split(".", 1)[0]
                is_crit = top_mod in _CRITICAL_PICKLE_MODULES or ev.opcode.startswith("EXT")
                sev = RiskSeverity.CRITICAL if is_crit else RiskSeverity.HIGH
                msg = f"Pickle at {rel_str} offset {ev.byte_offset} invokes disallowed global {ev.global_name} via opcode {ev.opcode}"
                s.flag(
                    "pickle_unsafe_global",
                    sev,
                    comp_ref,
                    msg,
                    f"{rel_str}@{ev.byte_offset}",
                    ev.byte_offset,
                    ev.opcode,
                    ev.global_name,
                )
            if truncated:
                msg = f"Pickle opcode stream in {rel_str} could not be bounded cleanly"
                s.flag("pickle_unsafe_global", RiskSeverity.HIGH, comp_ref, msg, rel_str)
        elif suffix == ".gguf":
            raw = _safe_read_bytes(files, rel_str, s)
            if raw is None:
                continue
            comp_ref = f"model:{rel_str}"
            gguf_keys, declared_license, malformed = inspect_gguf_general_keys(raw)
            comp = s.model(
                comp_ref,
                PurePosixPath(rel_str).name,
                "foundation",
                rel_str,
                AssuranceLevel.OBSERVED,
            )
            comp.hashes["sha256"] = hashlib.sha256(raw).hexdigest()
            comp.serialization_format = "gguf"
            comp.serialization_safety = SerializationSafety.SAFE
            if declared_license:
                comp.properties["declared_license"] = declared_license
            g_keys = [
                _rec(key=_clean(k.key), byte_offset=k.byte_offset, allowed=k.allowed)
                for k in gguf_keys
            ]
            rec = _rec(source_path=rel_str, component_ref=comp_ref, general_keys=g_keys)
            rec.update(declared_license=declared_license, malformed=malformed)
            s.gguf_inspections.append(rec)
            for k in (k for k in gguf_keys if not k.allowed):
                msg = f"GGUF header in {rel_str} at offset {k.byte_offset} carries unrecognized general key {k.key}"
                s.flag(
                    "gguf_unrecognized_general_key",
                    RiskSeverity.MEDIUM,
                    comp_ref,
                    msg,
                    f"{rel_str}@{k.byte_offset}",
                    k.byte_offset,
                )

    for claim in claims:
        if claim.get("cr") != "CR-10" and claim.get("kind") != "loader_safety":
            continue
        target_path = str(claim.get("model_path") or claim.get("target") or "").strip()
        if not target_path:
            continue
        loader_call = _clean(claim.get("loader_call") or "from_pretrained")
        file_loc = _clean(claim.get("file") or target_path)
        line = claim.get("line")
        locator = f"{file_loc}:{line}" if isinstance(line, int) else file_loc
        trust_remote = claim.get("trust_remote_code")
        comp_ref = f"model:{target_path}"
        comp = s.model(
            comp_ref, PurePosixPath(target_path).name or target_path, "foundation", target_path
        )
        if trust_remote is True:
            comp.trust_remote_code = True
        claim_ev = ClaimEvidence(
            assurance=AssuranceLevel.DECLARED, method="imported-claim-cr10", scope="repository"
        )
        claim_ev.collector = "shadowscan"
        claim_ev.locator = locator
        comp.claims["loader_safety"] = claim_ev
        comp.properties["loader_safety_call"] = loader_call
        if trust_remote is True:
            msg = f"Loader call {loader_call} at {locator} sets trust_remote_code=True"
            s.flag("loader_trust_remote_code", RiskSeverity.CRITICAL, comp_ref, msg, locator)


def _register_alias_route(
    s: ProvenanceSummary,
    alias_name: str,
    target_name: str,
    locator: str,
    alias_targets: dict[str, set[str]],
) -> None:
    clean_alias, clean_target = _clean(alias_name.strip()), _clean(target_name.strip())
    alias_ref, target_ref = f"model:alias:{clean_alias}", f"model:target:{clean_target}"
    alias_targets.setdefault(clean_alias, set()).add(clean_target)

    comp = s.model(alias_ref, clean_alias, "alias", locator)
    comp.requested_alias = clean_alias
    comp.resolved_revision = clean_target
    s.model(target_ref, clean_target, "foundation", locator)
    edge = DependencyEdge(
        source_ref=alias_ref,
        target_ref=target_ref,
        relationship="delegates-to",
        conditions="routes-to",
    )
    if edge not in s.bom.dependencies:
        s.bom.add_dependency(edge)
    rec = _rec(alias=clean_alias, target=clean_target, source_ref=alias_ref, target_ref=target_ref)
    rec.update(relationship="routes-to", locator=locator)
    s.alias_routes.append(rec)
    target_lower = clean_target.lower()
    has_pin = (
        "@sha256:" in target_lower
        or bool(re.search(r"\b[0-9a-f]{40}\b", target_lower))
        or bool(re.search(r"-[0-9]{4}-[0-9]{2}-[0-9]{2}$", target_lower))
    )
    if not has_pin or target_lower.endswith(":latest"):
        msg = f"Model alias {clean_alias} routes to mutable target {clean_target} at {locator}"
        s.flag("model_alias_mutable", RiskSeverity.MEDIUM, alias_ref, msg, locator)


def _classify_registry_uri(
    s: ProvenanceSummary, uri: str, revision: str | None, locator: str
) -> None:
    clean_uri = _clean(uri.strip())
    comp_ref = f"model:registry:{clean_uri}"
    pinned = _is_pinned_revision(revision)
    if not pinned:
        m_mlflow = re.match(r"^models:/[^/]+/([^/]+)$", clean_uri)
        if m_mlflow:
            pinned = _is_pinned_revision(m_mlflow.group(1))
        elif "@" in clean_uri:
            pinned = _is_pinned_revision(clean_uri.rsplit("@", 1)[-1])

    clean_rev = _clean(revision) if revision else None
    comp = s.model(comp_ref, clean_uri, "foundation", locator)
    comp.resolved_revision = clean_rev
    comp.properties["pinning_state"] = "pinned" if pinned else "floating"
    rec = _rec(
        uri=clean_uri, revision=clean_rev, pinned=pinned, component_ref=comp_ref, locator=locator
    )
    s.registry_references.append(rec)
    if not pinned:
        msg = f"Model or artifact registry reference {clean_uri} at {locator} is floating"
        s.flag("floating_registry_reference", RiskSeverity.HIGH, comp_ref, msg, locator)


def _inspect_aliases_and_registries(
    files: ConfinedCollection,
    rel_paths: list[str],
    yaml_files: list[tuple[str, dict[str, Any], bytes]],
    claims: list[dict[str, Any]],
    s: ProvenanceSummary,
) -> None:
    alias_targets: dict[str, set[str]] = {}
    for existing in s.bom.get_components_by_type(ComponentType.MODEL):
        if (
            isinstance(existing, ModelComponent)
            and existing.requested_alias
            and existing.resolved_revision
        ):
            alias_targets.setdefault(existing.requested_alias, set()).add(
                existing.resolved_revision
            )

    for rel_str in rel_paths:
        lower_name = PurePosixPath(rel_str).name.lower()
        if lower_name == "modelfile" or lower_name.endswith(".modelfile"):
            raw = _safe_read_bytes(files, rel_str, s)
            if raw is None:
                continue
            alias_stem = PurePosixPath(rel_str).stem
            if alias_stem.lower() == "modelfile":
                alias_stem = PurePosixPath(rel_str).parent.name or "modelfile-default"
            for line in raw.decode("utf-8", "replace").splitlines():
                stripped = line.strip()
                if stripped.upper().startswith("FROM ") and stripped[5:].strip():
                    _register_alias_route(
                        s, alias_stem, stripped[5:].strip(), rel_str, alias_targets
                    )

    for rel_str, mapping, _ in yaml_files:
        if isinstance(mapping.get("model_list"), list):
            for entry in (e for e in mapping["model_list"] if isinstance(e, dict)):
                alias, params = entry.get("model_name"), entry.get("litellm_params")
                target = params.get("model") if isinstance(params, dict) else None
                if isinstance(alias, str) and isinstance(target, str):
                    _register_alias_route(s, alias, target, rel_str, alias_targets)
        _extract_vllm_and_registry_from_mapping(s, mapping, rel_str, alias_targets)

    for claim in claims:
        if claim.get("cr") == "CR-2" or claim.get("kind") == "model_alias":
            alias, target = claim.get("alias"), claim.get("target")
            if isinstance(alias, str) and isinstance(target, str):
                _register_alias_route(
                    s, alias, target, _clean(claim.get("file") or "claim:CR-2"), alias_targets
                )
        elif claim.get("cr") == "CR-4" and isinstance(claim.get("registry_uri"), str):
            rev = claim.get("revision") if isinstance(claim.get("revision"), str) else None
            _classify_registry_uri(
                s, claim["registry_uri"], rev, _clean(claim.get("file") or "claim:CR-4")
            )

    for alias_name, targets in sorted(alias_targets.items()):
        if len(targets) > 1:
            msg = f"Model alias {alias_name} routes to multiple distinct targets: {', '.join(sorted(targets))}"
            s.flag("model_alias_retargeted", RiskSeverity.HIGH, f"model:alias:{alias_name}", msg)


def _extract_vllm_and_registry_from_mapping(
    s: ProvenanceSummary,
    mapping: dict[str, Any],
    rel_str: str,
    alias_targets: dict[str, set[str]],
) -> None:
    pending: list[Any] = [mapping]
    while pending:
        curr = pending.pop()
        if isinstance(curr, dict):
            for key, val in curr.items():
                if key in ("args", "command") and isinstance(val, list):
                    toks = [str(x) for x in val if isinstance(x, (str, int, float))]
                    _parse_vllm_tokens(s, toks, rel_str, alias_targets)
                elif isinstance(val, str) and (
                    key in ("model_uri", "artifact_uri", "mlflow_model", "registry_uri")
                    or val.startswith(("models:/", "runs:/", "wandb://", "hf://"))
                ):
                    rev = curr.get("revision") if isinstance(curr.get("revision"), str) else None
                    _classify_registry_uri(s, val, rev, rel_str)
                elif isinstance(val, (dict, list)):
                    pending.append(val)
        elif isinstance(curr, list):
            pending.extend(item for item in curr if isinstance(item, (dict, list)))


def _parse_vllm_tokens(
    s: ProvenanceSummary,
    tokens: list[str],
    locator: str,
    alias_targets: dict[str, set[str]],
) -> None:
    flat = [part for tok in tokens for part in tok.split()]
    target_model: str | None = None
    served_alias: str | None = None
    for idx, tok in enumerate(flat):
        if (
            tok in ("--model", "serve")
            and idx + 1 < len(flat)
            and not flat[idx + 1].startswith("-")
        ):
            target_model = flat[idx + 1]
        elif tok.startswith("--model="):
            target_model = tok.split("=", 1)[1]
        elif tok == "--served-model-name" and idx + 1 < len(flat):
            served_alias = flat[idx + 1]
        elif tok.startswith("--served-model-name="):
            served_alias = tok.split("=", 1)[1]
    if served_alias and target_model:
        _register_alias_route(s, served_alias, target_model, locator, alias_targets)


def _inspect_guardrails_memory_and_pii(
    yaml_files: list[tuple[str, dict[str, Any], bytes]],
    claims: list[dict[str, Any]],
    s: ProvenanceSummary,
) -> None:
    promptfoo_files = {
        "promptfooconfig.yaml",
        "promptfooconfig.yml",
        "promptfoo.yaml",
        "promptfoo.yml",
    }
    sensitive_data_refs: list[tuple[str, str, str]] = []

    for rel_str, mapping, raw in yaml_files:
        name = PurePosixPath(rel_str).name.lower()
        config_hash = "sha256:" + hashlib.sha256(raw).hexdigest()
        is_promptfoo = name in promptfoo_files or (
            "prompts" in mapping and "providers" in mapping and "tests" in mapping
        )
        is_guardrail = (
            name
            in ("guardrails.yaml", "guardrails.yml", "nemo_guardrails.yaml", "nemo_guardrails.yml")
            or "rails" in mapping
            or "guardrails" in mapping
        )
        if is_promptfoo or is_guardrail:
            base_ref = "eval.promptfoo" if is_promptfoo else "guard.config"
            comp_ref = (
                base_ref if s.bom.get_component(base_ref) is None else f"{base_ref}:{rel_str}"
            )
            g_type = (
                "output-filter"
                if is_promptfoo
                else _clean(mapping.get("guardrail_type") or "input-filter")
            )
            g_comp = GuardrailComponent(
                bom_ref=comp_ref, name=PurePosixPath(rel_str).name, guardrail_type=g_type
            )
            g_comp.policy_version = str(mapping["version"]) if mapping.get("version") else None
            g_comp.config_hash = config_hash
            g_comp.source_path = rel_str
            g_comp.hashes["sha256"] = config_hash.removeprefix("sha256:")
            g_comp.assurance_level = AssuranceLevel.OBSERVED
            s.bom.add_component(g_comp)
            s.guardrails.append(
                _rec(
                    bom_ref=comp_ref,
                    source_path=rel_str,
                    config_hash=config_hash,
                    guardrail_type=g_type,
                )
            )

        _extract_memory_stores(s, mapping, rel_str)
        _extract_data_classifications(s, mapping, rel_str, sensitive_data_refs)

    for claim in claims:
        if claim.get("cr") == "CR-9" or claim.get("kind") == "guardrail":
            ref_id = _clean(claim.get("bom_ref") or claim.get("name") or "guard.bedrock-guardrail")
            loc = _clean(claim.get("file") or "claim:CR-9")
            g_type = _clean(claim.get("guardrail_type") or "classifier")
            if s.bom.get_component(ref_id) is None:
                g_comp = GuardrailComponent(bom_ref=ref_id, name=ref_id, guardrail_type=g_type)
                g_comp.source_path = loc
                g_comp.assurance_level = AssuranceLevel.DECLARED
                g_comp.trust_tier = TrustTier.UNKNOWN
                s.bom.add_component(g_comp)
                s.guardrails.append(
                    _rec(bom_ref=ref_id, source_path=loc, config_hash=None, guardrail_type=g_type)
                )

    if sensitive_data_refs:
        for agent_ref in _find_exposed_agents(s.bom):
            for data_ref, classification, locator in sensitive_data_refs:
                s.bom.add_dependency(
                    DependencyEdge(
                        source_ref=agent_ref, target_ref=data_ref, relationship="retrieves-from"
                    )
                )
                msg = f"Exposed agent {agent_ref} reaches {classification} data source {data_ref} declared at {locator}"
                s.flag("pii_data_reaches_exposed_agent", RiskSeverity.HIGH, agent_ref, msg, locator)


def _extract_memory_stores(s: ProvenanceSummary, mapping: dict[str, Any], rel_str: str) -> None:
    raw_stores = mapping.get("memory_stores") or mapping.get("memory")
    stores = (
        [x for x in raw_stores if isinstance(x, dict)]
        if isinstance(raw_stores, list)
        else ([raw_stores] if isinstance(raw_stores, dict) else [])
    )
    for idx, store in enumerate(stores):
        name = _clean(store.get("name") or f"memory-{idx}")
        comp_ref = f"memory:{name}"
        if s.bom.get_component(comp_ref) is not None:
            continue
        store_type = _clean(store.get("store_type") or store.get("type") or "conversation")
        write_auth = _clean(store.get("write_authority") or "agent-only")
        tenant_iso, enc_rest = store.get("tenant_isolated"), store.get("encryption_at_rest")
        t_iso = tenant_iso if isinstance(tenant_iso, bool) else None
        m_comp = MemoryStoreComponent(
            bom_ref=comp_ref, name=name, store_type=store_type, write_authority=write_auth
        )
        m_comp.retention_policy = (
            _clean(store["retention_policy"]) if store.get("retention_policy") else None
        )
        m_comp.tenant_isolated = t_iso
        m_comp.encryption_at_rest = enc_rest if isinstance(enc_rest, bool) else None
        m_comp.source_path = rel_str
        m_comp.assurance_level = AssuranceLevel.DECLARED
        s.bom.add_component(m_comp)
        rec = _rec(bom_ref=comp_ref, name=name, store_type=store_type, write_authority=write_auth)
        rec.update(tenant_isolated=t_iso, source_path=rel_str)
        s.memory_stores.append(rec)
        if t_iso is False or write_auth == "public":
            msg = f"Memory store {name} at {rel_str} declares tenant_isolated={t_iso} and write_authority={write_auth}"
            s.flag("memory_store_unisolated", RiskSeverity.HIGH, comp_ref, msg, rel_str)


def _extract_data_classifications(
    s: ProvenanceSummary,
    mapping: dict[str, Any],
    rel_str: str,
    sensitive_data_refs: list[tuple[str, str, str]],
) -> None:
    if mapping.get("exposed") is True or mapping.get("public_endpoint") is True:
        agent_name = _clean(mapping.get("name") or "declared-agent")
        agent_ref = f"agent:{agent_name}"
        if s.bom.get_component(agent_ref) is None:
            ag = AgentComponent(bom_ref=agent_ref, name=agent_name, source_path=rel_str)
            ag.assurance_level = AssuranceLevel.DECLARED
            ag.properties["exposed"] = True
            s.bom.add_component(ag)
    for section_key in ("data", "datasets", "rag_sources"):
        entries = mapping.get(section_key)
        if not isinstance(entries, list):
            continue
        for idx, entry in ((i, e) for i, e in enumerate(entries) if isinstance(e, dict)):
            classification = str(entry.get("classification") or "").strip().lower()
            name = _clean(entry.get("name") or entry.get("id") or f"{section_key}-{idx}")
            data_ref = f"rag:{name}" if section_key == "rag_sources" else f"dataset:{name}"
            props = {"classification": classification} if classification else {}
            if section_key == "rag_sources":
                if s.bom.get_component(data_ref) is None:
                    rag = RAGSourceComponent(
                        bom_ref=data_ref, name=name, corpus_type="vector-store"
                    )
                    rag.source_path = rel_str
                    rag.assurance_level = AssuranceLevel.DECLARED
                    rag.properties = props
                    s.bom.add_component(rag)
            else:
                ds = s.dataset(data_ref, name, path=rel_str)
                ds.properties.update(props)
            if classification in _SENSITIVE_CLASSIFICATIONS:
                sensitive_data_refs.append((data_ref, classification, rel_str))


def _find_exposed_agents(bom: AIBOM) -> list[str]:
    agents = bom.get_components_by_type(ComponentType.AGENT)
    has_ext = bool(
        bom.get_components_by_type(ComponentType.A2A_SERVER)
        or bom.get_components_by_type(ComponentType.MCP_SERVER)
        or bom.get_components_by_type(ComponentType.IDE_AGENT)
    )
    return [
        ag.bom_ref
        for ag in agents
        if ag.properties.get("exposed") is True or has_ext or getattr(ag, "tool_refs", [])
    ]


def _inspect_training_lineage(
    files: ConfinedCollection,
    rel_paths: list[str],
    yaml_files: list[tuple[str, dict[str, Any], bytes]],
    claims: list[dict[str, Any]],
    attestations: list[dict[str, Any]],
    s: ProvenanceSummary,
) -> None:
    ds_revs: dict[str, set[str]] = {}
    base_models: dict[str, set[str]] = {}

    for rel_str in rel_paths:
        if PurePosixPath(rel_str).name.lower().endswith(".dvc"):
            _process_dvc_file(files, rel_str, s, ds_revs)

    for rel_str, mapping, _ in yaml_files:
        if PurePosixPath(rel_str).name.lower() in (
            "training.yaml",
            "training.yml",
            "finetune.yaml",
            "finetune.yml",
        ):
            _process_training_yaml(mapping, rel_str, s, ds_revs, base_models)

    for att in attestations:
        _process_lineage_attestation(att, s, ds_revs, base_models)

    for claim in claims:
        if claim.get("cr") == "CR-4" or claim.get("kind") in ("dataset", "training_lineage"):
            _process_cr4_claim(claim, s, ds_revs, base_models)

    for ds_name, revs in sorted(ds_revs.items()):
        ds_ref = f"dataset:{ds_name}"
        pinned_revs = {r for r in revs if r != "<unpinned>" and _is_pinned_revision(r)}
        has_unpinned = "<unpinned>" in revs or any(not _is_pinned_revision(r) for r in revs)
        if pinned_revs and has_unpinned:
            msg = f"Dataset {ds_name} is pinned ({', '.join(sorted(pinned_revs))}) in one declaration but loaded without an immutable pin elsewhere"
            s.flag("lineage_unpinned", RiskSeverity.HIGH, ds_ref, msg)
        if len(pinned_revs) > 1:
            msg = f"Dataset {ds_name} has conflicting pinned digests/revisions: {', '.join(sorted(pinned_revs))}"
            s.flag("lineage_conflict", RiskSeverity.HIGH, ds_ref, msg)

    for target_model, bases in sorted(base_models.items()):
        if len(bases) > 1:
            msg = f"Model {target_model} declares conflicting fine-tune base models: {', '.join(sorted(bases))}"
            s.flag("lineage_conflict", RiskSeverity.HIGH, target_model, msg)


def _normalize_dataset_rev(rev_str: str) -> str:
    if _is_pinned_revision(rev_str):
        return rev_str
    if re.fullmatch(r"[0-9a-f]{7,39}", rev_str):
        return rev_str.ljust(40, "0")
    return "<unpinned>"


def _process_dvc_file(
    files: ConfinedCollection,
    rel_str: str,
    s: ProvenanceSummary,
    ds_revs: dict[str, set[str]],
) -> None:
    loaded = _safe_read_yaml(files, rel_str, s)
    if loaded is None or not isinstance(loaded[0].get("outs"), list):
        return
    parent_dir = PurePosixPath(rel_str).parent
    for entry in (e for e in loaded[0]["outs"] if isinstance(e, dict)):
        out_path = entry.get("path")
        md5_val, sha256_val = entry.get("md5"), entry.get("sha256")
        if not isinstance(out_path, str) or not out_path.strip():
            continue
        target_rel = (
            (parent_dir / out_path).as_posix()
            if str(parent_dir) != "."
            else PurePosixPath(out_path).as_posix()
        )
        ds_name = _clean(PurePosixPath(target_rel).name)
        ds_ref = f"dataset:{ds_name}"
        is_sha = isinstance(sha256_val, str) and bool(re.fullmatch(r"[0-9a-f]{64}", sha256_val))
        is_md5 = isinstance(md5_val, str) and bool(_MD5_RE.fullmatch(md5_val))
        declared_digest = (
            f"sha256:{sha256_val}" if is_sha else (f"md5:{md5_val}" if is_md5 else None)
        )
        verified, mismatch = False, False
        raw_target = _safe_read_bytes(files, target_rel, s)
        if raw_target is not None and declared_digest is not None:
            if declared_digest.startswith("sha256:"):
                actual = "sha256:" + hashlib.sha256(raw_target).hexdigest()
            else:
                actual = "md5:" + hashlib.md5(raw_target, usedforsecurity=False).hexdigest()
            verified = hmac.compare_digest(actual, declared_digest)
            mismatch = not verified

        ds = s.dataset(ds_ref, ds_name, target_rel, declared_digest, rel_str)
        ds.properties["dvc_digest_verified"] = verified
        rec = _rec(dvc_file=rel_str, target_path=target_rel, declared_digest=declared_digest)
        rec.update(digest_verified=verified, component_ref=ds_ref)
        s.dvc_verifications.append(rec)
        if declared_digest is not None:
            norm = (
                declared_digest
                if declared_digest.startswith("sha256:")
                else ("0" * 8 + declared_digest[-32:])
            )
            ds_revs.setdefault(ds_name, set()).add(norm)
        if mismatch:
            msg = f"DVC manifest {rel_str} digest {declared_digest} does not match local bytes at {target_rel}"
            s.flag("lineage_conflict", RiskSeverity.HIGH, ds_ref, msg, rel_str)


def _record_dataset_usage(
    s: ProvenanceSummary,
    ds_name: str,
    rev_str: str,
    locator: str,
    ds_revs: dict[str, set[str]],
    run_ref: str | None = None,
) -> str:
    clean_ds = _clean(ds_name.strip())
    ds_ref = f"dataset:{clean_ds}"
    s.dataset(ds_ref, clean_ds, digest=rev_str if rev_str else None, path=locator)
    if run_ref is not None:
        s.edge(run_ref, ds_ref, "trained-on", locator)
    ds_revs.setdefault(clean_ds, set()).add(_normalize_dataset_rev(rev_str))
    if not rev_str or rev_str.lower() in _FLOATING_REFS:
        msg = f"Dataset {clean_ds} at {locator} has floating or missing revision"
        s.flag("floating_dataset_revision", RiskSeverity.HIGH, ds_ref, msg, locator)
    return ds_ref


def _record_finetune_pair(
    s: ProvenanceSummary,
    output_model: str,
    base_model: str | None,
    locator: str,
    base_models: dict[str, set[str]],
    run_ref: str | None = None,
) -> None:
    out_clean = _clean(output_model.strip())
    out_ref = f"model:{out_clean}"
    s.model(out_ref, out_clean, "fine-tuned", locator)
    if run_ref is not None:
        s.edge(run_ref, out_ref, "produces", locator)
    if isinstance(base_model, str) and base_model.strip():
        base_clean = _clean(base_model.strip())
        base_ref = f"model:{base_clean}"
        s.model(base_ref, base_clean, "foundation", locator)
        s.edge(out_ref, base_ref, "fine-tuned-from", locator)
        base_models.setdefault(out_ref, set()).add(base_clean)


def _process_training_yaml(
    mapping: dict[str, Any],
    rel_str: str,
    s: ProvenanceSummary,
    ds_revs: dict[str, set[str]],
    base_models: dict[str, set[str]],
) -> None:
    run_id = _clean(mapping.get("run_id") or mapping.get("name") or PurePosixPath(rel_str).stem)
    run_ref = f"training-run:{run_id}"
    run_comp = s.model(run_ref, run_id, "training-run", rel_str)
    run_comp.properties["component_subtype"] = "training-run"
    ds_name = mapping.get("dataset") or mapping.get("dataset_name")
    ds_rev = mapping.get("dataset_revision") or mapping.get("revision")
    if isinstance(ds_name, str) and ds_name.strip():
        rev_str = str(ds_rev).strip() if ds_rev is not None else ""
        _record_dataset_usage(s, ds_name, rev_str, rel_str, ds_revs, run_ref)
    output_model = mapping.get("output_model") or mapping.get("model")
    if isinstance(output_model, str) and output_model.strip():
        _record_finetune_pair(
            s, output_model, mapping.get("base_model"), rel_str, base_models, run_ref
        )


def _process_lineage_attestation(
    att: dict[str, Any],
    s: ProvenanceSummary,
    ds_revs: dict[str, set[str]],
    base_models: dict[str, set[str]],
) -> None:
    raw_subj, raw_pred = att.get("subject"), att.get("predicate")
    subjects: list[Any] = raw_subj if isinstance(raw_subj, list) else []
    predicate: dict[str, Any] = raw_pred if isinstance(raw_pred, dict) else {}
    run_id = _clean(predicate.get("run_id") or att.get("run_id") or "attested-run")
    run_ref = f"training-run:{run_id}"
    run_comp = s.model(run_ref, run_id, "training-run")
    run_comp.properties["component_subtype"] = "training-run"
    subject_refs: list[str] = []
    for subj in (x for x in subjects if isinstance(x, dict)):
        s_name = _clean(subj.get("name") or "model")
        raw_dig = subj.get("digest")
        digest_map: dict[str, Any] = raw_dig if isinstance(raw_dig, dict) else {}
        sha = digest_map.get("sha256")
        s_ref = f"model:{s_name}"
        m_comp = s.model(s_ref, s_name, "fine-tuned")
        if isinstance(sha, str):
            m_comp.hashes["sha256"] = sha
        subject_refs.append(s_ref)
        s.edge(run_ref, s_ref, "produces", "attestation")

    raw_materials = predicate.get("materials") or predicate.get("resolvedDependencies") or []
    materials = (
        [m for m in raw_materials if isinstance(m, dict)] if isinstance(raw_materials, list) else []
    )
    for mat in materials:
        uri = _clean(mat.get("uri") or mat.get("name") or "dataset")
        raw_mdig = mat.get("digest")
        d_map: dict[str, Any] = raw_mdig if isinstance(raw_mdig, dict) else {}
        sha = d_map.get("sha256")
        digest_str = f"sha256:{sha}" if isinstance(sha, str) and len(sha) == 64 else None
        if str(mat.get("kind") or "dataset").lower() == "base_model":
            base_ref = f"model:{uri}"
            s.model(base_ref, uri, "foundation")
            for s_ref in subject_refs:
                s.edge(s_ref, base_ref, "fine-tuned-from", "attestation")
                base_models.setdefault(s_ref, set()).add(uri)
        else:
            ds_ref = f"dataset:{uri}"
            s.dataset(ds_ref, uri, uri, digest_str)
            s.edge(run_ref, ds_ref, "trained-on", "attestation")
            for s_ref in subject_refs:
                s.edge(s_ref, ds_ref, "trained-on", "attestation")
            ds_revs.setdefault(uri, set()).add(digest_str if digest_str else "<unpinned>")


def _process_cr4_claim(
    claim: dict[str, Any],
    s: ProvenanceSummary,
    ds_revs: dict[str, set[str]],
    base_models: dict[str, set[str]],
) -> None:
    loc = _clean(claim.get("file") or "claim:CR-4")
    ds_name, rev = claim.get("dataset"), claim.get("revision")
    if isinstance(ds_name, str) and ds_name.strip():
        rev_str = str(rev).strip() if isinstance(rev, str) else ""
        _record_dataset_usage(s, ds_name, rev_str, loc, ds_revs)
    target_model = claim.get("target_model") or claim.get("model")
    if isinstance(target_model, str) and target_model.strip():
        _record_finetune_pair(s, target_model, claim.get("base_model"), loc, base_models)


def inspect_provenance_surfaces(
    *,
    inventory_path: Path | None = None,
    project_root: Path | None = None,
    claim_paths: tuple[Path, ...] = (),
    attestation_paths: tuple[Path, ...] = (),
    fail_on: str = "high",
) -> tuple[dict[str, Any], AIBOM]:
    """Run offline provenance inspection over a project, inventory, claims, and attestations."""
    bom = AIBOM.load(inventory_path) if inventory_path is not None else AIBOM()
    claims = _load_external_json_list(claim_paths)
    attestations = _load_external_json_list(attestation_paths)
    summary = ProvenanceSummary(bom=bom)
    failures: list[str] = []
    exclusions: list[str] = []

    root_to_open = project_root if project_root is not None else Path(".")
    with ConfinedCollection(root_to_open, failures, exclusions) as files:
        rel_paths = [p.as_posix() for p in files.iter_files()] if project_root is not None else []
        yaml_files: list[tuple[str, dict[str, Any], bytes]] = []
        for rel_str in rel_paths:
            if PurePosixPath(rel_str).name.lower().endswith((".yaml", ".yml")):
                loaded = _safe_read_yaml(files, rel_str, summary)
                if loaded is not None:
                    yaml_files.append((rel_str, loaded[0], loaded[1]))
        _inspect_model_forensics(files, rel_paths, claims, summary)
        _inspect_aliases_and_registries(files, rel_paths, yaml_files, claims, summary)
        _inspect_guardrails_memory_and_pii(yaml_files, claims, summary)
        _inspect_training_lineage(files, rel_paths, yaml_files, claims, attestations, summary)

    for fail_msg in failures:
        summary.unread_gaps.append(_clean(fail_msg))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    reasons: list[str] = []
    if fail_on != "none":
        cutoff = severity_order[fail_on]
        triggered = [f for f in summary.findings if severity_order.get(f.severity, 99) <= cutoff]
        if triggered:
            reasons.append(f"{len(triggered)} finding(s) at or above {fail_on} severity")
        if failures:
            reasons.append(f"{len(failures)} confined collection failure(s)")

    document: dict[str, Any] = {
        "format": FORMAT,
        "findings": [f.to_dict() for f in summary.findings],
        "pickle_inspections": summary.pickle_inspections,
        "gguf_inspections": summary.gguf_inspections,
        "alias_routes": summary.alias_routes,
        "registry_references": summary.registry_references,
        "guardrails": summary.guardrails,
        "memory_stores": summary.memory_stores,
        "lineage_edges": summary.lineage_edges,
        "dvc_verifications": summary.dvc_verifications,
        "unread_gaps": summary.unread_gaps,
        "gate": {"fail_on": fail_on, "passed": len(reasons) == 0, "reasons": reasons},
    }
    return document, bom
