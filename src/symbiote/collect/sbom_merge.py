"""``sbom-merge`` collector: the software layer from CycloneDX SBOMs (``spec/collectors.md``).

Inputs: ``ctx.options["sbom"]`` (one path or a list; relative paths resolve against the scan root) or, when no
SBOM is given, ``bom.json``, ``sbom.json`` and ``*.cdx.json`` at the repository root and in ``sbom/``. Only
CycloneDX JSON 1.4-1.7 is accepted; anything else (SPDX, other formats, other versions) is recorded as an
``unsupported-source`` coverage fact. When no SBOM exists the code surface stays ``not-attempted``: a missing
SBOM is never reported as "no software components" (I2).

Each document is validated **once** against the vendored CycloneDX schema for its ``specVersion`` (when one is
vendored); schema errors are warnings and the document is still imported. Validation is bounded so a large
SBOM cannot exhaust the collector budget: ``uniqueItems`` and string ``enum`` checks run in linear time, and
only the first :data:`MAX_SCHEMA_COMPONENTS` components / :data:`MAX_SCHEMA_DEPENDENCIES` dependency entries
are schema-checked (a warning says so). Auxiliary schemas the bom schema references but that are not vendored
(``cryptography-defs.schema.json`` for 1.7) are replaced by permissive stubs, with a warning when the document
uses the constructs they define.

Every component (nested ones included) becomes a ``SoftwareComponent`` keyed by purl (else
``[group/]name[@version]``) and de-duplicated by id, keeping the component JSON verbatim minus its nested
``components`` - except that credential-shaped strings are replaced by ``<redacted>`` (recorded as a
redaction) and integers JCS cannot represent are stringified. Edges: the scanned agent ``dependsOn`` the
components the SBOM's own subject depends on (``metadata.component`` in ``dependencies``), or every top-level
component when there is no such entry; ``dependencies[]`` become component-to-component ``dependsOn`` edges.
Components carrying cdxgen AI/MCP/agent properties are tagged ``cdxgen-ai-component``.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any, Final
from urllib.parse import quote, unquote, urljoin

from jsonschema import Draft7Validator, ValidationError, validators
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT7

from symbiote.collect._common import REDACTED, json_pointer, locator, read_bounded
from symbiote.collect.base import BaseCollector, CollectContext, CollectionResult
from symbiote.digest import bytes_digest
from symbiote.digest.jcs import parse_json_strict
from symbiote.model.common import EvidenceRef, Provenance, looks_like_secret
from symbiote.model.edges import Edge
from symbiote.model.entities import Evidence, Redaction, SoftwareComponent
from symbiote.model.enums import (
    ClaimMethod,
    CollectorMode,
    EdgeScope,
    EdgeType,
    EvidenceKind,
    Surface,
)
from symbiote.model.ids import evidence_id, make_id

__all__ = [
    "AI_PROPERTY_PREFIXES",
    "MAX_SCHEMA_COMPONENTS",
    "MAX_SCHEMA_DEPENDENCIES",
    "SUPPORTED_SPEC_VERSIONS",
    "SbomMergeCollector",
    "auto_detected_sboms",
    "sbom_dialect",
    "schema_warnings",
]

SUPPORTED_SPEC_VERSIONS: Final = frozenset({"1.4", "1.5", "1.6", "1.7"})
AUTO_DETECT_NAMES: Final = frozenset({"bom.json", "sbom.json", "bom.cdx.json", "sbom.cdx.json"})
AUTO_DETECT_SUFFIX: Final = ".cdx.json"
AUTO_DETECT_DIRS: Final = (".", "sbom")
#: cdxgen AI-BOM property namespaces (``spec/taxonomy.md``: ``cdx:mcp:*``, ``cdx:ai:*``, ``cdx:agent:*`` ...).
AI_PROPERTY_PREFIXES: Final = ("cdx:mcp:", "cdx:mcpb:", "cdx:ai:", "cdx:agent:", "cdx:agentic:", "cdx:gguf:")
AI_COMPONENT_TAG: Final = "cdxgen-ai-component"
REDACTED_TAG: Final = "redacted:credential-shaped-token"
STRINGIFIED_TAG: Final = "cyclonedx-number-stringified"
CYCLONEDX_MEDIA_TYPE: Final = "application/vnd.cyclonedx+json"
MAX_SCHEMA_COMPONENTS: Final = 2000
MAX_SCHEMA_DEPENDENCIES: Final = 5_000
MAX_SCHEMA_WARNINGS: Final = 10
#: Stop collecting schema errors after this many (the warning reports the cap).
_MAX_SCHEMA_ERRORS: Final = 200
_MAX_MESSAGE_CHARS: Final = 200

_SOURCE: Final = "cyclonedx-sbom"
_SCHEMA_DIR: Final = "schemas/vendor/cyclonedx"
_AUX_SCHEMAS: Final = ("spdx.schema.json", "jsf-0.82.schema.json", "cryptography-defs.schema.json")
#: Raw-document marker of the constructs an auxiliary schema defines (warn only when a stub was relevant).
_STUB_MARKERS: Final[dict[str, bytes]] = {"cryptography-defs.schema.json": b'"cryptoProperties"'}
#: Producer names recognised in ``metadata.tools`` (``spec/taxonomy.md`` ``agentbom:import:dialect``).
_DIALECTS: Final = ("cdxgen", "syft", "harness-aibom", "k8s-aibom", "brox")
_SHA256_HEX: Final = re.compile(r"^[0-9a-fA-F]{64}$")
#: A run of 16+ digits in a component's JSON may be an integer JCS cannot represent (2**53 has 16 digits).
_LONG_DIGITS: Final = re.compile(r"\d{16,}")
_SHA256_ALGS: Final = frozenset({"SHA-256", "SHA256"})
#: JCS (RFC 8785) cannot represent integers of this magnitude exactly.
_MAX_SAFE_INT: Final = 2**53


# --------------------------------------------------------------------------------------------- schema validation

_STOCK_ENUM: Final = Draft7Validator.VALIDATORS["enum"]
#: ``enum`` lists of the cached schemas -> their string members (schemas live for the process lifetime).
_ENUM_SETS: dict[int, frozenset[str]] = {}


def _fast_enum(validator: Any, enums: Any, instance: Any, schema: Any) -> Iterator[ValidationError]:
    """``enum`` with O(1) membership for strings (the SPDX licence list has ~700 members)."""
    if isinstance(instance, str) and isinstance(enums, list):
        allowed = _ENUM_SETS.get(id(enums))
        if allowed is None:
            allowed = _ENUM_SETS[id(enums)] = frozenset(e for e in enums if isinstance(e, str))
        if instance not in allowed:
            yield ValidationError(f"value is not one of the {len(enums)} allowed values")
        return
    yield from _STOCK_ENUM(validator, enums, instance, schema)


def _fast_unique(validator: Any, unique: Any, instance: Any, schema: Any) -> Iterator[ValidationError]:
    """``uniqueItems`` in O(n) via canonical JSON keys (the stock check is quadratic for objects).

    Numbers compare by their JSON text, so ``1`` and ``1.0`` count as distinct here (a documented deviation).
    """
    del validator, schema
    if not unique or not isinstance(instance, list):
        return
    seen: set[str] = set()
    for item in instance:
        key = json.dumps(item, sort_keys=True, separators=(",", ":"))
        if key in seen:
            yield ValidationError("array has non-unique elements")
            return
        seen.add(key)


_LinearDraft7Validator: Final = validators.extend(
    Draft7Validator, {"enum": _fast_enum, "uniqueItems": _fast_unique}
)


@dataclass(frozen=True, slots=True)
class _SchemaBundle:
    validator: Any
    stubbed: tuple[str, ...]


def _vendored(name: str) -> dict[str, Any] | None:
    try:
        text = resources.files("symbiote").joinpath(f"{_SCHEMA_DIR}/{name}").read_text(encoding="utf-8")
        data = json.loads(text)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):  # pragma: no cover - vendored files are JSON objects
        return None
    # without "$schema" every subschema keeps the extended validator class (jsonschema re-selects the class
    # from "$schema" when it descends into another resource)
    data.pop("$schema", None)
    return data


def _external_refs(schema: object) -> dict[str, set[str]]:
    """Definitions referenced in other files: ``{"file.json": {"definitionName", ...}}``."""
    found: dict[str, set[str]] = {}
    stack = [schema]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#"):
                name, _, fragment = ref.partition("#")
                parts = fragment.split("/")
                defs = found.setdefault(name, set())
                if len(parts) >= 3 and parts[1] == "definitions":
                    defs.add(parts[2])
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return found


@cache
def _schema_bundle(spec_version: str) -> _SchemaBundle | None:
    """Validator for one CycloneDX version with the vendored auxiliary schemas registered (built once)."""
    bom = _vendored(f"bom-{spec_version}.schema.json")
    if bom is None:
        return None
    base = str(bom.get("$id") or f"http://cyclonedx.org/schema/bom-{spec_version}.schema.json")
    pairs: list[tuple[str, Resource[Any]]] = []
    present: set[str] = set()
    for name in _AUX_SCHEMAS:
        aux = _vendored(name)
        if aux is not None:
            pairs.append((urljoin(base, name), Resource.from_contents(aux, default_specification=DRAFT7)))
            present.add(name)
    stubbed: list[str] = []
    for name, definitions in sorted(_external_refs(bom).items()):
        if name in present:
            continue
        stub: dict[str, Any] = {"definitions": {d: {} for d in sorted(definitions)}}
        pairs.append((urljoin(base, name), Resource.from_contents(stub, default_specification=DRAFT7)))
        stubbed.append(name)
    registry: Registry[Any] = Registry().with_resources(pairs)
    return _SchemaBundle(_LinearDraft7Validator(bom, registry=registry), tuple(stubbed))


def _subtree_size(component: object, limit: int) -> int:
    """Components in ``component``'s subtree, counting no further than ``limit + 1``."""
    count = 0
    stack = [component]
    while stack and count <= limit:
        node = stack.pop()
        count += 1
        children = node.get("components") if isinstance(node, Mapping) else None
        if isinstance(children, list):
            stack.extend(children)
    return count


def _validation_sample(doc: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """The document with ``components``/``dependencies`` capped for schema validation, and what was capped."""
    sample = dict(doc)
    notes: list[str] = []
    components = doc.get("components")
    if isinstance(components, list):
        budget = MAX_SCHEMA_COMPONENTS
        kept = 0
        for component in components:
            size = _subtree_size(component, budget)
            if size > budget:
                break
            budget -= size
            kept += 1
        if kept < len(components):
            sample["components"] = components[:kept]
            notes.append(f"{kept} of {len(components)} top-level components")
    dependencies = doc.get("dependencies")
    if isinstance(dependencies, list) and len(dependencies) > MAX_SCHEMA_DEPENDENCIES:
        sample["dependencies"] = dependencies[:MAX_SCHEMA_DEPENDENCIES]
        notes.append(f"{MAX_SCHEMA_DEPENDENCIES} of {len(dependencies)} dependency entries")
    return sample, notes


def _error_text(error: ValidationError) -> str:
    """Path and rule only: jsonschema messages embed ``repr(instance)``, whose escapes defeat secret checks."""
    where = json_pointer(*error.absolute_path) or "/"
    expected = error.validator_value if isinstance(error.validator_value, (str, int, bool)) else None
    detail = f" (expected {expected!r})" if expected is not None and len(str(expected)) <= 64 else ""
    return f"{where}: violates '{error.validator}'{detail}"


def schema_warnings(doc: Mapping[str, Any], spec_version: str, raw: bytes) -> list[str]:
    """Validate ``doc`` once against the vendored schema; returns warnings (empty when valid)."""
    bundle = _schema_bundle(spec_version)
    if bundle is None:
        return [f"no vendored CycloneDX {spec_version} schema; schema validation skipped"]
    sample, capped = _validation_sample(doc)
    warnings = [f"schema validation covered only {', '.join(capped)}"] if capped else []
    warnings.extend(
        f"{name} is not vendored; its definitions were not schema-checked"
        for name in bundle.stubbed
        if _STUB_MARKERS.get(name, b"\x00") in raw
    )
    errors = 0
    try:
        for error in bundle.validator.iter_errors(sample):
            errors += 1
            if errors <= MAX_SCHEMA_WARNINGS:
                warnings.append(f"schema: {_error_text(error)}")
            if errors >= _MAX_SCHEMA_ERRORS:
                break
    except Unresolvable as exc:  # pragma: no cover - every external reference is vendored or stubbed
        warnings.append(f"schema validation incomplete: unresolvable reference {exc.__class__.__name__}")
    except RecursionError:
        warnings.append("schema validation incomplete: the document nests too deeply to validate")
    if errors > MAX_SCHEMA_WARNINGS:
        more = f"{errors - MAX_SCHEMA_WARNINGS}{'+' if errors >= _MAX_SCHEMA_ERRORS else ''}"
        warnings.append(f"schema: {more} more errors not shown")
    return warnings


# --------------------------------------------------------------------------------------------- import helpers


def auto_detected_sboms(root: Path) -> list[Path]:
    """CycloneDX SBOM candidates at the repository root and in ``sbom/`` (symlinks are not followed)."""
    found: list[Path] = []
    for rel in AUTO_DETECT_DIRS:
        directory = root / rel
        if directory.is_symlink():  # a symlinked sbom/ can point outside the scanned root
            continue
        try:
            entries = sorted(directory.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        found.extend(
            entry
            for entry in entries
            if (entry.name in AUTO_DETECT_NAMES or entry.name.endswith(AUTO_DETECT_SUFFIX))
            and entry.is_file()
            and not entry.is_symlink()
        )
    return found


def _option_paths(ctx: CollectContext) -> list[Path] | None:
    raw = ctx.options.get("sbom")
    if not raw:
        return None
    items: Sequence[object] = raw if isinstance(raw, (list, tuple)) else [raw]
    paths: dict[Path, None] = {}
    for item in items:
        if isinstance(item, (str, os.PathLike)) and str(item):
            path = Path(item)
            paths.setdefault(path if path.is_absolute() else ctx.root / path, None)
    return list(paths)


def _dig(data: object, *path: str) -> object:
    for key in path:
        if not isinstance(data, Mapping):
            return None
        data = data.get(key)
    return data


def sbom_dialect(doc: Mapping[str, Any]) -> str:
    """Producer dialect from ``metadata.tools`` (1.4 list or 1.5+ ``{components, services}``), else ``generic``."""
    tools = _dig(doc, "metadata", "tools")
    entries: list[object] = []
    if isinstance(tools, list):
        entries = tools
    elif isinstance(tools, Mapping):
        for key in ("components", "services"):
            listed = tools.get(key)
            entries.extend(listed if isinstance(listed, list) else [])
    names = " ".join(
        f"{e.get('vendor', '')} {e.get('group', '')} {e.get('name', '')}".lower()
        for e in entries
        if isinstance(e, Mapping)
    )
    return next((d for d in _DIALECTS if d in names), "generic")


def _unsupported(doc: object) -> str | None:
    if not isinstance(doc, Mapping):
        return "not a JSON object"
    if doc.get("bomFormat") != "CycloneDX":
        if "spdxVersion" in doc or "@context" in doc:
            return "SPDX documents are not merged (CycloneDX JSON only)"
        return "not a CycloneDX document (bomFormat)"
    spec = doc.get("specVersion")
    if not isinstance(spec, str) or spec not in SUPPORTED_SPEC_VERSIONS:
        return "unsupported CycloneDX specVersion (1.4-1.7 are merged)"
    return None


def _iter_components(doc: Mapping[str, Any]) -> Iterator[tuple[Mapping[str, Any], str, bool]]:
    """Every component object in document order with its JSON pointer and whether it is top-level."""
    top = doc.get("components")
    stack: list[tuple[object, str, bool]] = (
        [(c, f"/components/{i}", True) for i, c in reversed(list(enumerate(top)))]
        if isinstance(top, list)
        else []
    )
    while stack:
        component, pointer, is_top = stack.pop()
        if not isinstance(component, Mapping):
            yield {}, pointer, is_top  # counted as skipped (no purl, no name) instead of vanishing silently
            continue
        yield component, pointer, is_top
        children = component.get("components")
        if isinstance(children, list):
            stack.extend(
                (child, f"{pointer}/components/{i}", False)
                for i, child in reversed(list(enumerate(children)))
            )


_URL_USERINFO: Final = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,15}://)[^/\s@?#]{1,256}@")
_PURL_URL_QUALIFIERS: Final = frozenset({"repository_url", "download_url", "vcs_url"})
_OWN_NAMESPACES: Final = ("agentbom:", "symbiote:")


def _strip_userinfo(text: str) -> tuple[str, int]:
    """Drop ``user:password@`` from every URL in ``text``; returns the text and how many were removed."""
    return _URL_USERINFO.subn(r"\1", text)


def _clean_purl(purl: str) -> tuple[str, int]:
    """Remove credentials from URL-valued purl qualifiers (plain or percent-encoded)."""
    head, sep, query = purl.partition("?")
    if not sep:
        return purl, 0
    query, sep2, subpath = query.partition("#")
    removed = 0
    parts: list[str] = []
    for item in query.split("&"):
        key, eq, value = item.partition("=")
        if eq and key in _PURL_URL_QUALIFIERS:
            decoded = unquote(value)
            cleaned, n = _strip_userinfo(decoded)
            if n:
                removed += n
                value = quote(cleaned, safe=":/")
        parts.append(f"{key}{eq}{value}")
    return head + "?" + "&".join(parts) + (sep2 + subpath if sep2 else ""), removed


@dataclass(slots=True)
class _Sanitizer:
    """Iterative deep copy that withholds credential-shaped strings and stringifies unsafe integers."""

    check_secrets: bool
    redacted: int = 0
    stringified: int = 0

    def scalar(self, value: Any) -> Any:
        if self.check_secrets and isinstance(value, str) and looks_like_secret(value):
            self.redacted += 1
            return REDACTED
        if isinstance(value, str) and "@" in value and "://" in unquote(value):
            if value.startswith("pkg:"):
                value, removed = _clean_purl(value)
            else:
                value, removed = _strip_userinfo(value)
            self.redacted += removed
        if isinstance(value, int) and not isinstance(value, bool) and abs(value) >= _MAX_SAFE_INT:
            self.stringified += 1
            return str(value)
        return value

    def key(self, key: str, target: dict[str, Any]) -> str:
        if not (self.check_secrets and looks_like_secret(key)):
            return key
        self.redacted += 1
        candidate, n = REDACTED, 1
        while candidate in target:
            n += 1
            candidate = f"{REDACTED}-{n}"
        return candidate

    def copy(self, source: Mapping[str, Any]) -> dict[str, Any]:
        root: dict[str, Any] = {}
        stack: list[tuple[Any, Any]] = [(source, root)]
        while stack:
            src, dst = stack.pop()
            items = src.items() if isinstance(src, Mapping) else enumerate(src)
            for k, child in items:
                if isinstance(child, (Mapping, list)):
                    new: Any = {} if isinstance(child, Mapping) else []
                    stack.append((child, new))
                else:
                    new = self.scalar(child)
                if isinstance(dst, dict):
                    dst[self.key(str(k), dst)] = new
                else:
                    dst.append(new)
        return root


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() and value != REDACTED else None


def _sha256_hashes(component: Mapping[str, Any]) -> list[str]:
    hashes = component.get("hashes")
    out: set[str] = set()
    for entry in hashes if isinstance(hashes, list) else []:
        if not isinstance(entry, Mapping):
            continue
        alg = str(entry.get("alg", "")).strip().upper().replace("_", "-")
        content = entry.get("content")
        if alg in _SHA256_ALGS and isinstance(content, str) and _SHA256_HEX.match(content.strip()):
            out.add("sha256:" + content.strip().lower())
    return sorted(out)


def _take_own_properties(component: dict[str, Any]) -> dict[str, str]:
    """Move ``agentbom:*``/``symbiote:*`` properties out of an imported component (no trust laundering).

    An imported SBOM cannot assert SymBiote's own facts (``agentbom:assurance=verified``); those properties are
    kept as ``imported:<name>`` provenance instead of being re-exported verbatim as if SymBiote made them.
    """
    props = component.get("properties")
    if not isinstance(props, list):
        return {}
    keep: list[Any] = []
    moved: dict[str, str] = {}
    for prop in props:
        name = prop.get("name") if isinstance(prop, dict) else None
        if isinstance(name, str) and name.startswith(_OWN_NAMESPACES):
            moved[f"imported:{name}"] = str(prop.get("value", ""))[:1024]
        else:
            keep.append(prop)
    if moved:
        component["properties"] = keep
    return moved


def _ai_families(component: Mapping[str, Any]) -> list[str]:
    props = component.get("properties")
    families = {
        str(p["name"]).split(":", 2)[1]
        for p in (props if isinstance(props, list) else [])
        if isinstance(p, Mapping)
        and isinstance(p.get("name"), str)
        and p["name"].startswith(AI_PROPERTY_PREFIXES)
    }
    return sorted(families)


# --------------------------------------------------------------------------------------------- collector


@dataclass(slots=True)
class _MergeState:
    """State shared across every SBOM merged in one run."""

    keys_by_id: dict[str, str] = field(default_factory=dict)
    emitted: set[str] = field(default_factory=set)
    purls: dict[str, str] = field(default_factory=dict)
    edges: set[tuple[str, str]] = field(default_factory=set)
    evidence: set[str] = field(default_factory=set)
    redacted: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class _Document:
    """One SBOM being merged."""

    display: str
    digest: str
    dialect: str
    evidence: EvidenceRef
    ref_ids: dict[str, str] = field(default_factory=dict)
    top_level: list[tuple[str, str]] = field(default_factory=list)
    examined: int = 0
    skipped: int = 0


class SbomMergeCollector(BaseCollector):
    """Software components and their dependency graph from CycloneDX SBOMs (cdxgen, syft, ...)."""

    name = "sbom-merge"
    version = "0.1.0"
    surfaces = (Surface.CODE,)
    mode = CollectorMode.DECLARED

    def detect(self, ctx: CollectContext) -> bool:
        return bool(ctx.options.get("sbom")) or bool(auto_detected_sboms(ctx.root))

    def collect(self, ctx: CollectContext) -> CollectionResult:
        result = self.new_result()
        explicit = _option_paths(ctx)
        paths = explicit if explicit is not None else auto_detected_sboms(ctx.root)
        if not paths:
            # no source: the code surface stays not-attempted (unknown), never "no components" (I2)
            result.warnings.append(
                "no CycloneDX SBOM given (--sbom) or found (bom.json, sbom.json, *.cdx.json at the root or in "
                "sbom/); software layer not collected"
            )
            return result
        state = _MergeState()
        for path in paths:
            marks = (len(result.entities), len(result.edges), len(result.evidence))
            try:
                self._merge_file(ctx, result, path, state)
            except (RecursionError, ValueError, TypeError) as exc:
                del result.entities[marks[0] :], result.edges[marks[1] :], result.evidence[marks[2] :]
                display = ctx.display(path)
                result.add_source(
                    Surface.CODE, _SOURCE, locator=display, ok=False, error_class="unsupported-source"
                )
                result.warnings.append(
                    f"{display}: SBOM rejected ({type(exc).__name__}); other SBOMs unaffected"
                )
        if state.redacted:
            result.redactions.append(
                Redaction(
                    redaction_class="credential-shaped-token",
                    count=sum(state.redacted.values()),
                    applied_by=self.ref,
                    applied_at=ctx.now,
                    ids=sorted(state.redacted),
                )
            )
        return result

    def _merge_file(
        self, ctx: CollectContext, result: CollectionResult, path: Path, state: _MergeState
    ) -> None:
        display = ctx.display(path)
        # Discovered SBOMs are confined to the scan root; an operator-supplied --sbom path may live elsewhere.
        inside = path.is_relative_to(ctx.root)
        outcome = ctx.read_config(path) if inside else read_bounded(path, ctx.max_file_bytes)
        if not outcome.ok or outcome.data is None:
            result.add_source(
                Surface.CODE, _SOURCE, locator=display, ok=False, error_class=outcome.error_class
            )
            return
        try:
            doc = parse_json_strict(outcome.data.decode("utf-8-sig"))
        except (ValueError, RecursionError) as exc:  # invalid UTF-8/JSON, duplicate keys, NaN, nesting
            result.add_source(Surface.CODE, _SOURCE, locator=display, ok=False, error_class="parse-error")
            result.warnings.append(f"{display}: not valid JSON ({type(exc).__name__})")
            return
        problem = _unsupported(doc)
        if problem is not None:
            result.add_source(
                Surface.CODE, _SOURCE, locator=display, ok=False, error_class="unsupported-source"
            )
            result.warnings.append(f"{display}: {problem}")
            return
        result.warnings.extend(
            f"{display}: {w}" for w in schema_warnings(doc, doc["specVersion"], outcome.data)
        )
        digest = bytes_digest(outcome.data)
        if digest not in state.evidence:
            state.evidence.add(digest)
            result.evidence.append(
                Evidence(
                    id=evidence_id(digest),
                    evidence_kind=EvidenceKind.SCAN_REPORT,
                    media_type=CYCLONEDX_MEDIA_TYPE,
                    digest=digest,
                    uri=display,
                    created=ctx.now,
                    provenance=Provenance(
                        method=ClaimMethod.MANIFEST, locator=display, collector=self.ref, observed_at=ctx.now
                    ),
                )
            )
        sbom = _Document(
            display=display,
            digest=digest,
            dialect=sbom_dialect(doc),
            evidence=EvidenceRef(digest=digest, media_type=CYCLONEDX_MEDIA_TYPE, uri=display),
        )
        for component, pointer, is_top in _iter_components(doc):
            self._component(ctx, result, sbom, state, component, pointer=pointer, is_top=is_top)
        self._edges(ctx, result, sbom, state, doc)
        if not isinstance(doc.get("components", []), list):
            sbom.skipped += 1
            result.warnings.append(f"{display}: 'components' is not a list; nothing under it was imported")
        if sbom.skipped:
            result.warnings.append(f"{display}: {sbom.skipped} components without purl or name were skipped")
        # a document whose components could not all be imported is partial coverage, not a complete inventory
        result.add_source(
            Surface.CODE,
            _SOURCE,
            locator=display,
            ok=not sbom.skipped,
            error_class="invalid-components" if sbom.skipped else None,
            items=sbom.examined,
        )

    def _component(
        self,
        ctx: CollectContext,
        result: CollectionResult,
        sbom: _Document,
        state: _MergeState,
        component: Mapping[str, Any],
        *,
        pointer: str,
        is_top: bool,
    ) -> None:
        sbom.examined += 1
        shallow = {k: v for k, v in component.items() if k != "components"}
        # every raw string is checked: a check on a JSON dump misses tokens after an escaped newline or tab
        sanitizer = _Sanitizer(check_secrets=True)
        clean = sanitizer.copy(shallow)
        imported = _take_own_properties(clean)
        name, version, purl, group = (_text(clean.get(k)) for k in ("name", "version", "purl", "group"))
        if purl is None and name is None:
            sbom.skipped += 1
            return
        key = purl or f"{group + '/' if group else ''}{name}{'@' + version if version else ''}"
        comp_id = make_id("sw", key)
        if state.keys_by_id.setdefault(comp_id, key) != key:  # slug collision between distinct components
            comp_id = make_id("sw", key, collision_seed=key)
            state.keys_by_id.setdefault(comp_id, key)
        bom_ref = component.get("bom-ref")
        if isinstance(bom_ref, str):
            sbom.ref_ids.setdefault(bom_ref, comp_id)
        if is_top:
            sbom.top_level.append((comp_id, pointer))
        if comp_id in state.emitted:
            return
        state.emitted.add(comp_id)
        if purl:
            state.purls[comp_id] = purl
        families = _ai_families(clean)
        tags = [AI_COMPONENT_TAG, *(f"cdxgen:{f}" for f in families)] if families else []
        if sanitizer.redacted:
            tags.append(REDACTED_TAG)
            state.redacted[comp_id] = sanitizer.redacted
        if sanitizer.stringified:
            tags.append(STRINGIFIED_TAG)
        if imported:
            tags.append("imported-agentbom-properties")  # the SBOM's own claims, kept apart from SymBiote's
        result.entities.append(
            SoftwareComponent(
                id=comp_id,
                name=name,
                provenance=Provenance(
                    method=ClaimMethod.MANIFEST,
                    evidence=[sbom.evidence],
                    locator=f"{sbom.display}#{pointer}",
                    collector=self.ref,
                    observed_at=ctx.now,
                ),
                tags=tags,
                foreign={
                    "agentbom:import:dialect": sbom.dialect,
                    "agentbom:import:source-digest": sbom.digest,
                    **imported,
                },
                purl=purl,
                version=version,
                component_type=_text(clean.get("type")) or "library",
                hashes=_sha256_hashes(clean),
                cyclonedx=clean,
            )
        )

    def _edge(
        self, result: CollectionResult, state: _MergeState, src: str, dst: str, declared_by: str
    ) -> None:
        if src == dst or (src, dst) in state.edges:
            return
        state.edges.add((src, dst))
        purl = state.purls.get(dst)
        result.edges.append(
            Edge.model_validate(
                {
                    "type": EdgeType.DEPENDS_ON,
                    "from": src,
                    "to": dst,
                    "scope": EdgeScope.RUNTIME,
                    "qualifiers": {"purl": purl} if purl else {},
                    "declaredBy": declared_by,
                }
            )
        )

    def _edges(
        self,
        ctx: CollectContext,
        result: CollectionResult,
        sbom: _Document,
        state: _MergeState,
        doc: Mapping[str, Any],
    ) -> None:
        deps = doc.get("dependencies")
        graph = [
            (i, d["ref"], [r for r in d.get("dependsOn") or [] if isinstance(r, str)])
            for i, d in enumerate(deps if isinstance(deps, list) else [])
            if isinstance(d, Mapping)
            and isinstance(d.get("ref"), str)
            and isinstance(d.get("dependsOn") or [], list)
        ]
        subject = _dig(doc, "metadata", "component", "bom-ref")
        root = next(((i, targets) for i, ref, targets in graph if ref == subject), None) if subject else None
        if root is not None:
            index, targets = root
            where = locator(sbom.display, "dependencies", index)
            for target in targets:
                if target in sbom.ref_ids:
                    self._edge(result, state, ctx.agent_id, sbom.ref_ids[target], where)
        else:
            for comp_id, pointer in sbom.top_level:
                self._edge(result, state, ctx.agent_id, comp_id, f"{sbom.display}#{pointer}")
        dangling = 0
        for index, ref, targets in graph:
            if ref == subject:
                continue
            src = sbom.ref_ids.get(ref)
            where = locator(sbom.display, "dependencies", index)
            for target in targets:
                dst = sbom.ref_ids.get(target)
                if src is None or dst is None:
                    dangling += 1
                    continue
                self._edge(result, state, src, dst, where)
        if dangling:
            result.warnings.append(f"{sbom.display}: {dangling} dependency references name unknown bom-refs")
