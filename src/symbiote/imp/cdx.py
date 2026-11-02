"""CycloneDX 1.5-1.7 importer (``spec/companion.md §6``).

``import_cyclonedx`` validates the raw JSON against the vendored official schema for its ``specVersion``
(1.6 and 1.7; a 1.5 document is checked structurally because that schema is not vendored, and the loss
report says so), detects the dialect (Symbiote-native, k8s-aibom, cdxgen, agent-harness-aibom or generic),
inverts the Symbiote projection exactly, runs the dialect adapter for foreign vocabularies, preserves every
unmapped property verbatim (``foreign`` / ``foreign_properties`` with ``agentbom:import:dialect`` and
``agentbom:import:source-digest``), and re-finalises the result with a fresh Merkle commitment.

Imported facts are ``declared`` unless the document carries evidence that maps to a higher level
(``spec/agentbom-profile.md §5`` for the k8s-aibom confidence tiers); ``verified`` is never reconstructed
from a projection that cannot carry its constraint record (I3).
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from symbiote.export.cdx.validate import validate_cyclonedx
from symbiote.imp._common import DOCUMENT_ELEMENT, ImportContext, properties_of, source_digest
from symbiote.imp.dialects import DIALECTS, detect_dialect_from_names
from symbiote.imp.k8s_aibom import K8sAibomError, extract_bom_document
from symbiote.imp.native import DialectAdapter, Draft, invert
from symbiote.model import enums as E
from symbiote.model.document import AgentBOM, Derived
from symbiote.model.entities import CycloneDXLink, Links, LossReport, Redaction
from symbiote.model.ids import snapshot_id
from symbiote.model.snapshot import ObservationWindow, Snapshot
from symbiote.snapshot.commit import PLACEHOLDER_DIGEST, finalize

#: Dialect name used for documents produced by Symbiote itself.
NATIVE = "symbiote"
SUPPORTED_SPEC_VERSIONS = ("1.5", "1.6", "1.7")
_VALIDATED_SPEC_VERSIONS = ("1.6", "1.7")
_FORMAT_ALIASES = {"cdx": None, "cyclonedx": None, "auto": None, "symbiote": NATIVE, "generic": "generic"}
#: Dialects handled by a dedicated pipeline that yields a complete snapshot (no adapter into the core).
SHADOWSCAN = "shadowscan"
_URN_UUID_RE = re.compile(r"^urn:uuid:([0-9a-fA-F-]{36})$")


class CycloneDXImportError(ValueError):
    """The input is not a CycloneDX document this importer accepts (schema or structure)."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("; ".join(errors[:5]) + (f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""))


# ------------------------------------------------------------------------------------------------ detection


def _all_property_names(doc: Mapping[str, Any]) -> tuple[set[str], set[str]]:
    """``(metadata property names, element property names)`` across the whole document."""
    md = doc.get("metadata") if isinstance(doc.get("metadata"), Mapping) else {}
    meta_names = {n for n, _ in properties_of(md)}
    names: set[str] = set()

    def walk(comp: Any) -> None:
        if not isinstance(comp, Mapping):
            return
        names.update(n for n, _ in properties_of(comp))
        for nested in comp.get("components") or []:
            walk(nested)

    walk(md.get("component"))
    for c in doc.get("components") or []:
        walk(c)
    for s in doc.get("services") or []:
        walk(s)
    for v in doc.get("vulnerabilities") or []:
        walk(v)
    return meta_names, names


def detect_dialect(doc: Mapping[str, Any]) -> str:
    """``symbiote`` | ``k8s-aibom`` | ``cdxgen`` | ``harness-aibom`` | ``generic`` for a CycloneDX document."""
    if str(doc.get("apiVersion", "")).startswith("aibom.k8saibom.dev/") and doc.get("kind") == "AIBOM":
        return "k8s-aibom"
    from symbiote.shadowscan.report import detect_cyclonedx

    if detect_cyclonedx(doc):
        return SHADOWSCAN
    meta_names, names = _all_property_names(doc)
    if "agentbom:spec-version" in meta_names:
        return NATIVE
    dialect = detect_dialect_from_names(meta_names | names)
    if dialect is not None:
        return dialect
    if any(n.startswith("agentbom:") for n in meta_names | names):
        return NATIVE
    return "generic"


# ------------------------------------------------------------------------------------------------ validation


def _validate(doc: Mapping[str, Any], ctx: ImportContext, spec_version: str) -> None:
    if spec_version in _VALIDATED_SPEC_VERSIONS:
        errors = validate_cyclonedx(dict(doc), spec_version)
        if errors:
            raise CycloneDXImportError(errors)
        return
    # 1.5: no vendored schema — structural checks only, recorded as a loss item (never silent)
    errors = []
    if doc.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must be CycloneDX")
    for key in ("components", "services", "dependencies", "vulnerabilities"):
        if key in doc and not isinstance(doc[key], list):
            errors.append(f"{key} must be an array")
    if "metadata" in doc and not isinstance(doc["metadata"], Mapping):
        errors.append("metadata must be an object")
    for key in ("components", "services"):
        for i, item in enumerate(doc.get(key) or []):
            if not isinstance(item, Mapping):
                errors.append(f"{key}[{i}] must be an object")
            elif key == "components" and not item.get("type"):
                errors.append(f"components[{i}].type is required")
    if errors:
        raise CycloneDXImportError(errors)
    ctx.lose(
        "/specVersion",
        E.LossReason.UNSUPPORTED_IN_TARGET_VERSION,
        E.LossPreservedIn.DROPPED,
        field_name="schema-validation",
    )
    ctx.warnings.append("CycloneDX 1.5 schema is not vendored: structural validation only")


# ------------------------------------------------------------------------------------------------ assembly


def assemble(
    draft: Draft,
    ctx: ImportContext,
    *,
    as_kind: E.SnapshotKind | None,
    default_kind: E.SnapshotKind,
    nonce: bytes | None,
    links: Links,
    direction: str,
) -> tuple[AgentBOM, LossReport]:
    """Turn a :class:`Draft` into a finalised :class:`AgentBOM` plus its import loss report."""
    if draft.subject is None or draft.producer is None:
        raise CycloneDXImportError(["document has no describable root component"])
    kind = as_kind or draft.kind or default_kind
    produced_at = draft.produced_at or ctx.now
    window = draft.window
    if window is None and draft.coverage.window is not None:
        window = ObservationWindow(start=draft.coverage.window.start, end=draft.coverage.window.end)
    if window is None and kind is E.SnapshotKind.OBSERVED:
        window = ObservationWindow(start=produced_at, end=produced_at)
        ctx.lose("/snapshot/observationWindow", E.LossReason.PRECISION_LOST, E.LossPreservedIn.DROPPED)
    if as_kind is not None and draft.kind is not None and as_kind is not draft.kind:
        ctx.warnings.append(
            f"document declares snapshot kind {draft.kind.value}; imported as {as_kind.value}"
        )
    snapshot = Snapshot(
        id=snapshot_id(draft.serial, PLACEHOLDER_DIGEST),
        kind=kind,
        digest=PLACEHOLDER_DIGEST,
        serial=draft.serial,
        agent_ref=draft.subject,
        deployment_ref=draft.deployment_ref,
        validity=draft.validity,
        produced_at=produced_at,
        observation_window=window,
    )
    redactions = list(draft.redactions)
    if ctx.redacted_values:
        redactions.append(
            Redaction(
                redaction_class=E.RedactionClass.CREDENTIAL_SHAPED_TOKEN.value,
                count=ctx.redacted_values,
                applied_by="symbiote-import",
                applied_at=ctx.now,
            )
        )
    coverage = draft.coverage.replace(
        collectors=draft.collector_runs, text_included=bool(draft.text_included)
    )
    # ``agentbom:import:*`` is recorded on the document (spec/companion.md §6)
    ctx.foreign_property(DOCUMENT_ELEMENT, "agentbom:import:dialect", ctx.dialect)
    ctx.foreign_property(DOCUMENT_ELEMENT, "agentbom:import:source-digest", ctx.source_digest)
    bom = AgentBOM(
        snapshot=snapshot,
        subject=draft.subject,
        producer=draft.producer,
        edges=draft.edges,
        coverage=coverage,
        derived=Derived(flags=draft.flags),
        redactions=redactions,
        redacted=draft.redacted,
        links=links,
        foreign_properties=sorted(ctx.foreign, key=lambda f: (f.element_id, f.name, f.value)),
        **draft.entities,
    )
    bom = finalize(bom, nonce=nonce, prev=draft.prev, validity=draft.validity, observation_window=window)
    report = LossReport(
        direction=direction,
        source_format=ctx.source_format,
        target_format="agentbom-model",
        model_digest=bom.snapshot.digest,
        items=sorted(ctx.losses, key=lambda i: (i.path, i.reason.value, i.field or "")),
    )
    bom = bom.replace(loss_report=report)
    return bom, report


def _cdx_links(doc: Mapping[str, Any], ctx: ImportContext) -> Links:
    serial = doc.get("serialNumber")
    version = doc.get("version") if isinstance(doc.get("version"), int) else 1
    if not isinstance(serial, str) or not serial:
        return Links()
    m = _URN_UUID_RE.match(serial)
    bom_link = f"urn:cdx:{uuid.UUID(m.group(1))}/{version}" if m else f"urn:cdx:{serial}/{version}"
    return Links(
        cyclonedx=CycloneDXLink(
            serial_number=serial, version=version, bom_link=bom_link, digest=ctx.source_digest
        )
    )


# ------------------------------------------------------------------------------------------------ shadowscan


def _import_shadowscan(
    document: Mapping[str, Any],
    *,
    as_kind: E.SnapshotKind | None,
    nonce: bytes | None,
    now: datetime | None,
) -> tuple[AgentBOM, LossReport]:
    """ShadowScan's CycloneDX output is a scan report: ``symbiote.shadowscan`` maps it to an observed snapshot."""
    from symbiote.shadowscan.mapping import import_report
    from symbiote.shadowscan.report import ReportError, load_report

    try:
        report = load_report(document, source_digest=source_digest(document))
        bom = import_report(report, now=now, nonce=nonce)
    except (ReportError, ValueError) as exc:
        raise CycloneDXImportError([f"shadowscan: {exc}"]) from exc
    if as_kind is not None and as_kind is not bom.snapshot.kind:
        bom = finalize(
            bom.replace(snapshot=bom.snapshot.replace(kind=as_kind)),
            nonce=nonce,
            observation_window=bom.snapshot.observation_window,
        )
    loss = bom.loss_report or LossReport(
        direction="shadowscan→model",
        source_format="shadowscan-cyclonedx",
        target_format="agentbom-model",
        model_digest=bom.snapshot.digest,
    )
    loss = loss.replace(model_digest=bom.snapshot.digest)
    return bom.replace(loss_report=loss), loss


# ------------------------------------------------------------------------------------------------ public API


def import_cyclonedx(
    doc: Mapping[str, Any],
    *,
    as_kind: E.SnapshotKind | None = None,
    dialect: str | None = None,
    nonce: bytes | None = None,
    now: datetime | None = None,
    source_digest_value: str | None = None,
    validate: bool = True,
) -> tuple[AgentBOM, LossReport]:
    """Import a CycloneDX 1.5-1.7 JSON document (or a k8s-aibom ``AIBOM`` custom resource).

    ``as_kind`` overrides the snapshot kind; when omitted a Symbiote-native document keeps the kind it
    declares, a k8s-aibom document becomes ``deployed`` and every other document ``declared``. ``dialect``
    forces an adapter (``k8s-aibom`` | ``cdxgen`` | ``harness-aibom`` | ``symbiote`` | ``generic``); the
    aliases ``cdx`` / ``cyclonedx`` / ``auto`` mean *detect*. Returns the re-finalised document and the
    ``cdx→model`` loss report (also attached as ``bom.loss_report``).
    """
    if not isinstance(doc, Mapping):
        raise CycloneDXImportError(["input is not a JSON object"])
    if str(doc.get("apiVersion", "")).startswith("aibom.k8saibom.dev/"):
        try:
            document, _ = extract_bom_document(doc)
        except K8sAibomError as exc:
            raise CycloneDXImportError([str(exc)]) from exc
        dialect = dialect or "k8s-aibom"
    else:
        document = doc
    if document.get("bomFormat") != "CycloneDX":
        raise CycloneDXImportError(["bomFormat must be CycloneDX"])
    spec_version = str(document.get("specVersion", ""))
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise CycloneDXImportError(
            [f"unsupported specVersion {spec_version!r} (expected one of {SUPPORTED_SPEC_VERSIONS})"]
        )
    requested = dialect.lower() if dialect else None
    if requested in _FORMAT_ALIASES:
        requested = _FORMAT_ALIASES[requested]
    chosen = requested or detect_dialect(document)
    if chosen == SHADOWSCAN:
        return _import_shadowscan(document, as_kind=as_kind, nonce=nonce, now=now)
    if chosen not in DIALECTS and chosen not in (NATIVE, "generic"):
        raise CycloneDXImportError([f"unknown dialect {chosen!r}"])
    ctx = ImportContext(
        dialect=chosen,
        source_format=f"cyclonedx-{spec_version}",
        source_digest=source_digest_value or source_digest(doc),
        now=now or datetime.now(UTC),
    )
    if validate:
        _validate(document, ctx, spec_version)
    adapter: DialectAdapter | None = DIALECTS[chosen]() if chosen in DIALECTS else None
    draft = invert(document, ctx, native=chosen == NATIVE, adapter=adapter)
    default_kind = adapter.default_kind if adapter is not None else E.SnapshotKind.DECLARED
    return assemble(
        draft,
        ctx,
        as_kind=as_kind,
        default_kind=default_kind,
        nonce=nonce,
        links=_cdx_links(document, ctx),
        direction="cdx→model",
    )


__all__ = [
    "NATIVE",
    "SHADOWSCAN",
    "SUPPORTED_SPEC_VERSIONS",
    "CycloneDXImportError",
    "assemble",
    "detect_dialect",
    "import_cyclonedx",
]
