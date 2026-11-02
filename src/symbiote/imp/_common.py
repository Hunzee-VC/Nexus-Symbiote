"""Shared importer plumbing: property bags, claim inversion, loss collection, id minting.

Every importer in :mod:`symbiote.imp` works on CycloneDX-shaped property lists (``[{name, value}]``) —
the SPDX importer first turns ``CdxPropertiesExtension`` entries back into that shape — so the inversion of
the exporter's property grammar (``spec/taxonomy.md``) lives here once.

Assurance rules enforced here (``spec/companion.md §6``, invariant I3): an imported claim keeps the
assurance the document states, except that ``verified`` is downgraded to ``observed`` whenever the document
cannot carry the verified-constrained evidence record the model requires; the downgrade is recorded as the
fact ``imported-verified-without-constraint`` (an entity tag) and as a security-relevant loss item.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, TypeVar

from symbiote.digest.envelope import digest_str
from symbiote.digest.jcs import UndigestableError, canonical_bytes
from symbiote.model import enums as E
from symbiote.model.common import Claim, EvidenceRef, Provenance, looks_like_secret
from symbiote.model.entities import ForeignProperty, LossItem
from symbiote.model.ids import make_id, slugify

#: Fact recorded (as an entity tag) whenever a ``verified`` assurance had to be downgraded on import.
VERIFIED_WITHOUT_CONSTRAINT = "imported-verified-without-constraint"

#: ``element_id`` used for document-level (``metadata.properties``) foreign properties.
DOCUMENT_ELEMENT = "metadata"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_ENTITY_ID_RE = re.compile(r"^[a-z][a-z0-9-]*:[A-Za-z0-9._~/@+-]+$")
_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)

T = TypeVar("T")


# ------------------------------------------------------------------------------------------ scalar parsing


def source_digest(doc: Mapping[str, Any]) -> str:
    """``sha256:`` digest of the imported document (RFC 8785 canonical form; plain sorted JSON as fallback)."""
    try:
        return digest_str(canonical_bytes(doc))
    except UndigestableError:
        return digest_str(json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8"))


def as_digest(value: Any) -> str | None:
    """Normalise ``sha256:<hex>`` / bare 64-hex / ``SHA-256:<hex>`` renderings to the model's digest string."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if _DIGEST_RE.match(v):
        return v
    if _HEX64_RE.match(v):
        return "sha256:" + v.lower()
    if ":" in v:
        alg, _, hexpart = v.partition(":")
        if alg.lower().replace("-", "") == "sha256" and _HEX64_RE.match(hexpart):
            return "sha256:" + hexpart.lower()
    return None


def hashes_sha256(obj: Mapping[str, Any]) -> str | None:
    """The first SHA-256 entry of a CycloneDX ``hashes[]`` list, as ``sha256:<hex>``."""
    for h in obj.get("hashes", []) or []:
        if isinstance(h, Mapping) and str(h.get("alg", "")).upper() in ("SHA-256", "SHA256"):
            d = as_digest(str(h.get("content", "")))
            if d:
                return d
    return None


def all_hashes_sha256(obj: Mapping[str, Any]) -> list[str]:
    out = []
    for h in obj.get("hashes", []) or []:
        if isinstance(h, Mapping) and str(h.get("alg", "")).upper() in ("SHA-256", "SHA256"):
            d = as_digest(str(h.get("content", "")))
            if d:
                out.append(d)
    return out


def parse_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes", "1"):
            return True
        if v in ("false", "no", "0"):
            return False
    return None


def parse_tristate(value: Any) -> E.TriState | None:
    if isinstance(value, str) and value.strip().lower() in ("true", "false", "unknown"):
        return E.TriState(value.strip().lower())
    b = parse_bool(value)
    return None if b is None else (E.TriState.TRUE if b else E.TriState.FALSE)


def parse_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def parse_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def parse_time(value: Any) -> datetime | None:
    """RFC 3339 text → aware UTC datetime (``None`` when unparsable)."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def parse_json(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except ValueError:
        return None


def enum_or_none(enum_cls: type[T], value: Any) -> T | None:
    """``enum_cls(value)`` when ``value`` is a member value, else ``None`` (never raises)."""
    if value is None:
        return None
    try:
        return enum_cls(value)  # type: ignore[call-arg]
    except ValueError:
        return None


def is_url(value: str | None) -> bool:
    return bool(value) and bool(_URL_RE.match(value or ""))


def valid_entity_id(value: str) -> bool:
    return bool(_ENTITY_ID_RE.match(value)) and 3 <= len(value) <= 512


def properties_of(obj: Mapping[str, Any] | None) -> list[tuple[str, str]]:
    """``[(name, value)]`` of a CycloneDX element's ``properties`` (non-string values are stringified)."""
    if not obj:
        return []
    out: list[tuple[str, str]] = []
    for p in obj.get("properties", []) or []:
        if isinstance(p, Mapping) and p.get("name") is not None:
            value = p.get("value", "")
            out.append((str(p["name"]), value if isinstance(value, str) else json.dumps(value)))
    return out


# ------------------------------------------------------------------------------------------ property bag


class PropertyBag:
    """Ordered multi-map of properties that remembers which entries the mapping consumed.

    Whatever is left unconsumed after an element has been mapped is foreign and is preserved verbatim.
    Sub-bags produced by :meth:`indexed` share the parent's consumption state.
    """

    def __init__(
        self,
        items: Iterable[tuple[str, str]] | None = None,
        *,
        _entries: list[tuple[int, str, str]] | None = None,
        _consumed: set[int] | None = None,
    ) -> None:
        if _entries is not None:
            self._entries = _entries
        else:
            self._entries = [(i, n, v) for i, (n, v) in enumerate(items or [])]
        self._consumed: set[int] = _consumed if _consumed is not None else set()

    def __len__(self) -> int:
        return len(self._entries)

    def __bool__(self) -> bool:
        return bool(self._entries)

    def names(self) -> set[str]:
        return {n for _, n, _ in self._entries}

    def has(self, name: str) -> bool:
        return any(n == name for _, n, _ in self._entries)

    def peek(self, name: str) -> str | None:
        for _, n, v in self._entries:
            if n == name:
                return v
        return None

    def get(self, name: str) -> str | None:
        """First value for ``name`` (every occurrence is marked consumed)."""
        found: str | None = None
        for idx, n, v in self._entries:
            if n == name:
                self._consumed.add(idx)
                if found is None:
                    found = v
        return found

    def get_all(self, name: str) -> list[str]:
        out = []
        for idx, n, v in self._entries:
            if n == name:
                self._consumed.add(idx)
                out.append(v)
        return out

    def first(self, *names: str) -> str | None:
        """First value among several alternative names (compat aliases)."""
        for name in names:
            v = self.get(name)
            if v is not None:
                return v
        return None

    def consume_prefix(self, prefix: str) -> list[tuple[str, str]]:
        out = []
        for idx, n, v in self._entries:
            if n.startswith(prefix):
                self._consumed.add(idx)
                out.append((n, v))
        return out

    def drop(self, name: str) -> None:
        """Mark ``name`` consumed without reading it (derived or redundant facts)."""
        for idx, n, _ in self._entries:
            if n == name:
                self._consumed.add(idx)

    def indexed(self, prefix: str, *, detach: bool = False) -> dict[int, PropertyBag]:
        """Group ``<prefix>:<i>:<rest>`` entries by ``i`` into sub-bags keyed by ``rest``.

        Sub-bags share the parent's consumption state, unless ``detach`` is set: then the grouped entries are
        consumed in the parent right away (they belong to the sub-record) and each sub-bag tracks its own
        leftovers, so they can be read later without the parent reporting them as foreign.
        """
        groups: dict[int, list[tuple[int, str, str]]] = {}
        p = prefix + ":"
        for idx, n, v in self._entries:
            if n.startswith(p):
                head, sep, tail = n[len(p) :].partition(":")
                if sep and head.isdigit():
                    groups.setdefault(int(head), []).append((idx, tail, v))
        if detach:
            for entries in groups.values():
                self._consumed.update(idx for idx, _, _ in entries)
            return {
                i: PropertyBag(_entries=entries, _consumed=set()) for i, entries in sorted(groups.items())
            }
        return {
            i: PropertyBag(_entries=entries, _consumed=self._consumed)
            for i, entries in sorted(groups.items())
        }

    def remaining(self) -> list[tuple[str, str]]:
        return [(n, v) for idx, n, v in self._entries if idx not in self._consumed]

    def with_prefix(self, prefix: str) -> list[tuple[str, str]]:
        return [(n, v) for _, n, v in self._entries if n.startswith(prefix)]


# ------------------------------------------------------------------------------------------ import context


@dataclass
class ImportContext:
    """Mutable state shared by every mapping step of one import."""

    dialect: str
    source_format: str
    source_digest: str
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    losses: list[LossItem] = field(default_factory=list)
    foreign: list[ForeignProperty] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    facts: list[str] = field(default_factory=list)
    redacted_values: int = 0
    _loss_keys: set[tuple[Any, ...]] = field(default_factory=set)
    _foreign_keys: set[tuple[str, str, str]] = field(default_factory=set)

    def lose(
        self,
        path: str,
        reason: E.LossReason,
        preserved: E.LossPreservedIn,
        severity: E.LossSeverity = E.LossSeverity.INFO,
        *,
        entity: str | None = None,
        field_name: str | None = None,
    ) -> None:
        key = (path, reason, preserved, severity, entity, field_name)
        if key in self._loss_keys:
            return
        self._loss_keys.add(key)
        self.losses.append(
            LossItem(
                path=path,
                entity=entity,
                field=field_name,
                reason=reason,
                preserved_in=preserved,
                severity=severity,
            )
        )

    def sanitize(self, value: str, *, count: bool = True) -> str:
        """Verbatim passthrough never carries credential material: secret-shaped values are replaced."""
        if looks_like_secret(value):
            if count:
                self.redacted_values += 1
            return "[redacted:credential-shaped-token]"
        return value

    def foreign_property(self, element_id: str, name: str, value: str, *, dialect: str | None = None) -> None:
        value = self.sanitize(value)
        key = (element_id, name, value)
        if key in self._foreign_keys:
            return
        self._foreign_keys.add(key)
        self.foreign.append(
            ForeignProperty(dialect=dialect or self.dialect, element_id=element_id, name=name, value=value)
        )

    def unforeign(self, element_id: str, names: set[str]) -> None:
        """Forget foreign properties an adapter mapped after the generic pass had preserved them."""
        self.foreign = [f for f in self.foreign if not (f.element_id == element_id and f.name in names)]
        self._foreign_keys = {k for k in self._foreign_keys if not (k[0] == element_id and k[1] in names)}

    def preserve_remaining(self, element_id: str, bag: PropertyBag, *, path: str) -> dict[str, str]:
        """Record every unconsumed property as foreign; return the per-entity ``foreign`` dict.

        The entity dict keeps the first value per name (so a re-export emits it on the element); every
        occurrence is kept in the document-level ``foreign_properties`` list. A repeated name is reported
        as ``cardinality-collapsed`` on the entity (never silently).
        """
        entity_foreign: dict[str, str] = {}
        collapsed = False
        for name, value in bag.remaining():
            self.foreign_property(element_id, name, value)
            if name in entity_foreign:
                collapsed = True
            else:
                entity_foreign[name] = self.sanitize(value, count=False)
        if entity_foreign:
            self.lose(
                path,
                E.LossReason.FOREIGN_UNMAPPED,
                E.LossPreservedIn.PROPERTY,
                entity=element_id,
                field_name="foreign",
            )
        if collapsed:
            self.lose(
                path,
                E.LossReason.CARDINALITY_COLLAPSED,
                E.LossPreservedIn.COMPANION,
                entity=element_id,
                field_name="foreign",
            )
        return entity_foreign


# ------------------------------------------------------------------------------------------ claims & provenance


def assurance_from(
    raw: str | None, ctx: ImportContext, *, path: str, entity: str | None, facts: list[str]
) -> E.AssuranceLevel:
    """Map an imported assurance word; ``verified`` cannot be reconstructed from a projection (I3)."""
    level = enum_or_none(E.AssuranceLevel, raw) if raw else None
    if level is None:
        return E.AssuranceLevel.DECLARED
    if level is E.AssuranceLevel.VERIFIED:
        if VERIFIED_WITHOUT_CONSTRAINT not in facts:
            facts.append(VERIFIED_WITHOUT_CONSTRAINT)
        ctx.lose(
            path,
            E.LossReason.ENUM_NARROWED,
            E.LossPreservedIn.DROPPED,
            E.LossSeverity.SECURITY_RELEVANT,
            entity=entity,
            field_name="assurance",
        )
        return E.AssuranceLevel.OBSERVED
    return level


def claim_from(
    bag: PropertyBag,
    name: str,
    parse: Callable[[str], T | None],
    ctx: ImportContext,
    *,
    path: str,
    entity: str | None,
    facts: list[str],
    required: bool = False,
    values: list[str] | None = None,
) -> Claim[T] | None:
    """Invert ``Props.claim()``: ``<name>``, ``<name>:assurance``, ``<name>:locator``, ``<name>:unknown-reason``.

    ``values`` lets callers pass a pre-read (possibly repeated) raw value; ``parse`` turns raw text into the
    claim value. A ``required`` claim that the document lacks becomes an explicit ``unknown`` (I2), never a
    guessed value.
    """
    raw = bag.get(name) if values is None else (values[0] if values else None)
    assurance = bag.get(f"{name}:assurance")
    locator = bag.get(f"{name}:locator")
    unknown = bag.get(f"{name}:unknown-reason")
    if raw is None and unknown is None:
        if assurance is None and locator is None and not required:
            return None
        return Claim.unknown(E.UnknownReason.NOT_COLLECTED, locator=locator)
    if raw is None:
        reason = enum_or_none(E.UnknownReason, unknown) or E.UnknownReason.NOT_COLLECTED
        return Claim.unknown(reason, locator=locator)
    value = parse(raw)
    if value is None:
        ctx.lose(
            f"{path}/{name}",
            E.LossReason.ENUM_NARROWED,
            E.LossPreservedIn.DROPPED,
            entity=entity,
            field_name=name,
        )
        ctx.warnings.append(f"{entity or path}: unparsable value {raw!r} for {name}")
        return Claim.unknown(E.UnknownReason.UNSUPPORTED_SOURCE, locator=locator) if required else None
    level = assurance_from(assurance, ctx, path=f"{path}/{name}", entity=entity, facts=facts)
    return Claim(value=value, assurance=level, locator=locator)


def provenance_from(
    bag: PropertyBag, ctx: ImportContext, *, path: str, entity: str, facts: list[str]
) -> Provenance:
    """Invert ``Props.provenance()`` (``agentbom:assurance``, ``agentbom:evidence:*``)."""
    level = assurance_from(bag.get("agentbom:assurance"), ctx, path=path, entity=entity, facts=facts)
    locator = bag.get("agentbom:evidence:locator")
    collector_raw = bag.get("agentbom:evidence:collector")
    collector = None
    if collector_raw:
        candidate = collector_raw if collector_raw.startswith("collector:") else f"collector:{collector_raw}"
        if re.match(r"^collector:[a-z0-9][a-z0-9._-]*@[A-Za-z0-9._+-]+$", candidate):
            collector = candidate
        else:
            ctx.warnings.append(f"{entity}: collector reference {collector_raw!r} is not <name>@<version>")
    source = bag.get("agentbom:evidence:source")
    method = enum_or_none(E.ClaimMethod, source) if source else None
    if source and method is None:
        # a dialect evidence source (e.g. k8s-aibom "pod-spec") is a fact about the source, keep it foreign
        ctx.foreign_property(entity, "agentbom:evidence:source", source)
    observed_at = parse_time(bag.get("agentbom:evidence:collected-at"))
    evidence = [
        EvidenceRef(digest=d) for d in (as_digest(v) for v in bag.get_all("agentbom:evidence:ref")) if d
    ]
    return Provenance(
        assurance=level,
        method=method,
        evidence=evidence,
        locator=locator,
        collector=collector,
        observed_at=observed_at,
    )


# ------------------------------------------------------------------------------------------ ids


def ensure_id(prefix: str, candidate: str | None, *fallback_parts: str, taken: set[str] | None = None) -> str:
    """A collection-conformant entity id: keep ``candidate`` when it already is one, else mint from the parts.

    A foreign bom-ref (``pkg:pypi/x@1``, ``workload:prod/x``) is never slugified into the id; the element's
    own name (the fallback parts) is, exactly as the collectors mint ids. Callers keep the bom-ref → id map.
    """
    if candidate and candidate.startswith(prefix + ":") and valid_entity_id(candidate):
        eid = candidate
    else:
        parts = [p for p in fallback_parts if p] or ([candidate] if candidate else [prefix])
        eid = make_id(prefix, *parts)
    if taken is not None:
        base = eid
        n = 2
        while eid in taken:
            eid = f"{base}-{n}"
            n += 1
        taken.add(eid)
    return eid


def software_id(purl: str | None, name: str | None, version: str | None, bom_ref: str | None) -> str:
    """``sw:<purl-or-slug>`` (``spec/agentbom-profile.md §1.1``)."""
    if bom_ref and bom_ref.startswith("sw:") and valid_entity_id(bom_ref):
        return bom_ref
    if purl:
        body = purl[4:] if purl.startswith("pkg:") else purl
        body = body.split("?", 1)[0].split("#", 1)[0]
        candidate = f"sw:{body}"
        if valid_entity_id(candidate):
            return candidate
        return make_id("sw", body)
    label = "/".join(p for p in (name, version) if p) or bom_ref or "component"
    return make_id("sw", label)


def slug(value: str) -> str:
    return slugify(value)


__all__ = [
    "DOCUMENT_ELEMENT",
    "VERIFIED_WITHOUT_CONSTRAINT",
    "ImportContext",
    "PropertyBag",
    "all_hashes_sha256",
    "as_digest",
    "assurance_from",
    "claim_from",
    "ensure_id",
    "enum_or_none",
    "hashes_sha256",
    "is_url",
    "parse_bool",
    "parse_float",
    "parse_int",
    "parse_json",
    "parse_time",
    "parse_tristate",
    "properties_of",
    "provenance_from",
    "slug",
    "software_id",
    "source_digest",
    "valid_entity_id",
]
