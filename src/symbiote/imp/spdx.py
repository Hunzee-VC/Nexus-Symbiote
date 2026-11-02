"""SPDX 3.0.1 JSON-LD importer (``spec/spdx-mapping.md``, ``spec/companion.md §6``).

The document is decoded with ``spdx_python_model``'s ``JSONLDDeserializer``. Symbiote's typed extensions
are recognised by IRI (``https://aisecnomad.github.io/symbiote/spdx/0.1/terms/<Class>``), and every
``extension_CdxPropertiesExtension`` entry is turned back into a CycloneDX property so the same inversion as
the CycloneDX importer (:mod:`symbiote.imp.native`) applies. Relationships become edges (the
``EdgeQualifiers`` extension names the exact edge type; the native relationship type is the fallback), and
``NoneElement`` / ``NoAssertionElement`` targets become coverage statuses: verified absence is ``queried``,
unknown keeps the failure class the ``EdgeQualifiers`` carry (``spec/spdx-mapping.md §3``).
"""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from spdx_python_model.bindings import v3_0_1 as m

from symbiote.export.spdx.emit import NOASSERTION_ELEMENT, NONE_ELEMENT, TERMS
from symbiote.export.spdx.validate import validate_spdx
from symbiote.imp._common import (
    ImportContext,
    as_digest,
    enum_or_none,
    parse_time,
    source_digest,
    valid_entity_id,
)
from symbiote.imp.cdx import assemble
from symbiote.imp.native import Draft, invert
from symbiote.model import enums as E
from symbiote.model.document import AgentBOM
from symbiote.model.entities import (
    Agent,
    CredentialBinding,
    CredentialStorage,
    Evidence,
    Identity,
    Links,
    LossReport,
    SpdxLink,
    SurfaceCoverage,
)
from symbiote.model.enums import EdgeType
from symbiote.model.ids import make_id

_SBOM_KIND = {
    "design": E.SnapshotKind.DECLARED,
    "build": E.SnapshotKind.APPROVED,
    "deployed": E.SnapshotKind.DEPLOYED,
    "runtime": E.SnapshotKind.OBSERVED,
}
_PURPOSE_TO_CDX_TYPE = {
    "application": "application",
    "model": "machine-learning-model",
    "specification": "data",
    "module": "library",
    "configuration": "data",
    "data": "data",
    "library": "library",
    "framework": "framework",
    "container": "container",
    "file": "file",
    "source": "file",
    "evidence": "file",
    "other": "library",
}
_TLP_TO_CLASSIFICATION = {
    "clear": "public",
    "green": "internal",
    "amber": "confidential",
    "red": "restricted",
}
_REVERSED_RELATIONS = {"configures", "modifiedBy"}
_VEX_STATUS_BY_RELATION = {
    "doesNotAffect": "not-affected",
    "affects": "affected",
    "underInvestigationFor": "under-investigation",
    "fixedIn": "fixed",
}
_VEX_STATE = {
    "affected": "exploitable",
    "not-affected": "not_affected",
    "under-investigation": "in_triage",
    "fixed": "resolved",
}
_TOOL_SUMMARY_RE = re.compile(
    r"^(?P<name>\S+) (?P<version>\S+)(?: \((?P<mode>declared|observed) collector\))?$"
)
_COLLECTOR_STATUS_RE = re.compile(r"^(?P<name>[^@]+)@(?P<version>[^:]+):(?P<status>[a-z]+)$")


class SpdxImportError(ValueError):
    """The input is not an SPDX 3.0.1 JSON-LD document this importer accepts."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("; ".join(errors[:5]) + (f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""))


# ------------------------------------------------------------------------------------------------ decoding helpers


def _suffix(iri: Any) -> str | None:
    if iri is None:
        return None
    if not isinstance(iri, str):
        iri = getattr(iri, "spdxId", None) or getattr(iri, "_id", None) or str(iri)
    return str(iri).rstrip("/").rsplit("/", 1)[-1]


def _scalar(value: Any) -> Any:
    if isinstance(value, list):
        if len(value) == 1:
            return _scalar(value[0])
        return [_scalar(v) for v in value]
    return value


def _ext_data(ext: Any) -> dict[str, Any]:
    data = getattr(ext, "_ext_data", None) or {}
    return {
        k[len(TERMS) :] if k.startswith(TERMS) else k.rsplit("/", 1)[-1]: _scalar(v) for k, v in data.items()
    }


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class _Element:
    """A decoded SPDX element with the bits the inversion needs."""

    def __init__(self, obj: Any, ns: str) -> None:
        self.obj = obj
        self.iri: str = getattr(obj, "spdxId", None) or getattr(obj, "_id", "") or ""
        self.ref = self.iri[len(ns) :] if self.iri.startswith(ns) else self.iri
        self.cls = type(obj).__name__
        self.name: str | None = getattr(obj, "name", None) or None
        self.props: list[dict[str, str]] = []
        self.exts: dict[str, dict[str, Any]] = {}
        self.ext_list: list[tuple[str, dict[str, Any]]] = []
        for ext in getattr(obj, "extension", None) or []:
            if isinstance(ext, m.extension_CdxPropertiesExtension):
                for entry in ext.extension_cdxProperty or []:
                    name, value = entry.extension_cdxPropName, entry.extension_cdxPropValue
                    if name is not None and value is not None:
                        self.props.append({"name": str(name), "value": str(value)})
            else:
                typ = ext.get_type() if hasattr(ext, "get_type") else type(ext).__name__
                if isinstance(typ, str) and typ.startswith(TERMS):
                    data = _ext_data(ext)
                    self.ext_list.append((typ[len(TERMS) :], data))
                    self.exts.setdefault(typ[len(TERMS) :], data)
        self.hashes: list[str] = []
        for h in getattr(obj, "verifiedUsing", None) or []:
            if _suffix(getattr(h, "algorithm", None)) == "sha256" and getattr(h, "hashValue", None):
                d = as_digest(str(h.hashValue))
                if d:
                    self.hashes.append(d)

    def prop(self, name: str) -> str | None:
        return next((p["value"] for p in self.props if p["name"] == name), None)

    def cdx_hashes(self) -> list[dict[str, str]] | None:
        return [{"alg": "SHA-256", "content": d[len("sha256:") :]} for d in self.hashes] or None

    def external_references(self) -> list[dict[str, Any]] | None:
        refs = []
        for er in getattr(self.obj, "externalRef", None) or []:
            locators = getattr(er, "locator", None) or []
            comment = getattr(er, "comment", None) or ""
            rtype, _, rcomment = comment.partition(": ")
            for loc in locators:
                refs.append(
                    {
                        "type": rtype or _suffix(getattr(er, "externalRefType", None)) or "other",
                        "url": str(loc),
                        **({"comment": rcomment} if rcomment else {}),
                    }
                )
        return refs or None


# ------------------------------------------------------------------------------------------------ pseudo-CycloneDX


class _Decoded:
    """The decoded object set, indexed, plus the pseudo-CycloneDX document built from it."""

    def __init__(self, doc: Mapping[str, Any]) -> None:
        self.objset = m.SHACLObjectSet()
        m.JSONLDDeserializer().deserialize_data(copy.deepcopy(dict(doc)), self.objset)
        objs = list(self.objset.foreach())
        self.sbom = next((o for o in objs if isinstance(o, m.software_Sbom)), None)
        self.document = next((o for o in objs if isinstance(o, m.SpdxDocument)), None)
        self.ns = self._namespace(objs)
        self.elements: dict[str, _Element] = {}
        self.relationships: list[Any] = []
        self.tools: list[Any] = []
        self.creation: Any = None
        for o in objs:
            if isinstance(o, m.Relationship):
                self.relationships.append(o)
            elif isinstance(o, m.Tool):
                self.tools.append(o)
            elif isinstance(o, m.CreationInfo):
                self.creation = self.creation or o
            elif isinstance(o, m.Element) and getattr(o, "spdxId", None):
                el = _Element(o, self.ns)
                self.elements[el.ref] = el

    def _namespace(self, objs: list[Any]) -> str:
        if self.sbom is not None and getattr(self.sbom, "spdxId", "").endswith("/sbom"):
            return self.sbom.spdxId[: -len("sbom")]
        iris = [getattr(o, "spdxId", "") for o in objs if getattr(o, "spdxId", "")]
        if not iris:
            return ""
        prefix = iris[0]
        for iri in iris[1:]:
            while not iri.startswith(prefix) and prefix:
                prefix = prefix[:-1]
        return prefix[: prefix.rfind("/") + 1] if "/" in prefix else prefix

    def ref_of(self, obj_or_iri: Any) -> str | None:
        if obj_or_iri is None:
            return None
        iri = (
            obj_or_iri
            if isinstance(obj_or_iri, str)
            else (getattr(obj_or_iri, "spdxId", None) or getattr(obj_or_iri, "_id", None))
        )
        if not iri:
            return None
        return iri[len(self.ns) :] if iri.startswith(self.ns) else iri

    # ---- element classification

    @staticmethod
    def _skip(ref: str) -> bool:
        return (
            ref.startswith(("producer:", "rel:")) or ref.endswith("/principal") or ref in ("sbom", "document")
        )

    def root_ref(self) -> str | None:
        if self.sbom is not None:
            roots = [self.ref_of(r) for r in (self.sbom.rootElement or [])]
            if roots and roots[0]:
                return roots[0]
        for ref, el in self.elements.items():
            if (
                el.cls == "ai_AIPackage"
                and _suffix(getattr(el.obj, "software_primaryPurpose", None)) == "application"
            ):
                return ref
        return None

    def pseudo_cyclonedx(self) -> tuple[dict[str, Any], dict[str, _Element]]:
        """Build the CycloneDX-shaped intermediate; returns it with the elements that need post-processing."""
        root_ref = self.root_ref()
        components: list[dict[str, Any]] = []
        services: list[dict[str, Any]] = []
        vulnerabilities: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        extras: dict[str, _Element] = {}
        root_component: dict[str, Any] | None = None
        parties = {
            ref: el
            for ref, el in self.elements.items()
            if el.cls in ("Organization", "Person") and "Identity" not in el.exts
        }
        for ref, el in self.elements.items():
            if self._skip(ref):
                continue
            if el.cls in ("SoftwareAgent", "Person", "Organization"):
                if "Identity" in el.exts:
                    extras[ref] = el
                continue
            if el.cls == "security_Vulnerability":
                extras[ref] = el
                continue
            purpose = _suffix(getattr(el.obj, "software_primaryPurpose", None))
            kind_prop = el.prop("agentbom:kind")
            if el.cls == "software_File" and purpose == "evidence":
                if "Evaluation" in el.exts:
                    extras[ref] = el
                    continue
                ev = el.exts.get("Evidence", {})
                evidence.append(
                    {
                        "bom-ref": ref,
                        "propertyName": ev.get("kind") or "other",
                        "description": getattr(el.obj, "description", None),
                        "created": ev.get("created"),
                        "expires": ev.get("expires"),
                        "data": [{"contents": {"url": el.hashes[0] if el.hashes else ev.get("uri")}}],
                    }
                )
                extras[ref] = el
                continue
            is_server = (
                kind_prop in ("mcp-server", "a2a-agent", "openapi-service", "builtin")
                or "ToolServer" in el.exts
            )
            if is_server:
                ts = el.exts.get("ToolServer", {})
                endpoint = ts.get("endpointOrigin") or next(
                    (
                        str(ei.identifier)
                        for ei in getattr(el.obj, "externalIdentifier", None) or []
                        if _suffix(getattr(ei, "externalIdentifierType", None)) == "urlScheme"
                    ),
                    None,
                )
                services.append(
                    _clean(
                        {
                            "bom-ref": ref,
                            "name": el.name or ref.split(":", 1)[-1],
                            "group": ts.get("client"),
                            "description": getattr(el.obj, "description", None),
                            "endpoints": [endpoint] if endpoint else None,
                            "x-trust-boundary": ts.get("crossesTrustBoundary")
                            if isinstance(ts.get("crossesTrustBoundary"), bool)
                            else None,
                            "trustZone": ts.get("trustZone"),
                            "externalReferences": el.external_references(),
                            "properties": el.props or None,
                        }
                    )
                )
                continue
            ctype = _PURPOSE_TO_CDX_TYPE.get(purpose or "", "library")
            if el.cls == "ai_AIPackage":
                ctype = "application" if purpose == "application" else "machine-learning-model"
            elif el.cls == "dataset_DatasetPackage":
                ctype = "data"
            elif el.cls == "software_File":
                ctype = "file"
            comp: dict[str, Any] = {
                "type": ctype,
                "bom-ref": ref,
                "name": el.name or ref.split(":", 1)[-1],
                "version": getattr(el.obj, "software_packageVersion", None),
                "description": getattr(el.obj, "description", None)
                or getattr(el.obj, "ai_informationAboutApplication", None),
                "purl": getattr(el.obj, "software_packageUrl", None),
                "hashes": el.cdx_hashes(),
                "mime-type": getattr(el.obj, "contentType", None) if el.cls == "software_File" else None,
                "externalReferences": el.external_references(),
                "properties": el.props or None,
            }
            supplier = getattr(el.obj, "suppliedBy", None)
            supplier_ref = self.ref_of(supplier)
            if supplier_ref and supplier_ref in parties:
                p = parties[supplier_ref]
                urls = [
                    str(ei.identifier)
                    for ei in getattr(p.obj, "externalIdentifier", None) or []
                    if _suffix(getattr(ei, "externalIdentifierType", None)) == "urlScheme"
                ]
                comp["supplier"] = _clean({"name": p.name, "url": urls or None})
            if kind_prop == "tool" or purpose == "specification":
                comp["type"] = "data"
                comp["data"] = [{"type": "definition", "name": el.name or ref.rsplit("/", 1)[-1]}]
            elif el.cls == "dataset_DatasetPackage":
                tlp = _suffix(getattr(el.obj, "dataset_confidentialityLevel", None))
                dl = getattr(el.obj, "software_downloadLocation", None)
                comp["data"] = [
                    _clean(
                        {
                            "type": "dataset",
                            "name": el.name or ref,
                            "classification": _TLP_TO_CLASSIFICATION.get(tlp or ""),
                            "contents": {"url": dl} if dl and dl != "NOASSERTION" else None,
                        }
                    )
                ]
            elif kind_prop == "policy-bundle":
                comp["type"] = "data"
                comp["data"] = [{"type": "configuration", "name": el.name or ref}]
            elif el.cls == "ai_AIPackage" and purpose == "model":
                comp["isExternal"] = True if el.prop("agentbom:model:kind") == "hosted" else None
                if getattr(el.obj, "ai_domain", None):
                    comp["modelCard"] = {"modelParameters": {"task": str(_as_list(el.obj.ai_domain)[0])}}
            comp = _clean(comp)
            if ref == root_ref:
                root_component = comp
            else:
                components.append(comp)
        # skills: nested script files are ``contains`` targets of the skill package
        pseudo: dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "version": 1,
            "metadata": _clean(
                {
                    "timestamp": self.creation.created.isoformat().replace("+00:00", "Z")
                    if self.creation is not None and self.creation.created
                    else None,
                    "component": root_component,
                    "properties": self.sbom_props(),
                    "tools": {"components": self.tool_components()} if self.tools else None,
                    "lifecycles": self.lifecycles(),
                }
            ),
            "components": components or None,
            "services": services or None,
            "declarations": _clean({"evidence": evidence or None, "claims": self.flag_claims() or None})
            or None,
            "vulnerabilities": vulnerabilities or None,
            "formulation": self.formulation(),
        }
        self.attach_scripts(pseudo)
        return _clean(pseudo), extras

    def attach_scripts(self, pseudo: dict[str, Any]) -> None:
        by_ref = {c["bom-ref"]: c for c in pseudo.get("components") or []}
        for rel in self.relationships:
            rtype = _suffix(getattr(rel, "relationshipType", None))
            src = self.ref_of(getattr(rel, "from_", None))
            if rtype != "contains" or not src or not src.startswith("skill:"):
                continue
            skill = by_ref.get(src)
            if skill is None:
                continue
            for target in rel.to or []:
                tref = self.ref_of(target)
                if not tref or not tref.startswith(f"{src}/"):
                    continue
                script = by_ref.pop(tref, None)
                if script is None:
                    continue
                pseudo["components"] = [c for c in pseudo["components"] if c is not script]
                skill.setdefault("components", []).append(
                    _clean(
                        {
                            "type": "file",
                            "bom-ref": tref,
                            "name": tref[len(src) + 1 :],
                            "hashes": script.get("hashes"),
                            "properties": [{"name": "agentbom:kind", "value": "skill-script"}],
                        }
                    )
                )

    def sbom_props(self) -> list[dict[str, str]] | None:
        if self.sbom is None:
            return None
        el = _Element(self.sbom, self.ns)
        props = list(el.props)
        names = {p["name"] for p in props}
        snap = el.exts.get("Snapshot", {})
        for key, name in (
            ("kind", "agentbom:snapshot:kind"),
            ("serial", "agentbom:snapshot:serial"),
            ("prev", "agentbom:snapshot:prev"),
            ("digest", "agentbom:snapshot:digest"),
            ("merkleRoot", "agentbom:merkle:root"),
            ("merkleLeafCount", "agentbom:merkle:leaf-count"),
            ("notBefore", "agentbom:snapshot:not-before"),
            ("notAfter", "agentbom:snapshot:not-after"),
            ("observationStart", "agentbom:snapshot:observation-start"),
            ("observationEnd", "agentbom:snapshot:observation-end"),
            ("companionDigest", "agentbom:companion:digest"),
            ("companionRef", "agentbom:companion:ref"),
        ):
            if name not in names and snap.get(key) is not None:
                props.append({"name": name, "value": str(snap[key])})
        if "agentbom:spec-version" not in names and (snap or el.props):
            props.append({"name": "agentbom:spec-version", "value": str(snap.get("specVersion") or "0.1")})
        cov = el.exts.get("Coverage", {})
        if cov.get("surfaces") and not any(n.startswith("agentbom:coverage:") for n in names):
            import json

            try:
                surfaces = json.loads(str(cov["surfaces"]))
            except ValueError:
                surfaces = {}
            for surface, status in sorted(surfaces.items()) if isinstance(surfaces, dict) else []:
                props.append({"name": f"agentbom:coverage:{surface}", "value": str(status)})
        return props or None

    def lifecycles(self) -> list[dict[str, str]] | None:
        if self.sbom is None:
            return None
        kinds = [_suffix(t) for t in (self.sbom.software_sbomType or [])]
        kind = next((_SBOM_KIND[k] for k in kinds if k in _SBOM_KIND), None)
        return [{"name": f"agentbom:snapshot:{kind.value}"}] if kind else None

    def tool_components(self) -> list[dict[str, Any]]:
        out = []
        for t in self.tools:
            ref = self.ref_of(t) or ""
            mm = _TOOL_SUMMARY_RE.match(str(getattr(t, "summary", "") or ""))
            name = str(getattr(t, "name", None) or (mm.group("name") if mm else ref))
            version = mm.group("version") if mm else "unknown"
            entry: dict[str, Any] = {"type": "application", "bom-ref": ref, "name": name, "version": version}
            if mm and mm.group("mode"):
                entry["properties"] = [
                    {"name": "agentbom:kind", "value": "collector"},
                    {"name": "symbiote:collector:mode", "value": mm.group("mode")},
                ]
            out.append(entry)
        return out

    def formulation(self) -> list[dict[str, Any]] | None:
        if self.sbom is None:
            return None
        cov = _Element(self.sbom, self.ns).exts.get("Coverage", {})
        tasks = []
        for raw in _as_list(cov.get("collectors")):
            mm = _COLLECTOR_STATUS_RE.match(str(raw))
            if mm:
                tasks.append(
                    {
                        "bom-ref": f"task:collector:{mm.group('name')}",
                        "uid": f"collector:{mm.group('name')}@{mm.group('version')}",
                        "name": mm.group("name"),
                        "taskTypes": ["scan"],
                        "properties": [{"name": "agentbom:coverage:status", "value": mm.group("status")}],
                    }
                )
        if not tasks:
            return None
        return [
            {
                "bom-ref": "formulation:collection",
                "workflows": [
                    {
                        "bom-ref": "workflow:collection",
                        "uid": "collection",
                        "name": "symbiote-collection",
                        "taskTypes": ["scan"],
                        "tasks": tasks,
                    }
                ],
            }
        ]

    def flag_claims(self) -> list[dict[str, Any]]:
        if self.sbom is None:
            return []
        flags = _Element(self.sbom, self.ns).exts.get("DerivedFlags", {})
        out = []
        for raw in _as_list(flags.get("flags")):
            mm = re.match(r"^([a-z0-9-]+)=(true|false|unknown)@(.+)$", str(raw))
            if mm:
                out.append(
                    {
                        "bom-ref": f"claim:flag:{mm.group(1)}:{mm.group(3)}",
                        "target": mm.group(3),
                        "predicate": f"agentbom:flag:{mm.group(1)}={mm.group(2)}",
                    }
                )
        return out


def _clean(obj: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in obj.items() if v is not None and v not in ([], {})}


# ------------------------------------------------------------------------------------------------ SPDX-only enrichment


class _SpdxEnricher:
    """Applies what only the SPDX document carries natively: relationships, None/NoAssertion, identities, VEX."""

    name = "spdx"
    default_kind = E.SnapshotKind.DECLARED

    def __init__(self, decoded: _Decoded, extras: dict[str, _Element]) -> None:
        self.decoded = decoded
        self.extras = extras

    def adapt(self, doc: Mapping[str, Any], ctx: ImportContext, draft: Draft, root: Agent) -> set[str]:
        text_included = (
            _Element(self.decoded.sbom, self.decoded.ns).exts.get("Coverage", {}).get("textIncluded")
            if self.decoded.sbom is not None
            else None
        )
        if isinstance(text_included, bool):
            draft.text_included = text_included
        return set()

    def post(self, doc: Mapping[str, Any], ctx: ImportContext, draft: Draft, root: Agent) -> None:
        d = self.decoded
        self.identities(ctx, draft)
        self.credentials(ctx, draft)
        self.evidence_media_types(draft)
        known = draft.ids()
        surfaces = dict(draft.coverage.surfaces)
        for rel in d.relationships:
            ref = d.ref_of(rel) or ""
            rtype = _suffix(getattr(rel, "relationshipType", None)) or "dependsOn"
            src = draft.map_ref(d.ref_of(getattr(rel, "from_", None)))
            quals = next((data for typ, data in _Element(rel, d.ns).ext_list if typ == "EdgeQualifiers"), {})
            targets = [t if isinstance(t, str) else d.ref_of(t) for t in (rel.to or [])]
            if ref.startswith("rel:surface:"):
                surface = enum_or_none(E.Surface, ref[len("rel:surface:") :])
                if surface is None:
                    continue
                current = surfaces.get(surface, SurfaceCoverage())
                if (
                    current.status is not E.CoverageStatus.NOT_ATTEMPTED
                    and str(current.status.value) != "not-attempted"
                ):
                    continue
                if NONE_ELEMENT in targets:
                    surfaces[surface] = current.replace(status=E.CoverageStatus.QUERIED)
                elif NOASSERTION_ELEMENT in targets:
                    status = (
                        enum_or_none(E.CoverageStatus, quals.get("coverageStatus"))
                        or E.CoverageStatus.NOT_ATTEMPTED
                    )
                    surfaces[surface] = current.replace(status=status)
                continue
            if ref.startswith("rel:vex:") or isinstance(rel, m.security_VulnAssessmentRelationship):
                self.vex(ctx, draft, rel, quals)
                continue
            if src is None or src not in known:
                continue
            edge_type = enum_or_none(EdgeType, quals.get("edgeType")) if quals else None
            if edge_type is None:
                if rtype == "contains" and src.startswith("server:"):
                    edge_type = EdgeType.PROVIDES_TOOL
                elif rtype == "contains" and src.startswith("skill:"):
                    continue  # script files live inside the skill entity
                elif rtype == "invokedBy":
                    continue  # the synthetic principal relationship
                elif rtype in ("dependsOn", "usesTool", "hasEvidence", "descendantOf"):
                    edge_type = {
                        "usesTool": EdgeType.INVOKES_TOOL,
                        "hasEvidence": EdgeType.EVALUATED_BY,
                        "descendantOf": EdgeType.DERIVED_FROM,
                    }.get(rtype, EdgeType.DEPENDS_ON)
                else:
                    continue
            for target in targets:
                if target in (NONE_ELEMENT, NOASSERTION_ELEMENT) or target is None:
                    continue
                dst = draft.map_ref(target)
                if edge_type is EdgeType.HOLDS_CREDENTIAL and ref.startswith("rel:holds-credential:"):
                    dst = ref[len("rel:holds-credential:") :]
                if rtype in _REVERSED_RELATIONS:
                    src, dst = dst, src
                if dst is None or dst not in known or src not in known:
                    continue
                extra: dict[str, Any] = {}
                scope = (
                    _suffix(getattr(rel, "scope", None))
                    if isinstance(rel, m.LifecycleScopedRelationship)
                    else None
                )
                extra["scope"] = enum_or_none(E.EdgeScope, scope) or (
                    E.EdgeScope.RUNTIME if scope else E.EdgeScope.DESIGN
                )
                level = enum_or_none(E.AssuranceLevel, quals.get("assurance"))
                if level is E.AssuranceLevel.VERIFIED:
                    level = E.AssuranceLevel.OBSERVED
                    ctx.lose(
                        f"/edges/{edge_type.value}:{src}->{dst}",
                        E.LossReason.ENUM_NARROWED,
                        E.LossPreservedIn.DROPPED,
                        E.LossSeverity.SECURITY_RELEVANT,
                        field_name="assurance",
                    )
                if level is not None:
                    extra["assurance"] = level
                qualifiers = {
                    k: v
                    for k, v in quals.items()
                    if k not in ("edgeType", "assurance", "nativeRelationship", "surface", "coverageStatus")
                }
                if qualifiers:
                    extra["qualifiers"] = qualifiers
                existing = next((e for e in draft.edges if e.key == (edge_type.value, src, dst)), None)
                if existing is not None:
                    draft.edges.remove(existing)
                    extra.setdefault("qualifiers", existing.qualifiers)
                draft.edges.append(
                    type(existing)(type=edge_type, from_ref=src, to_ref=dst, **extra)
                    if existing is not None
                    else _edge(edge_type, src, dst, extra)
                )
        draft.coverage = draft.coverage.replace(surfaces=surfaces)

    def identities(self, ctx: ImportContext, draft: Draft) -> None:
        for ref, el in self.extras.items():
            ident_ext = el.exts.get("Identity")
            if ident_ext is None:
                continue
            kind = enum_or_none(E.IdentityKind, ident_ext.get("kind"))
            if kind is None or not ident_ext.get("ref"):
                continue
            iid = (
                ref
                if (ref.startswith("ident:") and valid_entity_id(ref))
                else make_id("ident", str(ident_ext["ref"]))
            )
            existing = draft.get(iid)
            if isinstance(existing, Identity):
                if el.name and el.name not in (existing.name, existing.ref):
                    draft.replace(existing.replace(name=el.name))
                continue
            draft.add(
                Identity(
                    id=iid,
                    name=el.name if el.name != ident_ext.get("ref") else None,
                    identity_kind=kind,
                    ref=str(ident_ext["ref"]),
                    issuer=ident_ext.get("issuer"),
                    tenant=ident_ext.get("tenant"),
                )
            )

    def credentials(self, ctx: ImportContext, draft: Draft) -> None:
        """``CredentialBinding`` extensions carry the binding ids the CycloneDX projection lacks."""
        for ref, el in self.decoded.elements.items():
            subject = draft.map_ref(ref)
            if subject is None or not draft.has(subject):
                continue
            for typ, data in el.ext_list:
                if typ != "CredentialBinding":
                    continue
                cid = data.get("id")
                identity_ref = data.get("identityRef")
                if (
                    not isinstance(cid, str)
                    or not cid.startswith("cred:")
                    or not isinstance(identity_ref, str)
                ):
                    continue
                if draft.has(cid):
                    continue
                stray = next(
                    (
                        c
                        for c in draft.entities["credential_bindings"]
                        if c.subject_ref == subject and c.identity_ref == identity_ref
                    ),
                    None,
                )
                if stray is not None:
                    draft.entities["credential_bindings"].remove(stray)
                    draft.edges = [
                        e
                        for e in draft.edges
                        if not (e.type is EdgeType.HOLDS_CREDENTIAL and e.to_ref == stray.id)
                    ]
                    binding = stray.replace(id=cid)
                else:
                    scopes = _as_list(data.get("scopesGranted"))
                    binding = CredentialBinding(
                        id=cid,
                        subject_ref=subject,
                        identity_ref=identity_ref,
                        credential_kind=enum_or_none(E.CredentialKind, data.get("kind"))
                        or E.CredentialKind.UNKNOWN,
                        lifetime=data.get("lifetime"),
                        scopes_granted=None if not scopes else _claim_list([str(s) for s in scopes]),
                        storage=CredentialStorage(
                            kind=enum_or_none(E.CredentialStorageKind, data.get("storageKind"))
                            or E.CredentialStorageKind.UNKNOWN,
                            locator=data.get("storageLocator"),
                        ),
                    )
                draft.add(binding)
                draft.edge(EdgeType.HOLDS_CREDENTIAL, subject, cid)

    def evidence_media_types(self, draft: Draft) -> None:
        for ref, el in self.extras.items():
            if el.cls == "software_File" and "Evidence" in el.exts:
                ev = draft.get(draft.map_ref(ref) or ref)
                ctype = getattr(el.obj, "contentType", None)
                if isinstance(ev, Evidence) and ctype:
                    draft.replace(ev.replace(media_type=str(ctype)))

    def vex(self, ctx: ImportContext, draft: Draft, rel: Any, quals: dict[str, Any]) -> None:
        d = self.decoded
        vuln = getattr(rel, "from_", None)
        vref = d.ref_of(vuln)
        el = self.extras.get(vref or "")
        if el is None or el.cls != "security_Vulnerability":
            return
        targets = [draft.map_ref(d.ref_of(t)) for t in (rel.to or []) if not isinstance(t, str)]
        subject = next((t for t in targets if t and draft.has(t)), None)
        if subject is None:
            ctx.lose(
                f"/vex/{vref}",
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.DROPPED,
                E.LossSeverity.SECURITY_RELEVANT,
                entity=vref,
                field_name="subject",
            )
            return
        scope = el.exts.get("VexScope", {})
        rtype = _suffix(getattr(rel, "relationshipType", None)) or ""
        status = scope.get("status") or _VEX_STATUS_BY_RELATION.get(rtype, "under-investigation")
        framework, _, weakness_id = (getattr(el.obj, "summary", None) or f"other:{el.name}").partition(":")
        from symbiote.model.common import ThreatRef
        from symbiote.model.entities import VexStatement, VexSubject

        vid = (
            vref
            if vref and vref.startswith("vex:") and valid_entity_id(vref)
            else make_id("vex", f"{framework}-{weakness_id}-{subject}")
        )
        issued = draft.produced_at or ctx.now
        ctx.lose(
            f"/vex/{vid}",
            E.LossReason.PRECISION_LOST,
            E.LossPreservedIn.DROPPED,
            entity=vid,
            field_name="issued_at",
        )
        if draft.has(vid):
            return
        draft.add(
            VexStatement(
                id=vid,
                weakness=ThreatRef(framework=framework or "other", id=weakness_id or el.name or "unknown"),
                subject=VexSubject(ref=subject, config_digest=as_digest(scope.get("configDigest"))),
                status=str(status),
                justification=scope.get("justification"),
                detail=getattr(rel, "security_impactStatement", None),
                issued_at=issued,
                expires=parse_time(scope.get("expires")),
            )
        )


def _claim_list(values: list[str]) -> Any:
    from symbiote.model.common import Claim

    return Claim(value=values)


def _edge(edge_type: EdgeType, src: str, dst: str, extra: dict[str, Any]) -> Any:
    from symbiote.model.edges import Edge

    return Edge(type=edge_type, from_ref=src, to_ref=dst, **extra)


# ------------------------------------------------------------------------------------------------ public API


def import_spdx(
    doc: Mapping[str, Any],
    *,
    as_kind: E.SnapshotKind | None = None,
    nonce: bytes | None = None,
    now: datetime | None = None,
    source_digest_value: str | None = None,
    validate: bool = True,
) -> tuple[AgentBOM, LossReport]:
    """Import an SPDX 3.0.1 JSON-LD document; returns the re-finalised model and the ``spdx→model`` loss report."""
    if not isinstance(doc, Mapping) or "@context" not in doc:
        raise SpdxImportError(["input is not a JSON-LD document (missing @context)"])
    if validate:
        errors = validate_spdx(dict(doc), bindings=False)
        if errors:
            raise SpdxImportError(errors)
    try:
        decoded = _Decoded(doc)
    except Exception as exc:  # the bindings raise plain Python errors on malformed graphs
        raise SpdxImportError([f"spdx-python-model: {type(exc).__name__}: {exc}"]) from exc
    pseudo, extras = decoded.pseudo_cyclonedx()
    if not pseudo.get("metadata", {}).get("component"):
        raise SpdxImportError(["document has no root AIPackage (agent) element"])
    native = any(el.props or el.exts for el in decoded.elements.values()) or bool(
        decoded.sbom and _Element(decoded.sbom, decoded.ns).exts
    )
    ctx = ImportContext(
        dialect="symbiote" if native else "generic",
        source_format="spdx-3.0.1",
        source_digest=source_digest_value or source_digest(doc),
        now=now or datetime.now(UTC),
    )
    for ref, el in extras.items():
        if "Evaluation" in el.exts:
            ctx.lose(
                f"/evaluations/{ref}",
                E.LossReason.NO_NATIVE_CONSTRUCT,
                E.LossPreservedIn.DROPPED,
                entity=ref,
                field_name="results",
            )
    enricher = _SpdxEnricher(decoded, extras)
    draft = invert(pseudo, ctx, native=native, adapter=enricher)
    document_iri = getattr(decoded.document, "spdxId", None) or decoded.ns.rstrip("/")
    links = Links(spdx=SpdxLink(document_iri=str(document_iri), digest=ctx.source_digest))
    return assemble(
        draft,
        ctx,
        as_kind=as_kind,
        default_kind=E.SnapshotKind.DECLARED,
        nonce=nonce,
        links=links,
        direction="spdx→model",
    )


__all__ = ["SpdxImportError", "import_spdx"]
