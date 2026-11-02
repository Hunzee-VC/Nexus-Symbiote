"""Read ShadowScan output: the JSON report (full fidelity) or the CycloneDX 1.6 AI-BOM it writes.

The JSON report is ShadowScan's own ``ScanResult.to_dict()`` (``finding_identity_schema``
``shadowscan.finding-identity/v2``; v1 reports are accepted and flagged). It is read **strictly**: findings
without the identity fields a usable record needs are rejected, numbers must be finite, and NaN/Infinity are
refused outright (ShadowScan itself refuses to publish them). Everything else is kept as data —
``[REDACTED]`` placeholders stay placeholders, snippets are never copied into entities, and a field this
module does not understand is carried through ``metadata`` for the mapper to decide.

The CycloneDX dialect is lossy by construction (ShadowScan documents this): there is no autonomy interval,
no evidence list and no inventory state beyond ``shadowscan:shadow``. :func:`findings_from_cyclonedx`
reconstructs what it can and records every omission in :attr:`ShadowScanReport.losses`.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

IDENTITY_SCHEMAS = ("shadowscan.finding-identity/v2", "shadowscan.finding-identity/v1")
TOOL_NAME = "ShadowScan"
PROPERTY_PREFIX = "shadowscan:"
_REQUIRED = ("surface", "connector", "kind", "title", "resource", "resource_type")
_TEXT_OPTIONAL = ("provider", "account", "region", "owner", "registry_match", "first_seen", "last_seen")
_LIST_FIELDS = ("frameworks", "model_providers", "models", "capabilities", "permissions", "tags")
#: Kinds whose autonomy ShadowScan assesses (``docs/concepts/autonomy.md``); the others *enable* an agent.
AUTONOMY_KINDS = frozenset(
    {
        "agent",
        "framework-usage",
        "agent-config",
        "mcp-server",
        "workflow",
        "bot-app",
        "gateway-caller",
        "ai-app",
        "runtime-process",
        "cloud-resource",
    }
)


class ReportError(ValueError):
    """The input is not a ShadowScan report this reader understands."""


def _reject_constant(name: str) -> Any:
    raise ReportError(f"report contains non-finite number {name}")


@dataclass(slots=True)
class ShadowScanEvidence:
    signal: str
    description: str
    location: str | None = None
    weight: float = 0.5
    signature: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RiskFactor:
    id: str
    description: str
    weight: float


@dataclass(slots=True)
class Risk:
    score: float = 0
    level: str = "info"
    factors: list[RiskFactor] = field(default_factory=list)
    danger_score: float = 0


@dataclass(slots=True)
class ShadowScanFinding:
    """One ShadowScan finding, validated and typed; ``raw`` is the record as published (for digests)."""

    id: str
    surface: str
    connector: str
    kind: str
    title: str
    resource: str
    resource_type: str
    identity_discriminator: str
    identity_schema: str
    provider: str | None = None
    account: str | None = None
    region: str | None = None
    owner: str | None = None
    frameworks: list[str] = field(default_factory=list)
    model_providers: list[str] = field(default_factory=list)
    models: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    evidence: list[ShadowScanEvidence] = field(default_factory=list)
    confidence: float = 0.0
    likelihood: str = "weak"
    risk: Risk = field(default_factory=Risk)
    shadow: bool | None = None
    registry_match: str | None = None
    tags: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def scan_root(self) -> str | None:
        root = self.metadata.get("scan_root")
        return root if isinstance(root, str) and root else None

    @property
    def autonomy(self) -> dict[str, Any] | None:
        block = self.metadata.get("autonomy")
        return block if isinstance(block, dict) else None

    @property
    def servers(self) -> list[dict[str, Any]]:
        servers = self.metadata.get("servers")
        return [s for s in servers if isinstance(s, dict)] if isinstance(servers, list) else []

    @property
    def redacted_identity(self) -> bool:
        return any(
            "[REDACTED]" in (v or "") for v in (self.resource, self.provider, self.account, self.region)
        )

    def digest(self) -> str:
        """``sha256:<hex>`` over the published record (sorted keys, compact), the evidence identity in Symbiote."""
        body = json.dumps(self.raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
        return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class ConnectorStats:
    connector: str
    name: str | None
    findings: int
    errors: list[str]
    warnings: list[str]
    skipped: bool
    skip_reason: str | None
    incomplete: bool
    incomplete_reasons: dict[str, int]
    started_at: str | None
    finished_at: str | None
    coverage: dict[str, Any] | None
    declared_omissions: int

    @property
    def ok(self) -> bool:
        return not (self.errors or self.skipped or self.incomplete)

    @property
    def status(self) -> str:
        if self.skipped:
            return "skipped"
        if self.errors and not self.findings:
            return "failed"
        if self.errors or self.incomplete:
            return "partial"
        return "ok"

    @property
    def surface(self) -> str:
        """The ShadowScan surface (``code``, ``identity`` …) a connector belongs to, from its name."""
        name = self.name or self.connector
        return name.split(".", 1)[0] if "." in name else name


@dataclass(slots=True)
class ShadowScanReport:
    version: str
    identity_schema: str
    started_at: str | None
    finished_at: str | None
    complete: bool
    inventory_present: bool
    inventory_size: int
    findings: list[ShadowScanFinding]
    stats: list[ConnectorStats]
    summary: dict[str, Any] = field(default_factory=dict)
    collection_scope: dict[str, Any] | None = None
    source_format: str = "json"
    source_digest: str | None = None
    source_path: str | None = None
    losses: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def scan_roots(self) -> list[str]:
        roots: dict[str, int] = {}
        for f in self.findings:
            if f.scan_root:
                roots[f.scan_root] = roots.get(f.scan_root, 0) + 1
        return [r for r, _ in sorted(roots.items(), key=lambda kv: (-kv[1], kv[0]))]

    def by_kind(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.kind] = out.get(f.kind, 0) + 1
        return dict(sorted(out.items()))


# ----------------------------------------------------------------------------------------- JSON report


def _finite(value: Any, name: str, *, lo: float | None = None, hi: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ReportError(f"finding {name} must be a finite number")
    if (lo is not None and value < lo) or (hi is not None and value > hi):
        raise ReportError(f"finding {name} is outside its allowed range")
    return value


def _str_list(record: Mapping[str, Any], name: str) -> list[str]:
    value = record.get(name, [])
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
        raise ReportError(f"finding {name} must be a list of strings")
    return list(dict.fromkeys(value))


def _opt_str(record: Mapping[str, Any], name: str) -> str | None:
    value = record.get(name)
    if value is not None and not isinstance(value, str):
        raise ReportError(f"finding {name} must be a string or null")
    return value


def _evidence(items: Any) -> list[ShadowScanEvidence]:
    if items is None:
        return []
    if not isinstance(items, list):
        raise ReportError("finding evidence must be a list")
    out: list[ShadowScanEvidence] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise ReportError("finding evidence must be objects")
        signal, description = item.get("signal"), item.get("description")
        if not isinstance(signal, str) or not isinstance(description, str):
            raise ReportError("finding evidence must have a string signal and description")
        location, signature = item.get("location"), item.get("signature")
        if (location is not None and not isinstance(location, str)) or (
            signature is not None and not isinstance(signature, str)
        ):
            raise ReportError("finding evidence location and signature must be strings or null")
        attributes = item.get("attributes", {})
        if attributes is None:
            attributes = {}
        if not isinstance(attributes, Mapping):
            raise ReportError("finding evidence attributes must be an object")
        out.append(
            ShadowScanEvidence(
                signal=signal,
                description=description,
                location=location,
                weight=_finite(item.get("weight", 0.5), "evidence weight", lo=0, hi=1),
                signature=signature,
                attributes=dict(attributes),
            )
        )
    return out


def _risk(value: Any) -> Risk:
    if value is None:
        return Risk()
    if not isinstance(value, Mapping):
        raise ReportError("finding risk must be an object")
    factors_raw = value.get("factors", [])
    if not isinstance(factors_raw, list) or any(not isinstance(f, Mapping) for f in factors_raw):
        raise ReportError("finding risk factors must be objects")
    factors = []
    for f in factors_raw:
        if not isinstance(f.get("id"), str) or not isinstance(f.get("description"), str):
            raise ReportError("finding risk factors must have a string id and description")
        factors.append(
            RiskFactor(
                id=f["id"], description=f["description"], weight=_finite(f.get("weight", 0), "factor weight")
            )
        )
    level = value.get("level", "info")
    if not isinstance(level, str):
        raise ReportError("finding risk level must be a string")
    return Risk(
        score=_finite(value.get("score", 0), "risk score", lo=0, hi=100),
        level=level,
        factors=factors,
        danger_score=_finite(value.get("danger_score", 0), "risk danger score", lo=0, hi=100),
    )


def finding_from_dict(record: Mapping[str, Any]) -> ShadowScanFinding:
    """Validate one report finding (mirrors ShadowScan's own ``Finding.from_dict`` shape checks)."""
    if not isinstance(record, Mapping):
        raise ReportError("finding must be an object")
    for name in _REQUIRED:
        value = record.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ReportError(f"finding {name} is required")
    metadata = record.get("metadata", {})
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, Mapping):
        raise ReportError("finding metadata must be an object")
    shadow = record.get("shadow")
    if shadow is not None and not isinstance(shadow, bool):
        raise ReportError("finding shadow must be a boolean or null")
    fid = record.get("id")
    if not isinstance(fid, str) or not fid:
        raise ReportError("finding id is required")
    discriminator = record.get("identity_discriminator") or record["resource_type"].split("/", 1)[0]
    if not isinstance(discriminator, str):
        raise ReportError("finding identity_discriminator must be a string")
    schema = record.get("identity_schema", IDENTITY_SCHEMAS[1])
    if schema not in IDENTITY_SCHEMAS:
        raise ReportError("finding identity_schema is not a ShadowScan identity schema")
    likelihood = record.get("likelihood", "weak")
    if not isinstance(likelihood, str):
        raise ReportError("finding likelihood must be a string")
    return ShadowScanFinding(
        id=fid,
        surface=record["surface"],
        connector=record["connector"],
        kind=record["kind"],
        title=record["title"],
        resource=record["resource"],
        resource_type=record["resource_type"],
        identity_discriminator=discriminator,
        identity_schema=schema,
        provider=_opt_str(record, "provider"),
        account=_opt_str(record, "account"),
        region=_opt_str(record, "region"),
        owner=_opt_str(record, "owner"),
        frameworks=_str_list(record, "frameworks"),
        model_providers=_str_list(record, "model_providers"),
        models=_str_list(record, "models"),
        capabilities=_str_list(record, "capabilities"),
        permissions=_str_list(record, "permissions"),
        evidence=_evidence(record.get("evidence")),
        confidence=_finite(record.get("confidence", 0.0), "confidence", lo=0, hi=1),
        likelihood=likelihood,
        risk=_risk(record.get("risk")),
        shadow=shadow,
        registry_match=_opt_str(record, "registry_match"),
        tags=_str_list(record, "tags"),
        first_seen=_opt_str(record, "first_seen"),
        last_seen=_opt_str(record, "last_seen"),
        metadata=dict(metadata),
        raw=dict(record),
    )


def _stats(items: Any) -> list[ConnectorStats]:
    if items is None:
        return []
    if not isinstance(items, list):
        raise ReportError("report stats must be a list")
    out: list[ConnectorStats] = []
    for item in items:
        if not isinstance(item, Mapping) or not isinstance(item.get("connector"), str):
            raise ReportError("report stats entries must name a connector")
        errors = item.get("errors") or []
        warnings = item.get("warnings") or []
        reasons = item.get("incomplete_reasons") or {}
        out.append(
            ConnectorStats(
                connector=item["connector"],
                name=item.get("name") if isinstance(item.get("name"), str) else None,
                findings=int(item.get("findings") or 0),
                errors=[str(e) for e in errors] if isinstance(errors, list) else [str(errors)],
                warnings=[str(w) for w in warnings] if isinstance(warnings, list) else [str(warnings)],
                skipped=bool(item.get("skipped", False)),
                skip_reason=item.get("skip_reason") if isinstance(item.get("skip_reason"), str) else None,
                incomplete=bool(item.get("incomplete", False)),
                incomplete_reasons={str(k): int(v) for k, v in reasons.items()}
                if isinstance(reasons, Mapping)
                else {},
                started_at=item.get("started_at") if isinstance(item.get("started_at"), str) else None,
                finished_at=item.get("finished_at") if isinstance(item.get("finished_at"), str) else None,
                coverage=dict(item["coverage"]) if isinstance(item.get("coverage"), Mapping) else None,
                declared_omissions=int(item.get("declared_omissions") or 0),
            )
        )
    return out


def report_from_dict(
    data: Mapping[str, Any], *, source_digest: str | None = None, source_path: str | None = None
) -> ShadowScanReport:
    """Validate a parsed ShadowScan JSON report."""
    if not isinstance(data, Mapping):
        raise ReportError("report must be a JSON object")
    if "findings" not in data or "finding_identity_schema" not in data:
        raise ReportError("not a ShadowScan JSON report (no findings / finding_identity_schema)")
    schema = data.get("finding_identity_schema")
    if schema not in IDENTITY_SCHEMAS:
        raise ReportError(f"unsupported finding identity schema {schema!r}")
    findings_raw = data.get("findings")
    if not isinstance(findings_raw, list):
        raise ReportError("report findings must be a list")
    findings = [finding_from_dict(f) for f in findings_raw]
    ids = [f.id for f in findings]
    warnings: list[str] = []
    if len(ids) != len(set(ids)):
        warnings.append("report contains repeated finding ids; entities are disambiguated by digest")
    summary = data.get("summary") if isinstance(data.get("summary"), Mapping) else {}
    stats = _stats(data.get("stats"))
    complete = summary.get("complete")
    if not isinstance(complete, bool):
        # ShadowScan's definition: every requested connector completed, and there was at least one.
        complete = bool(stats) and all(s.ok for s in stats)
    scope = data.get("collection_scope")
    return ShadowScanReport(
        version=str(data.get("version") or ""),
        identity_schema=str(schema),
        started_at=data.get("started_at") if isinstance(data.get("started_at"), str) else None,
        finished_at=data.get("finished_at") if isinstance(data.get("finished_at"), str) else None,
        complete=complete,
        inventory_present=bool(data.get("inventory_present", False)),
        inventory_size=int(data.get("inventory_size") or 0),
        findings=findings,
        stats=stats,
        summary=dict(summary),
        collection_scope=dict(scope) if isinstance(scope, Mapping) else None,
        source_format="json",
        source_digest=source_digest,
        source_path=source_path,
        warnings=warnings,
    )


# ----------------------------------------------------------------------------------------- CycloneDX dialect


def _props(entry: Mapping[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in entry.get("properties") or []:
        if isinstance(p, Mapping) and isinstance(p.get("name"), str):
            out[p["name"]] = str(p.get("value", ""))
    return out


def _csv(value: str | None) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()] if value else []


def detect_cyclonedx(document: Mapping[str, Any]) -> bool:
    """Whether a CycloneDX document was written by ShadowScan (``--format cyclonedx``)."""
    if document.get("bomFormat") != "CycloneDX":
        return False
    tools = (document.get("metadata") or {}).get("tools")
    components = tools.get("components", []) if isinstance(tools, Mapping) else []
    if any(isinstance(c, Mapping) and c.get("name") == TOOL_NAME for c in components):
        return True
    meta_props = _props(document.get("metadata") or {})
    return any(k.startswith(PROPERTY_PREFIX) for k in meta_props)


def _bool(value: str | None) -> bool | None:
    if value is None:
        return None
    return {"true": True, "false": False}.get(value.lower())


def findings_from_cyclonedx(
    document: Mapping[str, Any], *, source_digest: str | None = None, source_path: str | None = None
) -> ShadowScanReport:
    """Reconstruct a report from ShadowScan's CycloneDX 1.6 output (lossy; losses are recorded)."""
    if not detect_cyclonedx(document):
        raise ReportError("not a ShadowScan CycloneDX document")
    metadata = document.get("metadata") or {}
    meta_props = _props(metadata)
    tools = metadata.get("tools")
    version = ""
    for c in tools.get("components", []) if isinstance(tools, Mapping) else []:
        if isinstance(c, Mapping) and c.get("name") == TOOL_NAME and isinstance(c.get("version"), str):
            version = c["version"]
    entries: dict[str, dict[str, Any]] = {}
    for e in list(document.get("components") or []) + list(document.get("services") or []):
        if isinstance(e, Mapping) and isinstance(e.get("bom-ref"), str):
            entries[e["bom-ref"]] = dict(e)
    deps: dict[str, list[str]] = {}
    for d in document.get("dependencies") or []:
        if isinstance(d, Mapping) and isinstance(d.get("ref"), str):
            deps[d["ref"]] = [x for x in d.get("dependsOn", []) if isinstance(x, str)]
    losses = [
        "cyclonedx dialect: no autonomy interval (metadata.autonomy) — no AutonomyAssessment is derived",
        "cyclonedx dialect: no per-finding evidence list; risk factors and confidence groups are absent",
        "cyclonedx dialect: credential findings (secret, token) are excluded by ShadowScan",
    ]
    findings: list[ShadowScanFinding] = []
    for ref, entry in entries.items():
        props = _props(entry)
        fid = props.get("shadowscan:finding-id")
        kind = props.get("shadowscan:kind")
        if not fid or not kind:
            continue
        servers: list[dict[str, Any]] = []
        frameworks: list[str] = []
        providers: list[str] = []
        models: list[str] = []
        mcp_tools: list[str] = []
        for dep in deps.get(ref, []):
            target = entries.get(dep)
            tprops = _props(target) if target else {}
            if dep.startswith("shadowscan:framework:"):
                frameworks.append(dep[len("shadowscan:framework:") :])
            elif dep.startswith("shadowscan:provider:"):
                providers.append(dep[len("shadowscan:provider:") :])
            elif dep.startswith("shadowscan:model:") and target:
                models.append(str(target.get("name", "")))
            elif dep.startswith("shadowscan:mcp:") and target:
                endpoints = [u for u in target.get("endpoints", []) if isinstance(u, str)]
                servers.append(
                    {
                        "name": target.get("name"),
                        "transport": tprops.get("shadowscan:mcp:transport"),
                        "command": tprops.get("shadowscan:mcp:command"),
                        "args": [],
                        "url": endpoints[0] if endpoints else None,
                        "urls": endpoints,
                        "env_names": [],
                        "headers": [],
                        "auto_approve": None,
                        "disabled": _bool(tprops.get("shadowscan:mcp:disabled")),
                        "risks": _csv(tprops.get("shadowscan:mcp:risks")),
                        "location": tprops.get("shadowscan:mcp:file"),
                    }
                )
            elif dep.startswith("shadowscan:mcp-server:") and target:
                mcp_tools.extend(_csv(tprops.get("shadowscan:mcp:tools")))
        metadata_block: dict[str, Any] = {}
        if servers:
            metadata_block["servers"] = servers
        if mcp_tools:
            metadata_block["mcp_tools"] = mcp_tools
        score = props.get("shadowscan:heuristic-risk-score")
        confidence = props.get("shadowscan:confidence")
        record = {
            "id": fid,
            "surface": props.get("shadowscan:surface") or str(entry.get("group") or "code"),
            "connector": props.get("shadowscan:connector") or "unknown",
            "kind": kind,
            "title": str(entry.get("name") or fid),
            "resource": props.get("shadowscan:resource") or str(entry.get("name") or fid),
            "resource_type": props.get("shadowscan:resource-type") or "unknown",
            "identity_discriminator": (props.get("shadowscan:resource-type") or "unknown").split("/", 1)[0],
            "identity_schema": IDENTITY_SCHEMAS[0],
            "provider": props.get("shadowscan:provider"),
            "account": props.get("shadowscan:account"),
            "region": props.get("shadowscan:region"),
            "owner": props.get("shadowscan:owner"),
            "frameworks": frameworks,
            "model_providers": providers,
            "models": models,
            "capabilities": _csv(props.get("shadowscan:capabilities")),
            "permissions": [],
            "evidence": [],
            "confidence": float(confidence) if confidence else 0.0,
            "likelihood": props.get("shadowscan:likelihood", "weak"),
            "risk": {
                "score": float(score) if score else 0,
                "level": props.get("shadowscan:heuristic-risk", "info"),
                "factors": [],
            },
            "shadow": _bool(props.get("shadowscan:shadow")),
            "registry_match": props.get("shadowscan:registry-match"),
            "tags": _csv(props.get("shadowscan:tags")),
            "first_seen": props.get("shadowscan:first-seen"),
            "last_seen": props.get("shadowscan:last-seen"),
            "metadata": metadata_block,
        }
        findings.append(finding_from_dict(record))
    _infer_scan_roots(findings)
    status = meta_props.get("shadowscan:scan:status", "incomplete")
    incomplete = set(_csv(meta_props.get("shadowscan:scan:incomplete-connectors")))
    stats = [
        ConnectorStats(
            connector=c,
            name=c,
            findings=0,
            errors=[],
            warnings=[],
            skipped=False,
            skip_reason=None,
            incomplete=c in incomplete,
            incomplete_reasons={},
            started_at=None,
            finished_at=None,
            coverage=None,
            declared_omissions=0,
        )
        for c in _csv(meta_props.get("shadowscan:scan:connectors"))
    ]
    return ShadowScanReport(
        version=version,
        identity_schema=IDENTITY_SCHEMAS[0],
        started_at=None,
        finished_at=metadata.get("timestamp") if isinstance(metadata.get("timestamp"), str) else None,
        complete=status == "complete",
        inventory_present=any(f.shadow is not None for f in findings),
        inventory_size=int(meta_props.get("shadowscan:scan:inventory-size") or 0),
        findings=findings,
        stats=stats,
        summary={"status": status, "total": len(findings)},
        collection_scope=None,
        source_format="cyclonedx",
        source_digest=source_digest,
        source_path=source_path,
        losses=losses,
    )


def _infer_scan_roots(findings: list[ShadowScanFinding]) -> None:
    """The CycloneDX dialect carries no ``scan_root``; a coding-agent configuration's resource *is* the root.

    Every other code-surface finding whose resource lies under such a root is attributed to it, so the mapper
    can bind repository findings to the scanned agent exactly as it does for the JSON report.
    """
    roots = sorted(
        {
            f.resource
            for f in findings
            if f.surface == "code" and f.kind == "agent-config" and f.resource_type == "coding-agent-config"
        },
        key=len,
        reverse=True,
    )
    for f in findings:
        if f.surface != "code" or f.scan_root:
            continue
        for root in roots:
            if f.resource == root or f.resource.startswith(root.rstrip("/") + "/"):
                f.metadata["scan_root"] = root
                break


# ----------------------------------------------------------------------------------------- entry points


def load_report(
    data: Mapping[str, Any], *, source_digest: str | None = None, source_path: str | None = None
) -> ShadowScanReport:
    """Build a report from parsed JSON of either format."""
    if data.get("bomFormat") == "CycloneDX":
        return findings_from_cyclonedx(data, source_digest=source_digest, source_path=source_path)
    return report_from_dict(data, source_digest=source_digest, source_path=source_path)


def read_report(source: Path | str | bytes) -> ShadowScanReport:
    """Read a ShadowScan JSON report or CycloneDX document from a path or bytes (NaN/Infinity refused)."""
    path: str | None = None
    if isinstance(source, bytes):
        raw = source
    else:
        p = Path(source)
        raw = p.read_bytes()
        path = p.name
    try:
        data = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except UnicodeDecodeError as exc:
        raise ReportError(f"report is not UTF-8: {exc}") from None
    except json.JSONDecodeError as exc:
        raise ReportError(f"report is not valid JSON: {exc.msg} at line {exc.lineno}") from None
    if not isinstance(data, Mapping):
        raise ReportError("report must be a JSON object")
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    return load_report(data, source_digest=digest, source_path=path)


__all__ = [
    "AUTONOMY_KINDS",
    "IDENTITY_SCHEMAS",
    "ConnectorStats",
    "ReportError",
    "Risk",
    "RiskFactor",
    "ShadowScanEvidence",
    "ShadowScanFinding",
    "ShadowScanReport",
    "detect_cyclonedx",
    "finding_from_dict",
    "findings_from_cyclonedx",
    "load_report",
    "read_report",
    "report_from_dict",
]
