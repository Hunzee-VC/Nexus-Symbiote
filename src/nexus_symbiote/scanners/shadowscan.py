"""Import untrusted Nexus-ShadowScan reports as *declared* discovery evidence.

No live collection, artifact execution, identity verification, or security
attestation occurs here. Report bytes remain a separate sensitive artifact.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import AssuranceLevel, AutonomyLevel, RiskSeverity, TrustTier
from nexus_symbiote.core.models import (
    AgentComponent,
    AnyComponent,
    MCPServerComponent,
    ModelComponent,
    RiskAssessment,
)
from nexus_symbiote.scanners.base import Scanner, ScanResult, read_regular_text

MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_FINDINGS = 100_000
_ALLOWED_SURFACES = frozenset(
    {"code", "identity", "gateway", "lowcode", "saas", "cloud", "endpoint", "network", "runtime"}
)


@dataclass
class ImportedReport:
    components: list[AnyComponent] = field(default_factory=list)
    digest: str = ""
    source_format: str = ""
    source_status: str = "unknown"
    unmapped_count: int = 0
    unmapped_indexes: list[int] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite JSON number")


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _risks(level: Any, shadow: Any) -> list[RiskAssessment]:
    findings: list[RiskAssessment] = []
    levels = {x.value: x for x in RiskSeverity}
    if isinstance(level, str) and level in levels:
        findings.append(
            RiskAssessment(
                severity=levels[level],
                category="shadowscan-heuristic",
                detail=f"ShadowScan heuristic risk: {level}; not an independently verified vulnerability.",
                recommendation="Review the original source evidence and verify under policy.",
            )
        )
    if shadow is True:
        findings.append(
            RiskAssessment(
                severity=RiskSeverity.INFO,
                category="shadowscan-inventory-unmatched",
                detail="ShadowScan reports no matching entry in its supplied inventory; authorization is not established.",
                recommendation="Verify inventory scope and reconcile the source finding.",
            )
        )
    return findings


def _make_component(
    kind: str,
    source_id: str,
    index: int,
    digest: str,
    surface: str | None,
    level: Any,
    shadow: Any,
    *,
    cdx_model: bool = False,
    cdx_mcp: bool = False,
) -> AnyComponent | None:
    identity_hash = _short_hash(source_id)
    ref = "shadowscan:" + identity_hash
    props: dict[str, Any] = {
        "shadowscan:report-sha256": digest,
        "shadowscan:finding-index": index,
        "shadowscan:source-id-sha256": identity_hash,
    }
    if surface in _ALLOWED_SURFACES:
        props["shadowscan:surface"] = surface
    if kind in {"agent", "mcp-server", "local-model", "model"}:
        props["shadowscan:kind"] = kind
    if isinstance(shadow, bool):
        props["shadowscan:inventory-unmatched"] = shadow
    risks = _risks(level, shadow)
    safe_kind = kind if kind in {"agent", "mcp-server", "local-model", "model"} else "component"
    common: dict[str, Any] = {
        "bom_ref": ref,
        "name": "ShadowScan " + safe_kind + " " + identity_hash[:12],
        "trust_tier": TrustTier.UNKNOWN,
        "assurance_level": AssuranceLevel.DECLARED,
        "properties": props,
        "risks": risks,
    }
    if kind == "mcp-server" or cdx_mcp:
        return MCPServerComponent(**common)
    if kind in {"local-model", "model"} or cdx_model:
        return ModelComponent(**common)
    if kind == "agent":
        return AgentComponent(autonomy_level=AutonomyLevel.UNKNOWN, **common)
    return None


class ShadowScanImporter(Scanner):
    """Import supported ShadowScan JSON and CycloneDX observations conservatively."""

    name = "shadowscan"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        for path in (
            project_root / ".shadowscan" / "report.json",
            project_root / "shadowscan-report.json",
            project_root / "shadowscan.json",
        ):
            if path.is_symlink():
                result.scan_failures.append("ShadowScan report is a symlink")
                break
            if path.exists():
                try:
                    imported = self.read_report(path)
                    result.components.extend(imported.components)
                    result.source_report_digest = imported.digest
                    result.source_report_format = imported.source_format
                    result.source_report_status = imported.source_status
                    result.source_unmapped_count = imported.unmapped_count
                    result.source_unmapped_indexes = imported.unmapped_indexes
                    result.surfaces_scanned.append("shadowscan:report")
                    result.surfaces_excluded.extend(imported.limitations)
                    if imported.source_status != "complete":
                        result.scan_failures.append(
                            "ShadowScan source report is incomplete or has unknown status"
                        )
                except (ValueError, OSError, UnicodeError, RecursionError):
                    result.scan_failures.append("ShadowScan report could not be safely imported")
                break
        else:
            result.surfaces_excluded.append("shadowscan-report (no report found)")
        return result

    def import_report(self, report_path: Path) -> ImportedReport:
        """Import components together with mandatory coverage and provenance."""
        return self.read_report(report_path)

    def read_report(self, report_path: Path) -> ImportedReport:
        text = read_regular_text(report_path, max_bytes=MAX_REPORT_BYTES)
        data = json.loads(
            text, object_pairs_hook=_object_no_duplicates, parse_constant=_reject_constant
        )
        if not isinstance(data, dict):
            raise ValueError("expected a ShadowScan report object")
        digest = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
        if data.get("bomFormat") == "CycloneDX":
            result = self._from_cyclonedx(data, digest)
        else:
            result = self._from_native(data, digest)
        # Discovery is not a verified, complete BOM even when source scan is complete.
        result.limitations.append(
            "ShadowScan discovery is a source claim; artifact integrity and full BOM coverage are unverified"
        )
        result.limitations.append(
            "Names, detailed evidence, models, and relationships remain in the source report and are not mapped"
        )
        if result.unmapped_count:
            result.limitations.append(
                f"{result.unmapped_count} source entries were not mapped into BOM components"
            )
        return result

    def _from_native(self, data: dict[str, Any], digest: str) -> ImportedReport:
        findings, stats, summary = data.get("findings"), data.get("stats"), data.get("summary")
        if (
            not isinstance(data.get("version"), str)
            or not isinstance(findings, list)
            or len(findings) > MAX_FINDINGS
        ):
            raise ValueError("invalid ShadowScan report envelope")
        if not isinstance(stats, list) or not isinstance(summary, dict):
            raise ValueError("ShadowScan report must include stats and summary")
        complete = summary.get("complete") is True and bool(stats)
        for stat in stats:
            if (
                not isinstance(stat, dict)
                or not isinstance(stat.get("errors"), list)
                or not isinstance(stat.get("skipped"), bool)
                or not isinstance(stat.get("incomplete"), bool)
            ):
                raise ValueError("invalid ShadowScan connector statistics")
            if stat["errors"] or stat["skipped"] or stat["incomplete"]:
                complete = False
            omissions = stat.get("declared_omissions", 0)
            if not isinstance(omissions, int) or isinstance(omissions, bool) or omissions != 0:
                complete = False
        for key in ("declared_omissions", "tolerated_gaps"):
            value = summary.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value != 0:
                complete = False
        result = ImportedReport(
            digest=digest,
            source_format="shadowscan-json",
            source_status="complete" if complete else "incomplete",
        )
        ids: set[str] = set()
        for index, finding in enumerate(findings):
            if (
                not isinstance(finding, dict)
                or not isinstance(finding.get("id"), str)
                or not finding["id"]
                or len(finding["id"]) > 4096
            ):
                raise ValueError("invalid ShadowScan finding or identifier")
            source_id = finding["id"]
            if source_id in ids:
                raise ValueError("duplicate ShadowScan finding identifier")
            ids.add(source_id)
            kind, surface = finding.get("kind"), finding.get("surface")
            if not isinstance(kind, str) or not isinstance(surface, str):
                raise ValueError("invalid ShadowScan finding kind or surface")
            risk = finding.get("risk")
            level = risk.get("level") if isinstance(risk, dict) else None
            comp = _make_component(
                kind, source_id, index, digest, surface, level, finding.get("shadow")
            )
            if comp is None:
                result.unmapped_count += 1
                result.unmapped_indexes.append(index)
            else:
                result.components.append(comp)
        return result

    def _from_cyclonedx(self, data: dict[str, Any], digest: str) -> ImportedReport:
        meta = data.get("metadata")
        if data.get("specVersion") not in ("1.6", "1.7") or not isinstance(meta, dict):
            raise ValueError("unsupported ShadowScan CycloneDX envelope")
        props = _properties(meta.get("properties", []))
        status = props.get("shadowscan:scan:status")
        if status not in ("complete", "incomplete"):
            raise ValueError("CycloneDX document lacks ShadowScan scan status")
        result = ImportedReport(
            digest=digest, source_format="shadowscan-cyclonedx", source_status=status
        )
        compositions = data.get("compositions")
        if not isinstance(compositions, list) or not compositions:
            result.limitations.append("CycloneDX composition completeness is not reported")
        elif any(
            not isinstance(c, dict) or c.get("aggregate") not in {"unknown", "complete"}
            for c in compositions
        ):
            result.limitations.append("CycloneDX source declares incomplete composition")
        for key in (
            "shadowscan:bom:truncated-findings",
            "shadowscan:scan:credential-findings-excluded",
        ):
            if props.get(key) not in (None, "0"):
                result.limitations.append("CycloneDX source omits or truncates findings")
        # CycloneDX is a lossy projection of discovery; it cannot prove full report coverage.
        result.limitations.append(
            "CycloneDX source omits or summarizes discovery evidence and relationships"
        )
        ids: set[str] = set()
        entries = []
        for key in ("components", "services"):
            items = data.get(key, [])
            if not isinstance(items, list):
                raise ValueError("invalid CycloneDX component list")
            entries.extend(items)
        if len(entries) > MAX_FINDINGS:
            raise ValueError("too many CycloneDX entries")
        for index, entry in enumerate(entries):
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("bom-ref"), str)
                or not entry["bom-ref"]
                or len(entry["bom-ref"]) > 4096
            ):
                raise ValueError("invalid CycloneDX entry")
            ref = entry["bom-ref"]
            if ref in ids:
                raise ValueError("duplicate CycloneDX bom-ref")
            ids.add(ref)
            p = _properties(entry.get("properties", []))
            kind = p.get("shadowscan:kind", "")
            shadow = {"true": True, "false": False}.get(p.get("shadowscan:shadow", ""))
            comp = _make_component(
                kind,
                ref,
                index,
                digest,
                p.get("shadowscan:surface"),
                p.get("shadowscan:heuristic-risk"),
                shadow,
                cdx_model=entry.get("type") == "machine-learning-model",
                cdx_mcp=entry.get("group") == "mcp-server",
            )
            if comp is None:
                result.unmapped_count += 1
                result.unmapped_indexes.append(index)
            else:
                result.components.append(comp)
        return result


def _properties(value: Any) -> dict[str, str]:
    if not isinstance(value, list):
        raise ValueError("invalid CycloneDX properties")
    result: dict[str, str] = {}
    for item in value:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("value"), str)
        ):
            raise ValueError("invalid CycloneDX property")
        name = item["name"]
        if name.startswith("shadowscan:"):
            if name in result:
                raise ValueError("duplicate ShadowScan property")
            result[name] = item["value"]
    return result
