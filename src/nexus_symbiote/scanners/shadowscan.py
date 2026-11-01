"""Import bounded, pre-generated ShadowScan reports without running discovery.

Imported claims retain declared assurance and unknown trust. Raw findings and
arbitrary properties are intentionally omitted; the exact report digest and
source index link each projection to separately governed source evidence.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import AssuranceLevel, RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import hash_bytes, parse_json_strict
from nexus_symbiote.core.models import (
    AgentComponent,
    MCPServerComponent,
    ModelComponent,
    RiskAssessment,
)
from nexus_symbiote.scanners.base import Scanner, ScanResult, sanitized_origin
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import redact_text

MAX_FINDINGS = 10_000


def _label(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError("invalid imported label")
    value = redact_text(value)
    return re.sub(
        r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>]+",
        lambda match: sanitized_origin(match.group()),
        value,
    )


class ShadowScanImporter(Scanner):
    name = "shadowscan"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        with self._collection(project_root, result) as files:
            for relative in (
                ".shadowscan/report.json",
                "shadowscan-report.json",
                "shadowscan.json",
            ):
                raw = files.read_bytes(relative, missing_ok=True)
                if raw is None:
                    continue
                result.surfaces_scanned.append(str(files.root / relative))
                try:
                    result.components.extend(self._import_bytes(raw))
                except (ValueError, TypeError, RecursionError):
                    result.scan_failures.append(
                        f"{relative}: ShadowScan report rejected (format, fields or limits)"
                    )
                break
        if not result.components and not result.scan_failures:
            result.surfaces_excluded.append("shadowscan-report (no conventional report file found)")
        return result

    def import_report(self, report_path: Path) -> list[Any]:
        """Import an explicit caller-selected local report, never a subprocess.

        The report's parent is the boundary for this explicit-file API. Automatic
        scan() instead uses the complete project root and configured exclusions.
        """
        failures: list[str] = []
        with ConfinedCollection(report_path.parent, failures) as files:
            raw = files.read_bytes(report_path.name)
        if raw is None:
            raise ValueError("ShadowScan report unavailable or outside safe read limits")
        try:
            return self._import_bytes(raw)
        except (ValueError, TypeError, RecursionError) as exc:
            raise ValueError("ShadowScan report rejected (format, fields or limits)") from exc

    def _import_bytes(self, raw: bytes) -> list[Any]:
        data = parse_json_strict(raw, max_bytes=4 * 1024 * 1024)
        report_hash = hash_bytes(raw)
        if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
            components = self._from_cyclonedx(data, report_hash)
        elif isinstance(data, dict) and "findings" in data:
            components = self._from_native(data["findings"], report_hash)
        elif isinstance(data, list):
            components = self._from_native(data, report_hash)
        else:
            raise ValueError("unrecognized ShadowScan report format")
        identifiers = [component.bom_ref for component in components]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("duplicate imported component identity")
        return components

    def _from_native(self, findings: Any, report_hash: str = "") -> list[Any]:
        if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
            raise ValueError("invalid or oversized finding list")
        components: list[Any] = []
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                raise ValueError("invalid finding object")
            kind = _label(finding.get("kind", "")).lower()
            title = _label(
                finding.get("title") or finding.get("resource") or "discovered-component"
            )
            reference = _label(finding.get("id") or f"shadowscan:{kind}:{title}")
            resource = finding.get("resource")
            resource = _label(resource) if resource is not None else None
            connector = _label(finding.get("connector", "")).lower()
            resource_type = _label(finding.get("resource_type", "")).lower()
            fields = {
                "bom_ref": reference,
                "name": title,
                "source_path": resource,
                "trust_tier": TrustTier.UNKNOWN,
                "assurance_level": AssuranceLevel.DECLARED,
                "risks": self._map_risks(finding),
                "properties": {
                    "shadowscan:kind": kind,
                    "shadowscan:report_hash": report_hash,
                    "shadowscan:source_index": index,
                    "shadowscan:raw_payload_omitted": True,
                    "collection_mode": "imported-unverified-report",
                },
            }
            if kind in {"mcp-server", "mcp"} or "mcp" in connector:
                components.append(MCPServerComponent(**fields))
            elif kind in {"local-model", "model"} or "model" in resource_type:
                components.append(ModelComponent(**fields))
            else:
                # Preserve the upstream generic-agent projection without treating
                # its kind, privileges or autonomy as independently established.
                components.append(AgentComponent(**fields))
        return components

    def _from_cyclonedx(self, bom: dict[str, Any], report_hash: str = "") -> list[Any]:
        source = bom.get("components", [])
        if not isinstance(source, list) or len(source) > MAX_FINDINGS:
            raise ValueError("invalid or oversized CycloneDX components")
        components: list[Any] = []
        for index, component in enumerate(source):
            if not isinstance(component, dict):
                raise ValueError("invalid CycloneDX component")
            properties = component.get("properties", [])
            if not isinstance(properties, list) or len(properties) > 1000:
                raise ValueError("invalid CycloneDX properties")
            selected: dict[str, str] = {}
            for prop in properties:
                if (
                    not isinstance(prop, dict)
                    or not isinstance(prop.get("name"), str)
                    or not isinstance(prop.get("value"), str)
                ):
                    raise ValueError("invalid CycloneDX property record")
                if prop["name"] in {"shadowscan:kind", "shadowscan:heuristic-risk"}:
                    if prop["name"] in selected:
                        raise ValueError("ambiguous duplicate property")
                    selected[prop["name"]] = _label(prop["value"])
            kind = selected.get("shadowscan:kind", "").lower()
            name = _label(component.get("name", "unknown"))
            reference = _label(component.get("bom-ref", f"cdx:{name}"))
            fields = {
                "bom_ref": reference,
                "name": name,
                "trust_tier": TrustTier.UNKNOWN,
                "assurance_level": AssuranceLevel.DECLARED,
                "risks": self._map_risks_from_props(selected),
                "properties": {
                    "shadowscan:kind": kind,
                    "shadowscan:report_hash": report_hash,
                    "shadowscan:source_index": index,
                    "shadowscan:raw_payload_omitted": True,
                    "collection_mode": "imported-unverified-report",
                },
            }
            if "mcp" in kind or component.get("group") == "mcp-server":
                components.append(MCPServerComponent(**fields))
            elif component.get("type") == "machine-learning-model" or "model" in kind:
                components.append(ModelComponent(**fields))
            else:
                components.append(AgentComponent(**fields))
        return components

    @staticmethod
    def _risk_level(level: Any) -> RiskSeverity:
        if not isinstance(level, str):
            raise ValueError("invalid risk level")
        return {
            "critical": RiskSeverity.CRITICAL,
            "high": RiskSeverity.HIGH,
            "medium": RiskSeverity.MEDIUM,
            "low": RiskSeverity.LOW,
            "info": RiskSeverity.INFO,
        }.get(level.lower(), RiskSeverity.INFO)

    def _map_risks(self, finding: dict[str, Any]) -> list[RiskAssessment]:
        risks: list[RiskAssessment] = []
        risk = finding.get("risk")
        if risk is not None:
            if not isinstance(risk, dict):
                raise ValueError("invalid finding risk")
            severity = self._risk_level(risk.get("level", "info"))
            score = risk.get("score")
            if score is not None and (type(score) not in (int, float) or not 0 <= score <= 100):
                raise ValueError("invalid finding risk score")
            risks.append(
                RiskAssessment(
                    severity=severity,
                    category="shadowscan-heuristic",
                    detail=f"Imported ShadowScan heuristic risk {severity.value}; not independently verified.",
                    recommendation="Review source evidence and apply independent deployment policy.",
                )
            )
        if finding.get("shadow") is True:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="shadow-agent",
                    detail="Source report marks this finding as absent from its approved inventory.",
                    recommendation="Verify report coverage and reconcile against the enterprise registry.",
                )
            )
        return risks

    def _map_risks_from_props(self, props: dict[str, str]) -> list[RiskAssessment]:
        level = props.get("shadowscan:heuristic-risk")
        if not level:
            return []
        severity = self._risk_level(level)
        return [
            RiskAssessment(
                severity=severity,
                category="shadowscan-heuristic",
                detail=f"Imported ShadowScan heuristic risk {severity.value}; not independently verified.",
            )
        ]
