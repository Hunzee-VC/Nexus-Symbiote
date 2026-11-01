"""ShadowScan importer — primary discovery scanner for Nexus SymBiote.

Nexus-ShadowScan is the multi-surface discovery engine (code, identity, gateways,
low-code, SaaS, cloud, endpoints, network, runtime). Nexus SymBiote consumes its
JSON or CycloneDX output, maps findings into the agent-native domain model,
and performs supply-chain verification, integrity checks, risk scoring, and
standards-grade BOM emission.

This scanner does not execute discovered artifacts. It only reads a previously
generated ShadowScan report (produced by a separate, least-privilege run).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import (
    AssuranceLevel,
    AutonomyLevel,
    ComponentType,
    RiskSeverity,
    TrustTier,
)
from nexus_symbiote.core.models import (
    AgentComponent,
    MCPServerComponent,
    ModelComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.scanners.base import Scanner, ScanResult


class ShadowScanImporter(Scanner):
    """Imports a Nexus-ShadowScan report and projects findings into AIBOM components.

    Supported inputs:
    - ShadowScan native JSON report (list of findings or a ScanResult dict)
    - CycloneDX 1.6/1.7 document produced by ShadowScan

    Mapping is conservative: unknown kinds become generic Agent or Tool
    components with assurance_level=declared and trust_tier=unknown.
    """

    name = "shadowscan"

    def scan(self, project_root: Path) -> ScanResult:
        """Look for a conventional ShadowScan report under the project root.

        Convention: ``.shadowscan/report.json`` or ``shadowscan-report.json``.
        Prefer an explicit CLI import path for production use.
        """
        result = ScanResult(scanner_name=self.name)
        candidates = [
            project_root / ".shadowscan" / "report.json",
            project_root / "shadowscan-report.json",
            project_root / "shadowscan.json",
        ]
        for path in candidates:
            if path.is_file():
                result.surfaces_scanned.append(str(path))
                try:
                    comps = self.import_report(path)
                    result.components.extend(comps)
                except Exception as exc:  # noqa: BLE001
                    result.scan_failures.append(f"ShadowScan import failed for {path}: {exc}")
                break
        else:
            result.surfaces_excluded.append("shadowscan-report (no conventional report file found)")
        return result

    def import_report(self, report_path: Path) -> list[Any]:
        """Load a ShadowScan report and return mapped components."""
        text = report_path.read_text(encoding="utf-8")
        data = json.loads(text)

        if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
            return self._from_cyclonedx(data)
        if isinstance(data, dict) and "findings" in data:
            return self._from_native(data["findings"])
        if isinstance(data, list):
            return self._from_native(data)
        raise ValueError("Unrecognized ShadowScan report format")

    def _from_native(self, findings: list[dict[str, Any]]) -> list[Any]:
        components: list[Any] = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            kind = str(f.get("kind", "")).lower()
            title = f.get("title") or f.get("resource") or "discovered-component"
            bom_ref = f.get("id") or f"shadowscan:{kind}:{title}"

            risks = self._map_risks(f)

            if kind in {"mcp-server", "mcp"} or "mcp" in str(f.get("connector", "")).lower():
                components.append(
                    MCPServerComponent(
                        bom_ref=bom_ref,
                        name=str(title),
                        source_path=f.get("resource"),
                        trust_tier=TrustTier.UNKNOWN,
                        assurance_level=AssuranceLevel.DECLARED,
                        risks=risks,
                        properties={"shadowscan:raw": f},
                    )
                )
            elif kind in {"local-model", "model"} or "model" in str(f.get("resource_type", "")).lower():
                components.append(
                    ModelComponent(
                        bom_ref=bom_ref,
                        name=str(title),
                        source_path=f.get("resource"),
                        trust_tier=TrustTier.UNKNOWN,
                        assurance_level=AssuranceLevel.DECLARED,
                        risks=risks,
                        properties={"shadowscan:raw": f},
                    )
                )
            else:
                # Default to Agent for agent, caller, app, process, etc.
                autonomy = AutonomyLevel.L2_AGENT
                components.append(
                    AgentComponent(
                        bom_ref=bom_ref,
                        name=str(title),
                        source_path=f.get("resource"),
                        autonomy_level=autonomy,
                        trust_tier=TrustTier.UNKNOWN,
                        assurance_level=AssuranceLevel.DECLARED,
                        risks=risks,
                        properties={"shadowscan:raw": f, "shadowscan:kind": kind},
                    )
                )
        return components

    def _from_cyclonedx(self, bom: dict[str, Any]) -> list[Any]:
        components: list[Any] = []
        for c in bom.get("components", []):
            if not isinstance(c, dict):
                continue
            props = {p["name"]: p["value"] for p in c.get("properties", []) if isinstance(p, dict)}
            kind = props.get("shadowscan:kind", "").lower()
            name = c.get("name", "unknown")
            bom_ref = c.get("bom-ref", f"cdx:{name}")
            risks = self._map_risks_from_props(props)

            if "mcp" in kind or c.get("group") == "mcp-server":
                components.append(
                    MCPServerComponent(
                        bom_ref=bom_ref,
                        name=name,
                        trust_tier=TrustTier.UNKNOWN,
                        assurance_level=AssuranceLevel.DECLARED,
                        risks=risks,
                        properties={"shadowscan:cdx": props},
                    )
                )
            elif c.get("type") == "machine-learning-model" or "model" in kind:
                components.append(
                    ModelComponent(
                        bom_ref=bom_ref,
                        name=name,
                        trust_tier=TrustTier.UNKNOWN,
                        assurance_level=AssuranceLevel.DECLARED,
                        risks=risks,
                        properties={"shadowscan:cdx": props},
                    )
                )
            else:
                components.append(
                    AgentComponent(
                        bom_ref=bom_ref,
                        name=name,
                        trust_tier=TrustTier.UNKNOWN,
                        assurance_level=AssuranceLevel.DECLARED,
                        risks=risks,
                        properties={"shadowscan:cdx": props, "shadowscan:kind": kind},
                    )
                )
        return components

    def _map_risks(self, finding: dict[str, Any]) -> list[RiskAssessment]:
        risks: list[RiskAssessment] = []
        risk_obj = finding.get("risk") or {}
        if isinstance(risk_obj, dict):
            level = str(risk_obj.get("level", "info")).lower()
            score = risk_obj.get("score", 0)
            sev = {
                "critical": RiskSeverity.CRITICAL,
                "high": RiskSeverity.HIGH,
                "medium": RiskSeverity.MEDIUM,
                "low": RiskSeverity.LOW,
            }.get(level, RiskSeverity.INFO)
            risks.append(
                RiskAssessment(
                    severity=sev,
                    category="shadowscan-heuristic",
                    detail=f"ShadowScan heuristic risk {level} (score {score})",
                    recommendation="Review evidence and apply independent policy.",
                )
            )
        if finding.get("shadow") is True:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="shadow-agent",
                    detail="Finding marked as shadow (not in approved inventory).",
                    recommendation="Reconcile against approved agent registry.",
                )
            )
        return risks

    def _map_risks_from_props(self, props: dict[str, str]) -> list[RiskAssessment]:
        risks: list[RiskAssessment] = []
        level = props.get("shadowscan:heuristic-risk", "").lower()
        if level:
            sev = {
                "critical": RiskSeverity.CRITICAL,
                "high": RiskSeverity.HIGH,
                "medium": RiskSeverity.MEDIUM,
                "low": RiskSeverity.LOW,
            }.get(level, RiskSeverity.INFO)
            risks.append(
                RiskAssessment(
                    severity=sev,
                    category="shadowscan-heuristic",
                    detail=f"ShadowScan heuristic risk {level}",
                )
            )
        return risks
