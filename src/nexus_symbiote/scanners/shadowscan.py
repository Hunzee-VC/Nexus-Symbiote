"""ShadowScan importer — primary discovery scanner for Nexus SymBiote.

Nexus-ShadowScan is the multi-surface discovery engine (code, identity, gateways,
low-code, SaaS, cloud, endpoints, network, runtime). Nexus SymBiote consumes its
JSON or CycloneDX output, maps findings into the agent-native domain model,
and performs supply-chain verification, integrity checks, risk scoring, and
standards-grade BOM emission.

This scanner does not execute discovered artifacts. It only reads a previously
generated ShadowScan report (produced by a separate, least-privilege run). Reports are
self-asserted: a repository-supplied report is marked as such, and only a report the
operator names explicitly is marked as trusted input.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import (
    AssuranceLevel,
    AutonomyLevel,
    RiskSeverity,
    TrustTier,
)
from nexus_symbiote.core.models import (
    AgentComponent,
    AnyComponent,
    MCPServerComponent,
    ModelComponent,
    RiskAssessment,
)
from nexus_symbiote.scanners.base import (
    Scanner,
    ScanResult,
    matched_exclusion,
    read_regular_text,
    relative_posix,
    sanitized_origin,
)

REPORT_MAX_BYTES = 64 * 1024 * 1024

_UPSTREAM_LEVELS: dict[str, RiskSeverity] = {
    "critical": RiskSeverity.CRITICAL,
    "high": RiskSeverity.HIGH,
    "medium": RiskSeverity.MEDIUM,
    "low": RiskSeverity.LOW,
    "info": RiskSeverity.INFO,
}


class ShadowScanImporter(Scanner):
    """Imports a Nexus-ShadowScan report and projects findings into AIBOM components.

    Supported inputs:
    - ShadowScan native JSON report (list of findings or a ScanResult dict)
    - CycloneDX 1.6/1.7 document produced by ShadowScan

    Mapping is conservative: unknown kinds become generic Agent or Tool
    components with assurance_level=declared and trust_tier=unknown.
    """

    name = "shadowscan"

    def __init__(
        self,
        exclude_paths: Iterable[str] | None = None,
        *,
        trusted_report: Path | None = None,
    ) -> None:
        super().__init__(exclude_paths)
        self.trusted_report = trusted_report
        self.import_failures: list[str] = []

    def scan(self, project_root: Path) -> ScanResult:
        """Import the operator-named report, or else a conventional report in the project.

        A repository-supplied report is self-asserted, so its components are marked
        ``repo-supplied`` and are not treated as trusted.
        """
        result = ScanResult(scanner_name=self.name)
        trusted = self.trusted_report
        if trusted is not None:
            label = trusted.name
            result.surfaces_scanned.append(f"{label} (trusted-input ShadowScan report)")
            self._collect(result, trusted, label, "trusted-input")
            return result

        candidates = _conventional_reports(project_root)
        found = False
        for candidate in candidates:
            rel = relative_posix(candidate, project_root)
            if matched_exclusion(candidate, project_root, self.exclude_paths):
                result.record_excluded(rel, "excluded by policy")
            elif candidate.is_symlink() or candidate.exists():
                found = True
                result.surfaces_scanned.append(
                    f"{rel} (repo-supplied ShadowScan report; self-asserted, not verified)"
                )
                self._collect(result, candidate, rel, "repo-supplied")
                break
        if not found and not result.surfaces_excluded:
            result.record_absent(
                "shadowscan-report",
                [relative_posix(candidate, project_root) for candidate in candidates],
            )
        return result

    def import_report(self, report_path: Path) -> list[AnyComponent]:
        """Load a ShadowScan report and return mapped components.

        The read is bounded and does not follow links. Records skipped inside the report
        are collected in ``import_failures``, which is reset on every call.
        """
        self.import_failures = []
        try:
            text = read_regular_text(report_path, max_bytes=REPORT_MAX_BYTES)
        except UnicodeError:
            raise ValueError("ShadowScan report is not valid UTF-8") from None
        try:
            data: object = json.loads(text)
        except json.JSONDecodeError:
            raise ValueError("ShadowScan report is not valid JSON") from None

        seen: set[str] = set()
        if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
            return self._from_cyclonedx(data, seen)
        if isinstance(data, dict) and "findings" in data:
            return self._from_native(data["findings"], seen)
        if isinstance(data, list):
            return self._from_native(data, seen)
        raise ValueError("Unrecognized ShadowScan report format")

    def _collect(self, result: ScanResult, path: Path, label: str, provenance: str) -> None:
        try:
            components = self.import_report(path)
        except OSError:
            result.record_failure(f"ShadowScan report {label} could not be read safely")
        except ValueError as exc:
            result.record_failure(f"ShadowScan report {label} was rejected: {exc}")
        else:
            for component in components:
                component.properties["nexus-symbiote:provenance"] = provenance
                result.components.append(component)
        result.scan_failures.extend(self.import_failures)

    def _from_native(self, findings: object, seen: set[str]) -> list[AnyComponent]:
        if not isinstance(findings, list):
            raise ValueError("ShadowScan findings must be a list")
        components: list[AnyComponent] = []
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                self.import_failures.append(f"ShadowScan finding {index} is not an object; skipped")
                continue
            kind = (_text(finding.get("kind")) or "").lower()
            resource = _text(finding.get("resource"))
            title = _text(finding.get("title")) or resource or "discovered-component"
            connector = _text(finding.get("connector"))
            resource_type = _text(finding.get("resource_type"))
            upstream_id = _text(finding.get("id"))
            bom_ref = _unique_ref(upstream_id or f"shadowscan:{kind}:{title}", index, seen)
            level, score = _risk_fields(finding)
            shadow = finding.get("shadow") is True

            risks = _heuristic_risks(level, score)
            if shadow:
                risks.append(_shadow_risk())
            properties: dict[str, Any] = {
                "shadowscan:kind": kind,
                "nexus-symbiote:raw-sha256": _digest(finding),
                "shadowscan:finding": {
                    "id": upstream_id,
                    "kind": kind or None,
                    "title": title,
                    "resource": resource,
                    "connector": connector,
                    "resource_type": resource_type,
                    "shadow": shadow,
                    "risk": {"level": level, "score": score},
                },
            }
            if level is not None:
                properties["shadowscan:heuristic-risk"] = level

            if kind in {"mcp-server", "mcp"} or "mcp" in (connector or "").lower():
                components.append(
                    MCPServerComponent(
                        bom_ref=bom_ref,
                        name=title,
                        source_path=resource,
                        trust_tier=TrustTier.UNKNOWN,
                        assurance_level=AssuranceLevel.DECLARED,
                        risks=risks,
                        properties=properties,
                    )
                )
            elif kind in {"local-model", "model"} or "model" in (resource_type or "").lower():
                components.append(
                    ModelComponent(
                        bom_ref=bom_ref,
                        name=title,
                        source_path=resource,
                        trust_tier=TrustTier.UNKNOWN,
                        assurance_level=AssuranceLevel.DECLARED,
                        risks=risks,
                        properties=properties,
                    )
                )
            else:
                # Default to Agent for agent, caller, app, process, etc.
                components.append(
                    AgentComponent(
                        bom_ref=bom_ref,
                        name=title,
                        source_path=resource,
                        autonomy_level=AutonomyLevel.L2_AGENT,
                        trust_tier=TrustTier.UNKNOWN,
                        assurance_level=AssuranceLevel.DECLARED,
                        risks=risks,
                        properties=properties,
                    )
                )
        return components

    def _from_cyclonedx(self, bom: dict[str, Any], seen: set[str]) -> list[AnyComponent]:
        raw_components = bom.get("components", [])
        if not isinstance(raw_components, list):
            raise ValueError("CycloneDX components must be a list")
        components: list[AnyComponent] = []
        for index, c in enumerate(raw_components):
            if not isinstance(c, dict):
                self.import_failures.append(f"CycloneDX component {index} is not an object; skipped")
                continue
            props = self._cyclonedx_properties(c, index)
            kind = props.get("shadowscan:kind", "").lower()
            name = _text(c.get("name")) or "unknown"
            bom_ref = _unique_ref(_text(c.get("bom-ref")) or f"cdx:{name}", index, seen)
            level = props.get("shadowscan:heuristic-risk", "").strip().lower() or None
            risks = _heuristic_risks(level)
            properties: dict[str, Any] = {
                "shadowscan:kind": kind,
                "nexus-symbiote:raw-sha256": _digest(c),
            }
            if level is not None:
                properties["shadowscan:heuristic-risk"] = level

            if "mcp" in kind or c.get("group") == "mcp-server":
                components.append(
                    MCPServerComponent(
                        bom_ref=bom_ref,
                        name=name,
                        trust_tier=TrustTier.UNKNOWN,
                        assurance_level=AssuranceLevel.DECLARED,
                        risks=risks,
                        properties=properties,
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
                        properties=properties,
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
                        properties=properties,
                    )
                )
        return components

    def _cyclonedx_properties(self, component: dict[str, Any], index: int) -> dict[str, str]:
        """Read the name and value pairs this importer needs. Other pairs are not copied."""
        entries = component.get("properties", [])
        props: dict[str, str] = {}
        if not isinstance(entries, list):
            self.import_failures.append(f"CycloneDX component {index} has malformed properties")
            return props
        for entry in entries:
            key = entry.get("name") if isinstance(entry, dict) else None
            value = entry.get("value") if isinstance(entry, dict) else None
            if not isinstance(key, str) or not isinstance(value, str):
                self.import_failures.append(
                    f"CycloneDX component {index} has a property without a string name or value"
                )
                continue
            props[key] = value
        return props


def _conventional_reports(root: Path) -> list[Path]:
    return [
        root / ".shadowscan" / "report.json",
        root / "shadowscan-report.json",
        root / "shadowscan.json",
    ]


def _text(value: object) -> str | None:
    """Return a non-empty string. A URL is reduced to its origin, because paths and queries may carry credentials."""
    if not isinstance(value, str) or not value:
        return None
    return sanitized_origin(value) if "://" in value else value


def _risk_fields(finding: dict[str, Any]) -> tuple[str | None, int | float | None]:
    risk = finding.get("risk")
    if not isinstance(risk, dict):
        return None, None
    level = risk.get("level")
    score = risk.get("score")
    normalized = level.strip().lower() if isinstance(level, str) else ""
    numeric = score if isinstance(score, int | float) and not isinstance(score, bool) else None
    return (normalized or None), numeric


def _heuristic_risks(level: str | None, score: int | float | None = None) -> list[RiskAssessment]:
    if level is None:
        return [_unassessed()]
    suffix = "" if score is None else f" (score {score})"
    return [
        RiskAssessment(
            severity=_UPSTREAM_LEVELS.get(level, RiskSeverity.INFO),
            category="shadowscan-heuristic",
            detail=f"ShadowScan heuristic risk {level}{suffix}",
            recommendation="Review evidence and apply independent policy.",
        )
    ]


def _unassessed() -> RiskAssessment:
    return RiskAssessment(
        severity=RiskSeverity.MEDIUM,
        category="unassessed-discovery",
        detail="ShadowScan supplied no risk level for this discovery, so it is not treated as clean.",
        recommendation="Assess this discovery before relying on the inventory.",
    )


def _shadow_risk() -> RiskAssessment:
    return RiskAssessment(
        severity=RiskSeverity.HIGH,
        category="shadow-agent",
        detail="Finding marked as shadow (not in approved inventory).",
        recommendation="Reconcile against approved agent registry.",
    )


def _digest(raw: object) -> str:
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _unique_ref(ref: str, index: int, seen: set[str]) -> str:
    """Return ``ref``, or a suffixed form when this report already used it."""
    candidate = ref
    if candidate in seen:
        candidate = f"{ref}#{index}"
    suffix = 1
    while candidate in seen:
        candidate = f"{ref}#{index}.{suffix}"
        suffix += 1
    seen.add(candidate)
    return candidate
