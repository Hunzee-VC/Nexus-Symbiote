"""AIBOM diff engine — compares two AIBOMs to detect supply chain changes.

Critical for detecting rug-pull attacks, tool definition mutations,
unauthorized component additions, and trust tier downgrades.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import TrustTier

TRUST_TIER_ORDER = {
    TrustTier.INTERNAL_VERIFIED: 0,
    TrustTier.INTERNAL_UNVERIFIED: 1,
    TrustTier.THIRD_PARTY_SIGNED: 2,
    TrustTier.THIRD_PARTY_UNSIGNED: 3,
    TrustTier.UNTRUSTED_PUBLIC: 4,
    TrustTier.UNKNOWN: 5,
}


@dataclass
class ComponentChange:
    bom_ref: str
    name: str
    change_type: str  # added, removed, modified
    component_type: str
    severity: str = "info"
    details: list[str] = field(default_factory=list)


@dataclass
class DependencyChange:
    source_ref: str
    target_ref: str
    relationship: str
    change_type: str  # added, removed


@dataclass
class DiffReport:
    has_changes: bool = False
    components_added: list[ComponentChange] = field(default_factory=list)
    components_removed: list[ComponentChange] = field(default_factory=list)
    components_modified: list[ComponentChange] = field(default_factory=list)
    dependencies_added: list[DependencyChange] = field(default_factory=list)
    dependencies_removed: list[DependencyChange] = field(default_factory=list)
    security_alerts: list[dict[str, str]] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return (
            len(self.components_added)
            + len(self.components_removed)
            + len(self.components_modified)
            + len(self.dependencies_added)
            + len(self.dependencies_removed)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_changes": self.has_changes,
            "total_changes": self.total_changes,
            "components_added": [self._change_dict(c) for c in self.components_added],
            "components_removed": [self._change_dict(c) for c in self.components_removed],
            "components_modified": [self._change_dict(c) for c in self.components_modified],
            "dependencies_added": [
                {"source": d.source_ref, "target": d.target_ref, "relationship": d.relationship}
                for d in self.dependencies_added
            ],
            "dependencies_removed": [
                {"source": d.source_ref, "target": d.target_ref, "relationship": d.relationship}
                for d in self.dependencies_removed
            ],
            "security_alerts": self.security_alerts,
        }

    def _change_dict(self, c: ComponentChange) -> dict[str, Any]:
        d: dict[str, Any] = {
            "bom_ref": c.bom_ref,
            "name": c.name,
            "type": c.component_type,
            "change": c.change_type,
            "severity": c.severity,
        }
        if c.details:
            d["details"] = c.details
        return d


class AIBOMDiffer:
    """Compares two AIBOMs and reports supply chain changes."""

    def diff(self, old: AIBOM, new: AIBOM) -> DiffReport:
        report = DiffReport()

        old_map = {c.bom_ref: c for c in old.components}
        new_map = {c.bom_ref: c for c in new.components}

        old_refs = set(old_map.keys())
        new_refs = set(new_map.keys())

        for ref in sorted(new_refs - old_refs):
            comp = new_map[ref]
            change = ComponentChange(
                bom_ref=ref,
                name=comp.name,
                change_type="added",
                component_type=comp.component_type.value,
                severity="medium",
                details=[f"New {comp.component_type.value} component added."],
            )
            report.components_added.append(change)

        for ref in sorted(old_refs - new_refs):
            comp = old_map[ref]
            change = ComponentChange(
                bom_ref=ref,
                name=comp.name,
                change_type="removed",
                component_type=comp.component_type.value,
                severity="info",
                details=[f"{comp.component_type.value} component removed."],
            )
            report.components_removed.append(change)

        for ref in sorted(old_refs & new_refs):
            modifications = self._compare_components(old_map[ref], new_map[ref])
            if modifications:
                severity = max(
                    (m.get("severity", "info") for m in modifications),
                    key=lambda s: ["info", "low", "medium", "high", "critical"].index(s),
                )
                change = ComponentChange(
                    bom_ref=ref,
                    name=new_map[ref].name,
                    change_type="modified",
                    component_type=new_map[ref].component_type.value,
                    severity=severity,
                    details=[m["detail"] for m in modifications],
                )
                report.components_modified.append(change)

        self._diff_dependencies(old, new, report)
        self._generate_security_alerts(report)
        self._detect_identity_rugpull(old_map, new_map, report)

        report.has_changes = report.total_changes > 0
        return report

    @staticmethod
    def _identity(comp: Any) -> tuple[str, str, str | None]:
        """Stable identity independent of the (attacker-controlled) bom_ref."""
        return (
            comp.component_type.value,
            comp.name,
            getattr(comp, "mcp_server_ref", None) or comp.source_path,
        )

    def _detect_identity_rugpull(
        self, old_map: dict[str, Any], new_map: dict[str, Any], report: DiffReport
    ) -> None:
        """Catch a rug-pull hidden behind a bom_ref change (NS-08).

        An attacker who both mutates a tool definition and renames its bom_ref
        makes the change look like a benign remove+add. Correlate removed and
        added components by stable identity (type + name + server/source) and
        flag a changed definition/content hash as a high-severity alert.
        """
        new_by_identity: dict[tuple[str, str, str | None], list[Any]] = {}
        for change in report.components_added:
            comp = new_map[change.bom_ref]
            new_by_identity.setdefault(self._identity(comp), []).append(comp)

        for change in report.components_removed:
            old_comp = old_map[change.bom_ref]
            for new_comp in new_by_identity.get(self._identity(old_comp), []):
                for attr in ("definition_hash", "content_hash"):
                    old_hash = getattr(old_comp, attr, None)
                    new_hash = getattr(new_comp, attr, None)
                    if old_hash and new_hash and old_hash != new_hash:
                        report.security_alerts.append(
                            {
                                "severity": "high",
                                "component": new_comp.bom_ref,
                                "alert": (
                                    f"Component '{new_comp.name}' reappeared under a new "
                                    f"bom-ref ({old_comp.bom_ref} -> {new_comp.bom_ref}) with a "
                                    f"changed {attr} — possible rug-pull disguised as remove+add."
                                ),
                            }
                        )
                        break

    def _compare_components(self, old: Any, new: Any) -> list[dict[str, str]]:
        modifications: list[dict[str, str]] = []

        if old.trust_tier != new.trust_tier:
            old_rank = TRUST_TIER_ORDER.get(old.trust_tier, 5)
            new_rank = TRUST_TIER_ORDER.get(new.trust_tier, 5)
            if new_rank > old_rank:
                modifications.append(
                    {
                        "detail": (
                            f"Trust tier downgraded: "
                            f"{old.trust_tier.value} → {new.trust_tier.value}"
                        ),
                        "severity": "high",
                    }
                )
            else:
                modifications.append(
                    {
                        "detail": (
                            f"Trust tier upgraded: {old.trust_tier.value} → {new.trust_tier.value}"
                        ),
                        "severity": "info",
                    }
                )

        if old.version != new.version:
            modifications.append(
                {
                    "detail": f"Version changed: {old.version} → {new.version}",
                    "severity": "medium",
                }
            )

        old_hash = getattr(old, "definition_hash", None)
        new_hash = getattr(new, "definition_hash", None)
        old_hash_version = getattr(old, "definition_hash_version", None)
        new_hash_version = getattr(new, "definition_hash_version", None)
        if (
            old_hash
            and new_hash
            and (old_hash_version != "rfc8785-jcs-v1" or new_hash_version != "rfc8785-jcs-v1")
        ):
            modifications.append(
                {
                    "detail": "Tool fingerprint versions are unknown or incompatible; re-collect and re-approve.",
                    "severity": "high",
                }
            )
        elif old_hash and new_hash and old_hash != new_hash:
            modifications.append(
                {
                    "detail": "Tool definition hash changed — possible rug-pull attack.",
                    "severity": "critical",
                }
            )

        elif old_hash and not new_hash:
            modifications.append(
                {
                    "detail": "Tool definition hash missing — assurance regressed; content is unknown.",
                    "severity": "high",
                }
            )
        elif not old_hash and new_hash:
            modifications.append(
                {"detail": "Tool definition hash became available.", "severity": "info"}
            )

        old_content = getattr(old, "content_hash", None)
        new_content = getattr(new, "content_hash", None)
        if old_content and new_content and old_content != new_content:
            modifications.append(
                {
                    "detail": "Prompt content hash changed.",
                    "severity": "medium",
                }
            )

        for hash_key in set(old.hashes.keys()) | set(new.hashes.keys()):
            old_h = old.hashes.get(hash_key)
            new_h = new.hashes.get(hash_key)
            if old_h and new_h and old_h != new_h:
                modifications.append(
                    {
                        "detail": f"File hash ({hash_key}) changed.",
                        "severity": "high",
                    }
                )

        old_pinned = getattr(old, "version_pinned", None)
        new_pinned = getattr(new, "version_pinned", None)
        if old_pinned is True and new_pinned is False:
            modifications.append(
                {
                    "detail": "Version pin removed — now floating.",
                    "severity": "high",
                }
            )

        old_safety = getattr(old, "serialization_safety", None)
        new_safety = getattr(new, "serialization_safety", None)
        if old_safety and new_safety and old_safety != new_safety:
            modifications.append(
                {
                    "detail": f"Serialization safety changed: {old_safety.value} → {new_safety.value}",
                    "severity": "high",
                }
            )

        old_signing = getattr(old, "signing_status", None)
        new_signing = getattr(new, "signing_status", None)
        if old_signing != new_signing:
            sev = "high" if old_signing in {"sigstore-signed", "pgp-signed"} else "info"
            modifications.append(
                {
                    "detail": f"Signing status changed: {old_signing} → {new_signing}",
                    "severity": sev,
                }
            )

        return modifications

    def _diff_dependencies(self, old: AIBOM, new: AIBOM, report: DiffReport) -> None:
        old_deps = {(d.source_ref, d.target_ref, d.relationship) for d in old.dependencies}
        new_deps = {(d.source_ref, d.target_ref, d.relationship) for d in new.dependencies}

        for src, tgt, rel in sorted(new_deps - old_deps):
            report.dependencies_added.append(
                DependencyChange(
                    source_ref=src,
                    target_ref=tgt,
                    relationship=rel,
                    change_type="added",
                )
            )

        for src, tgt, rel in sorted(old_deps - new_deps):
            report.dependencies_removed.append(
                DependencyChange(
                    source_ref=src,
                    target_ref=tgt,
                    relationship=rel,
                    change_type="removed",
                )
            )

    def _generate_security_alerts(self, report: DiffReport) -> None:
        for change in report.components_modified:
            if change.severity in ("critical", "high"):
                report.security_alerts.append(
                    {
                        "severity": change.severity,
                        "component": change.bom_ref,
                        "alert": (
                            f"{change.severity.title()} change in '{change.name}': "
                            f"{'; '.join(change.details)}"
                        ),
                    }
                )

        for change in report.components_added:
            report.security_alerts.append(
                {
                    "severity": "medium",
                    "component": change.bom_ref,
                    "alert": (
                        f"New component '{change.name}' "
                        f"({change.component_type}) added to supply chain."
                    ),
                }
            )
