"""Dual-axis AI-BOM quality scoring: ``structure_score`` vs ``completeness_score``.

Separates structural/schema validity from substantive provenance and security documentation
so a schema-valid but undocumented AI-BOM scores high on ``structure_score`` and low on
``completeness_score`` with an explicit per-component ``missing_fields`` checklist.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, SerializationSafety
from nexus_symbiote.core.models import (
    AgentComponent,
    AnyComponent,
    DataSourceComponent,
    IDEAgentComponent,
    MCPClientComponent,
    MCPServerComponent,
    ModelComponent,
    ToolComponent,
)
from nexus_symbiote.model_policy import extract_model_licenses, model_has_pinned_revision

COMPLETENESS_FORMAT = "nexus-symbiote/completeness-score/v1"
_UNKNOWN_STRINGS = frozenset({"", "unknown", "none", "n/a", "na", "noassertion", "unspecified"})


@dataclass(frozen=True)
class ComponentScore:
    """Dual-axis quality breakdown for one AgentBOM component."""

    bom_ref: str
    component_type: str
    name: str
    structure_score: float
    completeness_score: float
    checks_passed: int
    checks_total: int
    structural_issues: tuple[str, ...]
    missing_fields: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CompletenessReport:
    """Overall dual-axis AI-BOM structure and completeness report."""

    structure_score: float
    completeness_score: float
    quality_gap: float
    verdict: Literal["complete", "structurally_valid_but_incomplete", "structurally_invalid"]
    component_count: int
    dangling_dependency_edges: tuple[str, ...]
    components: tuple[ComponentScore, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": COMPLETENESS_FORMAT,
            "structure_score": self.structure_score,
            "completeness_score": self.completeness_score,
            "quality_gap": self.quality_gap,
            "verdict": self.verdict,
            "component_count": self.component_count,
            "dangling_dependency_edge_count": len(self.dangling_dependency_edges),
            "dangling_dependency_edges": list(self.dangling_dependency_edges),
            "components": [c.to_dict() for c in self.components],
        }


def _known_str(value: str | None) -> bool:
    return isinstance(value, str) and value.strip().lower() not in _UNKNOWN_STRINGS


def _has_evidence(comp: AnyComponent) -> bool:
    return comp.assurance_level in {AssuranceLevel.OBSERVED, AssuranceLevel.VERIFIED} or bool(
        comp.claims
    )


def _outbound_refs(comp: AnyComponent) -> list[tuple[str, str]]:
    refs: list[tuple[str, str]] = []
    if isinstance(comp, AgentComponent):
        for field in (
            "model_refs",
            "tool_refs",
            "memory_refs",
            "prompt_refs",
            "guardrail_refs",
            "sub_agent_refs",
            "data_refs",
            "skill_refs",
        ):
            refs.extend((field, r) for r in getattr(comp, field))
    elif isinstance(comp, MCPServerComponent):
        refs.extend(("tool_refs", r) for r in comp.tool_refs)
    elif isinstance(comp, ToolComponent) and comp.mcp_server_ref:
        refs.append(("mcp_server_ref", comp.mcp_server_ref))
    elif isinstance(comp, ModelComponent) and comp.base_model_ref:
        refs.append(("base_model_ref", comp.base_model_ref))
    elif isinstance(comp, MCPClientComponent):
        refs.extend(("server_refs", r) for r in comp.server_refs)
    elif isinstance(comp, IDEAgentComponent):
        refs.extend(("mcp_server_refs", r) for r in comp.mcp_server_refs)
        refs.extend(("prompt_refs", r) for r in comp.prompt_refs)
    return refs


def _completeness_checks(comp: AnyComponent) -> list[tuple[str, bool]]:
    props = comp.properties if isinstance(comp.properties, dict) else {}
    if isinstance(comp, ModelComponent):
        pinned, _ = model_has_pinned_revision(comp)
        has_digest = bool(
            comp.hashes.get("sha256") or comp.safetensors_header_hash or comp.tensor_inventory_hash
        )
        has_card = _known_str(comp.description) or _known_str(
            props.get("model_card") if isinstance(props.get("model_card"), str) else None
        )
        return [
            ("pinned_revision", pinned),
            ("cryptographic_digest", has_digest),
            ("provider_or_supplier", _known_str(comp.provider) or _known_str(comp.supplier)),
            ("license", bool(extract_model_licenses(comp))),
            ("model_type", _known_str(comp.model_type)),
            (
                "serialization_format",
                _known_str(comp.serialization_format)
                and comp.serialization_safety != SerializationSafety.UNKNOWN,
            ),
            ("trust_remote_code_declared", comp.trust_remote_code is not None),
            ("description_or_model_card", has_card),
            ("source_locator", _known_str(comp.source_path) or _known_str(comp.endpoint)),
            ("evidence_assurance", _has_evidence(comp)),
        ]
    if isinstance(comp, MCPServerComponent):
        return [
            ("transport", _known_str(comp.transport)),
            (
                "pinned_package_or_version",
                comp.version_pinned is True or _known_str(comp.package_url),
            ),
            ("schema_hash", _known_str(comp.schema_hash)),
            ("declared_tools", comp.tool_count > 0 or bool(comp.tool_refs)),
            ("supplier_or_source", _known_str(comp.supplier) or _known_str(comp.source_path)),
            ("evidence_assurance", _has_evidence(comp)),
        ]
    if isinstance(comp, ToolComponent):
        return [
            ("mcp_server_ref", _known_str(comp.mcp_server_ref)),
            ("description_text", _known_str(comp.description_text) or _known_str(comp.description)),
            ("input_schema", isinstance(comp.input_schema, dict) and bool(comp.input_schema)),
            ("definition_hash", _known_str(comp.definition_hash)),
            ("annotations", bool(comp.annotations)),
            ("evidence_assurance", _has_evidence(comp)),
        ]
    if isinstance(comp, AgentComponent):
        return [
            ("framework", _known_str(comp.framework)),
            ("model_or_tool_refs", bool(comp.model_refs) or bool(comp.tool_refs)),
            ("autonomy_level", comp.autonomy_level is not None),
            ("capabilities", comp.capabilities is not None),
            ("workload_identity", _known_str(comp.workload_identity)),
            ("source_path", _known_str(comp.source_path)),
            ("evidence_assurance", _has_evidence(comp)),
        ]
    if isinstance(comp, DataSourceComponent):
        return [
            ("dataset_type", _known_str(comp.dataset_type)),
            ("source_uri", _known_str(comp.source_uri)),
            ("content_hash", _known_str(comp.content_hash) or bool(comp.hashes)),
            ("license", _known_str(comp.license)),
            ("consent_status", _known_str(comp.consent_status)),
            ("evidence_assurance", _has_evidence(comp)),
        ]
    return [
        ("version", _known_str(comp.version)),
        ("supplier", _known_str(comp.supplier)),
        ("description", _known_str(comp.description)),
        ("hashes", bool(comp.hashes)),
        ("source_path", _known_str(comp.source_path)),
        ("evidence_assurance", _has_evidence(comp)),
    ]


def score_aibom_completeness(bom: AIBOM) -> CompletenessReport:
    """Compute deterministic dual-axis structure and completeness scores in linear O(V + E) time."""
    all_refs: set[str] = set()
    dup_refs: set[str] = set()
    for comp in bom.components:
        if comp.bom_ref in all_refs:
            dup_refs.add(comp.bom_ref)
        all_refs.add(comp.bom_ref)

    dangling_edges: list[str] = []
    for edge in bom.dependencies:
        if edge.source_ref not in all_refs or edge.target_ref not in all_refs:
            dangling_edges.append(f"{edge.source_ref}->{edge.target_ref}")
    dangling_edges.sort()

    scores: list[ComponentScore] = []
    for comp in sorted(bom.components, key=lambda c: c.bom_ref):
        struct_issues: list[str] = []
        if not comp.bom_ref.strip():
            struct_issues.append("empty_bom_ref")
        if comp.bom_ref in dup_refs:
            struct_issues.append(f"duplicate_bom_ref:{comp.bom_ref}")
        if not comp.name.strip():
            struct_issues.append("empty_name")
        for field, ref in _outbound_refs(comp):
            if ref not in all_refs:
                struct_issues.append(f"dangling_ref:{field}:{ref}")
        struct_score = max(0.0, round(100.0 - 25.0 * len(struct_issues), 2))

        checks = _completeness_checks(comp)
        passed = sum(1 for _, ok in checks if ok)
        total = len(checks)
        missing = tuple(name for name, ok in checks if not ok)
        comp_score = round((passed / total) * 100.0, 2) if total else 0.0
        scores.append(
            ComponentScore(
                bom_ref=comp.bom_ref,
                component_type=comp.component_type.value,
                name=comp.name,
                structure_score=struct_score,
                completeness_score=comp_score,
                checks_passed=passed,
                checks_total=total,
                structural_issues=tuple(sorted(struct_issues)),
                missing_fields=missing,
            )
        )

    if scores:
        avg_struct = sum(c.structure_score for c in scores) / len(scores)
        edge_penalty = min(50.0, 15.0 * len(dangling_edges))
        overall_struct = max(0.0, round(avg_struct - edge_penalty, 2))
        overall_comp = round(sum(c.completeness_score for c in scores) / len(scores), 2)
    else:
        overall_struct = (
            100.0 if not dangling_edges else max(0.0, 100.0 - 25.0 * len(dangling_edges))
        )
        overall_comp = 0.0

    gap = round(overall_struct - overall_comp, 2)
    if overall_struct < 80.0:
        verdict: Literal[
            "complete", "structurally_valid_but_incomplete", "structurally_invalid"
        ] = "structurally_invalid"
    elif overall_comp >= 80.0:
        verdict = "complete"
    else:
        verdict = "structurally_valid_but_incomplete"

    return CompletenessReport(
        structure_score=overall_struct,
        completeness_score=overall_comp,
        quality_gap=gap,
        verdict=verdict,
        component_count=len(scores),
        dangling_dependency_edges=tuple(dangling_edges),
        components=tuple(scores),
    )
