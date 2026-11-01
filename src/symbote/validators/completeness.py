"""Completeness validator — checks that an AIBOM covers all expected surfaces."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from symbote.core.aibom import AIBOM
from symbote.core.enums import AssuranceLevel, ComponentType

EXPECTED_SURFACES = {
    "mcp-config": "MCP server configuration (.mcp.json etc.)",
    "model-weights": "Model weight files and signing status",
    "prompts": "System prompts and instruction files",
    "rag-sources": "RAG / vector store configurations",
    "registry-trust": "Package registry trust and pinning",
    "tools": "Tool definitions with capability hashes",
}

MINIMUM_COMPONENT_TYPES = {
    ComponentType.MCP_SERVER,
    ComponentType.TOOL,
    ComponentType.PROMPT_TEMPLATE,
}


@dataclass
class CompletenessIssue:
    surface: str
    description: str
    severity: str = "warning"


@dataclass
class CompletenessReport:
    is_complete: bool = True
    surfaces_covered: list[str] = field(default_factory=list)
    surfaces_missing: list[str] = field(default_factory=list)
    issues: list[CompletenessIssue] = field(default_factory=list)
    assurance_level: AssuranceLevel = AssuranceLevel.DECLARED
    component_type_coverage: dict[str, int] = field(default_factory=dict)
    total_components: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "is_complete": self.is_complete,
            "surfaces_covered": self.surfaces_covered,
            "surfaces_missing": self.surfaces_missing,
            "issues": [
                {"surface": i.surface, "description": i.description, "severity": i.severity}
                for i in self.issues
            ],
            "assurance_level": self.assurance_level.value,
            "component_type_coverage": self.component_type_coverage,
            "total_components": self.total_components,
        }


class CompletenessValidator:
    """Validates that an AIBOM covers all expected attack surfaces."""

    def validate(self, bom: AIBOM) -> CompletenessReport:
        report = CompletenessReport()
        report.total_components = len(bom.components)

        type_counts: dict[str, int] = {}
        for c in bom.components:
            key = c.component_type.value
            type_counts[key] = type_counts.get(key, 0) + 1
        report.component_type_coverage = type_counts

        if bom.metadata.completeness:
            report.surfaces_covered = list(bom.metadata.completeness.surfaces_scanned)
            report.surfaces_missing = list(bom.metadata.completeness.surfaces_excluded)
            report.assurance_level = bom.metadata.completeness.assurance_level
        else:
            report.issues.append(
                CompletenessIssue(
                    surface="metadata",
                    description="AIBOM has no completeness claim — cannot assess coverage.",
                    severity="error",
                )
            )
            report.is_complete = False

        if bom.metadata.completeness:
            claim = bom.metadata.completeness
            if claim.scan_failures:
                report.is_complete = False
                for failure in claim.scan_failures:
                    report.issues.append(CompletenessIssue("collection", failure, "error"))
            if not claim.scanner_status:
                report.is_complete = False
                report.issues.append(
                    CompletenessIssue(
                        "coverage",
                        "No per-scanner coverage recorded; completeness is unknown.",
                        "error",
                    )
                )
            for scanner, state in claim.scanner_status.items():
                if state != "complete":
                    report.is_complete = False
                    report.issues.append(
                        CompletenessIssue(scanner, f"Scanner coverage is {state}.", "error")
                    )

        for c in bom.components:
            if not c.hashes and c.component_type in (
                ComponentType.MODEL,
                ComponentType.TOOL,
                ComponentType.PROMPT_TEMPLATE,
            ):
                if not (hasattr(c, "content_hash") and c.content_hash):
                    if not (hasattr(c, "definition_hash") and c.definition_hash):
                        report.issues.append(
                            CompletenessIssue(
                                surface=c.bom_ref,
                                description=f"Component '{c.name}' has no integrity hash.",
                                severity="warning",
                            )
                        )

        orphan_refs = self._find_orphan_refs(bom)
        for ref, field_name in orphan_refs:
            report.issues.append(
                CompletenessIssue(
                    surface=ref,
                    description=f"Reference '{ref}' in '{field_name}' points to no component.",
                    severity="error",
                )
            )
            report.is_complete = False

        if report.surfaces_missing:
            for surface in report.surfaces_missing:
                for key, _desc in EXPECTED_SURFACES.items():
                    if key in surface.lower():
                        report.issues.append(
                            CompletenessIssue(
                                surface=key,
                                description=f"Surface excluded: {surface}",
                                severity="info",
                            )
                        )

        return report

    def validate_against_project(self, bom: AIBOM, project_root: Path) -> CompletenessReport:
        report = self.validate(bom)

        from symbote.scanners.mcp import MCP_CONFIG_FILES
        from symbote.scanners.prompt import INSTRUCTION_FILES

        has_mcp = any((project_root / f).exists() for f in MCP_CONFIG_FILES)
        has_prompt = any((project_root / f).exists() for f in INSTRUCTION_FILES)
        has_models = any(
            f.suffix.lower() in (".safetensors", ".pt", ".pth", ".gguf", ".onnx", ".pkl")
            for f in project_root.rglob("*")
            if ".git" not in f.parts
        )

        bom_types = {c.component_type for c in bom.components}

        if has_mcp and ComponentType.MCP_SERVER not in bom_types:
            report.issues.append(
                CompletenessIssue(
                    surface="mcp-config",
                    description="Project has MCP config files but AIBOM has no MCP server components.",
                    severity="error",
                )
            )
            report.is_complete = False

        if has_prompt and ComponentType.PROMPT_TEMPLATE not in bom_types:
            report.issues.append(
                CompletenessIssue(
                    surface="prompts",
                    description="Project has instruction files but AIBOM has no prompt components.",
                    severity="error",
                )
            )
            report.is_complete = False

        if has_models and ComponentType.MODEL not in bom_types:
            report.issues.append(
                CompletenessIssue(
                    surface="model-weights",
                    description="Project has model files but AIBOM has no model components.",
                    severity="error",
                )
            )
            report.is_complete = False

        return report

    def _find_orphan_refs(self, bom: AIBOM) -> list[tuple[str, str]]:
        all_refs = {c.bom_ref for c in bom.components}
        orphans: list[tuple[str, str]] = []

        for dep in bom.dependencies:
            if dep.source_ref not in all_refs:
                orphans.append((dep.source_ref, "dependency.source_ref"))
            if dep.target_ref not in all_refs:
                orphans.append((dep.target_ref, "dependency.target_ref"))

        for c in bom.components:
            for ref_field in (
                "model_refs",
                "tool_refs",
                "memory_refs",
                "prompt_refs",
                "guardrail_refs",
                "sub_agent_refs",
            ):
                refs = getattr(c, ref_field, None)
                if refs:
                    for ref in refs:
                        if ref not in all_refs:
                            orphans.append((ref, f"{c.bom_ref}.{ref_field}"))

            for ref_field in (
                "mcp_server_ref",
                "model_ref",
                "embedding_model_ref",
                "registry_ref",
                "base_model_ref",
            ):
                ref = getattr(c, ref_field, None)
                if ref and ref not in all_refs:
                    orphans.append((ref, f"{c.bom_ref}.{ref_field}"))

        return orphans
