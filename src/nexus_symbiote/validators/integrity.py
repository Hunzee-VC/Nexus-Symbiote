"""Integrity validator — verifies hashes, signatures, and version pins."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import SerializationSafety
from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.core.models import (
    ComponentBase,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    ToolComponent,
)
from nexus_symbiote.core.vocab import (
    SIGNING_NOT_FOUND,
    SIGNING_PRESENT_UNVERIFIED,
    SIGNING_VERIFIED,
    normalize_signing_status,
)
from nexus_symbiote.utils.confined import hash_confined_file

_DEFINITION_HASH_VERSION = "rfc8785-jcs-v1"


@dataclass
class IntegrityIssue:
    component_ref: str
    category: str
    detail: str
    severity: str = "error"


@dataclass
class IntegrityReport:
    is_valid: bool = True
    components_checked: int = 0
    hashes_verified: int = 0
    hashes_failed: int = 0
    signatures_checked: int = 0
    issues: list[IntegrityIssue] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "is_valid": self.is_valid,
            "components_checked": self.components_checked,
            "hashes_verified": self.hashes_verified,
            "hashes_failed": self.hashes_failed,
            "signatures_checked": self.signatures_checked,
            "issues": [
                {
                    "component_ref": i.component_ref,
                    "category": i.category,
                    "detail": i.detail,
                    "severity": i.severity,
                }
                for i in self.issues
            ],
        }


class IntegrityValidator:
    """Verifies that AIBOM component hashes match their on-disk artifacts."""

    def validate(self, bom: AIBOM, project_root: Path | None = None) -> IntegrityReport:
        report = IntegrityReport()

        for comp in bom.components:
            report.components_checked += 1

            if isinstance(comp, ToolComponent):
                self._check_tool_hash(comp, report)
            elif isinstance(comp, ModelComponent):
                self._check_model_integrity(comp, project_root, report)
            elif isinstance(comp, PromptComponent):
                self._check_prompt_hash(comp, project_root, report)
            elif isinstance(comp, MCPServerComponent):
                self._check_mcp_version_pin(comp, report)

            self._check_file_hash(comp, project_root, report)

        return report

    def _check_tool_hash(self, comp: ToolComponent, report: IntegrityReport) -> None:
        if not comp.definition_hash:
            substantive = bool(comp.description_text) or comp.input_schema is not None
            report.issues.append(
                IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="missing_hash",
                    detail=(
                        f"Tool '{comp.name}' has no definition hash — rug-pull detection disabled."
                    ),
                    severity="error" if substantive else "warning",
                )
            )
            if substantive:
                report.is_valid = False
            return

        if comp.description_text is None:
            report.issues.append(
                IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="unverifiable_definition",
                    detail=(
                        f"Tool '{comp.name}' has a definition hash but no description text "
                        "to verify it against."
                    ),
                    severity="error",
                )
            )
            report.is_valid = False
            return

        if comp.definition_hash_version != _DEFINITION_HASH_VERSION:
            report.issues.append(
                IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="fingerprint_version_unknown",
                    detail=(
                        f"Tool '{comp.name}' fingerprint version is unknown or unsupported; "
                        "re-collect and re-approve."
                    ),
                    severity="error",
                )
            )
            report.is_valid = False
            return

        recomputed = hash_tool_definition(
            comp.name,
            comp.description_text,
            comp.input_schema,
            comp.annotations,
        )
        if recomputed != comp.definition_hash:
            report.issues.append(
                IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="hash_mismatch",
                    detail=(
                        f"Tool '{comp.name}' definition hash mismatch: "
                        f"declared={comp.definition_hash}, computed={recomputed}. "
                        "Possible rug-pull — tool definition changed post-approval."
                    ),
                    severity="error",
                )
            )
            report.hashes_failed += 1
            report.is_valid = False
        else:
            report.hashes_verified += 1

    def _check_model_integrity(
        self,
        comp: ModelComponent,
        project_root: Path | None,
        report: IntegrityReport,
    ) -> None:
        if comp.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION:
            report.issues.append(
                IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="unsafe_format",
                    detail=(
                        f"Model '{comp.name}' uses an unsafe serialization "
                        "format that allows arbitrary code execution."
                    ),
                    severity="critical",
                )
            )
            report.is_valid = False

        status = normalize_signing_status(comp.signing_status)
        if status == SIGNING_NOT_FOUND:
            report.issues.append(
                IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="unsigned_model",
                    detail=f"Model '{comp.name}' has no cryptographic signature.",
                    severity="warning",
                )
            )
        elif status == SIGNING_PRESENT_UNVERIFIED:
            report.issues.append(
                IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="unverified_signature",
                    detail=f"Model '{comp.name}' has a signature that was not verified.",
                    severity="info",
                )
            )
        elif status is not None and status != SIGNING_VERIFIED:
            report.issues.append(
                IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="unknown_signing_status",
                    detail=f"Model '{comp.name}' has an unrecognized signing status.",
                    severity="warning",
                )
            )

        if comp.trust_remote_code:
            report.issues.append(
                IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="trust_remote_code",
                    detail=(
                        f"Model '{comp.name}' requires trust_remote_code=True "
                        "— arbitrary code execution from model repo."
                    ),
                    severity="critical",
                )
            )
            report.is_valid = False

    def _check_prompt_hash(
        self,
        comp: PromptComponent,
        project_root: Path | None,
        report: IntegrityReport,
    ) -> None:
        if not comp.content_hash:
            report.issues.append(
                IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="missing_hash",
                    detail=f"Prompt '{comp.name}' has no content hash.",
                    severity="warning",
                )
            )
            return

        if not project_root:
            report.issues.append(
                IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="project_required",
                    detail="A project root is required to verify prompt content.",
                    severity="error",
                )
            )
            report.hashes_failed += 1
            report.is_valid = False
        else:
            try:
                if not comp.source_path:
                    raise OSError("missing source path")
                recomputed = hash_confined_file(project_root, comp.source_path)
                if recomputed != comp.content_hash:
                    raise OSError("content hash mismatch")
                report.hashes_verified += 1
            except OSError:
                report.issues.append(
                    IntegrityIssue(
                        component_ref=comp.bom_ref,
                        category="hash_mismatch",
                        detail=f"Prompt '{comp.name}' could not be verified within the project root.",
                        severity="error",
                    )
                )
                report.hashes_failed += 1
                report.is_valid = False

    def _check_mcp_version_pin(self, comp: MCPServerComponent, report: IntegrityReport) -> None:
        if not comp.version_pinned:
            report.issues.append(
                IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="unpinned_version",
                    detail=(
                        f"MCP server '{comp.name}' uses an unpinned package "
                        "— vulnerable to supply chain attacks."
                    ),
                    severity="warning",
                )
            )

    def _check_file_hash(
        self,
        comp: ComponentBase,
        project_root: Path | None,
        report: IntegrityReport,
    ) -> None:
        if not comp.hashes:
            return

        if not project_root:
            report.issues.append(
                IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="project_required",
                    detail="A project root is required to verify file hashes.",
                    severity="error",
                )
            )
            report.hashes_failed += len(comp.hashes)
            report.is_valid = False
            return

        for algo, declared_hash in comp.hashes.items():
            try:
                if not comp.source_path:
                    raise OSError("missing source path")
                recomputed = hash_confined_file(project_root, comp.source_path, algorithm=algo)
                if recomputed != declared_hash:
                    report.issues.append(
                        IntegrityIssue(
                            component_ref=comp.bom_ref,
                            category="file_hash_mismatch",
                            detail=(f"File hash mismatch for '{comp.name}'."),
                            severity="error",
                        )
                    )
                    report.hashes_failed += 1
                    report.is_valid = False
                else:
                    report.hashes_verified += 1
            except OSError:
                report.issues.append(
                    IntegrityIssue(
                        component_ref=comp.bom_ref,
                        category="hash_error",
                        detail=f"Could not verify '{comp.name}' within the project root.",
                        severity="error",
                    )
                )
                report.hashes_failed += 1
                report.is_valid = False
