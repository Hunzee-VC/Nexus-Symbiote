"""Integrity validator — verifies hashes, signatures, and version pins."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from symbote.core.aibom import AIBOM
from symbote.core.enums import ComponentType, SerializationSafety
from symbote.core.hashing import hash_file, hash_tool_definition


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

            if comp.component_type == ComponentType.TOOL:
                self._check_tool_hash(comp, report)
            elif comp.component_type == ComponentType.MODEL:
                self._check_model_integrity(comp, project_root, report)
            elif comp.component_type == ComponentType.PROMPT_TEMPLATE:
                self._check_prompt_hash(comp, project_root, report)
            elif comp.component_type == ComponentType.MCP_SERVER:
                self._check_mcp_version_pin(comp, report)

            self._check_file_hash(comp, project_root, report)

        return report

    def _check_tool_hash(self, comp, report: IntegrityReport) -> None:  # type: ignore[no-untyped-def]
        if not hasattr(comp, "definition_hash") or not comp.definition_hash:
            report.issues.append(IntegrityIssue(
                component_ref=comp.bom_ref,
                category="missing_hash",
                detail=f"Tool '{comp.name}' has no definition hash — rug-pull detection disabled.",
                severity="warning",
            ))
            return

        if hasattr(comp, "description_text") and comp.description_text is not None:
            recomputed = hash_tool_definition(
                comp.name,
                comp.description_text,
                getattr(comp, "input_schema", None),
                getattr(comp, "annotations", None) or None,
            )
            if recomputed != comp.definition_hash:
                report.issues.append(IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="hash_mismatch",
                    detail=(
                        f"Tool '{comp.name}' definition hash mismatch: "
                        f"declared={comp.definition_hash}, computed={recomputed}. "
                        "Possible rug-pull — tool definition changed post-approval."
                    ),
                    severity="error",
                ))
                report.hashes_failed += 1
                report.is_valid = False
            else:
                report.hashes_verified += 1

    def _check_model_integrity(  # type: ignore[no-untyped-def]
        self, comp, project_root: Path | None, report: IntegrityReport,
    ) -> None:
        if hasattr(comp, "serialization_safety"):
            if comp.serialization_safety == SerializationSafety.UNSAFE_CODE_EXECUTION:
                report.issues.append(IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="unsafe_format",
                    detail=(
                        f"Model '{comp.name}' uses an unsafe serialization "
                        "format that allows arbitrary code execution."
                    ),
                    severity="critical",
                ))

        if hasattr(comp, "signing_status") and comp.signing_status == "unsigned":
            report.issues.append(IntegrityIssue(
                component_ref=comp.bom_ref,
                category="unsigned_model",
                detail=f"Model '{comp.name}' has no cryptographic signature.",
                severity="warning",
            ))

        if hasattr(comp, "trust_remote_code") and comp.trust_remote_code:
            report.issues.append(IntegrityIssue(
                component_ref=comp.bom_ref,
                category="trust_remote_code",
                detail=(
                    f"Model '{comp.name}' requires trust_remote_code=True "
                    "— arbitrary code execution from model repo."
                ),
                severity="critical",
            ))
            report.is_valid = False

    def _check_prompt_hash(  # type: ignore[no-untyped-def]
        self, comp, project_root: Path | None, report: IntegrityReport,
    ) -> None:
        if not hasattr(comp, "content_hash") or not comp.content_hash:
            report.issues.append(IntegrityIssue(
                component_ref=comp.bom_ref,
                category="missing_hash",
                detail=f"Prompt '{comp.name}' has no content hash.",
                severity="warning",
            ))
            return

        if project_root and comp.source_path:
            path = Path(comp.source_path)
            if not path.is_absolute():
                path = project_root / path
            if path.exists():
                recomputed = hash_file(path)
                if recomputed != comp.content_hash:
                    report.issues.append(IntegrityIssue(
                        component_ref=comp.bom_ref,
                        category="hash_mismatch",
                        detail=(
                            f"Prompt '{comp.name}' content hash mismatch "
                            "— file changed since scan."
                        ),
                        severity="error",
                    ))
                    report.hashes_failed += 1
                    report.is_valid = False
                else:
                    report.hashes_verified += 1

    def _check_mcp_version_pin(self, comp, report: IntegrityReport) -> None:  # type: ignore[no-untyped-def]
        if hasattr(comp, "version_pinned") and not comp.version_pinned:
            report.issues.append(IntegrityIssue(
                component_ref=comp.bom_ref,
                category="unpinned_version",
                detail=(
                    f"MCP server '{comp.name}' uses an unpinned package "
                    "— vulnerable to supply chain attacks."
                ),
                severity="warning",
            ))

    def _check_file_hash(  # type: ignore[no-untyped-def]
        self, comp, project_root: Path | None, report: IntegrityReport,
    ) -> None:
        if not project_root or not comp.source_path:
            return
        if not comp.hashes:
            return

        path = Path(comp.source_path)
        if not path.is_absolute():
            path = project_root / path
        if not path.exists():
            return

        for algo, declared_hash in comp.hashes.items():
            try:
                recomputed = hash_file(path, algorithm=algo)
                if recomputed != declared_hash:
                    report.issues.append(IntegrityIssue(
                        component_ref=comp.bom_ref,
                        category="file_hash_mismatch",
                        detail=(
                            f"File hash mismatch for '{comp.name}': "
                            f"declared={declared_hash}, "
                            f"computed={recomputed}."
                        ),
                        severity="error",
                    ))
                    report.hashes_failed += 1
                    report.is_valid = False
                else:
                    report.hashes_verified += 1
            except OSError:
                report.issues.append(IntegrityIssue(
                    component_ref=comp.bom_ref,
                    category="hash_error",
                    detail=f"Could not read '{path}' to verify hash.",
                    severity="warning",
                ))
