"""Integrity checks with explicit pass, fail and unavailable-evidence outcomes."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import SerializationSafety
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    hash_tool_definition,
    normalize_digest,
)
from nexus_symbiote.core.models import (
    AnyComponent,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    ToolComponent,
)
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import (
    ModelPackages,
    memoized,
    unused_policy_entries,
    verify_weight_files,
)
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.crypto import (
    ArtifactPolicy,
    SigstoreArtifactPolicy,
    policy_entries,
    verify_file_hash,
    verify_sigstore_bundle,
)


@dataclass
class IntegrityIssue:
    component_ref: str
    category: str
    detail: str
    severity: str = "error"


@dataclass
class IntegrityReport:
    components_checked: int = 0
    hashes_verified: int = 0
    hashes_failed: int = 0
    signatures_checked: int = 0
    signatures_verified: int = 0
    issues: list[IntegrityIssue] = field(default_factory=list)

    @property
    def status(self) -> Literal["pass", "fail", "unknown"]:
        if any(i.severity in {"critical", "error"} for i in self.issues):
            return "fail"
        if any(i.severity == "unknown" for i in self.issues):
            return "unknown"
        if self.hashes_verified + self.signatures_verified == 0:
            return "unknown"
        return "pass"

    @property
    def is_valid(self) -> bool:
        """Compatibility gate: unknown evidence never produces a passing verdict."""
        return self.status == "pass"

    def to_dict(self) -> dict[str, object]:
        return {
            "is_valid": self.is_valid,
            "status": self.status,
            "components_checked": self.components_checked,
            "hashes_verified": self.hashes_verified,
            "hashes_failed": self.hashes_failed,
            "signatures_checked": self.signatures_checked,
            "signatures_verified": self.signatures_verified,
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
    """Check manifest consistency and scoped artifacts, not runtime admission.

    Signature policies must come from the trusted caller. BOM signing_status and
    signing_identity fields, and adjacent signature filenames, are never trusted
    as verification evidence. Model signatures are required by default.
    """

    def __init__(
        self,
        signature_policies: Sequence[SigstoreArtifactPolicy] = (),
        *,
        require_model_signatures: bool = True,
    ) -> None:
        # Digest pins arrive with the Sigstore entries of a loaded policy set.
        self._signature_policies: dict[Path, ArtifactPolicy] = {
            p.artifact_path.resolve(): p for p in policy_entries(signature_policies)
        }
        self._packages: tuple[IntegrityReport, ModelPackages] | None = None
        self.require_model_signatures = require_model_signatures

    def validate(
        self,
        bom: AIBOM,
        project_root: Path | None = None,
        *,
        exclude_paths: Sequence[str] = (),
    ) -> IntegrityReport:
        report = IntegrityReport()
        local_tools: dict[str, ToolComponent | None] = {}
        if project_root is not None and any(isinstance(c, ToolComponent) for c in bom.components):
            # Resolve configuration only inside the operator's root. Never use a BOM-supplied
            # descriptor path or launch a server to corroborate omitted instance values.
            scanner = MCPScanner()
            scanner.configure(exclude_paths)
            for local in scanner.scan(project_root, config_only=True).components:
                if isinstance(local, ToolComponent):
                    local_tools[local.bom_ref] = None if local.bom_ref in local_tools else local
        for comp in bom.components:
            report.components_checked += 1
            if isinstance(comp, ToolComponent):
                self._check_tool_hash(comp, report, local_tools)
            elif isinstance(comp, ModelComponent):
                self._check_model_integrity(comp, project_root, report)
                self._check_tensor_metadata(comp, project_root, report)
            elif isinstance(comp, PromptComponent):
                self._check_prompt_hash(comp, project_root, report)
            elif isinstance(comp, MCPServerComponent) and comp.version_pinned is False:
                report.issues.append(
                    IntegrityIssue(
                        comp.bom_ref,
                        "unpinned_version",
                        "MCP package version is not pinned",
                        "warning",
                    )
                )
            if isinstance(comp, MCPServerComponent) and comp.endpoint_url:
                try:
                    if comp.schema_hash is None:
                        raise ValueError("descriptor digest is unavailable")
                    normalize_digest(comp.schema_hash, "sha256")
                except ValueError:
                    report.issues.append(
                        IntegrityIssue(
                            comp.bom_ref,
                            "unpinned_remote_server",
                            "Remote MCP descriptor digest is unavailable or malformed; endpoint identity and behavior remain unverified",
                            "warning",
                        )
                    )
            self._check_file_hash(comp, project_root, report)
        self._report_unused_policies(project_root, report)
        return report

    def _check_tensor_metadata(
        self, comp: ModelComponent, project_root: Path | None, report: IntegrityReport
    ) -> None:
        declared = {
            "tensor_inventory_sha256": comp.tensor_inventory_hash,
            "safetensors_header_sha256": comp.safetensors_header_hash,
        }
        declared = {key: value for key, value in declared.items() if value is not None}
        if not declared:
            return
        try:
            if project_root is None or comp.source_path is None:
                raise ValueError("project root and artifact path are required")
            expected_weight = comp.hashes.get("sha256")
            if not expected_weight:
                raise ValueError("tensor metadata requires a whole-artifact SHA-256 binding")
            algorithm, hex_digest = normalize_digest(expected_weight, "sha256")
            root = project_root.resolve()
            source = Path(comp.source_path)
            # The integrity check's observation of the same file; the artifact is
            # read once per validation.
            observation = self._model_packages(report, root).observation(
                source.relative_to(root) if source.is_absolute() else source
            )
            if (
                observation is None
                or observation.safety != SerializationSafety.SAFE
                or not observation.fingerprint
            ):
                raise ValueError("SafeTensors metadata could not be corroborated")
            if observation.digest != f"{algorithm}:{hex_digest}":
                raise ValueError("Tensor metadata belongs to different artifact bytes")
            live = observation.fingerprint
            for key, expected in declared.items():
                assert expected is not None
                normalize_digest(expected, "sha256")
                if live[key] != expected:
                    raise ValueError("tensor metadata differs from the declared fingerprint")
                report.hashes_verified += 1
        except (OSError, ValueError, RecursionError):
            report.hashes_failed += 1
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "tensor_metadata_unverified",
                    "Declared tensor metadata cannot be corroborated within the supplied root",
                )
            )

    def _check_tool_hash(
        self,
        comp: ToolComponent,
        report: IntegrityReport,
        local_tools: dict[str, ToolComponent | None],
    ) -> None:
        if not comp.definition_hash:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref, "missing_hash", "Tool definition digest is unavailable", "unknown"
                )
            )
            return
        if comp.definition_hash_version != TOOL_DEFINITION_HASH_VERSION:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "fingerprint_version_unknown",
                    "Tool fingerprint protocol is unknown or legacy; re-collect and re-approve",
                )
            )
            return
        if comp.description_text is None:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "missing_definition",
                    "Model-visible tool description is unavailable",
                    "unknown",
                )
            )
            return
        try:
            algorithm, expected = normalize_digest(comp.definition_hash, "sha256")
            recomputed = hash_tool_definition(
                comp.name, comp.description_text, comp.input_schema, comp.annotations
            )
            raw_hash = f"{algorithm}:{expected}"
            if recomputed != (comp.redacted_definition_hash or raw_hash):
                raise ValueError("Tool definition differs from its declared digest")
            if comp.bom_ref in local_tools:
                local = local_tools[comp.bom_ref]
                if (
                    local is None
                    or comp.mcp_server_ref != local.mcp_server_ref
                    or raw_hash != local.definition_hash
                    or comp.redacted_definition_hash != local.redacted_definition_hash
                ):
                    raise ValueError("Tool fingerprint differs from its local configuration")
            elif comp.redacted_definition_hash is not None:
                report.issues.append(
                    IntegrityIssue(
                        comp.bom_ref,
                        "descriptor_source_unavailable",
                        "Redacted representation matches; original descriptor requires matching source evidence",
                        "unknown",
                    )
                )
                return
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            report.hashes_failed += 1
            report.issues.append(IntegrityIssue(comp.bom_ref, "hash_mismatch", str(exc)))
        else:
            report.hashes_verified += 1

    def _artifact_path(
        self, comp: AnyComponent, project_root: Path | None, report: IntegrityReport
    ) -> Path | None:
        if project_root is None or not comp.source_path:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "artifact_unavailable",
                    "A project root and artifact path are required",
                    "unknown",
                )
            )
            return None
        root = project_root.resolve()
        candidate = Path(comp.source_path)
        if ".." in candidate.parts:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref, "missing_artifact", "Parent traversal is not permitted"
                )
            )
            return None
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            if candidate.is_symlink() or not candidate.resolve().is_relative_to(root):
                raise ValueError("Artifact path escapes the supplied project root or is a symlink")
            if not candidate.is_file():
                raise ValueError("Declared artifact is missing or is not a regular file")
        except (OSError, ValueError) as exc:
            report.issues.append(IntegrityIssue(comp.bom_ref, "missing_artifact", str(exc)))
            return None
        return candidate

    def _check_model_integrity(
        self, comp: ModelComponent, project_root: Path | None, report: IntegrityReport
    ) -> None:
        if comp.serialization_safety in {
            SerializationSafety.UNSAFE_CODE_EXECUTION,
            SerializationSafety.UNSAFE_TEMPLATE_INJECTION,
        }:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "unsafe_format",
                    "Declared model loading format permits unsafe behavior",
                    "critical",
                )
            )
        if comp.trust_remote_code:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "trust_remote_code",
                    "Model loading permits repository code execution",
                    "critical",
                )
            )
        path = self._artifact_path(comp, project_root, report)
        if path is None or project_root is None:
            self._unsigned_model(comp, report)
            return
        root = project_root.resolve()
        packages = self._model_packages(report, root)
        try:
            relative = path.resolve().relative_to(root)
            # The collector's own confined observation: the same verdict, digest and
            # bound weight files for the same bytes, never the BOM's account of them.
            package = packages.observe(relative)
        except (OSError, ValueError):
            package = None
        observation = package.observation if package is not None else None
        if observation is None:
            actual, explanation = (
                SerializationSafety.UNKNOWN,
                "Model structure could not be bound to its SHA-256 subject",
            )
        else:
            actual, explanation = observation.safety, observation.explanation
            try:
                _, expected_digest = normalize_digest(comp.hashes.get("sha256", ""), "sha256")
                if observation.digest != f"sha256:{expected_digest}":
                    raise ValueError("subject mismatch")
            except ValueError:
                report.issues.append(
                    IntegrityIssue(
                        comp.bom_ref,
                        "format_subject_mismatch",
                        "Inspected model structure does not match the BOM's SHA-256 subject",
                    )
                )
        if actual in {
            SerializationSafety.UNSAFE_CODE_EXECUTION,
            SerializationSafety.UNSAFE_TEMPLATE_INJECTION,
        }:
            report.issues.append(
                IntegrityIssue(comp.bom_ref, "unsafe_format", explanation, "critical")
            )
        elif actual == SerializationSafety.UNKNOWN:
            report.issues.append(
                IntegrityIssue(comp.bom_ref, "format_unverified", explanation, "unknown")
            )
        if (
            comp.serialization_safety == SerializationSafety.SAFE
            and actual != SerializationSafety.SAFE
        ):
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "format_claim_mismatch",
                    "Declared safe format was not corroborated",
                )
            )
        if package is None:
            self._unsigned_model(comp, report)
            return
        if package.budget_exhausted:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "validation_budget_exhausted",
                    "Model files of this inventory exceed the bytes or weight-file bindings "
                    "one validation checks (as many as one scan); this model was not checked "
                    "completely",
                    "unknown",
                )
            )
        if not package.complete:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "weight_files_unverified",
                    "The weight files bound to this model could not all be read beneath the root",
                    "unknown",
                )
            )
        local = sorted((weight.as_posix(), digest) for weight, digest in package.weight_files[1:])
        if self._recorded_weight_files(comp) != local:
            report.hashes_failed += 1
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "weight_files_mismatch",
                    "Weight files bound to this model differ from the BOM's record",
                )
            )
        verification = verify_weight_files(
            package.weight_files,
            root,
            self._signature_policies,
            verify=memoized(verify_sigstore_bundle, packages.verified),
        )
        if verification.status is None:
            self._unsigned_model(comp, report)
            return
        report.signatures_checked += verification.signatures_checked
        report.signatures_verified += verification.signatures_verified
        report.hashes_verified += verification.pins_verified
        for category, detail, severity in verification.issues:
            if severity == "unknown" and not self.require_model_signatures:
                severity = "warning"
            report.issues.append(IntegrityIssue(comp.bom_ref, category, detail, severity))

    def _model_packages(self, report: IntegrityReport, root: Path) -> ModelPackages:
        """One observer per validation, so models share walks, digests and one byte budget."""
        current = self._packages
        if current is None or current[0] is not report or current[1].root != root:
            current = self._packages = (report, ModelPackages(root))
        return current[1]

    def _report_unused_policies(self, project_root: Path | None, report: IntegrityReport) -> None:
        """An operator entry that no model of this inventory uses must not look enforced.

        The model collector reports the same entries when validation recollects the
        project; this states them even when the completeness check does not run.
        """
        if not self._signature_policies or project_root is None:
            return
        root = project_root.resolve()
        covered = self._model_packages(report, root).covered
        with ConfinedCollection(root, []) as files:
            unused = unused_policy_entries(files, self._signature_policies, covered)
        for label, reason in unused:
            report.issues.append(
                IntegrityIssue("signature-policy", "unused_policy_entry", f"{label}: {reason}")
            )

    @staticmethod
    def _recorded_weight_files(comp: ModelComponent) -> list[tuple[str, str | None]] | None:
        recorded = comp.properties.get("weight_files", [])
        if not isinstance(recorded, list):
            return None
        entries: list[tuple[str, str | None]] = []
        for item in recorded:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                return None
            digest = item.get("sha256")
            entries.append((item["path"], digest if isinstance(digest, str) else None))
        return sorted(entries)

    def _unsigned_model(self, comp: ModelComponent, report: IntegrityReport) -> None:
        category = (
            "unsigned_model"
            if comp.signing_status in {"unsigned", "signature-not-found"}
            else "unverified_signature"
        )
        report.issues.append(
            IntegrityIssue(
                comp.bom_ref,
                category,
                "No trusted artifact-bound signer policy was supplied",
                "unknown" if self.require_model_signatures else "warning",
            )
        )

    def _check_prompt_hash(
        self, comp: PromptComponent, project_root: Path | None, report: IntegrityReport
    ) -> None:
        if not comp.content_hash:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref, "missing_hash", "Prompt content digest is unavailable", "unknown"
                )
            )
            return
        path = self._artifact_path(comp, project_root, report)
        if path is None:
            report.hashes_failed += 1
            return
        result = verify_file_hash(path, comp.content_hash)
        if result.verified:
            report.hashes_verified += 1
        else:
            report.hashes_failed += 1
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref, "hash_mismatch", result.error or "Prompt digest mismatch"
                )
            )

    def _check_file_hash(
        self, comp: AnyComponent, project_root: Path | None, report: IntegrityReport
    ) -> None:
        if not comp.hashes:
            if isinstance(comp, ModelComponent):
                report.issues.append(
                    IntegrityIssue(
                        comp.bom_ref,
                        "missing_hash",
                        "Model artifact digest is unavailable",
                        "unknown",
                    )
                )
            return
        # Reject malformed declarations even when the artifact cannot be opened.
        valid: list[tuple[str, str]] = []
        for algorithm, expected in comp.hashes.items():
            try:
                normalize_digest(expected, algorithm)
                valid.append((algorithm, expected))
            except ValueError as exc:
                report.hashes_failed += 1
                report.issues.append(IntegrityIssue(comp.bom_ref, "file_hash_mismatch", str(exc)))
        if not valid:
            return
        path = self._artifact_path(comp, project_root, report)
        if path is None:
            report.hashes_failed += len(valid)
            return
        for algorithm, expected in valid:
            result = verify_file_hash(path, expected, algorithm)
            if result.verified:
                report.hashes_verified += 1
            else:
                report.hashes_failed += 1
                report.issues.append(
                    IntegrityIssue(
                        comp.bom_ref,
                        "file_hash_mismatch",
                        result.error or "Artifact digest mismatch",
                    )
                )
