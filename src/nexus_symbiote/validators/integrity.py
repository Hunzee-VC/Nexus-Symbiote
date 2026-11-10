"""Integrity checks with explicit pass, fail and unavailable-evidence outcomes."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.collection import is_imported
from nexus_symbiote.core.enums import SerializationSafety
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    descriptor_binding,
    hash_tool_definition,
    normalize_digest,
    open_regular_file,
    pathname_identity,
)
from nexus_symbiote.core.models import (
    AnyComponent,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    ToolComponent,
)
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import inspect_model_artifact, model_format
from nexus_symbiote.utils.confined import MAX_HASH_BYTES
from nexus_symbiote.utils.crypto import (
    MAX_BUNDLE_BYTES,
    SigstoreArtifactPolicy,
    verify_sigstore_bundle,
)

VALIDATION_BYTE_BUDGET = 6 * MAX_HASH_BYTES
"""Bytes one validation may read from artifacts, so a supplied BOM cannot multiply work.

A maximal scan inventory (the model collector reads at most ``MAX_HASH_BYTES`` of
weights) needs at most four passes over its models; the rest is headroom.
"""
SIGNATURE_VERIFICATION_COST = MAX_BUNDLE_BYTES
"""Work charged for one offline signature verification beyond the bytes it reads.

Loading the trust root and checking the certificate chain is charged like reading
this many bytes, so verification work draws on the same budget as artifact reads.
"""
MAX_REPORTED_ISSUES = 1000
_IMPORTED_EVIDENCE_GAPS = frozenset(
    {
        "artifact_unavailable",
        "missing_hash",
        "missing_definition",
        "unverified_signature",
        "unsigned_model",
        "descriptor_source_unavailable",
    }
)
"""Unknown-evidence categories that a bound imported claim reports without blocking."""
_BLOCKING = {"critical", "error"}
_SEVERITY_RANK = {"critical": 0, "error": 0, "unknown": 1, "warning": 2, "info": 3}


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
    basis: Literal["supplied-bom", "project"] = "supplied-bom"
    bytes_charged: int = 0
    issues_omitted: int = 0
    omitted_severities: set[str] = field(default_factory=set)

    @property
    def status(self) -> Literal["pass", "fail", "unknown"]:
        severities = {i.severity for i in self.issues} | self.omitted_severities
        if severities & _BLOCKING:
            return "fail"
        if "unknown" in severities:
            return "unknown"
        if self.hashes_verified + self.signatures_verified == 0:
            return "unknown"
        return "pass"

    @property
    def is_valid(self) -> bool:
        """Compatibility gate: unknown evidence never produces a passing verdict."""
        return self.status == "pass"

    def bound_issues(self) -> None:
        """Keep at most ``MAX_REPORTED_ISSUES`` issues, blocking ones first; the verdict keeps all."""
        if len(self.issues) <= MAX_REPORTED_ISSUES:
            return
        ranked = sorted(self.issues, key=lambda issue: _SEVERITY_RANK.get(issue.severity, 0))
        omitted = ranked[MAX_REPORTED_ISSUES:]
        self.issues_omitted += len(omitted)
        self.omitted_severities |= {issue.severity for issue in omitted}
        self.issues = ranked[:MAX_REPORTED_ISSUES]

    def to_dict(self) -> dict[str, object]:
        return {
            "is_valid": self.is_valid,
            "status": self.status,
            "assessment_basis": self.basis,
            "components_checked": self.components_checked,
            "hashes_verified": self.hashes_verified,
            "hashes_failed": self.hashes_failed,
            "signatures_checked": self.signatures_checked,
            "signatures_verified": self.signatures_verified,
            "bytes_charged": self.bytes_charged,
            "issues": [
                {
                    "component_ref": i.component_ref,
                    "category": i.category,
                    "detail": i.detail,
                    "severity": i.severity,
                }
                for i in self.issues
            ],
            "issues_omitted": self.issues_omitted,
        }


class _BudgetExhaustedError(Exception):
    pass


class _ArtifactDigests:
    """Hash each artifact at most once per algorithm within one validation.

    Entries are keyed by the open descriptor's identity, so a file changed between two
    reads is hashed again. Bytes read are charged to one validation-wide budget.
    """

    def __init__(self, budget: int) -> None:
        self.remaining = budget
        self._digests: dict[tuple[tuple[int, ...], str], str | None] = {}

    def charge(self, size: int) -> None:
        if size > self.remaining:
            raise _BudgetExhaustedError
        self.remaining -= size

    def digest(self, path: Path, algorithm: str) -> str | None:
        """Return ``algorithm:hex`` of ``path``, or None when it cannot be read safely."""
        try:
            with open_regular_file(path) as stream:
                before = os.fstat(stream.fileno())
                key = (descriptor_binding(before), algorithm)
                if key in self._digests:
                    return self._digests[key]
                if before.st_size > MAX_HASH_BYTES:
                    self._digests[key] = None
                    return None
                self.charge(before.st_size)
                digest = hashlib.new(algorithm)
                total = 0
                while chunk := stream.read(1024 * 1024):
                    total += len(chunk)
                    if total > before.st_size:
                        return None
                    digest.update(chunk)
                after = os.fstat(stream.fileno())
                if descriptor_binding(before) != descriptor_binding(after) or pathname_identity(
                    path
                ) != (after.st_dev, after.st_ino):
                    return None
        except (OSError, ValueError):
            return None
        value = f"{algorithm}:{digest.hexdigest()}"
        self._digests[key] = value
        return value


def _locate_artifact(project_root: Path, source_path: str) -> Path | str:
    """Return the in-root artifact a component names, or the fixed reason it is refused.

    Every reader applies these rules: no parent traversal, inside the resolved root,
    not a symbolic link, and a regular file. Reasons never quote the path.
    """
    root = project_root.resolve()
    candidate = Path(source_path)
    if ".." in candidate.parts:
        return "Parent traversal is not permitted"
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        if candidate.is_symlink() or not candidate.resolve().is_relative_to(root):
            return "Artifact path escapes the supplied project root or is a symlink"
        if not candidate.is_file():
            return "Declared artifact is missing or is not a regular file"
    except (OSError, RuntimeError, ValueError):
        return "Declared artifact could not be examined"
    return candidate


def _regular_file_size(path: Path) -> int:
    """Size of the regular file a no-follow open reaches; zero when there is none."""
    try:
        with open_regular_file(path) as stream:
            return os.fstat(stream.fileno()).st_size
    except (OSError, ValueError):
        return 0


class IntegrityValidator:
    """Check manifest consistency and scoped artifacts, not runtime admission.

    Signature policies must come from the trusted caller. BOM signing_status and
    signing_identity fields, and adjacent signature filenames, are never trusted
    as verification evidence. Model signatures are required by default. A digest
    that agrees only with other fields of the same BOM is self-consistency, not
    verification: it is reported as unknown evidence and never counted as verified.
    """

    def __init__(
        self,
        signature_policies: Sequence[SigstoreArtifactPolicy] = (),
        *,
        require_model_signatures: bool = True,
        byte_budget: int = VALIDATION_BYTE_BUDGET,
    ) -> None:
        self._signature_policies = {p.artifact_path.resolve(): p for p in signature_policies}
        if len(self._signature_policies) != len(signature_policies):
            raise ValueError("Duplicate artifact signature policies")
        self.require_model_signatures = require_model_signatures
        self.byte_budget = byte_budget
        self._digests = _ArtifactDigests(byte_budget)
        self._inspected_models: set[Path] = set()

    def validate(
        self,
        bom: AIBOM,
        project_root: Path | None = None,
        *,
        exclude_paths: Sequence[str] = (),
        bound_imports: frozenset[str] = frozenset(),
    ) -> IntegrityReport:
        """Check every component; ``bound_imports`` names imported discovery claims.

        Only references that project reconciliation bound to the local discovery report
        may be passed as ``bound_imports``. Those are judged as imported claims: their
        unavailable local evidence is reported without blocking, while intrinsic findings
        such as an unsafe loading format still fail.
        """
        report = IntegrityReport(basis="supplied-bom" if project_root is None else "project")
        self._digests = _ArtifactDigests(self.byte_budget)
        self._inspected_models = set()
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
            first_issue = len(report.issues)
            if isinstance(comp, ModelComponent) and not self._admit_model(
                comp, project_root, report
            ):
                continue
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
            if comp.bom_ref in bound_imports and is_imported(comp):
                for issue in report.issues[first_issue:]:
                    if issue.severity == "unknown" and issue.category in _IMPORTED_EVIDENCE_GAPS:
                        issue.severity = "info"
                        issue.detail = "Imported discovery claim without local evidence: " + (
                            issue.detail
                        )
        report.bytes_charged = self.byte_budget - self._digests.remaining
        if report.hashes_verified + report.signatures_verified == 0 and not any(
            i.severity in {"critical", "error", "unknown"} for i in report.issues
        ):
            report.issues.append(
                IntegrityIssue(
                    "inventory",
                    "nothing_verified",
                    "No artifact hash or signature could be verified against local evidence",
                    "unknown",
                )
            )
        report.bound_issues()
        return report

    def _admit_model(
        self, comp: ModelComponent, project_root: Path | None, report: IntegrityReport
    ) -> bool:
        """Charge a model's artifact work to the validation budget before it happens.

        Inspection reads the artifact once, tensor metadata and a signer policy once
        more each; a verification also reads its bundle and costs a fixed amount of
        work. A weights file, or a file the signer policy covers, is inspected for one
        component only: a later model component naming it fails instead of repeating
        the work. Other files, such as the manifest that declares hosted models, are
        charged for each component. A component the budget cannot cover is unknown,
        not skipped silently. A path the readers refuse costs nothing here; the
        checks report why.
        """
        if project_root is None or not comp.source_path:
            return True
        located = _locate_artifact(project_root, comp.source_path)
        if isinstance(located, str):
            return True
        try:
            artifact = located.resolve()
        except (OSError, RuntimeError, ValueError):
            return True
        policy = self._signature_policies.get(artifact)
        once = policy is not None or model_format(artifact) is not None
        if once and artifact in self._inspected_models:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "duplicate_artifact",
                    "An earlier model component already names this artifact; an inventory "
                    "describes each model artifact once",
                )
            )
            return False
        size = _regular_file_size(located)
        cost = size * (1 + bool(comp.tensor_inventory_hash or comp.safetensors_header_hash))
        if policy is not None:
            bundle = min(_regular_file_size(policy.bundle_path), MAX_BUNDLE_BYTES + 1)
            cost += size + bundle + SIGNATURE_VERIFICATION_COST
        try:
            self._digests.charge(cost)
        except _BudgetExhaustedError:
            report.issues.append(_budget_issue(comp.bom_ref, self.byte_budget))
            return False
        if once:
            self._inspected_models.add(artifact)
        return True

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
        from nexus_symbiote.scanners.model import safetensors_fingerprint

        try:
            if project_root is None or comp.source_path is None:
                raise ValueError("project root and artifact path are required")
            expected_weight = comp.hashes.get("sha256")
            if not expected_weight:
                raise ValueError("tensor metadata requires a whole-artifact SHA-256 binding")
            algorithm, hex_digest = normalize_digest(expected_weight, "sha256")
            live = safetensors_fingerprint(
                Path(comp.source_path),
                root=project_root,
                expected_digest=f"{algorithm}:{hex_digest}",
            )
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
            else:
                # The descriptor and its digest both come from the document under review.
                report.issues.append(
                    IntegrityIssue(
                        comp.bom_ref,
                        "descriptor_source_unavailable",
                        "Tool descriptor matches only its own recorded digest; no local "
                        "configuration corroborates it",
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
        located = _locate_artifact(project_root, comp.source_path)
        if isinstance(located, str):
            report.issues.append(IntegrityIssue(comp.bom_ref, "missing_artifact", located))
            return None
        return located

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
        if path is not None:
            try:
                with open_regular_file(path) as stream:
                    actual, explanation, inspected_digest = inspect_model_artifact(
                        path, stream=stream
                    )
                _, expected_digest = normalize_digest(comp.hashes.get("sha256", ""), "sha256")
                if inspected_digest != f"sha256:{expected_digest}":
                    report.issues.append(
                        IntegrityIssue(
                            comp.bom_ref,
                            "format_subject_mismatch",
                            "Inspected model structure does not match the BOM's SHA-256 subject",
                        )
                    )
            except (OSError, ValueError):
                actual, explanation = (
                    SerializationSafety.UNKNOWN,
                    "Model structure could not be bound to its SHA-256 subject",
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

        policy = self._signature_policies.get(path.resolve()) if path is not None else None
        if policy is None or path is None:
            category = (
                "unsigned_model" if comp.signing_status == "unsigned" else "unverified_signature"
            )
            severity = "unknown" if self.require_model_signatures else "warning"
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    category,
                    "No trusted artifact-bound signer policy was supplied",
                    severity,
                )
            )
            return
        report.signatures_checked += 1
        result = verify_sigstore_bundle(
            path, policy.bundle_path, policy.expected_identity, policy.expected_issuer
        )
        if (
            not result.verified
            or result.identity != policy.expected_identity
            or result.issuer != policy.expected_issuer
        ):
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "signature_verification_failed",
                    result.error or "Signature verification failed",
                )
            )
            return
        # Bind the verification result to the same bytes represented by the BOM.
        try:
            _, digest = normalize_digest(comp.hashes.get("sha256", ""), "sha256")
            if not result.details or result.details.get("artifact_digest") != f"sha256:{digest}":
                raise ValueError("Signed artifact does not match the BOM's SHA-256 digest")
        except ValueError as exc:
            report.issues.append(
                IntegrityIssue(comp.bom_ref, "signature_subject_mismatch", str(exc))
            )
            return
        report.signatures_verified += 1

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
        self._verify_digest(comp, path, comp.content_hash, None, report, "hash_mismatch")

    def _verify_digest(
        self,
        comp: AnyComponent,
        path: Path,
        expected: str,
        algorithm: str | None,
        report: IntegrityReport,
        category: str,
    ) -> None:
        try:
            algorithm, digest = normalize_digest(expected, algorithm)
        except ValueError as exc:
            report.hashes_failed += 1
            report.issues.append(IntegrityIssue(comp.bom_ref, category, str(exc)))
            return
        try:
            actual = self._digests.digest(path, algorithm)
        except _BudgetExhaustedError:
            report.issues.append(_budget_issue(comp.bom_ref, self.byte_budget))
            return
        if actual is None:
            report.hashes_failed += 1
            report.issues.append(
                IntegrityIssue(comp.bom_ref, category, "Failed to read a regular artifact file")
            )
        elif actual == f"{algorithm}:{digest}":
            report.hashes_verified += 1
        else:
            report.hashes_failed += 1
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref, category, "Hash mismatch against the expected artifact digest"
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
        # Reject malformed declarations even when the artifact cannot be opened. Keys
        # differing only in case name one algorithm and must not buy another full read.
        valid: dict[str, str] = {}
        for algorithm, expected in comp.hashes.items():
            folded = algorithm.lower()
            try:
                if folded in valid:
                    raise ValueError("Digest algorithm is declared more than once")
                normalize_digest(expected, folded)
                valid[folded] = expected
            except ValueError as exc:
                report.hashes_failed += 1
                report.issues.append(IntegrityIssue(comp.bom_ref, "file_hash_mismatch", str(exc)))
        if not valid:
            return
        path = self._artifact_path(comp, project_root, report)
        if path is None:
            report.hashes_failed += len(valid)
            return
        for algorithm, expected in valid.items():
            self._verify_digest(comp, path, expected, algorithm, report, "file_hash_mismatch")


def _budget_issue(component_ref: str, budget: int) -> IntegrityIssue:
    return IntegrityIssue(
        component_ref,
        "validation_budget_exhausted",
        f"Not checked: the work would exceed this validation's artifact budget of {budget:,} bytes",
        "unknown",
    )
