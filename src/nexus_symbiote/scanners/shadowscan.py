"""Import untrusted Nexus-ShadowScan reports as *declared* discovery evidence.

No live collection, artifact execution, identity verification, or security
attestation occurs here. Report bytes remain a separate sensitive artifact.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter, deque
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.collection import CITED_EVIDENCE_CLAIM, IMPORTED_MODE
from nexus_symbiote.core.enums import AssuranceLevel, RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import hash_canonical, parse_json_strict
from nexus_symbiote.core.models import (
    AgentComponent,
    AIBOMMetadata,
    AnyComponent,
    ClaimEvidence,
    CompletenessClaim,
    DiscoveryVerification,
    MCPServerComponent,
    ModelComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.scanners.base import Scanner, ScanResult, SourceBudget
from nexus_symbiote.scanners.credential_files import credential_gap
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import redact_text
from nexus_symbiote.utils.terminal import UNSAFE_TEXT

MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_FINDINGS = 10_000
MAX_DEPENDENCIES = 10_000
MAX_MODEL_CITATIONS = 10_000
MAX_CITED_PATH_CHARS = 256
MAX_CITED_LINE_CHARS = 4_096
# The redactor costs about a microsecond a character, so the lines it checks are bounded.
MAX_REDACTED_CHARS = 1024 * 1024
CITED_LINES_GAP = (
    "ShadowScan cited lines exceed the text checked for credentials; the rest were not confirmed"
)
MAX_EVIDENCE_LOCATIONS = 16
# With the bounds above, the named models of one report stay under 3 MiB of inventory.
MAX_NAMED_MODELS = 500
PROJECTION_PROFILE = "nexus-symbiote/shadowscan-projection/v5"
EVIDENCE_CLAIM = CITED_EVIDENCE_CLAIM
MODEL_REF_PREFIX = "shadowscan:model:"
CONTENT_PROFILE = "nexus-symbiote/shadowscan-content/v1"
# The fields that only record when a collection run happened. The list is closed:
# any other field, including one a later ShadowScan release adds, stays content,
# and so does a listed field whose value is not the expected run-event shape.
_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})", re.ASCII
)
_SERIAL_NUMBER = re.compile(r"urn:uuid:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}")
_RUN_EVENT_FIELDS = frozenset({"started_at", "finished_at"})
_FINDING_RUN_EVENT_FIELDS = frozenset({"last_seen"})
_CYCLONEDX_RUN_EVENT_FIELDS = frozenset({"serialNumber"})
_CYCLONEDX_METADATA_RUN_EVENT_FIELDS = frozenset({"timestamp"})
REPORT_PATHS = (".shadowscan/report.json", "shadowscan-report.json", "shadowscan.json")
_ALLOWED_SURFACES = frozenset(
    {"code", "identity", "gateway", "lowcode", "saas", "cloud", "endpoint", "network", "runtime"}
)
_PROJECTED_KINDS = frozenset({"agent", "mcp-server", "local-model", "model"})
_RISK_LEVELS = frozenset(level.value for level in RiskSeverity)
UNRECOGNIZED_VALUES_GAP = "ShadowScan report contains values the projection does not recognize"
# A source-reported label such as ``model:provider.aws-bedrock``: short parts only.
_MODEL_SIGNAL = re.compile(r"model:[a-z0-9]{1,24}(?:[.-][a-z0-9]{1,24}){0,3}", re.ASCII)
_MODEL_LITERAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,126}[A-Za-z0-9]", re.ASCII)
_CITED_LINE = re.compile(r"[1-9][0-9]{0,6}", re.ASCII)
# A JSON file with one of these top-level keys is a bill of materials or a scan report
# (CycloneDX, SPDX 2 and 3, SARIF, a ShadowScan report, a native inventory or risk report).
_RESTATED_KEYS = frozenset({"bomFormat", "spdxVersion", "@graph", "runs", "findings", "components"})


@dataclass(frozen=True)
class ModelCitation:
    """One report evidence entry that names a model identifier at a file and line.

    Every field is the report's assertion until a scan reads the cited line itself.
    """

    signal: str
    path: str
    line: int
    literal: str


@dataclass
class ImportedReport:
    components: list[AnyComponent] = field(default_factory=list)
    dependencies: list[DependencyEdge] = field(default_factory=list)
    digest: str = ""
    content_digest: str = ""
    source_format: str = ""
    source_status: str = "unknown"
    unmapped_count: int = 0
    unmapped_indexes: list[int] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    unrecognized: Counter[str] = field(default_factory=Counter)
    # Signature-verification outcome for this report, recorded in the BOM.
    # ``None`` only for reports built without going through the importer.
    discovery_verification: DiscoveryVerification | None = None
    # Repo-relative POSIX path of the report, or its bare file name when it was
    # read from outside a project root; ``None`` for parsed bytes. Never an
    # absolute local path: that would leak the operator's filesystem layout.
    source_path: str | None = None
    model_citations: list[ModelCitation] = field(default_factory=list)
    # Model evidence that names no usable file, line and identifier, or lies past the bound.
    uncited_model_evidence: int = 0

    def with_verification(self, verification: DiscoveryVerification) -> ImportedReport:
        """Return this report carrying a verified discovery record.

        The record must bind the same exact report bytes; anything else is a
        substitution, not a verification.
        """
        if verification.report_digest != self.digest:
            raise ValueError("Discovery verification binds a different report digest")
        return replace(self, discovery_verification=verification)

    def to_native_bom(self) -> AIBOM:
        """Reproduce a direct native import without promoting source assertions."""
        aibom = AIBOM(metadata=AIBOMMetadata(authors=[]))
        for component in self.components:
            aibom.add_component(component)
        for dependency in self.dependencies:
            aibom.add_dependency(dependency)
        aibom.metadata.completeness = CompletenessClaim(
            scope="shadowscan-imported",
            surfaces_scanned=["shadowscan:report"],
            surfaces_excluded=self.limitations,
            scan_failures=(
                []
                if self.source_status == "complete"
                else ["ShadowScan source report is incomplete or has unknown status"]
            ),
            scanner_status={"shadowscan": "partial"},
            source_report_digest=self.digest,
            source_report_content_digest=self.content_digest or None,
            source_report_content_profile=CONTENT_PROFILE if self.content_digest else None,
            source_report_format=self.source_format,
            source_report_status=self.source_status,
            source_unmapped_count=self.unmapped_count,
            source_unmapped_indexes=self.unmapped_indexes,
            source_report_path=self.source_path,
            discovery_verification=self.discovery_verification,
            assurance_level=AssuranceLevel.DECLARED,
            collectors_requested=["shadowscan"],
            collectors_completed=["shadowscan"],
            unobserved_surfaces=["runtime", "effective-identity", "effective-authorization"],
        )
        return aibom


def _recorded_report_path(report_path: Path, root: Path | None) -> str:
    if root is not None:
        try:
            return report_path.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, RuntimeError, ValueError):
            # Outside the root or unresolvable: record only the file name, never a host path.
            pass
    return report_path.name


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _without(
    record: dict[str, Any], fields: frozenset[str], shape: re.Pattern[str] = _TIMESTAMP
) -> dict[str, Any]:
    return {
        key: value
        for key, value in record.items()
        if key not in fields
        or not (value is None or (isinstance(value, str) and shape.fullmatch(value)))
    }


def report_content_digest(data: dict[str, Any]) -> str:
    """Digest a strictly parsed report under CONTENT_PROFILE, for drift and not authentication.

    RFC 8785 canonical JSON of the report without its run-event fields: native
    top-level and per-connector ``started_at``/``finished_at`` and per-finding
    ``last_seen``; CycloneDX ``serialNumber`` and ``metadata.timestamp``. A field is
    dropped only when null or shaped as an RFC 3339 timestamp (a URN UUID for the
    serial number).
    """
    if data.get("bomFormat") == "CycloneDX":
        content = _without(data, _CYCLONEDX_RUN_EVENT_FIELDS, _SERIAL_NUMBER)
        content["metadata"] = _without(data["metadata"], _CYCLONEDX_METADATA_RUN_EVENT_FIELDS)
        return hash_canonical(content)
    content = _without(data, _RUN_EVENT_FIELDS)
    content["stats"] = [_without(stat, _RUN_EVENT_FIELDS) for stat in data["stats"]]
    content["findings"] = [finding_content(finding) for finding in data["findings"]]
    return hash_canonical(content)


def finding_content(finding: dict[str, Any]) -> dict[str, Any]:
    return _without(finding, _FINDING_RUN_EVENT_FIELDS)


def _unrecognized(
    level: Any, shadow: Any, surface: Any, *, malformed_risk: bool = False
) -> list[str]:
    """Present values the projection cannot represent; dropping them silently would read as clean."""
    found = []
    if malformed_risk or (
        level is not None and not (isinstance(level, str) and level in _RISK_LEVELS)
    ):
        found.append("a risk level")
    if shadow is not None and not isinstance(shadow, bool):
        found.append("a shadow flag")
    if surface is not None and surface not in _ALLOWED_SURFACES:
        found.append("a surface")
    return found


def _clean_binding(value: Any) -> str | None:
    """One binding value from a report, or ``None`` when it is absent or unsafe.

    A binding is a non-empty string of at most 4,096 characters without a control
    character (C0, DEL or C1) or a format character that disguises text, such as a
    bidirectional override or a zero-width space. Anything else is not a repository or
    commit the report can be bound to.
    """
    if not isinstance(value, str) or not value or len(value) > 4096:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return None
    if UNSAFE_TEXT.search(value):
        return None
    return value


def _cited_path(value: str) -> str | None:
    """A cited file as a project-relative POSIX path, or ``None`` when it is not one."""
    if len(value) > MAX_CITED_PATH_CHARS or value.startswith("/") or "\\" in value:
        return None
    if _clean_binding(value) is None or any(part in {"", ".", ".."} for part in value.split("/")):
        return None
    return value


def _model_citation(item: dict[str, Any]) -> ModelCitation | None:
    """The citation a model evidence entry carries, or ``None`` when it cannot be re-read.

    The identifier must be the entry's own ``attributes.value``, in the characters model
    identifiers use, and neither it nor the signal label may read as a credential: a
    report cannot make a scan record text the report does not state, or a secret it does.
    """
    signal, location, attributes = item["signal"], item.get("location"), item.get("attributes")
    literal = attributes.get("value") if isinstance(attributes, dict) else None
    if not isinstance(location, str) or not isinstance(literal, str):
        return None
    cited, _, line = location.rpartition(":")
    path = _cited_path(cited)
    if (
        path is None
        or not _CITED_LINE.fullmatch(line)
        or not _MODEL_SIGNAL.fullmatch(signal)
        or not _MODEL_LITERAL.fullmatch(literal)
        or not any(char.isalpha() for char in literal)
        or redact_text(literal) != literal
        or redact_text(signal) != signal
    ):
        return None
    return ModelCitation(signal, path, int(line), literal)


def names_whole_identifier(line: str, literal: str) -> bool:
    """Whether ``literal`` occurs in ``line`` as a complete identifier, not inside a longer one.

    Identifier text may not continue it on either side. ``/`` and ``:`` before it are
    namespace separators (``anthropic/<model>``, ``openai:<model>``); after it they
    continue the name (``<org>/<model>``, ``<model>:<tag>``).
    """
    whole = rf"(?<![\w.@+-]){re.escape(literal)}(?![\w@+/-]|[.:]\w)"
    return re.search(whole, line) is not None


def _restates_a_scan(raw: bytes) -> bool:
    """Whether a file is a bill of materials or a scan report, by its top-level JSON keys.

    Such a file repeats the identifiers a scan found. It is not where the repository
    states them, so an inventory or report kept in the tree cannot keep a model named.
    """
    if not raw.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"{"):
        return False
    try:
        data = parse_json_strict(
            raw.decode("utf-8").removeprefix("\ufeff"), max_bytes=MAX_REPORT_BYTES
        )
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return False
    return isinstance(data, dict) and not _RESTATED_KEYS.isdisjoint(data)


def _cited_lines(files: ConfinedCollection, budget: SourceBudget, path: str) -> list[str]:
    """The lines of a cited file that may confirm an identifier; none when it is not read.

    Not read: a file named as holding credentials, by its own name or its link target,
    so that no line of it reaches the inventory; a file over the file limit; a bill of
    materials or scan report, which the report itself is under any name; and text that
    is not UTF-8.
    """
    found = None if budget.exhausted else files.regular_file(path)
    if (
        found is None
        or credential_gap(path, found[0].as_posix()) is not None
        or found[1] > files.max_file_bytes
        or not budget.admit(found[1], path)
    ):
        return []
    raw = files.read_bytes(path, missing_ok=True)
    if raw is None or _restates_a_scan(raw):
        return []
    try:
        return raw.decode("utf-8").split("\n")
    except UnicodeDecodeError:
        return []


def _report_time(value: Any) -> str | None:
    if isinstance(value, str) and _TIMESTAMP.fullmatch(value):
        return value
    return None


def _report_binding(data: dict[str, Any]) -> tuple[str, str, str]:
    """Repository, commit and time the report itself carries; ``"unknown"`` when absent.

    Native reports carry their run times (``finished_at``, else ``started_at``)
    and no repository or commit; CycloneDX reports carry ``metadata.timestamp``
    and may carry ``shadowscan:repository`` / ``shadowscan:commit`` properties.
    Nothing is invented: a field the report does not carry stays unknown, and
    the digest in the verification record is what binds those exact bytes.
    """
    repository = _clean_binding(data.get("repository"))
    commit = _clean_binding(data.get("commit"))
    report_time = _report_time(data.get("finished_at")) or _report_time(data.get("started_at"))
    if data.get("bomFormat") == "CycloneDX":
        meta = data.get("metadata")
        if isinstance(meta, dict):
            props = _properties(meta.get("properties", []))
            repository = _clean_binding(props.get("shadowscan:repository")) or repository
            commit = _clean_binding(props.get("shadowscan:commit")) or commit
            report_time = _report_time(meta.get("timestamp")) or report_time
    return repository or "unknown", commit or "unknown", report_time or "unknown"


def verify_discovery_report(
    record: DiscoveryVerification,
    bundle_bytes: bytes,
    expected_identity: str,
    expected_issuer: str,
) -> DiscoveryVerification:
    """Verify a Sigstore bundle over the exact report bytes a record binds.

    Returns a ``verified`` copy of the record carrying the signer identity and
    issuer. Raises ValueError when the bundle does not verify, names another
    signer or issuer, or the Sigstore extra is missing; the caller must not
    record a verified outcome in any of those cases.
    """
    from nexus_symbiote.utils.crypto import SIGSTORE_MISSING, verify_sigstore_digest

    if record.report_digest is None:
        raise ValueError("Discovery verification record has no report digest to verify")
    verified = verify_sigstore_digest(
        record.report_digest, bundle_bytes, expected_identity, expected_issuer
    )
    if not verified.verified:
        if verified.error == SIGSTORE_MISSING:
            raise ValueError(SIGSTORE_MISSING)
        raise ValueError("ShadowScan report signature or signer policy verification failed")
    # verify_sigstore_digest enforces the expected identity and issuer as its
    # verification policy, so a True result already names that signer; the
    # recorded identity is the operator-supplied expectation it enforced.
    return DiscoveryVerification(
        status="verified",
        method="sigstore",
        report_digest=record.report_digest,
        report_content_digest=record.report_content_digest,
        signer_identity=expected_identity,
        issuer=expected_issuer,
        repository=record.repository,
        commit=record.commit,
        report_time=record.report_time,
    )


def _risks(level: Any, shadow: Any) -> list[RiskAssessment]:
    findings: list[RiskAssessment] = []
    levels = {x.value: x for x in RiskSeverity}
    if isinstance(level, str) and level in levels:
        findings.append(
            RiskAssessment(
                severity=levels[level],
                category="shadowscan-heuristic",
                detail=f"ShadowScan heuristic risk: {level}; not an independently verified vulnerability.",
                recommendation="Review the original source evidence and verify under policy.",
            )
        )
    if shadow is True:
        findings.append(
            RiskAssessment(
                severity=RiskSeverity.INFO,
                category="shadowscan-inventory-unmatched",
                detail="ShadowScan reports no matching entry in its supplied inventory; authorization is not established.",
                recommendation="Verify inventory scope and reconcile the source finding.",
            )
        )
    return findings


def _make_component(
    kind: str,
    source_id: str,
    index: int,
    digest: str,
    finding_digest: str,
    surface: str | None,
    level: Any,
    shadow: Any,
    *,
    cdx_model: bool = False,
    cdx_mcp: bool = False,
    resource_type: Any = None,
) -> AnyComponent | None:
    # ShadowScan's endpoint connector emits an MCP tool as kind=mcp-server
    # and resource_type=mcp-tool. The latter is an observation type, not
    # proof that the tool is itself a server or linked to a particular server.
    # Conflicting claims are not projected as either kind.
    if resource_type == "mcp-tool" and (kind != "mcp-server" or cdx_model):
        return None
    # A CycloneDX type or group contradicting the ShadowScan kind is not resolved by precedence.
    if (cdx_model and (cdx_mcp or kind not in {"", "local-model", "model"})) or (
        cdx_mcp and kind not in {"", "mcp-server"}
    ):
        return None
    is_mcp_tool = kind == "mcp-server" and resource_type == "mcp-tool"
    identity_hash = _short_hash(source_id)
    ref = "shadowscan:" + identity_hash
    props: dict[str, Any] = {
        "shadowscan:report-sha256": digest,
        "shadowscan:finding-sha256": finding_digest,
        "shadowscan:finding-index": index,
        "shadowscan:source-id-sha256": identity_hash,
        "collection_mode": "imported-unverified-report",
        "shadowscan:projection-profile": PROJECTION_PROFILE,
    }
    if surface in _ALLOWED_SURFACES:
        props["shadowscan:surface"] = surface
    if kind in _PROJECTED_KINDS:
        props["shadowscan:kind"] = kind
    if isinstance(shadow, bool):
        props["shadowscan:inventory-unmatched"] = shadow
    risks = _risks(level, shadow)
    safe_kind = "mcp-tool" if is_mcp_tool else kind if kind in _PROJECTED_KINDS else "component"
    common: dict[str, Any] = {
        "bom_ref": ref,
        "name": "ShadowScan " + safe_kind + " " + identity_hash[:12],
        "trust_tier": TrustTier.UNKNOWN,
        "assurance_level": AssuranceLevel.DECLARED,
        "properties": props,
        "risks": risks,
    }
    if is_mcp_tool:
        props["shadowscan:resource-type"] = "mcp-tool"
        return ToolComponent(**common)
    if kind == "mcp-server" or cdx_mcp:
        return MCPServerComponent(**common)
    if kind in {"local-model", "model"} or cdx_model:
        return ModelComponent(**common)
    if kind == "agent":
        return AgentComponent(autonomy_level=None, **common)
    return None


def _model_component(
    literal: str, locations: set[tuple[str, int]], signals: set[str]
) -> ModelComponent:
    listed = [f"{path}:{line}" for path, line in sorted(locations)[:MAX_EVIDENCE_LOCATIONS]]
    # No source_path: for a model that names the weight file, and the cited file is not one.
    return ModelComponent(
        bom_ref=MODEL_REF_PREFIX + _short_hash(literal),
        name=literal,
        trust_tier=TrustTier.UNKNOWN,
        assurance_level=AssuranceLevel.DECLARED,
        properties={
            "collection_mode": IMPORTED_MODE,
            "shadowscan:projection-profile": PROJECTION_PROFILE,
            "shadowscan:kind": "model",
            "shadowscan:signals": sorted(signals),
            **(
                {"shadowscan:evidence-unlisted": len(locations) - len(listed)}
                if len(locations) > len(listed)
                else {}
            ),
        },
        claims={
            # An identifier in a source line is a declaration, as a hosted-model alias in
            # agent.yaml is: reading it measures no model, so the import raises no assurance.
            EVIDENCE_CLAIM: ClaimEvidence(
                assurance=AssuranceLevel.DECLARED,
                method="cited-line-reread",
                scope="repository",
                collector="shadowscan",
                locator=listed[0],
                evidence_refs=listed,
            )
        },
    )


class ShadowScanImporter(Scanner):
    """Import supported ShadowScan JSON and CycloneDX observations conservatively."""

    name = "shadowscan"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        report: ImportedReport | None = None
        with self._collection(
            project_root,
            result,
            max_file_bytes=MAX_REPORT_BYTES,
            max_total_bytes=MAX_REPORT_BYTES,
        ) as files:
            present: dict[tuple[int, int], str] = {}
            linked: list[str] = []
            for relative in REPORT_PATHS:
                identity = files.path_identity(relative)
                if identity is not None:
                    present.setdefault(identity, relative)
                elif files.regular_file(relative) is not None:
                    # path_identity follows no link, but a read follows one in-root
                    # directory link, so a report that only a link reaches would be
                    # imported without counting against the paths below. A link is
                    # what the checkout chose, not where a pipeline wrote its report.
                    linked.append(relative)
            for relative in linked:
                result.scan_failures.append(
                    f"{relative}: ShadowScan report is reached through a symbolic link; "
                    "not imported"
                )
            if len(present) > 1:
                # A file committed at a higher-precedence name must not silently replace
                # the report a pipeline generated: import neither.
                result.scan_failures.append(
                    "ShadowScan reports found at more than one supported path ("
                    + ", ".join(sorted(present.values()))
                    + "); keep exactly one"
                )
            for relative in REPORT_PATHS if len(present) <= 1 and not linked else ():
                raw = files.read_bytes(relative, missing_ok=True)
                if raw is None:
                    continue
                try:
                    imported = self._import_bytes(raw)
                except (ValueError, TypeError, UnicodeError, RecursionError):
                    result.scan_failures.append("ShadowScan report could not be safely imported")
                    break
                result.components.extend(imported.components)
                result.dependencies.extend(imported.dependencies)
                result.source_report_digest = imported.digest
                result.source_report_content_digest = imported.content_digest
                result.source_report_content_profile = CONTENT_PROFILE
                result.source_report_path = relative
                result.source_report_format = imported.source_format
                result.source_report_status = imported.source_status
                result.source_unmapped_count = imported.unmapped_count
                result.source_unmapped_indexes = imported.unmapped_indexes
                result.discovery_verification = imported.discovery_verification
                result.surfaces_scanned.extend(("shadowscan:report", relative))
                result.source_projection_limitations = list(imported.limitations)
                report = imported
                if imported.unmapped_count:
                    result.surfaces_excluded.append("ShadowScan report contains unmapped entries")
                if imported.unrecognized:
                    result.surfaces_excluded.append(UNRECOGNIZED_VALUES_GAP)
                if imported.source_format == "shadowscan-cyclonedx":
                    result.surfaces_excluded.append(
                        "ShadowScan CycloneDX source is a lossy projection"
                    )
                if imported.source_status != "complete":
                    result.scan_failures.append(
                        "ShadowScan source report is incomplete or has unknown status"
                    )
                break
        if report is not None:
            self._name_cited_models(project_root, report, result)
        if (
            not result.source_report_digest
            and not result.scan_failures
            and not result.surfaces_excluded
        ):
            result.surfaces_scanned.append("shadowscan-report (no report found)")
        return result

    def _name_cited_models(
        self, project_root: Path, imported: ImportedReport, result: ScanResult
    ) -> None:
        """Name the models whose identifier this scan reads at the line the report cites.

        The report says where an identifier is; the name recorded is what the scan read
        there, as a whole identifier outside any text the redactor withholds. A cited
        file is read once with the confined reader under the operator's source limit.
        Evidence the scan could not confirm stays in the report and is counted.
        """
        unconfirmed = imported.uncited_model_evidence
        by_path: dict[str, list[ModelCitation]] = {}
        for citation in imported.model_citations:
            by_path.setdefault(citation.path, []).append(citation)
        locations: dict[str, set[tuple[str, int]]] = {}
        signals: dict[str, set[str]] = {}
        budget = SourceBudget("ShadowScan cited files", result)
        unchecked = MAX_REDACTED_CHARS
        # A file the report cites and the scan does not read is evidence left unconfirmed,
        # counted below; it is not a failure of this collection.
        with ConfinedCollection(
            project_root, [], exclude_paths=self._exclude_paths, max_total_bytes=budget.bound
        ) as files:
            for path in sorted(by_path):
                lines = _cited_lines(files, budget, path)
                redacted: dict[int, str] = {}
                for citation in by_path[path]:
                    index = citation.line - 1
                    line = lines[index] if index < len(lines) else ""
                    held = len(line) <= MAX_CITED_LINE_CHARS and names_whole_identifier(
                        line, citation.literal
                    )
                    # The redactor runs once on a line that already holds an identifier. A
                    # line that holds nothing else may be the value of a key on the line
                    # before it, so those two are read together.
                    if held and citation.line not in redacted and unchecked >= 0:
                        bare = line.strip().strip("\"',-[] \t") == citation.literal
                        before = lines[index - 1][-MAX_CITED_LINE_CHARS:] if bare and index else ""
                        unchecked -= len(before) + len(line)
                        if unchecked < 0:
                            result.scan_failures.append(CITED_LINES_GAP)
                        else:
                            text = redact_text(f"{before}\n{line}")
                            redacted[citation.line] = (
                                text.rpartition("\n")[2] if "\n" in text else ""
                            )
                    if held and names_whole_identifier(
                        redacted.get(citation.line, ""), citation.literal
                    ):
                        locations.setdefault(citation.literal, set()).add((path, citation.line))
                        signals.setdefault(citation.literal, set()).add(citation.signal)
                    else:
                        unconfirmed += 1
        named = sorted(locations)[:MAX_NAMED_MODELS]
        result.components.extend(
            _model_component(literal, locations[literal], signals[literal]) for literal in named
        )
        limitations = result.source_projection_limitations
        if unconfirmed and limitations is not None:
            limitations.append(
                f"{unconfirmed} model evidence entries were not confirmed at a cited file and "
                "line; they are not named"
            )
        if len(locations) > len(named) and limitations is not None:
            limitations.append(
                f"{len(locations) - len(named)} confirmed model identifiers past the bound of "
                f"{MAX_NAMED_MODELS} are not named"
            )

    def import_report(self, report_path: Path, root: Path | None = None) -> ImportedReport:
        """Import components together with mandatory coverage and provenance."""
        return self.read_report(report_path, root)

    def read_report(self, report_path: Path, root: Path | None = None) -> ImportedReport:
        """Read a report; its recorded location is relative to ``root`` or a bare name."""
        failures: list[str] = []
        with ConfinedCollection(
            report_path.parent,
            failures,
            max_file_bytes=MAX_REPORT_BYTES,
            max_total_bytes=MAX_REPORT_BYTES,
        ) as files:
            raw = files.read_bytes(report_path.name)
        if raw is None or failures:
            raise ValueError("ShadowScan report unavailable or outside safe read limits")
        imported = self._import_bytes(raw)
        imported.source_path = _recorded_report_path(report_path, root)
        return imported

    def parse_report(self, text: str | bytes) -> ImportedReport:
        """Parse the exact bounded bytes used for digest and signature verification."""
        return self._import_bytes(text.encode("utf-8") if isinstance(text, str) else text)

    def _import_bytes(self, raw: bytes) -> ImportedReport:
        # json.loads would also detect UTF-16 and UTF-32, which verify-discovery cannot read.
        text = raw.decode("utf-8")
        data = parse_json_strict(text.removeprefix("\ufeff"), max_bytes=MAX_REPORT_BYTES)
        if not isinstance(data, dict):
            raise ValueError("expected a ShadowScan report object")
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if data.get("bomFormat") == "CycloneDX":
            result = self._from_cyclonedx(data, digest)
        else:
            result = self._from_native(data, digest)
        result.content_digest = report_content_digest(data)
        # The import-time verification outcome, bound to these exact bytes and
        # to whatever repository/commit/time the report itself carries. No
        # signature is checked here, so an import without --bundle records
        # ``unverified``; that is the outcome, not a missing field.
        repository, commit, report_time = _report_binding(data)
        result.discovery_verification = DiscoveryVerification(
            report_digest=digest,
            report_content_digest=result.content_digest,
            repository=repository,
            commit=commit,
            report_time=report_time,
        )
        # Discovery is not a verified, complete BOM even when source scan is complete.
        result.limitations.append(
            "ShadowScan discovery is a source claim; artifact integrity and full BOM coverage are unverified"
        )
        result.limitations.append(
            "Names, detailed evidence, and unmapped relationships remain in the source report"
        )
        if result.unmapped_count:
            result.limitations.append(
                f"{result.unmapped_count} source entries were not mapped into BOM components"
            )
        for value, count in sorted(result.unrecognized.items()):
            result.limitations.append(
                f"{count} source entries carry {value} the projection does not recognize; "
                "it is not represented"
            )
        return result

    @staticmethod
    def _native_complete(
        data: dict[str, Any], findings: list[Any], stats: list[Any], summary: dict[str, Any]
    ) -> bool:
        # The producer's summary describes the final, filtered findings. Connector
        # statistics can legitimately count observations before merging/filtering.
        if "total" in summary or "finding_identity_schema" in data:
            total = summary.get("total")
            if type(total) is not int or total != len(findings):
                raise ValueError("ShadowScan summary total disagrees with findings")
        complete = summary.get("complete") is True and bool(stats)
        if "status" in summary and summary["status"] != "complete":
            complete = False
        for stat in stats:
            if (
                not isinstance(stat, dict)
                or not isinstance(stat.get("errors"), list)
                or not isinstance(stat.get("skipped"), bool)
                or not isinstance(stat.get("incomplete"), bool)
            ):
                raise ValueError("invalid ShadowScan connector statistics")
            if stat["errors"] or stat["skipped"] or stat["incomplete"]:
                complete = False
            omissions = stat.get("declared_omissions", 0)
            if not isinstance(omissions, int) or isinstance(omissions, bool) or omissions != 0:
                complete = False
        for key in ("declared_omissions", "tolerated_gaps"):
            value = summary.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value != 0:
                complete = False
        return complete

    @staticmethod
    def _project_native_findings(findings: list[Any], result: ImportedReport) -> None:
        ids: set[str] = set()
        for index, finding in enumerate(findings):
            if (
                not isinstance(finding, dict)
                or not isinstance(finding.get("id"), str)
                or not finding["id"]
                or len(finding["id"]) > 4096
            ):
                raise ValueError("invalid ShadowScan finding or identifier")
            source_id = finding["id"]
            if source_id in ids:
                raise ValueError("duplicate ShadowScan finding identifier")
            ids.add(source_id)
            kind, surface = finding.get("kind"), finding.get("surface")
            if not isinstance(kind, str) or not isinstance(surface, str):
                raise ValueError("invalid ShadowScan finding kind or surface")
            risk = finding.get("risk")
            level = risk.get("level") if isinstance(risk, dict) else None
            result.unrecognized.update(
                _unrecognized(
                    level,
                    finding.get("shadow"),
                    surface,
                    # A rating without a level string, such as a bare score, is not "unrated".
                    malformed_risk=risk is not None
                    and (not isinstance(risk, dict) or (bool(risk) and not isinstance(level, str))),
                )
            )
            comp = _make_component(
                kind,
                source_id,
                index,
                result.digest,
                hash_canonical(finding_content(finding)),
                surface,
                level,
                finding.get("shadow"),
                resource_type=finding.get("resource_type"),
            )
            if comp is None:
                result.unmapped_count += 1
                result.unmapped_indexes.append(index)
            else:
                result.components.append(comp)
            evidence = finding.get("evidence")
            for item in evidence if isinstance(evidence, list) else ():
                signal = item.get("signal") if isinstance(item, dict) else None
                if not isinstance(signal, str) or not signal.startswith("model:"):
                    continue
                citation = (
                    _model_citation(item)
                    if len(result.model_citations) < MAX_MODEL_CITATIONS
                    else None
                )
                if citation is None:
                    result.uncited_model_evidence += 1
                else:
                    result.model_citations.append(citation)

    @staticmethod
    def _check_native_breakdowns(summary: dict[str, Any], findings: list[Any]) -> None:
        levels = Counter(
            finding["risk"]["level"]
            for finding in findings
            if isinstance(finding.get("risk"), dict)
            and isinstance(finding["risk"].get("level"), str)
        )
        for key, expected in (
            ("by_surface", Counter(finding["surface"] for finding in findings)),
            ("by_kind", Counter(finding["kind"] for finding in findings)),
            ("by_risk_level", levels),
        ):
            if key not in summary:
                continue
            counts = summary[key]
            if (
                not isinstance(counts, dict)
                or any(type(count) is not int for count in counts.values())
                or {name: count for name, count in counts.items() if count} != dict(expected)
            ):
                raise ValueError(f"ShadowScan summary {key} disagrees with findings")
        if "shadow" in summary and (
            type(summary["shadow"]) is not int
            or summary["shadow"] != sum(finding.get("shadow") is True for finding in findings)
        ):
            raise ValueError("ShadowScan summary shadow count disagrees with findings")

    def _from_native(self, data: dict[str, Any], digest: str) -> ImportedReport:
        findings, stats, summary = data.get("findings"), data.get("stats"), data.get("summary")
        if (
            not isinstance(data.get("version"), str)
            or not isinstance(findings, list)
            or len(findings) > MAX_FINDINGS
        ):
            raise ValueError("invalid ShadowScan report envelope")
        if not isinstance(stats, list) or not isinstance(summary, dict):
            raise ValueError("ShadowScan report must include stats and summary")
        complete = self._native_complete(data, findings, stats, summary)
        result = ImportedReport(
            digest=digest,
            source_format="shadowscan-json",
            source_status="complete" if complete else "incomplete",
        )
        self._project_native_findings(findings, result)
        self._check_native_breakdowns(summary, findings)
        return result

    @staticmethod
    def _project_cyclonedx_dependencies(
        data: dict[str, Any], result: ImportedReport, mapped_refs: dict[str, str]
    ) -> None:
        """Retain bounded, source-reported edges without resolving external identities."""
        dependencies = data.get("dependencies", [])
        if not isinstance(dependencies, list) or len(dependencies) > MAX_DEPENDENCIES:
            raise ValueError("invalid or oversized CycloneDX dependency list")
        seen_sources: set[str] = set()
        total = 0
        omitted = 0
        for index, entry in enumerate(dependencies):
            if not isinstance(entry, dict):
                raise ValueError("invalid CycloneDX dependency")
            source, targets = entry.get("ref"), entry.get("dependsOn", [])
            if (
                not isinstance(source, str)
                or not source
                or len(source) > 4096
                or source in seen_sources
                or not isinstance(targets, list)
            ):
                raise ValueError("invalid or duplicate CycloneDX dependency source")
            seen_sources.add(source)
            total += len(targets)
            if total > MAX_DEPENDENCIES:
                raise ValueError("too many CycloneDX dependency edges")
            seen_targets: set[str] = set()
            for target in targets:
                if (
                    not isinstance(target, str)
                    or not target
                    or len(target) > 4096
                    or target in seen_targets
                ):
                    raise ValueError("invalid or duplicate CycloneDX dependency target")
                seen_targets.add(target)
                if source not in mapped_refs or target not in mapped_refs:
                    omitted += 1
                    continue
                result.dependencies.append(
                    DependencyEdge(
                        source_ref=mapped_refs[source],
                        target_ref=mapped_refs[target],
                        relationship="depends-on",
                        assurance_level="declared",
                        conditions=(
                            f"Source-reported CycloneDX dependency; dependencies index {index}; "
                            "not independently verified"
                        ),
                    )
                )
        if omitted:
            result.limitations.append(
                f"{omitted} source dependency edges have unmapped endpoints and were not projected"
            )

    def _from_cyclonedx(self, data: dict[str, Any], digest: str) -> ImportedReport:
        meta = data.get("metadata")
        if data.get("specVersion") not in ("1.6", "1.7") or not isinstance(meta, dict):
            raise ValueError("unsupported ShadowScan CycloneDX envelope")
        props = _properties(meta.get("properties", []))
        status = props.get("shadowscan:scan:status")
        if status not in ("complete", "incomplete"):
            raise ValueError("CycloneDX document lacks ShadowScan scan status")
        result = ImportedReport(
            digest=digest, source_format="shadowscan-cyclonedx", source_status=status
        )
        compositions = data.get("compositions")
        if not isinstance(compositions, list) or not compositions:
            result.limitations.append("CycloneDX composition completeness is not reported")
        elif any(
            not isinstance(c, dict) or c.get("aggregate") not in {"unknown", "complete"}
            for c in compositions
        ):
            result.limitations.append("CycloneDX source declares incomplete composition")
        if any(
            props.get(key) not in (None, "0")
            for key in (
                "shadowscan:bom:truncated-findings",
                "shadowscan:scan:credential-findings-excluded",
            )
        ):
            result.limitations.append("CycloneDX source omits or truncates findings")
        # CycloneDX is a lossy projection of discovery; it cannot prove full report coverage.
        result.limitations.append(
            "CycloneDX source omits or summarizes discovery evidence and relationships"
        )
        ids: set[str] = set()
        mapped_refs: dict[str, str] = {}
        entries: list[Any] = []
        pending_lists: deque[tuple[list[Any], int]] = deque()
        for key in ("components", "services"):
            items = data.get(key, [])
            if not isinstance(items, list):
                raise ValueError("invalid CycloneDX component list")
            if items:
                pending_lists.append((items, 0))
        while pending_lists:
            current_items, depth = pending_lists.popleft()
            if depth > 16:
                raise ValueError("CycloneDX component nesting limit exceeded")
            for item in current_items:
                entries.append(item)
                if len(entries) > MAX_FINDINGS:
                    raise ValueError("too many CycloneDX entries")
                if isinstance(item, dict) and "components" in item:
                    nested_items = item["components"]
                    if not isinstance(nested_items, list):
                        raise ValueError("invalid CycloneDX component list")
                    if nested_items:
                        pending_lists.append((nested_items, depth + 1))
        for index, entry in enumerate(entries):
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("bom-ref"), str)
                or not entry["bom-ref"]
                or len(entry["bom-ref"]) > 4096
            ):
                raise ValueError("invalid CycloneDX entry")
            ref = entry["bom-ref"]
            if ref in ids:
                raise ValueError("duplicate CycloneDX bom-ref")
            ids.add(ref)
            p = _properties(entry.get("properties", []))
            kind = p.get("shadowscan:kind", "")
            shadow_text = p.get("shadowscan:shadow")
            shadow = {"true": True, "false": False}.get(shadow_text or "", shadow_text)
            result.unrecognized.update(
                _unrecognized(
                    p.get("shadowscan:heuristic-risk"), shadow, p.get("shadowscan:surface")
                )
            )
            comp = _make_component(
                kind,
                ref,
                index,
                digest,
                hash_canonical(entry),
                p.get("shadowscan:surface"),
                p.get("shadowscan:heuristic-risk"),
                shadow,
                cdx_model=entry.get("type") == "machine-learning-model",
                cdx_mcp=entry.get("group") == "mcp-server",
                resource_type=p.get("shadowscan:resource-type"),
            )
            if comp is None:
                result.unmapped_count += 1
                result.unmapped_indexes.append(index)
            else:
                result.components.append(comp)
                mapped_refs[ref] = comp.bom_ref
        self._project_cyclonedx_dependencies(data, result, mapped_refs)
        return result


def _properties(value: Any) -> dict[str, str]:
    if not isinstance(value, list):
        raise ValueError("invalid CycloneDX properties")
    result: dict[str, str] = {}
    for item in value:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("value"), str)
        ):
            raise ValueError("invalid CycloneDX property")
        name = item["name"]
        if name.startswith("shadowscan:"):
            if name in result:
                raise ValueError("duplicate ShadowScan property")
            result[name] = item["value"]
    return result
