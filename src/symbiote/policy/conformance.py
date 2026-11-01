"""Conformance levels AgentBOM-Minimal / Standard / Verified (``spec/conformance.md``).

Conformance is a statement about the *document*, never about the safety of the agent. Each requirement yields
``pass | fail | unknown`` with reasons; the level attained is the highest level with no ``fail`` and no
``unknown`` among its own requirements and those of every lower level. Requirements whose evidence lives
outside the document (schema validation of an exported CycloneDX file, a verified attestation) are ``unknown``
unless the caller supplies that evidence in ``evidence``.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal

from symbiote.authz.classify import side_effect_class
from symbiote.model.common import looks_like_secret
from symbiote.model.document import AgentBOM
from symbiote.model.enums import (
    ApprovalGate,
    CoverageStatus,
    DataSourceKind,
    ModelKind,
    SideEffectClass,
    SignatureStatus,
    ToolSource,
    TrustTier,
    ValueState,
)

__all__ = ["LEVELS", "ConformanceReport", "Requirement", "evaluate_conformance"]

Level = Literal["minimal", "standard", "verified"]
Status = Literal["pass", "fail", "unknown"]
LEVELS: Final[tuple[Level, ...]] = ("minimal", "standard", "verified")


@dataclass(frozen=True, slots=True)
class Requirement:
    id: str
    level: Level
    title: str
    status: Status
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ConformanceReport:
    requested: Level
    attained: Level | None
    requirements: tuple[Requirement, ...]

    @property
    def passed(self) -> bool:
        return self.attained is not None and LEVELS.index(self.attained) >= LEVELS.index(self.requested)

    def to_json(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "attained": self.attained,
            "passed": self.passed,
            "note": "Conformance describes the document's completeness and evidence, not the agent's safety.",
            "requirements": [
                {
                    "id": r.id,
                    "level": r.level,
                    "title": r.title,
                    "status": r.status,
                    "reasons": list(r.reasons),
                }
                for r in self.requirements
            ],
        }


Result = tuple[Status, list[str]]
Evaluator = Callable[[AgentBOM, Mapping[str, Any]], Result]


def _ok(cond: bool, failing: list[str]) -> Result:
    return ("pass", []) if cond else ("fail", failing)


def _min01(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    agent = bom.root_agent
    problems = [p for p, missing in (("name", not agent.name), ("version", not agent.version)) if missing]
    if problems:
        return "fail", [f"root agent has no {p}" for p in problems]
    return "pass", [] if agent.owner_ref else ["owner unknown (allowed; record it in symbiote.yaml)"]


def _min02(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    missing = [
        m.id
        for m in bom.models
        if m.weights is None and m.hosted is None and m.model_kind is not ModelKind.CHAT_TEMPLATE
    ]
    return _ok(not missing, [f"{m}: no identity" for m in missing])


def _min03(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    bad = [s.id for s in bom.tool_servers if s.package is None and s.endpoint is None and not s.command]
    return _ok(not bad, [f"{s}: neither package, endpoint nor command" for s in bad])


def _min04(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    bad = [t.id for t in bom.tools if not t.digest.ok and not t.digest.reason]
    return _ok(not bad, [f"{t}: no digest and no reason" for t in bad])


def _min05(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    return "pass", []  # Instruction.digest and Skill.digest are required by the model


def _min06(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    return _ok(len(bom.coverage.surfaces) == 10, ["coverage does not list all ten surfaces"])


def _min07(bom: AgentBOM, evidence: Mapping[str, Any]) -> Result:
    if "cyclonedx_valid" not in evidence:
        return "unknown", ["no CycloneDX validation result supplied (run `symbiote validate`)"]
    if bom.links.spdx is not None and "spdx_valid" not in evidence:
        return "unknown", ["no validation result supplied for the linked SPDX document"]
    ok = evidence["cyclonedx_valid"] is True and evidence.get("spdx_valid", True) is True
    return _ok(ok, ["an exported document failed official schema validation"])


def _min08(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    blob = json.dumps(bom.to_json_dict())
    return _ok(not looks_like_secret(blob), ["a credential-shaped value appears in the document"])


def _std01(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    links = bom.links
    if links.cyclonedx is None and links.spdx is None:
        return "unknown", ["no exported format is linked yet"]
    return "pass", []


def _std02(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    granted = {g.subject_ref for g in bom.grants if g.layer.value == "declared"}
    missing = [s.id for s in bom.tool_servers if s.id not in granted] + [
        t.id for t in bom.tools if t.id not in granted and t.server_ref not in granted
    ]
    return _ok(not missing, [f"{m}: no declared grant" for m in missing[:20]])


def _std03(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    missing = [g.id for g in bom.grants if g.credential_binding_ref is None]
    return _ok(not missing, [f"{g}: no credential binding" for g in missing[:20]])


def _std04(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    missing = [
        s.id
        for s in bom.tool_servers
        if s.package is not None
        and s.package.value is not None
        and s.package.value.purl
        and s.registry_resolution_ref is None
    ]
    return _ok(not missing, [f"{m}: registry-sourced without a resolution record" for m in missing[:20]])


def _std05(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    snap = bom.snapshot
    problems = []
    if snap.validity.not_after is None:
        problems.append("no validity window (not_after)")
    if snap.serial > 1 and snap.prev is None:
        problems.append("serial > 1 without a prev link")
    return _ok(not problems, problems)


def _std06(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    return _ok(bool(bom.derived.flags), ["computed flags missing (run `symbiote policy check`)"])


def _std07(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    if bom.loss_report is None:
        return "unknown", ["no loss report attached"]
    dropped = bom.loss_report.security_relevant_dropped
    return _ok(not dropped, [f"security-relevant field dropped: {i.path}" for i in dropped[:10]])


def _std08(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    problems = [f"{d.id}: trust tier unknown" for d in bom.data_sources if d.trust_tier is TrustTier.UNKNOWN]
    problems += [
        f"{d.id}: memory writers not recorded"
        for d in bom.data_sources
        if d.data_kind is DataSourceKind.MEMORY_STORE and d.writers is None
    ]
    return _ok(not problems, problems[:20])


def _std09(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    problems = [
        f"{t.id}: approval gate or side-effect class unknown"
        for t in bom.tools
        if t.approval_gate is ApprovalGate.UNKNOWN or side_effect_class(t) is SideEffectClass.UNKNOWN
    ]
    return _ok(not problems, problems[:20])


def _std10(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    served = {t.server_ref for t in bom.tools if t.source is ToolSource.SERVED_LIVE}
    missing = [s.id for s in bom.tool_servers if s.server_kind.value == "mcp" and s.id not in served]
    if not missing:
        return "pass", []
    tools_cov = bom.coverage.surfaces
    explained = any(
        src.source.startswith("mcp-live") and not src.ok for cov in tools_cov.values() for src in cov.sources
    )
    return ("unknown" if explained else "fail"), [f"{m}: no served tool definitions" for m in missing[:20]]


def _ver_evidence(key: str, what: str) -> Evaluator:
    def evaluate(bom: AgentBOM, evidence: Mapping[str, Any]) -> Result:
        del bom
        if key not in evidence:
            return "unknown", [f"{what}: not supplied"]
        return _ok(evidence[key] is True, [f"{what}: did not verify"])

    return evaluate


def _ver03(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    bad = [
        m.id
        for m in bom.models
        if m.model_kind in (ModelKind.WEIGHTS, ModelKind.ADAPTER, ModelKind.EMBEDDING)
        and (m.signature is None or m.signature.status is not SignatureStatus.VERIFIED)
    ]
    bad += [
        m.id
        for m in bom.models
        if m.model_kind is ModelKind.HOSTED
        and m.hosted is not None
        and m.hosted.value is not None
        and m.hosted.value.fingerprint is None
        and m.hosted.value.resolved_ref.state is not ValueState.PRESENT
    ]
    return _ok(not bad, [f"{m}: not verified and no fingerprint" for m in bad[:20]])


def _ver04(bom: AgentBOM, evidence: Mapping[str, Any]) -> Result:
    now = evidence.get("now") or datetime.now(UTC)
    if not bom.trust_status:
        return "fail", ["no trust-status list"]
    expired = [t.id for t in bom.trust_status if t.expires is not None and t.expires <= now]
    return _ok(not expired, [f"{t}: expired" for t in expired])


def _ver05(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    if bom.merkle is None:
        return "fail", ["no Merkle commitment"]
    from symbiote.snapshot.commit import verify_document

    return _ok(verify_document(bom), ["Merkle root does not recompute from the document"])


def _ver07(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    missing = sorted(
        s.value for s, c in bom.coverage.surfaces.items() if c.status is not CoverageStatus.QUERIED
    )
    return _ok(not missing, [f"surface {m} not queried" for m in missing])


def _ver08(bom: AgentBOM, _: Mapping[str, Any]) -> Result:
    digest = bom.snapshot.digest
    producer = bom.producer.name
    ok = [a for a in bom.approvals if a.approved_snapshot_digest == digest and a.approver_ref != producer]
    return _ok(
        bool(ok), ["no approval statement for this snapshot from an identity distinct from the producer"]
    )


_REQUIREMENTS: Final[tuple[tuple[str, Level, str, Evaluator], ...]] = (
    ("AB-MIN-01", "minimal", "Agent identity", _min01),
    ("AB-MIN-02", "minimal", "Every model has an identity or explicit unknown", _min02),
    ("AB-MIN-03", "minimal", "Every tool server has transport and package or endpoint", _min03),
    ("AB-MIN-04", "minimal", "Every tool definition has a digest or an undigestable reason", _min04),
    ("AB-MIN-05", "minimal", "Every instruction file and skill is digested", _min05),
    ("AB-MIN-06", "minimal", "Coverage statement for all ten surfaces", _min06),
    ("AB-MIN-07", "minimal", "Exported documents validate against the official schemas", _min07),
    ("AB-MIN-08", "minimal", "No secret values anywhere", _min08),
    ("AB-STD-01", "standard", "Companion linked by digest in every emitted format", _std01),
    ("AB-STD-02", "standard", "Declared grant per tool server and tool", _std02),
    ("AB-STD-03", "standard", "Identities and credential bindings for every grant", _std03),
    ("AB-STD-04", "standard", "Name-resolution record for every registry-sourced component", _std04),
    ("AB-STD-05", "standard", "Snapshot serial, prev link and validity window", _std05),
    ("AB-STD-06", "standard", "Computed flags with cited inputs", _std06),
    ("AB-STD-07", "standard", "Loss report with no security-relevant item dropped", _std07),
    ("AB-STD-08", "standard", "Trust tier for every data source; writers for every memory store", _std08),
    ("AB-STD-09", "standard", "Approval gate and side-effect class for every tool", _std09),
    ("AB-STD-10", "standard", "Served tool digests for every reachable MCP server", _std10),
    (
        "AB-VER-01",
        "verified",
        "Signed snapshot statement verifies under an identity constraint",
        _ver_evidence("snapshot_attestation_verified", "snapshot attestation"),
    ),
    (
        "AB-VER-02",
        "verified",
        "Live tool-definition set matches the approved set within max staleness",
        _ver_evidence("toolset_matches_approved", "live toolset comparison"),
    ),
    ("AB-VER-03", "verified", "Every model verified, or unknown with a fingerprint", _ver03),
    ("AB-VER-04", "verified", "Current, verified trust-status list", _ver04),
    ("AB-VER-05", "verified", "Merkle root present and recomputable", _ver05),
    (
        "AB-VER-06",
        "verified",
        "Evaluation evidence bound to current digests for risky tools",
        _ver_evidence("evaluations_current", "evaluation binding"),
    ),
    ("AB-VER-07", "verified", "All ten coverage surfaces queried", _ver07),
    (
        "AB-VER-08",
        "verified",
        "Approval covers the deployed snapshot digest from a distinct identity",
        _ver08,
    ),
)


def evaluate_conformance(
    bom: AgentBOM, level: Level = "minimal", *, evidence: Mapping[str, Any] | None = None
) -> ConformanceReport:
    """Evaluate every requirement up to ``level`` and report the highest level attained."""
    ev = evidence or {}
    wanted = LEVELS[: LEVELS.index(level) + 1]
    results: list[Requirement] = []
    for req_id, req_level, title, evaluate in _REQUIREMENTS:
        if req_level not in wanted:
            continue
        status, reasons = evaluate(bom, ev)
        results.append(Requirement(req_id, req_level, title, status, tuple(reasons)))
    attained: Level | None = None
    for lvl in wanted:
        relevant = [r for r in results if LEVELS.index(r.level) <= LEVELS.index(lvl)]
        if all(r.status == "pass" for r in relevant):
            attained = lvl
        else:
            break
    return ConformanceReport(requested=level, attained=attained, requirements=tuple(results))
