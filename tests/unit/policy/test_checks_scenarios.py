"""Targeted scenarios for authorization, registry, trust, attestation, evaluation and coverage checks."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from symbiote.model.common import Claim, EvidenceRef
from symbiote.model.edges import Edge
from symbiote.model.entities import (
    A2ACard,
    Agent,
    CredentialBinding,
    DelegationHop,
    EnforcementPoint,
    Evaluation,
    Evidence,
    Grant,
    Harness,
    Identity,
    PublisherFacts,
    RegistryFacts,
    RegistryResolution,
    RequestedRef,
    ResolvedRef,
    Scope,
    SideEffectProfile,
    SignatureFacts,
    SubjectConfig,
    ToolDefinition,
    TransparencyLog,
    TrustStatus,
    TyposquatDistance,
)
from symbiote.model.enums import (
    AgentRole,
    AssuranceLevel,
    CapabilityClass,
    CredentialKind,
    DelegationProtocol,
    EdgeType,
    EnforcementPointKind,
    EvidenceKind,
    EvidenceVerification,
    FindingState,
    GrantLayer,
    IdentityKind,
    RegistryStatus,
    RequestedRefKind,
    SignatureOutcome,
    SignatureStatus,
    TrustState,
    TrustSubjectKind,
    ValueState,
)
from symbiote.policy import run_policy

from .conftest import AGENT, NOW, build_risky_bom

E = "sha256:" + "e" * 64


def _ids(tmp_path: Path, extra: Any, select: list[str], **kwargs: Any) -> list[tuple[str, str]]:
    bom = build_risky_bom(tmp_path, extra=extra)
    result = run_policy(bom, select=select, now=NOW, **kwargs)
    return [(f.check_id, f.state.value) for f in result.findings]


def test_authorization_checks(tmp_path: Path) -> None:
    def extra(c: dict[str, list[Any]]) -> None:
        gh = "server:claude-code-github"
        tools = c["tools"]
        idx = next(i for i, t in enumerate(tools) if t.tool_name == "create_issue")
        tools[idx] = tools[idx].replace(required_scopes={"value": ["repo:read"], "state": "present"})
        egress_tool: ToolDefinition = tools[idx].replace(
            id="tool:claude-code-github/exfil",
            tool_name="exfil",
            side_effects=Claim.observed(SideEffectProfile(egress_destinations=["paste.evil.example"])),
        )
        tools.append(egress_tool)
        binding = next(b for b in c["credential_bindings"] if b.subject_ref == gh)
        c["credential_bindings"].remove(binding)
        c["credential_bindings"].append(
            binding.replace(scopes_granted={"value": ["repo", "admin:org"], "state": "present"})
        )
        anon = Identity(id="ident:anon", kind=IdentityKind.UNAUTHENTICATED, ref="anonymous")
        c["identities"].append(anon)
        c["credential_bindings"].append(
            CredentialBinding(
                id="cred:anon", subject_ref=gh, identity_ref=anon.id, kind=CredentialKind.UNAUTHENTICATED
            )
        )
        c.setdefault("grants", []).extend(
            [
                Grant(
                    id="grant:write-none",
                    layer=GrantLayer.DECLARED,
                    subject_ref=gh,
                    capability=CapabilityClass.WRITE,
                    enforcement_point=EnforcementPoint(kind=EnforcementPointKind.NONE),
                    scope=Scope(egress=["glob:*.github.com"]),
                ),
                Grant(
                    id="grant:write-unknown",
                    layer=GrantLayer.DECLARED,
                    subject_ref=gh,
                    capability=CapabilityClass.EXECUTE,
                ),
                Grant(
                    id="grant:delegated",
                    layer=GrantLayer.DECLARED,
                    subject_ref=AGENT,
                    capability=CapabilityClass.DELEGATE,
                    enforcement_point=EnforcementPoint(kind=EnforcementPointKind.GATEWAY),
                    delegation_chain=[
                        DelegationHop.model_validate(
                            {"from": AGENT, "to": "agent:helper", "protocol": DelegationProtocol.A2A}
                        )
                    ],
                ),
            ]
        )
        c["agents"].append(Agent(id="agent:helper", name="helper", version="1", role=AgentRole.SUB_AGENT))
        c["edges"].append(
            Edge.model_validate({"type": EdgeType.DELEGATES_TO, "from": AGENT, "to": "agent:helper"})
        )

    found = _ids(tmp_path, extra, ["SYM-AUTHZ-00[2-7]"])
    assert ("SYM-AUTHZ-002", "fail") in found  # over-privilege and missing scope
    assert ("SYM-AUTHZ-004", "fail") in found
    assert ("SYM-AUTHZ-005", "fail") in found and ("SYM-AUTHZ-005", "indeterminate") in found
    assert ("SYM-AUTHZ-006", "fail") in found and ("SYM-AUTHZ-006", "indeterminate") in found
    assert ("SYM-AUTHZ-007", "fail") in found


def test_registry_and_trust_checks(tmp_path: Path) -> None:
    def extra(c: dict[str, list[Any]]) -> None:
        base = {
            "resolved_at": NOW,
            "resolver": "test",
            "resolved": ResolvedRef(immutable_ref="x", state="present"),
        }
        c["resolutions"] = [
            RegistryResolution(
                id="res:deleted",
                requested=RequestedRef(kind=RequestedRefKind.NPM, ref="srv-a"),
                registry=RegistryFacts(status=RegistryStatus.DELETED),
                **base,
            ),
            RegistryResolution(
                id="res:deprecated",
                requested=RequestedRef(kind=RequestedRefKind.NPM, ref="srv-b"),
                registry=RegistryFacts(status=RegistryStatus.DEPRECATED),
                **base,
            ),
            RegistryResolution(
                id="res:unknown",
                requested=RequestedRef(kind=RequestedRefKind.NPM, ref="srv-c"),
                registry=RegistryFacts(),
                **base,
            ),
            RegistryResolution(
                id="res:typo",
                requested=RequestedRef(kind=RequestedRefKind.NPM, ref="@modelcontextprotocol/server-githuh"),
                typosquat_distance=TyposquatDistance(
                    nearest="@modelcontextprotocol/server-github", levenshtein=1
                ),
                publisher=PublisherFacts(identity="https://github.com/evil"),
                signer=SignatureFacts(
                    status=SignatureStatus.CLAIMED, outcome=SignatureOutcome.SIGNATURE_VALID_UNCONSTRAINED
                ),
                transparency_log=TransparencyLog(inclusion_proof_verified=False),
                **base,
            ),
        ]
        tool = next(t for t in c["tools"] if t.tool_name == "create_issue")
        c["parties"] = []
        c["trust_status"] = [
            TrustStatus(
                id="trust:tool",
                subject_kind=TrustSubjectKind.TOOL_DIGEST,
                subject_key=tool.digest.value or "",
                status=TrustState.REVOKED,
                reason="rug pull",
                decided_by_ref=AGENT,
                decided_at=NOW,
                serial=1,
            ),
            TrustStatus(
                id="trust:pub",
                subject_kind=TrustSubjectKind.PUBLISHER_IDENTITY,
                subject_key="https://github.com/evil",
                status=TrustState.REVOKED,
                reason="compromised",
                decided_by_ref=AGENT,
                decided_at=NOW,
                serial=1,
            ),
        ]

    found = _ids(tmp_path, extra, ["SYM-MCP-004", "SYM-MCP-005", "SYM-TRUST-*", "SYM-ATT-001", "SYM-REG-001"])
    for expected in (
        ("SYM-MCP-004", "fail"),
        ("SYM-MCP-004", "indeterminate"),
        ("SYM-MCP-005", "fail"),
        ("SYM-TRUST-001", "fail"),
        ("SYM-TRUST-002", "fail"),
        ("SYM-ATT-001", "fail"),
        ("SYM-REG-001", "fail"),
    ):
        assert expected in found, expected


def test_evidence_evaluation_card_and_coverage(tmp_path: Path) -> None:
    def extra(c: dict[str, list[Any]]) -> None:
        c["evidence"] = [
            Evidence(
                id="ev:" + "e" * 12,
                kind=EvidenceKind.SCAN_REPORT,
                media_type="application/json",
                digest=E,
                created=NOW - timedelta(days=30),
                expires=NOW - timedelta(days=1),
            )
        ]
        c["evaluations"] = [
            Evaluation(
                id="eval:redteam",
                subject_config=SubjectConfig(toolset_digests=["sha256:" + "4" * 64]),
                harness=Harness(name="garak"),
                assessor_ref=AGENT,
                performed_at=NOW,
            )
        ]
        c["agents"].append(
            Agent(
                id="agent:peer",
                name="peer",
                version="1",
                role=AgentRole.EXTERNAL_AGENT,
                a2a_card=A2ACard(digest=E),
            )
        )
        server = c["tool_servers"][0]
        c["tool_servers"][0] = server.replace(
            server_info={"state": "absent-verified", "assurance": "observed"},
            provenance={
                "evidence": [
                    EvidenceRef(
                        digest=E, verification=EvidenceVerification.SIGNATURE_VALID_UNCONSTRAINED
                    ).model_dump(mode="python")
                ]
            },
        )

    found = _ids(tmp_path, extra, ["SYM-ATT-*", "SYM-EVAL-001", "SYM-A2A-001", "SYM-COV-002"])
    for expected in (
        ("SYM-ATT-002", "fail"),
        ("SYM-ATT-001", "fail"),
        ("SYM-EVAL-001", "fail"),
        ("SYM-A2A-001", "fail"),
        ("SYM-COV-002", "fail"),
    ):
        assert expected in found, expected


def test_undeclared_sub_agent_against_baseline(tmp_path: Path) -> None:
    baseline = build_risky_bom(tmp_path / "a")

    def extra(c: dict[str, list[Any]]) -> None:
        c["agents"].append(Agent(id="agent:shadow", name="shadow", version="1", role=AgentRole.SUB_AGENT))
        c["edges"].append(
            Edge.model_validate(
                {
                    "type": EdgeType.SPAWNS,
                    "from": AGENT,
                    "to": "agent:shadow",
                    "assurance": AssuranceLevel.OBSERVED,
                }
            )
        )

    bom = build_risky_bom(tmp_path / "b", extra=extra)
    result = run_policy(bom, baseline=baseline, select=["SYM-SUB-001"], now=NOW)
    assert [f.subject_refs for f in result.findings] == [["agent:shadow"]]


def test_mixed_trust_and_unauthenticated(tmp_path: Path) -> None:
    def extra(c: dict[str, list[Any]]) -> None:
        mail = next(s for s in c["tool_servers"] if s.name == "mail")
        c["tool_servers"].remove(mail)
        c["tool_servers"].append(mail.replace(authentication={"value": {"mode": "none"}, "state": "present"}))

    found = _ids(tmp_path, extra, ["SYM-MCP-001", "SYM-MCP-006"])
    assert ("SYM-MCP-001", "fail") in found
    assert ("SYM-MCP-006", "fail") in found


def test_memory_writers_unknown(tmp_path: Path) -> None:
    found = _ids(tmp_path, None, ["SYM-MEM-001", "SYM-INSTR-001"])
    assert ("SYM-MEM-001", "fail") in found
    assert ValueState.UNKNOWN.value == "unknown"  # SYM-INSTR-001 fires only for prompts with unknown editors
    assert FindingState.FAIL.value == "fail"
