"""Security changes must survive snapshot comparison even when evidence disappears."""

from datetime import UTC, datetime, timedelta

import pytest

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import (
    AgentComponent,
    AuthorizationRecord,
    CapabilityDeclaration,
    ClaimEvidence,
    CompletenessClaim,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    ToolComponent,
)
from nexus_symbiote.diff.differ import AIBOMDiffer


def compare(old, new):
    return AIBOMDiffer().diff(AIBOM(components=[old]), AIBOM(components=[new]))


@pytest.mark.parametrize(
    "old,new,severity",
    [
        (
            ModelComponent(bom_ref="m", name="m", hashes={"sha256": "a" * 64}),
            ModelComponent(bom_ref="m", name="m"),
            "high",
        ),
        (
            PromptComponent(bom_ref="p", name="p", content_hash="sha256:" + "a" * 64),
            PromptComponent(bom_ref="p", name="p"),
            "high",
        ),
        (
            ModelComponent(bom_ref="m", name="m", trust_remote_code=False),
            ModelComponent(bom_ref="m", name="m", trust_remote_code=True),
            "critical",
        ),
        (
            MCPServerComponent(bom_ref="s", name="s", endpoint_url="https://reviewed.example"),
            MCPServerComponent(bom_ref="s", name="s", endpoint_url="https://different.example"),
            "critical",
        ),
        (
            ModelComponent(bom_ref="m", name="m", assurance_level=AssuranceLevel.VERIFIED),
            ModelComponent(bom_ref="m", name="m"),
            "high",
        ),
        (
            ModelComponent(bom_ref="m", name="m", tokenizer_hash="sha256:" + "a" * 64),
            ModelComponent(bom_ref="m", name="m"),
            "high",
        ),
        (
            MCPServerComponent(bom_ref="s", name="s", version_pinned=True),
            MCPServerComponent(bom_ref="s", name="s", version_pinned=None),
            "high",
        ),
    ],
)
def test_security_mutation_or_evidence_removal_is_reported(old, new, severity):
    report = compare(old, new)
    assert report.has_changes
    assert report.components_modified[0].severity == severity
    assert report.security_alerts[0]["severity"] == severity


def test_capability_expansion_and_authorization_change_are_not_unchanged():
    old = AgentComponent(
        bom_ref="a",
        name="a",
        capabilities=CapabilityDeclaration(egress_domains=["api.example"]),
        authorizations=[AuthorizationRecord(principal="user", action="read", resource_scope="one")],
    )
    for update in (
        {"capabilities": CapabilityDeclaration(egress_domains=["*"])},
        {
            "authorizations": [
                AuthorizationRecord(principal="user", action="write", resource_scope="*")
            ]
        },
        {"authorizations": []},
    ):
        report = compare(old, old.model_copy(update=update))
        assert report.has_changes and report.components_modified[0].severity == "high"


def test_opaque_extension_and_ordered_schema_changes_are_visible():
    tool = ToolComponent(
        bom_ref="t",
        name="t",
        properties={"pipeline": ["validate", "execute"]},
        input_schema={"type": "array", "prefixItems": [{"type": "string"}, {"type": "number"}]},
    )
    extension_change = compare(
        tool, tool.model_copy(update={"properties": {"pipeline": ["execute", "validate"]}})
    )
    assert extension_change.has_changes
    schema_change = compare(
        tool,
        tool.model_copy(
            update={
                "input_schema": {
                    "type": "array",
                    "prefixItems": [{"type": "number"}, {"type": "string"}],
                }
            }
        ),
    )
    assert schema_change.components_modified[0].severity == "critical"


def test_unrecognized_future_field_is_not_needed_for_existing_extension_drift():
    old = ModelComponent(bom_ref="m", name="m", properties={"loader_policy": "restricted"})
    assert compare(
        old, old.model_copy(update={"properties": {"loader_policy": "unrestricted"}})
    ).has_changes


def test_collection_order_and_claim_observation_time_do_not_manufacture_drift():
    now = datetime.now(UTC)
    old = AgentComponent(
        bom_ref="a",
        name="a",
        model_refs=["m1", "m2"],
        capabilities=CapabilityDeclaration(egress_domains=["one", "two"]),
        authorizations=[AuthorizationRecord(principal="u", action="read", conditions=["a", "b"])],
        claims={
            "presence": ClaimEvidence(
                method="file", scope="repo", observed_at=now, evidence_refs=["e1", "e2"]
            )
        },
    )
    new = old.model_copy(deep=True)
    new.model_refs.reverse()
    new.capabilities.egress_domains.reverse()
    new.authorizations[0].conditions.reverse()
    new.claims["presence"].evidence_refs.reverse()
    new.claims["presence"].observed_at = now + timedelta(seconds=1)
    assert not compare(old, new).has_changes
    new.claims["presence"].assurance = AssuranceLevel.VERIFIED
    assert compare(old, new).components_modified[0].severity == "high"


@pytest.mark.parametrize("mutation", [{"conditions": None}, {"assurance_level": "declared"}])
def test_edge_conditions_and_assurance_changes_retain_both_records(mutation):
    edge = DependencyEdge(
        source_ref="a",
        target_ref="t",
        relationship="invokes",
        assurance_level="verified",
        conditions="ticket-approved",
    )
    old = AIBOM(dependencies=[edge])
    new = AIBOM(dependencies=[edge.model_copy(update=mutation)])
    report = AIBOMDiffer().diff(old, new)
    assert report.has_changes and report.total_changes == 2
    assert report.dependencies_removed[0].conditions == "ticket-approved"
    serialized = report.to_dict()
    assert serialized["dependencies_added"][0][next(iter(mutation))] == next(
        iter(mutation.values())
    )
    assert report.security_alerts[0]["severity"] == "high"


def test_coverage_loss_cannot_hide_behind_unchanged_components():
    old = AIBOM(components=[ModelComponent(bom_ref="m", name="m")])
    old.metadata.completeness = CompletenessClaim(
        scope="repository", scanner_status={"model": "complete"}
    )
    new = old.model_copy(deep=True)
    new.metadata.completeness.scanner_status["model"] = "failed"
    report = AIBOMDiffer().diff(old, new)
    assert report.has_changes and report.total_changes == 1
    assert report.to_dict()["metadata_changes"][0]["field"] == "completeness.scanner_status.model"
    assert report.security_alerts[0]["severity"] == "high"
    assert "'model'" in report.security_alerts[0]["alert"]
    assert "complete to failed" in report.security_alerts[0]["alert"]


def test_new_collection_event_is_not_composition_drift():
    old = AIBOM()
    old.finalize()
    # finalize() no longer stamps an observation timestamp (ARCH-F1); the
    # test sets one explicitly, as a re-collection would observe it.
    old.metadata.timestamp = datetime.now(UTC)
    old.metadata.completeness = CompletenessClaim(
        scope="repository", surfaces_scanned=["a", "b"], timestamp=datetime.now(UTC)
    )
    new = old.model_copy(deep=True)
    new.metadata.serial_number = "urn:uuid:second-collection"
    new.metadata.timestamp += timedelta(seconds=1)
    new.metadata.completeness.timestamp += timedelta(seconds=1)
    new.metadata.completeness.surfaces_scanned.reverse()
    assert not AIBOMDiffer().diff(old, new).has_changes


def test_risk_multiplicity_remains_visible_when_it_changes_scoring():
    from nexus_symbiote.core.models import RiskAssessment
    from nexus_symbiote.validators.risk import RiskScorer

    finding = RiskAssessment(severity="high", category="declared", detail="Review required")
    old = ModelComponent(bom_ref="m", name="m", risks=[finding])
    new = old.model_copy(deep=True)
    new.risks.append(finding.model_copy())
    before, after = AIBOM(components=[old]), AIBOM(components=[new])
    assert RiskScorer().score(before).overall_score == 7.0
    assert RiskScorer().score(after).overall_score == 14.0
    assert AIBOMDiffer().diff(before, after).has_changes
