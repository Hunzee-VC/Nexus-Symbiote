"""Tests for completeness, integrity, and risk validators."""

from __future__ import annotations

from symbote.core.aibom import AIBOM, DependencyEdge
from symbote.core.enums import (
    AssuranceLevel,
    RiskSeverity,
    SerializationSafety,
    TrustTier,
)
from symbote.core.models import (
    CompletenessClaim,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    RiskAssessment,
    ToolComponent,
)
from symbote.diff.differ import AIBOMDiffer
from symbote.validators.completeness import CompletenessValidator
from symbote.validators.integrity import IntegrityValidator
from symbote.validators.risk import RiskScorer


def _full_bom() -> AIBOM:
    bom = AIBOM()
    bom.metadata.completeness = CompletenessClaim(
        scope="full-agent",
        surfaces_scanned=[".mcp.json", "CLAUDE.md", "package.json"],
        assurance_level=AssuranceLevel.OBSERVED,
    )
    bom.add_component(MCPServerComponent(
        bom_ref="mcp:fs",
        name="filesystem",
        transport="stdio",
        version_pinned=True,
    ))
    bom.add_component(ToolComponent(
        bom_ref="tool:read",
        name="read_file",
        mcp_server_ref="mcp:fs",
        definition_hash="sha256:abc123",
        description_text="Read a file",
    ))
    bom.add_component(PromptComponent(
        bom_ref="prompt:system",
        name="CLAUDE.md",
        prompt_type="system-prompt",
        content_hash="sha256:def456",
    ))
    return bom


def _risky_bom() -> AIBOM:
    bom = AIBOM()
    bom.add_component(ModelComponent(
        bom_ref="model:unsafe",
        name="unsafe-model.pkl",
        serialization_format="pickle",
        serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION,
        signing_status="unsigned",
        trust_remote_code=True,
        trust_tier=TrustTier.UNTRUSTED_PUBLIC,
        risks=[
            RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="serialization_format",
                detail="Pickle allows arbitrary code execution.",
            ),
            RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="code_execution",
                detail="trust_remote_code=True.",
            ),
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="signing_status",
                detail="Model is unsigned.",
            ),
        ],
    ))
    bom.add_component(ToolComponent(
        bom_ref="tool:danger",
        name="dangerous_tool",
        risks=[
            RiskAssessment(
                severity=RiskSeverity.MEDIUM,
                category="capability_scope",
                detail="Tool has broad permissions.",
            ),
        ],
    ))
    return bom


class TestCompletenessValidator:
    def test_complete_bom_passes(self):
        bom = _full_bom()
        cv = CompletenessValidator()
        report = cv.validate(bom)
        assert report.total_components == 3
        assert len(report.surfaces_covered) > 0

    def test_missing_completeness_claim(self):
        bom = AIBOM()
        bom.add_component(ToolComponent(bom_ref="tool:t", name="t"))
        cv = CompletenessValidator()
        report = cv.validate(bom)
        assert not report.is_complete
        assert any(i.surface == "metadata" for i in report.issues)

    def test_orphan_ref_detected(self):
        bom = _full_bom()
        bom.add_dependency(DependencyEdge(
            source_ref="mcp:fs",
            target_ref="tool:nonexistent",
            relationship="invokes",
        ))
        cv = CompletenessValidator()
        report = cv.validate(bom)
        assert not report.is_complete
        assert any("nonexistent" in i.description for i in report.issues)

    def test_report_to_dict(self):
        bom = _full_bom()
        cv = CompletenessValidator()
        report = cv.validate(bom)
        d = report.to_dict()
        assert "is_complete" in d
        assert "issues" in d
        assert "total_components" in d


class TestIntegrityValidator:
    def test_tool_hash_mismatch(self):
        bom = AIBOM()
        bom.add_component(ToolComponent(
            bom_ref="tool:test",
            name="test_tool",
            description_text="Does something",
            definition_hash="sha256:wrong_hash_value",
        ))
        iv = IntegrityValidator()
        report = iv.validate(bom)
        assert not report.is_valid
        assert report.hashes_failed > 0

    def test_tool_hash_correct(self):
        from symbote.core.hashing import hash_tool_definition
        correct_hash = hash_tool_definition("test_tool", "Does something")
        bom = AIBOM()
        bom.add_component(ToolComponent(
            bom_ref="tool:test",
            name="test_tool",
            description_text="Does something",
            definition_hash=correct_hash,
        ))
        iv = IntegrityValidator()
        report = iv.validate(bom)
        assert report.hashes_verified == 1
        assert report.hashes_failed == 0

    def test_unsafe_model_flagged(self):
        bom = AIBOM()
        bom.add_component(ModelComponent(
            bom_ref="model:pkl",
            name="model.pkl",
            serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION,
            signing_status="unsigned",
            trust_remote_code=True,
        ))
        iv = IntegrityValidator()
        report = iv.validate(bom)
        assert not report.is_valid
        categories = {i.category for i in report.issues}
        assert "unsafe_format" in categories
        assert "trust_remote_code" in categories

    def test_unpinned_mcp_flagged(self):
        bom = AIBOM()
        bom.add_component(MCPServerComponent(
            bom_ref="mcp:test",
            name="test-server",
            version_pinned=False,
        ))
        iv = IntegrityValidator()
        report = iv.validate(bom)
        assert any(i.category == "unpinned_version" for i in report.issues)

    def test_report_to_dict(self):
        bom = _full_bom()
        iv = IntegrityValidator()
        report = iv.validate(bom)
        d = report.to_dict()
        assert "is_valid" in d
        assert "components_checked" in d


class TestRiskScorer:
    def test_clean_bom_low_score(self):
        bom = _full_bom()
        scorer = RiskScorer()
        report = scorer.score(bom)
        assert report.overall_score == 0.0
        assert report.risk_level == "clean"

    def test_risky_bom_high_score(self):
        bom = _risky_bom()
        scorer = RiskScorer()
        report = scorer.score(bom)
        assert report.overall_score > 20.0
        assert report.risk_level in ("high", "critical")
        assert report.severity_counts.get("critical", 0) >= 2

    def test_passes_gate(self):
        bom = _full_bom()
        scorer = RiskScorer(fail_threshold=50.0)
        passed, report = scorer.passes_gate(bom)
        assert passed

    def test_fails_gate(self):
        bom = _risky_bom()
        scorer = RiskScorer(fail_threshold=10.0)
        passed, report = scorer.passes_gate(bom)
        assert not passed

    def test_report_to_dict(self):
        bom = _risky_bom()
        scorer = RiskScorer()
        report = scorer.score(bom)
        d = report.to_dict()
        assert "overall_score" in d
        assert "risk_level" in d
        assert "findings" in d
        assert len(d["findings"]) > 0


class TestAIBOMDiffer:
    def test_no_changes(self):
        bom = _full_bom()
        differ = AIBOMDiffer()
        result = differ.diff(bom, bom)
        assert not result.has_changes

    def test_component_added(self):
        old = _full_bom()
        new = _full_bom()
        new.add_component(ModelComponent(
            bom_ref="model:new",
            name="new-model",
        ))
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        assert result.has_changes
        assert len(result.components_added) == 1
        assert result.components_added[0].bom_ref == "model:new"

    def test_component_removed(self):
        old = _full_bom()
        new = AIBOM()
        new.add_component(MCPServerComponent(bom_ref="mcp:fs", name="filesystem"))
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        assert len(result.components_removed) == 2

    def test_component_modified(self):
        old = _full_bom()
        new = _full_bom()
        new.add_component(MCPServerComponent(
            bom_ref="mcp:fs",
            name="filesystem",
            transport="sse",
            trust_tier=TrustTier.UNTRUSTED_PUBLIC,
        ))
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        assert len(result.components_modified) == 1
        assert any("trust tier" in d.lower() for d in result.components_modified[0].details)

    def test_security_alert_on_hash_change(self):
        old = _full_bom()
        new = _full_bom()
        new.add_component(ToolComponent(
            bom_ref="tool:read",
            name="read_file",
            mcp_server_ref="mcp:fs",
            definition_hash="sha256:changed_hash",
            description_text="Read a file (modified)",
        ))
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        assert len(result.security_alerts) >= 1
        assert any("critical" in a["severity"] for a in result.security_alerts)

    def test_diff_to_dict(self):
        old = _full_bom()
        new = _full_bom()
        new.add_component(ModelComponent(bom_ref="model:x", name="x"))
        differ = AIBOMDiffer()
        result = differ.diff(old, new)
        d = result.to_dict()
        assert "has_changes" in d
        assert "components_added" in d
