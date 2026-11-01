"""Coverage must reflect every built-in scanner, including newly added ones."""

from nexus_symbiote.cli import _get_scanners
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import (
    AIBOMMetadata,
    CompletenessClaim,
    ModelComponent,
    ToolComponent,
)
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from nexus_symbiote.validators.completeness import CompletenessValidator
from nexus_symbiote.validators.risk import RiskScorer


def test_catalog_matches_cli_registry():
    assert set(_get_scanners()) == BUILTIN_SCANNER_NAMES


def test_imported_bom_with_legacy_five_scanners_cannot_pass_coverage():
    claim = CompletenessClaim(
        scope="local-static-project",
        scanner_status=dict.fromkeys(("mcp", "model", "prompt", "rag", "registry"), "complete"),
        surfaces_scanned=["config.json"],
    )
    bom = AIBOM(metadata=AIBOMMetadata(completeness=claim))
    bom.add_component(ModelComponent(bom_ref="model:a", name="a"))
    report = CompletenessValidator().validate(bom)
    assert not report.is_complete
    assert any(
        "a2a" in issue.description and "ide_agents" in issue.description for issue in report.issues
    )
    passed, risk_report = RiskScorer().passes_gate(bom)
    assert not passed
    assert risk_report.coverage_status == "partial"


def test_policy_template_and_required_coverage_match_every_builtin_scanner():
    import yaml

    from nexus_symbiote.policy import DEFAULT_POLICY_YAML, default_policy

    catalog = set(_get_scanners())
    assert set(default_policy().scan.scanners) == catalog
    assert set(yaml.safe_load(DEFAULT_POLICY_YAML)["scan"]["scanners"]) == catalog
    for missing in ("shadowscan", "a2a", "ide_agents"):
        claim = CompletenessClaim(
            scope="local-static-project",
            surfaces_scanned=["repo"],
            scanner_status=dict.fromkeys(catalog - {missing}, "complete"),
        )
        bom = AIBOM(components=[ToolComponent(name="t", bom_ref="tool:t")])
        bom.metadata.completeness = claim
        assert RiskScorer().passes_gate(bom)[0] is False
        assert any(
            missing in issue.description for issue in CompletenessValidator().validate(bom).issues
        )
