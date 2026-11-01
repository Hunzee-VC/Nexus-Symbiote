"""Coverage must reflect every built-in scanner, including newly added ones."""

import pytest
import yaml

from nexus_symbiote.cli import _get_scanners
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import AIBOMMetadata, CompletenessClaim, ModelComponent
from nexus_symbiote.policy import DEFAULT_POLICY_YAML, default_policy
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from nexus_symbiote.validators.completeness import CompletenessValidator
from nexus_symbiote.validators.risk import RiskScorer


def test_catalog_matches_cli_registry():
    assert set(_get_scanners()) == BUILTIN_SCANNER_NAMES
    assert set(default_policy().scan.scanners) == BUILTIN_SCANNER_NAMES
    assert set(yaml.safe_load(DEFAULT_POLICY_YAML)["scan"]["scanners"]) == BUILTIN_SCANNER_NAMES


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


@pytest.mark.parametrize("missing", sorted(BUILTIN_SCANNER_NAMES))
def test_one_omitted_collector_fails_both_gates(missing):
    claim = CompletenessClaim(
        scope="repository",
        surfaces_scanned=["project"],
        scanner_status=dict.fromkeys(BUILTIN_SCANNER_NAMES - {missing}, "complete"),
    )
    bom = AIBOM(
        metadata=AIBOMMetadata(completeness=claim),
        components=[ModelComponent(bom_ref="model:a", name="a")],
    )
    passed, report = RiskScorer().passes_gate(bom)
    assert not passed and report.coverage_status == "partial"
    assert any(
        missing in issue.description for issue in CompletenessValidator().validate(bom).issues
    )
