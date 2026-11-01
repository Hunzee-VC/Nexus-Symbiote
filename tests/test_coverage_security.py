import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import SCANNER_REGISTRY, main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import CompletenessClaim, ToolComponent
from nexus_symbiote.validators.completeness import CompletenessValidator


def test_failed_collector_produces_partial_output_and_nonzero(tmp_path, monkeypatch):
    class Broken:
        def scan(self, root):
            raise RuntimeError("unavailable")

    monkeypatch.setitem(SCANNER_REGISTRY, "broken", Broken)
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--scanner", "broken", "-o", str(output)]
    )
    assert result.exit_code != 0
    bom = AIBOM.load(output)
    assert bom.metadata.completeness.scope == "repository"
    assert bom.metadata.completeness.scanner_status["broken"] == "failed"
    assert bom.metadata.completeness.scan_failures
    assert not CompletenessValidator().validate(bom).is_complete


def test_unselected_scanners_remain_unknown(tmp_path):
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--scanner", "model", "-o", str(output)]
    )
    assert result.exit_code != 0
    bom = AIBOM.load(output)
    assert bom.metadata.completeness.scanner_status["model"] == "partial"
    assert bom.metadata.completeness.surfaces_excluded
    assert bom.metadata.completeness.scanner_status["mcp"] == "unknown"
    assert not CompletenessValidator().validate(bom).is_complete


def test_component_collision_is_rejected_on_add_and_import():
    bom = AIBOM()
    bom.add_component(ToolComponent(bom_ref="tool:x", name="x"))
    with pytest.raises(ValueError, match="Duplicate"):
        bom.add_component(ToolComponent(bom_ref="tool:x", name="other"))
    component = bom.components[0].model_dump(mode="json")
    with pytest.raises(ValueError, match="Duplicate"):
        AIBOM.model_validate({"components": [component, component]})


def test_policy_with_typo_or_invalid_yaml_does_not_fall_back(tmp_path):
    output = tmp_path / "bom.json"
    (tmp_path / ".nexus-symbiote.yaml").write_text("scan:\n  scaners: [mcp]\n")
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "-o", str(output)])
    assert result.exit_code != 0
    assert not output.exists()


def test_recorded_failure_cannot_be_complete():
    bom = AIBOM()
    bom.metadata.completeness = CompletenessClaim(
        scope="local-static-project",
        scanner_status={"model": "complete"},
        scan_failures=["read failed"],
    )
    assert not CompletenessValidator().validate(bom).is_complete


def test_imported_status_cannot_omit_required_scanners():
    bom = AIBOM()
    bom.metadata.completeness = CompletenessClaim(
        scope="local-static-project",
        scanner_status={"model": "complete"},
        surfaces_scanned=["model"],
    )
    result = CompletenessValidator().validate(bom)
    assert not result.is_complete
    assert any("Missing scanner coverage" in issue.description for issue in result.issues)


def test_imported_complete_status_cannot_hide_excluded_surfaces():
    bom = AIBOM()
    bom.metadata.completeness = CompletenessClaim(
        scope="local-static-project",
        scanner_status=dict.fromkeys(("model", "mcp", "prompt", "rag", "registry"), "complete"),
        surfaces_excluded=["prompts (not scanned)"],
    )
    assert not CompletenessValidator().validate(bom).is_complete


def test_policy_template_and_required_coverage_match_every_builtin_scanner():
    import yaml

    from nexus_symbiote.cli import _get_scanners
    from nexus_symbiote.policy import DEFAULT_POLICY_YAML, default_policy
    from nexus_symbiote.validators.risk import RiskScorer

    catalog = set(_get_scanners())
    assert (
        set(default_policy().scan.scanners)
        == catalog
        == set(yaml.safe_load(DEFAULT_POLICY_YAML)["scan"]["scanners"])
    )
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
