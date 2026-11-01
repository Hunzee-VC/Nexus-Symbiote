import pytest
from click.testing import CliRunner

from symbote.cli import SCANNER_REGISTRY, main
from symbote.core.aibom import AIBOM
from symbote.core.models import CompletenessClaim, ToolComponent
from symbote.validators.completeness import CompletenessValidator


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
    assert bom.metadata.completeness.scope == "local-static-project"
    assert bom.metadata.completeness.scanner_status["broken"] == "failed"
    assert bom.metadata.completeness.scan_failures
    assert not CompletenessValidator().validate(bom).is_complete


def test_unselected_scanners_remain_unknown(tmp_path):
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--scanner", "model", "-o", str(output)]
    )
    assert result.exit_code == 0
    bom = AIBOM.load(output)
    assert bom.metadata.completeness.scanner_status["model"] == "complete"
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
    (tmp_path / ".symbote.yaml").write_text("scan:\n  scaners: [mcp]\n")
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
