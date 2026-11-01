"""Regression tests for A2A collection coverage and evidence claims."""

import json

import pytest

from symbiote.core.enums import ComponentType, TrustTier
from symbiote.scanners.a2a import A2AScanner


def test_declared_authentication_does_not_prove_runtime_enforcement(tmp_path):
    (tmp_path / "agent.json").write_text(
        json.dumps({"name": "agent", "authentication": {"schemes": ["bearer"]}})
    )
    result = A2AScanner().scan(tmp_path)
    server = next(c for c in result.components if c.component_type == ComponentType.A2A_SERVER)
    assert server.authentication_required is None
    assert server.trust_tier == TrustTier.UNKNOWN


def test_a2a_yaml_config_is_parsed_with_optional_dependency(tmp_path):
    pytest.importorskip("yaml")
    (tmp_path / "a2a.yaml").write_text(
        "clients:\n  - name: example\n    url: https://example.org\n"
    )
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures
    assert any(c.component_type == ComponentType.A2A_CLIENT for c in result.components)


def test_malformed_yaml_reports_failure(tmp_path):
    pytest.importorskip("yaml")
    (tmp_path / "a2a.yml").write_text("clients: [")
    result = A2AScanner().scan(tmp_path)
    assert result.scan_failures


def test_symlink_config_is_a_collection_failure(tmp_path):
    target = tmp_path / "target"
    target.write_text("{}")
    (tmp_path / "a2a.json").symlink_to(target)
    result = A2AScanner().scan(tmp_path)
    assert result.scan_failures


def test_code_file_limit_is_reported_and_all_examined_files_recorded(tmp_path):
    for index in range(21):
        (tmp_path / f"file_{index:02}.py").write_text("pass\n")
    result = A2AScanner().scan(tmp_path)
    assert any("more than 20" in item for item in result.surfaces_excluded)
    assert len(result.surfaces_scanned) == 20
