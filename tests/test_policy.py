"""Policy configuration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_symbiote.policy import DEFAULT_SCANNERS, Policy, default_policy, load_policy


class TestDefaultPolicy:
    def test_default_values(self) -> None:
        policy = default_policy()
        assert policy.version == "1.0"
        assert "mcp" in policy.scan.scanners
        assert "model" in policy.scan.scanners
        assert policy.risk.fail_threshold == 50.0
        assert policy.risk.warn_threshold == 25.0
        assert policy.validation.require_completeness is True
        assert policy.output.default_format == "json"

    def test_default_exclude_paths(self) -> None:
        policy = default_policy()
        assert "node_modules" in policy.scan.exclude_paths
        assert ".git" in policy.scan.exclude_paths


class TestLoadPolicy:
    def test_load_valid_yaml(self, tmp_path: Path) -> None:
        content = (
            'version: "1.0"\nscan:\n  scanners: ["mcp", "prompt"]\nrisk:\n  fail_threshold: 75.0\n'
        )
        (tmp_path / ".nexus-symbiote.yaml").write_text(content)
        policy = load_policy(tmp_path)
        assert policy is not None
        assert policy.scan.scanners == ["mcp", "prompt"]
        assert policy.risk.fail_threshold == 75.0

    def test_load_yml_extension(self, tmp_path: Path) -> None:
        content = 'version: "1.0"\nrisk:\n  fail_threshold: 30.0\n'
        (tmp_path / ".nexus-symbiote.yml").write_text(content)
        policy = load_policy(tmp_path)
        assert policy is not None
        assert policy.risk.fail_threshold == 30.0

    def test_load_missing_returns_none(self, tmp_path: Path) -> None:
        assert load_policy(tmp_path) is None

    def test_load_invalid_yaml_returns_none(self, tmp_path: Path) -> None:
        (tmp_path / ".nexus-symbiote.yaml").write_text("{{invalid yaml:::")
        with pytest.raises(ValueError):
            load_policy(tmp_path)

    def test_load_empty_file_returns_none(self, tmp_path: Path) -> None:
        (tmp_path / ".nexus-symbiote.yaml").write_text("")
        with pytest.raises(ValueError):
            load_policy(tmp_path)

    def test_load_searches_parent_dirs(self, tmp_path: Path) -> None:
        content = 'version: "2.0"\n'
        (tmp_path / ".nexus-symbiote.yaml").write_text(content)
        subdir = tmp_path / "subproject" / "src"
        subdir.mkdir(parents=True)
        policy = load_policy(subdir)
        assert policy is not None
        assert policy.version == "2.0"

    def test_defaults_for_missing_sections(self, tmp_path: Path) -> None:
        (tmp_path / ".nexus-symbiote.yaml").write_text('version: "1.0"\n')
        policy = load_policy(tmp_path)
        assert policy is not None
        assert "shadowscan" in policy.scan.scanners
        assert policy.risk.fail_threshold == 50.0


class TestPolicyModel:
    def test_model_validation(self) -> None:
        policy = Policy(
            version="1.0",
        )
        assert policy.scan.scanners == list(DEFAULT_SCANNERS)

    def test_custom_risk_config(self) -> None:
        from nexus_symbiote.policy import RiskPolicy

        risk = RiskPolicy(fail_threshold=80.0, ignore_categories=["signing_status"])
        assert risk.fail_threshold == 80.0
        assert "signing_status" in risk.ignore_categories
