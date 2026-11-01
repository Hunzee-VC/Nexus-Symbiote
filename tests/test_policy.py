"""Policy configuration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus_symbiote.core.vocab import SCANNER_NAMES
from nexus_symbiote.policy import (
    DEFAULT_POLICY_YAML,
    Policy,
    PolicyError,
    RiskPolicy,
    default_policy,
    discover_policy,
    load_policy_file,
)


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

    def test_default_policy_lists_all_scanners(self) -> None:
        policy = default_policy()
        assert policy.scan.scanners == list(SCANNER_NAMES)
        assert len(policy.scan.scanners) == 8

    def test_default_policy_yaml_lists_all_scanners(self) -> None:
        pytest.importorskip("yaml")
        import yaml

        data = yaml.safe_load(DEFAULT_POLICY_YAML)
        assert data["scan"]["scanners"] == list(SCANNER_NAMES)
        assert len(data["scan"]["scanners"]) == 8


class TestLoadPolicyFile:
    def test_load_valid_yaml(self, tmp_path: Path) -> None:
        content = (
            'version: "1.0"\nscan:\n  scanners: ["mcp", "prompt"]\nrisk:\n  fail_threshold: 75.0\n'
        )
        path = tmp_path / ".nexus-symbiote.yaml"
        path.write_text(content)
        policy = load_policy_file(path)
        assert policy.scan.scanners == ["mcp", "prompt"]
        assert policy.risk.fail_threshold == 75.0

    def test_load_yml_extension(self, tmp_path: Path) -> None:
        content = 'version: "1.0"\nrisk:\n  fail_threshold: 30.0\n'
        path = tmp_path / ".nexus-symbiote.yml"
        path.write_text(content)
        policy = load_policy_file(path)
        assert policy.risk.fail_threshold == 30.0

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyError):
            load_policy_file(tmp_path / "missing.yaml")

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        path = tmp_path / ".nexus-symbiote.yaml"
        path.write_text("{{invalid yaml:::")
        with pytest.raises(ValueError):
            load_policy_file(path)

    def test_empty_file_raises(self, tmp_path: Path) -> None:
        path = tmp_path / ".nexus-symbiote.yaml"
        path.write_text("")
        with pytest.raises(ValueError):
            load_policy_file(path)

    def test_symlinked_policy_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "real-policy.yaml"
        target.write_text('version: "1.0"\n')
        link = tmp_path / ".nexus-symbiote.yaml"
        link.symlink_to(target)
        with pytest.raises(PolicyError):
            load_policy_file(link)

    def test_fail_threshold_out_of_range_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / ".nexus-symbiote.yaml"
        path.write_text("risk:\n  fail_threshold: 500\n")
        with pytest.raises(PolicyError):
            load_policy_file(path)

    def test_error_message_does_not_echo_rejected_value(self, tmp_path: Path) -> None:
        path = tmp_path / ".nexus-symbiote.yaml"
        path.write_text("risk:\n  fail_threshold: 987.25\n")
        with pytest.raises(PolicyError) as excinfo:
            load_policy_file(path)
        message = str(excinfo.value)
        assert "987" not in message
        assert "fail_threshold" in message

    def test_warn_threshold_above_fail_threshold_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / ".nexus-symbiote.yaml"
        path.write_text("risk:\n  fail_threshold: 20.0\n  warn_threshold: 30.0\n")
        with pytest.raises(PolicyError):
            load_policy_file(path)

    def test_unknown_scanner_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / ".nexus-symbiote.yaml"
        path.write_text('scan:\n  scanners: ["not-a-scanner"]\n')
        with pytest.raises(PolicyError):
            load_policy_file(path)

    def test_defaults_for_missing_sections(self, tmp_path: Path) -> None:
        path = tmp_path / ".nexus-symbiote.yaml"
        path.write_text('version: "1.0"\n')
        policy = load_policy_file(path)
        assert len(policy.scan.scanners) == len(SCANNER_NAMES)
        assert policy.risk.fail_threshold == 50.0


class TestDiscoverPolicy:
    def test_discovers_policy_in_start_directory(self, tmp_path: Path) -> None:
        path = tmp_path / ".nexus-symbiote.yaml"
        path.write_text('version: "2.0"\n')
        assert discover_policy(tmp_path) == path.resolve()

    def test_discovers_yml_extension(self, tmp_path: Path) -> None:
        path = tmp_path / ".nexus-symbiote.yml"
        path.write_text('version: "1.0"\n')
        assert discover_policy(tmp_path) == path.resolve()

    def test_searches_parent_dirs(self, tmp_path: Path) -> None:
        path = tmp_path / ".nexus-symbiote.yaml"
        path.write_text('version: "2.0"\n')
        subdir = tmp_path / "subproject" / "src"
        subdir.mkdir(parents=True)
        found = discover_policy(subdir)
        assert found == path.resolve()
        assert found is not None
        policy = load_policy_file(found)
        assert policy.version == "2.0"

    def test_skips_symlinked_policy(self, tmp_path: Path) -> None:
        target = tmp_path / "real-policy.yaml"
        target.write_text('version: "1.0"\n')
        (tmp_path / ".nexus-symbiote.yaml").symlink_to(target)
        subdir = tmp_path / "sub"
        subdir.mkdir()
        found = discover_policy(subdir)
        assert found is None or found.parent != tmp_path.resolve()


class TestPolicyModel:
    def test_model_validation(self) -> None:
        policy = Policy(
            version="1.0",
        )
        assert policy.scan.scanners == list(SCANNER_NAMES)

    def test_custom_risk_config(self) -> None:
        risk = RiskPolicy(fail_threshold=80.0, ignore_categories=["signing_status"])
        assert risk.fail_threshold == 80.0
        assert "signing_status" in risk.ignore_categories
