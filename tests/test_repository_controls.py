from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "repository_controls", Path(__file__).parents[1] / "scripts/check_repository_controls.py"
)
assert spec and spec.loader
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)


def branch():
    return {
        "protected": True,
        "protection": {
            "enabled": True,
            "required_status_checks": {
                "enforcement_level": "everyone",
                "contexts": ["Verified CI"],
                "checks": [],
            },
        },
    }


def test_required_verified_ci_applies_to_everyone():
    assert controls.evaluate(branch()) == []
    metadata = branch()
    metadata["protection"]["required_status_checks"]["contexts"] = []
    metadata["protection"]["required_status_checks"]["checks"] = [{"context": "Verified CI"}]
    assert controls.evaluate(metadata) == []


@pytest.mark.parametrize("metadata", [None, {}, {"protected": False}, {"protected": 1}])
def test_unknown_or_disabled_protection_fails(metadata):
    assert controls.evaluate(metadata)


def test_checks_cannot_be_bypassed_by_administrator():
    metadata = branch()
    metadata["protection"]["required_status_checks"]["enforcement_level"] = "non_admins"
    assert controls.evaluate(metadata)


def test_missing_aggregate_context_fails_even_with_other_green_checks():
    metadata = branch()
    metadata["protection"]["required_status_checks"]["contexts"] = ["quality", "Tests Python 3.12"]
    assert controls.evaluate(metadata)


@pytest.mark.parametrize("key,value", [("contexts", "Verified CI"), ("checks", [None])])
def test_malformed_check_metadata_fails(key, value):
    metadata = branch()
    metadata["protection"]["required_status_checks"][key] = value
    assert controls.evaluate(metadata)


def test_no_network_request_without_credentials():
    with pytest.raises(ValueError, match="token"):
        controls.fetch_branch("aisecnomad/Nexus-Symbiote", "main", "")


def test_no_arbitrary_network_origin():
    with pytest.raises(ValueError, match="owner/name"):
        controls.fetch_branch("https://evil.example", "main", "unused")
