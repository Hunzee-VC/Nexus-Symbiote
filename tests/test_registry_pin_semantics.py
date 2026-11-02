"""Declared package identities follow packaging semantics without evaluating markers."""

from pathlib import Path

import pytest

from nexus_symbiote.advisories import package_identity
from nexus_symbiote.core.models import RegistryEntryComponent
from nexus_symbiote.scanners.registry import RegistryScanner


@pytest.mark.parametrize(
    "specifier,version",
    [
        ("==1", "1"),
        ("===1.2.3", "1.2.3"),
        ("==1!2.3", "1!2.3"),
        ("==1.2rc1", "1.2rc1"),
        ("==1.2+local", "1.2+local"),
    ],
)
def test_exact_pep440_registry_pins_reconcile_with_advisory_identity(specifier, version):
    component = RegistryScanner()._pip_component(
        "OpenAI[extra]" + specifier, Path("requirements.txt")
    )
    assert component is not None and not component.risks
    assert component.name == "openai"
    assert package_identity(component) == ("PyPI", "openai", version)


@pytest.mark.parametrize(
    "requirement",
    [
        "openai==1.2.invalid",
        "openai==1.2.*",
        "openai>=1.2",
        "openai==1.2,!=1.2.1",
        "openai==1.2; python_version >= '3.11'",
        "openai @ https://example.com/openai.whl",
        "openai===01.2.3",
        "openai",
    ],
)
def test_nonexact_or_conditional_references_remain_unresolved(requirement):
    component = RegistryScanner()._pip_component(requirement, Path("requirements.txt"))
    assert component is not None and component.package_url is None
    assert component.risks
    with pytest.raises(ValueError):
        package_identity(component)


def test_invalid_registry_requirement_remains_visible_in_collection(tmp_path):
    (tmp_path / "requirements.txt").write_text("openai==1.2.invalid\n")
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures
    assert result.components[0].package_url is None


@pytest.mark.parametrize(
    "kind,name,version", [("pypi", "openai", "1.2.invalid"), ("npm", "openai", "1.2.3-01")]
)
def test_advisory_identity_does_not_accept_invalid_versions_from_external_boms(kind, name, version):
    component = RegistryEntryComponent(
        bom_ref="r",
        name=name,
        registry_type=kind,
        version=version,
        package_url=f"pkg:{kind}/{name}@{version}",
    )
    with pytest.raises(ValueError):
        package_identity(component)


def test_conditional_requirement_retains_marker_and_requested_extras():
    component = RegistryScanner()._pip_component(
        "openai[cli]==1.2; python_version < '3.10'", Path("requirements.txt")
    )
    assert component is not None
    assert "python_version" in component.version
    assert "[cli]" in component.properties["requested_requirement"]
    assert component.package_url is None
