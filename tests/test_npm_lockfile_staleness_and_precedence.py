"""A lockfile resolved for other package.json specs binds nothing, and a spec counts
as a pin only when npm and pnpm both take it."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from nexus_symbiote.scanners.registry import RegistryScanner

INTEGRITY = "sha512-" + base64.b64encode(b"s" * 64).decode()
STALE = "selected package version disagrees with package.json"


def _openai(result):
    (component,) = [c for c in result.components if c.name == "openai"]
    return component


def _npm_lock(root_spec: str, version: str) -> str:
    return json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"openai": root_spec}},
                "node_modules/openai": {
                    "version": version,
                    "resolved": f"https://registry.npmjs.org/openai/-/openai-{version}.tgz",
                    "integrity": INTEGRITY,
                },
            },
        }
    )


def _pnpm_lock(specifier: str, version: str) -> str:
    return (
        "lockfileVersion: '9.0'\n"
        "importers:\n  .:\n    dependencies:\n"
        f"      openai:\n        specifier: {specifier}\n        version: {version}\n"
        f"packages:\n  openai@{version}: {{resolution: {{integrity: '{INTEGRITY}'}}}}\n"
        f"snapshots:\n  openai@{version}: {{}}\n"
    )


def test_a_stale_package_lock_is_not_bound(tmp_path: Path) -> None:
    # package.json moved to ^5 after the lockfile was written for ^4: npm ci refuses it
    # and npm install installs a 5.x release, never the 4.52.0 the record names.
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"^5.0.0"}}')
    (tmp_path / "package-lock.json").write_text(_npm_lock("^4.0.0", "4.52.0"))
    result = RegistryScanner().scan(tmp_path)
    component = _openai(result)
    assert f"package-lock.json: {STALE}" in result.scan_failures
    assert component.package_url is None
    assert "package_resolution" not in component.claims
    assert "version_pinning" in {risk.category for risk in component.risks}


def test_a_stale_pnpm_lock_is_not_bound(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"^5.0.0"}}')
    (tmp_path / "pnpm-lock.yaml").write_text(_pnpm_lock("^4.0.0", "4.52.0"))
    result = RegistryScanner().scan(tmp_path)
    component = _openai(result)
    assert f"pnpm-lock.yaml: {STALE}" in result.scan_failures
    assert component.package_url is None


def test_current_lockfiles_still_bind(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"^4.0.0"}}')
    (tmp_path / "package-lock.json").write_text(_npm_lock("^4.0.0", "4.52.0"))
    assert _openai(RegistryScanner().scan(tmp_path)).package_url == "pkg:npm/openai@4.52.0"
    (tmp_path / "package-lock.json").unlink()
    (tmp_path / "pnpm-lock.yaml").write_text(_pnpm_lock("^4.0.0", "4.52.0"))
    assert _openai(RegistryScanner().scan(tmp_path)).package_url == "pkg:npm/openai@4.52.0"


def test_a_range_in_dependencies_and_a_pin_in_dev_dependencies_is_not_a_pin(
    tmp_path: Path,
) -> None:
    # npm installs the devDependencies pin, pnpm and Yarn the dependencies range.
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"openai":"^4.0.0"},"devDependencies":{"openai":"4.0.0"}}'
    )
    component = _openai(RegistryScanner().scan(tmp_path))
    assert component.package_url is None
    risks = {risk.category: risk for risk in component.risks}
    assert "version_pinning" in risks
    assert "dependencies: ^4.0.0" in risks["version_pinning"].detail


@pytest.mark.parametrize(
    "lock",
    [
        # pnpm 6 and 9 record a specifier with each dependency, pnpm 5 a specifiers map:
        # one that records none was not resolved for package.json.
        "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n"
        "      openai:\n        version: 4.0.0\n"
        f"packages:\n  openai@4.0.0: {{resolution: {{integrity: '{INTEGRITY}'}}}}\n",
        "lockfileVersion: '6.0'\ndependencies:\n  openai:\n    version: 4.0.0\n"
        f"packages:\n  /openai@4.0.0: {{resolution: {{integrity: '{INTEGRITY}'}}}}\n",
        "lockfileVersion: 5.4\ndependencies:\n  openai: 4.0.0\n"
        f"packages:\n  /openai/4.0.0: {{resolution: {{integrity: '{INTEGRITY}'}}}}\n",
        "lockfileVersion: 5.4\nspecifiers:\n  zod: ^3.0.0\ndependencies:\n  openai: 4.0.0\n"
        f"packages:\n  /openai/4.0.0: {{resolution: {{integrity: '{INTEGRITY}'}}}}\n",
    ],
    ids=["v9", "v6", "v5-no-map", "v5-no-entry"],
)
def test_a_pnpm_lock_that_records_no_specifier_is_not_bound(tmp_path: Path, lock: str) -> None:
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"^5.0.0"}}')
    (tmp_path / "pnpm-lock.yaml").write_text(lock)
    result = RegistryScanner().scan(tmp_path)
    assert f"pnpm-lock.yaml: {STALE}" in result.scan_failures
    assert _openai(result).package_url is None
    assert INTEGRITY not in str(_openai(result).model_dump(mode="json"))


def test_a_pnpm_lock_resolved_through_an_override_is_bound(tmp_path: Path) -> None:
    # pnpm 10 writes the override's spec as the importer's specifier, and installs the
    # lockfile frozen.
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"openai":"^4.0.0"},"pnpm":{"overrides":{"openai":"4.52.0"}}}'
    )
    lock = _pnpm_lock("4.52.0", "4.52.0").replace(
        "importers:", "overrides:\n  openai: 4.52.0\nimporters:"
    )
    (tmp_path / "pnpm-lock.yaml").write_text(lock)
    result = RegistryScanner().scan(tmp_path)
    assert f"pnpm-lock.yaml: {STALE}" not in result.scan_failures
    assert _openai(result).package_url == "pkg:npm/openai@4.52.0"
    # A specifier that is neither the override nor package.json's is still stale.
    (tmp_path / "pnpm-lock.yaml").write_text(lock.replace("specifier: 4.52.0", "specifier: 4.0.0"))
    result = RegistryScanner().scan(tmp_path)
    assert f"pnpm-lock.yaml: {STALE}" in result.scan_failures
    assert _openai(result).package_url is None


def test_a_package_lock_without_a_root_entry_is_not_bound(tmp_path: Path) -> None:
    # npm writes the root entry in every lockfile with packages; without it npm finds
    # package.json's edges unaccounted for and resolves again.
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"^5.0.0"}}')
    lock = json.loads(_npm_lock("^4.0.0", "4.52.0"))
    del lock["packages"][""]
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    result = RegistryScanner().scan(tmp_path)
    assert f"package-lock.json: {STALE}" in result.scan_failures
    assert _openai(result).package_url is None


def test_a_dependency_also_listed_as_optional_agrees_with_the_lock_root(tmp_path: Path) -> None:
    # npm drops the dependencies copy of a name optionalDependencies lists before it
    # writes the lockfile, and before it compares package.json with the lock root.
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"openai":"4.52.0"},"optionalDependencies":{"openai":"4.52.0"}}'
    )
    lock = json.loads(_npm_lock("4.52.0", "4.52.0"))
    lock["packages"][""] = {"optionalDependencies": {"openai": "4.52.0"}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert _openai(result).properties["lockfile_integrity"] == INTEGRITY
