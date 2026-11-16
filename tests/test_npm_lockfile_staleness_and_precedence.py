"""A lockfile resolved for other package.json specs binds nothing, and a spec counts
as a pin only when npm and pnpm both take it."""

from __future__ import annotations

import base64
import json
from pathlib import Path

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
