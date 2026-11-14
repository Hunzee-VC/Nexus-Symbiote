"""Lockfile records say where a package came from, in every lockfile format.

A `package-lock.json` record from another registry carries a `registry_origin` finding
and one without an integrity value a `missing_lockfile_integrity` finding; pnpm and Yarn
records carried neither. A uv or Poetry record from another index kept an unqualified
`pkg:pypi` package URL with no finding, and one whose source was a path or a URL that is
not HTTP(S) was recorded as resolved from `https://pypi.org` and exported as the public
package.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from nexus_symbiote.advisories import package_identity
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.scanners.registry import RegistryScanner

INTEGRITY = "sha512-" + base64.b64encode(b"y" * 64).decode()
NPM_MANIFEST = '{"dependencies":{"openai":"^4.0.0"}}'
PYTHON_MANIFEST = '[project]\ndependencies = ["mcp-acme-tools>=1.0"]\n'
UNVERIFIED = (
    "package index of the selected record is not a plain http(s) URL; its origin is unverified"
)


def _scan(root: Path, files: dict[str, str]):
    for name, text in files.items():
        (root / name).write_text(text, encoding="utf-8")
    result = RegistryScanner().scan(root)
    assert len(result.components) == 1
    return result, result.components[0]


def _risks(component) -> dict[str, RiskSeverity]:
    return {risk.category: risk.severity for risk in component.risks}


def _exported_purl(component) -> str | None:
    document = json.loads(CycloneDXGenerator().generate_json(AIBOM(components=[component])))
    return document["components"][0].get("purl")


def _uv(source: str) -> dict[str, str]:
    lock = f'version = 1\n\n[[package]]\nname = "mcp-acme-tools"\nversion = "1.2.3"\n{source}\n'
    return {"pyproject.toml": PYTHON_MANIFEST, "uv.lock": lock}


def _poetry(source: str) -> dict[str, str]:
    lock = f'[[package]]\nname = "mcp-acme-tools"\nversion = "1.2.3"\n{source}\n'
    return {"pyproject.toml": PYTHON_MANIFEST, "poetry.lock": lock}


def _uv_registry(url: str) -> dict[str, str]:
    return _uv(f'source = {{ registry = "{url}" }}')


def _poetry_legacy(url: str) -> dict[str, str]:
    return _poetry(f'source = {{ type = "legacy", url = "{url}", reference = "corp" }}')


@pytest.mark.parametrize("lock", [_uv_registry, _poetry_legacy], ids=["uv", "poetry"])
def test_a_python_record_from_another_index_names_it_and_carries_a_finding(tmp_path, lock):
    result, component = _scan(tmp_path, lock("https://pypi.acme.example/simple"))
    assert not result.scan_failures and not result.surfaces_excluded
    assert component.version == "1.2.3"
    assert component.registry_uri == "https://pypi.acme.example"
    qualified = "pkg:pypi/mcp-acme-tools@1.2.3?repository_url=https://pypi.acme.example"
    assert component.package_url == qualified
    assert _exported_purl(component) == qualified
    assert _risks(component)["registry_origin"] == RiskSeverity.LOW
    assert package_identity(component) == ("PyPI", "mcp-acme-tools", "1.2.3")


@pytest.mark.parametrize("lock", [_uv_registry, _poetry_legacy], ids=["uv", "poetry"])
def test_a_python_record_from_a_cleartext_index_is_a_high_finding(tmp_path, lock):
    result, component = _scan(tmp_path, lock("http://pypi.acme.example/simple"))
    assert not result.scan_failures and not result.surfaces_excluded
    assert component.registry_uri == "http://pypi.acme.example"
    assert component.package_url.endswith("?repository_url=http://pypi.acme.example")
    assert _risks(component)["registry_origin"] == RiskSeverity.HIGH
    detail = next(r.detail for r in component.risks if r.category == "registry_origin")
    assert "cleartext" in detail


@pytest.mark.parametrize(
    "files",
    [
        _uv_registry("https://pypi.org/simple"),
        _uv_registry("https://PyPI.org:443/simple/"),
        _poetry(""),
    ],
    ids=["uv", "uv-port-and-case", "poetry-no-source"],
)
def test_a_python_record_from_the_default_index_keeps_the_public_identity(tmp_path, files):
    result, component = _scan(tmp_path, files)
    assert not result.scan_failures and not result.surfaces_excluded
    assert component.package_url == "pkg:pypi/mcp-acme-tools@1.2.3"
    assert component.registry_uri == "https://pypi.org"
    assert "registry_origin" not in _risks(component)
    assert _exported_purl(component) == "pkg:pypi/mcp-acme-tools@1.2.3"


@pytest.mark.parametrize(
    "files",
    [
        _uv_registry("ftp://files.acme.example/simple"),
        _uv_registry("../wheels"),
        _uv_registry("file:///srv/wheels"),
        _uv_registry("https://"),
        _uv("source = { registry = 7 }"),
        _uv('source = { mirror = "https://pypi.acme.example/simple" }'),
        _poetry_legacy("ftp://files.acme.example/simple"),
        _poetry_legacy("/srv/wheels"),
        _poetry('source = { type = "legacy", reference = "corp" }'),
    ],
    ids=[
        "uv-ftp",
        "uv-path",
        "uv-file-url",
        "uv-no-host",
        "uv-not-text",
        "uv-unknown-kind",
        "poetry-ftp",
        "poetry-path",
        "poetry-no-url",
    ],
)
def test_a_python_record_whose_source_is_not_an_http_index_is_not_bound_to_pypi(tmp_path, files):
    result, component = _scan(tmp_path, files)
    lock_name = next(name for name in files if name.endswith(".lock"))
    assert f"{lock_name}: {UNVERIFIED}" in result.surfaces_excluded
    assert component.package_url is None
    assert component.version != "1.2.3"
    assert "package_resolution" not in component.claims
    assert _exported_purl(component) is None


def _pnpm(resolution: str) -> dict[str, str]:
    lock = (
        "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      openai:\n"
        "        specifier: ^4.0.0\n        version: 4.52.0\npackages:\n  openai@4.52.0:\n"
        "    resolution:\n" + resolution
    )
    return {"package.json": NPM_MANIFEST, "pnpm-lock.yaml": lock}


def _yarn(resolved: str, digest: str) -> dict[str, str]:
    lock = (
        '# yarn lockfile v1\n\n"openai@^4.0.0":\n  version "4.52.0"\n'
        f'  resolved "{resolved}"\n{digest}'
    )
    return {"package.json": NPM_MANIFEST, "yarn.lock": lock}


def _berry(digest: str) -> dict[str, str]:
    lock = (
        "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"
        '"openai@npm:^4.0.0":\n  version: 4.52.0\n  resolution: "openai@npm:4.52.0"\n'
        f"{digest}  languageName: node\n  linkType: hard\n"
    )
    return {"package.json": NPM_MANIFEST, "yarn.lock": lock}


PUBLIC_TARBALL = "https://registry.npmjs.org/openai/-/openai-4.52.0.tgz"
OTHER_TARBALL = "https://npm.acme.example/openai/-/openai-4.52.0.tgz"


@pytest.mark.parametrize(
    "files",
    [
        _pnpm(f"      tarball: {PUBLIC_TARBALL}\n"),
        _yarn(PUBLIC_TARBALL + "#abc", ""),
        _berry(""),
    ],
    ids=["pnpm", "yarn", "yarn-berry"],
)
def test_a_pnpm_or_yarn_record_without_an_integrity_value_is_a_finding(tmp_path, files):
    result, component = _scan(tmp_path, files)
    assert not result.scan_failures
    assert component.version == "4.52.0"
    assert _risks(component)["missing_lockfile_integrity"] == RiskSeverity.MEDIUM


@pytest.mark.parametrize(
    "files",
    [
        _pnpm(f"      integrity: {INTEGRITY}\n      tarball: {OTHER_TARBALL}\n"),
        _yarn(OTHER_TARBALL + "#abc", f"  integrity {INTEGRITY}\n"),
    ],
    ids=["pnpm", "yarn"],
)
def test_a_pnpm_or_yarn_record_from_another_registry_is_a_finding(tmp_path, files):
    result, component = _scan(tmp_path, files)
    assert not result.scan_failures
    assert component.registry_uri == "https://npm.acme.example"
    assert _risks(component)["registry_origin"] == RiskSeverity.LOW
    assert "missing_lockfile_integrity" not in _risks(component)


@pytest.mark.parametrize(
    "files",
    [
        _pnpm(f"      integrity: {INTEGRITY}\n"),
        _yarn(PUBLIC_TARBALL + "#abc", f"  integrity {INTEGRITY}\n"),
        _berry("  checksum: 10c0/" + "ab" * 64 + "\n"),
    ],
    ids=["pnpm", "yarn", "yarn-berry-checksum"],
)
def test_a_complete_public_pnpm_or_yarn_record_carries_neither_finding(tmp_path, files):
    result, component = _scan(tmp_path, files)
    assert not result.scan_failures and not result.surfaces_excluded
    assert component.version == "4.52.0"
    assert not {"missing_lockfile_integrity", "registry_origin"} & set(_risks(component))
