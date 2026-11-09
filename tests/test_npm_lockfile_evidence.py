"""Lockfile resolution is a bound declaration, never artifact verification."""

import base64
import hashlib
import json

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, TrustTier
from nexus_symbiote.scanners.registry import RegistryScanner
from nexus_symbiote.utils.confined import ConfinedCollection


def project(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"^1.0.0"}}')
    return tmp_path / "package-lock.json"


def record():
    return {
        "version": "1.2.3",
        "resolved": "https://user:PRIVATE_CANARY@private.example/artifacts/PRIVATE_CANARY?token=PRIVATE_CANARY",
        "integrity": "sha512-" + base64.b64encode(b"x" * 64).decode(),
    }


def lock_bytes(entry):
    return (
        json.dumps({"lockfileVersion": 3, "packages": {"node_modules/openai": entry}}, indent=2)
        .replace("\n", "\r\n")
        .encode()
    )


def test_manifest_does_not_invent_registry_origin(tmp_path):
    project(tmp_path)
    component = RegistryScanner().scan(tmp_path).components[0]
    assert component.version == "^1.0.0"
    assert component.registry_uri is None
    assert component.package_url is None


def test_lockfile_resolution_binds_exact_bytes_and_record_without_secrets(tmp_path):
    path = project(tmp_path)
    raw = lock_bytes(record())
    path.write_bytes(raw)
    result = RegistryScanner().scan(tmp_path)
    assert not result.scan_failures
    component = result.components[0]
    assert component.version == "1.2.3"
    assert component.registry_uri == "https://private.example"
    assert component.package_url == "pkg:npm/openai@1.2.3"
    assert component.source_path == "package-lock.json"
    assert component.assurance_level is AssuranceLevel.DECLARED
    assert component.trust_tier is TrustTier.UNKNOWN
    assert component.properties["requested_version"] == "^1.0.0"
    assert component.properties["lockfile_sha256"] == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert (
        component.properties["lockfile_record"]
        == "package-lock.json#/packages/node_modules~1openai"
    )
    assert component.properties["lockfile_integrity"] == record()["integrity"]
    assert component.properties["artifact_verified"] is False
    assert component.claims["package_resolution"].assurance is AssuranceLevel.DECLARED
    assert "PRIVATE_CANARY" not in component.model_dump_json()
    bom = AIBOM(components=[component])
    from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
    from nexus_symbiote.generators.spdx import SPDXGenerator

    assert "PRIVATE_CANARY" not in CycloneDXGenerator().generate_json(bom)
    assert "PRIVATE_CANARY" not in SPDXGenerator().generate_json(bom)


def test_duplicate_lockfile_json_fails_coverage_without_resolution(tmp_path):
    path = project(tmp_path)
    path.write_text('{"packages":{},"packages":{"node_modules/openai":{"version":"9.9.9"}}}')
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures
    assert result.components[0].version == "^1.0.0"
    assert "lockfile_sha256" not in result.components[0].properties


@pytest.mark.parametrize("value", ["PRIVATE_CANARY", "sha512-bm90LWEtaGFzaA==", False])
def test_invalid_integrity_is_reported_and_not_exported(tmp_path, value):
    path = project(tmp_path)
    entry = record()
    entry["integrity"] = value
    path.write_bytes(lock_bytes(entry))
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures
    assert "lockfile_integrity" not in result.components[0].properties
    assert "PRIVATE_CANARY" not in result.components[0].model_dump_json()


def test_excluded_and_symlinked_lockfile_never_supply_resolved_evidence(tmp_path):
    path = project(tmp_path)
    outside = tmp_path / "external.json"
    outside.write_bytes(lock_bytes(record()))
    path.symlink_to(outside)
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures
    assert result.components[0].version == "^1.0.0"
    path.unlink()
    path.write_bytes(lock_bytes(record()))
    scanner = RegistryScanner()
    scanner.configure(exclude_paths=["package-lock.json"])
    result = scanner.scan(tmp_path)
    assert result.surfaces_excluded
    assert result.components[0].version == "^1.0.0"


@pytest.mark.parametrize("extra", [{"link": True}, {"name": "unrelated"}])
def test_local_links_and_aliases_do_not_get_invented_package_identity(tmp_path, extra):
    path = project(tmp_path)
    path.write_bytes(lock_bytes({**record(), **extra}))
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded
    assert result.components[0].version == "^1.0.0"
    assert result.components[0].registry_uri is None


def test_lock_digest_and_resolution_share_a_single_read(tmp_path, monkeypatch):
    path = project(tmp_path)
    raw = lock_bytes(record())
    path.write_bytes(raw)
    original = ConfinedCollection.read_bytes

    def swap(self, candidate, **kwargs):
        content = original(self, candidate, **kwargs)
        if str(candidate).endswith("package-lock.json") and content is not None:
            path.write_bytes(lock_bytes({**record(), "version": "9.9.9"}))
        return content

    monkeypatch.setattr(ConfinedCollection, "read_bytes", swap)
    component = RegistryScanner().scan(tmp_path).components[0]
    assert component.version == "1.2.3"
    assert component.properties["lockfile_sha256"] == "sha256:" + hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    "lock_name, method, source_toml",
    [
        (
            "uv.lock",
            "uv-lockfile",
            'source = { registry = "https://user:SECRET_CANARY@pypi.private.example/simple" }',
        ),
        (
            "poetry.lock",
            "poetry-lockfile",
            'source = { type = "legacy", url = "https://user:SECRET_CANARY@pypi.private.example/simple" }',
        ),
    ],
)
def test_python_lockfile_resolution_binds_exact_version_and_redacts_origin(
    tmp_path, lock_name, method, source_toml
):
    from nexus_symbiote.advisories import package_identity

    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["langgraph>=0.2.0"]\n')
    raw = (
        f'version = 1\n\n[[package]]\nname = "langgraph"\nversion = "0.2.14"\n{source_toml}\n'
    ).encode()
    (tmp_path / lock_name).write_bytes(raw)
    result = RegistryScanner().scan(tmp_path)
    assert not result.scan_failures and not result.surfaces_excluded
    comp = result.components[0]
    assert comp.name == "langgraph"
    assert comp.version == "0.2.14"
    assert comp.package_url == "pkg:pypi/langgraph@0.2.14"
    assert comp.registry_uri == "https://pypi.private.example"
    assert comp.source_path == lock_name
    assert comp.properties["lockfile_sha256"] == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert comp.properties["lockfile_record"] == f"{lock_name}#/package/0"
    assert comp.claims["package_resolution"].method == method
    assert package_identity(comp) == ("PyPI", "langgraph", "0.2.14")
    assert "SECRET_CANARY" not in comp.model_dump_json()


def test_python_lockfile_rejects_editable_or_competing_lockfiles(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["openai>=1.0"]\n')
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "openai"\nversion = "1.2.3"\nsource = { editable = "." }\n'
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded
    assert result.components[0].package_url is None

    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "openai"\nversion = "1.2.3"\n')
    both = RegistryScanner().scan(tmp_path)
    assert any("multiple Python lockfiles" in gap for gap in both.surfaces_excluded)
    assert both.components[0].package_url is None


def test_pnpm_lockfile_resolution_binds_exact_version_and_redacts_origin(tmp_path):
    from nexus_symbiote.advisories import package_identity

    (tmp_path / "package.json").write_text(
        '{"dependencies":{"@modelcontextprotocol/sdk":"^1.0.0"}}'
    )
    integrity = "sha512-" + base64.b64encode(b"y" * 64).decode()
    raw = (
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      '@modelcontextprotocol/sdk':\n"
        "        specifier: ^1.0.0\n"
        "        version: 1.0.4(zod@3.23.8)\n"
        "packages:\n"
        "  '@modelcontextprotocol/sdk@1.0.4':\n"
        "    resolution:\n"
        f"      integrity: {integrity}\n"
        "      tarball: https://user:PNPM_CANARY@npm.private.example/@modelcontextprotocol/sdk/-/sdk-1.0.4.tgz?token=PNPM_CANARY\n"
    ).encode()
    (tmp_path / "pnpm-lock.yaml").write_bytes(raw)
    result = RegistryScanner().scan(tmp_path)
    assert not result.scan_failures and not result.surfaces_excluded
    comp = result.components[0]
    assert comp.name == "@modelcontextprotocol/sdk"
    assert comp.version == "1.0.4"
    assert comp.package_url == "pkg:npm/%40modelcontextprotocol/sdk@1.0.4"
    assert comp.registry_uri == "https://npm.private.example"
    assert comp.source_path == "pnpm-lock.yaml"
    assert comp.properties["lockfile_sha256"] == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert (
        comp.properties["lockfile_record"]
        == "pnpm-lock.yaml#/packages/@modelcontextprotocol~1sdk@1.0.4"
    )
    assert comp.properties["lockfile_integrity"] == integrity
    assert comp.claims["package_resolution"].method == "pnpm-lockfile"
    assert package_identity(comp) == ("npm", "@modelcontextprotocol/sdk", "1.0.4")
    assert "PNPM_CANARY" not in comp.model_dump_json()


def test_yarn_lockfile_resolution_binds_exact_version_and_redacts_origin(tmp_path):
    from nexus_symbiote.advisories import package_identity

    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"^4.0.0"}}')
    integrity = "sha512-" + base64.b64encode(b"z" * 64).decode()
    raw = (
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n"
        "# yarn lockfile v1\n\n"
        '"openai@^4.0.0":\n'
        '  version "4.52.0"\n'
        '  resolved "https://user:YARN_CANARY@registry.private.example/openai/-/openai-4.52.0.tgz#abc"\n'
        f"  integrity {integrity}\n"
    ).encode()
    (tmp_path / "yarn.lock").write_bytes(raw)
    result = RegistryScanner().scan(tmp_path)
    assert not result.scan_failures and not result.surfaces_excluded
    comp = result.components[0]
    assert comp.name == "openai"
    assert comp.version == "4.52.0"
    assert comp.package_url == "pkg:npm/openai@4.52.0"
    assert comp.registry_uri == "https://registry.private.example"
    assert comp.source_path == "yarn.lock"
    assert comp.properties["lockfile_sha256"] == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert comp.properties["lockfile_record"] == "yarn.lock#/openai@^4.0.0"
    assert comp.properties["lockfile_integrity"] == integrity
    assert comp.claims["package_resolution"].method == "yarn-lockfile"
    assert package_identity(comp) == ("npm", "openai", "4.52.0")
    assert "YARN_CANARY" not in comp.model_dump_json()


def test_npm_lockfiles_reject_workspace_links_and_competing_lockfiles(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"^4.0.0"}}')
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      openai:\n"
        "        specifier: workspace:*\n"
        "        version: link:../openai\n"
    )
    pnpm_res = RegistryScanner().scan(tmp_path)
    assert pnpm_res.surfaces_excluded
    assert pnpm_res.components[0].package_url is None

    (tmp_path / "yarn.lock").write_text(
        '"openai@^4.0.0":\n  version "4.52.0"\n  resolution "openai@workspace:."\n'
    )
    both = RegistryScanner().scan(tmp_path)
    assert any("multiple npm lockfiles" in gap for gap in both.surfaces_excluded)
    assert both.components[0].package_url is None
