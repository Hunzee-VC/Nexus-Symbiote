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
    # The record is from another registry, so the package URL names it and is not
    # mistaken for the public package of the same name.
    assert component.package_url == "pkg:npm/openai@1.2.3?repository_url=https://private.example"
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
    # The record resolves from another registry, so the package URL names it, as an
    # npm lockfile record's does.
    assert comp.package_url == (
        "pkg:npm/%40modelcontextprotocol/sdk@1.0.4?repository_url=https://npm.private.example"
    )
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
    assert comp.package_url == (
        "pkg:npm/openai@4.52.0?repository_url=https://registry.private.example"
    )
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


def test_pnpm_lockfile_of_an_ordinary_application_is_resolved(tmp_path):
    # 2,000 packages is about 80,000 YAML tokens; a 50,000-token bound refused every
    # lockfile past roughly 1,250 packages and failed the project's gate.
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"^4.0.0"}}')
    integrity = "sha512-" + base64.b64encode(b"z" * 64).decode()
    entries = "".join(
        f"  pkg-{index}@1.0.{index}:\n"
        f"    resolution: {{integrity: {integrity}}}\n"
        "    engines: {node: '>=18'}\n"
        "    dependencies:\n"
        f"      dep-{index}: 2.0.{index}\n"
        for index in range(2_000)
    )
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      openai:\n"
        "        specifier: ^4.0.0\n"
        "        version: 4.0.1\n"
        "packages:\n"
        f"  openai@4.0.1:\n    resolution: {{integrity: {integrity}}}\n" + entries
    )
    result = RegistryScanner().scan(tmp_path)
    assert not result.scan_failures and not result.surfaces_excluded
    assert result.components[0].version == "4.0.1"
    assert result.components[0].claims["package_resolution"].method == "pnpm-lockfile"


def npmjs(**changes):
    entry = {
        "version": "1.2.3",
        "resolved": "https://registry.npmjs.org/openai/-/openai-1.2.3.tgz",
        "integrity": "sha512-" + base64.b64encode(b"x" * 64).decode(),
    }
    return {**entry, **changes}


@pytest.mark.parametrize(
    "resolved",
    [
        # Python reads the host after the backslash; WHATWG parsers, which npm
        # uses, treat it as a path separator and connect to evil.example.
        "https://evil.example\\@registry.npmjs.org/openai/-/openai-1.2.3.tgz",
        "https:///evil.example/openai-1.2.3.tgz",
        "http://registry.npmjs.org/openai/-/openai-1.2.3.tgz",
        "git+ssh://git@github.com/openai/openai-node.git",
        "https://registry.npmjs.оrg/openai/-/openai-1.2.3.tgz",
        "https://registry%2enpmjs.org/openai/-/openai-1.2.3.tgz",
        "https://registry.npmjs.org/openai/-/openai-1.2.3.tgz\t",
        7,
    ],
)
def test_a_resolved_url_another_parser_could_read_differently_is_a_failure(tmp_path, resolved):
    path = project(tmp_path)
    path.write_bytes(lock_bytes(npmjs(resolved=resolved)))
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [
        "package-lock.json: selected package has an unsupported resolved URL"
    ]
    component = result.components[0]
    assert component.registry_uri is None and component.package_url is None
    assert component.version == "^1.0.0"
    assert "lockfile_record" not in component.properties


def test_a_consistent_registry_record_resolves_the_declared_range(tmp_path):
    path = project(tmp_path)
    path.write_bytes(lock_bytes(npmjs()))
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    component = result.components[0]
    assert component.registry_uri == "https://registry.npmjs.org"
    assert component.package_url == "pkg:npm/openai@1.2.3"
    # The lockfile pins the range to one version with sha512 integrity.
    assert component.risks == []


@pytest.mark.parametrize(
    ("changes", "category", "severity"),
    [
        ({"integrity": None}, "missing_lockfile_integrity", "medium"),
        (
            {"resolved": "https://registry.npmjs.org/evil/-/evil-1.2.3.tgz"},
            "lockfile_resolution_mismatch",
            "high",
        ),
        (
            {"resolved": "https://registry.npmjs.org/openai/-/openai-9.9.9.tgz"},
            "lockfile_resolution_mismatch",
            "high",
        ),
        (
            {"resolved": "https://npm.corp.example/api/npm/openai/-/other-1.2.3.tgz"},
            "lockfile_resolution_mismatch",
            "high",
        ),
        (
            {"resolved": "https://npm.corp.example/openai/-/openai-1.2.3.tgz"},
            "registry_origin",
            "low",
        ),
    ],
)
def test_lock_record_inconsistencies_are_findings(tmp_path, changes, category, severity):
    path = project(tmp_path)
    entry = npmjs(**changes)
    if entry.get("integrity") is None:
        del entry["integrity"]
    path.write_bytes(lock_bytes(entry))
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    component = result.components[0]
    found = [(r.category, r.severity.value) for r in component.risks]
    assert (category, severity) in found
    if category == "lockfile_resolution_mismatch":
        # The record contradicts itself, so it does not establish an identity.
        assert component.package_url is None
    if category != "registry_origin":
        # The range is not resolved by a record without strong, consistent evidence.
        assert ("version_pinning", "medium") in found


def test_an_integrity_value_with_only_sha1_is_a_failure(tmp_path):
    # npm, pnpm and Yarn read the same SRI values; one with only SHA-1 is refused for
    # every lockfile, so the record binds nothing and the range stays unresolved.
    path = project(tmp_path)
    sha1 = "sha1-" + base64.b64encode(b"x" * 20).decode()
    path.write_bytes(lock_bytes(npmjs(integrity=sha1)))
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == ["package-lock.json: invalid selected package integrity"]
    component = result.components[0]
    assert "lockfile_integrity" not in component.properties
    assert component.package_url is None and component.version == "^1.0.0"
    assert ("version_pinning", "medium") in [
        (r.category, r.severity.value) for r in component.risks
    ]


def test_an_integrity_value_with_a_strong_hash_beside_sha1_is_strong(tmp_path):
    path = project(tmp_path)
    both = " ".join(
        [
            "sha512-" + base64.b64encode(b"x" * 64).decode(),
            "sha1-" + base64.b64encode(b"x" * 20).decode(),
        ]
    )
    path.write_bytes(lock_bytes(npmjs(integrity=both)))
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [] and result.components[0].risks == []
    assert result.components[0].properties["lockfile_integrity"] == both


def test_an_exact_spec_the_lock_record_contradicts_is_a_failure(tmp_path):
    # npm ci refuses a lockfile that does not satisfy package.json.
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"1.0.0"}}')
    (tmp_path / "package-lock.json").write_bytes(lock_bytes(npmjs()))
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [
        "package-lock.json: selected package version disagrees with package.json"
    ]
    component = result.components[0]
    assert component.version == "1.0.0" and component.package_url is None


@pytest.mark.parametrize(
    ("spec", "category", "severity"),
    [
        ("github:openai/openai-node", "nonregistry_source", "high"),
        ("git+https://github.com/openai/openai-node.git#v4.52.0", "nonregistry_source", "high"),
        (
            "git+https://github.com/openai/openai-node.git#" + "a" * 40,
            "nonregistry_source",
            "medium",
        ),
        ("https://h.example/openai-4.52.0.tgz", "nonregistry_source", "medium"),
        ("http://h.example/openai-4.52.0.tgz", "nonregistry_source", "high"),
        ("file:../openai", "nonregistry_source", "medium"),
        ("npm:openai@4.52.0", "package_alias", "low"),
    ],
)
def test_sources_that_change_identity_have_their_own_findings(tmp_path, spec, category, severity):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"openai": spec}}))
    component = RegistryScanner().scan(tmp_path).components[0]
    assert [(r.category, r.severity.value) for r in component.risks] == [(category, severity)]
    if category == "nonregistry_source":
        # Not a registry package, so no npm package URL.
        assert component.package_url is None


def test_an_unrelated_lockfile_change_still_alerts_through_the_lockfile_digest(tmp_path):
    # The digest of the whole lockfile is the only drift signal for the transitive
    # dependencies the collector does not inventory, so it stays on each component.
    path = project(tmp_path)
    path.write_bytes(lock_bytes(npmjs()))
    first = RegistryScanner().scan(tmp_path).components[0]
    lock = json.loads(path.read_text())
    lock["packages"]["node_modules/semver"] = {"version": "7.6.0"}
    path.write_text(json.dumps(lock))
    second = RegistryScanner().scan(tmp_path).components[0]
    assert first.properties["lockfile_sha256"] != second.properties["lockfile_sha256"]


SHA512 = "sha512-" + base64.b64encode(b"w" * 64).decode()
NPMJS_TARBALL = "https://registry.npmjs.org/openai/-/openai-4.52.0.tgz"


def node_lock(lock_name, resolved=NPMJS_TARBALL, *, integrity=SHA512, version="4.52.0"):
    """A pnpm or Yarn v1 lockfile resolving openai@^4.0.0 to one record."""
    if lock_name == "pnpm-lock.yaml":
        resolution = f"      integrity: {integrity}\n"
        if resolved is not None:
            resolution += f"      tarball: '{resolved}'\n"
        return (
            "lockfileVersion: '9.0'\n"
            "importers:\n"
            "  .:\n"
            "    dependencies:\n"
            "      openai:\n"
            "        specifier: ^4.0.0\n"
            f"        version: {version}\n"
            "packages:\n"
            f"  openai@{version}:\n"
            "    resolution:\n" + resolution
        )
    lines = ['"openai@^4.0.0":', f'  version "{version}"']
    if resolved is not None:
        lines.append(f'  resolved "{resolved}"')
    lines.append(f"  integrity {integrity}")
    return "# yarn lockfile v1\n\n" + "\n".join(lines) + "\n"


@pytest.mark.parametrize("lock_name", ["pnpm-lock.yaml", "yarn.lock"])
def test_pnpm_and_yarn_records_from_the_default_registry_keep_an_advisory_identity(
    tmp_path, lock_name
):
    from nexus_symbiote.advisories import package_identity

    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"^4.0.0"}}')
    (tmp_path / lock_name).write_text(node_lock(lock_name))
    result = RegistryScanner().scan(tmp_path)
    assert not result.scan_failures and not result.surfaces_excluded
    comp = result.components[0]
    assert comp.package_url == "pkg:npm/openai@4.52.0"
    assert comp.registry_uri == "https://registry.npmjs.org"
    assert package_identity(comp) == ("npm", "openai", "4.52.0")


@pytest.mark.parametrize("lock_name", ["pnpm-lock.yaml", "yarn.lock"])
@pytest.mark.parametrize(
    ("changes", "failure"),
    [
        # A WHATWG parser, which pnpm and Yarn use as npm does, connects to evil.example.
        (
            {"resolved": "https://evil.example\\@registry.npmjs.org/openai/-/openai-4.52.0.tgz"},
            "selected package has an unsupported resolved URL",
        ),
        (
            {"resolved": "http://registry.npmjs.org/openai/-/openai-4.52.0.tgz"},
            "selected package has an unsupported resolved URL",
        ),
        (
            {"integrity": "sha1-" + base64.b64encode(b"w" * 20).decode()},
            "invalid selected package integrity",
        ),
        ({"version": "04.52.0"}, "selected package lacks an exact version"),
    ],
)
def test_pnpm_and_yarn_records_are_checked_as_npm_lockfile_records(
    tmp_path, lock_name, changes, failure
):
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"^4.0.0"}}')
    (tmp_path / lock_name).write_text(node_lock(lock_name, **changes))
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [f"{lock_name}: {failure}"]
    comp = result.components[0]
    assert comp.version == "^4.0.0" and comp.package_url is None and comp.registry_uri is None
    assert "lockfile_record" not in comp.properties
    assert "package_resolution" not in comp.claims


@pytest.mark.parametrize("lock_name", ["pnpm-lock.yaml", "yarn.lock"])
def test_a_pnpm_or_yarn_tarball_naming_another_package_is_a_finding(tmp_path, lock_name):
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"^4.0.0"}}')
    evil = "https://registry.npmjs.org/evil/-/evil-4.52.0.tgz"
    (tmp_path / lock_name).write_text(node_lock(lock_name, evil))
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    comp = result.components[0]
    assert ("lockfile_resolution_mismatch", "high") in [
        (r.category, r.severity.value) for r in comp.risks
    ]
    # The record contradicts itself, so it does not establish an identity.
    assert comp.package_url is None and comp.version == "4.52.0"


@pytest.mark.parametrize("lock_name", ["pnpm-lock.yaml", "yarn.lock"])
def test_an_exact_spec_a_pnpm_or_yarn_record_contradicts_is_a_failure(tmp_path, lock_name):
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"4.0.0"}}')
    (tmp_path / lock_name).write_text(node_lock(lock_name))
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [
        f"{lock_name}: selected package version disagrees with package.json"
    ]
    comp = result.components[0]
    assert comp.version == "4.0.0" and "package_resolution" not in comp.claims
    # The record is not taken, so the version the spec names is in doubt, as for npm.
    assert comp.package_url is None


@pytest.mark.parametrize("other", ["pnpm-lock.yaml", "yarn.lock"])
def test_npm_shrinkwrap_beside_another_package_managers_lockfile_is_ambiguous(tmp_path, other):
    project(tmp_path)
    (tmp_path / "npm-shrinkwrap.json").write_bytes(lock_bytes(npmjs()))
    (tmp_path / other).write_text(node_lock(other))
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded == [
        f"multiple npm lockfiles present (npm-shrinkwrap.json, {other}); resolution is ambiguous"
    ]
    comp = result.components[0]
    assert comp.version == "^1.0.0" and "lockfile_sha256" not in comp.properties


@pytest.mark.parametrize("lock_name", ["uv.lock", "poetry.lock"])
# 18 parts are 17 dots, one over the bound pyproject.toml has.
@pytest.mark.parametrize("parts", [18, 4_000])
def test_a_long_dotted_key_in_a_python_lockfile_is_refused_before_parsing(
    tmp_path, lock_name, parts
):
    # tomllib's cost grows with the square of a dotted key's parts, quoted ones too.
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["langgraph>=0.2.0"]\n')
    key = ".".join(['""'] * parts)
    (tmp_path / lock_name).write_text(
        f'[[package]]\nname = "langgraph"\nversion = "0.2.14"\n{key} = 1\n'
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [f"{lock_name}: invalid or unsupported lockfile"]
    assert "package_resolution" not in result.components[0].claims


@pytest.mark.parametrize("url_file", ["requirements.txt", "pyproject.toml"])
def test_a_python_lockfile_does_not_bind_a_package_declared_from_a_url(tmp_path, url_file):
    # The rating follows every declaration whichever file holds it, so a URL in either
    # file keeps the registry resolution of uv.lock off the component.
    url = "langgraph @ https://example.com/langgraph-0.2.14.tar.gz"
    pin = "langgraph==0.2.14"
    requirements, dependency = (url, pin) if url_file == "requirements.txt" else (pin, url)
    (tmp_path / "requirements.txt").write_text(requirements + "\n")
    (tmp_path / "pyproject.toml").write_text(f'[project]\ndependencies = ["{dependency}"]\n')
    (tmp_path / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "langgraph"\nversion = "0.2.14"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    result = RegistryScanner().scan(tmp_path)
    assert "uv.lock" in result.surfaces_scanned
    comp = result.components[0]
    assert comp.package_url is None
    assert "package_resolution" not in comp.claims
    assert "nonregistry_source" in [r.category for r in comp.risks]


@pytest.mark.parametrize("lock_name", ["pnpm-lock.yaml", "yarn.lock"])
def test_an_alias_is_not_resolved_through_a_pnpm_or_yarn_record(tmp_path, lock_name):
    # The alias installs openai under "oai"; the record of the direct openai dependency
    # must not be bound to it.
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"oai": "npm:openai@^3.0.0", "openai": "^4.0.0"}})
    )
    if lock_name == "pnpm-lock.yaml":
        lock = (
            "lockfileVersion: '9.0'\n"
            "importers:\n"
            "  .:\n"
            "    dependencies:\n"
            "      oai:\n"
            "        specifier: npm:openai@^3.0.0\n"
            "        version: openai@3.3.0\n"
            "      openai:\n"
            "        specifier: ^4.0.0\n"
            "        version: 4.52.0\n"
            "packages:\n"
            "  openai@3.3.0:\n"
            f"    resolution: {{integrity: {SHA512}}}\n"
            "  openai@4.52.0:\n"
            f"    resolution: {{integrity: {SHA512}}}\n"
        )
    else:
        lock = (
            '"oai@npm:openai@^3.0.0":\n  version "3.3.0"\n'
            f'  resolved "https://registry.yarnpkg.com/openai/-/openai-3.3.0.tgz"\n'
            f"  integrity {SHA512}\n\n"
            '"openai@^4.0.0":\n  version "4.52.0"\n'
            f'  resolved "https://registry.yarnpkg.com/openai/-/openai-4.52.0.tgz"\n'
            f"  integrity {SHA512}\n"
        )
    (tmp_path / lock_name).write_text(lock)
    result = RegistryScanner().scan(tmp_path)
    by_ref = {c.bom_ref: c for c in result.components}
    assert by_ref["registry:npm/openai"].version == "4.52.0"
    alias = by_ref["registry:npm/oai"]
    assert alias.name == "openai" and alias.version == "^3.0.0"
    assert "package_resolution" not in alias.claims
    assert result.surfaces_excluded == [f"{lock_name}: aliased package identity is unresolved"]
