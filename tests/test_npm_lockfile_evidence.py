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
            {"integrity": "sha1-" + base64.b64encode(b"x" * 20).decode()},
            "weak_lockfile_integrity",
            "medium",
        ),
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
