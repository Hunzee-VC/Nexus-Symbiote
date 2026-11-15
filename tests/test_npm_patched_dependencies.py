"""A package the package manager patches at install is not the registry artifact.

pnpm applies the patches that ``pnpm.patchedDependencies`` in package.json, or
``patchedDependencies`` in pnpm-workspace.yaml, names, and records them in the lockfile
(``patchedDependencies`` and a ``(patch_hash=...)`` suffix); Bun applies those of a
top-level ``patchedDependencies``. The lockfile's integrity value is that of the
unpatched tarball, so a patched package binds no package URL or integrity, as a Yarn
``patch:`` resolution does not.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.registry import RegistryScanner

HASH = "bf334fe002a3145952411ceb9359620a132a3b7dad0b9f0e3dd46b698d536fd2"
INTEGRITY = (
    "sha512-UHv70gIw20pxu9tiUueE9iS+4U4eTGiTgQr+zlJ5aX4oj6LUUp+7mBn0xAqilawftwUB/"
    "biohPth2vcZFmoNYw=="
)
PATCH = (
    "diff --git a/index.js b/index.js\n"
    "--- a/index.js\n"
    "+++ b/index.js\n"
    "@@ -1,1 +1,2 @@\n"
    ' "use strict";\n'
    "+globalThis.__fixture_patched = true;\n"
)
PNPM_GAP = "pnpm-lock.yaml: patched dependency is unverified"
MANIFEST_GAP = "package.json: patched dependency is unverified"
WORKSPACE_GAP = "pnpm-workspace.yaml: patched dependency is unverified"
WORKSPACE_UNREAD = "pnpm-workspace.yaml: workspace settings not read"


def pnpm10_lock(
    *,
    patched: str | None = "openai@4.0.0",
    version: str = f"4.0.0(patch_hash={HASH})",
) -> str:
    """The lockfile pnpm 10.28 writes for openai 4.0.0 under a patch, trimmed to the
    records the collector reads."""
    header = "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\n"
    if patched is not None:
        header += (
            "patchedDependencies:\n"
            f"  {patched}:\n"
            f"    hash: {HASH}\n"
            "    path: patches/openai@4.0.0.patch\n\n"
        )
    return header + (
        "importers:\n\n"
        "  .:\n"
        "    dependencies:\n"
        "      openai:\n"
        "        specifier: 4.0.0\n"
        f"        version: {version}\n\n"
        "packages:\n\n"
        "  openai@4.0.0:\n"
        f"    resolution: {{integrity: {INTEGRITY}}}\n"
        "    hasBin: true\n\n"
        "snapshots:\n\n"
        f"  openai@4.0.0(patch_hash={HASH}):\n"
        "    dependencies:\n"
        "      node-fetch: 2.7.0\n"
    )


def write_project(root, manifest, lock=None, workspace=None):
    (root / "package.json").write_text(json.dumps(manifest))
    (root / "patches").mkdir(exist_ok=True)
    (root / "patches" / "openai@4.0.0.patch").write_text(PATCH)
    if lock is not None:
        (root / "pnpm-lock.yaml").write_text(lock)
    if workspace is not None:
        (root / "pnpm-workspace.yaml").write_text(workspace)
    return RegistryScanner().scan(root)


def assert_unbound(component, spec="4.0.0"):
    assert component.version == spec
    assert component.package_url is None
    assert component.registry_uri is None
    assert component.source_path == "package.json"
    for key in ("lockfile_integrity", "lockfile_record", "lockfile_sha256"):
        assert key not in component.properties
    assert component.properties["collection_mode"] == "manifest-reference"
    assert "package_resolution" not in component.claims
    assert ("nonregistry_source", "medium") in [
        (risk.category, risk.severity.value) for risk in component.risks
    ]
    (patched,) = [risk for risk in component.risks if "patch" in risk.detail]
    assert component.name in patched.detail


PNPM_MANIFEST = {
    "name": "fixture",
    "dependencies": {"openai": "4.0.0"},
    "pnpm": {"patchedDependencies": {"openai@4.0.0": "patches/openai@4.0.0.patch"}},
}


def test_a_pnpm_patch_binds_neither_the_registry_package_url_nor_its_integrity(tmp_path):
    result = write_project(tmp_path, PNPM_MANIFEST, pnpm10_lock())
    assert result.scan_failures == []
    assert result.surfaces_excluded == [MANIFEST_GAP]
    (component,) = result.components
    assert component.name == "openai"
    assert_unbound(component)


def test_a_patched_package_fails_the_scan_gate(tmp_path):
    write_project(tmp_path, PNPM_MANIFEST, pnpm10_lock())
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "--no-project-policy", "--check"])
    assert result.exit_code == 1
    assert "Scan gate failed" in result.stderr
    assert MANIFEST_GAP in result.stderr


@pytest.mark.parametrize(
    "patched",
    [
        "openai@4.0.0",
        # pnpm 10 patches every version for a bare name, and a range's versions.
        "openai",
        "openai@^4.0.0",
        "'openai@4.0.0 || 4.1.0'",
        # pnpm refuses a patch it does not apply; any version of the name counts.
        "openai@3.0.0",
        "OpenAI@4.0.0",
        "'  openai@4.0.0 '",
        "/openai@4.0.0",
        '"open\\x61i@4.0.0"',
    ],
)
def test_a_lockfile_patch_entry_alone_unbinds_the_package(tmp_path, patched):
    # The lockfile keeps the patch that package.json no longer names, and its importer
    # version no longer carries the hash.
    manifest = {"dependencies": {"openai": "4.0.0"}}
    result = write_project(tmp_path, manifest, pnpm10_lock(patched=patched, version="4.0.0"))
    assert result.scan_failures == []
    assert result.surfaces_excluded == [PNPM_GAP]
    assert_unbound(result.components[0])


@pytest.mark.parametrize(
    "version",
    [
        f"4.0.0(patch_hash={HASH})",
        f"4.0.0(patch_hash={HASH})(zod@3.23.8)",
        f"4.0.0(zod@3.23.8)(patch_hash={HASH})",
        f"4.0.0(zod@3.23.8(@types/node@20.0.0))(patch_hash={HASH})",
        f"'4.0.0( PATCH_HASH={HASH})'",
        f"4.0.0(patch_hash={HASH}",
        f"4.0.0)(patch_hash={HASH}",
        f"4.0.0_patch_hash={HASH}",
    ],
)
def test_a_patch_hash_in_the_importer_version_alone_unbinds_the_package(tmp_path, version):
    manifest = {"dependencies": {"openai": "4.0.0"}}
    result = write_project(tmp_path, manifest, pnpm10_lock(patched=None, version=version))
    assert result.scan_failures == []
    assert result.surfaces_excluded == [PNPM_GAP]
    assert_unbound(result.components[0])


def pnpm8_lock(*, patched=True, version=f"4.0.0(patch_hash={HASH})", key=None):
    """A lockfile v6 as pnpm 8 writes it for a patched package (written by hand from
    the format: pnpm 8 records ``patched: true`` on the package record)."""
    head = "lockfileVersion: '6.0'\n\n"
    if patched:
        head += f"patchedDependencies:\n  openai@4.0.0:\n    hash: {HASH}\n    path: p.patch\n\n"
    return head + (
        "dependencies:\n"
        "  openai:\n"
        "    specifier: 4.0.0\n"
        f"    version: {version}\n\n"
        "packages:\n\n"
        f"  {key or '/openai@' + version}:\n"
        f"    resolution: {{integrity: {INTEGRITY}}}\n"
        "    patched: true\n"
        "    dev: false\n"
    )


@pytest.mark.parametrize(
    "lock",
    [
        pnpm8_lock(),
        pnpm8_lock(patched=False),
        # Only the record says it is patched.
        pnpm8_lock(patched=False, version="4.0.0"),
        # No root importer: the record is found by name.
        f"lockfileVersion: 5.4\npackages:\n  /openai@4.0.0(patch_hash={HASH}):\n"
        f"    resolution: {{integrity: {INTEGRITY}}}\n",
    ],
)
def test_a_pnpm8_patched_record_unbinds_the_package(tmp_path, lock):
    result = write_project(tmp_path, {"dependencies": {"openai": "4.0.0"}}, lock)
    assert result.scan_failures == []
    assert result.surfaces_excluded == [PNPM_GAP]
    assert_unbound(result.components[0])


@pytest.mark.parametrize(
    "workspace",
    [
        # As pnpm 10 writes it.
        "patchedDependencies:\n  openai: patches/openai.patch\n",
        "packages:\n  - 'packages/*'\npatchedDependencies:\n  'openai@4.0.0': patches/x.patch\n",
        "patchedDependencies: {openai@^4: patches/x.patch}\n",
        'patchedDependencies:\n  "@scope/other": a.patch\n  "openai": b.patch\n',
    ],
)
def test_a_workspace_patch_unbinds_the_package_the_lockfile_does_not_mark(tmp_path, workspace):
    # pnpm install without --frozen-lockfile applies the patch the workspace names
    # and rewrites the lockfile.
    manifest = {"dependencies": {"openai": "4.0.0"}}
    lock = pnpm10_lock(patched=None, version="4.0.0")
    result = write_project(tmp_path, manifest, lock, workspace)
    assert result.scan_failures == []
    assert result.surfaces_excluded == [WORKSPACE_UNREAD, WORKSPACE_GAP]
    assert "pnpm-workspace.yaml" in result.surfaces_scanned
    assert_unbound(result.components[0])


@pytest.mark.parametrize(
    "workspace",
    [
        # An alias would hide the map from a reader that does not resolve it.
        "base: &b {openai: x.patch}\npatchedDependencies: *b\n",
        "patchedDependencies: !!map {openai: x.patch}\n",
        "patchedDependencies: [\n",
        "- openai\n",
        "patchedDependencies:\n  openai: a.patch\npatchedDependencies: {}\n",
        "patchedDependencies:\n  1: a.patch\n",
        "patchedDependencies: [openai]\n",
        "patchedDependencies:\n  '@4.0.0': a.patch\n",
    ],
)
def test_a_workspace_file_that_is_not_read_leaves_every_package_unbound(tmp_path, workspace):
    manifest = {"dependencies": {"openai": "4.0.0", "@anthropic-ai/sdk": "0.20.0"}}
    lock = pnpm10_lock(patched=None, version="4.0.0")
    result = write_project(tmp_path, manifest, lock, workspace)
    assert result.scan_failures in (
        [],
        ["pnpm-workspace.yaml: invalid or unsupported workspace file"],
    )
    assert result.surfaces_excluded == [WORKSPACE_UNREAD, WORKSPACE_GAP]
    assert [c.package_url for c in result.components] == [None, None]
    assert all("lockfile_integrity" not in c.properties for c in result.components)


@pytest.mark.parametrize("workspace", ["", "# no settings\n", "---\n", "--- # empty\n...\n"])
def test_an_empty_workspace_file_patches_nothing(tmp_path, workspace):
    manifest = {"dependencies": {"openai": "4.0.0"}}
    result = write_project(
        tmp_path, manifest, pnpm10_lock(patched=None, version="4.0.0"), workspace
    )
    assert result.scan_failures == []
    assert result.surfaces_excluded == [WORKSPACE_UNREAD]
    assert result.components[0].package_url == "pkg:npm/openai@4.0.0"


def test_a_workspace_patch_symlinked_out_of_the_root_is_not_followed(tmp_path):
    outside = tmp_path / "outside.yaml"
    outside.write_text("patchedDependencies:\n  openai: x.patch\n")
    root = tmp_path / "root"
    root.mkdir()
    (root / "pnpm-workspace.yaml").symlink_to(outside)
    result = write_project(root, {"dependencies": {"openai": "4.0.0"}})
    assert result.scan_failures or WORKSPACE_GAP in result.surfaces_excluded
    assert result.components[0].package_url is None


@pytest.mark.parametrize(
    "manifest",
    [
        # pnpm, without a lockfile.
        PNPM_MANIFEST,
        # Bun reads the top-level field.
        {"dependencies": {"openai": "4.0.0"}, "patchedDependencies": {"openai@4.0.0": "p"}},
        {"dependencies": {"openai": "4.0.0"}, "patchedDependencies": {"openai": "p"}},
        # The patch names the package an alias installs.
        {
            "dependencies": {"my-openai": "npm:openai@4.0.0"},
            "pnpm": {"patchedDependencies": {"openai@4.0.0": "p"}},
        },
        {
            "dependencies": {"openai": "4.0.0"},
            "pnpm": {"patchedDependencies": {"@x/y": "p", "OPENAI@4.0.0": "p"}},
        },
    ],
)
def test_an_exact_spec_a_manifest_patch_names_has_no_package_url(tmp_path, manifest):
    result = write_project(tmp_path, manifest)
    assert result.scan_failures == []
    assert result.surfaces_excluded == [MANIFEST_GAP]
    (component,) = result.components
    assert component.package_url is None
    assert ("nonregistry_source", "medium") in [
        (risk.category, risk.severity.value) for risk in component.risks
    ]


@pytest.mark.parametrize("field", [["openai@4.0.0"], "openai@4.0.0", 1, True])
@pytest.mark.parametrize("path", [("pnpm", "patchedDependencies"), ("patchedDependencies",)])
def test_a_patch_map_that_is_not_a_map_leaves_every_package_unbound(tmp_path, field, path):
    manifest: dict = {"dependencies": {"openai": "4.0.0", "@anthropic-ai/sdk": "0.20.0"}}
    if len(path) == 2:
        manifest["pnpm"] = {"patchedDependencies": field}
    else:
        manifest["patchedDependencies"] = field
    result = write_project(tmp_path, manifest)
    assert result.surfaces_excluded == [MANIFEST_GAP]
    assert [c.package_url for c in result.components] == [None, None]


def test_too_many_patch_entries_leave_every_package_unbound(tmp_path):
    entries = {f"pkg-{index}@1.0.0": "p" for index in range(10_001)}
    manifest = {"dependencies": {"openai": "4.0.0"}, "pnpm": {"patchedDependencies": entries}}
    result = write_project(tmp_path, manifest)
    assert result.surfaces_excluded == [MANIFEST_GAP]
    assert result.components[0].package_url is None


@pytest.mark.parametrize("value", ["[openai@4.0.0]", "openai@4.0.0", "1"])
def test_a_lockfile_patch_map_that_is_not_a_map_is_an_unsupported_lockfile(tmp_path, value):
    lock = pnpm10_lock(patched=None, version="4.0.0").replace(
        "importers:", f"patchedDependencies: {value}\n\nimporters:", 1
    )
    result = write_project(tmp_path, {"dependencies": {"openai": "4.0.0"}}, lock)
    assert result.scan_failures == ["pnpm-lock.yaml: invalid or unsupported lockfile"]
    assert result.components[0].package_url is None


def npm_lock():
    return json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/openai": {
                    "version": "4.0.0",
                    "resolved": "https://registry.npmjs.org/openai/-/openai-4.0.0.tgz",
                    "integrity": INTEGRITY,
                }
            },
        }
    )


@pytest.mark.parametrize(
    ("lock_name", "lock"),
    [
        ("package-lock.json", npm_lock()),
        (
            "yarn.lock",
            '"openai@4.0.0":\n  version "4.0.0"\n'
            '  resolved "https://registry.yarnpkg.com/openai/-/openai-4.0.0.tgz"\n'
            f"  integrity {INTEGRITY}\n",
        ),
    ],
)
def test_another_package_managers_record_does_not_bind_a_patched_package(tmp_path, lock_name, lock):
    # Which package manager installs is not known: pnpm resolves afresh beside another
    # lockfile, and Bun migrates package-lock.json.
    (tmp_path / lock_name).write_text(lock)
    result = write_project(tmp_path, PNPM_MANIFEST)
    assert result.scan_failures == []
    assert result.surfaces_excluded == [MANIFEST_GAP]
    assert_unbound(result.components[0])


def test_a_patch_hash_of_a_peer_does_not_unbind_the_package_that_requires_it(tmp_path):
    # pnpm 10 writes the peer's own suffix, patch hash included, inside the parentheses
    # that follow the dependent's version.
    lock = (
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      '@langchain/core':\n"
        "        specifier: 0.3.0\n"
        f"        version: 0.3.0(openai@4.104.0(patch_hash={HASH})(zod@3.25.76))\n"
        "packages:\n"
        "  '@langchain/core@0.3.0':\n"
        f"    resolution: {{integrity: {INTEGRITY}}}\n"
    )
    manifest = {"dependencies": {"@langchain/core": "0.3.0"}}
    (tmp_path / "package.json").write_text(json.dumps(manifest))
    (tmp_path / "pnpm-lock.yaml").write_text(lock)
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    (component,) = result.components
    assert component.package_url == "pkg:npm/%40langchain/core@0.3.0"
    assert component.properties["lockfile_integrity"] == INTEGRITY


@pytest.mark.parametrize(
    "patches",
    [
        {"left-pad@1.3.0": "p"},
        {"openai-extra@1.0.0": "p"},
        {"@openai/agents@0.1.0": "p"},
        {"@scope/openai@1.0.0": "p"},
        # The name a package without an alias would be compared under if it had one.
        {"none@1.0.0": "p"},
        {},
    ],
)
def test_a_patch_of_another_package_leaves_the_package_bound(tmp_path, patches):
    manifest = {"dependencies": {"openai": "4.0.0"}, "pnpm": {"patchedDependencies": patches}}
    lock = pnpm10_lock(patched=None, version="4.0.0")
    if patches:
        names = "".join(f"  '{key}':\n    hash: {HASH}\n    path: p\n" for key in patches)
        lock = lock.replace("importers:", f"patchedDependencies:\n{names}\nimporters:", 1)
    result = write_project(tmp_path, manifest, lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    (component,) = result.components
    assert component.package_url == "pkg:npm/openai@4.0.0"
    assert component.properties["lockfile_integrity"] == INTEGRITY
    assert not any("patch" in risk.detail for risk in component.risks)


def test_a_workspace_without_patches_leaves_the_package_bound(tmp_path):
    manifest = {"dependencies": {"openai": "4.0.0"}}
    lock = pnpm10_lock(patched=None, version="4.0.0")
    workspace = "packages:\n  - 'packages/*'\ncatalog:\n  zod: ^3.23.8\npatchedDependencies:\n"
    result = write_project(tmp_path, manifest, lock, workspace)
    assert result.scan_failures == []
    assert result.surfaces_excluded == [WORKSPACE_UNREAD]
    assert result.components[0].package_url == "pkg:npm/openai@4.0.0"


def test_a_patched_package_outside_the_catalog_needs_no_workspace_read(tmp_path):
    # Without an inventoried npm package, the workspace file is not parsed, so a file
    # pnpm would refuse does not fail a project the collector has nothing to say about.
    (tmp_path / "package.json").write_text('{"dependencies":{"left-pad":"1.3.0"}}')
    (tmp_path / "pnpm-workspace.yaml").write_text("patchedDependencies: [\n")
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert result.surfaces_excluded == [WORKSPACE_UNREAD]
    assert result.components == []


def test_a_patched_and_an_unpatched_package_are_told_apart(tmp_path):
    manifest = {
        "dependencies": {"openai": "4.0.0", "@anthropic-ai/sdk": "0.20.0"},
        "pnpm": {"patchedDependencies": {"@anthropic-ai/sdk@0.20.0": "p"}},
    }
    result = write_project(tmp_path, manifest)
    assert result.surfaces_excluded == [MANIFEST_GAP]
    by_name = {component.name: component for component in result.components}
    assert by_name["openai"].package_url == "pkg:npm/openai@4.0.0"
    assert by_name["@anthropic-ai/sdk"].package_url is None
    assert any("patch" in risk.detail for risk in by_name["@anthropic-ai/sdk"].risks)
    assert not any("patch" in risk.detail for risk in by_name["openai"].risks)


def test_a_lockfile_patch_of_the_package_an_alias_installs_unbinds_the_alias(tmp_path):
    lock = pnpm10_lock(version="4.0.0").replace("      openai:\n", "      left-pad:\n", 1)
    manifest = {"dependencies": {"my-openai": "npm:openai@4.0.0"}}
    result = write_project(tmp_path, manifest, lock)
    assert result.scan_failures == []
    assert result.surfaces_excluded == [PNPM_GAP]
    (component,) = result.components
    assert component.name == "openai" and component.package_url is None
    assert any("patch" in risk.detail for risk in component.risks)


def test_a_patch_repeated_under_a_duplicate_manifest_key_is_refused(tmp_path):
    # JSON.parse keeps the last of two keys; a reader that kept the first would miss
    # the patch.
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"openai":"4.0.0"},"pnpm":{"patchedDependencies":{}},'
        '"pnpm":{"patchedDependencies":{"openai@4.0.0":"p"}}}'
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == ["package.json: invalid JSON or duplicate keys"]
    assert all(component.package_url is None for component in result.components)
