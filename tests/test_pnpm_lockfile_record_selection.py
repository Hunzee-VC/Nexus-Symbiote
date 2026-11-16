"""pnpm-lock.yaml binds the record pnpm installs from, by lockfile format, never a decoy."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from nexus_symbiote.scanners.registry import RegistryScanner

INTEGRITY = "sha512-" + base64.b64encode(b"g" * 64).decode()
REAL = "{resolution: {type: git, repo: 'https://git.example/o/openai.git', commit: abc123}}"
DECOY = f"{{resolution: {{integrity: '{INTEGRITY}'}}}}"


def _scan(root: Path, lock: str):
    (root / "package.json").write_text('{"dependencies":{"openai":"4.52.0","zod":"3.23.8"}}')
    (root / "pnpm-lock.yaml").write_text(lock)
    result = RegistryScanner().scan(root)
    (component,) = [c for c in result.components if c.name == "openai"]
    return result, component


def _v9(packages: str) -> str:
    return (
        "lockfileVersion: '9.0'\n"
        "importers:\n  .:\n    dependencies:\n"
        "      openai:\n        specifier: 4.52.0\n        version: 4.52.0(zod@3.23.8)\n"
        "      zod:\n        specifier: 3.23.8\n        version: 3.23.8\n"
        f"packages:\n{packages}"
        "snapshots:\n  openai@4.52.0(zod@3.23.8): {}\n  zod@3.23.8: {}\n"
    )


def _v6(packages: str) -> str:
    return (
        "lockfileVersion: '6.0'\n"
        "dependencies:\n"
        "  openai:\n    specifier: 4.52.0\n    version: 4.52.0(zod@3.23.8)\n"
        "  zod:\n    specifier: 3.23.8\n    version: 3.23.8\n"
        f"packages:\n{packages}"
    )


@pytest.mark.parametrize(
    ("lock", "real_key", "decoy_key"),
    [
        (_v9, "openai@4.52.0", "openai@4.52.0(zod@3.23.8)"),
        (_v6, "/openai@4.52.0(zod@3.23.8)", "openai@4.52.0"),
    ],
    ids=["v9", "v6"],
)
def test_a_decoy_record_under_a_key_pnpm_never_reads_binds_nothing(
    tmp_path: Path, lock, real_key: str, decoy_key: str
) -> None:
    # pnpm installs openai from the git record; the decoy's integrity and registry
    # origin must not stand in for it.
    result, component = _scan(tmp_path, lock(f"  '{real_key}': {REAL}\n  '{decoy_key}': {DECOY}\n"))
    assert component.package_url is None
    assert INTEGRITY not in str(component.model_dump(mode="json"))
    assert (
        "pnpm-lock.yaml: multiple package resolutions for openai are ambiguous"
        in result.surfaces_excluded
    )


def test_a_v9_lockfile_binds_the_record_without_peers(tmp_path: Path) -> None:
    result, component = _scan(tmp_path, _v9(f"  'openai@4.52.0': {DECOY}\n"))
    assert result.scan_failures == []
    assert component.package_url == "pkg:npm/openai@4.52.0"
    assert component.properties["lockfile_integrity"] == INTEGRITY


def test_a_v9_lockfile_reads_the_git_record_pnpm_installs(tmp_path: Path) -> None:
    result, component = _scan(tmp_path, _v9(f"  'openai@4.52.0': {REAL}\n"))
    assert component.package_url is None
    assert "pnpm-lock.yaml: local or non-registry resolution is unverified" in (
        result.surfaces_excluded
    )


def test_an_unknown_lockfile_version_is_a_failure(tmp_path: Path) -> None:
    lock = _v9(f"  'openai@4.52.0': {DECOY}\n").replace("'9.0'", "'7.0'")
    result, component = _scan(tmp_path, lock)
    assert "pnpm-lock.yaml: invalid or unsupported lockfile" in result.scan_failures
    assert component.package_url is None


OTHER = "sha512-" + base64.b64encode(b"h" * 64).decode()


@pytest.mark.parametrize(
    ("version", "key"),
    [("4.52.0(zod@3.23.8)", "/openai@4.52.0(zod@3.23.8)"), ("4.52.0", "/openai@4.52.0")],
    ids=["peered", "unpeered"],
)
def test_a_v6_lockfile_with_one_version_in_two_peer_contexts_binds_the_importers_record(
    tmp_path: Path, version: str, key: str
) -> None:
    # pnpm 8 writes one record per peer context; both keys are its own spelling, so
    # neither is a decoy for the other.
    records = {"/openai@4.52.0(zod@3.23.8)": INTEGRITY, "/openai@4.52.0": OTHER}
    packages = "".join(
        f"  '{name}': {{resolution: {{integrity: '{value}'}}}}\n" for name, value in records.items()
    )
    lock = _v6(packages).replace("version: 4.52.0(zod@3.23.8)", f"version: {version}")
    result, component = _scan(tmp_path, lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert component.package_url == "pkg:npm/openai@4.52.0"
    assert component.properties["lockfile_integrity"] == records[key]


def test_a_v5_lockfile_with_one_version_in_two_peer_contexts_binds_the_importers_record(
    tmp_path: Path,
) -> None:
    lock = (
        "lockfileVersion: 5.4\n"
        "specifiers:\n  openai: 4.52.0\n  zod: 3.23.8\n"
        "dependencies:\n  openai: 4.52.0\n  zod: 3.23.8\n"
        "packages:\n"
        f"  /openai/4.52.0: {{resolution: {{integrity: '{INTEGRITY}'}}}}\n"
        f"  /openai/4.52.0_zod@3.23.8: {{resolution: {{integrity: '{OTHER}'}}}}\n"
    )
    result, component = _scan(tmp_path, lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert component.properties["lockfile_integrity"] == INTEGRITY


@pytest.mark.parametrize("version", ["9.0", "6.0"])
def test_a_v6_or_v9_lockfile_without_importers_binds_no_record_by_name(
    tmp_path: Path, version: str
) -> None:
    # pnpm 6 and 9 always list the root's dependencies; a lockfile that does not
    # resolves nothing pnpm installs, whatever key its records use.
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"^5.0.0"}}')
    (tmp_path / "pnpm-lock.yaml").write_text(
        f"lockfileVersion: '{version}'\npackages:\n  /openai@4.0.0: {DECOY}\n"
    )
    result = RegistryScanner().scan(tmp_path)
    (component,) = result.components
    assert component.package_url is None
    assert "package_resolution" not in component.claims
    assert INTEGRITY not in str(component.model_dump(mode="json"))
    assert "pnpm-lock.yaml: selected package version disagrees with package.json" in (
        result.scan_failures
    )
