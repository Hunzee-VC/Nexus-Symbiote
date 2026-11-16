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
