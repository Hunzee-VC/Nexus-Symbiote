"""The operator's file-bytes limit, not a fixed parser cap, bounds an npm lockfile."""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from pathlib import Path

from nexus_symbiote import limits
from nexus_symbiote.scanners.registry import RegistryScanner


def test_a_lockfile_above_four_mebibytes_is_read_when_file_bytes_allows_it(
    tmp_path: Path,
) -> None:
    integrity = "sha512-" + base64.b64encode(b"x" * 64).decode()
    packages: dict[str, object] = {
        "": {"dependencies": {"openai": "4.52.0"}},
        "node_modules/openai": {
            "version": "4.52.0",
            "resolved": "https://registry.npmjs.org/openai/-/openai-4.52.0.tgz",
            "integrity": integrity,
        },
    }
    for index in range(20_000):
        packages[f"node_modules/filler-{index}"] = {
            "version": "1.0.0",
            "resolved": f"https://registry.npmjs.org/filler-{index}/-/filler-{index}-1.0.0.tgz",
            "integrity": integrity,
        }
    raw = json.dumps({"lockfileVersion": 3, "packages": packages}).encode()
    assert len(raw) > 4 * 1024 * 1024
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"4.52.0"}}')
    (tmp_path / "package-lock.json").write_bytes(raw)
    settings = replace(limits.DEFAULTS, file_bytes=64 * limits.MIB, total_bytes=256 * limits.MIB)
    with limits.applied(settings):
        result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    (component,) = [c for c in result.components if c.name == "openai"]
    assert component.package_url == "pkg:npm/openai@4.52.0"
