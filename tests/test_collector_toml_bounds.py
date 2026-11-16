"""Every untrusted TOML route rejects expensive key structure before parsing."""

import json
import tomllib

import pytest

from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.registry import RegistryScanner


@pytest.mark.parametrize(
    "scanner,path,launcher",
    [
        (IDEAgentScanner, ".codex/config.toml", None),
        (MCPScanner, ".codex/config.toml", None),
        (MCPScanner, "uv.toml", "uvx"),
        (MCPScanner, "bunfig.toml", "bunx"),
        (RegistryScanner, "pyproject.toml", None),
        (RegistryScanner, "uv.lock", None),
    ],
)
@pytest.mark.parametrize("part", ["a", '""', "'a'"])
def test_long_keys_never_reach_tomllib(tmp_path, monkeypatch, scanner, path, launcher, part):
    # Each key is below CPython's own cap; many of them amplify allocations.
    hostile = "".join(f"k{i}." + ".".join([part] * 900) + " = 1\n" for i in range(12))
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(hostile)
    if launcher:
        (tmp_path / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"s": {"command": launcher, "args": ["server@1.0.0"]}}})
        )
    if path == "uv.lock":
        (tmp_path / "requirements.txt").write_text("openai>=1\n")
    original = tomllib.loads

    def bounded_only(text, **kwargs):
        assert text != hostile, "expensive dotted keys reached the allocating parser"
        return original(text, **kwargs)

    monkeypatch.setattr(tomllib, "loads", bounded_only)
    result = scanner().scan(tmp_path)
    assert any(failure.startswith(path + ":") for failure in result.scan_failures)
    assert not any("cannot be canonicalized" in failure for failure in result.scan_failures)
