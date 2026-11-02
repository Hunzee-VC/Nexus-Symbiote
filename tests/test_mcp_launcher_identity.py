"""The static inventory binds each server to its declared launcher package."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner


def write_project(project: Path, command: str, args: list[str]) -> None:
    server = {
        "command": command,
        "args": args,
        "env": {"TOKEN": "secret-canary"},
        "tools": [{"name": "read", "description": "Read docs", "inputSchema": {"type": "object"}}],
    }
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"docs": server}}))


@pytest.mark.parametrize(
    "command,args,expected",
    [
        ("npx", ["-y", "@scope/docs@1.2.3", "secret-canary"], "npm:@scope/docs"),
        ("bunx", ["pkg@^1.2.3"], "npm:pkg"),
        ("uvx", ["--from", "My_Docs[cli]==1.2.3", "docs"], "pypi:my-docs"),
        ("pipx", ["run", "--spec", "My.Docs==1.2.3", "docs"], "pypi:my-docs"),
        (
            "docker",
            ["run", "--rm", "registry.test:5000/team/docs:1.2.3"],
            "oci:registry.test:5000/team/docs",
        ),
        ("docker", ["run", "docs@sha256:" + "ab" * 32], "oci:docs"),
        ("npx", ["docs@npm:other@1.2.3"], None),
        ("npx", ["docs@https://example.test/secret-canary"], None),
        ("uvx", ["docs @ https://example.test/secret-canary"], None),
        ("npx", ["--password", "secret-canary"], None),
        ("npx", ["secret-canary@1.2.3"], None),
    ],
)
def test_safe_launcher_package_projection(tmp_path, command, args, expected):
    write_project(tmp_path, command, args)
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert server.launcher_package == expected
    assert "secret-canary" not in server.model_dump_json()
    assert server.args == ["***"] * len(args)


def test_cli_rejects_substituted_missing_and_legacy_package_identity(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    runner = CliRunner()

    def scan(filename, target):
        path = tmp_path / filename
        write_project(project, "npx", [target])
        result = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(path)])
        assert result.exit_code == 0, result.output
        return path

    def validate(bom, expected):
        result = runner.invoke(
            main, ["validate", str(bom), "--project", str(project), "--no-project-policy"]
        )
        assert result.exit_code == expected, result.output

    def diff(old, new):
        result = runner.invoke(
            main, ["diff", str(old), str(new), "--json-output", "--fail-on-alert"]
        )
        assert result.exit_code == 1, result.output
        alerts = json.loads(result.output)["security_alerts"]
        assert any(a["severity"] == "critical" and "launcher package" in a["alert"] for a in alerts)

    original = scan("reviewed.json", "reviewed-docs@1.2.3")
    validate(original, 0)

    legacy = tmp_path / "legacy.json"
    document = json.loads(original.read_text())
    server = next(c for c in document["components"] if "launcher_package" in c)
    del server["launcher_package"]
    legacy.write_text(json.dumps(document))
    validate(legacy, 1)
    diff(legacy, original)

    candidate = scan("candidate.json", "replacement-docs@1.2.3")
    validate(candidate, 0)
    validate(original, 1)
    diff(original, candidate)

    opaque = scan("opaque.json", "reviewed-docs@npm:replacement-docs@1.2.3")
    validate(original, 1)
    diff(original, opaque)
