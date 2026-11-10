"""Exercise credential redaction on the exact paths the composite Action uploads."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("format_name", ["json", "cyclonedx", "spdx"])
def test_staged_artifact_omits_descriptor_credential(tmp_path: Path, format_name: str) -> None:
    project = tmp_path / "project"
    project.mkdir()
    canary = "symbiote-test-only-credential-7d39"
    tool = {
        "name": "read_docs",
        "description": "Read project documentation",
        "inputSchema": {
            "type": "object",
            "properties": {"api_key": {"type": "string", "default": canary}},
        },
    }
    config = {"command": "npx", "args": ["docs-server@1.2.3"], "tools": [tool]}
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"docs": config}}))
    outputs = tmp_path / "action.outputs"
    # JSON exercises the default artifact even when a subsequent policy gate fails.
    fail_risk = format_name == "json"
    env = {
        **os.environ,
        "GITHUB_WORKSPACE": str(tmp_path),
        "GITHUB_OUTPUT": str(outputs),
        "SYMBIOTE_SCAN_PATH": "project",
        "SYMBIOTE_FORMAT": format_name,
        "SYMBIOTE_OUTPUT_FILE": "inventory.json",
        "SYMBIOTE_SCANNERS": "",
        "SYMBIOTE_VALIDATE": "true",
        "SYMBIOTE_RISK_CHECK": "true",
        "SYMBIOTE_RISK_THRESHOLD": "1" if fail_risk else "100",
        "SYMBIOTE_SARIF": "true",
    }
    runner = Path(__file__).resolve().parents[1] / "scripts" / "run_action.py"
    result = subprocess.run(  # noqa: S603 -- use the installed interpreter and reviewed Action
        [sys.executable, "-I", str(runner)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == int(fail_risk), result.stderr
    published = dict(line.split("=", 1) for line in outputs.read_text().splitlines())
    assert published["passed"] == ("false" if fail_risk else "true")
    for key in ("aibom_path", "sarif_path"):
        assert canary not in Path(published[key]).read_text()
    assert "read_docs" in Path(published["aibom_path"]).read_text()
