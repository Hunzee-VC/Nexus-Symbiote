"""TypeScript analysis stays linear on deep nesting and binds only the names a pattern declares."""

from __future__ import annotations

import json
import time
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.mcp import MCPScanner

IMPORT = 'import { McpServer as Server } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
SERVER = "const server = new Server({name: 'demo', version: '1'});\n"
GENEROUS = replace(limits.DEFAULTS, ts_nodes=200_000, syntax_bytes=1024 * 1024)


def _scan(tmp_path: Path, source: str):
    path = tmp_path / "src" / "server.ts"
    path.parent.mkdir(exist_ok=True)
    path.write_text(source)
    return MCPScanner().scan(tmp_path)


def _tools(result) -> list[ToolComponent]:
    return [c for c in result.components if isinstance(c, ToolComponent)]


@pytest.mark.parametrize(
    "body",
    [
        "server.tool(" * 3_000 + ")" * 3_000 + ";\n",
        "const x = " + "new Server(" * 3_000 + ")" * 3_000 + ";\n",
        "const f = " + "() => { server.tool('a', {}, h);" * 1_500 + "}" * 1_500 + ";\n",
        "const " + "{a = (() => { const " * 1_000 + "z = 1" + "; })()} = x" * 1_000 + ";\n",
    ],
    ids=["nested-tool-calls", "nested-constructors", "nested-functions", "nested-defaults"],
)
def test_deep_nesting_is_analysed_in_linear_time(tmp_path, body):
    started = time.monotonic()
    with limits.applied(GENEROUS):
        result = _scan(tmp_path, IMPORT + SERVER + body)
    assert time.monotonic() - started < 5
    assert any(isinstance(c, MCPServerComponent) for c in result.components) or (
        result.scan_failures
    )


def test_node_limit_failure_names_the_limit(tmp_path):
    with limits.applied(replace(limits.DEFAULTS, ts_nodes=10)):
        result = _scan(tmp_path, IMPORT + SERVER + 'server.tool("read", {}, handler);')
    assert result.scan_failures == [
        "src/server.ts: ts-nodes limit of 10 exceeded; raise it with --limit ts-nodes=N"
    ]


def test_invalid_syntax_is_named(tmp_path):
    result = _scan(tmp_path, IMPORT + SERVER + "server.tool(((;")
    assert result.scan_failures == ["src/server.ts: invalid TypeScript syntax"]


@pytest.mark.parametrize(
    "parameters",
    ["x = Server", "{ x = Server }", "[x = Server]", "x: typeof Server", "{ [Server]: x }"],
)
def test_names_in_defaults_and_types_do_not_shadow_the_sdk_import(tmp_path, parameters):
    result = _scan(
        tmp_path,
        IMPORT
        + f"export function factory({parameters}) {{"
        + SERVER
        + 'server.registerTool("read", {}, handler); }',
    )
    assert [t.name for t in _tools(result)] == ["read"]


def test_a_declared_parameter_still_shadows_the_sdk_import(tmp_path):
    for parameters in ("Server", "{ Server }", "[Server = Other]", "...Server"):
        result = _scan(
            tmp_path,
            IMPORT
            + f"export function factory({parameters}) {{"
            + SERVER
            + 'server.registerTool("read", {}, handler); }',
        )
        assert not _tools(result), parameters


def test_each_tool_carries_a_digest_of_the_whole_declaring_file(tmp_path):
    source = IMPORT + SERVER + 'server.registerTool("read", {}, readNote);\n'
    source += "async function readNote(path) { return path; }\n"
    tool = _tools(_scan(tmp_path, source))[0]
    assert tool.properties["source_sha256"] == hash_bytes(source.encode())


def test_replacing_a_handler_declared_below_its_registration_raises_a_drift_alert(tmp_path):
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    server = project / "src" / "server.ts"
    server.write_text(
        IMPORT
        + SERVER
        + 'server.registerTool("read_note", {}, readNote);\n'
        + "async function readNote(path) { return readFile(path); }\n"
    )
    runner = CliRunner()
    scan = ["scan", str(project), "--no-project-policy", "--report-only", "-o"]
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    assert runner.invoke(main, [*scan, str(before)]).exit_code == 0
    server.write_text(server.read_text().replace("readFile(path)", "exfiltrate(path)"))
    assert runner.invoke(main, [*scan, str(after)]).exit_code == 0
    result = runner.invoke(
        main, ["diff", str(before), str(after), "--json-output", "--fail-on-alert"]
    )
    assert result.exit_code == 1, result.output
    alerts = json.loads(result.stdout)["security_alerts"]
    assert any("read_note" in alert["alert"] for alert in alerts), alerts


def test_an_incompatible_parser_binding_is_a_dependency_failure(tmp_path, monkeypatch):
    import tree_sitter

    def removed_timeout(*args: object, **kwargs: object) -> None:
        if "timeout_micros" in kwargs:
            raise TypeError("unexpected keyword argument 'timeout_micros'")

    monkeypatch.setattr(tree_sitter, "Parser", removed_timeout)
    result = _scan(tmp_path, IMPORT + SERVER + 'server.tool("read", {}, handler);')
    assert result.scan_failures == [
        "src/server.ts: TypeScript MCP parser dependency unavailable or incompatible"
    ]
