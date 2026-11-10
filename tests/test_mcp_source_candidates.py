"""MCP source collection parses only files that reference the SDK, so size alone never fails it."""

from __future__ import annotations

import json
import re
import shutil
import time
from dataclasses import replace
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nexus_symbiote import limits
from nexus_symbiote.core.models import MCPClientComponent
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.mcp_sources import strip_js_comments

REPOSITORY = Path(__file__).resolve().parents[1]
CLIENT_PY = "from mcp import ClientSession\n"
SERVER_TS = (
    'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
    'const server = new McpServer({ name: "s", version: "1" });\n'
    'server.registerTool("read", {}, handler);\n'
)
CLIENT_JS = 'const { Client } = require("@modelcontextprotocol/sdk/client/index.js");\n'
OLD_STRIPPER = re.compile(r"/\*.*?\*/|(?m:^\s*//[^\n]*$)", re.S)


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _unrelated(root: Path, count: int) -> None:
    for index in range(count):
        _write(root, f"pkg{index % 7}/module{index:03d}.py", f"def f{index}(x):\n    return x\n")
        _write(root, f"web/view{index:03d}.ts", f"export const v{index} = {index};\n")
    for index in range(12):
        _write(root, f"root{index}.js", f"module.exports = {index};\n")
        _write(root, f"root{index}.ts", f"export default {index};\n")


def _client(result) -> MCPClientComponent | None:
    found = [c for c in result.components if isinstance(c, MCPClientComponent)]
    return found[0] if found else None


def test_a_large_project_without_mcp_source_completes(tmp_path):
    _unrelated(tmp_path, 120)
    (tmp_path / "big").mkdir()
    (tmp_path / "big" / "generated_pb2.py").write_text("DATA = '" + "x" * 300_000 + "'\n")
    (tmp_path / "py2.py").write_text("print 'python 2'\n")
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"files": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}})
    )
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert result.surfaces_excluded == []
    assert len(result.surfaces_scanned) == 1
    assert result.surfaces_scanned[0].endswith(".mcp.json")


def test_sdk_references_are_found_wherever_the_files_are(tmp_path):
    _unrelated(tmp_path, 60)
    _write(tmp_path, "agents/deep/client.py", CLIENT_PY)
    _write(tmp_path, "server/src/index.ts", SERVER_TS)
    _write(tmp_path, "cli.js", CLIENT_JS)
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == []
    client = _client(result)
    assert client is not None
    assert client.properties["source_paths"] == ["agents/deep/client.py", "cli.js"]
    assert client.source_path == "agents/deep/client.py"
    assert sorted(result.surfaces_scanned) == [
        "agents/deep/client.py",
        "cli.js",
        "mcp-config (no config files found)",
        "server/src/index.ts",
    ]
    assert [c.name for c in result.components if c.component_type == "tool"] == ["read"]


def test_unrelated_source_changes_leave_the_result_unchanged(tmp_path):
    _write(tmp_path, "client.py", CLIENT_PY)
    _write(tmp_path, "server.ts", SERVER_TS)

    def snapshot():
        result = MCPScanner().scan(tmp_path)
        return (
            [c.model_dump(mode="json") for c in result.components],
            result.surfaces_scanned,
            result.surfaces_excluded,
            result.scan_failures,
        )

    before = snapshot()
    _write(tmp_path, "helpers/strings.py", "def shout(text):\n    return text.upper()\n")
    _write(tmp_path, "notes.ts", "export const greeting = 'hello';\n")
    _write(tmp_path, "notes.js", "// mentions mcp in a comment\nmodule.exports = 1;\n")
    _write(tmp_path, "broken.py", "def broken(:\n")
    assert snapshot() == before


def test_the_same_tree_at_two_locations_gives_the_same_result(tmp_path):
    first = tmp_path / "one" / "checkout"
    _write(first, "agents/client.py", CLIENT_PY)
    _write(first, "server/index.ts", SERVER_TS)
    _write(first, "cli.js", CLIENT_JS)
    second = tmp_path / "elsewhere" / "renamed"
    shutil.copytree(first, second)

    def dump(root: Path) -> str:
        result = MCPScanner().scan(root)
        return json.dumps(
            [
                [c.model_dump(mode="json") for c in result.components],
                result.surfaces_scanned,
                result.scan_failures,
            ]
        )

    assert dump(first) == dump(second)
    assert str(tmp_path) not in dump(first)


def test_the_source_files_limit_counts_candidates_and_names_what_was_not_parsed(tmp_path):
    for index in range(53):
        _write(tmp_path, f"clients/c{index:02d}.py", CLIENT_PY)
    _unrelated(tmp_path, 80)
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == [
        "clients/c50.py: Python MCP source not parsed (3 files in all); "
        "source-files limit of 50 exceeded; raise it with --limit source-files=N"
    ]
    client = _client(result)
    assert client is not None and len(client.properties["source_paths"]) == 50
    with limits.applied(replace(limits.DEFAULTS, source_files=60)):
        result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == []
    client = _client(result)
    assert client is not None and len(client.properties["source_paths"]) == 53


def test_only_candidate_files_are_held_to_the_syntax_limit(tmp_path):
    _write(tmp_path, "data.py", "DATA = '" + "x" * 300_000 + "'\n")
    assert MCPScanner().scan(tmp_path).scan_failures == []
    _write(tmp_path, "pkg/agent.py", CLIENT_PY + "PAD = '" + "x" * 300_000 + "'\n")
    _write(tmp_path, "server.ts", SERVER_TS + "//" + "x" * 300_000 + "\n")
    assert sorted(MCPScanner().scan(tmp_path).scan_failures) == [
        "pkg/agent.py: syntax-bytes limit of 256 KiB exceeded; "
        "raise it with --limit syntax-bytes=N",
        "server.ts: syntax-bytes limit of 256 KiB exceeded; raise it with --limit syntax-bytes=N",
    ]
    with limits.applied(replace(limits.DEFAULTS, syntax_bytes=512 * limits.KIB)):
        result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert _client(result) is not None


def test_the_source_scan_budget_names_the_first_file_not_searched(tmp_path):
    for index in range(6):
        _write(tmp_path, f"m{index}.py", "x = 1\n" * 100)
    with limits.applied(replace(limits.DEFAULTS, source_scan_bytes=1500)):
        failures = MCPScanner().scan(tmp_path).scan_failures
    hint = (
        "source-scan-bytes limit of 1500 bytes exceeded; raise it with --limit source-scan-bytes=N"
    )
    assert failures == [
        f"m2.py: {hint}",
        f"m3.py: not searched for MCP SDK references (3 files in all); {hint}",
    ]


def test_python_identifiers_are_compared_as_python_reads_them(tmp_path):
    fullwidth = "".join(chr(ord(letter) + 0xFEE0) for letter in "mcp")
    _write(tmp_path, "pkg/stealth.py", f"from {fullwidth} import ClientSession\n")
    _write(tmp_path, "pkg/direct.py", "client = MCPClient()\n")
    result = MCPScanner().scan(tmp_path)
    client = _client(result)
    assert client is not None
    assert client.properties["source_paths"] == ["pkg/direct.py", "pkg/stealth.py"]


def test_python_source_python_could_decode_differently_is_a_failure(tmp_path):
    (tmp_path / "latin.py").write_bytes(b"# -*- coding: latin-1 -*-\nname = '\xe9'\n")
    (tmp_path / "ascii.py").write_bytes(b"name = 'plain'\n")
    assert MCPScanner().scan(tmp_path).scan_failures == ["latin.py: invalid UTF-8"]


def test_a_byte_order_mark_does_not_make_python_source_invalid(tmp_path):
    (tmp_path / "agent.py").write_bytes(b"\xef\xbb\xbf" + CLIENT_PY.encode())
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert _client(result) is not None


def test_the_repository_itself_passes_the_mcp_collector():
    result = MCPScanner().scan(REPOSITORY)
    assert result.scan_failures == []


@pytest.mark.parametrize(
    "text",
    [
        "/* " * 87_381,
        "\n" * 262_144,
        " \n" * 131_072,
        "a\n" * 131_072,
        "/*/" * 87_381,
    ],
)
def test_comment_stripping_is_linear_at_the_syntax_limit(text):
    started = time.monotonic()
    strip_js_comments(text)
    assert time.monotonic() - started < 5


@settings(max_examples=3_000, deadline=None)
@given(st.lists(st.sampled_from(["/", "*", "\n", " ", "\t", "a", chr(0xA0), "\x0b", "//"])))
def test_comment_stripping_matches_the_previous_expression(pieces):
    text = "".join(pieces)
    assert strip_js_comments(text) == OLD_STRIPPER.sub("", text)
