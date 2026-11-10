"""MCP source collection parses only files that reference the SDK, so size alone never fails it."""

from __future__ import annotations

import json
import re
import shutil
import time
import tracemalloc
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


def _write(root: Path, relative: str, text: str | bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))


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


def test_python_source_is_read_in_its_declared_encoding(tmp_path):
    (tmp_path / "latin.py").write_bytes(b"# -*- coding: latin-1 -*-\nname = '\xe9'\n")
    (tmp_path / "declared.py").write_bytes(b"# -*- coding: latin-1 -*-\nname = 'plain'\n")
    (tmp_path / "ascii.py").write_bytes(b"name = 'plain'\n")
    assert MCPScanner().scan(tmp_path).scan_failures == []
    fullwidth = "".join(chr(ord(letter) + 0xFEE0) for letter in "mcp")
    source = f"# coding: cp932\nfrom {fullwidth} import ClientSession\n"
    _write(tmp_path, "pkg/japanese.py", source.encode("cp932"))
    _write(
        tmp_path, "pkg/legacy.py", b"# coding: latin-1\n# caf\xe9\nfrom mcp import ClientSession\n"
    )
    _write(tmp_path, "pkg/undeclared.py", b"name = '\xe9'\n")
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == ["pkg/undeclared.py: invalid UTF-8"]
    assert result.surfaces_excluded == []
    client = _client(result)
    assert client is not None
    assert client.properties["source_paths"] == ["pkg/japanese.py", "pkg/legacy.py"]


HIDDEN_REFERENCES = {
    "unicode_escape": b"# -*- coding: unicode_escape -*-\nfrom \\x6dcp.client import Client\n",
    "utf-7": b"# coding: utf-7\nfrom +AG0AYwBw-.client import Client\n",
    "raw_unicode_escape": b"# coding: raw_unicode_escape\nfrom \\u006dcp.client import Client\n",
    "carriage_returns": b"\r# coding: utf-7\rfrom +AG0AYwBw-.client import Client\r",
    "continued_declaration": b"# coding: unicode_escape \\\nfrom \\x6dcp.client import Client\n",
    "iso2022": b"# coding: iso2022_jp\nfrom \x1b$B#m#c#p\x1b(B.client import Client\n",
    "utf-16": b"# coding: utf-16\n" + "from mcp.client import Client\n".encode("utf-16-le"),
    "idna": b"# coding: idna\nfrom xn--mcp.client import Client\n",
    "unknown": b"# coding: no-such-codec\nfrom mcp.client import Client\n",
    "bom_conflict": b"\xef\xbb\xbf# coding: latin-1\nfrom mcp.client import Client\n",
}


@pytest.mark.parametrize("location", ["agent.py", "pkg/deep/agent.py"])
@pytest.mark.parametrize("source", HIDDEN_REFERENCES.values(), ids=HIDDEN_REFERENCES)
def test_a_declaration_static_reading_cannot_follow_is_a_failure(tmp_path, location, source):
    path = tmp_path / location
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(source)
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == [f"{location}: unsupported source encoding declaration"]
    assert result.components == []


def test_a_hostile_declaration_is_refused_without_decoding(tmp_path):
    payload = b"a" * 2_000_000 + b"-" + b"b" * 2_000_000
    _write(tmp_path, "slow.py", b"# coding: punycode\n" + payload)
    started = time.monotonic()
    failures = MCPScanner().scan(tmp_path).scan_failures
    assert time.monotonic() - started < 5
    assert failures == ["slow.py: unsupported source encoding declaration"]


def test_an_import_spelled_with_compatibility_characters_is_a_gap(tmp_path):
    fullwidth = "".join(chr(ord(letter) + 0xFEE0) for letter in "mcp")
    _write(
        tmp_path,
        "pkg/server.py",
        f"from {fullwidth}.server.fast{fullwidth} import FastMCP\n"
        'server = FastMCP("files")\n'
        "@server.tool()\n"
        "def read(path: str) -> str:\n"
        "    return path\n",
    )
    result = MCPScanner().scan(tmp_path)
    assert result.surfaces_excluded == [
        "pkg/server.py: Python MCP server import spelled with compatibility characters; "
        "its servers and tools are not collected"
    ]
    assert result.surfaces_scanned == ["pkg/server.py"]
    literal = (tmp_path / "pkg" / "server.py").read_text(encoding="utf-8")
    _write(tmp_path, "pkg/server.py", literal.replace(fullwidth, "mcp"))
    result = MCPScanner().scan(tmp_path)
    assert result.surfaces_excluded == []
    assert [c.name for c in result.components if c.component_type == "tool"] == ["read"]


@pytest.mark.parametrize("character", ["\ufdfa", "\u3300", "\uff4d"])
def test_compatibility_characters_cannot_inflate_the_search(tmp_path, character):
    # U+FDFA has an 18-character compatibility form; folding the whole text at once
    # held about 150 MiB and took seconds for this 4 MiB file.
    body = "# " + character * ((4 * limits.MIB - 16) // len(character.encode()))
    _write(tmp_path, "wide.py", body + "\n")
    tracemalloc.start()
    try:
        started = time.monotonic()
        failures = MCPScanner().scan(tmp_path).scan_failures
        elapsed = time.monotonic() - started
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert failures == []
    assert peak < 32 * limits.MIB
    assert elapsed < 10


def test_unrelated_sources_larger_than_file_bytes_are_searched_as_a_stream(tmp_path):
    padding = "x" * (5 * limits.MIB)
    _write(tmp_path, "pkg/generated_pb2.py", f"DATA = '{padding}'\n")
    _write(tmp_path, "web/generated.ts", f"export const data = '{padding}';\n")
    _write(tmp_path, "bundle.js", f"module.exports = '{padding}';\n")
    _write(tmp_path, "bundle.ts", f"export default '{padding}';\n")
    assert MCPScanner().scan(tmp_path).scan_failures == []
    _write(tmp_path, "pkg/text.py", f"DATA = '{padding}\u00e9'\n")
    # "m" ends the first one-MiB read and "cp" starts the second.
    marker_across_reads = "x" * (limits.MIB - 3) + "mcp" + padding
    _write(tmp_path, "pkg/late.py", f"# {marker_across_reads}\n")
    assert sorted(MCPScanner().scan(tmp_path).scan_failures) == [
        "pkg/late.py: syntax-bytes limit of 256 KiB exceeded; raise it with --limit syntax-bytes=N",
        "pkg/text.py: file-bytes limit of 4 MiB exceeded; raise it with --limit file-bytes=N",
    ]


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
