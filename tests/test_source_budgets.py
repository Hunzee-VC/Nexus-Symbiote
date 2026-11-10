"""Source collection is bounded by the text read, not by how many files a project has."""

from __future__ import annotations

import itertools
import json
import re
import time
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners import a2a, mcp, rag
from nexus_symbiote.scanners.a2a import A2AScanner
from nexus_symbiote.scanners.base import ScanResult, SourceBudget
from nexus_symbiote.scanners.mcp import MCPScanner, without_js_comments
from nexus_symbiote.scanners.rag import RAGScanner

_OLD_COMMENTS = re.compile(r"/\*.*?\*/|(?m:^\s*//[^\n]*$)", re.S)


def _write_many(directory: Path, suffix: str, count: int, body: str = "x = 1\n") -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for index in range(count):
        (directory / f"module_{index:03d}{suffix}").write_text(body)


def test_ordinary_python_project_is_not_a_coverage_failure(tmp_path):
    _write_many(tmp_path / "app", ".py", 120)
    _write_many(tmp_path, ".py", 30)
    assert not MCPScanner().scan(tmp_path).scan_failures
    assert not A2AScanner().scan(tmp_path).scan_failures


def test_ordinary_typescript_project_is_not_a_coverage_failure(tmp_path):
    _write_many(tmp_path / "src", ".ts", 80, "export const x = 1;\n")
    _write_many(tmp_path, ".js", 15, "module.exports = 1;\n")
    assert not MCPScanner().scan(tmp_path).scan_failures


def test_scan_gate_passes_with_more_than_fifty_python_files(tmp_path):
    _write_many(tmp_path / "app", ".py", 60)
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"files": {"command": "npx", "args": ["server@1.2.3"]}}})
    )
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--no-project-policy", "-o", str(output)]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text())["metadata"]["completeness"]["scan_failures"] == []


def test_sdk_reference_past_the_fiftieth_module_is_still_found(tmp_path):
    _write_many(tmp_path / "app", ".py", 70)
    (tmp_path / "app" / "zz_last.py").write_text("from mcp import ClientSession\n")
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures
    [client] = [c for c in result.components if c.bom_ref == "mcp-client:sdk"]
    assert client.properties["source_paths"] == [str(tmp_path / "app" / "zz_last.py")]


def test_unrelated_binary_named_like_a_module_is_not_a_failure(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "blob.py").write_bytes(b"\xff\xfe\x00data")
    assert not MCPScanner().scan(tmp_path).scan_failures


def test_exhausted_budget_is_one_named_gap(tmp_path, monkeypatch):
    _write_many(tmp_path / "app", ".py", 40, "import mcp\n" + "#" * 200 + "\n")
    monkeypatch.setattr(
        mcp, "SourceBudget", lambda label, result: SourceBudget(label, result, 1024)
    )
    failures = MCPScanner().scan(tmp_path).scan_failures
    assert failures == [
        "MCP source references exceed the combined size limit: the rest were not read"
    ]


def test_exhausted_a2a_budget_is_one_named_gap(tmp_path, monkeypatch):
    _write_many(tmp_path, ".py", 40, "#" * 200 + "\n")
    monkeypatch.setattr(
        a2a, "SourceBudget", lambda label, result: SourceBudget(label, result, 1024)
    )
    failures = A2AScanner().scan(tmp_path).scan_failures
    assert failures == [
        "a2a code references exceed the combined size limit: the rest were not read"
    ]


def test_exhausted_rag_budget_is_one_named_gap(tmp_path, monkeypatch):
    # The vector-store import heuristic reads under the same source budget, so it never
    # stops reading silently.
    _write_many(tmp_path, ".py", 40, "#" * 200 + "\n")
    monkeypatch.setattr(
        rag, "SourceBudget", lambda label, result: SourceBudget(label, result, 1024)
    )
    failures = RAGScanner().scan(tmp_path).scan_failures
    assert failures == [
        "rag vector-store imports exceed the combined size limit: the rest were not read"
    ]


def test_budget_refuses_everything_after_the_first_overrun():
    result = ScanResult(scanner_name="x")
    budget = SourceBudget("sources", result, 10)
    assert budget.admit(6)
    assert not budget.admit(6)
    assert not budget.admit(1)
    assert len(result.scan_failures) == 1


def test_comment_stripper_matches_the_pattern_it_replaced():
    for length in range(7):
        for letters in itertools.product("/* \na\t", repeat=length):
            text = "".join(letters)
            assert without_js_comments(text) == _OLD_COMMENTS.sub("", text), repr(text)
    sample = "/* a */import x from 'y';\n  // note\ncode(); // trailing stays\n/* open"
    assert without_js_comments(sample) == _OLD_COMMENTS.sub("", sample)


def test_comment_stripping_is_linear_in_blank_lines(tmp_path):
    # The pattern rescanned the blank run from every line: about 80 seconds for
    # this file, which is within the syntax size limit.
    (tmp_path / "client.js").write_text("\n" * 262_000)
    started = time.monotonic()
    result = MCPScanner().scan(tmp_path)
    assert time.monotonic() - started < 5
    assert not result.scan_failures


def test_commented_sdk_import_is_still_not_a_client(tmp_path):
    (tmp_path / "a.js").write_text(
        "/* import { Client } from '@modelcontextprotocol/sdk/client/index.js' */\n"
        "  // const sdk = require('@modelcontextprotocol/sdk')\n"
    )
    (tmp_path / "b.js").write_text("const sdk = require('@modelcontextprotocol/sdk/client')\n")
    [client] = [c for c in MCPScanner().scan(tmp_path).components if c.bom_ref == "mcp-client:sdk"]
    assert client.properties["source_paths"] == [str(tmp_path / "b.js")]
