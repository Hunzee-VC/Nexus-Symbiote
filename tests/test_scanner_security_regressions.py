"""Regression tests for untrusted repository inputs and secret minimization."""

import json
import os
from pathlib import Path

import pytest

from nexus_symbiote.scanners.base import read_regular_text
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.rag import RAGScanner


def test_mcp_redacts_args_and_url_from_components_and_findings(tmp_path: Path) -> None:
    config = {
        "mcpServers": {
            "remote": {
                "command": "npx",
                "args": ["--api-key=CANARY", "package@latest"],
                "env": {"SECRET": "CANARY"},
                "url": "http://user:CANARY@localhost.attacker.example/private/CANARY?token=CANARY#CANARY",
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")
    result = MCPScanner().scan(tmp_path)
    rendered = repr(result)
    assert "CANARY" not in rendered
    server = result.components[0]
    assert server.endpoint_url == "http://localhost.attacker.example"
    assert any(r.category == "transport_security" for r in server.risks)


@pytest.mark.parametrize("url", ["http://localhost", "http://127.0.0.1:8080", "http://[::1]"])
def test_exact_loopback_allowed(url: str) -> None:
    assert MCPScanner._secure_endpoint(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost.attacker.example",
        "http://127.0.0.1.attacker.example",
        "https://user:secret@example.com",
        "http://example.com",
        "https://example.com:bad",
    ],
)
def test_non_loopback_or_invalid_url_rejected(url: str) -> None:
    assert not MCPScanner._secure_endpoint(url)


def test_rag_yaml_is_parsed_and_urls_are_minimized(tmp_path: Path) -> None:
    pytest.importorskip("yaml")
    (tmp_path / "rag_config.yaml").write_text(
        "sources:\n  - name: docs\n    type: vector-store\n"
        "    source_uris: ['http://user:CANARY@example.com/private/CANARY?token=CANARY']\n",
        encoding="utf-8",
    )
    result = RAGScanner().scan(tmp_path)
    assert not result.scan_failures
    assert result.components[0].source_uris == ["http://example.com"]
    assert "CANARY" not in repr(result)


def test_malformed_rag_config_reports_failure_not_absence(tmp_path: Path) -> None:
    (tmp_path / "rag_config.json").write_text("{bad", encoding="utf-8")
    result = RAGScanner().scan(tmp_path)
    assert result.scan_failures
    assert not result.surfaces_excluded


def test_malformed_rag_yaml_reports_failure(tmp_path: Path) -> None:
    pytest.importorskip("yaml")
    (tmp_path / "rag_config.yaml").write_text("sources: [", encoding="utf-8")
    result = RAGScanner().scan(tmp_path)
    assert result.scan_failures
    assert not result.surfaces_excluded


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="POSIX no-follow opens required")
def test_bounded_reader_rejects_symlinks_and_large_files(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("abcd", encoding="utf-8")
    with pytest.raises(OSError):
        read_regular_text(target, max_bytes=3)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        read_regular_text(link)
    parent_link = tmp_path / "dirlink"
    parent_link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError):
        read_regular_text(parent_link / "target")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO required")
def test_bounded_reader_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(OSError):
        read_regular_text(fifo)
