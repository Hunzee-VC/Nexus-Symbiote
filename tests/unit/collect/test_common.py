"""Shared collector helpers: JSONC, locators, placeholders, redaction, trust zones."""

from __future__ import annotations

from pathlib import Path

import pytest

from symbiote.collect._common import (
    REDACTED,
    classify_env_value,
    json_pointer,
    locator,
    parse_jsonc,
    parse_structured,
    placeholders_in,
    read_bounded,
    redact_args,
    url_facts,
)
from symbiote.model.enums import TrustZone


def test_jsonc_comments_and_trailing_commas() -> None:
    text = """
    // servers
    {
      "servers": {
        "a": {"url": "https://x.test/mcp", /* inline */ "note": "keep // this and /* this */",},
      },
    }
    """
    data = parse_jsonc(text)
    assert data["servers"]["a"]["note"] == "keep // this and /* this */"


def test_duplicate_keys_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate key"):
        parse_jsonc('{"a": 1, "a": 2}')
    with pytest.raises(ValueError, match="duplicate key"):
        parse_structured(b'{"a": 1, "a": 2}', "json")


def test_structured_formats() -> None:
    assert parse_structured(b'\xef\xbb\xbf{"a": 1}', "json") == {"a": 1}
    assert parse_structured(b'[mcp_servers.x]\ncommand = "npx"\n', "toml") == {
        "mcp_servers": {"x": {"command": "npx"}}
    }
    assert parse_structured(b"a: [1, 2]\n", "yaml") == {"a": [1, 2]}


def test_json_pointer_escaping() -> None:
    assert json_pointer("mcpServers", "a/b", "c~d", 0) == "/mcpServers/a~1b/c~0d/0"
    assert locator(".mcp.json", "mcpServers", "gh") == ".mcp.json#/mcpServers/gh"
    assert locator("x.toml") == "x.toml"


def test_placeholders() -> None:
    assert placeholders_in("Bearer ${env:API_TOKEN}") == ["env:API_TOKEN"]
    assert placeholders_in("${input:pat} ${GITHUB_TOKEN:-x} $HOME_DIR") == [
        "input:pat",
        "GITHUB_TOKEN",
        "HOME_DIR",
    ]


@pytest.mark.parametrize(
    ("name", "value", "kind"),
    [
        ("GITHUB_TOKEN", "${GITHUB_TOKEN}", "placeholder"),
        ("GITHUB_TOKEN", "ghp_" + "a" * 36, "literal-secret"),
        ("API_KEY", "anything", "literal-secret"),
        ("LOG_LEVEL", "debug", "literal"),
        ("LOG_LEVEL", "", "empty"),
        ("Authorization", "Bearer ${env:TOKEN}", "placeholder"),
        ("Authorization", "Bearer abc.def", "literal-secret"),
    ],
)
def test_classify_env_value(name: str, value: str, kind: str) -> None:
    assert classify_env_value(name, value) == kind


def test_redact_args() -> None:
    args = [
        "--token", "abc123",
        "--api-key=sk-" + "x" * 30,
        "PASSWORD=hunter2",
        "postgres://admin:s3cret@db.internal:5432/app",
        "--verbose",
        "--token=${TOKEN}",
        "AKIA" + "A" * 16,
    ]  # fmt: skip
    redacted, count = redact_args(args)
    assert count == 5
    joined = " ".join(redacted)
    assert "abc123" not in joined and "hunter2" not in joined and "s3cret" not in joined
    assert "--token=${TOKEN}" in redacted  # placeholders are names, not secrets
    assert redacted[1] == REDACTED
    assert redacted[-1] == REDACTED


@pytest.mark.parametrize(
    ("url", "zone", "crosses"),
    [
        ("http://localhost:3000/mcp", TrustZone.LOOPBACK, False),
        ("http://127.0.0.1:8080/sse", TrustZone.LOOPBACK, False),
        ("http://[::1]:9000/", TrustZone.LOOPBACK, False),
        ("https://10.1.2.3/mcp", TrustZone.INTERNAL, True),
        ("https://mcp.corp/mcp", TrustZone.INTERNAL, True),
        ("https://intranet/mcp", TrustZone.INTERNAL, True),
        ("https://api.githubcopilot.com/mcp/", TrustZone.EXTERNAL, True),
        ("not a url", TrustZone.UNKNOWN, True),
    ],
)
def test_url_zones(url: str, zone: TrustZone, crosses: bool) -> None:
    facts = url_facts(url)
    assert facts.trust_zone is zone
    assert facts.crosses_trust_boundary is crosses


def test_url_credentials_dropped() -> None:
    facts = url_facts("https://user:pw@Mcp.Example.com/v1/mcp?api_key=SECRET&mode=x#frag")
    assert facts.display == "https://mcp.example.com/v1/mcp"
    assert facts.had_userinfo and facts.secret_in_query
    assert facts.query_param_names == ("api_key", "mode")


def test_read_bounded(tmp_path: Path) -> None:
    small = tmp_path / "a.json"
    small.write_text("{}")
    assert read_bounded(small, 10).data == b"{}"
    assert read_bounded(small, 1).error_class == "too-large"
    assert read_bounded(tmp_path / "missing", 10).error_class == "not-found"
