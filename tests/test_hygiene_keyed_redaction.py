"""A credential held as a mapping's value is redacted by its key, as its text form is.

`redact_text` removes the value of `Authorization: ...`, `Cookie: ...` and
`password=...` when key and value are one string. Parsed JSON or TOML hands them over
separately, so a value with no token shape of its own, such as
`{"Authorization": "rawSecretToken_12345"}`, was exported in tool metadata and covered
by the unkeyed digest of IDE settings.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.core.models import IDEAgentComponent
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV
from nexus_symbiote.utils.secrets import redact_descriptor, redact_keyed_text, redact_metadata
from tests.support import scaling_ratio

PLANTED = "rawSecretToken_12345"
OTHER = "otherSecretValue_6789"


@pytest.fixture(autouse=True)
def _no_ambient_key(monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("Authorization", PLANTED, "***"),
        ("authorization", "Bearer plainwords", "Bearer ***"),
        ("Proxy-Authorization", "Basic dXNlcjpwYXNzd29yZA==", "Basic ***"),
        ("AUTHORIZATION", "custom-scheme " + PLANTED, "***"),
        ("Cookie", "sid=mySecretSession99; Path=/", "sid=***; Path=/"),
        ("Set-Cookie", "sid=mySecretSession99", "sid=***"),
        ("password", "MySecretPassword9", "***"),
        ("passwd", "short", "***"),
        ("X-Api-Key", PLANTED, "***"),
        ("apiKey", PLANTED, "***"),
        ("client_secret", PLANTED, "***"),
        ("GITHUB_TOKEN", PLANTED, "***"),
        ("accessToken", PLANTED, "***"),
        ("privateKey", PLANTED, "***"),
        ("db_password_prod", PLANTED, "***"),
        ("token2", PLANTED, "***"),
    ],
)
def test_a_value_is_redacted_when_its_key_names_a_credential(key, value, expected):
    assert redact_keyed_text(key, value) == expected
    assert redact_metadata({key: value}) == {key: expected}
    assert redact_metadata({"headers": [{key: value}]}) == {"headers": [{key: expected}]}


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("author", "Jane Example", "Jane Example"),
        ("keywords", "search, files, read", "search, files, read"),
        ("tokenizer", "cl100k_base", "cl100k_base"),
        ("max_tokens", "4096 per call", "4096 per call"),
        ("description", "Pass the token in the header", "Pass the token in the header"),
        ("session", "interactive", "interactive"),
        ("token_url", "https://idp.example/oauth/token", "https://idp.example"),
        ("Authorization", "${GITHUB_TOKEN}", "${GITHUB_TOKEN}"),
        ("Authorization", "Bearer ${GITHUB_TOKEN}", "Bearer ${GITHUB_TOKEN}"),
        ("Authorization", "Bearer $GITHUB_TOKEN", "Bearer $GITHUB_TOKEN"),
        ("api_key", "${env:OPENAI_API_KEY}", "${env:OPENAI_API_KEY}"),
        ("password", "", ""),
        ("Cookie", "theme=dark", "theme=dark"),
    ],
)
def test_other_keys_urls_and_variable_references_keep_their_values(key, value, expected):
    assert redact_keyed_text(key, value) == expected
    assert redact_metadata({key: value}) == {key: expected}


def test_values_that_are_not_text_are_left_to_their_own_keys():
    data = {"password": {"minLength": 12}, "token": 7, "secret": None, "sig": ["a", "b"]}
    assert redact_metadata(data) == data


def test_a_descriptor_exports_no_credential_held_under_a_key():
    descriptor = {
        "name": "read_file",
        "description": "Reads a file.",
        "annotations": {"Authorization": PLANTED, "title": "Reader"},
        "_meta": {"upstream": {"headers": {"Cookie": "sid=mySecretSession99"}}},
        "serverInfo": {"password": "MySecretPassword9"},
    }
    safe = redact_descriptor(descriptor)
    text = json.dumps(safe)
    assert PLANTED not in text and "mySecretSession99" not in text
    assert "MySecretPassword9" not in text
    assert safe["annotations"]["title"] == "Reader"
    assert safe["name"] == "read_file"


def _write(root: Path, relative: str, value: Any) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")


def _scan(root: Path, relative: str, value: Any):
    _write(root, relative, value)
    result = IDEAgentScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    agent = next(c for c in result.components if isinstance(c, IDEAgentComponent))
    return agent


def _cursor(secret: str, url: str = "https://mcp.example/sse") -> dict[str, Any]:
    return {"mcpServers": {"x": {"url": url, "headers": {"Authorization": secret}}}}


def _codex(secret: str, url: str = "https://mcp.example/sse") -> str:
    return (
        f'[mcp_servers.x]\nurl = "{url}"\n\n'
        f'[mcp_servers.x.http_headers]\nAuthorization = "{secret}"\npassword = "{secret}"\n'
    )


@pytest.mark.parametrize(
    ("relative", "settings"),
    [(".cursor/cli.json", _cursor), (".codex/config.toml", _codex)],
    ids=["cursor-json", "codex-toml"],
)
def test_the_unkeyed_settings_digest_does_not_cover_a_credential_held_under_a_key(
    tmp_path, relative, settings
):
    first = _scan(tmp_path / "a", relative, settings(PLANTED))
    second = _scan(tmp_path / "b", relative, settings(OTHER))
    assert first.properties["settings_hashes"] == second.properties["settings_hashes"]
    moved = _scan(tmp_path / "c", relative, settings(PLANTED, "https://elsewhere.example/sse"))
    assert moved.properties["settings_hashes"] != first.properties["settings_hashes"]
    unbound = [risk.detail for risk in first.risks if risk.category == "completeness"]
    assert any(relative in detail and "not bound" in detail for detail in unbound)


def test_the_keyed_binding_still_tells_two_credentials_apart(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "ide-binding-key-" + "0123456789abcdef" * 2)
    first = _scan(tmp_path / "a", ".cursor/cli.json", _cursor(PLANTED))
    second = _scan(tmp_path / "b", ".cursor/cli.json", _cursor(OTHER))
    assert first.properties["settings_hashes"] == second.properties["settings_hashes"]
    assert first.model_dump(mode="json") != second.model_dump(mode="json")
    assert PLANTED not in json.dumps(first.model_dump(mode="json"))


def test_redacting_many_keyed_values_is_linear():
    def run(scale):
        count = 2_000 * scale
        data = {f"key{index}_token": "x" * 40 for index in range(count)}
        data["token_" * count] = "y" * 40
        data["Cookie"] = "; ".join(f"c{index}=value{index}value" for index in range(count))
        return redact_metadata(data)

    assert scaling_ratio(run) < 10
