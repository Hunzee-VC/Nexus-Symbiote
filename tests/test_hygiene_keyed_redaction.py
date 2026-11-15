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
        ("api_key", "${env:OPENAI_API_KEY}", "${env:OPENAI_API_KEY}"),
        ("Authorization", "Bearer ${input:github-token}", "Bearer ${input:github-token}"),
        ("password", "${config:db.password}", "${config:db.password}"),
        ("token", "${command:auth.getToken}", "${command:auth.getToken}"),
        ("client_secret", "${_CLIENT_SECRET2}", "${_CLIENT_SECRET2}"),
        ("password", "", ""),
        ("Cookie", "theme=dark", "theme=dark"),
    ],
)
def test_other_keys_urls_and_variable_references_keep_their_values(key, value, expected):
    assert redact_keyed_text(key, value) == expected
    assert redact_metadata({key: value}) == {key: expected}


DEFAULT = "FakeDefaultPw9"


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("password", "${DB_PASS:-" + DEFAULT + "}", "***"),
        ("password", "${DB_PASS:=" + DEFAULT + "}", "***"),
        ("password", "${DB_PASS-" + DEFAULT + "}", "***"),
        ("password", "${DB_PASS=" + DEFAULT + "}", "***"),
        ("password", "${DB_PASS:+" + DEFAULT + "}", "***"),
        ("password", "${DB_PASS:?" + DEFAULT + "}", "***"),
        ("password", "${DB_PASS#" + DEFAULT + "}", "***"),
        ("password", "${DB_PASS/x/" + DEFAULT + "}", "***"),
        ("password", "${env:DB_PASS:-" + DEFAULT + "}", "***"),
        ("password", "${env:-" + DEFAULT + "}", "***"),
        ("password", "${input:=" + DEFAULT + "}", "***"),
        ("password", "${DB_PASS:-${OTHER:-" + DEFAULT + "}}", "***"),
        ("password", "${DB_PASS}" + DEFAULT, "***"),
        ("password", "${db_pass:-" + DEFAULT + "}", "***"),
        ("password", "${DB_PA\u0405S}", "***"),
        ("password", "\uff04{DB_PASS}", "***"),
        ("password", "${DB_PASS}\n", "***"),
        ("password", "${" + DEFAULT + "}x", "***"),
        ("password", "${}", "***"),
        ("Authorization", "${X:=" + DEFAULT + "}", "***"),
        ("Authorization", "Bearer ${TOKEN:-" + DEFAULT + "}", "Bearer ***"),
        ("Proxy-Authorization", "Basic ${X-" + DEFAULT + "}", "Basic ***"),
        ("X-Api-Key", "${API_KEY:-" + DEFAULT + "}", "***"),
        ("api_key", "$FAKEDEFAULTPW9", "***"),
        ("GITHUB_TOKEN", "$GITHUB_TOKEN", "***"),
        ("Authorization", "$FAKEDEFAULTPW9", "***"),
        ("Authorization", "Bearer $FAKEDEFAULTPW9", "Bearer ***"),
    ],
)
def test_a_reference_with_a_literal_is_redacted_under_a_credential_key(key, value, expected):
    # A default, alternate value or pattern is written in the settings, and a bare
    # upper-case $NAME may be the password itself: only ${NAME} names a source alone.
    assert redact_keyed_text(key, value) == expected
    assert redact_metadata({key: value}) == {key: expected}
    assert DEFAULT not in json.dumps(redact_metadata({"headers": [{key: value}]}))


@pytest.mark.parametrize("value", [12345678, 7, -42, 0, 1.5, 3.0e9])
@pytest.mark.parametrize("key", ["password", "token", "api_key", "Authorization", "Cookie"])
def test_a_number_under_a_credential_key_is_redacted(key, value):
    assert redact_metadata({key: value}) == {key: "***"}
    assert redact_metadata({"auth": {key: [value, [value]]}}) == {"auth": {key: ["***", ["***"]]}}


def test_text_in_a_list_under_a_credential_key_is_redacted_by_that_key():
    data = {"password": [PLANTED, OTHER], "Authorization": ["Bearer plainwords"]}
    assert redact_metadata(data) == {"password": ["***", "***"], "Authorization": ["Bearer ***"]}


def test_values_that_say_nothing_or_have_keys_of_their_own_are_left_as_they_are():
    data = {
        "password": {"minLength": 12},
        "token": True,
        "secret": None,
        "sig": [False, None],
        "max_tokens": 4096,
        "tokenizer": ["cl100k_base"],
        "timeout": 30,
        "args": ["--port", 8080],
    }
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


def test_a_descriptor_field_named_as_a_credential_is_redacted_by_its_name():
    descriptor = {
        "name": "read_file",
        "description": "Reads a file.",
        "api_key": PLANTED,
        "sessionToken": [OTHER],
        "pin_password": 48291375,
        "_meta": {"upstream": {"Authorization": "Bearer ${UPSTREAM:-" + DEFAULT + "}"}},
    }
    safe = redact_descriptor(descriptor)
    assert (safe["api_key"], safe["sessionToken"], safe["pin_password"]) == ("***", ["***"], "***")
    assert safe["_meta"] == {"upstream": {"Authorization": "Bearer ***"}}
    assert safe["description"] == "Reads a file." and safe["name"] == "read_file"


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


def _held(relative: str, value: Any) -> Any:
    if relative.endswith(".toml"):
        held = json.dumps(value)
        return f'[mcp_servers.x]\nurl = "https://mcp.example"\npassword = {held}\n'
    return {"mcpServers": {"x": {"url": "https://mcp.example", "password": value}}}


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("${DB_PASS:-" + PLANTED + "}", "${DB_PASS:-" + OTHER + "}"),
        ("${DB_PASS:=" + PLANTED + "}", "${DB_PASS:=" + OTHER + "}"),
        ("${env:DB_PASS:-" + PLANTED + "}", "${env:DB_PASS:-" + OTHER + "}"),
        ("$" + PLANTED.upper(), "$" + OTHER.upper()),
        (12345678, 12345679),
        (1.25, 1.5),
        ([PLANTED], [OTHER]),
    ],
    ids=["default", "assign-default", "namespaced-default", "bare-name", "int", "float", "list"],
)
@pytest.mark.parametrize("relative", [".cursor/cli.json", ".codex/config.toml"])
def test_the_unkeyed_settings_digest_cannot_confirm_a_literal_a_reference_holds(
    tmp_path, relative, first, second
):
    one = _scan(tmp_path / "a", relative, _held(relative, first))
    two = _scan(tmp_path / "b", relative, _held(relative, second))
    assert one.properties["settings_hashes"] == two.properties["settings_hashes"]
    unbound = [risk.detail for risk in one.risks if risk.category == "completeness"]
    assert any(relative in detail and "not bound" in detail for detail in unbound)


@pytest.mark.parametrize("relative", [".cursor/cli.json", ".codex/config.toml"])
def test_a_pure_reference_under_a_credential_key_still_changes_the_digest(tmp_path, relative):
    one = _scan(tmp_path / "a", relative, _held(relative, "${DB_PASS}"))
    two = _scan(tmp_path / "b", relative, _held(relative, "${env:OTHER_PASS}"))
    assert one.properties["settings_hashes"] != two.properties["settings_hashes"]
    assert not [risk for risk in one.risks if risk.category == "completeness"]


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
