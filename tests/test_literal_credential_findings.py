"""A literal credential in an MCP server definition, or in the `env` of Claude Code settings,
is a finding that names its file, its position and its type, never its value; a reference
or a placeholder is not one.

Every planted value is put together from parts when the tests run, so that this file holds
no literal in a token format.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import IDEAgentComponent, MCPServerComponent
from nexus_symbiote.crosswalk import sarif_tags
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.scanners.credential_literals import (
    ADVICE,
    CATEGORY,
    KINDS,
    URL_PASSWORD,
    candidate_kinds,
    credential_name,
    ordered_kinds,
    value_kinds,
)
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV, MCPScanner
from tests.support import ROOT

BODY = "Ab3dEf6hIj9k" * 3
GITHUB = "gh" + "p_" + BODY
FINE_GRAINED = "github" + "_pat_" + BODY
AWS_KEY_ID = "AK" + "IA" + "Q7RTZ2MWX4PLD9VN"
ANTHROPIC = "sk" + "-ant-" + "api03-" + BODY * 2
OPENAI = "sk" + "-proj-" + BODY
GITLAB = "gl" + "pat-" + BODY[:24]
JWT = ".".join(("ey" + "J" + BODY[:20], "ey" + "J" + BODY[:24], BODY[:22]))
RANDOM = "9f8e7d6c5b4a" + "3f2e1d0c9b8a" + "7f6e5d4c"
WORDY = "hunter2" + "hunter"
MIXED = "Zq8vLm2p" + "Xr7tKw4n"
BASIC = base64.b64encode(f"service:{WORDY}".encode()).decode()
PEM_BEGIN, PEM_END = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----"
PEM = "\n".join((PEM_BEGIN, "MIIEvQIBADANBgkqhkiG9w0BAQEF" + "AASCBKcwggSjAgEAAoIBAQC7", PEM_END))
URL = "https://mcp.example.test/mcp"
DIGEST = "mcp/x@sha256:" + "a" * 64
RANDOM_KIND, UNKNOWN_KIND = "generic high-entropy value", "unknown"
_DETAIL = re.compile(
    r"MCP server '(?P<server>[^']*)' holds a literal credential in (?P<path>\S+) at "
    r"(?P<position>\S+) \(credential types?: (?P<kinds>[^()]+)\)\."
)


def _stdio(*args: str, **fields: Any) -> dict[str, Any]:
    return {"command": "npx", "args": ["-y", "some-mcp@1.0.0", *args], **fields}


def _http(**fields: Any) -> dict[str, Any]:
    return {"type": "http", "url": URL, **fields}


def _docker(*args: str) -> dict[str, Any]:
    return {"command": "docker", "args": ["run", "-i", "--rm", *args, DIGEST]}


def _servers(
    root: Path, servers: dict[str, Any], path: str = ".mcp.json"
) -> list[MCPServerComponent]:
    file = root / path
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps({"mcpServers": servers}))
    result = MCPScanner().scan(root, config_only=True)
    assert not result.scan_failures, result.scan_failures
    return [c for c in result.components if isinstance(c, MCPServerComponent)]


def _literals(servers: list[MCPServerComponent]) -> list[tuple[str, str]]:
    """The position and types of every literal credential finding, in recorded order."""
    found = []
    for server in servers:
        for risk in server.risks:
            if risk.category == CATEGORY:
                match = _DETAIL.fullmatch(risk.detail)
                assert match is not None, risk.detail
                assert match["server"] == server.name and match["path"] == server.source_path
                found.append((match["position"], match["kinds"]))
    return found


def _dump(servers: list[MCPServerComponent]) -> str:
    return json.dumps([server.model_dump(mode="json") for server in servers])


# Each rule: a definition that holds a literal credential, its twin that holds none, where
# the finding is, its type, and the planted value.
CASES: dict[str, tuple[dict[str, Any], dict[str, Any], str, str, str]] = {
    "a bearer token in an Authorization header": (
        _http(headers={"Authorization": f"Bearer {RANDOM}"}),
        _http(headers={"Authorization": "Bearer ${API_TOKEN}"}),
        "headers.Authorization",
        "bearer token",
        RANDOM,
    ),
    "basic credentials in an Authorization header": (
        _http(headers={"Authorization": f"Basic {BASIC}"}),
        _http(headers={"Authorization": "Basic ${BASIC_CREDENTIALS}"}),
        "headers.Authorization",
        "basic credentials",
        BASIC,
    ),
    "a bearer value with characters outside the token alphabet": (
        _http(headers={"Authorization": f"Bearer svc:{WORDY}"}),
        _http(headers={"Authorization": "Bearer svc:${API_TOKEN}"}),
        "headers.Authorization",
        "bearer token",
        WORDY,
    ),
    "basic credentials in a Proxy-Authorization header": (
        _http(headers={"Proxy-Authorization": f"Basic {BASIC}"}),
        _http(headers={"Proxy-Authorization": "Basic %PROXY_CREDENTIALS%"}),
        "headers.Proxy-Authorization",
        "basic credentials",
        BASIC,
    ),
    "an Authorization header without a scheme": (
        _http(headers={"Authorization": RANDOM}),
        _http(headers={"Authorization": "${input:api_token}"}),
        "headers.Authorization",
        RANDOM_KIND,
        RANDOM,
    ),
    "a Codex header named for a credential": (
        _http(http_headers={"X-Api-Key": RANDOM}),
        _http(http_headers={"X-Request-Id": RANDOM}),
        "http_headers.X-Api-Key",
        RANDOM_KIND,
        RANDOM,
    ),
    "a bearer value under a name that marks no credential": (
        _stdio(env={"AUTH_HEADER": f"Bearer {RANDOM}"}),
        _stdio(env={"AUTH_HEADER": "Bearer ${AUTH_TOKEN}"}),
        "env.AUTH_HEADER",
        "bearer token",
        RANDOM,
    ),
    "a GitHub token in an environment value": (
        _stdio(env={"GITHUB_TOKEN": GITHUB}),
        _stdio(env={"GITHUB_TOKEN": "${GITHUB_TOKEN}"}),
        "env.GITHUB_TOKEN",
        "GitHub token",
        GITHUB,
    ),
    "a fine-grained GitHub token under an unrelated name": (
        _stdio(env={"LOG_LEVEL": FINE_GRAINED}),
        _stdio(env={"LOG_LEVEL": "github" + "_pat_" + "x" * 30}),
        "env.LOG_LEVEL",
        "GitHub token",
        FINE_GRAINED,
    ),
    "an AWS access key ID": (
        _stdio(env={"AWS_ACCESS_KEY_ID": AWS_KEY_ID}),
        _stdio(env={"AWS_ACCESS_KEY_ID": "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"}),
        "env.AWS_ACCESS_KEY_ID",
        "AWS access key ID",
        AWS_KEY_ID,
    ),
    "an Anthropic key": (
        _stdio(env={"ANTHROPIC_API_KEY": ANTHROPIC}),
        _stdio(env={"ANTHROPIC_API_KEY": "${env:ANTHROPIC_API_KEY}"}),
        "env.ANTHROPIC_API_KEY",
        "Anthropic key",
        ANTHROPIC,
    ),
    "an OpenAI key": (
        _stdio(env={"OPENAI_API_KEY": OPENAI}),
        _stdio(env={"OPENAI_API_KEY": "sk" + "-your-openai-api-key-here"}),
        "env.OPENAI_API_KEY",
        "OpenAI key",
        OPENAI,
    ),
    "a token in another known format": (
        _stdio(env={"UPSTREAM": GITLAB}),
        _stdio(env={"UPSTREAM": "gl" + "pat-" + "x" * 24}),
        "env.UPSTREAM",
        "token in a known format",
        GITLAB,
    ),
    "a JSON Web Token": (
        _stdio(env={"SERVICE_ROLE": JWT}),
        _stdio(env={"SERVICE_ROLE": "<service-role-jwt>"}),
        "env.SERVICE_ROLE",
        "token in a known format",
        JWT,
    ),
    "a private key block": (
        _stdio(env={"SIGNING_KEY": PEM}),
        _stdio(env={"SIGNING_KEY": "\n".join((PEM_BEGIN, "...", PEM_END))}),
        "env.SIGNING_KEY",
        "private key",
        PEM,
    ),
    "a password under a name that ends in a credential word": (
        _stdio(env={"DB_PASSWORD": WORDY}),
        _stdio(env={"DB_PASSWORD": "postgres"}),
        "env.DB_PASSWORD",
        UNKNOWN_KIND,
        WORDY,
    ),
    "a password in the user information of an argument": (
        _stdio(f"postgresql://app:{MIXED}@db.internal/app"),
        _stdio("postgresql://app:${DB_PASSWORD}@db.internal/app"),
        "args[2]",
        "URL password",
        MIXED,
    ),
    "a password in the user information of an endpoint": (
        {"type": "http", "url": f"https://svc:{MIXED}@mcp.example.test/mcp"},
        {"type": "http", "url": "https://svc:${MCP_PASSWORD}@mcp.example.test/mcp"},
        "url",
        "URL password",
        MIXED,
    ),
    "a query parameter of an endpoint named for a credential": (
        {"type": "http", "serverUrl": f"{URL}?api_key={RANDOM}"},
        {"type": "http", "serverUrl": f"{URL}?request={RANDOM}"},
        "serverUrl",
        RANDOM_KIND,
        RANDOM,
    ),
    "the value of an option named for a credential": (
        _stdio("--api-key", RANDOM),
        _stdio("--api-key", "${API_KEY}"),
        "args[3]",
        RANDOM_KIND,
        RANDOM,
    ),
    "the value of an option named for a bearer": (
        _stdio("--sse", URL, "--oauth2Bearer", RANDOM),
        _stdio("--sse", URL, "--oauth2Bearer", "${GATEWAY_TOKEN}"),
        "args[5]",
        RANDOM_KIND,
        RANDOM,
    ),
    "an option named for a credential with its value attached": (
        _stdio(f"--api-key={RANDOM}"),
        _stdio("--api-key=<your-api-key>"),
        "args[2]",
        RANDOM_KIND,
        RANDOM,
    ),
    "an environment assignment passed to a container": (
        _docker("-e", f"API_KEY={RANDOM}"),
        _docker("-e", "API_KEY"),
        "args[4]",
        RANDOM_KIND,
        RANDOM,
    ),
    "a container environment option with its assignment attached": (
        _docker(f"--env=API_KEY={RANDOM}"),
        _docker("--env=API_KEY"),
        "args[3]",
        RANDOM_KIND,
        RANDOM,
    ),
    "a header line after a header option": (
        _stdio(URL, "--header", f"Authorization: Bearer {RANDOM}"),
        _stdio(URL, "--header", "Authorization: Bearer ${AUTH_TOKEN}"),
        "args[4]",
        "bearer token",
        RANDOM,
    ),
    "a header line attached to its option": (
        _stdio(URL, f"--header=X-Api-Key: {RANDOM}"),
        _stdio(URL, f"--header=X-Request-Id: {RANDOM}"),
        "args[3]",
        RANDOM_KIND,
        RANDOM,
    ),
    "a header line joined to a short header option": (
        _stdio(URL, f"-HX-Api-Key: {RANDOM}"),
        _stdio(URL, f"-HX-Request-Id: {RANDOM}"),
        "args[3]",
        RANDOM_KIND,
        RANDOM,
    ),
    "an assignment in an inline shell script": (
        {"command": "sh", "args": ["-c", f'API_TOKEN="Bearer {RANDOM}" exec uvx x==1.0']},
        {"command": "sh", "args": ["-c", 'API_TOKEN="Bearer $API_TOKEN" exec uvx x==1.0']},
        "args[1]",
        "bearer token",
        RANDOM,
    ),
    "a scheme word and its credential in a cmd script": (
        {"command": "cmd", "args": ["/c", f"set API_TOKEN=Bearer {RANDOM}&& npx -y x@1.0.0"]},
        {"command": "cmd", "args": ["/c", "set API_TOKEN=Bearer %API_TOKEN%&& npx -y x@1.0.0"]},
        "args[1]",
        "bearer token",
        RANDOM,
    ),
    "a bearer token inside a JSON argument": (
        _stdio("--headers", json.dumps({"Authorization": f"Bearer {RANDOM}"})),
        _stdio("--headers", json.dumps({"Authorization": "Bearer ${AUTH_TOKEN}"})),
        "args[3]",
        "bearer token",
        RANDOM,
    ),
    "a header line in an inline script": (
        {"command": "sh", "args": ["-c", f"exec gateway -H 'X-Api-Key: {RANDOM}' --stdio"]},
        {"command": "sh", "args": ["-c", f"exec gateway -H 'X-Request-Id: {RANDOM}' --stdio"]},
        "args[1]",
        RANDOM_KIND,
        RANDOM,
    ),
    "a passphrase with spaces as the value of an option": (
        _stdio("--passphrase", f"correct horse {WORDY}"),
        _stdio("--passphrase", "correct horse battery staple"),
        "args[3]",
        UNKNOWN_KIND,
        WORDY,
    ),
    "a value under a numbered credential name": (
        _stdio(env={"API_KEY_2": RANDOM}),
        _stdio(env={"API_KEY_NAME": RANDOM}),
        "env.API_KEY_2",
        RANDOM_KIND,
        RANDOM,
    ),
    "a command line in the command field": (
        {"command": f"npx -y some-mcp@1.0.0 --token {RANDOM}"},
        {"command": "npx -y some-mcp@1.0.0 --token $SERVICE_TOKEN"},
        "command",
        RANDOM_KIND,
        RANDOM,
    ),
}
REFERENCES = (
    "${API_TOKEN}",
    "${input:api_token}",
    "${env:API_TOKEN}",
    "$API_TOKEN",
    "%API_TOKEN%",
    "$(cat /run/secrets/api_token)",
    "",
)
PLACEHOLDERS = (
    "CHANGE_ME",
    "<token>",
    "xxxx",
    "your-api-key",
    "x" * 32,
    "<YOUR_API_KEY>",
    "API_KEY_GOES_HERE_1",
    "[redacted]",
    "{{API_TOKEN}}",
    "changeme123",
    "replace-with-token-1",
    "dummy-token-12345",
    "example-token-12345",
    "sk" + "-...",
    "*" * 12,
    "[api-token-1]",
    "{{ api_token_1 }}",
    "prefix-<token-1>",
    "1234567890",
    "abcdef0123456789",
    "sk" + "-1234567890abcdef1234567890abcdef",
    "{api-token-1}",
    "token-1...token-2",
    "sample-token-1",
    "placeholder-token-1",
    "insert-token-1-here",
    "redacted-token-1",
)
WORDS = (
    "postgres",
    "not-needed",
    "lm-studio",
    "development",
    "MyApiKey",
    "correct-horse-battery-staple",
    "1" * 12,
    "ab12" * 3,
)
LOCATORS = (
    "/run/secrets/api_token1",
    "./secrets/token1.txt",
    "~/.config/service/token9",
    "C:\\secrets\\token1",
    "service-account-1.json",
    "https://vault.example.test/v1/secret9",
)


@pytest.mark.parametrize("case", CASES)
def test_each_rule_reports_its_literal_and_not_its_benign_twin(tmp_path, monkeypatch, case):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    planted, twin, position, kind, _ = CASES[case]
    assert _literals(_servers(tmp_path / "planted", {"svc": planted})) == [(position, kind)]
    assert _literals(_servers(tmp_path / "twin", {"svc": twin})) == []


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("key", [None, "k" * 40])
def test_a_finding_never_holds_the_value_a_part_of_it_its_length_or_a_digest(
    tmp_path, monkeypatch, case, key
):
    if key is None:
        monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    else:
        monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, key)
    planted, _, position, _, secret = CASES[case]
    servers = _servers(tmp_path, {"svc": planted})
    assert [found for found, _ in _literals(servers)] == [position]
    dump = _dump(servers)
    assert secret not in dump
    assert not any(secret[start : start + 8] in dump for start in range(len(secret) - 7))
    for algorithm in ("sha256", "sha1", "md5"):
        digest = hashlib.new(algorithm, secret.encode(), usedforsecurity=False).hexdigest()
        assert digest not in dump and digest[:16] not in dump
    (finding,) = [risk for risk in servers[0].risks if risk.category == CATEGORY]
    text = f"{finding.detail} {finding.recommendation}"
    assert secret[:4] not in text and secret[-4:] not in text
    assert str(len(secret)) not in text
    assert finding.severity is RiskSeverity.HIGH and finding.recommendation == ADVICE
    assert "Rotate the credential" in ADVICE and "reference" in ADVICE


def _positions(value: str) -> dict[str, dict[str, Any]]:
    """One server for every position that reads a value by where it is written."""
    return {
        "authorization": _http(headers={"Authorization": value}),
        "bearer": _http(headers={"Authorization": f"Bearer {value}"}),
        "header": _http(headers={"X-Api-Key": value}),
        "environment": _stdio(env={"API_TOKEN": value}),
        "option": _stdio("--api-key", value),
        "assignment": _stdio(f"--api-key={value}"),
        "container": _docker("-e", f"API_KEY={value}"),
        "password": {"type": "http", "url": f"https://svc:{quote(value, safe='')}@h.test/mcp"},
        "query": {"type": "http", "url": f"{URL}?api_key={quote(value, safe='')}"},
    }


@pytest.mark.parametrize("value", [*REFERENCES, *PLACEHOLDERS, *WORDS])
def test_a_reference_a_placeholder_or_a_word_is_no_credential_in_any_position(tmp_path, value):
    assert _literals(_servers(tmp_path, _positions(value))) == []


def test_the_same_positions_report_a_value_that_is_a_credential(tmp_path):
    found = _literals(_servers(tmp_path, _positions(RANDOM)))
    assert len(found) == len(_positions(RANDOM))
    assert {kinds for _, kinds in found} == {RANDOM_KIND, "bearer token", "URL password"}


@pytest.mark.parametrize(
    "value",
    [
        "sk" + "-local-development-key-for-ollama",
        "sk" + "-your-openai-api-key-here",
        "sk" + "-" + "x" * 48,
        f"Bearer {RANDOM}$SUFFIX",
        f"Bearer {RANDOM}" + "${SUFFIX}",
        "Bearer authentication",
    ],
)
def test_a_stand_in_key_and_a_composed_bearer_value_are_no_credentials(tmp_path, value):
    servers = {"model": _stdio(env={"OPENAI_API_KEY": value}), "raw": _stdio("--upstream", value)}
    assert _literals(_servers(tmp_path, servers)) == []


def test_a_url_that_cannot_be_parsed_does_not_hide_the_next_one(tmp_path):
    text = f"http://[broken postgresql://app:{MIXED}@db.internal/app"
    assert _literals(_servers(tmp_path, {"svc": _stdio(text)})) == [("args[2]", "URL password")]


@pytest.mark.parametrize("value", LOCATORS)
def test_a_locator_under_a_credential_name_is_no_credential(tmp_path, value):
    servers = {
        "environment": _stdio(env={"API_TOKEN": value, "PRIVATE_KEY": value}),
        "option": _stdio("--private-key", value, "--token", value),
    }
    assert _literals(_servers(tmp_path, servers)) == []


@pytest.mark.parametrize(
    "args",
    [
        ["mcp-server-tokens==10.20.30"],
        ["--with", "some-secret==10.20.30", "mcp-server-git==0.6.2"],
        ["--with", "auth-token>=10.20.30", "mcp-server-git==0.6.2"],
    ],
)
def test_a_requirement_is_not_a_credential_assignment(tmp_path, args):
    assert _literals(_servers(tmp_path, {"git": {"command": "uvx", "args": args}})) == []


@pytest.mark.parametrize(
    "name",
    [
        "GITHUB_TOKEN",
        "GITHUB_PERSONAL_ACCESS_TOKEN",
        "token2",
        "clientSecret",
        "DB_PASSWORD",
        "PGPASSWORD",
        "MYSQL_PWD",
        "SMTP_PASS",
        "GITHUB_PAT",
        "X-API-Key",
        "apikey",
        "AWS_SECRET_ACCESS_KEY",
        "private.key",
        "--account-key",
        "SSH_PASSPHRASE",
        "--oauth2Bearer",
        "GITHUB_TOKEN_2",
    ],
)
def test_a_name_that_ends_in_a_credential_word_marks_its_value(name):
    assert credential_name(name)
    assert value_kinds(RANDOM, name) == [RANDOM_KIND]


@pytest.mark.parametrize(
    "name",
    [
        "TOKEN_FILE",
        "MAX_TOKENS",
        "SECRET_NAME",
        "API_KEY_ID",
        "SORT_KEY",
        "PUBLIC_KEY",
        "BYPASS",
        "COMPASS",
        "DISPATCH",
        "LOG_LEVEL",
        "tokenizer",
        "",
    ],
)
def test_any_other_name_marks_no_value_but_a_known_format_still_counts(name):
    assert not credential_name(name)
    assert value_kinds(RANDOM, name) == []
    assert value_kinds(GITHUB, name) == ["GitHub token"]


@pytest.mark.parametrize(
    "candidate,kind",
    [
        (RANDOM, RANDOM_KIND),
        ("123e4567-e89b-12d3-a456-426614174000", RANDOM_KIND),
        (RANDOM[:19], UNKNOWN_KIND),
        ("ab12cd34" * 3, UNKNOWN_KIND),
        (WORDY, UNKNOWN_KIND),
        ("correct horse battery staple 1", UNKNOWN_KIND),
        ("MixedCaseLettersOnlyValue", UNKNOWN_KIND),
    ],
)
def test_a_value_without_a_known_format_is_typed_by_how_random_it_reads(candidate, kind):
    assert candidate_kinds(candidate) == [kind]
    assert candidate_kinds(candidate, URL_PASSWORD) == ["URL password"]


def test_types_come_from_a_fixed_vocabulary_in_a_fixed_order(tmp_path):
    assert len(KINDS) == len(set(KINDS)) == 11
    assert ordered_kinds(["unknown", "URL password", "GitHub token", "unknown"]) == [
        "GitHub token",
        "URL password",
        "unknown",
    ]
    script = f"TOKEN={GITHUB} exec server postgresql://app:{MIXED}@db.internal/app"
    (server,) = _servers(tmp_path, {"svc": {"command": "sh", "args": ["-c", script]}})
    assert [risk.detail for risk in server.risks if risk.category == CATEGORY] == [
        "MCP server 'svc' holds a literal credential in .mcp.json at args[1] "
        "(credential types: GitHub token, URL password)."
    ]


def test_findings_keep_a_fixed_order_and_reproduce(tmp_path):
    server = {
        "url": f"https://svc:{MIXED}@mcp.example.test/mcp",
        "headers": {"X-Api-Key": RANDOM, "Authorization": f"Bearer {RANDOM}"},
        "env": {"OPENAI_API_KEY": OPENAI, "ANTHROPIC_API_KEY": ANTHROPIC},
        "command": "npx",
        "args": ["-y", "some-mcp@1.0.0", "--token", RANDOM, f"--api-key={AWS_KEY_ID}"],
    }
    first = _servers(tmp_path / "a", {"svc": server})
    assert _literals(first) == [
        ("url", "URL password"),
        ("headers.Authorization", "bearer token"),
        ("headers.X-Api-Key", RANDOM_KIND),
        ("env.ANTHROPIC_API_KEY", "Anthropic key"),
        ("env.OPENAI_API_KEY", "OpenAI key"),
        ("args[3]", RANDOM_KIND),
        ("args[4]", "AWS access key ID"),
    ]
    reordered = {**server, "env": dict(reversed(server["env"].items()))}
    assert _dump(_servers(tmp_path / "b", {"svc": reordered})) == _dump(first)


def test_a_name_the_inventory_withholds_is_not_shown_in_the_position(tmp_path):
    servers = {
        # A token pasted as a variable name is exported as a marker, and so is a header
        # name that repeats a value another server holds.
        "pasted": _stdio(env={GITHUB: AWS_KEY_ID}),
        "repeated": _http(headers={WORDY: GITLAB}),
        "holder": _stdio(env={"DB_PASSWORD": WORDY}),
    }
    found = _servers(tmp_path, servers)
    assert sorted(_literals(found)) == [
        ("env.DB_PASSWORD", UNKNOWN_KIND),
        ("env.[redacted]", "AWS access key ID"),
        ("headers.[redacted]", "token in a known format"),
    ]
    details = [risk.detail for server in found for risk in server.risks]
    assert not any(GITHUB in detail or WORDY in detail for detail in details)
    assert GITHUB not in _dump(found)


@pytest.mark.parametrize(
    "path,content,position",
    [
        (".cursor/mcp.json", {"mcpServers": {"svc": _stdio(env={"GITHUB_TOKEN": GITHUB})}}, "env"),
        (
            "config/claude_desktop_config.json",
            {"mcpServers": {"svc": _stdio(env={"GITHUB_TOKEN": GITHUB})}},
            "env",
        ),
        (
            ".vscode/mcp.json",
            '{\n  // VS Code reads comments.\n  "servers": {"svc": '
            + json.dumps(_stdio(env={"GITHUB_TOKEN": GITHUB}))
            + "},\n}",
            "env",
        ),
        (
            ".codex/config.toml",
            '[mcp_servers.svc]\ncommand = "npx"\nargs = ["-y", "some-mcp@1.0.0"]\n\n'
            f'[mcp_servers.svc.env]\nGITHUB_TOKEN = "{GITHUB}"\n',
            "env",
        ),
        (
            ".gemini/settings.json",
            {"mcpServerCommand": f"npx -y some-mcp@1.0.0 --github-token={GITHUB}"},
            "args",
        ),
    ],
)
def test_a_client_file_of_each_syntax_names_itself_in_the_finding(
    tmp_path, path, content, position
):
    file = tmp_path / path
    file.parent.mkdir(parents=True)
    file.write_text(content if isinstance(content, str) else json.dumps(content))
    result = MCPScanner().scan(tmp_path, config_only=True)
    assert not result.scan_failures, result.scan_failures
    (server,) = [c for c in result.components if isinstance(c, MCPServerComponent)]
    (finding,) = [risk for risk in server.risks if risk.category == CATEGORY]
    where = "env.GITHUB_TOKEN" if position == "env" else "args[2]"
    assert finding.detail == (
        f"MCP server '{server.name}' holds a literal credential in {path} at {where} "
        "(credential type: GitHub token)."
    )
    assert GITHUB not in server.model_dump_json()


def test_an_endpoint_password_keeps_its_transport_finding(tmp_path):
    (server,) = _servers(
        tmp_path, {"svc": CASES["a password in the user information of an endpoint"][0]}
    )
    categories = [risk.category for risk in server.risks]
    assert categories.count("transport_security") == 1 and categories.count(CATEGORY) == 1


def _project(root: Path) -> list[str]:
    """A project that plants every listed credential type; the planted values."""
    servers = {
        "payments": _http(headers={"Authorization": f"Bearer {RANDOM}"}),
        "orders": _stdio(env={"GITHUB_TOKEN": GITHUB, "AWS_ACCESS_KEY_ID": AWS_KEY_ID}),
        "models": _stdio(env={"ANTHROPIC_API_KEY": ANTHROPIC, "OPENAI_API_KEY": OPENAI}),
        "database": _stdio(f"postgresql://app:{MIXED}@db.internal/app", "--token", WORDY),
    }
    for path, names in (
        (".mcp.json", ("payments", "orders")),
        (".cursor/mcp.json", ("models", "database")),
    ):
        file = root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(json.dumps({"mcpServers": {name: servers[name] for name in names}}))
    return [RANDOM, GITHUB, AWS_KEY_ID, ANTHROPIC, OPENAI, MIXED, WORDY]


def test_planted_values_reach_no_export_and_no_command_output(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    project = tmp_path / "project"
    planted = _project(project)
    outputs: dict[str, str] = {}
    for form in ("json", "cyclonedx", "spdx", "sarif"):
        options = ["scan", "--no-project-policy", "--report-only", "-f", form]
        printed = CliRunner().invoke(main, [*options, str(project)])
        assert printed.exit_code == 0, printed.output
        outputs[f"{form} stdout"], outputs[f"{form} stderr"] = printed.stdout, printed.stderr
        written = CliRunner().invoke(main, [*options, "-o", f"out.{form}", str(project)])
        assert written.exit_code == 0, written.output
        outputs[f"{form} file"] = (tmp_path / f"out.{form}").read_text(encoding="utf-8")
        outputs[f"{form} report"] = written.output
    for name, options in (
        ("risk", ["risk", "out.json", "--no-project-policy"]),
        ("risk json", ["risk", "out.json", "--no-project-policy", "--json-output"]),
        ("summary", ["summary", "out.json"]),
        ("vex", ["vex", "out.json"]),
        ("crosswalk", ["crosswalk", "out.json", "--format", "markdown"]),
    ):
        outputs[name] = CliRunner().invoke(main, options).output
    for name, text in outputs.items():
        assert text, name
        for secret in planted:
            assert secret not in text, name

    native = json.loads(outputs["json stdout"])
    details = sorted(
        risk["detail"]
        for component in native["components"]
        for risk in component.get("risks", [])
        if risk["category"] == CATEGORY
    )
    expected = sorted(
        f"MCP server '{server}' holds a literal credential in {path} at {position} "
        f"(credential type: {kind})."
        for server, path, position, kind in (
            ("payments", ".mcp.json", "headers.Authorization", "bearer token"),
            ("orders", ".mcp.json", "env.AWS_ACCESS_KEY_ID", "AWS access key ID"),
            ("orders", ".mcp.json", "env.GITHUB_TOKEN", "GitHub token"),
            ("models", ".cursor/mcp.json", "env.ANTHROPIC_API_KEY", "Anthropic key"),
            ("models", ".cursor/mcp.json", "env.OPENAI_API_KEY", "OpenAI key"),
            ("database", ".cursor/mcp.json", "args[2]", "URL password"),
            ("database", ".cursor/mcp.json", "args[4]", "unknown"),
        )
    )
    assert details == expected
    for form in ("cyclonedx", "spdx"):
        assert all(json.dumps(detail)[1:-1] in outputs[f"{form} file"] for detail in expected)

    run = json.loads(outputs["sarif file"])["runs"][0]
    (rule,) = [r for r in run["tool"]["driver"]["rules"] if CATEGORY in r["id"]]
    assert rule["id"] == "nexus_symbiote/literal_credential/high"
    assert rule["properties"]["tags"] == ["security", *sarif_tags(CATEGORY, RiskSeverity.HIGH)]
    assert "external/cwe/cwe-798" in rule["properties"]["tags"]
    results = [r for r in run["results"] if r["ruleId"] == rule["id"]]
    assert len(results) == len(expected) and all(r["level"] == "error" for r in results)
    located = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
    assert located == {"project/.mcp.json", "project/.cursor/mcp.json"}
    assert {r["properties"]["recommendation"] for r in results} == {ADVICE}
    report = json.loads(outputs["risk json"])
    assert sum(f["category"] == CATEGORY for f in report["findings"]) == len(expected)
    assert "[literal_credential]" in outputs["risk"]


def test_one_literal_credential_passes_the_default_gate_and_fails_a_high_gate(
    tmp_path, monkeypatch
):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    project = tmp_path / "project"
    _servers(project, {"orders": _stdio(env={"GITHUB_TOKEN": GITHUB})})
    scan = ["scan", "--no-project-policy", str(project)]
    assert CliRunner().invoke(main, [*scan, "--check"]).exit_code == 0
    assert CliRunner().invoke(main, [*scan, "-o", "inventory.json"]).exit_code == 0
    risk = ["risk", "inventory.json", "--no-project-policy"]
    assert CliRunner().invoke(main, risk).exit_code == 0
    failed = CliRunner().invoke(main, [*risk, "--fail-on-severity", "high"])
    assert failed.exit_code == 1 and "env.GITHUB_TOKEN" in failed.output
    assert GITHUB not in failed.output


def test_a_literal_credential_added_between_snapshots_is_a_high_alert(tmp_path):
    before = _servers(
        tmp_path / "before", {"orders": _stdio(env={"GITHUB_TOKEN": "${GITHUB_TOKEN}"})}
    )
    after = _servers(tmp_path / "after", {"orders": _stdio(env={"GITHUB_TOKEN": GITHUB})})
    report = AIBOMDiffer().diff(AIBOM(components=before), AIBOM(components=after))
    (change,) = report.components_modified
    assert change.severity == "high"
    assert "Risk findings added: 1 high (literal_credential)." in change.details


def _claude(root: Path, settings: Any, path: str = ".claude/settings.json") -> list[str]:
    """The literal credential findings of the Claude Code record that reads ``path``."""
    file = root / path
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps(settings))
    result = IDEAgentScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    (agent,) = [
        c
        for c in result.components
        if isinstance(c, IDEAgentComponent) and path in c.properties.get("settings_hashes", {})
    ]
    assert ANTHROPIC not in agent.model_dump_json() and MIXED not in agent.model_dump_json()
    return [risk.detail for risk in agent.risks if risk.category == CATEGORY]


@pytest.mark.parametrize(
    "path",
    [
        ".claude/settings.json",
        ".claude/settings.local.json",
        "packages/app/.claude/settings.json",
    ],
)
def test_a_claude_code_settings_environment_value_is_reported_by_file_and_name(tmp_path, path):
    settings = {
        "env": {
            "HTTPS_PROXY": f"http://svc:{MIXED}@proxy.example.test:8080",
            "ANTHROPIC_API_KEY": ANTHROPIC,
            "ANTHROPIC_MODEL": "claude-sonnet-4-5",
            GITHUB: "1",
            "RETRIES": 3,
        }
    }
    assert _claude(tmp_path, settings, path) == [
        f"IDE agent 'claude-code' holds a literal credential in {path} at "
        "env.ANTHROPIC_API_KEY (credential type: Anthropic key).",
        f"IDE agent 'claude-code' holds a literal credential in {path} at env.HTTPS_PROXY "
        "(credential type: URL password).",
    ]


@pytest.mark.parametrize(
    "settings",
    [
        {"env": {"ANTHROPIC_API_KEY": "<your-api-key>"}},
        {"env": {"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"}},
        {"env": {"ANTHROPIC_BASE_URL": "https://proxy.example.test/v1", "DEBUG": "1"}},
        {"env": {"ANTHROPIC_API_KEY": 12345678}},
        {"env": ["ANTHROPIC_API_KEY"]},
        {"permissions": {"deny": ["WebFetch"]}},
    ],
)
def test_claude_code_settings_without_a_literal_credential_stay_clean(tmp_path, settings):
    assert _claude(tmp_path, settings) == []


def test_a_token_pasted_as_a_settings_variable_name_is_not_shown(tmp_path):
    (detail,) = _claude(tmp_path, {"env": {GITHUB: AWS_KEY_ID}})
    assert detail == (
        "IDE agent 'claude-code' holds a literal credential in .claude/settings.json at "
        "env.*** (credential type: AWS access key ID)."
    )


def test_the_finding_catalog_documents_the_category_and_every_type():
    catalog = (ROOT / "docs" / "finding-catalog.md").read_text(encoding="utf-8")
    (row,) = [line for line in catalog.splitlines() if line.startswith(f"| `{CATEGORY}` |")]
    assert row.split(" | ")[1:3] == ["high", "`mcp`, `ide_agents`"]
    for kind in KINDS:
        assert kind in row, kind
    limitations = (ROOT / "docs" / "known-limitations.md").read_text(encoding="utf-8")
    assert f"`{CATEGORY}`" in limitations
