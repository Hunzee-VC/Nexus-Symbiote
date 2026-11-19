"""A literal credential in an MCP launch raises credential_exposure, which names positions only."""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners import mcp
from nexus_symbiote.scanners.mcp import (
    LISTED_CREDENTIAL_POSITIONS,
    MAX_CREDENTIAL_POSITIONS,
    MCPScanner,
    _credential_positions,
    _server_launch,
    _server_secrets,
)
from nexus_symbiote.utils.secrets import names_reference

CATEGORY = "credential_exposure"
NAMED = "a generic secret-like value"
ENV_SENTINEL = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_11"
SCHEME_SENTINEL = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_12"
PASSWORD = "synthetic-launch-password-98765"  # noqa: S105 - synthetic sentinel
VENDOR_TOKEN = "ghp_" + "A1" * 18
KEY_TOKEN = "ghp_" + "B2" * 18
QUERY_SENTINEL = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_13"
ENVFLAG_SENTINEL = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_14"
LEAK_VALUE = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_15"
PEM_SENTINEL = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_16"
SCRIPT_SENTINEL = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_17"
DEFAULT_SENTINEL = "Zx9synthPassw0rdSentinel77"  # noqa: S105 - synthetic sentinel
# A password that is also written as an env name: the name repeats a secret value.
LEAK_NAME = "synthetic-leaked-password-98765"
SENTINELS = (
    ENV_SENTINEL,
    DEFAULT_SENTINEL,
    SCHEME_SENTINEL,
    PASSWORD,
    VENDOR_TOKEN,
    KEY_TOKEN,
    QUERY_SENTINEL,
    ENVFLAG_SENTINEL,
    LEAK_VALUE,
    LEAK_NAME,
    PEM_SENTINEL,
)
PEM_BLOCK = f"-----BEGIN PRIVATE KEY-----\n{PEM_SENTINEL}\n-----END PRIVATE KEY-----"
# The independent review's benign server: each value is a path, a name, a number or
# prose under a name the scrubber treats as a credential's.
REVIEW_BENIGN = {
    "command": "npx",
    "args": [
        "-y",
        "some-mcp@1.0.0",
        "--description",
        "Basic calculator tools",
        "--title",
        "Token usage dashboard",
        "--note",
        "Authentication: handled by the gateway",
    ],
    "env": {
        "PWD": "/workspace/app2",
        "GIT_AUTHOR_NAME": "Jane Developer",
        "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
        "GOOGLE_APPLICATION_CREDENTIALS": "/home/dev/.config/gcloud/sa.json",
        "TOKENIZER": "cl100k_base",
        "KEYBOARD_LAYOUT": "us-international",
        "SESSION_TIMEOUT_MS": "3600000000",
    },
}
REVIEW_SCRIPTS = {
    "script": {
        "command": "sh",
        "args": ["-c", 'API_TOKEN="${API_TOKEN}" exec npx -y some-mcp@1.0.0'],
    },
    "script2": {
        "command": "sh",
        "args": ["-c", "GITHUB_TOKEN=$(gh auth token) exec npx -y x@1.0.0"],
    },
    "export": {
        "command": "sh",
        "args": ["-c", "export API_TOKEN=${API_TOKEN}; exec npx -y x@1.0.0"],
    },
}
QUERY_SERVER = {"type": "sse", "url": f"https://mcp.example.com/sse?api_key={QUERY_SENTINEL}"}
ENVFLAG_SERVER = {
    "command": "docker",
    "args": ["run", f"--env=API_TOKEN={ENVFLAG_SENTINEL}", "img"],
}
LEAK_SERVER = {
    "command": "npx",
    "args": ["x@1.0.0"],
    "env": {LEAK_NAME: LEAK_VALUE, "DB_PASSWORD": LEAK_NAME},
}
PEM_SERVER = {"command": "npx", "args": ["x@1.0.0"], "env": {"TLS_MATERIAL": PEM_BLOCK}}
LITERAL = {
    "command": "npx",
    "args": ["-y", "fixture-mcp@1.2.3", "--token", VENDOR_TOKEN, f"--password={PASSWORD}"],
    "env": {"API_TOKEN": ENV_SENTINEL, "LOG_LEVEL": "info"},
    "url": "https://example.invalid/mcp",
    "headers": {"Authorization": f"Bearer {SCHEME_SENTINEL}", "X-Trace": "abc"},
}
REFERENCED = {
    "command": "npx",
    "args": ["-y", "fixture-mcp@1.2.3", "--token", "${TOKEN}", "--password=$PASSWORD"],
    "env": {"API_TOKEN": "${API_TOKEN}", "LOG_LEVEL": "info"},
    "url": "https://example.invalid/mcp",
    "headers": {"Authorization": "Bearer ${TOKEN}", "X-Trace": "abc"},
}
DEFAULT_SERVER = {
    "command": "npx",
    "args": ["-y", "fixture-mcp@1.2.3", "--token=${TOKEN:-" + DEFAULT_SENTINEL + "}"],
    "env": {"API_TOKEN": "${TOKEN-" + DEFAULT_SENTINEL + "}", "LOG_LEVEL": "${LOG_LEVEL:-info}"},
}
ALL_SERVERS = {
    "api": LITERAL,
    "default": DEFAULT_SERVER,
    "ref": REFERENCED,
    "srv": REVIEW_BENIGN,
    **REVIEW_SCRIPTS,
    "query": QUERY_SERVER,
    "envflag": ENVFLAG_SERVER,
    "leak": LEAK_SERVER,
    "pem": PEM_SERVER,
}


def _project(root: Path, servers: dict) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return root


def _scan(root: Path, servers: dict):
    _project(root, servers)
    result = MCPScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    return result


def _servers(result) -> dict[str, MCPServerComponent]:
    return {c.name: c for c in result.components if isinstance(c, MCPServerComponent)}


def _findings(server: MCPServerComponent) -> list:
    return [risk for risk in server.risks if risk.category == CATEGORY]


def _dump(result) -> str:
    return json.dumps([c.model_dump(mode="json") for c in result.components])


def test_literal_credentials_raise_one_finding_naming_each_position(tmp_path):
    result = _scan(tmp_path, {"api": LITERAL})
    server = _servers(result)["api"]
    findings = _findings(server)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == RiskSeverity.HIGH
    assert finding.detail == (
        "MCP server 'api' records a literal credential in its launch: "
        "env API_TOKEN (a generic secret-like value); "
        "argument 4 (a vendor token shape); "
        "argument 5 (a generic secret-like value); "
        "header Authorization (an authorization scheme credential)."
    )
    assert "reference" in finding.recommendation and "rotate" in finding.recommendation
    dump = _dump(result)
    assert not any(sentinel in dump for sentinel in SENTINELS)
    assert "LOG_LEVEL" not in finding.detail and "X-Trace" not in finding.detail


def test_references_and_templates_do_not_fire(tmp_path):
    result = _scan(tmp_path, {"api": REFERENCED})
    assert _findings(_servers(result)["api"]) == []


@pytest.mark.parametrize(
    ("value", "fires"),
    [
        ("${TOKEN:-" + DEFAULT_SENTINEL + "}", True),
        ("${TOKEN:=" + DEFAULT_SENTINEL + "}", True),
        ("${TOKEN-" + DEFAULT_SENTINEL + "}", True),
        ("${TOKEN:+" + DEFAULT_SENTINEL + "}", True),
        ("${TOKEN:-changeme}", False),
        ("${TOKEN:-}", False),
        ("${TOKEN:?set TOKEN}", False),
        ("${TOKEN:-${OTHER}}", False),
        ("${TOKEN:-/run/secrets/token}", False),
        ("${TOKEN:-info}", False),
    ],
    ids=[
        "colon-dash",
        "colon-equals",
        "dash",
        "colon-plus",
        "placeholder",
        "empty",
        "message",
        "nested",
        "path",
        "setting",
    ],
)
def test_a_literal_default_inside_a_shell_expansion_is_reported(tmp_path, value, fires):
    server = {
        "command": "npx",
        "args": ["-y", "fixture-mcp@1.2.3", "--token=" + value],
        "env": {"API_TOKEN": value},
    }
    result = _scan(tmp_path, {"api": server})
    findings = _findings(_servers(result)["api"])
    if fires:
        assert len(findings) == 1
        assert "env API_TOKEN (" in findings[0].detail and "argument 3 (" in findings[0].detail
    else:
        assert findings == []
    assert DEFAULT_SENTINEL not in _dump(result)


def test_the_benign_twin_differs_only_by_the_finding(tmp_path):
    literal = _servers(_scan(tmp_path / "literal", {"api": LITERAL}))["api"]
    referenced = _servers(_scan(tmp_path / "referenced", {"api": REFERENCED}))["api"]
    assert sorted(r.category for r in literal.risks if r.category != CATEGORY) == sorted(
        r.category for r in referenced.risks
    )
    assert literal.env == referenced.env


@pytest.mark.parametrize(
    "value",
    [
        "${TOKEN}",
        "$TOKEN",
        "{{ secrets.token }}",
        "Bearer ${TOKEN}",
        "  Basic $TOKEN ",
        "Token {{ vault.read('x') }}",
    ],
)
def test_names_reference_covers_bare_and_scheme_prefixed_forms(value):
    assert names_reference(value)


@pytest.mark.parametrize(
    "value",
    ["$token", "${}", "{{}}", "Bearer " + SCHEME_SENTINEL, "pa$SWORD12x", "x-${TOKEN}", "Bearer"],
)
def test_names_reference_rejects_literals_and_partial_references(value):
    assert not names_reference(value)


def test_a_token_shaped_env_key_is_withheld_from_the_detail(tmp_path):
    result = _scan(
        tmp_path, {"api": {"command": "npx", "args": ["x@1.0.0"], "env": {KEY_TOKEN: "1"}}}
    )
    server = _servers(result)["api"]
    (finding,) = _findings(server)
    assert finding.detail.endswith("in its launch: an env key (a vendor token shape).")
    assert KEY_TOKEN not in _dump(result) and KEY_TOKEN[:8] not in finding.detail


def test_a_token_shaped_header_name_is_withheld_from_the_detail(tmp_path):
    servers = {"api": {"url": "https://example.invalid/mcp", "headers": {KEY_TOKEN: "1"}}}
    result = _scan(tmp_path, servers)
    (finding,) = _findings(_servers(result)["api"])
    assert finding.detail.endswith("in its launch: a header (a vendor token shape).")
    assert KEY_TOKEN not in _dump(result)


@pytest.mark.parametrize(
    "server,expected",
    [
        (
            {
                "command": "sh",
                "args": ["-c", f'API_TOKEN="Bearer {SCHEME_SENTINEL}" exec uvx x==1.0'],
            },
            "argument 2 (an authorization scheme credential)",
        ),
        (
            {
                "command": "docker",
                "args": ["run", "-i", "-e", f"API_KEY={ENV_SENTINEL}", "img@sha256:" + "a" * 64],
            },
            "argument 4 (a generic secret-like value)",
        ),
        (
            {
                "command": "npx",
                "args": ["x@1.0.0"],
                "env": {"DATABASE_URL": "postgres://app:Sup3rSecret99@db.invalid/app"},
            },
            "env DATABASE_URL (a generic secret-like value)",
        ),
        (
            {"command": "npx", "args": ["x@1.0.0"], "env": {"HF_HOME_TOKEN": "hf_" + "C3" * 15}},
            "env HF_HOME_TOKEN (a vendor token shape)",
        ),
        (
            {"url": "https://example.invalid/mcp", "headers": {"X-Api-Key": PASSWORD}},
            "header X-Api-Key (a generic secret-like value)",
        ),
        (
            {"command": "npx", "args": ["x@1.0.0"], "env": {"DB_PASSWORD": f"admin:{PASSWORD}"}},
            "env DB_PASSWORD (a generic secret-like value)",
        ),
        (
            {"command": "npx", "args": ["x@1.0.0"], "env": {"TOKEN": f"Xyz9:{ENV_SENTINEL}"}},
            "env TOKEN (a generic secret-like value)",
        ),
        (
            {"command": "npx", "args": ["x@1.0.0", "--password", f"user:{PASSWORD}"]},
            "argument 3 (a generic secret-like value)",
        ),
        (
            {"command": "sh", "args": ["-c", f"server --token {ENV_SENTINEL} --port 1"]},
            "argument 2 (a generic secret-like value)",
        ),
    ],
)
def test_each_credential_position_is_named_with_its_pattern_class(tmp_path, server, expected):
    result = _scan(tmp_path, {"api": server})
    (finding,) = _findings(_servers(result)["api"])
    assert finding.detail.endswith(f"in its launch: {expected}.")
    assert not any(sentinel in _dump(result) for sentinel in (*SENTINELS, "Sup3rSecret99"))


@pytest.mark.parametrize(
    "server",
    [
        {
            "command": "npx",
            "args": ["x@1.0.0"],
            "env": {"TOKEN_URL": "https://example.invalid/oauth/token"},
        },
        {
            "command": "npx",
            "args": ["x@1.0.0"],
            "env": {"DATABASE_URL": "postgres://app:${DB_PASSWORD}@db.invalid/app"},
        },
        {
            "command": "npx",
            "args": ["x@1.0.0"],
            "env": {"DATABASE_URL": "postgres://postgres:postgres@localhost/app"},
        },
        {"command": "npx", "args": ["x@1.0.0"], "env": {"API_TOKEN": "short"}},
        {"command": "uvx", "args": ["mcp-server-tokens==10.20.30"]},
        {"command": "npx", "args": ["x@1.0.0", "--header", "Authorization: Bearer ${TOKEN}"]},
        {
            "command": "npx",
            "args": ["x@1.0.0"],
            "env": {"OTHER": "$OTHER_TOKEN", "TPL": "{{ secrets.token }}"},
        },
        {"url": "https://example.invalid/mcp", "headers": {"X-Api-Key": "{{ vault.key }}"}},
    ],
)
def test_locators_references_and_short_values_stay_clean(tmp_path, server):
    result = _scan(tmp_path, {"api": server})
    assert _findings(_servers(result)["api"]) == []


@pytest.mark.parametrize(
    "env",
    [
        {"API_TOKEN": 12345678},
        {"API_TOKEN": [ENV_SENTINEL]},
        {"API_TOKEN": {"nested": {"deeper": ENV_SENTINEL}}},
        {"API_TOKEN": None},
    ],
)
def test_non_string_env_values_never_crash_or_leak(tmp_path, env):
    _project(tmp_path, {"api": {"command": "npx", "args": ["x@1.0.0"], "env": env}})
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == [".mcp.json: invalid server configuration"]
    assert _servers(result) == {}
    text = _dump(result) + json.dumps(result.scan_failures) + json.dumps(result.surfaces_excluded)
    assert ENV_SENTINEL not in text
    assert _credential_positions(env, [], [env]) == []


@pytest.mark.parametrize(
    "value,literal",
    [
        ("ab:" * 3000 + "x", True),
        # A run of one character over half the value reads as a placeholder (xxxxxxxx).
        ("ab:" * 900 + "y" * 200_000, False),
        # A value with white space is never one generic literal; it is still scrubbed.
        ("X-A: " * 2000 + PASSWORD, False),
    ],
)
@pytest.mark.parametrize("field", ["env", "args", "headers"])
def test_colon_chains_keep_the_server_inventoried_and_stay_fast(tmp_path, field, value, literal):
    server: dict = {"command": "npx", "args": ["x@1.0.0"]}
    if field == "args":
        server["args"] = ["x@1.0.0", "--token", value]
    else:
        server[field] = {"API_TOKEN": value}
    start = time.monotonic()
    result = _scan(tmp_path, {"api": server})
    assert time.monotonic() - start < 10
    findings = _findings(_servers(result)["api"])
    if literal:
        (finding,) = findings
        assert "(a generic secret-like value)" in finding.detail
    else:
        assert findings == []
    assert PASSWORD not in _dump(result)


@pytest.mark.parametrize(
    "field,value,literal",
    [
        ("env", ENV_SENTINEL, True),
        ("env", f"admin:{PASSWORD}", True),
        ("env", f"Authorization: Bearer {SCHEME_SENTINEL}", True),
        ("env", f"Bearer {SCHEME_SENTINEL}", True),
        ("env", f"https://app:{PASSWORD}@db.invalid/app", True),
        ("env", VENDOR_TOKEN, True),
        ("env", "${API_TOKEN}", False),
        ("env", "Authorization: Bearer ${TOKEN}", False),
        ("env", "postgres://app:${DB_PASSWORD}@db.invalid/app", False),
        ("env", "https://example.invalid/oauth/token", False),
        ("env", "short", False),
        ("headers", f"Bearer {SCHEME_SENTINEL}", True),
        ("headers", PASSWORD, True),
        ("headers", "Bearer ${TOKEN}", False),
        ("headers", "{{ vault.key }}", False),
        ("args", f"--token={ENV_SENTINEL}", True),
        ("args", f"run --password {PASSWORD}", True),
        ("args", f"--password=user:{PASSWORD}", True),
        ("args", "--token=${TOKEN}", False),
        ("args", "run --password $PASSWORD", False),
        ("args", "--port=8080", False),
    ],
)
def test_the_finding_fires_exactly_where_the_scrubber_redacts_a_literal(field, value, literal):
    config: dict = {"command": "npx", "args": ["x@1.0.0"], "env": {}, "headers": {}}
    if field == "args":
        config["args"] = ["x@1.0.0", value]
    else:
        config[field] = {"API_TOKEN": value}
    positions = _credential_positions(config["env"], config["args"], [config["headers"]])
    secrets = _server_secrets(config, _server_launch(config))
    assert bool(positions) is literal
    if positions:
        assert any(secret and secret in value for secret in secrets)


def test_a_header_shadowed_by_http_headers_is_still_reported(tmp_path):
    servers = {
        "api": {
            "url": "https://example.invalid/mcp",
            "headers": {"X-Api-Key": PASSWORD},
            "http_headers": {"X-Api-Key": "${KEY}"},
        }
    }
    result = _scan(tmp_path, servers)
    (finding,) = _findings(_servers(result)["api"])
    assert finding.detail.endswith("in its launch: header X-Api-Key (a generic secret-like value).")
    assert PASSWORD not in _dump(result)


def test_an_oversized_value_fires_without_recording_its_length(tmp_path):
    long_value = "Q7" * 5000
    args = ["x@1.0.0", "--verbose", "--token", long_value]
    result = _scan(
        tmp_path, {"api": {"command": "npx", "args": args, "env": {"API_TOKEN": long_value}}}
    )
    (finding,) = _findings(_servers(result)["api"])
    assert finding.detail.endswith(
        "env API_TOKEN (a generic secret-like value); argument 4 (a generic secret-like value)."
    )
    assert "10000" not in finding.detail and long_value[:16] not in _dump(result)


def test_non_string_arguments_are_a_collection_failure_that_leaks_nothing(tmp_path):
    args = ["x@1.0.0", 42, ["nested", ENV_SENTINEL], None, "--token", VENDOR_TOKEN]
    _project(tmp_path, {"api": {"command": "npx", "args": args}})
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == [".mcp.json: invalid server configuration"]
    assert _servers(result) == {}
    text = _dump(result) + json.dumps(result.scan_failures) + json.dumps(result.surfaces_excluded)
    assert ENV_SENTINEL not in text and VENDOR_TOKEN not in text


def test_sentinels_never_reach_any_cli_artifact(tmp_path):
    project = _project(tmp_path / "project", ALL_SERVERS)
    out = tmp_path / "out"
    out.mkdir()
    runner = CliRunner()
    outputs: dict[str, str] = {}
    for fmt in ("json", "cyclonedx", "spdx", "sarif"):
        path = out / f"scan.{fmt}"
        result = runner.invoke(
            main,
            [
                "scan",
                "--no-project-policy",
                "--report-only",
                "-f",
                fmt,
                "-o",
                str(path),
                str(project),
            ],
        )
        assert result.exit_code == 0, result.output
        outputs[f"scan-{fmt}-stdout"] = result.output
        outputs[f"scan-{fmt}"] = path.read_text(encoding="utf-8")
    inventory = str(out / "scan.json")
    for name, arguments in {
        "risk-text": ["risk", "--no-project-policy", inventory],
        "risk-json": ["risk", "--no-project-policy", "--json-output", inventory],
        "summary": ["summary", inventory],
        "summary-json": ["summary", "--json-output", inventory],
        "crosswalk-markdown": ["crosswalk", "--format", "markdown", inventory],
        "crosswalk-json": ["crosswalk", inventory],
    }.items():
        result = runner.invoke(main, arguments)
        assert result.exit_code in (0, 1), result.output
        outputs[name] = result.output
    vex = out / "findings.vex.json"
    result = runner.invoke(main, ["vex", "-o", str(vex), inventory])
    assert result.exit_code == 0, result.output
    outputs["vex"] = vex.read_text(encoding="utf-8")
    assert CATEGORY in outputs["scan-json"] and CATEGORY in outputs["risk-json"]
    assert "nexus_symbiote/credential_exposure/high" in outputs["scan-sarif"]
    assert "external/cwe/cwe-798" in outputs["scan-sarif"]
    for name, text in outputs.items():
        for sentinel in SENTINELS:
            assert sentinel not in text, name


def test_two_scans_of_a_literal_credential_are_byte_identical(tmp_path):
    project = _project(tmp_path / "project", ALL_SERVERS)
    runner = CliRunner()
    outputs = []
    for name in ("first", "second"):
        path = tmp_path / f"{name}.json"
        result = runner.invoke(
            main, ["scan", "--no-project-policy", "--report-only", "-o", str(path), str(project)]
        )
        assert result.exit_code == 0, result.output
        outputs.append(path.read_bytes())
    assert outputs[0] == outputs[1]
    assert CATEGORY in outputs[0].decode("utf-8")


def _positions(server: dict) -> list[tuple[str, str]]:
    return _credential_positions(
        server.get("env", {}),
        server.get("args", []),
        [server.get("headers", {})],
        endpoints=[server[field] for field in ("url",) if field in server],
    )


def test_the_review_benign_servers_raise_nothing_in_any_export(tmp_path):
    servers = {"srv": REVIEW_BENIGN, **REVIEW_SCRIPTS}
    result = _scan(tmp_path / "scan", servers)
    found = _servers(result)
    assert set(found) == set(servers)
    assert all(_findings(server) == [] for server in found.values())
    project = _project(tmp_path / "project", servers)
    runner = CliRunner()
    for fmt in ("json", "cyclonedx", "spdx", "sarif"):
        path = tmp_path / f"scan.{fmt}"
        arguments = ["scan", "--no-project-policy", "--report-only", "-f", fmt, "-o", str(path)]
        outcome = runner.invoke(main, [*arguments, str(project)])
        assert outcome.exit_code == 0, outcome.output
        assert CATEGORY not in path.read_text(encoding="utf-8"), fmt
    vex = tmp_path / "findings.vex.json"
    outcome = runner.invoke(main, ["vex", "-o", str(vex), str(tmp_path / "scan.json")])
    assert outcome.exit_code == 0, outcome.output
    assert CATEGORY not in vex.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "benign,credential",
    [
        (
            {"env": {"GOOGLE_APPLICATION_CREDENTIALS": "/home/dev/.config/gcloud/sa.json"}},
            {"env": {"GOOGLE_APPLICATION_CREDENTIALS": ENV_SENTINEL}},
        ),
        ({"env": {"PWD": "/workspace/app2"}}, {"env": {"PWD": PASSWORD}}),
        ({"env": {"API_KEY": "C:\\keys\\api.txt"}}, {"env": {"API_KEY": ENV_SENTINEL}}),
        ({"env": {"API_TOKEN": "./secrets/token"}}, {"env": {"API_TOKEN": "s3cr3t-T0ken"}}),
        ({"env": {"SSL_CERT_FILE": ENV_SENTINEL}}, {"env": {"SSL_CERT_PASSWORD": ENV_SENTINEL}}),
        ({"env": {"TOKENIZER": "cl100k_base"}}, {"env": {"TOKENIZER": VENDOR_TOKEN}}),
        ({"env": {"TOKEN": "cl100k_base"}}, {"env": {"TOKEN": "cl100k_b4se_Q9x2"}}),
        ({"env": {"PUBLIC_KEY": ENV_SENTINEL}}, {"env": {"LICENSE_KEY": ENV_SENTINEL}}),
        ({"env": {"GIT_AUTHOR_NAME": ENV_SENTINEL}}, {"env": {"apiKey": ENV_SENTINEL}}),
        ({"env": {"API_TOKEN": "3600000000"}}, {"env": {"API_TOKEN": "3600abcd0000"}}),
        ({"env": {"API_TOKEN_TTL": "3600abcd0000"}}, {"env": {"API_TOKEN": "3600abcd0000"}}),
        ({"env": {"DB_PASSWORD": "30000ms"}}, {"env": {"DB_PASSWORD": "30000ms-x9"}}),
        ({"env": {"SMTP_PASSWORD": "ops@example.com"}}, {"env": {"SMTP_PASSWORD": PASSWORD}}),
        (
            {"env": {"DB_DSN": "db.internal:5432"}},
            {"env": {"DB_DSN": "postgres://app:Sup3rSecret99@db.internal:5432/app"}},
        ),
        (
            {"env": {"DB_DSN": "db.internal.example.com"}},
            {"env": {"DB_DSN": "db.internal.corp:5432:" + PASSWORD}},
        ),
        (
            {"env": {"API_TOKEN": "https://auth.example.com/token"}},
            {"env": {"API_TOKEN": f"https://auth.example.com/token?token={ENV_SENTINEL}"}},
        ),
        (
            {"args": ["x@1.0.0", "--description", "Basic calculator tools"]},
            {"args": ["x@1.0.0", "--description", f"Bearer {SCHEME_SENTINEL}"]},
        ),
        (
            {"headers": {"X-Title": "Token usage dashboard"}},
            {"headers": {"X-Title": f"Token {SCHEME_SENTINEL}"}},
        ),
        (
            {"headers": {"X-Title": "Basic notebooks"}},
            {"headers": {"Authorization": "Basic notebooks"}},
        ),
        (
            {"args": ["x@1.0.0", "--note", "Authentication: handled by the gateway"]},
            {"args": ["x@1.0.0", "--note", f"Authorization: Bearer {SCHEME_SENTINEL}"]},
        ),
        (
            {"args": ["x@1.0.0", "--note", f"X-Trace: {ENV_SENTINEL}"]},
            {"args": ["x@1.0.0", "--header", f"X-Trace: Bearer {SCHEME_SENTINEL}"]},
        ),
        (
            {"args": ["-c", 'API_TOKEN="${API_TOKEN}" exec npx -y x@1.0.0']},
            {"args": ["-c", f'API_TOKEN="{SCRIPT_SENTINEL}" exec npx -y x@1.0.0']},
        ),
        (
            {"args": ["-c", "GITHUB_TOKEN=$(gh auth token) exec npx -y x@1.0.0"]},
            {"args": ["-c", f"GITHUB_TOKEN={SCRIPT_SENTINEL} exec npx -y x@1.0.0"]},
        ),
        (
            {"args": ["-c", "API_TOKEN=`gh auth token` exec npx -y x@1.0.0"]},
            {"args": ["-c", f"export API_TOKEN={SCRIPT_SENTINEL}; exec npx -y x@1.0.0"]},
        ),
        (
            {"args": ["x@1.0.0", "--token", "two words here"]},
            {"args": ["x@1.0.0", "--token", SCRIPT_SENTINEL]},
        ),
        (
            {"args": ["x@1.0.0", "a=1,token=${TOKEN}"]},
            {"args": ["x@1.0.0", "a=1,token=" + SCRIPT_SENTINEL]},
        ),
    ],
)
def test_each_benign_rule_has_a_credential_twin_that_still_fires(benign, credential):
    base: dict = {"command": "npx", "args": ["x@1.0.0"]}
    assert _positions({**base, **benign}) == []
    assert _positions({**base, **credential})


@pytest.mark.parametrize(
    "args,expected",
    [
        (["run", f"--env=API_TOKEN={ENVFLAG_SENTINEL}", "img"], "argument 2"),
        (["run", "-e", f"API_TOKEN={ENVFLAG_SENTINEL}", "img"], "argument 3"),
        (["build", "--build-arg", f"NPM_TOKEN={ENVFLAG_SENTINEL}", "."], "argument 3"),
        (["build", f"--build-arg=NPM_TOKEN={ENVFLAG_SENTINEL}", "."], "argument 2"),
    ],
)
def test_an_assignment_after_an_env_flag_fires(args, expected):
    assert _positions({"command": "docker", "args": args}) == [(expected, NAMED)]


def test_env_flag_assignment_of_a_reference_or_path_does_not_fire():
    args = ["run", "--env=API_TOKEN=${API_TOKEN}", "--env=CA_CERT_FILE=/etc/ca.pem", "img"]
    assert _positions({"command": "docker", "args": args}) == []


def test_a_credential_in_an_endpoint_url_query_fires_at_its_own_position(tmp_path):
    shaped = {"type": "http", "url": f"https://mcp.example.com/mcp?access_token={VENDOR_TOKEN}"}
    referenced = {"type": "sse", "url": "https://mcp.example.com/sse?api_key=${API_KEY}"}
    plain = {"type": "sse", "url": f"https://mcp.example.com/sse?page={QUERY_SENTINEL}"}
    servers = {"query": QUERY_SERVER, "shaped": shaped, "referenced": referenced, "plain": plain}
    found = _servers(_scan(tmp_path, servers))
    (finding,) = _findings(found["query"])
    assert finding.detail.endswith(
        "in its launch: endpoint URL query (a generic secret-like value)."
    )
    (finding,) = _findings(found["shaped"])
    assert finding.detail.endswith("in its launch: endpoint URL query (a vendor token shape).")
    assert _findings(found["referenced"]) == [] and _findings(found["plain"]) == []
    assert QUERY_SENTINEL not in json.dumps([c.model_dump(mode="json") for c in found.values()])


def test_user_information_in_an_endpoint_stays_with_transport_security(tmp_path):
    servers = {"userinfo": {"type": "sse", "url": f"https://app:{PASSWORD}@mcp.example.com/sse"}}
    result = _scan(tmp_path, servers)
    server = _servers(result)["userinfo"]
    assert _findings(server) == []
    assert any(
        risk.category == "transport_security" and "embeds credentials" in risk.detail
        for risk in server.risks
    )
    assert PASSWORD not in _dump(result)


def test_a_name_that_repeats_a_secret_value_is_withheld(tmp_path):
    result = _scan(tmp_path, {"leak": LEAK_SERVER})
    (finding,) = _findings(_servers(result)["leak"])
    assert finding.detail.endswith(
        "in its launch: env DB_PASSWORD (a generic secret-like value); "
        "an env key (a generic secret-like value)."
    )
    assert LEAK_NAME not in _dump(result) and LEAK_VALUE not in _dump(result)


@pytest.mark.parametrize(
    "server,expected",
    [
        (PEM_SERVER, "env TLS_MATERIAL (a generic secret-like value)"),
        (
            {"command": "npx", "args": ["x@1.0.0", "--material", PEM_BLOCK]},
            "argument 3 (a generic secret-like value)",
        ),
        (
            {"command": "npx", "args": ["x@1.0.0"], "env": {"CA": PEM_BLOCK[:40]}},
            "env CA (a generic secret-like value)",
        ),
    ],
)
def test_a_private_key_block_fires_under_any_name(tmp_path, server, expected):
    result = _scan(tmp_path, {"pem": server})
    (finding,) = _findings(_servers(result)["pem"])
    assert finding.detail.endswith(f"in its launch: {expected}.")
    assert PEM_SENTINEL not in _dump(result)


def test_a_certificate_block_is_not_a_private_key():
    certificate = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----"
    assert _positions({"command": "npx", "env": {"CA_BUNDLE": certificate}}) == []


def test_the_detail_lists_twelve_positions_and_counts_the_rest(tmp_path):
    server = {
        "command": "npx",
        "args": ["x@1.0.0", *(f"--token={ENV_SENTINEL}{index:04d}" for index in range(749))],
        "env": {f"API_TOKEN_{index:04d}": f"{SCHEME_SENTINEL}{index:04d}" for index in range(250)},
    }
    assert len(_positions(server)) == MAX_CREDENTIAL_POSITIONS
    start = time.monotonic()
    result = _scan(tmp_path, {"api": server})
    assert time.monotonic() - start < 1
    (finding,) = _findings(_servers(result)["api"])
    listed = MAX_CREDENTIAL_POSITIONS - LISTED_CREDENTIAL_POSITIONS
    assert finding.detail.endswith(
        f"env API_TOKEN_0011 (a generic secret-like value); and at least {listed} more positions."
    )
    assert finding.detail.count("(a generic secret-like value)") == LISTED_CREDENTIAL_POSITIONS
    assert len(finding.detail) < 1000
    assert ENV_SENTINEL not in _dump(result) and SCHEME_SENTINEL not in _dump(result)


def test_thirteen_positions_count_one_more_position(tmp_path):
    env = {f"API_TOKEN_{index:02d}": f"{ENV_SENTINEL}{index:02d}" for index in range(13)}
    result = _scan(tmp_path, {"api": {"command": "npx", "args": ["x@1.0.0"], "env": env}})
    (finding,) = _findings(_servers(result)["api"])
    assert finding.detail.endswith("(a generic secret-like value); and 1 more position.")


def test_the_review_literal_server_still_raises_its_three_positions(tmp_path):
    real = {
        "command": "npx",
        "args": ["-y", "x@1.0.0"],
        "env": {"API_TOKEN": ENV_SENTINEL, "DB_PASSWORD": PASSWORD},
        "headers": {"Authorization": f"Bearer {SCHEME_SENTINEL}"},
    }
    result = _scan(tmp_path, {"real": real})
    (finding,) = _findings(_servers(result)["real"])
    assert finding.detail == (
        "MCP server 'real' records a literal credential in its launch: "
        "env API_TOKEN (a generic secret-like value); "
        "env DB_PASSWORD (a generic secret-like value); "
        "header Authorization (an authorization scheme credential)."
    )
    assert not any(sentinel in _dump(result) for sentinel in SENTINELS)


@pytest.mark.parametrize(
    "value",
    [
        "%API_TOKEN%",
        "%APITOKEN%",
        "$env:API_TOKEN",
        "${{ secrets.API_TOKEN }}",
        "<your-api-key>",
        "YOUR_API_KEY_HERE",
        "changeme",
    ],
)
def test_placeholders_and_foreign_references_follow_the_value_rules(value):
    assert _positions({"command": "npx", "env": {"API_TOKEN": value}}) == []


# A random value that the scrubber's name rule does not select under SIG: only the
# finding's classifier reads it as a credential.
CLASSIFIER_ONLY = "Zq8vLm2pXr7tKw4n"  # noqa: S105 - synthetic sentinel
RANDOM = "eb0PtJYwJyiQMPj68c7HBAi01TWElQxv"  # noqa: S105 - synthetic sentinel


@pytest.mark.parametrize(
    "name",
    [
        "PGPASSWORD",
        "SMTP_PASS",
        "DB_PASS",
        "DB_PASS_RO",
        "ACCESSTOKEN",
        "AUTHTOKEN",
        "CLIENTSECRET",
        "SECRETKEY",
        "PRIVATEKEY",
        "KEY",
        "API_KEY",
        "SSH_KEY",
        "LICENSE_KEY",
        "ENCRYPTION_KEY",
        "CONNECTION_STRING",
        "REFRESH_TOKEN",
        "X-Api-Key",
        "apiKey",
        "TOKEN2",
        "Secret2",
    ],
)
def test_credential_names_by_their_words_fire(name):
    assert _positions({"command": "npx", "env": {name: RANDOM}}) == [(f"env {name}", NAMED)]
    assert _positions({"command": "npx", "env": {name: "${VALUE}"}}) == []


@pytest.mark.parametrize(
    "name",
    [
        "PASSTHROUGH_MODE",
        "PASSIVE",
        "PASSPORT_ID",
        "TOKENIZER",
        "PASSWORDLESS",
        "SECRETARY",
        "KEYBOARD_LAYOUT",
        "KEY_ID",
        "API_KEY_ID",
        "API_KEY_NAME",
        "SECRET_NAME",
        "COOKIE_NAME",
        "JWT_AUDIENCE",
        "AUTH_PROVIDER",
        "AUTH_STRATEGY",
        "TOKEN_ENDPOINT_AUTH_METHOD",
        "SECRET_BACKEND",
        "SIGNATURE_ALGORITHM",
        "SSH_KEY_FINGERPRINT",
        "PAT_SCOPE",
        "PASSWORD_POLICY",
        "BEARER_TOKEN_ENV_VAR",
        "TOKEN_PATH",
        "SECRET_DIR",
        "CACHE_KEY",
        "SORT_KEY",
        "PARTITION_KEY",
        "IDEMPOTENCY_KEY",
        "STRIPE_PUBLISHABLE_KEY",
        "JWT_VERIFY_KEY",
    ],
)
def test_names_that_describe_or_index_do_not_name_a_credential(name):
    assert _positions({"command": "npx", "env": {name: RANDOM}}) == []


@pytest.mark.parametrize(
    "benign,credential",
    [
        (["--title", RANDOM], ["--key", RANDOM]),
        (["--passthrough", RANDOM], ["--pass", RANDOM]),
        (["-t", RANDOM], ["-k", RANDOM]),
        (["--token-env", "GITHUB_TOKEN_2"], ["--token", RANDOM]),
        (["--api-key-env", RANDOM], ["--api-key", RANDOM]),
    ],
)
def test_flag_names_follow_the_name_rules(benign, credential):
    assert _positions({"command": "npx", "args": ["x@1.0.0", *benign]}) == []
    assert _positions({"command": "npx", "args": ["x@1.0.0", *credential]})


@pytest.mark.parametrize(
    "name,value",
    [
        ("API_TOKEN", "hunter2hunter"),
        ("API_TOKEN", "kT9#vQ2!mZ7@wL4&"),
        ("API_TOKEN", "s3cr3tPw9!"),
        ("API_TOKEN", "4a472c89-f239-45be-9f67-cfdeb3c7e0f4"),
        ("API_TOKEN", "synthetic-launch-password-98765"),
        ("API_TOKEN", "S3cret.V4lue#9"),
        ("API_TOKEN", ENV_SENTINEL),
        ("DB_PASSWORD", "correct-horse-battery-staple"),
        ("DB_PASSWORD", "Zürich-Geheimnis-48-äöü"),
        ("ADMIN_PASSWORD", "$ecretPa55w0rd-Kx9"),
        ("AWS_SECRET_ACCESS_KEY", "/O9JSGiOfJUVSJYUEGcOT9nWIaokDJ9thOOJ5SAux"),
        ("AUTH_TOKEN", RANDOM + "\n"),
        ("TOTP_SECRET", "DOXSATMJWAW455UM"),
        # Base64 holds "/": a random segment is not a directory or a port's path.
        ("API_TOKEN", "aGqy4Hp4ozCBKeri7sNkZFqbIH4qNooG0UP6/myix"),
        ("API_TOKEN", "5/mgFBr7lioC8v1ydijSZhEYqIwfdyBHWXEl4g0jx"),
        ("API_TOKEN", "/g5wJ/64ojaMe8Tk6Xe89v9UaDs77mPyv1XXjMvsx"),
        # A short word between a random token's letters and digits is not a placeholder.
        ("API_TOKEN", "Q9x7dev3Kp2mY8vL"),
    ],
)
def test_password_and_token_shapes_stay_literals(name, value):
    assert _positions({"command": "npx", "env": {name: value}}) == [(f"env {name}", NAMED)]


@pytest.mark.parametrize(
    "benign,credential",
    [
        # References, also in other syntaxes, partial ones and code reads.
        ("x-${TOKEN}", "x-" + RANDOM),
        ("$api_token_2", "$ecretPa55w0rd-Kx9"),
        ("$API_TOKEN_2", "$up3rsecret99"),
        ("Bearer " + RANDOM + "$SUFFIX", "Bearer " + RANDOM + "$"),
        ("process.env.API_TOKEN", RANDOM),
        ("os.getenv('API_TOKEN')", RANDOM),
        ("GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN_2024"),
        ("vault:secret/data/app#password", RANDOM),
        ("arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf", RANDOM),
        ("op://Private/GitHub/token", RANDOM),
        ("projects/p/secrets/s/versions/1", RANDOM),
        ("fastmcp.server.auth.providers.github.GitHubProvider", RANDOM),
        # Paths and file names.
        ("keys/id_ed25519", "ab12/cd34ef"),
        ("certs/sa.json", RANDOM),
        ("id_ed25519", RANDOM),
        ("/run/secrets/token", "/O9JSGiOfJUVSJYUEGcOT9nWIaokDJ9thOOJ5SAux"),
        # Numbers, versions, images and locators.
        ("3.12.7-slim", RANDOM),
        ("docker://python:3.12.7-slim@sha256:" + "3a7c" * 16, RANDOM),
        ("vault-token-helper:0.9.12-alpine", RANDOM),
        ("auth-service:8443/api/v2", "auth-service:" + RANDOM),
        ("db.internal.corp", "db.internal.corp:5432:" + PASSWORD),
        # Placeholders.
        ("<your-api-key>", RANDOM),
        ("[api-token-1]", RANDOM),
        ("token-1...token-2", RANDOM),
        ("xxxxxxxxxxxxxxxx", RANDOM),
        ("abcdef0123456789", "42c848d5f7be8abcdef7a31c2ec5de1b"),
        ("not-needed", RANDOM),
        ("PasteTokenFromSettings", RANDOM),
        ("TODO-JIRA-4521", RANDOM),
        ("sk-your-openai-api-key-here", "sk-" + RANDOM),
        ("ghp_" + "x" * 36, VENDOR_TOKEN),
        ("AKIAIOSFODNN7EXAMPLE", VENDOR_TOKEN),
        # Word phrases and short settings under a name that is not a password's.
        ("oauth2-client-secret", "oauth2-client-secret-98765"),
        ("hmac-sha256-secret", "hmac-sha256-" + RANDOM),
        ("k8s-webhook-secret", "k8s-webhook-" + RANDOM),
        ("cl100k_base", "cl100k_base_Q9x2"),
        ("Votre-Cle-API-Ici-SVP", RANDOM),
        ("ваш-ключ-api", RANDOM),
        ("请填写1个有效的密钥", RANDOM),
        ("MixedCaseLettersValue", "MixedCaseLettersValue2024x"),
        ("mcp-gateway.internal", "mcp-gateway:" + RANDOM),
        ("mcp-gateway.internal:8443", "mcp-gateway:8443:" + RANDOM),
        ("@Microsoft.KeyVault(VaultName=v;SecretName=s)", RANDOM),
        ("os.environ/OPENAI_API_KEY", RANDOM),
    ],
)
def test_each_value_rule_has_a_credential_twin_under_the_same_name(benign, credential):
    assert _positions({"command": "npx", "env": {"API_TOKEN": benign}}) == []
    assert _positions({"command": "npx", "env": {"API_TOKEN": credential}})


@pytest.mark.parametrize(
    "benign,credential",
    [
        ("Provided by Vault Agent", "purple monkey dishwasher lamp"),
        ("Generate an app password in account settings", "correct horse hunter2hunter"),
    ],
)
def test_a_lower_case_passphrase_counts_only_under_a_passphrase_name(benign, credential):
    assert _positions({"command": "npx", "env": {"SSH_PASSPHRASE": benign}}) == []
    assert _positions({"command": "npx", "env": {"SSH_PASSPHRASE": credential}})
    assert _positions({"command": "npx", "env": {"API_TOKEN": credential}}) == []
    args = ["x@1.0.0", "--passphrase", credential]
    assert _positions({"command": "npx", "args": args}) == [("argument 3", NAMED)]


@pytest.mark.parametrize("name", ["DB_PASSWORD", "DB_PASS"])
def test_word_phrases_stay_literals_under_password_names(name):
    value = "launch-password-hunter"
    assert _positions({"command": "npx", "env": {name: value}}) == [(f"env {name}", NAMED)]
    assert _positions({"command": "npx", "env": {"API_TOKEN": value}}) == []


@pytest.mark.parametrize(
    "value",
    [
        f"Server=db;User Id=sa;Password={RANDOM};",
        f"jdbc:sqlserver://db.test:1433;user=sa;password={RANDOM}",
        f"DefaultEndpointsProtocol=https;AccountName=acme;AccountKey={RANDOM}+vQ/lWAW==",
        f"Server=tcp:db.test,1433;Initial Catalog=app;User ID=svc;Password={RANDOM};",
    ],
)
def test_a_connection_string_credential_pair_fires_under_any_name(value):
    assert _positions({"command": "npx", "env": {"STORAGE": value}}) == [("env STORAGE", NAMED)]
    benign = value.replace(RANDOM, "${DB_PASSWORD}")
    assert _positions({"command": "npx", "env": {"STORAGE": benign}}) == []


@pytest.mark.parametrize(
    "header,benign,credential",
    [
        ("Cookie", "theme=dark; lang=en-GB", f"sid={RANDOM}; theme=dark"),
        ("Cookie", "sid=${SESSION}", f"a=1; sid={RANDOM}; csrftoken={RANDOM}"),
        ("Authorization", "Bearer Personal Access Token", 'Digest username="u", response="x9Q"'),
        ("Authorization", "postgres", "hunter2hunter"),
        ("Authorization", "Bearer 请在此处填写密钥令牌", "Bearer " + RANDOM),
        ("Authorization", "Bearer test-token-1", "Bearer svc:hunter2hunter"),
        ("Authorization", "Bearer TOKEN_GOES_HERE", f"Bearer v2|{RANDOM}"),
        ("Authorization", "Basic base64(username:password)", "Basic dXNlcjpwYXNzd29yZA=="),
        ("Proxy-Authorization", "Bearer abc123", "Bearer opensesamex"),
        ("X-Custom", "Bearer opensesamex", f"Bearer {RANDOM}$"),
        ("X-Custom", "Bearer realm=api1.example.com", f"Bearer {RANDOM}%"),
    ],
)
def test_header_values_follow_the_cookie_and_authorization_rules(header, benign, credential):
    server = {"url": "https://example.invalid/mcp"}
    assert _positions({**server, "headers": {header: benign}}) == []
    assert _positions({**server, "headers": {header: credential}})


@pytest.mark.parametrize(
    "benign,credential",
    [
        (
            ["-c", 'API_TOKEN = "${API_TOKEN}" npx -y x@1.0.0'],
            ["-c", f"API_TOKEN = {RANDOM} npx -y x@1.0.0"],
        ),
        (["--opts", "retries=3,token=${TOKEN}"], ["--opts", f"retries=3,token={RANDOM},x=5"]),
        (["--opt", "/title:" + RANDOM], ["--opt", "/token:" + RANDOM]),
        (
            ["--oauth", '{"clientId": "mcp-reader", "clientSecret": "${SECRET}"}'],
            ["--oauth", f'{{"clientId": "mcp-reader", "clientSecret": "{RANDOM}"}}'],
        ),
        (
            ["--headers", '{"Authorization": "Bearer ${TOKEN}"}'],
            ["--headers", f'{{"Authorization": "Bearer {RANDOM}"}}'],
        ),
        (["--headers", '{"X-Trace": "abc"}'], ["--headers", f'{{"X-Api-Key": "{RANDOM}"}}']),
        (
            ["--config", '{"keys": [{"api_key": "${KEY}"}]}'],
            ["--config", f'{{"keys": [{{"api_key": "{RANDOM}"}}]}}'],
        ),
        (
            ["-c", "curl -u admin:${PASSWORD} https://x.test/"],
            ["-c", f"curl -u admin:{RANDOM} https://x.test/"],
        ),
        (["--secret", "id=npm2,src=.npmrc"], ["--secret", RANDOM]),
        (["--secret=mcp-api-key-v2"], [f"--secret={RANDOM}"]),
        (["--secret", "prod/mcp/api-key-2"], ["--secret", "+" + RANDOM]),
        (["--secret-id", "prod/mcp/api-key-2"], ["--secret-key", RANDOM]),
        (
            ["--note", f"X-Trace: Bearer {SCHEME_SENTINEL}"],
            [f"-HX-Trace: Bearer {SCHEME_SENTINEL}"],
        ),
        (
            [f"--note=X-Trace: Bearer {SCHEME_SENTINEL}"],
            [f"--header=X-Trace: Bearer {SCHEME_SENTINEL}"],
        ),
        (
            ["/c", "set API_TOKEN=Bearer ${TOKEN}&& npx x@1.0.0"],
            ["/c", f"set API_TOKEN=Bearer {SCHEME_SENTINEL}&& npx x@1.0.0"],
        ),
    ],
)
def test_argument_forms_have_credential_twins(benign, credential):
    assert _positions({"command": "npx", "args": ["x@1.0.0", *benign]}) == []
    assert _positions({"command": "npx", "args": ["x@1.0.0", *credential]})


@pytest.mark.parametrize(
    "benign,credential",
    [
        (
            "https://x.test/mcp?page_token=abc123def456",
            f"https://x.test/mcp?access_token={RANDOM}",
        ),
        ("https://x.test/mcp?token=<your-token>", f"https://x.test/mcp?token={RANDOM}"),
        ("https://x.test/mcp?state=" + RANDOM, f"https://x.test/mcp?x=1;api_key={RANDOM}"),
        ("https://x.test/mcp?api_key=not-needed", f"https://x.test/mcp?apiKey={RANDOM}"),
    ],
)
def test_endpoint_url_query_values_follow_the_value_rules(benign, credential):
    assert _positions({"type": "http", "url": benign}) == []
    assert _positions({"type": "http", "url": credential}) == [("endpoint URL query", NAMED)]


@pytest.mark.parametrize(
    "benign,credential",
    [
        (
            "PuTTY-User-Key-File-3: ssh-ed25519\nPublic-Lines: 2\nAAAA",
            "PuTTY-User-Key-File-3: ssh-ed25519\nPrivate-Lines: 1\n" + RANDOM,
        ),
        (
            "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
            PEM_BLOCK,
        ),
        (
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
            "eyJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIsICJwcml2YXRlX2tleSI6ICJ4In0=",
        ),
        ("pk_live_51HqZq8vLm2pXr7tKw4nBv6y", VENDOR_TOKEN),
    ],
)
def test_private_and_public_key_material_under_any_name(benign, credential):
    assert _positions({"command": "npx", "env": {"MATERIAL": benign}}) == []
    assert _positions({"command": "npx", "env": {"MATERIAL": credential}})


def test_names_that_repeat_a_value_only_the_finding_reads_are_withheld(tmp_path):
    servers = {
        "signed": {
            "url": "https://example.invalid/mcp",
            "env": {"SIG": CLASSIFIER_ONLY},
            "headers": {CLASSIFIER_ONLY: "1", "X-Trace": "abc"},
        },
        "sibling": {"command": "npx", "args": ["x@1.0.0"], "env": {CLASSIFIER_ONLY: "1"}},
    }
    result = _scan(tmp_path, servers)
    found = _servers(result)
    (finding,) = _findings(found["signed"])
    assert finding.detail.endswith("in its launch: env SIG (a generic secret-like value).")
    signed = found["signed"].model_dump(mode="json")
    sibling = found["sibling"].model_dump(mode="json")
    assert signed["properties"]["header_names"] == ["X-Trace", "[redacted]"]
    assert list(sibling["env"]) == ["[redacted-1]"]
    assert CLASSIFIER_ONLY not in _dump(result)


def test_a_header_name_that_repeats_a_value_is_withheld_from_the_finding(tmp_path):
    servers = {
        "api": {
            "url": "https://example.invalid/mcp",
            "headers": {"X-Sig": CLASSIFIER_ONLY, CLASSIFIER_ONLY: f"Bearer {SCHEME_SENTINEL}"},
        }
    }
    result = _scan(tmp_path, servers)
    (finding,) = _findings(_servers(result)["api"])
    assert finding.detail.endswith(
        "in its launch: header X-Sig (a generic secret-like value); "
        "a header (an authorization scheme credential)."
    )
    assert CLASSIFIER_ONLY not in _dump(result)


@pytest.mark.parametrize(
    "name,benign,credential",
    [
        # A path's own signals stand even when one segment mixes cases and digits.
        ("GOOGLE_SA_KEY", "Keys/ServiceAccount2024.json", "Keys/" + RANDOM),
        ("SSH_PRIVATE_KEY", "C:\\Users\\JohnSmith\\Keys\\GoogleSA2024Prod.pem", RANDOM),
        ("TLS_KEY", "./Secrets/MyToken2024File.key", RANDOM),
        ("TLS_KEY", "/etc/ssl/private/Server2024Key.pem", "/" + RANDOM),
        ("SSH_KEY", "~/.ssh/GitHubDeploy2024Key", RANDOM),
        ("API_KEY", "Keys\\Prod2024Service.json", "Keys\\" + RANDOM),
        # Under a password name a path, an e-mail, a package or a host is still none.
        ("DB_PASSWORD", "~/.secrets/dbpassword", RANDOM),
        ("DB_PASSWORD", "C:\\keys\\dbpassword", "C:" + RANDOM),
        ("DB_PASSWORD", "\\\\server\\share\\dbpassword", RANDOM),
        ("DB_PASSWORD", "db_password_2024.txt", "db_password_2024" + RANDOM),
        ("SMTP_PASSWORD", "alerts@acme-corp.io", "alerts@" + RANDOM),
        ("DB_PASSWORD", "some-mcp@1.0.0", "some-mcp@" + RANDOM),
        ("DB_PASSWORD", "requests>=2.31", "requests" + RANDOM),
        ("DB_PASSWORD", "db-prod2.acme-corp.io:5432", "p4ssw0rd.secure"),
        ("DB_PASSWORD", "5432/postgres2", "kx9vq2.zrtpwm"),
        ("TOKEN_SERVER_IMAGE", "acme/token-server:main", "acme/token-server:" + RANDOM),
    ],
)
def test_paths_and_locators_have_twins_under_credential_names(name, benign, credential):
    assert _positions({"command": "npx", "env": {name: benign}}) == []
    assert _positions({"command": "npx", "env": {name: credential}}) == [(f"env {name}", NAMED)]


def test_a_kustomize_directory_after_k_is_a_path():
    args = ["apply", "-k", "overlays/prod-Cluster2024A"]
    assert _positions({"command": "kubectl", "args": args}) == []
    args = ["apply", "-k", "aGqy4Hp4ozCBKeri7sNkZFqbIH4qNooG0UP6/myix"]
    assert _positions({"command": "kubectl", "args": args}) == [("argument 3", NAMED)]


@pytest.mark.parametrize(
    "value", ["Correct Horse Battery Staple 9", "Tr0ub4dor & 3 Horses!", "purple Monkey dishwasher"]
)
def test_a_passphrase_counts_in_any_case_and_punctuation(value):
    assert _positions({"command": "npx", "env": {"DB_PASSWORD": value}}) == [
        ("env DB_PASSWORD", NAMED)
    ]
    args = ["x@1.0.0", "--password", value]
    assert _positions({"command": "npx", "args": args}) == [("argument 3", NAMED)]
    script = ["-c", f"PGPASSWORD='{value}' psql -h db -U app"]
    assert _positions({"command": "sh", "args": script}) == [("argument 2", NAMED)]
    assert _positions({"command": "npx", "env": {"DB_PASSWORD": "Set in the Vault UI"}}) == []


@pytest.mark.parametrize(
    "benign,credential",
    [
        ("{api_token}", "a{b}cDe9!xYz"),
        ("{{ secrets.API_TOKEN }}", "Pa$$w0rd{2024}"),
        ("#{api.token}", "hunter2{x}Kq9"),
        ("x-$API_TOKEN", "hunter2hunter$X"),
    ],
)
def test_braces_and_dollars_are_references_only_around_a_name(benign, credential):
    assert _positions({"command": "npx", "env": {"DB_PASSWORD": benign}}) == []
    assert _positions({"command": "npx", "env": {"DB_PASSWORD": credential}})


def test_an_odbc_password_in_braces_is_read_without_them():
    dsn = "Driver={ODBC Driver 18 for SQL Server};Server=db;Uid=sa;Pwd={%s};"
    assert _positions({"command": "npx", "env": {"ODBC_DSN": dsn % "Qx7!vR2#mL9pZ"}}) == [
        ("env ODBC_DSN", NAMED)
    ]
    assert _positions({"command": "npx", "env": {"ODBC_DSN": dsn % "${DB_PASSWORD}"}}) == []


@pytest.mark.parametrize(
    "benign,credential",
    [
        (
            'export API_KEY="${API_KEY:?set API_KEY}" && exec node s.js',
            f'export API_KEY="{RANDOM}" && exec node s.js',
        ),
        (
            'API_KEY="${API_KEY:-not set yet}" exec node s.js',
            f'API_KEY="{RANDOM}" exec node s.js',
        ),
        (
            'node -e "const apiKey = fs.readFileSync(keyPath).toString(); start(apiKey)"',
            f'node -e "const apiKey = {RANDOM}; start(apiKey)"',
        ),
        (
            'python -c \'import keyring; token = keyring.get_password("mcp", "me"); main(token)\'',
            f"python -c 'import keyring; token = {RANDOM}; main(token)'",
        ),
    ],
)
def test_script_references_and_code_reads_have_literal_twins(benign, credential):
    assert _positions({"command": "sh", "args": ["-c", benign]}) == []
    assert _positions({"command": "sh", "args": ["-c", credential]}) == [("argument 2", NAMED)]


def test_a_chained_code_read_in_an_env_value_is_a_reference():
    value = "require('fs').readFileSync('/run/secrets/api_key','utf8').trim()"
    assert _positions({"command": "npx", "env": {"API_KEY": value}}) == []


@pytest.mark.parametrize(
    "name,benign,credential",
    [
        ("GITHUB_TOKEN", "ghp_YourGitHubTokenGoesHere1234567890ab", VENDOR_TOKEN),
        ("API_TOKEN", "YourApiKeyHere123", "Kx9TestQ2vL7pZr4Tn8Wb"),
        ("DB_PASSWORD", "MyDevPassword9", "Mv9Pass2024Qx7"),
        ("AUTH_SCHEME", "OAuthClientCredentials", "OAuthClient" + RANDOM),
        ("TOKEN_LIFETIME", "P1DT12H30M", "P1DT12H30M" + RANDOM),
        ("JWT_ALGORITHMS", "RS256,ES256", "RS256," + RANDOM),
        ("TOKEN_GRANT", "urn:ietf:params:oauth:grant-type:token-exchange", "urn" + RANDOM),
        ("SECRET_ROTATION", "rotate-every-90d", "rotate-every-" + RANDOM),
        ("AUTH_FLOW", "oauth2:client_credentials", "oauth2:" + RANDOM),
    ],
)
def test_camel_placeholders_and_settings_have_twins(name, benign, credential):
    assert _positions({"command": "npx", "env": {name: benign}}) == []
    assert _positions({"command": "npx", "env": {name: credential}})


@pytest.mark.parametrize(
    "benign,credential",
    [
        ("PASSWORD_HASHER", "DB_PASSWORD"),
        ("PASS_THROUGH_HEADERS", "PASS"),
        ("COMPILER_PASS", "SMTP_PASS"),
        ("FIRST_PASS", "DB_PASS_RO"),
        ("passwordField", "passwordValue"),
    ],
)
def test_a_pass_that_is_a_stage_or_a_field_is_not_a_password(benign, credential):
    value = "dead-code-elimination-" + RANDOM
    assert _positions({"command": "npx", "env": {benign: value}}) == []
    assert _positions({"command": "npx", "env": {credential: value}}) == [
        (f"env {credential}", NAMED)
    ]
    args = ["x@1.0.0", "--first-pass", "analysis2024"]
    assert _positions({"command": "npx", "args": args}) == []
    config = '{"passwordField": "user_password_hash"}'
    assert _positions({"command": "npx", "args": ["x@1.0.0", "--config", config]}) == []


@pytest.mark.parametrize(
    "benign,credential",
    [
        (
            "host=db port=5432 user=app password=${PGPASSWORD} dbname=app",
            "host=db port=5432 user=app password=Vq8mT3xL2pK dbname=app",
        ),
        ("host=db password=Vq8mT3xL2pK", "user=app password=Vq8mT3xL2pK dbname=app"),
    ],
)
def test_a_libpq_keyword_string_is_read_pair_by_pair(benign, credential):
    assert _positions({"command": "npx", "env": {"LIBPQ": benign}}) == []
    assert _positions({"command": "npx", "env": {"LIBPQ": credential}}) == [("env LIBPQ", NAMED)]


def test_a_user_flag_in_a_cluster_of_short_flags_is_read():
    script = "curl -su admin:Vq8mT3xL2pR7 https://x.test/"
    assert _positions({"command": "sh", "args": ["-c", script]}) == [("argument 2", NAMED)]
    benign = "curl -su admin:${PASSWORD} https://x.test/"
    assert _positions({"command": "sh", "args": ["-c", benign]}) == []


@pytest.mark.parametrize(
    "benign,credential",
    [
        ("theme=dark; lang=en-US; tz=Europe/Berlin", "sid=Kx9mQ2vL7pZr; theme=dark"),
        (
            "_ga=GA1.2.987654321.1609459200; _gid=GA1.2.112233445.1609459201",
            f"prefs={RANDOM}; theme=dark",
        ),
    ],
)
def test_preference_and_analytics_cookies_hold_no_credential(benign, credential):
    server = {"url": "https://example.invalid/mcp"}
    assert _positions({**server, "headers": {"Cookie": benign}}) == []
    assert _positions({**server, "headers": {"Cookie": credential}}) == [("header Cookie", NAMED)]


def test_a_putty_key_in_base64_fires_under_any_name():
    key = "PuTTY-User-Key-File-3: ssh-ed25519\nPrivate-Lines: 1\n" + RANDOM + "\n"
    public = "PuTTY-User-Key-File-3: ssh-ed25519\nPublic-Lines: 2\n" + RANDOM + "\n"
    encoded = base64.b64encode(key.encode()).decode()
    assert _positions({"command": "npx", "env": {"MATERIAL": encoded}}) == [("env MATERIAL", NAMED)]
    benign = base64.b64encode(public.encode()).decode()
    assert _positions({"command": "npx", "env": {"MATERIAL": benign}}) == []


@pytest.mark.parametrize(
    "name,value",
    [
        ("STRIPE_KEY", "pk_live_51HqZq8vLm2pXr7tKw4nBv6y"),
        ("POSTHOG_API_KEY", "phc_Kx9mQ2vL7pZr4Tn8Wb3Yc6Hd1aBcDeFgHiJkLmN"),
        ("JWT_KEY", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" + RANDOM),
    ],
)
def test_public_material_by_value_holds_no_credential_under_credential_names(name, value):
    assert _positions({"command": "npx", "env": {name: value}}) == []
    twin = "sk_" + value[3:] if value.startswith("pk_") else RANDOM
    assert _positions({"command": "npx", "env": {name: twin}})


@pytest.mark.parametrize("benign,credential", [("aB3$x9", "aB3$x9Kq"), ("Kx9mQ2v", "Kx9mQ2vL")])
def test_a_literal_needs_eight_characters(benign, credential):
    for name in ("DB_PASSWORD", "API_TOKEN"):
        assert _positions({"command": "npx", "env": {name: benign}}) == []
        assert _positions({"command": "npx", "env": {name: credential}})


@pytest.mark.parametrize(
    "benign,credential",
    [
        (
            '{"a": {"b": [{"apiKey": "${API_KEY}"}]}}',
            f'{{"a": {{"b": [{{"apiKey": "{RANDOM}"}}]}}}}',
        ),
        (
            '{"headers": {"Cookie": "theme=dark; lang=en"}}',
            f'{{"headers": {{"Cookie": "sid={RANDOM}; theme=dark"}}}}',
        ),
        (
            '{"headers": {"Authorization": "postgres"}}',
            '{"headers": {"Authorization": "svc:hunter2hunter"}}',
        ),
    ],
)
def test_a_json_env_value_is_walked_with_header_semantics(benign, credential):
    assert _positions({"command": "npx", "env": {"MCP_CONFIG": benign}}) == []
    assert _positions({"command": "npx", "env": {"MCP_CONFIG": credential}}) == [
        ("env MCP_CONFIG", NAMED)
    ]


@pytest.mark.parametrize(
    "name,benign,credential",
    [
        (
            "CONN",
            "Server=db;User Id=sa;Database=correct-horse-battery-staple;",
            "Server=db;User Id=sa;Password=correct-horse-battery-staple;",
        ),
        ("CONN", f"Password={RANDOM};", f"Server=db;Password={RANDOM};"),
        (
            "NETRC",
            "machine api.acme.io login bot password ${NETRC_PASSWORD}",
            f"machine api.acme.io login bot password {RANDOM}",
        ),
        ("X", "Bearer error=invalid_token2X", "Bearer invalid_token2X"),
        ("API_TOKEN", "@/run/secrets/api", "@" + RANDOM),
        ("API_TOKEN", "process.env.API_TOKEN;", RANDOM + ";"),
    ],
)
def test_connection_netrc_challenge_and_code_read_rules_have_twins(name, benign, credential):
    assert _positions({"command": "npx", "env": {name: benign}}) == []
    assert _positions({"command": "npx", "env": {name: credential}})


def test_a_name_that_repeats_a_value_only_the_scrubber_redacts_is_withheld(tmp_path):
    scrubbed = "oauth2-client-secret-xyz"
    servers = {
        "api": {
            "url": "https://example.invalid/mcp",
            "env": {"API_TOKEN": scrubbed, scrubbed: "1"},
            "headers": {"X-Api-Key": scrubbed, scrubbed: "1"},
        }
    }
    result = _scan(tmp_path, servers)
    server = _servers(result)["api"].model_dump(mode="json")
    assert list(server["env"]) == ["API_TOKEN", "[redacted-1]"]
    assert "[redacted]" in server["properties"]["header_names"]
    assert scrubbed not in _dump(result)


def test_a_server_named_after_its_own_classifier_literal_is_withheld(tmp_path):
    sig, user, cookie, plain = (f"Qz6{index}Kp7Lm9Rt3Vw" for index in range(1, 5))
    servers = {
        sig: {"command": "uvx", "args": [f"--sig={sig}"]},
        user: {"command": "uvx", "args": ["-u", f"bob:{user}"]},
        cookie: {"url": "https://a.example.com/mcp", "headers": {"Cookie": f"sid={cookie}"}},
        "plain": {
            "command": "uvx",
            "args": ["t"],
            "env": {"SIG": plain},
            "tools": [{"name": plain, "description": f"uses {plain} and {sig}"}],
        },
    }
    result = _scan(tmp_path, servers)
    dump = _dump(result)
    for literal in (sig, user, cookie, plain):
        assert literal not in dump
    details = [
        risk.detail
        for component in result.components
        if isinstance(component, MCPServerComponent)
        for risk in _findings(component)
    ]
    assert len(details) == 4
    assert not any(literal in detail for detail in details for literal in (sig, user, cookie))


def test_a_refused_servers_classifier_literal_is_withheld_from_a_sibling_name(tmp_path):
    literal = "Rf41Kp7Lm9Rt3Vw"
    servers = {
        "refused": {"command": "uvx", "args": "notalist", "env": {"SIG": literal}},
        "sib": {"command": "uvx", "args": ["t"], "env": {literal: "2", "N": "x"}},
    }
    _project(tmp_path, servers)
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures
    assert list(_servers(result)["sib"].env) == ["N", "[redacted-1]"]
    assert literal not in _dump(result)


def test_each_argument_is_split_into_shell_words_once_for_the_finding(tmp_path, monkeypatch):
    split: list[str] = []
    words = mcp._launch_words

    def counting(texts):
        texts = list(texts)
        split.extend(text for text in texts if " " in text)
        return words(texts)

    monkeypatch.setattr(mcp, "_launch_words", counting)
    script = f"API_TOKEN={RANDOM} exec npx -y x@1.0.0"
    result = _scan(tmp_path, {"script": {"command": "sh", "args": ["-c", script]}})
    assert _findings(_servers(result)["script"])
    # Once for the scrubber's launcher values and once for the finding.
    assert split.count(script) == 2
    long_script = script + " " + "x" * mcp._SHELL_SPLIT_LIMIT
    split.clear()
    assert _positions({"command": "sh", "args": ["-c", long_script]}) == [("argument 2", NAMED)]
    assert long_script not in split


@pytest.mark.parametrize("value", ["$up3rsecret99", "$hunter_two_pw"])
def test_a_lower_case_shell_variable_is_a_password_under_a_password_name(value):
    assert _positions({"command": "npx", "env": {"SMTP_PASSWORD": value}}) == [
        ("env SMTP_PASSWORD", NAMED)
    ]


def test_a_negated_flag_names_no_credential():
    args = ["x@1.0.0", "--no-password", "service1.internal"]
    assert _positions({"command": "npx", "args": args}) == []
    args = ["x@1.0.0", "--password", "service1.internal"]
    assert _positions({"command": "npx", "args": args}) == [("argument 3", NAMED)]
