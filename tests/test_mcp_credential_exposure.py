"""A literal credential in an MCP launch raises credential_exposure, which names positions only."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import (
    MCPScanner,
    _credential_positions,
    _server_launch,
    _server_secrets,
)
from nexus_symbiote.utils.secrets import names_reference

CATEGORY = "credential_exposure"
ENV_SENTINEL = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_11"
SCHEME_SENTINEL = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_12"
PASSWORD = "synthetic-launch-password-98765"  # noqa: S105 - synthetic sentinel
VENDOR_TOKEN = "ghp_" + "A1" * 18
KEY_TOKEN = "ghp_" + "B2" * 18
SENTINELS = (ENV_SENTINEL, SCHEME_SENTINEL, PASSWORD, VENDOR_TOKEN, KEY_TOKEN)
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
    "value",
    ["ab:" * 3000 + "x", "ab:" * 900 + "y" * 200_000, "X-A: " * 2000 + PASSWORD],
)
@pytest.mark.parametrize("field", ["env", "args", "headers"])
def test_colon_chains_keep_the_server_inventoried_and_stay_fast(tmp_path, field, value):
    server: dict = {"command": "npx", "args": ["x@1.0.0"]}
    if field == "args":
        server["args"] = ["x@1.0.0", "--token", value]
    else:
        server[field] = {"API_TOKEN": value}
    start = time.monotonic()
    result = _scan(tmp_path, {"api": server})
    assert time.monotonic() - start < 10
    (finding,) = _findings(_servers(result)["api"])
    assert "(a generic secret-like value)" in finding.detail
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
    project = _project(tmp_path / "project", {"api": LITERAL, "ref": REFERENCED})
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
    project = _project(tmp_path / "project", {"api": LITERAL, "ref": REFERENCED})
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
