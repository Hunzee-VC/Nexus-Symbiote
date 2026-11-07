"""A2A records must bind endpoint paths and required scopes without exporting the paths."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import A2AClientComponent, A2AServerComponent
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.scanners import mcp
from nexus_symbiote.scanners.a2a import (
    CARD_STRUCTURE_PROFILE,
    CARD_VALUE_BINDING_PROFILE,
    CLIENT_STRUCTURE_PROFILE,
    CLIENT_VALUE_BINDING_PROFILE,
    A2AScanner,
)
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV
from nexus_symbiote.validators.completeness import CompletenessValidator

KEY = "k" * 40

CARD: dict[str, Any] = {
    "name": "billing-agent",
    "version": "1.0.0",
    "url": "https://agents.example.com/trusted",
    "protocols": ["a2a/0.3"],
    "securitySchemes": {
        "oauth": {
            "type": "oauth2",
            "flows": {
                "clientCredentials": {
                    "tokenUrl": "https://auth.example.com/token",
                    "scopes": {"read:only": "Read-only access"},
                }
            },
        }
    },
    "security": [{"oauth": ["read:only"]}],
    "skills": [{"id": "lookup", "name": "lookup-invoice"}],
}


@pytest.fixture(autouse=True)
def _no_ambient_key(monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)


def _write_card(root: Path, card: dict[str, Any]) -> None:
    (root / ".well-known").mkdir(parents=True, exist_ok=True)
    (root / ".well-known" / "agent.json").write_text(json.dumps(card))


def _server(root: Path, card: dict[str, Any]) -> A2AServerComponent:
    _write_card(root, card)
    result = A2AScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    (server,) = [c for c in result.components if isinstance(c, A2AServerComponent)]
    return server


def _client(root: Path, client: dict[str, Any]) -> A2AClientComponent:
    root.mkdir(parents=True, exist_ok=True)
    (root / "a2a.json").write_text(json.dumps({"clients": [client]}))
    result = A2AScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    (component,) = [c for c in result.components if isinstance(c, A2AClientComponent)]
    return component


def _failures(root: Path, card: dict[str, Any]) -> list[str]:
    _write_card(root, card)
    result = A2AScanner().scan(root)
    assert not any(isinstance(c, A2AServerComponent) for c in result.components)
    return result.scan_failures


def _scan(project: Path, output: Path) -> str:
    run = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    )
    assert run.exit_code == 0, run.output
    return output.read_text()


def _drift(tmp_path: Path, before: dict[str, Any], after: dict[str, Any]):
    project = tmp_path / "project"
    _write_card(project, before)
    first = _scan(project, tmp_path / "before.json")
    _write_card(project, after)
    second = _scan(project, tmp_path / "after.json")
    run = CliRunner().invoke(
        main,
        [
            "diff",
            str(tmp_path / "before.json"),
            str(tmp_path / "after.json"),
            "--json-output",
            "--fail-on-alert",
        ],
    )
    return run, first + second


def _moved(card: dict[str, Any]) -> dict[str, Any]:
    return {**card, "url": "https://agents.example.com/attacker"}


def _scoped(card: dict[str, Any], scope: str) -> dict[str, Any]:
    scoped = copy.deepcopy(card)
    scoped["securitySchemes"]["oauth"]["flows"]["clientCredentials"]["scopes"] = {scope: "Access"}
    scoped["security"] = [{"oauth": [scope]}]
    return scoped


def _token_url(card: dict[str, Any], url: str) -> dict[str, Any]:
    changed = copy.deepcopy(card)
    changed["securitySchemes"]["oauth"]["flows"]["clientCredentials"]["tokenUrl"] = url
    return changed


AZURE_APP = "api://11111111-2222-3333-4444-555555555555"


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("read:only", "admin"),
        # Scope URIs name the permission in their path (RFC 6749 section 3.3 tokens).
        (
            "https://www.googleapis.com/auth/drive.readonly",
            "https://www.googleapis.com/auth/cloud-platform",
        ),
        (f"{AZURE_APP}/access_as_user", f"{AZURE_APP}/admin"),
        ("https://graph.microsoft.com/User.Read", "https://graph.microsoft.com/Mail.ReadWrite"),
    ],
)
def test_required_scope_change_fails_the_drift_gate_without_a_key(tmp_path, before, after):
    run, boms = _drift(tmp_path, _scoped(CARD, before), _scoped(CARD, after))
    assert run.exit_code == 1, run.output
    alerts = json.loads(run.stdout)["security_alerts"]
    assert any(
        alert["severity"] == "high" and "capabilities changed" in alert["alert"] for alert in alerts
    ), alerts
    baseline = json.loads((tmp_path / "before.json").read_text())
    (server,) = [c for c in baseline["components"] if c["component_type"] == "a2a-server"]
    assert server["capabilities"]["oauth_scopes"] == [before]
    assert server["properties"]["security_scheme_types"] == ["oauth2"]
    assert not any("OAuth scopes" in risk["detail"] for risk in server["risks"])


def test_same_origin_path_change_fails_the_drift_gate_with_a_key(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    run, boms = _drift(tmp_path, CARD, _moved(CARD))
    assert run.exit_code == 1, run.output
    alerts = json.loads(run.stdout)["security_alerts"]
    assert any("billing-agent" in alert["alert"] for alert in alerts), alerts
    assert "trusted" not in boms and "attacker" not in boms
    assert "auth.example.com/token" not in boms and KEY not in boms


def test_without_a_key_the_path_is_neither_exported_nor_digested_but_marked_unbound(tmp_path):
    first = _server(tmp_path / "a", CARD)
    moved = _server(tmp_path / "b", _moved(CARD))
    assert first.endpoint_url == "https://agents.example.com"
    assert first.properties["source_values_bound"] is False
    assert "static_value_binding" not in first.properties
    # An unkeyed digest that changed with the path would let anyone confirm guesses.
    assert first.properties["static_card_hash"] == moved.properties["static_card_hash"]
    (gap,) = [r for r in first.risks if r.category == "completeness"]
    assert gap.severity == "low" and "endpoint path" in gap.detail
    assert SOURCE_BINDING_KEY_ENV in gap.recommendation
    assert "trusted" not in first.model_dump_json()
    origin_only = _server(tmp_path / "c", {**CARD, "url": "https://agents.example.com/"})
    assert origin_only.properties["source_values_bound"] is False
    assert not any("endpoint path" in r.detail for r in origin_only.risks)


def test_keyed_binding_ignores_key_order_and_whitespace(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    first = _server(tmp_path / "a", CARD)
    reordered = tmp_path / "b" / ".well-known"
    reordered.mkdir(parents=True)
    (reordered / "agent.json").write_text(
        json.dumps(dict(reversed(list(CARD.items()))), indent=4, sort_keys=True)
    )
    result = A2AScanner().scan(tmp_path / "b")
    (second,) = result.components
    for key in ("static_value_binding", "static_value_binding_key_id", "static_card_hash"):
        assert first.properties[key] == second.properties[key]
    assert first.properties["static_value_binding_profile"] == CARD_VALUE_BINDING_PROFILE
    assert first.properties["source_values_bound"] is True
    assert not any(r.category == "completeness" for r in first.risks)


def test_card_client_and_mcp_bindings_are_domain_separated(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    shared = {"name": "same", "url": "https://agents.example.com/same"}
    card = _server(tmp_path / "card", shared)
    client = _client(tmp_path / "client", shared)
    mcp_binding = mcp._value_binding(shared)
    assert mcp_binding is not None
    macs = {
        card.properties["static_value_binding"],
        client.properties["static_value_binding"],
        mcp_binding[0],
    }
    assert len(macs) == 3
    # One operator key has one identifier across collectors.
    assert card.properties["static_value_binding_key_id"] == mcp_binding[1]
    assert client.properties["static_value_binding_key_id"] == mcp_binding[1]


def test_short_binding_key_is_a_scan_failure(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "too-short")
    failures = _failures(tmp_path, CARD)
    assert failures == [
        f".well-known/agent.json: {SOURCE_BINDING_KEY_ENV} must contain at least 32 characters"
    ]
    (tmp_path / "a2a.json").write_text(json.dumps({"clients": [{"name": "c"}]}))
    assert any("a2a.json" in failure for failure in A2AScanner().scan(tmp_path).scan_failures)


def test_validation_with_the_key_rejects_a_baseline_after_a_path_change(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    project = tmp_path / "project"
    _write_card(project, CARD)
    # Integrity validation needs at least one verifiable descriptor in the inventory.
    tool = {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}}
    server = {"command": "npx", "args": ["trusted-tool@1.2.3"], "tools": [tool]}
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"local": server}}))
    baseline = tmp_path / "baseline.json"
    _scan(project, baseline)
    validate = ["validate", "--no-project-policy", str(baseline), "--project", str(project)]
    unchanged = CliRunner().invoke(main, validate)
    assert unchanged.exit_code == 0, unchanged.output
    _write_card(project, _moved(CARD))
    run = CliRunner().invoke(main, validate)
    assert run.exit_code == 1, run.output
    assert "a2a-server:billing-agent" in run.output


def test_keyed_baseline_fails_reconciliation_without_its_key(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    project = tmp_path / "project"
    _write_card(project, {**CARD, "url": "https://agents.example.com"})
    baseline = tmp_path / "baseline.json"
    _scan(project, baseline)
    bom = AIBOM.load(baseline)
    assert CompletenessValidator().validate_against_project(bom, project).is_complete
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV)
    report = CompletenessValidator().validate_against_project(bom, project)
    assert not report.is_complete
    assert any("a2a-server:billing-agent" in issue.description for issue in report.issues)
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "j" * 40)
    assert not CompletenessValidator().validate_against_project(bom, project).is_complete


def test_client_card_url_path_change_is_bound_by_the_key(tmp_path, monkeypatch):
    before = {"name": "planner", "agentCardUrl": "https://agents.example.com/trusted/card.json"}
    after = {**before, "agentCardUrl": "https://agents.example.com/attacker/card.json"}
    unkeyed = _client(tmp_path / "a", before)
    assert unkeyed.agent_card_url == "https://agents.example.com"
    assert unkeyed.properties["source_values_bound"] is False
    assert any(r.severity == "low" and r.category == "completeness" for r in unkeyed.risks)
    assert "trusted" not in unkeyed.model_dump_json()
    assert (
        unkeyed.properties["static_config_hash"]
        == _client(tmp_path / "b", after).properties["static_config_hash"]
    )
    well_known = _client(
        tmp_path / "c",
        {**before, "agentCardUrl": "https://agents.example.com/.well-known/agent.json"},
    )
    assert not any(r.category == "completeness" for r in well_known.risks)
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    old, new = _client(tmp_path / "d", before), _client(tmp_path / "e", after)
    assert old.properties["static_value_binding_profile"] == CLIENT_VALUE_BINDING_PROFILE
    report = AIBOMDiffer().diff(AIBOM(components=[old]), AIBOM(components=[new]))
    assert [alert["component"] for alert in report.security_alerts] == ["a2a-client:planner"]
    assert "trusted" not in old.model_dump_json() and "attacker" not in new.model_dump_json()


@pytest.mark.parametrize(
    ("security", "required"),
    [
        ([{}], False),
        ([{"oauth": ["read:only"]}, {}], False),
        ([], False),
        ([{"undeclared": []}], False),
        ([{"oauth": ["read:only"], "undeclared": []}], False),
        ([{"oauth": ["read:only"]}], True),
        ([{"oauth": []}, {"oauth": ["read:only"]}], True),
    ],
)
def test_authentication_is_required_only_when_every_alternative_names_declared_schemes(
    tmp_path, security, required
):
    server = _server(tmp_path, {**CARD, "security": security})
    assert server.authentication_required is required
    medium = [r for r in server.risks if r.category == "authentication"]
    assert [r.severity for r in medium] == ([] if required else ["medium"])


@pytest.mark.parametrize(
    ("authentication", "security", "required"),
    [
        ({"schemes": ["bearer"]}, None, True),
        ({"schemes": []}, None, False),
        ({}, None, False),
        ({"schemes": ["bearer"]}, [{}], False),
        ({"schemes": []}, [{"oauth": []}], False),
    ],
)
def test_legacy_authentication_needs_nonempty_schemes(tmp_path, authentication, security, required):
    card = {**CARD, "authentication": authentication}
    card.pop("security")
    if security is not None:
        card["security"] = security
    assert _server(tmp_path, card).authentication_required is required


@pytest.mark.parametrize(
    "change",
    [
        {"security": {"oauth": ["read:only"]}},
        {"security": [["oauth"]]},
        {"security": [{"oauth": "read:only"}]},
        {"security": [{"oauth": [1]}]},
        {"security": [{"oauth": [f"s{i}" for i in range(1001)]}]},
        {"security": [{f"s{i}": [] for i in range(1001)}]},
        {"securitySchemes": []},
        {"securitySchemes": {"oauth": "oauth2"}},
        {"securitySchemes": {"oauth": {"type": 2}}},
        {"securitySchemes": {f"s{i}": {} for i in range(1001)}},
        {"authentication": ["bearer"]},
        {"authentication": {"schemes": "bearer"}},
        {"authentication": {"schemes": [None]}},
    ],
)
def test_malformed_security_declarations_are_scan_failures(tmp_path, change):
    assert _failures(tmp_path, {**CARD, **change}) == [
        ".well-known/agent.json: invalid A2A card field types"
    ]


def test_scheme_types_map_onto_a_fixed_set_and_scopes_are_redacted(tmp_path):
    secret = "ghp_" + "a" * 36
    card = copy.deepcopy(CARD)
    card["securitySchemes"].update(
        {"key": {"type": "apiKey"}, "custom": {"type": f"x-{secret}"}, "bare": {}}
    )
    card["security"] = [{"oauth": [f"token={secret}", "read:only"], "key": []}]
    server = _server(tmp_path, card)
    assert server.properties["security_scheme_types"] == ["apiKey", "oauth2", "other"]
    assert server.capabilities is not None
    assert "read:only" in server.capabilities.oauth_scopes
    assert secret not in server.model_dump_json()


@pytest.mark.parametrize(
    "change",
    [
        # SDK serializers that keep None fields emit these shapes.
        {"securitySchemes": None, "security": None},
        {"securitySchemes": None},
        {"authentication": {"schemes": None}, "security": None},
        {"authentication": {"schemes": [""]}, "security": None},
        {"authentication": {"schemes": [" "]}, "security": None},
        # A referenced scheme must declare a type to count as authentication.
        {"securitySchemes": {"oauth": {}}, "security": [{"oauth": []}]},
        {"securitySchemes": {"oauth": {"type": None}}, "security": [{"oauth": []}]},
        {"securitySchemes": {"oauth": {"type": ""}}, "security": [{"oauth": []}]},
    ],
)
def test_null_empty_and_typeless_declarations_are_not_authentication(tmp_path, change):
    server = _server(tmp_path, {**CARD, **change})
    assert server.authentication_required is False
    assert [r.severity for r in server.risks if r.category == "authentication"] == ["medium"]


def test_only_oauth_scopes_are_exported_and_secret_shaped_values_are_withheld(
    tmp_path, monkeypatch
):
    pat = "ghp_" + "b" * 36
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlc2lnbmF0dXJl"
    card = copy.deepcopy(CARD)
    card["securitySchemes"]["key"] = {"type": "apiKey", "in": "header", "name": "X-Key"}
    card["security"] = [
        {"oauth": ["read:only", jwt, "https://x.example/s?api_key=v"], "key": [pat]}
    ]
    server = _server(tmp_path / "a", card)
    assert server.capabilities is not None
    assert server.capabilities.oauth_scopes == ["***", "https://x.example", "read:only"]
    exported = server.model_dump_json()
    assert pat not in exported and jwt not in exported and "api_key=v" not in exported
    (gap,) = [r for r in server.risks if r.category == "completeness"]
    assert "redacted OAuth scopes" in gap.detail and "role names" in gap.detail
    role_changed = copy.deepcopy(card)
    role_changed["security"][0]["key"] = ["ghp_" + "c" * 36]
    unkeyed = _server(tmp_path / "b", role_changed)
    assert unkeyed.properties["static_card_hash"] == server.properties["static_card_hash"]
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    keyed, rekeyed = _server(tmp_path / "c", card), _server(tmp_path / "d", role_changed)
    assert keyed.properties["static_value_binding"] != rekeyed.properties["static_value_binding"]
    assert not any(r.category == "completeness" for r in keyed.risks)


def test_credential_endpoint_host_change_fails_the_drift_gate_without_a_key(tmp_path):
    run, boms = _drift(tmp_path, CARD, _token_url(CARD, "https://evil.example.net/steal"))
    assert run.exit_code == 1, run.output
    assert any("billing-agent" in a["alert"] for a in json.loads(run.stdout)["security_alerts"])
    assert "auth.example.com/token" not in boms and "evil.example.net/steal" not in boms
    baseline = json.loads((tmp_path / "before.json").read_text())
    (server,) = [c for c in baseline["components"] if c["component_type"] == "a2a-server"]
    assert server["properties"]["security_scheme_origins"] == ["https://auth.example.com"]
    (gap,) = [r for r in server["risks"] if r["category"] == "completeness"]
    assert "security scheme URL paths" in gap["detail"]


def test_additional_interface_urls_export_origins_and_mark_paths_unbound(tmp_path):
    interface = {"url": "https://grpc.example.com/secret-path", "transport": "GRPC"}
    card = {**_token_url(CARD, "https://auth.example.com"), "url": "https://agents.example.com"}
    server = _server(tmp_path / "a", {**card, "additionalInterfaces": [interface]})
    assert server.properties["additional_interface_origins"] == ["https://grpc.example.com"]
    assert server.properties["security_scheme_origins"] == ["https://auth.example.com"]
    (gap,) = [r for r in server.risks if r.category == "completeness"]
    assert gap.detail.endswith(
        "values not bound in this inventory: additional interface URL paths or queries."
    )
    assert "secret-path" not in server.model_dump_json()
    moved = _server(
        tmp_path / "b",
        {**card, "additionalInterfaces": [{**interface, "url": "https://evil.example.net"}]},
    )
    assert moved.properties["additional_interface_origins"] == ["https://evil.example.net"]
    relative = _server(tmp_path / "c", {**card, "additionalInterfaces": [{"url": "/trusted"}]})
    assert any("additional interface" in r.detail for r in relative.risks)
    assert "trusted" not in relative.model_dump_json()
    plain = _server(tmp_path / "d", card)
    assert plain.properties["additional_interface_origins"] == []
    assert not any(r.category == "completeness" for r in plain.risks)


def test_backslash_authority_is_not_exported_as_an_origin(tmp_path):
    hidden = "SecretPathToken123"
    server = _server(tmp_path / "a", {**CARD, "url": f"https://agents.example.com\\{hidden}"})
    client = _client(tmp_path / "b", {"name": "c", "agentCardUrl": f"https://h.example\\{hidden}"})
    assert server.endpoint_url == "[redacted]" and client.agent_card_url == "[redacted]"
    for record in (server, client):
        assert hidden.lower() not in record.model_dump_json().lower()
        assert any(r.category == "completeness" for r in record.risks)


def test_client_well_known_card_path_swap_changes_the_structure_digest(tmp_path):
    hashes = set()
    for index, path in enumerate(("agent.json", "agent-card.json")):
        url = f"https://agents.example.com/.well-known/{path}"
        client = _client(tmp_path / str(index), {"name": "c", "agentCardUrl": url})
        assert not any(r.category == "completeness" for r in client.risks)
        hashes.add(client.properties["static_config_hash"])
    assert len(hashes) == 2


def test_keyed_binding_names_yaml_values_that_are_not_json(tmp_path, monkeypatch):
    (tmp_path / "a2a.yaml").write_text("clients:\n  - name: c\n    added: 2024-01-01\n")
    assert not A2AScanner().scan(tmp_path).scan_failures
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    (failure,) = A2AScanner().scan(tmp_path).scan_failures
    assert failure.startswith(f"a2a.yaml: {SOURCE_BINDING_KEY_ENV} binding needs RFC 8785 JSON")
    assert "quote YAML dates" in failure


VECTOR_KEY = "nexus-symbiote-a2a-test-vector-key"
VECTOR_CARD = {
    "name": "v",
    "url": "https://a.example/p",
    "securitySchemes": {
        "o": {
            "type": "oauth2",
            "flows": {"clientCredentials": {"tokenUrl": "https://t.example/token", "scopes": {}}},
        },
        "k": {"type": "apiKey"},
    },
    "security": [{"o": ["s", "https://a.example/scope"]}, {"k": ["role"]}],
    "additionalInterfaces": [{"url": "https://g.example", "transport": "GRPC"}],
}
VECTOR_CLIENT = {"name": "c", "agentCardUrl": "https://a.example/.well-known/agent-card.json"}
VECTORS = [
    (
        "static_card_hash",
        '{"profile":"nexus-symbiote/a2a-card-structure/v1","structure":{'
        '"additional_interfaces":[{"fragment":false,"path_separators":0,"plain_path":"",'
        '"query":false,"userinfo":false}],"authentication_schemes":null,'
        '"endpoint":{"fragment":false,"path_separators":1,"plain_path":null,"query":false,'
        '"userinfo":false},"fields":["additionalInterfaces","name","security",'
        '"securitySchemes","url"],"security":[{"k":1},{"o":["https://a.example/scope","s"]}],'
        '"security_scheme_urls":[{"fragment":false,"path_separators":1,"plain_path":null,'
        '"query":false,"userinfo":false}],"security_schemes":[["k","apiKey"],["o","oauth2"]]}}',
        "sha256:078c59393036dd82e7b3846bfd0ce88e7124cf3287657bed8586e641b953eb67",
    ),
    (
        "static_value_binding",
        '{"configuration":{"additionalInterfaces":[{"transport":"GRPC","url":"https://g.example"}],'
        '"name":"v","security":[{"o":["s","https://a.example/scope"]},{"k":["role"]}],'
        '"securitySchemes":{"k":{"type":"apiKey"},"o":{"flows":{"clientCredentials":{'
        '"scopes":{},"tokenUrl":"https://t.example/token"}},"type":"oauth2"}},'
        '"url":"https://a.example/p"},"profile":"nexus-symbiote/a2a-card-values/v1"}',
        "hmac-sha256:6891a90bc0fe990cca5ba895975fd35bb9a3a319abb88ea27c080b5568e81ba4",
    ),
    (
        "static_config_hash",
        '{"profile":"nexus-symbiote/a2a-client-structure/v1","structure":{"card_url":{'
        '"fragment":false,"path_separators":2,"plain_path":"/.well-known/agent-card.json",'
        '"query":false,"userinfo":false},"fields":["agentCardUrl","name"]}}',
        "sha256:37abbd341b98747178d6d9393bb2343dc6d7f4a2168a0d4fd3dd9d9a56f14d3a",
    ),
    (
        "static_value_binding",
        '{"configuration":{"agentCardUrl":"https://a.example/.well-known/agent-card.json",'
        '"name":"c"},"profile":"nexus-symbiote/a2a-client-values/v1"}',
        "hmac-sha256:54acc1cb60bb70eaa929aa3bec0e4d5ce0ccc13728191fdc72412c76d0ff0462",
    ),
]


def test_binding_profiles_match_their_published_vectors(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, VECTOR_KEY)
    card = _server(tmp_path / "card", VECTOR_CARD)
    client = _client(tmp_path / "client", VECTOR_CLIENT)
    assert card.properties["static_card_hash_profile"] == CARD_STRUCTURE_PROFILE
    assert client.properties["static_config_hash_profile"] == CLIENT_STRUCTURE_PROFILE
    for record, (field, message, expected) in zip(
        (card, card, client, client), VECTORS, strict=True
    ):
        if expected.startswith("sha256:"):
            computed = "sha256:" + hashlib.sha256(message.encode()).hexdigest()
        else:
            mac = hmac.new(VECTOR_KEY.encode(), message.encode(), "sha256").hexdigest()
            computed = "hmac-sha256:" + mac
        assert computed == expected
        assert record.properties[field] == expected
    assert card.properties["static_value_binding_key_id"] == "46c23d6a04382e01f726b1da3f2253b1"
    assert card.capabilities is not None
    assert card.capabilities.oauth_scopes == ["https://a.example/scope", "s"]
    assert card.properties["security_scheme_origins"] == ["https://t.example"]
    assert card.properties["additional_interface_origins"] == ["https://g.example"]
