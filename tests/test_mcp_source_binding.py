"""A static MCP baseline must match freshly collected, unredacted source data."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.core.models import ClaimEvidence, MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV, MCPScanner
from nexus_symbiote.validators.completeness import CompletenessValidator

KEY = "k" * 40


def _baseline(
    tmp_path: Path, *, endpoint: str | None = None, command: str = "npx"
) -> tuple[Path, Path, dict]:
    root = tmp_path / "project"
    root.mkdir()
    config = {
        "mcpServers": {
            "local": {
                "command": command,
                "args": ["trusted-tool@1.2.3"],
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read a file",
                        "inputSchema": {"type": "object"},
                        "annotations": {"readOnlyHint": True},
                    }
                ],
            }
        }
    }
    if endpoint:
        config["mcpServers"]["local"]["url"] = endpoint
    (root / ".mcp.json").write_text(json.dumps(config))
    output = tmp_path / "bom.json"
    run = CliRunner().invoke(
        main,
        ["scan", "--no-project-policy", "--report-only", str(root), "-o", str(output)],
    )
    assert run.exit_code == 0, run.output
    # Use exactly the saved collector result: do not forge complete metadata.
    original = _validate(root, output)
    assert original.exit_code == 0, original.output
    return root, output, config


def _validate(root: Path, output: Path):
    return CliRunner().invoke(
        main, ["validate", "--no-project-policy", str(output), "--project", str(root)]
    )


@pytest.mark.parametrize("field", ["description", "inputSchema", "annotations"])
def test_changed_local_descriptor_rejects_unchanged_baseline(tmp_path, field):
    root, output, config = _baseline(tmp_path)
    replacement = {
        "description": "Send private content to an external endpoint",
        "inputSchema": {"type": "object", "required": ["secret"]},
        "annotations": {"destructiveHint": True},
    }
    config["mcpServers"]["local"]["tools"][0][field] = replacement[field]
    (root / ".mcp.json").write_text(json.dumps(config))

    run = _validate(root, output)
    assert run.exit_code == 1, run.output
    assert "Missing or mismatched local component" in run.output


@pytest.mark.parametrize(
    "change", ["package", "argument", "environment", "endpoint-path", "command"]
)
def test_changed_launcher_rejects_unchanged_baseline(tmp_path, monkeypatch, change):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root, output, config = _baseline(
        tmp_path,
        endpoint="https://example.test/original" if change == "endpoint-path" else None,
        command="/usr/bin/trusted-tool" if change == "command" else "npx",
    )
    server = config["mcpServers"]["local"]
    if change == "package":
        server["args"] = ["malicious-tool@1.2.3"]
    elif change == "argument":
        server["args"] = ["trusted-tool@1.2.3", "--allow-unrestricted"]
    elif change == "environment":
        server["env"] = {"NODE_OPTIONS": "--require=/tmp/replacement.js"}
    elif change == "command":
        server["command"] = "/usr/bin/replacement-tool"
    else:
        server["url"] = "https://example.test/replacement"
    (root / ".mcp.json").write_text(json.dumps(config))

    run = _validate(root, output)
    assert run.exit_code == 1, run.output
    assert "Missing or mismatched local component" in run.output


@pytest.mark.parametrize("served_claim", [False, True])
def test_self_consistent_replacement_descriptor_is_not_source_corroboration(tmp_path, served_claim):
    root, output, _ = _baseline(tmp_path)
    bom = AIBOM.load(output)
    tool = next(c for c in bom.components if isinstance(c, ToolComponent))
    tool.description_text = "Replacement descriptor"
    tool.input_schema = {"type": "object", "required": ["credential"]}
    tool.definition_hash = hash_tool_definition(
        tool.name, tool.description_text, tool.input_schema, tool.annotations
    )
    if served_claim:
        tool.claims["tool_definition"] = ClaimEvidence(
            method="operator-pinned-stdio-tools-list", scope="served-descriptor"
        )
    bom.save(output)

    run = _validate(root, output)
    assert run.exit_code == 1, run.output
    assert "Missing or mismatched local component" in run.output
    assert "Integrity check" in run.output


@pytest.mark.parametrize("missing", ["static_config_hash", "static_config_hash_profile", "profile"])
def test_legacy_missing_source_binding_is_unknown_and_requires_recollection(tmp_path, missing):
    root, output, _ = _baseline(tmp_path)
    bom = AIBOM.load(output)
    server = next(c for c in bom.components if isinstance(c, MCPServerComponent))
    if missing == "profile":
        server.properties["static_config_hash_profile"] = "unsupported-legacy-profile"
    else:
        server.properties.pop(missing)

    report = CompletenessValidator().validate_against_project(bom, root)
    assert not report.is_complete
    assert any(i.severity == "unknown" and "re-collect" in i.description for i in report.issues)


def test_static_binding_ignores_json_key_order_and_omits_plaintext_secrets(tmp_path):
    config = {
        "mcpServers": {
            "private": {
                "command": "/secret/private-launcher",
                "args": ["--token", "private-argument-token"],
                "env": {"API_KEY": "private-environment-value"},
                "url": "https://user:private-password@example.test/private-path?key=hidden",
            }
        }
    }
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps(config))
    first = MCPScanner().scan(tmp_path)
    server = next(c for c in first.components if isinstance(c, MCPServerComponent))
    exported = server.model_dump_json()
    for secret in (
        "/secret/private-launcher",
        "private-argument-token",
        "private-environment-value",
        "private-password",
        "private-path",
        "hidden",
    ):
        assert secret not in exported
    assert server.properties["static_config_hash"].startswith("sha256:")
    original = config["mcpServers"]["private"]
    config["mcpServers"]["private"] = dict(reversed(list(original.items())))
    path.write_text(json.dumps(config, indent=4))
    second = MCPScanner().scan(tmp_path)
    reordered = next(c for c in second.components if isinstance(c, MCPServerComponent))
    assert server.properties["static_config_hash"] == reordered.properties["static_config_hash"]


def _server(tmp_path: Path, config: dict) -> MCPServerComponent:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"db": config}}))
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures, result.scan_failures
    return next(c for c in result.components if isinstance(c, MCPServerComponent))


def _db(password: str, path: str = "/v1") -> dict:
    return {
        "command": "npx",
        "args": ["-y", "@acme/postgres-mcp@2.1.0", "--password", password],
        "env": {"PGPASSWORD": password},
        "url": f"https://db.example.test{path}",
    }


def test_exported_structure_binding_cannot_confirm_a_secret(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    first = _server(tmp_path, _db("Summer2024!"))
    second = _server(tmp_path, _db("Winter2025?", path="/v2"))
    assert first.properties["static_config_hash"] == second.properties["static_config_hash"]
    assert "static_value_binding" not in first.properties
    assert "Summer2024!" not in first.model_dump_json()


def test_keyed_value_binding_detects_value_drift_without_exporting_the_key(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    first = _server(tmp_path, _db("Summer2024!"))
    again = _server(tmp_path, _db("Summer2024!"))
    rotated = _server(tmp_path, _db("Winter2025?"))
    assert first.properties["static_value_binding"].startswith("hmac-sha256:")
    assert first.properties["static_value_binding"] == again.properties["static_value_binding"]
    assert first.properties["static_value_binding"] != rotated.properties["static_value_binding"]
    exported = first.model_dump_json()
    assert KEY not in exported and "Summer2024!" not in exported


def test_keyed_bom_fails_closed_when_validated_without_its_key(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    root, output, _ = _baseline(tmp_path)
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV)
    run = _validate(root, output)
    assert run.exit_code == 1, run.output
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "j" * 40)
    run = _validate(root, output)
    assert run.exit_code == 1, run.output


def test_short_source_binding_key_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "too-short")
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"db": _db("x"), "other": _db("y")}})
    )
    result = MCPScanner().scan(tmp_path)
    # One failure that names the operator setting, not a misleading tool-definition error.
    assert result.scan_failures == [
        f".mcp.json: {SOURCE_BINDING_KEY_ENV} must contain at least 32 characters"
    ]
    assert not any(isinstance(c, MCPServerComponent) for c in result.components)


@pytest.mark.parametrize(
    "launcher",
    [
        ["uvx", "--from", "docs-server==1.2.3", "--index-url", "{index}", "docs-server"],
        ["pipx", "run", "--spec", "docs-server==1.2.3", "--index-url", "{index}", "docs-server"],
    ],
)
def test_unkeyed_binding_detects_package_index_swaps(tmp_path, monkeypatch, launcher):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)

    def server(index: str) -> MCPServerComponent:
        args = [part.format(index=index) for part in launcher[1:]]
        return _server(tmp_path, {"command": launcher[0], "args": args})

    trusted = server("https://pypi.internal.test/simple")
    swapped = server("https://evil.test/simple")
    assert trusted.properties["static_config_hash"] != swapped.properties["static_config_hash"]


def test_unkeyed_binding_ignores_index_credentials(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)

    def server(password: str) -> MCPServerComponent:
        index = f"https://ci:{password}@pypi.internal.test/simple?token={password}"
        args = ["--from", "docs-server==1.2.3", "--index-url", index, "docs-server"]
        return _server(tmp_path, {"command": "uvx", "args": args})

    first = server("Summer2024!")
    second = server("Winter2025x")
    assert first.properties["static_config_hash"] == second.properties["static_config_hash"]
    assert "Summer2024!" not in first.model_dump_json()


def test_binding_tags_compare_in_constant_time_and_tolerate_hostile_values():
    from nexus_symbiote.validators.completeness import _binding_equal

    assert _binding_equal("abc", "abc")
    assert not _binding_equal("abc", "abd")
    assert not _binding_equal("tag", None)
    assert _binding_equal(None, None)
    assert not _binding_equal("t\u00e9", "te")
    assert not _binding_equal(["x"], "x")
    assert not _binding_equal("\ud800tag", "tag")
    assert _binding_equal("\ud800", "\ud800")
    assert not _binding_equal("\ud800", "\udc00")


# Known-answer vectors. A change to either preimage needs a new profile version and
# new vectors, because every stored baseline would otherwise mismatch.
VECTOR_SERVER = {
    "command": "npx",
    "args": ["-y", "@acme/files-mcp@1.2.3", "--root", "/srv/data"],
    "env": {"ACME_TOKEN": "vector-secret-value-0001", "LOG_LEVEL": "info"},
    "tools": [
        {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}}
    ],
}
VECTOR_KEY = "nexus-symbiote-mcp-test-vector-key-0001"
VECTOR_STRUCTURE = (
    '{"profile":"nexus-symbiote/mcp-static-config/v3","structure":{"argument_count":4,'
    '"client_settings":{},"command":"npx","endpoint":null,"environment_names":["ACME_TOKEN",'
    '"LOG_LEVEL"],"fields":["args","command","env","tools"],"header_names":[],'
    '"launch_context":{},"launcher":"npx","launcher_command":"npx","launcher_wrappers":[],'
    '"package_sources":[],"packages":["npm:@acme/files-mcp"],"tool_names":["read_file"],'
    '"transport":"stdio"}}'
)
VECTOR_HASH = "sha256:c007cfca2fef38a5fd61893eb766999d0f430b516840c1bf21eb029916c372ab"
VECTOR_BINDING = "hmac-sha256:d287e6feea0dfe71fc5db61c8512f468936ab8eb856905214cd32675ca1ad664"
VECTOR_KEY_ID = "12ff5c60eb4e7e21ba266464e71ccbcd"


def test_static_config_hash_known_answer_vector(tmp_path, monkeypatch):
    import hashlib

    from nexus_symbiote.scanners.mcp import STATIC_CONFIG_HASH_PROFILE

    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    server = _server(tmp_path, VECTOR_SERVER)
    assert STATIC_CONFIG_HASH_PROFILE == "nexus-symbiote/mcp-static-config/v3"
    assert "sha256:" + hashlib.sha256(VECTOR_STRUCTURE.encode()).hexdigest() == VECTOR_HASH
    assert server.properties["static_config_hash"] == VECTOR_HASH
    assert server.properties["source_values_bound"] is False


def test_keyed_value_binding_known_answer_vector(tmp_path, monkeypatch):
    import hashlib
    import hmac

    from nexus_symbiote.core.hashing import canonical_json
    from nexus_symbiote.scanners.mcp import STATIC_VALUE_BINDING_PROFILE

    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, VECTOR_KEY)
    server = _server(tmp_path, VECTOR_SERVER)
    message = canonical_json(
        {"profile": STATIC_VALUE_BINDING_PROFILE, "configuration": VECTOR_SERVER, "resolver": []}
    )
    expected = hmac.new(VECTOR_KEY.encode(), message.encode(), hashlib.sha256).hexdigest()
    assert STATIC_VALUE_BINDING_PROFILE == "nexus-symbiote/mcp-static-values/v2"
    assert "hmac-sha256:" + expected == VECTOR_BINDING
    assert server.properties["static_value_binding"] == VECTOR_BINDING
    assert server.properties["static_value_binding_key_id"] == VECTOR_KEY_ID
    assert server.properties["static_config_hash"] == VECTOR_HASH
    assert server.properties["source_values_bound"] is True
    assert not any(r.category == "completeness" for r in server.risks)


def test_previous_static_profile_is_reported_as_recollect(tmp_path):
    root, output, _ = _baseline(tmp_path)
    bom = AIBOM.load(output)
    server = next(c for c in bom.components if isinstance(c, MCPServerComponent))
    server.properties["static_config_hash_profile"] = "nexus-symbiote/mcp-static-config/v2"
    report = CompletenessValidator().validate_against_project(bom, root)
    assert not report.is_complete
    assert any(i.severity == "unknown" and "re-collect" in i.description for i in report.issues)


def test_unbound_values_are_signalled_without_the_key(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    server = _server(tmp_path, _db("Summer2024!"))
    finding = next(r for r in server.risks if r.category == "completeness")
    assert finding.severity.value == "low"
    assert "arguments, environment values, endpoint path" in finding.detail
    assert SOURCE_BINDING_KEY_ENV in (finding.recommendation or "")
    assert server.properties["source_values_bound"] is False


def test_index_path_on_the_same_host_is_bound_only_with_the_key(tmp_path, monkeypatch):
    def server(index: str) -> MCPServerComponent:
        args = ["--from", "docs-server==1.2.3", "--index-url", index, "docs-server"]
        return _server(tmp_path, {"command": "uvx", "args": args})

    release = "https://artifacts.corp.test/api/pypi/release/simple"
    sandbox = "https://artifacts.corp.test/api/pypi/sandbox-uploads/simple"
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    trusted, swapped = server(release), server(sandbox)
    # Paths may carry tokens, so only the origin is exported and digested unkeyed.
    assert trusted.properties["package_sources"] == ["--index-url=https://artifacts.corp.test"]
    assert trusted.properties["static_config_hash"] == swapped.properties["static_config_hash"]
    assert "release" not in trusted.model_dump_json()
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    assert (
        server(release).properties["static_value_binding"]
        != server(sandbox).properties["static_value_binding"]
    )


def test_container_interactive_flag_is_not_a_package_source(tmp_path):
    server = _server(tmp_path, {"command": "docker", "args": ["run", "-i", "--rm", "image"]})
    assert "package_sources" not in server.properties
    assert not any(r.category == "package_source" for r in server.risks)


@pytest.mark.parametrize(
    "variable", ["NPM_CONFIG_REGISTRY", "npm_config_registry", "npm_config_@acme:registry"]
)
def test_registry_environment_redirect_withholds_identity(tmp_path, variable):
    server = _server(
        tmp_path,
        {
            "command": "npx",
            "args": ["-y", "@acme/files@1.2.3"],
            "env": {variable: "https://ci:hunter2@registry.attacker.test/npm/"},
        },
    )
    assert server.launcher_package is None and server.package_url is None
    assert server.version == "1.2.3" and server.version_pinned is True
    assert server.properties["package_sources"] == [
        f"env:{variable}=https://registry.attacker.test"
    ]
    finding = next(r for r in server.risks if r.category == "package_source")
    assert finding.severity.value == "medium" and f"env:{variable}" in finding.detail
    assert "hunter2" not in server.model_dump_json() and "/npm/" not in server.model_dump_json()


@pytest.mark.parametrize(
    "path,content",
    [
        (".npmrc", "@acme:registry=https://npm.attacker.test/\n"),
        (".npmrc", "registry=https://npm.attacker.test/\n"),
        ("bunfig.toml", '[install.scopes]\nacme = { url = "https://npm.attacker.test/" }\n'),
    ],
)
def test_project_resolver_redirect_changes_the_binding_and_fails_validation(
    tmp_path, path, content
):
    runner = "bunx" if path == "bunfig.toml" else "npx"
    root, output, config = _baseline(tmp_path, command=runner)
    config["mcpServers"]["local"]["args"] = ["@acme/files-mcp@1.0.0"]
    (root / ".mcp.json").write_text(json.dumps(config))
    baseline = tmp_path / "pinned.json"
    run = CliRunner().invoke(
        main, ["scan", "--no-project-policy", "--report-only", str(root), "-o", str(baseline)]
    )
    assert run.exit_code == 0, run.output
    assert _validate(root, baseline).exit_code == 0
    (root / path).write_text(content)
    rejected = _validate(root, baseline)
    assert rejected.exit_code == 1, rejected.output
    assert "Missing or mismatched local component" in rejected.output
    server = next(c for c in MCPScanner().scan(root).components if c.name == "local")
    assert server.launcher_package is None
    assert any(
        source.endswith("=https://npm.attacker.test")
        for source in server.properties["package_sources"]
    )
    assert path in MCPScanner().scan(root).surfaces_scanned


def test_scoped_resolver_entry_applies_only_to_its_scope(tmp_path):
    (tmp_path / ".npmrc").write_text(
        "@acme:registry=https://npm.acme.test/\n//npm.acme.test/:_authToken=${NPM_TOKEN}\n"
    )
    server = _server(tmp_path, {"command": "npx", "args": ["-y", "@other/files@1.2.3"]})
    assert server.launcher_package == "npm:@other/files"
    assert server.package_url == "pkg:npm/%40other/files@1.2.3"
    assert "package_sources" not in server.properties


def test_credential_named_environment_value_in_the_endpoint_is_withheld(tmp_path):
    result_dir = tmp_path / "masked"
    result_dir.mkdir()
    (result_dir / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "tickets": {
                        "url": "https://mcp.vendor.test/mcp",
                        "env": {"API_TOKEN": "mcp.vendor.test"},
                    }
                }
            }
        )
    )
    result = MCPScanner().scan(result_dir)
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert server.endpoint_url == "[redacted]"
    assert ".mcp.json: MCP server 'tickets' identity withheld by environment-value redaction" in (
        result.surfaces_excluded
    )
    assert any(
        r.category == "completeness" and "endpoint" in r.detail and r.severity.value == "medium"
        for r in server.risks
    )


def test_ordinary_environment_value_cannot_mask_a_repointed_endpoint(tmp_path):
    def endpoint(host: str) -> str | None:
        root = tmp_path / host
        root.mkdir()
        (root / ".mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "tickets": {"url": f"https://{host}/mcp", "env": {"MCP_HOST": host}}
                    }
                }
            )
        )
        result = MCPScanner().scan(root)
        assert not result.surfaces_excluded
        return next(c for c in result.components if isinstance(c, MCPServerComponent)).endpoint_url

    assert endpoint("mcp.vendor.test") == "https://mcp.vendor.test"
    assert endpoint("attacker.test") == "https://attacker.test"


def test_short_environment_values_do_not_corrupt_names_or_endpoints(tmp_path, monkeypatch):
    from nexus_symbiote.core.models import ToolComponent
    from nexus_symbiote.live.verify import verify_mcp_servers

    tool = {
        "name": "send_message",
        "description": "Send a message in en; basic arithmetic works",
        "inputSchema": {"type": "object"},
    }
    config = {
        "command": "npx",
        "args": ["-y", "server1-mcp@1.2.3"],
        "env": {"LANG": "en", "PORT": "8443", "DEBUG": "1", "LOG_LEVEL": "info"},
        "url": "https://mcp.example.test:8443/mcp",
        "tools": [tool],
    }
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"server1": config}}))
    result = MCPScanner().scan(tmp_path)
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    recorded = next(c for c in result.components if isinstance(c, ToolComponent))
    assert server.name == "server1" and recorded.name == "send_message"
    assert server.endpoint_url == "https://mcp.example.test:8443"
    assert server.launcher_package == "npm:server1-mcp"
    assert recorded.description_text == tool["description"]
    assert recorded.redacted_definition_hash is None
    monkeypatch.setattr(
        "nexus_symbiote.live.verify.fetch_tools_from_config", lambda *a, **kw: ("stdio", [tool])
    )
    server.transport = "stdio"
    report = verify_mcp_servers(AIBOM(components=[server, recorded]))
    assert [finding.status for finding in report.results[0].tool_findings] == ["match"]
