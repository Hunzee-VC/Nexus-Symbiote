"""Adversarial regression tests for PR 2 scanner, redaction, and live MCP hardening."""

from __future__ import annotations

import io
import json
import os
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.core.models import (
    A2AServerComponent,
    IDEAgentComponent,
    MCPServerComponent,
    ModelComponent,
    RegistryEntryComponent,
    ToolComponent,
)
from nexus_symbiote.scanners.a2a import A2AScanner
from nexus_symbiote.scanners.base import sanitized_origin
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner, _broad_grants, _starting_mode_risk
from nexus_symbiote.scanners.live_mcp import (
    DiscoveryError,
    PinnedHTTPTransport,
    check_served_tool,
)
from nexus_symbiote.scanners.mcp import (
    SOURCE_BINDING_KEY_ENV,
    MCPScanner,
    SourceBindingKeyError,
    _load_jsonc,
    _npmrc,
    source_binding_key,
    without_js_comments,
)
from nexus_symbiote.scanners.mcp_launch import analyze
from nexus_symbiote.scanners.model import ModelScanner, inspect_model_format, observe_model_artifact
from nexus_symbiote.scanners.registry import RegistryScanner
from nexus_symbiote.scanners.shadowscan import ShadowScanImporter
from nexus_symbiote.scanners.source_binding import BindingError, origin, value_binding
from nexus_symbiote.utils.model_formats import template_escape_markers
from nexus_symbiote.utils.secrets import REDACTED, redact_metadata, redact_text, redact_url


def test_secrets_redaction_long_quoted_jwt_url_token_host_and_jwk_fields() -> None:
    long_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." + ("A" * 600) + ".sig_part_12345"
    text = f'token="{long_jwt}"'
    scrubbed = redact_text(text)
    assert long_jwt not in scrubbed
    assert REDACTED in scrubbed

    gh_token = "ghp_" + ("A1b2C3d4E5f6" * 3)
    assert redact_url(f"https://{gh_token}.attacker.example/v1") == "[redacted-url]"
    assert sanitized_origin(f"https://{gh_token}.attacker.example/v1") == "[redacted]"
    assert sanitized_origin("https://bad\\host.example/v1") == "[redacted]"
    assert origin(f"//{gh_token}.attacker.example:8443/mcp") == "[redacted]"
    assert redact_url("https://api.openai.com/v1/models") == "https://api.openai.com"

    jwk_and_meta = {
        "jwk": {
            "kty": "RSA",
            "kid": "prod-key-1",
            "n": "publicModulusValue",
            "e": "AQAB",
            "d": "superSecretPrivateExponentValue12345",
            "p": "primeFactorOneValue",
            "oth": [{"r": "prime3"}],
            "dp": "",
        },
        "oauth": {
            "client_id": "public-client-id",
            "client_secret": "plainwordswithoutdigitsorshapesbutsecret",
            "endpoint": "https://oauth2.googleapis.com/token",
        },
    }
    redacted = redact_metadata(jwk_and_meta)
    assert redacted["jwk"]["n"] == "publicModulusValue"
    assert redacted["jwk"]["d"] == REDACTED
    assert redacted["jwk"]["p"] == REDACTED
    assert redacted["jwk"]["oth"] == REDACTED
    assert redacted["jwk"]["dp"] == ""
    assert redacted["oauth"]["client_id"] == "public-client-id"
    assert redacted["oauth"]["client_secret"] == REDACTED
    assert redacted["oauth"]["endpoint"] == "https://oauth2.googleapis.com"


def test_source_binding_surrogate_key_does_not_echo_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    canary_prefix = "operator_hmac_material_" + ("x" * 16)
    monkeypatch.setitem(
        os.environb,
        SOURCE_BINDING_KEY_ENV.encode("ascii"),
        canary_prefix.encode("ascii") + b"\xff",
    )

    with pytest.raises(SourceBindingKeyError) as mcp_exc:
        source_binding_key()
    assert canary_prefix not in str(mcp_exc.value)
    assert mcp_exc.value.__cause__ is None

    with pytest.raises(BindingError) as bind_exc:
        value_binding("nexus-symbiote/test/v1", {"url": "https://mcp.example.com"})
    assert canary_prefix not in str(bind_exc.value)
    assert bind_exc.value.__cause__ is None


def test_template_escape_markers_catch_pipe_attr_and_single_underscore_frames() -> None:
    assert template_escape_markers(b"{{ '' | attr('class') }}")
    assert template_escape_markers(b"{{ cycler.next._globals.os }}")
    assert template_escape_markers(b"{{ namespace._builtins }}")
    assert not template_escape_markers(b"{{ messages[0]['content'] | trim }}")


def test_mcp_launch_rejects_package_runner_shells_and_marks_uv_env_file() -> None:
    for shell_cmd in ("sh", "bash", "csh", "tcsh", "busybox", "toybox", "env"):
        verdict = analyze(
            "npx", ["-y", "--package", "@modelcontextprotocol/server-memory@0.6.2", shell_cmd]
        )
        assert verdict.unknown is not None

    uv_env = analyze("uv", ["run", "--env-file", ".env.local", "--with", "mcp==1.2.0", "s.py"])
    assert uv_env.injected_environment is True


def test_mcp_jsonc_depth_nonfinite_float_js_comments_npmrc_nested_and_dup_tools(
    tmp_path: Path,
) -> None:
    deep = "[" * 300 + "]" * 300
    with pytest.raises(RecursionError, match="nesting limit"):
        _load_jsonc(deep)

    with pytest.raises(ValueError, match="nonfinite JSON"):
        _load_jsonc('{"timeout": 1e309}')

    assert _load_jsonc('{"timeout": 30.5 /* ok */}') == {"timeout": 30.5}

    code_with_string_comment = (
        'const open = "/*";\n'
        'import { Client } from "@modelcontextprotocol/sdk/client/index.js";\n'
        "  // whole line comment\n"
        'const close = "*/";\n'
        '/* real block comment */const trail = "http://example.com";\n'
    )
    stripped = without_js_comments(code_with_string_comment)
    assert "@modelcontextprotocol/sdk/client/index.js" in stripped
    assert "whole line comment" not in stripped
    assert "real block comment" not in stripped
    assert 'const trail = "http://example.com";' in stripped

    parsed_npmrc = _npmrc("${DYNAMIC_KEY}=https://evil.example/\n")
    assert parsed_npmrc.unresolved is True

    # Nested .gemini/settings.json and duplicate static tool names
    nested_gemini = tmp_path / "packages" / "sub" / ".gemini"
    nested_gemini.mkdir(parents=True)
    (nested_gemini / "settings.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "nested-srv": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-memory@0.6.2"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    dup_cfg = tmp_path / ".mcp.json"
    dup_cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "dup-srv": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-memory@0.6.2"],
                        "tools": [
                            {"name": "ping", "description": "first"},
                            {"name": "ping", "description": "second"},
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    scan_res = MCPScanner().scan(tmp_path)
    servers = [c for c in scan_res.components if isinstance(c, MCPServerComponent)]
    assert any(s.name == "nested-srv" for s in servers)
    assert any(".mcp.json: invalid tool definition" in f for f in scan_res.scan_failures)


def test_live_mcp_rejects_external_schema_refs_vocabularies_and_non_ascii_content_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Allowed local $defs reference and properties literally named $id / $schema
    valid_tool = check_served_tool(
        {
            "name": "search_docs",
            "description": "Search docs",
            "inputSchema": {
                "type": "object",
                "$defs": {"Query": {"type": "string"}},
                "properties": {
                    "q": {"$ref": "#/$defs/Query"},
                    "$id": {"type": "string"},
                    "$schema": {"type": "string"},
                },
            },
        }
    )
    assert valid_tool.name == "search_docs"

    bad_schemas: list[dict[str, Any]] = [
        {"type": "object", "$ref": "https://attacker.example/schema.json"},
        {"type": "object", "properties": {"x": {"$dynamicRef": "https://attacker.example/s#x"}}},
        {"type": "object", "$id": "https://attacker.example/root.json"},
        {
            "type": "object",
            "properties": {"x": {"$schema": "http://json-schema.org/draft-07/schema#"}},
        },
        {
            "type": "object",
            "$vocabulary": {"https://attacker.example/vocab/custom": True},
        },
    ]
    for schema in bad_schemas:
        with pytest.raises(DiscoveryError):
            check_served_tool({"name": "bad", "inputSchema": schema})

    # Non-ASCII digit Content-Length ("\uff11\uff10") must be refused
    fake_resp = MagicMock()
    fake_resp.status = 200
    fake_resp.getheaders.return_value = [
        ("Content-Type", "application/json"),
        ("Content-Length", "\uff11\uff10"),
    ]
    fake_conn = MagicMock()
    fake_conn.getresponse.return_value = fake_resp
    transport = PinnedHTTPTransport()
    transport._peers[("mcp.example.com", 443)] = (2, "93.184.216.34")
    monkeypatch.setattr(
        "nexus_symbiote.scanners.live_mcp._PinnedHTTPSConnection",
        lambda *_args, **_kwargs: fake_conn,
    )
    with pytest.raises(DiscoveryError, match="HTTP body length refused"):
        transport.request(
            "https://mcp.example.com/mcp",
            b"{}",
            {"Accept": "application/json"},
            timeout=5.0,
            max_bytes=1024,
        )


def test_registry_scanner_tarball_mismatch_pnpm_risks_and_patched_dependencies(
    tmp_path: Path,
) -> None:
    assert RegistryScanner._tarball_matches(
        "https://npm.pkg.github.com",
        "/download/@modelcontextprotocol/sdk/1.2.0/sdk-1.2.0.tgz",
        "@modelcontextprotocol/sdk",
        "1.2.0",
    )
    assert not RegistryScanner._tarball_matches(
        "https://npm.pkg.github.com",
        "/download/evil-backdoor/9.9.9/evil-9.9.9.tgz",
        "@modelcontextprotocol/sdk",
        "1.2.0",
    )

    # pnpm lockfile without integrity and with non-default registry + patchedDependencies
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-app",
                "version": "1.0.0",
                "dependencies": {"openai": "4.80.0"},
                "pnpm": {"patchedDependencies": {"openai@4.80.0": "patches/openai.patch"}},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      openai:\n"
        "        specifier: 4.80.0\n"
        "        version: 4.80.0\n"
        "packages:\n"
        "  openai@4.80.0:\n"
        "    resolution:\n"
        "      tarball: https://npm.custom-corp.example/openai/-/openai-4.80.0.tgz\n",
        encoding="utf-8",
    )
    res = RegistryScanner().scan(tmp_path)
    entries = [
        c for c in res.components if isinstance(c, RegistryEntryComponent) and c.name == "openai"
    ]
    assert len(entries) == 1
    # Patched dependency is excluded from registry resolution binding as a local override
    assert any(
        "override" in g.lower() or "patch" in g.lower() or "package.json" in g
        for g in res.surfaces_excluded
    )

    # Now test pnpm resolution without patchedDependencies to verify missing_lockfile_integrity + registry_origin
    pkg_dir = tmp_path / "unpatched"
    pkg_dir.mkdir()
    (pkg_dir / "package.json").write_text(
        json.dumps({"name": "demo2", "version": "1.0.0", "dependencies": {"openai": "4.80.0"}}),
        encoding="utf-8",
    )
    (pkg_dir / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      openai:\n"
        "        specifier: 4.80.0\n"
        "        version: 4.80.0\n"
        "packages:\n"
        "  openai@4.80.0:\n"
        "    resolution:\n"
        "      tarball: https://npm.custom-corp.example/openai/-/openai-4.80.0.tgz\n",
        encoding="utf-8",
    )
    res2 = RegistryScanner().scan(pkg_dir)
    comp2 = next(
        c for c in res2.components if isinstance(c, RegistryEntryComponent) and c.name == "openai"
    )
    categories = {r.category for r in comp2.risks}
    assert "missing_lockfile_integrity" in categories
    assert "registry_origin" in categories

    # Python lockfile resolving over cleartext HTTP from a private index
    py_dir = tmp_path / "py-http"
    py_dir.mkdir()
    (py_dir / "pyproject.toml").write_text(
        '[project]\ndependencies = ["langgraph>=0.2.0"]\n',
        encoding="utf-8",
    )
    (py_dir / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "langgraph"\nversion = "0.2.14"\n'
        'source = { registry = "http://pypi.corp.example/simple" }\n',
        encoding="utf-8",
    )
    res3 = RegistryScanner().scan(py_dir)
    comp3 = next(
        c
        for c in res3.components
        if isinstance(c, RegistryEntryComponent) and c.name == "langgraph"
    )
    py_categories = {(r.category, r.severity.value) for r in comp3.risks}
    assert ("transport_security", "high") in py_categories
    assert ("registry_origin", "low") in py_categories


def test_model_scanner_second_zip_pickle_member_jinja2_and_nested_custom_code(
    tmp_path: Path,
) -> None:
    # ZIP container disguised as .onnx where first member is benign and second member is data.pkl
    disguised = tmp_path / "model.onnx"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/version", b"3\n")
        zf.writestr("archive/data.pkl", b"\x80\x04\x95\x02\x00\x00\x00\x00\x00\x00\x00N.")
    disguised.write_bytes(buf.getvalue())

    safety, reason = inspect_model_format(disguised)
    assert safety == SerializationSafety.UNSAFE_CODE_EXECUTION
    assert "pickle member" in reason

    # Also test streaming data-descriptor ZIP (flag 0x08) via Central Directory fallback
    stream_zip = tmp_path / "streamed.onnx"
    raw_bytes = bytearray(buf.getvalue())
    # Set general-purpose bit 3 (0x08) on first local header so sequential walk falls back to CD
    raw_bytes[6] |= 0x08
    stream_zip.write_bytes(bytes(raw_bytes))
    with stream_zip.open("rb") as f:
        obs = observe_model_artifact(stream_zip, stream=f)
    assert obs.safety == SerializationSafety.UNSAFE_CODE_EXECUTION
    assert "pickle member" in obs.explanation

    # Model directory with additional_chat_templates/default.jinja2 and nested subpkg/modeling.py
    mdir = tmp_path / "hf_model"
    (mdir / "additional_chat_templates").mkdir(parents=True)
    (mdir / "subpkg").mkdir(parents=True)
    (mdir / "config.json").write_text(
        json.dumps({"model_type": "llama", "auto_map": {"AutoModel": "subpkg.modeling.MyModel"}}),
        encoding="utf-8",
    )
    (mdir / "additional_chat_templates" / "default.jinja2").write_text(
        "{{ '' | attr('__class__') }}",
        encoding="utf-8",
    )
    (mdir / "subpkg" / "modeling.py").write_text("class MyModel:\n    pass\n", encoding="utf-8")
    # Minimal valid safetensors file: 8-byte header length + "{}"
    (mdir / "model.safetensors").write_bytes((2).to_bytes(8, "little") + b"{}")

    mres = ModelScanner().scan(mdir)
    mcomp = next(c for c in mres.components if isinstance(c, ModelComponent))
    assert any("CVE-2024-34359" in ref for r in mcomp.risks for ref in r.references)
    assert any(
        entry["source"].endswith("default.jinja2")
        for entry in mcomp.properties.get("chat_templates", [])
    )
    custom = mcomp.properties.get("custom_code", {})
    assert any(
        entry["path"].endswith("subpkg/modeling.py") for entry in custom.get("python_files", [])
    )


def test_ide_agents_subshell_grants_dont_ask_and_codex_full_access(tmp_path: Path) -> None:
    assert "shell commands" in _broad_grants(["Bash(sh -c *)"])
    assert "shell commands" in _broad_grants(["Bash(/bin/bash -c *)"])
    assert "shell commands" in _broad_grants(["Bash(python3 -c *)"])
    assert _broad_grants(["Bash(git status)"]) == []

    risk = _starting_mode_risk("claude-code", "dontAsk")
    assert risk is not None and risk.severity == RiskSeverity.MEDIUM

    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text(
        'sandbox_mode = "full-access"\napproval_policy = "on-request"\n',
        encoding="utf-8",
    )
    ide_res = IDEAgentScanner().scan(tmp_path)
    codex = next(c for c in ide_res.components if isinstance(c, IDEAgentComponent))
    assert any(
        r.severity == RiskSeverity.HIGH and r.category == "permission_scope" for r in codex.risks
    )


def test_a2a_secondary_cleartext_interface_ts_escaped_namespace_and_nested_cyclonedx(
    tmp_path: Path,
) -> None:
    # A2A card with HTTPS primary URL but HTTP additionalInterfaces fallback
    well_known = tmp_path / ".well-known"
    well_known.mkdir()
    (well_known / "agent.json").write_text(
        json.dumps(
            {
                "name": "billing-agent",
                "url": "https://agent.example.com/a2a",
                "version": "1.0.0",
                "capabilities": {},
                "skills": [{"id": "s1", "name": "Skill 1"}],
                "additionalInterfaces": [
                    {"url": "http://cleartext.example.com/a2a", "transport": "JSONRPC"}
                ],
            }
        ),
        encoding="utf-8",
    )
    a2a_res = A2AScanner().scan(tmp_path)
    agent = next(c for c in a2a_res.components if isinstance(c, A2AServerComponent))
    assert any(r.category == "transport_security" for r in agent.risks)

    # TypeScript namespace import with hex-escaped McpServer property
    ts_dir = tmp_path / "ts_proj"
    ts_dir.mkdir()
    (ts_dir / "server.ts").write_text(
        'import * as sdk from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        'const server = new sdk["\\x4dcpServer"]({ name: "hex-srv", version: "1.0.0" });\n'
        'server.registerTool("lookup", {}, async () => ({ content: [] }));\n',
        encoding="utf-8",
    )
    ts_res = MCPScanner().scan(ts_dir)
    tools = [c for c in ts_res.components if isinstance(c, ToolComponent)]
    assert [t.name for t in tools] == ["lookup"]

    # ShadowScan CycloneDX nested components flattening
    cdx_path = tmp_path / "shadowscan-cdx.json"
    cdx_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {
                    "properties": [{"name": "shadowscan:scan:status", "value": "complete"}]
                },
                "components": [
                    {
                        "type": "application",
                        "bom-ref": "parent-app",
                        "name": "parent-app",
                        "properties": [
                            {"name": "shadowscan:kind", "value": "agent"},
                            {"name": "shadowscan:shadow", "value": "false"},
                        ],
                        "components": [
                            {
                                "type": "service",
                                "group": "mcp-server",
                                "bom-ref": "nested-mcp-server",
                                "name": "nested-mcp-server",
                                "properties": [
                                    {"name": "shadowscan:kind", "value": "mcp-server"},
                                    {"name": "shadowscan:shadow", "value": "true"},
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    imported = ShadowScanImporter().import_report(cdx_path)
    assert any(isinstance(c, MCPServerComponent) for c in imported.components)
    assert len(imported.components) == 2
