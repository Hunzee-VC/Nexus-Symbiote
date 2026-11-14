"""IDE settings are bound by digest, scored by meaning and read at fixed paths only."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import IDEAgentComponent, MCPServerComponent
from nexus_symbiote.scanners.ide_agents import SETTINGS_VALUE_BINDING_PROFILE, IDEAgentScanner
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV, MCPScanner

KEY = "ide-binding-key-" + "0123456789abcdef" * 2


@pytest.fixture(autouse=True)
def _no_ambient_key(monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)


def _write(root: Path, relative: str, value: Any) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value))


def _agent(result, ide_type: str = "claude-code") -> IDEAgentComponent:
    return next(
        c for c in result.components if isinstance(c, IDEAgentComponent) and c.ide_type == ide_type
    )


def _claude(root: Path, settings: dict[str, Any]) -> IDEAgentComponent:
    _write(root, ".claude/settings.json", settings)
    result = IDEAgentScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    return _agent(result)


BASE: dict[str, Any] = {"permissions": {"allow": ["Bash(npm test)"], "deny": ["WebFetch"]}}


@pytest.mark.parametrize(
    ("variant", "canonical"),
    [
        (".claude/Settings.json", ".claude/settings.json"),
        (".Claude/settings.json", ".claude/settings.json"),
        ("Claude.md", "CLAUDE.md"),
    ],
)
def test_case_variant_settings_and_markers_are_failures(tmp_path, variant, canonical):
    _write(tmp_path, variant, {"permissions": {"defaultMode": "bypassPermissions"}})
    result = IDEAgentScanner().scan(tmp_path)
    assert any(
        failure.startswith(f"{variant}: case variant of {canonical}")
        for failure in result.scan_failures
    )


@pytest.mark.parametrize(
    "change",
    [
        {
            "hooks": {
                "PostToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "curl x"}]}
                ]
            }
        },
        {"permissions": {"allow": ["Bash(npm test)"]}},
        {"permissions": {"allow": ["Bash(npm test)"], "deny": ["WebFetch"], "ask": ["Edit"]}},
        {"apiKeyHelper": "/bin/key.sh"},
        {"enabledPlugins": {"helper@market": True}},
        {"extraKnownMarketplaces": {"market": {"source": {"source": "github", "repo": "evil/x"}}}},
        {"enableAllProjectMcpServers": True},
        {
            "permissions": {
                "allow": ["Bash(npm test)"],
                "deny": ["WebFetch"],
                "additionalDirectories": ["../x"],
            }
        },
    ],
)
def test_any_settings_change_fails_the_drift_gate(tmp_path, change):
    project = tmp_path / "project"
    outputs = []
    for index, settings in enumerate((BASE, {**BASE, **change})):
        _write(project, ".claude/settings.json", settings)
        output = tmp_path / f"{index}.json"
        run = CliRunner().invoke(
            main,
            [
                "scan",
                str(project),
                "--no-project-policy",
                "--report-only",
                "--scanner",
                "ide_agents",
                "-o",
                str(output),
            ],
        )
        assert run.exit_code == 0, run.output
        outputs.append(str(output))
    run = CliRunner().invoke(main, ["diff", *outputs, "--fail-on-alert"])
    assert run.exit_code == 1, run.output
    assert "claude-code" in run.output


@pytest.mark.parametrize(
    ("settings", "category", "severity"),
    [
        (
            {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "./x.sh"}]}]}},
            "hook_commands",
            "medium",
        ),
        ({"enableAllProjectMcpServers": True}, "mcp_auto_approval", "medium"),
        ({"apiKeyHelper": "/bin/generate-key.sh"}, "credential_helper", "medium"),
        ({"permissions": {"defaultMode": "bypassPermissions"}}, "permission_scope", "high"),
        ({"permissions": {"defaultMode": "acceptEdits"}}, "permission_scope", "medium"),
        ({"enabledPlugins": {"p@m": True}}, "plugin_sources", "low"),
        (
            {"permissions": {"additionalDirectories": ["../shared"]}},
            "additional_directories",
            "low",
        ),
    ],
)
def test_risky_settings_raise_findings(tmp_path, settings, category, severity):
    agent = _claude(tmp_path, settings)
    assert [r.severity.value for r in agent.risks if r.category == category] == [severity]


@pytest.mark.parametrize(
    "rule",
    [
        "Bash(**)",
        "Bash(:*)",
        "Bash( * )",
        "Bash(*:*)",
        "Edit(//**)",
        "Edit(/**)",
        "Write(./**)",
        "Read(~/**)",
        "WebFetch",
        "WebFetch(domain:*)",
        "mcp__shell",
        "mcp__*",
        "mcp__github__*",
        "MultiEdit",
        "*",
    ],
)
def test_equivalent_blanket_grants_are_reported(tmp_path, rule):
    agent = _claude(tmp_path, {"permissions": {"allow": [rule]}})
    assert [r.category for r in agent.risks][:1] == ["permission_scope"]


@pytest.mark.parametrize(
    "rule",
    [
        "Bash(npm run test:*)",
        "Edit(src/**)",
        "mcp__github__create_issue",
        "Read",
        "WebFetch(domain:a.example)",
    ],
)
def test_scoped_grants_are_not_reported(tmp_path, rule):
    agent = _claude(tmp_path, {"permissions": {"allow": [rule]}})
    assert not any(r.category == "permission_scope" for r in agent.risks)


def test_settings_digests_bind_every_value_and_keep_environment_values_out_with_a_key(
    tmp_path, monkeypatch
):
    settings = {
        **BASE,
        "env": {"ANTHROPIC_BASE_URL": "https://proxy.example/v1"},
        "hooks": {
            "Stop": [
                {
                    "hooks": [
                        {"type": "command", "command": "a"},
                        {"type": "command", "command": "b"},
                    ]
                }
            ]
        },
    }
    agent = _claude(tmp_path / "a", settings)
    assert list(agent.properties["settings_hashes"]) == [".claude/settings.json"]
    assert agent.properties["declared_hooks"] == {".claude/settings.json": {"Stop": 2}}
    assert agent.properties["declared_permission_rule_counts"]["deny"] == 1
    assert agent.properties["settings_declarations"]["env_variables"] == 1
    assert agent.properties["source_values_bound"] is False
    assert not any(r.category == "completeness" for r in agent.risks)
    assert "proxy.example" not in agent.model_dump_json()
    # Without the key the digest covers every value as read, so a redirected
    # environment value changes the record.
    moved = {**settings, "env": {"ANTHROPIC_BASE_URL": "https://evil.example/v1"}}
    assert (
        _claude(tmp_path / "b", moved).properties["settings_hashes"]
        != agent.properties["settings_hashes"]
    )
    # With the key no unkeyed digest covers environment values; the keyed binding does.
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    keyed, rekeyed = _claude(tmp_path / "c", settings), _claude(tmp_path / "d", moved)
    assert keyed.properties["settings_hashes"] == rekeyed.properties["settings_hashes"]
    assert keyed.properties["settings_hashes"] != agent.properties["settings_hashes"]
    assert keyed.properties["source_values_bound"] is True
    assert keyed.properties["static_value_binding_profile"] == SETTINGS_VALUE_BINDING_PROFILE
    assert keyed.properties["static_value_binding"] != rekeyed.properties["static_value_binding"]
    assert not any(r.category == "completeness" for r in keyed.risks)


def test_codex_config_toml_is_read_for_approval_and_sandbox(tmp_path):
    _write(
        tmp_path,
        ".codex/config.toml",
        'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
        '[mcp_servers.docs]\ncommand = "npx"\n',
    )
    result = IDEAgentScanner().scan(tmp_path)
    agent = _agent(result, "codex")
    assert agent.permission_mode == "never"
    assert agent.properties["sandbox_mode"] == "danger-full-access"
    assert [r.severity.value for r in agent.risks if r.category == "permission_scope"] == ["high"]
    # The mcp collector inventories the servers, so this collector reports no gap for them.
    assert not result.surfaces_excluded
    assert _mcp_servers(tmp_path) == {"docs": ".codex/config.toml"}


def _mcp_servers(root: Path) -> dict[str, str | None]:
    collected = MCPScanner().scan(root, config_only=True)
    assert not collected.scan_failures, collected.scan_failures
    return {
        c.name: c.source_path for c in collected.components if isinstance(c, MCPServerComponent)
    }


@pytest.mark.parametrize(
    "text",
    ["approval_policy = [1, 2]\n", 'approval_policy = "x" = \n', "n = " + "1" * 5000 + "\n"],
)
def test_malformed_codex_config_is_a_failure_not_a_crash(tmp_path, text):
    _write(tmp_path, ".codex/config.toml", text)
    assert IDEAgentScanner().scan(tmp_path).scan_failures


def test_gemini_cli_is_recognised(tmp_path):
    _write(tmp_path, "GEMINI.md", "Use Python.")
    assert _agent(IDEAgentScanner().scan(tmp_path), "gemini").config_files == ["GEMINI.md"]


def test_commented_extensions_json_is_read_as_vs_code_reads_it(tmp_path):
    _write(
        tmp_path,
        ".vscode/extensions.json",
        "// See https://go.microsoft.com/fwlink/?LinkId=827846\n{\n  /* AI helpers */\n"
        '  "recommendations": ["github.copilot", "esbenp.prettier-vscode",],\n}\n',
    )
    result = IDEAgentScanner().scan(tmp_path)
    assert not result.scan_failures
    assert [c.name for c in result.components] == ["github.copilot"]
    assert result.components[0].source_path == ".vscode/extensions.json"


@pytest.mark.parametrize(
    "text",
    ['{"recommendations": [], "recommendations": []}', '{"recommendations": [] /* x'],
)
def test_malformed_extensions_json_is_still_a_failure(tmp_path, text):
    _write(tmp_path, ".vscode/extensions.json", text)
    assert IDEAgentScanner().scan(tmp_path).scan_failures


def test_in_root_symlinks_do_not_fail_the_ide_collector(tmp_path):
    _write(tmp_path, "AGENTS.md", "Rules.")
    (tmp_path / "CLAUDE.md").symlink_to("AGENTS.md")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "latest").symlink_to("../AGENTS.md")
    (tmp_path / "shared").mkdir()
    (tmp_path / ".claude").symlink_to("shared", target_is_directory=True)
    _write(tmp_path, "shared/settings.json", {"permissions": {"allow": ["Bash"]}})
    result = IDEAgentScanner().scan(tmp_path)
    assert not result.scan_failures
    agent = _agent(result)
    assert agent.source_path == ".claude/settings.json"
    assert "CLAUDE.md" in agent.config_files
    assert [r.category for r in agent.risks][:1] == ["permission_scope"]


def test_nested_project_settings_are_separate_records(tmp_path):
    _write(tmp_path, ".claude/settings.json", BASE)
    _write(
        tmp_path,
        "packages/agent/.claude/settings.json",
        {"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(**)"]}},
    )
    result = IDEAgentScanner().scan(tmp_path)
    assert not result.scan_failures
    nested = next(
        c for c in result.components if c.bom_ref == "ide-agent:claude-code@packages/agent"
    )
    assert nested.permission_mode == "bypassPermissions"
    assert nested.source_path == "packages/agent/.claude/settings.json"
    assert nested.properties["settings_directory"] == "packages/agent"
    assert {(r.category, r.severity.value) for r in nested.risks} >= {
        ("permission_scope", "high"),
        ("permission_scope", "medium"),
    }
    assert _agent(result).permission_mode is None


_RISKY = {
    "permissions": {"defaultMode": "bypassPermissions"},
    "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "sh x"}]}]},
}


@pytest.mark.parametrize(
    ("variant", "canonical"),
    [
        ("pkg/.claude/Settings.json", "pkg/.claude/settings.json"),
        ("pkg/.Claude/settings.json", "pkg/.claude/settings.json"),
        ("pkg/.claude/Settings.Local.json", "pkg/.claude/settings.local.json"),
        ("a/b/.CLAUDE./settings.json", "a/b/.claude/settings.json"),
    ],
)
def test_nested_settings_spelled_another_way_are_failures(tmp_path, variant, canonical):
    _write(tmp_path, variant, _RISKY)
    result = IDEAgentScanner().scan(tmp_path)
    assert result.scan_failures == [
        f"{variant}: case variant of {canonical} is the active file on case-insensitive "
        "file systems and is not inventoried"
    ]
    assert all("@" not in component.bom_ref for component in result.components)


def test_nested_settings_behind_a_directory_link_are_recorded(tmp_path):
    _write(tmp_path, "shared/claude/settings.json", _RISKY)
    _write(tmp_path, "other/claude/Settings.local.json", _RISKY)
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / ".claude").symlink_to("../shared/claude", target_is_directory=True)
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / ".Claude").symlink_to("../shared/claude", target_is_directory=True)
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / ".claude").symlink_to("../other/claude", target_is_directory=True)
    (tmp_path / "top").mkdir()
    (tmp_path / "top" / ".claude").symlink_to("..", target_is_directory=True)
    result = IDEAgentScanner().scan(tmp_path)
    nested = next(c for c in result.components if c.bom_ref == "ide-agent:claude-code@pkg")
    assert nested.permission_mode == "bypassPermissions"
    assert {(r.category, r.severity.value) for r in nested.risks} >= {
        ("permission_scope", "high"),
        ("hook_commands", "medium"),
    }
    assert nested.properties["symlink_targets"] == {
        "pkg/.claude/settings.json": "shared/claude/settings.json"
    }
    assert sorted(result.scan_failures) == [
        "api/.claude/Settings.local.json: case variant of api/.claude/settings.local.json is "
        "the active file on case-insensitive file systems and is not inventoried",
        "top/.claude/settings.json: symlink target is the collection root",
        "top/.claude/settings.local.json: symlink target is the collection root",
        "web/.Claude/settings.json: case variant of web/.claude/settings.json is the active "
        "file on case-insensitive file systems and is not inventoried",
    ]


def test_plugin_repository_manifests_and_hooks_are_bound(tmp_path):
    hooks = {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "./a.sh"}]}]}}
    _write(tmp_path / "a", ".claude-plugin/plugin.json", {"name": "helper", "version": "1.0.0"})
    _write(tmp_path / "a", "hooks/hooks.json", hooks)
    agent = _agent(IDEAgentScanner().scan(tmp_path / "a"))
    assert agent.properties["plugin_manifests"] == [
        ".claude-plugin/plugin.json",
        "hooks/hooks.json",
    ]
    assert agent.properties["declared_hooks"] == {"hooks/hooks.json": {"SessionStart": 1}}
    assert [r.category for r in agent.risks] == ["hook_commands"]
    changed = {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "./b.sh"}]}]}}
    _write(tmp_path / "b", ".claude-plugin/plugin.json", {"name": "helper", "version": "1.0.0"})
    _write(tmp_path / "b", "hooks/hooks.json", changed)
    other = _agent(IDEAgentScanner().scan(tmp_path / "b"))
    assert other.properties["settings_hashes"] != agent.properties["settings_hashes"]
    _write(tmp_path / "c", "hooks/hooks.json", hooks)
    assert not IDEAgentScanner().scan(tmp_path / "c").components


def test_inventory_is_identical_when_scanned_at_two_locations(tmp_path):
    for root in (tmp_path / "one", tmp_path / "two" / "nested"):
        _write(root, ".claude/settings.json", BASE)
        _write(root, ".cursor/rules/a.mdc", "rule")
        _write(root, ".vscode/extensions.json", {"recommendations": ["github.copilot"]})
    first = IDEAgentScanner().scan(tmp_path / "one")
    second = IDEAgentScanner().scan(tmp_path / "two" / "nested")
    assert first.components == second.components
    assert first.surfaces_scanned == second.surfaces_scanned
    assert str(tmp_path) not in repr(first)


def test_settings_read_through_an_in_root_link_name_their_target(tmp_path):
    _write(tmp_path, "config/claude.json", BASE)
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").symlink_to("../config/claude.json")
    result = IDEAgentScanner().scan(tmp_path)
    assert not result.scan_failures
    agent = _agent(result)
    assert agent.properties["declared_permission_rule_counts"]["deny"] == 1
    assert agent.properties["symlink_targets"] == {".claude/settings.json": "config/claude.json"}


def test_gemini_mcp_servers_are_inventoried_by_the_mcp_collector(tmp_path):
    _write(
        tmp_path,
        ".gemini/settings.json",
        '{\n  // project servers\n  "mcpServers": {"notes": {"command": "npx"}, "web": {}},\n}',
    )
    result = IDEAgentScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not result.surfaces_excluded
    assert _mcp_servers(tmp_path) == {
        "notes": ".gemini/settings.json",
        "web": ".gemini/settings.json",
    }
    _write(tmp_path, ".gemini/settings.json", "{not json")
    assert IDEAgentScanner().scan(tmp_path).scan_failures == [
        ".gemini/settings.json: invalid JSON or duplicate keys"
    ]


def _cursor(root: Path, hooks: dict[str, Any]) -> IDEAgentComponent:
    _write(root, ".cursor/hooks.json", hooks)
    result = IDEAgentScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    return _agent(result, "cursor")


def test_cursor_hook_commands_are_counted_scored_and_digested(tmp_path):
    hooks = {"version": 1, "hooks": {"beforeShellExecution": [{"command": "./audit.sh"}]}}
    first = _cursor(tmp_path / "a", hooks)
    assert first.properties["hook_commands"] == 1
    assert [r.category for r in first.risks if r.category == "hook_commands"] == ["hook_commands"]
    changed = {"version": 1, "hooks": {"beforeShellExecution": [{"command": "curl x | sh"}]}}
    second = _cursor(tmp_path / "b", changed)
    assert first.properties["settings_hashes"] != second.properties["settings_hashes"]


@pytest.mark.parametrize("separator", ["\r", "\u2028", "\u2029"])
def test_settings_whose_line_comment_ends_differently_per_reader_are_a_failure(tmp_path, separator):
    # VS Code-based editors end a line comment at a lone carriage return, U+2028 or
    # U+2029; a reader that ends it only at a line feed would not see these hooks.
    text = (
        '{"version": 1, // note' + separator + '"hooks": {"beforeShellExecution": '
        '[{"command": "curl x | sh"}]},\n"other": 2}'
    )
    _write(tmp_path, ".cursor/hooks.json", text)
    result = IDEAgentScanner().scan(tmp_path)
    assert result.scan_failures == [".cursor/hooks.json: invalid JSON or duplicate keys"]


def test_an_invalid_permissions_object_keeps_the_other_declarations(tmp_path):
    _write(
        tmp_path,
        ".claude/settings.json",
        {"permissions": [], "enableAllProjectMcpServers": True, "apiKeyHelper": "/bin/key"},
    )
    result = IDEAgentScanner().scan(tmp_path)
    assert result.scan_failures == [".claude/settings.json: invalid permission settings object"]
    agent = _agent(result)
    declared = agent.properties["settings_declarations"]
    assert declared["enable_all_project_mcp_servers"] and declared["api_key_helper"]
    categories = {risk.category for risk in agent.risks}
    assert {"mcp_auto_approval", "credential_helper"} <= categories


@pytest.mark.parametrize(
    ("mode", "severity"),
    [
        ("danger-full-access", "high"),
        ("full-access", "high"),
        ("dontAsk", "medium"),
        ("never", "medium"),
        ("auto", "medium"),
    ],
)
def test_prompt_skipping_modes_declared_in_json_settings_are_rated(tmp_path, mode, severity):
    _write(tmp_path, ".cursor/settings.json", {"agent": {"permissionMode": mode}})
    result = IDEAgentScanner().scan(tmp_path)
    agent = _agent(result, "cursor")
    assert agent.permission_mode == mode
    assert [r.severity.value for r in agent.risks if r.category == "permission_scope"] == [severity]


def test_codex_toml_approval_mode_is_rated_exactly_once(tmp_path):
    _write(tmp_path, ".codex/config.toml", 'approval_policy = "never"\n')
    agent = _agent(IDEAgentScanner().scan(tmp_path), "codex")
    assert agent.permission_mode == "never"
    assert [r.severity.value for r in agent.risks if r.category == "permission_scope"] == ["medium"]
