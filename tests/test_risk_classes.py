"""Risk classes restate recorded evidence exactly, and unknown evidence stays unassessed."""

from __future__ import annotations

import itertools
import json
import pickle
from pathlib import Path

import pytest

from nexus_symbiote.core.enums import CapabilityClass, SerializationSafety, SideEffectProfile
from nexus_symbiote.core.models import (
    A2AClientComponent,
    A2AServerComponent,
    AgentComponent,
    CapabilityDeclaration,
    IDEAgentComponent,
    MCPClientComponent,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    RAGSourceComponent,
    RegistryEntryComponent,
    SkillPackageComponent,
    ToolComponent,
    VerifiedExtensionComponent,
)
from nexus_symbiote.risk_classes import BASIS, RiskClass, RiskClassification, classify
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import ModelScanner

ROOT = Path(__file__).resolve().parents[1]
UNASSESSED = RiskClassification(classes=(), basis=(), assessed=False)
NONE_DERIVED = RiskClassification(classes=(), basis=(), assessed=True)


def tool(*capabilities: CapabilityClass, **declared: object) -> ToolComponent:
    return ToolComponent(
        bom_ref="tool:t",
        name="t",
        capabilities=CapabilityDeclaration(capabilities=list(capabilities), **declared),
    )


@pytest.mark.parametrize(
    ("capability", "risk"),
    [
        (CapabilityClass.EXECUTE, RiskClass.CODE_EXEC),
        (CapabilityClass.WRITE, RiskClass.WRITE_CAPABLE),
        (CapabilityClass.DESTRUCTIVE, RiskClass.WRITE_CAPABLE),
        (CapabilityClass.PAYMENT, RiskClass.WRITE_CAPABLE),
        (CapabilityClass.NETWORK, RiskClass.NETWORK_EGRESS),
        (CapabilityClass.CREDENTIALS, RiskClass.SECRET_ACCESS),
    ],
)
def test_each_declared_capability_gives_its_class(capability, risk):
    assert classify(tool(capability)) == RiskClassification(
        classes=(risk,), basis=(f"capabilities:{capability.value}",), assessed=True
    )


@pytest.mark.parametrize(
    "profile",
    [
        SideEffectProfile.STATE_MODIFYING,
        SideEffectProfile.DESTRUCTIVE,
        SideEffectProfile.FINANCIAL_TRANSACTION,
    ],
)
def test_a_side_effect_that_changes_state_is_write_capable(profile):
    assert classify(tool(side_effect_profile=profile)) == RiskClassification(
        classes=(RiskClass.WRITE_CAPABLE,),
        basis=(f"side_effect_profile:{profile.value}",),
        assessed=True,
    )


def test_declared_egress_domains_are_network_egress():
    assert classify(tool(egress_domains=["api.example.com"])) == RiskClassification(
        classes=(RiskClass.NETWORK_EGRESS,), basis=("egress_domains:declared",), assessed=True
    )


@pytest.mark.parametrize(
    "source", [CapabilityClass.READ, CapabilityClass.FILESYSTEM, CapabilityClass.CREDENTIALS]
)
def test_network_with_something_to_send_is_exfil_capable(source):
    result = classify(tool(CapabilityClass.NETWORK, source))
    assert RiskClass.EXFIL_CAPABLE in result.classes
    assert {"capabilities:network", f"capabilities:{source.value}"} <= set(result.basis)


def test_declared_egress_domains_with_a_read_source_are_exfil_capable():
    result = classify(tool(CapabilityClass.READ, egress_domains=["upload.example.com"]))
    assert result.classes == (RiskClass.EXFIL_CAPABLE, RiskClass.NETWORK_EGRESS)
    assert result.basis == ("capabilities:read", "egress_domains:declared")


def test_network_without_a_read_source_is_not_exfil_capable():
    result = classify(tool(CapabilityClass.NETWORK, CapabilityClass.WRITE, CapabilityClass.EXECUTE))
    assert RiskClass.EXFIL_CAPABLE not in result.classes
    assert result.classes == (
        RiskClass.CODE_EXEC,
        RiskClass.NETWORK_EGRESS,
        RiskClass.WRITE_CAPABLE,
    )


def test_a_read_source_without_network_derives_nothing_but_is_assessed():
    assert classify(tool(CapabilityClass.READ, CapabilityClass.FILESYSTEM)) == NONE_DERIVED
    assert classify(tool(side_effect_profile=SideEffectProfile.READ_ONLY)) == NONE_DERIVED


def test_an_empty_declaration_is_unassessed():
    assert classify(tool()) == UNASSESSED
    assert classify(ToolComponent(bom_ref="tool:t", name="t")) == UNASSESSED


def test_declaration_fields_no_rule_reads_leave_it_unassessed():
    declared = tool(
        oauth_scopes=["repo"],
        filesystem_paths=["/srv"],
        execution_isolation="none",
        human_in_the_loop="none",
    )
    assert classify(declared) == UNASSESSED


@pytest.mark.parametrize(
    "component_class",
    [
        AgentComponent,
        SkillPackageComponent,
        A2AClientComponent,
        A2AServerComponent,
        VerifiedExtensionComponent,
    ],
)
def test_every_type_with_a_declaration_is_classified_by_it(component_class):
    component = component_class(
        bom_ref="c",
        name="c",
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.EXECUTE, CapabilityClass.NETWORK, CapabilityClass.READ]
        ),
    )
    assert classify(component).classes == (
        RiskClass.CODE_EXEC,
        RiskClass.EXFIL_CAPABLE,
        RiskClass.NETWORK_EGRESS,
    )


@pytest.mark.parametrize(
    ("endpoint", "basis"),
    [
        ("https://mcp.example.com", "endpoint_url:remote"),
        ("http://10.0.0.8:8080", "endpoint_url:remote"),
        ("https://localhost.example.com", "endpoint_url:remote"),
        ("http://0.0.0.0:3000", "endpoint_url:remote"),
        ("http://mcp_server:8080", "endpoint_url:remote"),
        # Interpreters disagree on whether an IPv4-mapped address is loopback.
        ("http://[::ffff:127.0.0.1]:8080", "endpoint_url:remote"),
        ("http://localhost..:8080", "endpoint_url:remote"),
        ("[redacted]", "endpoint_url:unresolved"),
        ("https://[bad", "endpoint_url:unresolved"),
        # WHATWG parsers, as in Node-based MCP clients, connect to evil.example here.
        ("http://evil.example\\@localhost/mcp", "endpoint_url:unresolved"),
        ("http://evil.example\\@127.0.0.1:8080/", "endpoint_url:unresolved"),
        ("http://localhost\\@evil.example/", "endpoint_url:unresolved"),
        ("http://user@localhost/", "endpoint_url:unresolved"),
        ("http://%6cocalhost/", "endpoint_url:unresolved"),
        ("http://localhost:99999/", "endpoint_url:unresolved"),
        ("http://localhost:/", "endpoint_url:unresolved"),
        ("http://ｌｏｃａｌｈｏｓｔ/", "endpoint_url:unresolved"),
        ("stdio://localhost", "endpoint_url:unresolved"),
        ("file://localhost/srv/mcp.sock", "endpoint_url:unresolved"),
    ],
)
def test_a_remote_or_unresolved_mcp_endpoint_is_network_egress(endpoint, basis):
    server = MCPServerComponent(bom_ref="s", name="s", endpoint_url=endpoint)
    assert classify(server) == RiskClassification(
        classes=(RiskClass.NETWORK_EGRESS,), basis=(basis,), assessed=True
    )


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://localhost:8080",
        "http://LOCALHOST.:1",
        "https://localhost/mcp",
        "http://127.0.0.1:3000",
        "ws://127.8.9.10/socket",
        "wss://[::1]:9",
        "http://[0:0:0:0:0:0:0:1]",
    ],
)
def test_a_loopback_mcp_endpoint_derives_nothing_but_is_assessed(endpoint):
    assert classify(MCPServerComponent(bom_ref="s", name="s", endpoint_url=endpoint)) == (
        NONE_DERIVED
    )


def test_a_withheld_environment_name_marks_secret_access():
    server = MCPServerComponent(
        bom_ref="s", name="s", env={"LOG_LEVEL": "***", "[redacted-1]": "***"}
    )
    assert classify(server) == RiskClassification(
        classes=(RiskClass.SECRET_ACCESS,), basis=("env:withheld-name",), assessed=True
    )


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"GITHUB_TOKEN": "***", "API_KEY": "***"},
        {"[redacted-0]": "***", "[redacted]": "***", "[redacted-1] ": "***", "redacted-1": "***"},
    ],
)
def test_environment_names_are_not_guessed_at(env):
    assert classify(MCPServerComponent(bom_ref="s", name="s", env=env)) == UNASSESSED


def test_a_server_does_not_inherit_its_tools_classes():
    server = MCPServerComponent(bom_ref="s", name="s", tool_refs=["t"], transport="stdio")
    assert classify(server) == UNASSESSED


@pytest.mark.parametrize(
    ("safety", "remote_code", "basis"),
    [
        (
            SerializationSafety.UNSAFE_CODE_EXECUTION,
            None,
            "serialization_safety:unsafe-code-execution",
        ),
        (
            SerializationSafety.UNSAFE_TEMPLATE_INJECTION,
            False,
            "serialization_safety:unsafe-template-injection",
        ),
        (SerializationSafety.SAFE, True, "trust_remote_code:true"),
        (SerializationSafety.UNKNOWN, True, "trust_remote_code:true"),
    ],
)
def test_a_model_whose_loading_runs_code_is_code_exec(safety, remote_code, basis):
    model = ModelComponent(
        bom_ref="m", name="m", serialization_safety=safety, trust_remote_code=remote_code
    )
    assert classify(model) == RiskClassification(
        classes=(RiskClass.CODE_EXEC,), basis=(basis,), assessed=True
    )


def test_a_pickle_model_and_remote_code_record_both_bases():
    model = ModelComponent(
        bom_ref="m",
        name="m",
        serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION,
        trust_remote_code=True,
    )
    assert classify(model).basis == (
        "serialization_safety:unsafe-code-execution",
        "trust_remote_code:true",
    )


def test_model_safety_evidence_without_a_class_is_assessed_and_unknown_is_not():
    safe = ModelComponent(bom_ref="m", name="m", serialization_safety=SerializationSafety.SAFE)
    no_remote_code = ModelComponent(bom_ref="m", name="m", trust_remote_code=False)
    assert classify(safe) == classify(no_remote_code) == NONE_DERIVED
    assert classify(ModelComponent(bom_ref="m", name="m")) == UNASSESSED


@pytest.mark.parametrize(
    ("mode", "classes"),
    [
        ("bypassPermissions", (RiskClass.CODE_EXEC, RiskClass.WRITE_CAPABLE)),
        ("acceptEdits", (RiskClass.WRITE_CAPABLE,)),
    ],
)
def test_a_claude_code_mode_that_skips_prompts_grants_its_classes(mode, classes):
    agent = IDEAgentComponent(
        bom_ref="ide", name="claude-code", ide_type="claude-code", permission_mode=mode
    )
    assert classify(agent) == RiskClassification(
        classes=classes, basis=(f"permission_mode:{mode}",), assessed=True
    )


@pytest.mark.parametrize(
    ("ide_type", "mode"),
    [
        ("claude-code", "default"),
        ("claude-code", "plan"),
        ("claude-code", "dontAsk"),
        ("claude-code", "auto"),
        ("claude-code", None),
        ("cursor", "bypassPermissions"),
        ("windsurf", "acceptEdits"),
        ("codex", "bypassPermissions"),
        (None, "bypassPermissions"),
    ],
)
def test_other_permission_modes_and_hosts_stay_unassessed(ide_type, mode):
    agent = IDEAgentComponent(bom_ref="ide", name="i", ide_type=ide_type, permission_mode=mode)
    assert classify(agent) == UNASSESSED


def test_codex_approval_policy_never_is_code_exec():
    agent = IDEAgentComponent(
        bom_ref="ide",
        name="codex",
        ide_type="codex",
        permission_mode="never",
        properties={"approval_policy": "never", "sandbox_mode": "workspace-write"},
    )
    assert classify(agent) == RiskClassification(
        classes=(RiskClass.CODE_EXEC,), basis=("approval_policy:never",), assessed=True
    )


@pytest.mark.parametrize(
    ("ide_type", "properties"),
    [
        ("codex", {"approval_policy": "on-request", "sandbox_mode": "danger-full-access"}),
        ("codex", {"approval_policy": ["never"]}),
        ("cursor", {"approval_policy": "never"}),
    ],
)
def test_other_codex_settings_stay_unassessed(ide_type, properties):
    agent = IDEAgentComponent(bom_ref="ide", name="i", ide_type=ide_type, properties=properties)
    assert classify(agent) == UNASSESSED


@pytest.mark.parametrize(
    "component",
    [
        PromptComponent(bom_ref="p", name="p"),
        RAGSourceComponent(bom_ref="r", name="r"),
        RegistryEntryComponent(bom_ref="g", name="g"),
        MCPClientComponent(bom_ref="c", name="c", server_refs=["s"]),
        AgentComponent(bom_ref="a", name="a"),
    ],
)
def test_types_without_rules_have_no_classes(component):
    assert classify(component) == UNASSESSED


def test_classification_is_sorted_deterministic_and_from_the_fixed_vocabulary():
    declarations = [
        (capabilities, profile, domains)
        for size in range(4)
        for capabilities in itertools.combinations(CapabilityClass, size)
        for profile in SideEffectProfile
        for domains in ([], ["x.example"])
    ]
    for capabilities, profile, domains in declarations:
        component = tool(*capabilities, side_effect_profile=profile, egress_domains=domains)
        first, second = classify(component), classify(component)
        assert first == second
        assert list(first.classes) == sorted(first.classes)
        assert list(first.basis) == sorted(first.basis)
        assert set(first.basis) <= BASIS
        assert bool(first.classes) <= first.assessed
    models = [
        ModelComponent(bom_ref="m", name="m", serialization_safety=safety, trust_remote_code=code)
        for safety in SerializationSafety
        for code in (None, False, True)
    ]
    agents = [
        IDEAgentComponent(
            bom_ref="i",
            name="i",
            ide_type=ide_type,
            permission_mode=mode,
            properties={"approval_policy": mode},
        )
        for ide_type in ("claude-code", "codex")
        for mode in ("bypassPermissions", "acceptEdits", "never", "default")
    ]
    for component in [*models, *agents]:
        assert set(classify(component).basis) <= BASIS


def test_every_basis_string_is_reachable():
    produced: set[str] = set()
    for capability in CapabilityClass:
        produced.update(classify(tool(capability, CapabilityClass.NETWORK)).basis)
    for profile in SideEffectProfile:
        produced.update(classify(tool(side_effect_profile=profile)).basis)
    produced.update(classify(tool(egress_domains=["x"])).basis)
    for endpoint in ("https://x.example", "[redacted]"):
        produced.update(
            classify(MCPServerComponent(bom_ref="s", name="s", endpoint_url=endpoint)).basis
        )
    produced.update(
        classify(MCPServerComponent(bom_ref="s", name="s", env={"[redacted-1]": "***"})).basis
    )
    for safety in SerializationSafety:
        produced.update(
            classify(
                ModelComponent(
                    bom_ref="m", name="m", serialization_safety=safety, trust_remote_code=True
                )
            ).basis
        )
    for mode in ("bypassPermissions", "acceptEdits"):
        produced.update(
            classify(
                IDEAgentComponent(
                    bom_ref="i", name="i", ide_type="claude-code", permission_mode=mode
                )
            ).basis
        )
    produced.update(
        classify(
            IDEAgentComponent(
                bom_ref="i", name="i", ide_type="codex", properties={"approval_policy": "never"}
            )
        ).basis
    )
    assert produced == BASIS


def test_collector_records_from_a_static_mcp_configuration(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "ops": {
                        "command": "npx",
                        "args": ["-y", "ops-mcp@1.0.0"],
                        "env": {"ghp_" + "a" * 36: "value", "LOG_LEVEL": "info"},
                        "tools": [
                            {"name": "run_command", "description": "Run a shell command"},
                            {"name": "read_file", "description": "Read a file and fetch a URL"},
                            {"name": "list_issues", "description": "List issues"},
                        ],
                    },
                    "remote": {"type": "http", "url": "https://mcp.example.com/v1"},
                    "local": {"type": "http", "url": "http://localhost:8080/mcp"},
                    "split": {"type": "http", "url": "http://evil.example\\@localhost/mcp"},
                }
            }
        )
    )
    result = MCPScanner().scan(tmp_path)
    by_name = {component.name: component for component in result.components}
    assert classify(by_name["run_command"]).classes == (RiskClass.CODE_EXEC,)
    assert classify(by_name["read_file"]).classes == (
        RiskClass.EXFIL_CAPABLE,
        RiskClass.NETWORK_EGRESS,
    )
    assert classify(by_name["list_issues"]) == NONE_DERIVED
    assert by_name["run_command"].properties["capability_evidence"] == (
        "unverified-declaration-and-name-heuristic"
    )
    assert classify(by_name["ops"]).basis == ("env:withheld-name",)
    assert classify(by_name["remote"]).basis == ("endpoint_url:remote",)
    assert classify(by_name["local"]) == NONE_DERIVED
    assert by_name["split"].endpoint_url == "[redacted]"
    assert classify(by_name["split"]).basis == ("endpoint_url:unresolved",)


def test_unscoped_allow_rules_leave_a_claude_code_agent_unclassified(tmp_path):
    # The collector records unscoped allow rules only as finding text, which is not parsed;
    # docs/graph-view.md states the consequence. Update both when a field records them.
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps({"permissions": {"allow": ["Bash", "Edit"]}})
    )
    [agent] = IDEAgentScanner().scan(tmp_path).components
    assert "permission_scope" in {risk.category for risk in agent.risks}
    assert agent.permission_mode is None
    assert classify(agent) == UNASSESSED


def test_collector_records_of_an_ide_agent_and_a_pickle_model(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps({"permissions": {"defaultMode": "bypassPermissions"}})
    )
    (tmp_path / "model.pkl").write_bytes(pickle.dumps({"weights": [1, 2, 3]}))
    agents = IDEAgentScanner().scan(tmp_path).components
    models = ModelScanner().scan(tmp_path).components
    assert [classify(agent).classes for agent in agents] == [
        (RiskClass.CODE_EXEC, RiskClass.WRITE_CAPABLE)
    ]
    assert [classify(model).basis for model in models] == [
        ("serialization_safety:unsafe-code-execution",)
    ]
