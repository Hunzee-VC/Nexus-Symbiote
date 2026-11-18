"""Collected identifiers are neutralized once, at collection, and the characters that
disguised them are reported without their raw text."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from hypothesis import given, settings
from hypothesis import strategies as st

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.collection import merge_collected
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.identifiers import (
    CATEGORY,
    character_classes,
    mixed_scripts,
    neutralize_identifiers,
    raw_digest,
)
from nexus_symbiote.core.models import (
    MCPServerComponent,
    ModelComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.crosswalk import CROSSWALK
from nexus_symbiote.generators._rules import RULES, rule_tags
from nexus_symbiote.generators.validation import validate_cyclonedx, validate_sarif, validate_spdx
from nexus_symbiote.generators.vex import VEXGenerator
from nexus_symbiote.utils.terminal import neutralize

ESC_NAME = "browser\x1b[2K"
ESC_NAME_SHA256 = "363f76b7a8f435e71ca89dc6d3ee5e63ac2c197a5e34db43e03c1738664d6f60"
LOOKALIKE = "rеad_file"
CYRILLIC = "читать"
EMOJI = "\U0001f4c1\U0001f50d"
ASCII = "read_file"


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _controls(text: str) -> set[str]:
    return {c for c in text if unicodedata.category(c) in {"Cc", "Cf"} and c != "\t"}


def _write_project(root: Path, servers: dict[str, Any]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")


def _scan(root: Path, output: Path, *args: str) -> str:
    result = CliRunner().invoke(
        main, ["scan", str(root), "--report-only", "-o", str(output), *args]
    )
    assert result.exit_code == 0, result.output
    return output.read_text(encoding="utf-8")


def _findings(document: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    return {
        component["name"]: [r for r in component.get("risks", []) if r["category"] == CATEGORY]
        for component in document["components"]
    }


def _server(name: str, tools: list[str], **extra: Any) -> dict[str, Any]:
    return {
        "command": "npx",
        "args": ["browser-mcp@1.0.0"],
        "tools": [{"name": tool, "description": "reads"} for tool in tools],
        **extra,
    }


def test_escape_sequence_in_a_server_name_is_neutralized_in_every_export(tmp_path):
    project = tmp_path / "project"
    _write_project(project, {ESC_NAME: _server(ESC_NAME, [ASCII])})
    native = json.loads(_scan(project, tmp_path / "bom.json"))
    (server,) = [c for c in native["components"] if c["component_type"] == "mcp-server"]
    assert server["name"] == "browser\ufffd[2K"
    (finding,) = _findings(native)[server["name"]]
    assert finding["severity"] == "high"
    assert "name holds 1 ESC sequence" in finding["detail"]
    assert f"sha256:{ESC_NAME_SHA256}" in finding["detail"]
    assert "\x1b" not in finding["detail"]
    for risk in server["risks"]:
        assert "\x1b" not in risk["detail"]

    exports = {"json": native}
    for fmt in ("cyclonedx", "spdx", "sarif"):
        exports[fmt] = json.loads(_scan(project, tmp_path / f"bom.{fmt}", "-f", fmt))
    exports["vex"] = VEXGenerator().generate(AIBOM.model_validate(native))
    for fmt, document in exports.items():
        strings = _strings(document)
        assert strings, fmt
        assert not {c for text in strings for c in _controls(text)}, fmt
        assert any("browser\ufffd" in text for text in strings), fmt
        assert not any(ESC_NAME in text for text in strings), fmt
    assert validate_cyclonedx(exports["cyclonedx"]) == []
    assert validate_spdx(exports["spdx"]) == []
    assert validate_sarif(exports["sarif"]) == []
    sarif_rules = {
        rule["id"] for run in exports["sarif"]["runs"] for rule in run["tool"]["driver"]["rules"]
    }
    assert f"nexus_symbiote/{CATEGORY}/high" in sarif_rules


def test_mixed_script_tool_name_is_reported_and_single_script_names_are_not(tmp_path):
    project = tmp_path / "project"
    _write_project(
        project,
        {
            "mixed": _server("mixed", [LOOKALIKE], alwaysAllow=[LOOKALIKE]),
            "cyrillic": _server("cyrillic", [CYRILLIC], alwaysAllow=[CYRILLIC]),
            "emoji": _server("emoji", [EMOJI]),
            "ascii": _server("ascii", [ASCII], alwaysAllow=[ASCII]),
            "japanese": _server("japanese", ["東京タワー"]),
        },
    )
    native = json.loads(_scan(project, tmp_path / "bom.json"))
    findings = _findings(native)
    (tool_finding,) = findings[LOOKALIKE]
    assert "name mixes the Cyrillic, Latin scripts" in tool_finding["detail"]
    assert f"sha256:{raw_digest(LOOKALIKE)}" in tool_finding["detail"]
    (server_finding,) = findings["mixed"]
    assert (
        f"tool name '{LOOKALIKE}' in alwaysAllow mixes the Cyrillic, Latin scripts"
        in (server_finding["detail"])
    )
    for clean in (CYRILLIC, EMOJI, ASCII, "東京タワー"):
        assert findings[clean] == [], clean
    for clean in ("cyrillic", "emoji", "ascii", "japanese"):
        assert findings[clean] == [], clean
    assert LOOKALIKE in findings and LOOKALIKE in json.dumps(native, ensure_ascii=False)
    assert all(c["name"] == neutralize(c["name"]) for c in native["components"])


def test_bidirectional_override_in_a_description_is_replaced_and_reported():
    collected: dict[str, Any] = {}
    component = ModelComponent(
        bom_ref="model:x", name="weights", description="safe\u202eevil", supplier="acme\u200b"
    )
    assert merge_collected(collected, component, "model", None) == "added"
    assert component.description == "safe\ufffdevil"
    assert component.supplier == "acme\ufffd"
    (finding,) = [r for r in component.risks if r.category == CATEGORY]
    assert finding.severity is RiskSeverity.HIGH
    assert "description holds 1 bidirectional format character" in finding.detail
    assert "supplier holds 1 other format or invisible character" in finding.detail
    assert "\u202e" not in finding.detail and "\u200b" not in finding.detail
    assert f"sha256:{raw_digest('safe' + chr(0x202E) + 'evil')}" in finding.detail
    assert "mixes" not in finding.detail

    twin = ModelComponent(bom_ref="model:y", name="weights", description="safe evil")
    assert merge_collected(collected, twin, "model", None) == "added"
    assert twin.risks == []


def test_two_scans_of_a_hostile_project_are_byte_identical(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    project = tmp_path / "project"
    _write_project(project, {ESC_NAME: _server(ESC_NAME, [LOOKALIKE], alwaysAllow=[LOOKALIKE])})
    first = _scan(project, tmp_path / "first.json")
    second = _scan(project, tmp_path / "second.json")
    assert first == second
    for fmt in ("cyclonedx", "spdx", "sarif"):
        assert _scan(project, tmp_path / f"a.{fmt}", "-f", fmt) == _scan(
            project, tmp_path / f"b.{fmt}", "-f", fmt
        ), fmt


def _validate(baseline: Path, project: Path) -> tuple[int, dict[str, Any]]:
    result = CliRunner().invoke(
        main,
        [
            "validate",
            "--no-project-policy",
            str(baseline),
            "--project",
            str(project),
            "--json-output",
        ],
    )
    assert "\x1b" not in result.output
    return result.exit_code, json.loads(result.output)


def test_project_reconciliation_verifies_tools_whose_names_were_neutralized(tmp_path):
    project = tmp_path / "project"
    tools = ["t\x1b[2K", "read\tfile", LOOKALIKE, ASCII]
    _write_project(project, {ESC_NAME: _server(ESC_NAME, tools)})
    baseline = tmp_path / "bom.json"
    document = json.loads(_scan(project, baseline))
    names = {c["name"] for c in document["components"] if c["component_type"] == "tool"}
    assert names == {"t\ufffd[2K", "read file", LOOKALIKE, ASCII}

    code, report = _validate(baseline, project)
    assert code == 0, report
    integrity = report["integrity"]
    assert integrity["status"] == "pass", integrity
    assert integrity["hashes_verified"] == len(tools)
    assert integrity["hashes_failed"] == 0
    assert not [i for i in integrity["issues"] if i["issue_type"] == "hash_mismatch"]

    for component in document["components"]:
        if component["name"] == "read file":
            component["name"] = "read  file"
    baseline.write_text(json.dumps(document), encoding="utf-8")
    code, report = _validate(baseline, project)
    assert code != 0
    assert report["integrity"]["hashes_failed"] == 1


def test_agent_manifest_and_coverage_reasons_are_neutralized_in_the_exports(tmp_path):
    project = tmp_path / "project"
    server = {**_server("srv", [ASCII]), "command": "python", "custom": 1}
    _write_project(project, {"srv\x1b[2K": server})
    (project / "agent.yaml").write_text(
        'name: "agent\\x1b[2K"\npurpose: "does\\x1b]0;x\\x07 things"\nowner: "acme\\u202e"\n',
        encoding="utf-8",
    )
    native = json.loads(_scan(project, tmp_path / "bom.json"))
    (agent,) = [c for c in native["components"] if c["component_type"] == "agent"]
    assert agent["name"] == "agent\ufffd[2K"
    assert agent["description"] == "does\ufffd]0;x\ufffd things"
    assert agent["supplier"] == "acme\ufffd"
    (finding,) = [r for r in agent["risks"] if r["category"] == CATEGORY]
    assert "description holds 1 ESC sequence, 1 C0 control" in finding["detail"]
    assert "supplier holds 1 bidirectional format character" in finding["detail"]
    assert native["metadata"]["completeness"]["surfaces_excluded"] == [
        ".mcp.json: MCP server 'srv\ufffd[2K' declares 1 field the collector does not interpret"
    ]
    cyclonedx = json.loads(_scan(project, tmp_path / "bom.cdx.json", "-f", "cyclonedx"))
    subject = cyclonedx["metadata"]["component"]
    assert subject["name"] == "agent\ufffd[2K"
    assert subject["description"] == "does\ufffd]0;x\ufffd things"
    for document in (native, cyclonedx):
        assert not {c for text in _strings(document) for c in _controls(text)}

    (project / "agent.yaml").write_text(
        'name: a\nmodels:\n  m:\n    provider: example\n    requested_ref: "hosted\\x1b[2K"\n',
        encoding="utf-8",
    )
    declared = json.loads(_scan(project, tmp_path / "declared.json"))
    (model,) = [c for c in declared["components"] if c["component_type"] == "model"]
    assert model["name"] == "hosted\ufffd[2K"
    assert [r["category"] for r in model["risks"]].count(CATEGORY) == 1

    (project / "agent.yaml").write_text(
        'name: "agent"\npurpose: "does things"\nowner: "acme"\n', encoding="utf-8"
    )
    benign = json.loads(_scan(project, tmp_path / "benign.json"))
    (agent,) = [c for c in benign["components"] if c["component_type"] == "agent"]
    assert agent["name"] == "agent"
    assert not [r for r in agent["risks"] if r["category"] == CATEGORY]


def test_raw_digest_is_the_sha256_of_the_raw_utf8_bytes():
    assert raw_digest(ESC_NAME) == ESC_NAME_SHA256
    assert raw_digest(ESC_NAME) == hashlib.sha256(ESC_NAME.encode()).hexdigest()
    assert raw_digest(neutralize(ESC_NAME)) != ESC_NAME_SHA256
    assert raw_digest("a\udcffb") == hashlib.sha256(b"a\xed\xb3\xbfb").hexdigest()


def test_character_classes_are_counted_by_class():
    assert character_classes("\x1b[2K\x00\x7f\x85\u202e\u200b##[error]") == {
        "ESC sequence": 1,
        "C0 control": 2,
        "C1 control": 1,
        "bidirectional format character": 1,
        "other format or invisible character": 1,
        "CI log-command introducer": 1,
    }
    assert character_classes("plain name and ##hash") == {}
    assert character_classes("a tab\tbecomes a space") == {"tab": 1}
    assert character_classes("") == {}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (LOOKALIKE, ("Cyrillic", "Latin")),
        ("aβ", ("Greek", "Latin")),
        ("աb", ("Armenian", "Latin")),
        ("дα", ("Cyrillic", "Greek")),
        ("ａа", ("Cyrillic", "Latin")),
        (CYRILLIC, ()),
        (EMOJI, ()),
        (ASCII, ()),
        ("v2.0-rc1_x!", ()),
        ("東京タワー", ()),
        ("Tokyoタワー", ()),
        ("한글漢", ()),
        ("漢а", ("Cyrillic", "Han")),
        ("\U0001d400b", ()),
        ("", ()),
    ],
)
def test_mixed_scripts_names_the_scripts_of_a_mixed_name_only(value, expected):
    assert mixed_scripts(value) == expected


def test_neutralization_is_idempotent_and_adds_one_finding():
    component = MCPServerComponent(
        bom_ref="mcp-server:x",
        name=ESC_NAME,
        risks=[
            RiskAssessment(
                severity=RiskSeverity.LOW,
                category="local_process",
                detail=f"MCP server '{ESC_NAME}' uses stdio transport.",
                recommendation="Pin it\x1b[2K.",
            )
        ],
        properties={
            "client_settings": {
                "auto_approved_tools": {"alwaysAllow": [LOOKALIKE, 7, "ok"]},
                "tool_filter_names": {"disabledTools": ["x\x07y"]},
            }
        },
    )
    first = neutralize_identifiers(component)
    assert first is not None and first.category == CATEGORY
    assert component.name == "browser\ufffd[2K"
    assert component.risks[0].detail == "MCP server 'browser\ufffd[2K' uses stdio transport."
    assert component.risks[0].recommendation == "Pin it\ufffd[2K."
    settings = component.properties["client_settings"]
    assert settings["auto_approved_tools"]["alwaysAllow"] == [LOOKALIKE, 7, "ok"]
    assert settings["tool_filter_names"]["disabledTools"] == ["x\ufffdy"]
    assert "tool name 'x\ufffdy' in disabledTools holds 1 C0 control" in first.detail
    assert f"tool name '{LOOKALIKE}' in alwaysAllow mixes" in first.detail
    snapshot = component.model_dump()
    assert neutralize_identifiers(component) is None
    assert component.model_dump() == snapshot
    assert [r.category for r in component.risks].count(CATEGORY) == 1

    reported = ModelComponent(bom_ref="model:x", name=ESC_NAME, risks=[first])
    assert neutralize_identifiers(reported) is None
    assert reported.name == "browser\ufffd[2K"
    assert [r.category for r in reported.risks] == [CATEGORY]


def test_the_finding_cuts_long_names_and_caps_the_listed_values():
    long_name = "\x1b" + "n" * 200
    component = ToolComponent(
        bom_ref="tool:x",
        name=long_name,
        mcp_server_ref="mcp-server:x",
        properties={"client_settings": {}},
    )
    finding = neutralize_identifiers(component)
    assert finding is not None
    assert "\ufffd" + "n" * 79 + "...'" in finding.detail
    assert "n" * 100 not in finding.detail
    server = MCPServerComponent(
        bom_ref="mcp-server:x",
        name="ok",
        properties={
            "client_settings": {
                "auto_approved_tools": {"alwaysAllow": [f"t\x1b{i}" for i in range(14)]}
            }
        },
    )
    finding = neutralize_identifiers(server)
    assert finding is not None
    assert finding.detail.count("ESC sequence") == 10
    assert "and 4 more values" in finding.detail


def test_duplicate_collectors_of_a_hostile_component_agree():
    collected: dict[str, Any] = {}
    first = MCPServerComponent(bom_ref="mcp-server:x", name=ESC_NAME)
    second = MCPServerComponent(bom_ref="mcp-server:x", name=ESC_NAME)
    assert merge_collected(collected, first, "mcp", None) == "added"
    assert merge_collected(collected, second, "ide_agents", None) == "duplicate"
    assert collected["mcp-server:x"].name == "browser\ufffd[2K"
    changed = MCPServerComponent(bom_ref="mcp-server:x", name="browser\x1b[3K")
    assert merge_collected(collected, changed, "live", None) == "conflict"


def test_the_category_is_catalogued_with_hidden_text_and_tool_references():
    assert CATEGORY in RULES and CATEGORY in CROSSWALK
    tags = rule_tags(CATEGORY, RiskSeverity.HIGH)
    assert "external/cwe/cwe-451" in tags
    assert "external/mitre-atlas/aml.t0010.005" in tags
    assert "external/mitre-atlas/aml.t0074" in tags


@settings(max_examples=200)
@given(st.text(max_size=40))
def test_a_neutralized_name_holds_no_class_and_a_changed_name_held_one(value):
    component = ModelComponent(bom_ref="model:x", name=value)
    finding = neutralize_identifiers(component)
    assert character_classes(component.name) == {}
    assert (component.name != value) == bool(character_classes(value))
    assert (finding is not None) == (component.name != value)
    if finding is not None:
        assert value not in finding.detail or value == neutralize(value)
        assert raw_digest(value) in finding.detail
