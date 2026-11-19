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
    RAW_DIGESTS,
    character_classes,
    mixed_scripts,
    name_key,
    neutral_text,
    neutralize_identifiers,
    raw_digest,
    recorded_name_key,
    reference_text,
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
from nexus_symbiote.utils.terminal import UNSAFE_TEXT, neutralize
from tests.support import otlp_export, otlp_span, scaling_ratio

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
    assert all(c["name"] == neutral_text(c["name"]) for c in native["components"])


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
    assert character_classes("a\nb\r\nc") == {"line break": 3}
    assert character_classes("\x08\x0b\x0c") == {"C0 control": 3}
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
        assert value not in finding.detail or value == neutral_text(value)
        assert raw_digest(value) in finding.detail


VS16 = "\ufe0f"
ZWJ = "\u200d"
ZWNJ = "\u200c"
BENIGN_NAMES = (
    "GitHub-интеграция",
    "Jira-интеграция",
    "Slack-уведомления",
    "MCP сервер файлов",
    "API πύλη",
    f"⚙{VS16} settings",
    f"1{VS16}\u20e3 first",
    f"\U0001f469\U0001f3fd{ZWJ}\U0001f4bb dev",
    f"\U0001f3f3{VS16}{ZWJ}\U0001f308 pride",
    f"می{ZWNJ}خواهم",
    "البحث",
    f"\u2139{VS16} info",
    f"\U0001f600{ZWJ}\u2139{VS16}",
    f"क\u094d{ZWJ}ष",
    f"ශ\u0dca{ZWJ}ර\u0dd3",
    "Tokyoタワー",
)


def _risk_gate(inventory: Path) -> int:
    result = CliRunner().invoke(
        main,
        [
            "risk",
            str(inventory),
            "--no-project-policy",
            "--no-score-threshold",
            "--fail-on-severity",
            "high",
        ],
    )
    return result.exit_code


def test_ordinary_names_in_other_scripts_and_emoji_are_kept_and_not_reported(tmp_path):
    project = tmp_path / "project"
    servers = {name: _server(name, [name], alwaysAllow=[name]) for name in BENIGN_NAMES}
    _write_project(project, servers)
    output = tmp_path / "bom.json"
    native = json.loads(_scan(project, output))
    findings = _findings(native)
    for name in BENIGN_NAMES:
        assert findings[name] == [], name
    for component in native["components"]:
        assert RAW_DIGESTS not in component.get("properties", {}), component["name"]
    names = {c["name"] for c in native["components"]}
    assert set(BENIGN_NAMES) <= names
    assert _risk_gate(output) == 0


@pytest.mark.parametrize(
    "purpose",
    [
        "purpose: >\n  Triages support tickets\n  and drafts replies.\n",
        "purpose: |\n  Triages support tickets\n  and drafts replies.\n",
        "purpose: |-\n  Разбирает обращения\n  и готовит ответы.\n",
        'purpose: "first line\\r\\nsecond\\tline"\n',
    ],
)
def test_line_breaks_in_a_description_become_spaces_without_a_finding(tmp_path, purpose):
    project = tmp_path / "project"
    project.mkdir()
    (project / "agent.yaml").write_text(
        f"name: triage-agent\n{purpose}owner: |\n  Support\n  Team\n", encoding="utf-8"
    )
    output = tmp_path / "bom.json"
    native = json.loads(_scan(project, output))
    (agent,) = [c for c in native["components"] if c["component_type"] == "agent"]
    assert not [r for r in agent["risks"] if r["category"] == CATEGORY]
    assert "\n" not in agent["description"] and "\r" not in agent["description"]
    assert "\t" not in agent["description"]
    assert agent["supplier"] == "Support Team "
    assert sorted(agent["properties"][RAW_DIGESTS]) == ["description", "supplier"]
    assert _risk_gate(output) == 0


@pytest.mark.parametrize(
    ("name", "recorded", "reported"),
    [
        ("name: >\n  triage-agent\n", "triage-agent", False),
        ("name: |\n  triage-agent\n", "triage-agent", False),
        ("name: >-\n  triage-agent\n", "triage-agent", False),
        ('name: "triage-agent\\n"\n', "triage-agent", False),
        ("name: |+\n  triage-agent\n\n", "triage-agent ", True),
        ('name: "triage\\nagent"\n', "triage agent", True),
    ],
)
def test_an_agent_name_keeps_no_clip_line_break(tmp_path, name, recorded, reported):
    project = tmp_path / "project"
    project.mkdir()
    (project / "agent.yaml").write_text(f"{name}owner: platform\n", encoding="utf-8")
    output = tmp_path / "bom.json"
    native = json.loads(_scan(project, output))
    (agent,) = [c for c in native["components"] if c["component_type"] == "agent"]
    assert agent["name"] == recorded
    assert bool([r for r in agent["risks"] if r["category"] == CATEGORY]) is reported


def test_a_lookalike_letter_inside_a_word_keeps_the_finding_beside_ordinary_words(tmp_path):
    project = tmp_path / "project"
    homoglyph = "GitHub-интеграция-rеad"
    _write_project(project, {homoglyph: _server(homoglyph, ["MCP сервер"])})
    output = tmp_path / "bom.json"
    native = json.loads(_scan(project, output))
    findings = _findings(native)
    (finding,) = findings[homoglyph]
    assert "name mixes the Cyrillic, Latin scripts" in finding["detail"]
    assert findings["MCP сервер"] == []
    assert _risk_gate(output) == 1


@pytest.mark.parametrize(
    "name",
    [
        "shell_ехес",
        "file-сору",
        "github.сом",
        "read_ο",
        "АРІ_tools",
        f"github-{VS16}mcp",
        f"github.{VS16}mcp",
        f"a/{VS16}b",
        f"v1{VS16}",
        f"@{VS16}scope",
        f"a+{VS16}b",
        f"a={ZWJ}=b",
        f"pa\u094d{ZWJ}ypal",
        f"ש{ZWJ}לום",
        f"مر{ZWJ}حبا",
        f"क{ZWJ}ख",
    ],
)
def test_lookalike_server_and_tool_names_get_the_finding(tmp_path, name):
    project = tmp_path / "project"
    _write_project(project, {name: _server(name, [name])})
    output = tmp_path / "bom.json"
    native = json.loads(_scan(project, output))
    servers = [c for c in native["components"] if c["component_type"] == "mcp_server"]
    tools = [c for c in native["components"] if c["component_type"] == "tool"]
    for component in (*servers, *tools):
        assert [r for r in component["risks"] if r["category"] == CATEGORY], component["name"]
    assert _risk_gate(output) == 1


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        (f"❤{VS16}", True),
        ("❤\ufe0e", True),
        (f"#{VS16}\u20e3", True),
        (f"‼{VS16}", True),
        (f"a{VS16}", False),
        (f"❤{VS16}{VS16}", False),
        (VS16, False),
        (f"\U0001f468{ZWJ}\U0001f469", True),
        (f"\U0001f9d1\U0001f3fd{ZWJ}\U0001f52c", True),
        (f"\U0001f441{VS16}{ZWJ}\U0001f5e8{VS16}", True),
        (f"\U0001f468{ZWJ}a", False),
        (f"a{ZWJ}\U0001f469", False),
        (f"\U0001f468{ZWJ}{ZWJ}\U0001f469", False),
        (f"\U0001f468{ZWNJ}\U0001f469", False),
        (f"کتاب{ZWNJ}ها", True),
        (f"کتاب{ZWNJ}", False),
        (f"{ZWNJ}ها", False),
        (f"ب{ZWNJ}b", False),
        (f"pa{ZWNJ}ypal", False),
        (f"pa{ZWJ}ypal", False),
        (f"ра{ZWNJ}урал", False),
        (f"קב{ZWNJ}צים", False),
        (f"ש{ZWJ}לום", False),
        (f"مر{ZWJ}حبا", False),
        (f"مر{ZWNJ}حبا", False),
        (f"ب{ZWNJ}\u064eب", True),
        (f"क{ZWJ}ख", False),
        (f"pa\u094d{ZWJ}ypal", False),
        (f"pa\u094d{ZWNJ}ypal", False),
        (f"क\u093c\u094d{ZWJ}ष", True),
        (f"ශ\u0dca{ZWJ}ර\u0dd3", True),
        (f"\u2139{VS16}", True),
        (f"\u25b6{VS16}", True),
        (f"\u3030{VS16}", True),
        (f"github-{VS16}mcp", False),
        (f"github.{VS16}mcp", False),
        (f"a/{VS16}b", False),
        (f"v1{VS16}", False),
        (f"@{VS16}scope", False),
        (f"a+{VS16}b", False),
        (f"a={ZWJ}=b", False),
        (f"क\u094d{ZWNJ}ष", True),
        (f"ന\u0d4d{ZWJ}", True),
        (f"র{ZWJ}\u09cdয", True),
        (f"क{ZWJ}", False),
        (f"क{ZWJ}ب", False),
        (f"क\u094d{ZWJ}{ZWJ}ष", False),
    ],
)
def test_selectors_and_joiners_are_kept_only_in_ordinary_spelling(value, kept):
    assert (neutral_text(value) == value) is kept
    assert bool(character_classes(value)) is not kept
    finding = neutralize_identifiers(ToolComponent(bom_ref="tool:x", name=value))
    assert (finding is None) is kept


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (f"র{ZWJ}\u09cdয{ZWJ}{ZWJ}\u09cdক", f"র{ZWJ}\u09cdয\ufffd\ufffd\u09cdক"),
        (f"srv{ZWJ}क\u094d{ZWJ}ष{ZWJ}", f"srv\ufffdक\u094d{ZWJ}ष\ufffd"),
        (
            f"\U0001f468{ZWJ}\U0001f469{ZWJ}a{ZWJ}\u09cd",
            f"\U0001f468{ZWJ}\U0001f469\ufffda\ufffd\u09cd",
        ),
        (f"ক\u09bc{ZWJ}\u09cdষ ক{ZWJ}\u094d", f"ক\u09bc{ZWJ}\u09cdষ ক\ufffd\u094d"),
        (f"{ZWJ}\u09cd{ZWJ}", "\ufffd\u09cd\ufffd"),
        (f"ന\u0d4d{ZWJ}{ZWNJ}x{ZWJ}\u0d4dന", f"ന\u0d4d{ZWJ}\ufffdx\ufffd\u0d4dന"),
    ],
)
def test_joiners_in_mixed_strings_are_judged_each_on_its_neighbours(value, expected):
    assert neutral_text(value) == expected
    assert neutral_text(expected) == expected


@pytest.mark.parametrize(
    "unit",
    [ZWJ, f"র{ZWJ}\u09cd"],
    ids=["joiners-after-latin", "bengali-ra-ya-phala"],
)
def test_neutralizing_many_joiners_is_linear(unit):
    values = {scale: "srv" + unit * (40_000 * scale // len(unit)) for scale in (1, 4)}
    assert scaling_ratio(lambda scale: neutral_text(values[scale])) < 10


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("MCP сервер", ()),
        ("GitHub-интеграция", ()),
        ("Slack-уведомления_bot", ()),
        ("read_файл", ()),
        ("API πύλη", ()),
        ("rеad_file", ("Cyrillic", "Latin")),
        ("MCP сеrver", ("Cyrillic", "Latin")),
        ("shell_ехес", ("Cyrillic", "Latin")),
        ("file-сору", ("Cyrillic", "Latin")),
        ("github.сом", ("Cyrillic", "Latin")),
        ("read_ο", ("Greek", "Latin")),
        ("АРІ_tools", ("Cyrillic", "Latin")),
        ("օս-tools", ("Armenian", "Latin")),
        ("раура", ()),
        ("ехес сору", ()),
        ("v2\u0430", ("Cyrillic", "Latin")),
        ("xаb cαd", ("Cyrillic", "Greek", "Latin")),
        (f"ب{ZWNJ}b", ("Arabic", "Latin")),
    ],
)
def test_scripts_mix_only_within_a_word(value, expected):
    assert mixed_scripts(value) == expected


def test_a_name_that_only_mixes_scripts_across_words_is_recorded_exactly_as_collected():
    collected: dict[str, Any] = {}
    server = MCPServerComponent(bom_ref="mcp-server:x", name="MCP сервер", description="d\te")
    snapshot = server.model_dump()
    assert merge_collected(collected, server, "mcp", None) == "added"
    assert server.name == "MCP сервер"
    assert server.risks == []
    assert server.description == "d e"
    digest = raw_digest("d\te")
    assert server.properties[RAW_DIGESTS] == {"description": f"sha256:{digest}"}
    plain = MCPServerComponent(bom_ref="mcp-server:y", name="MCP сервер")
    before = plain.model_dump()
    assert neutralize_identifiers(plain) is None
    assert plain.model_dump() == before
    assert snapshot["name"] == server.name


def test_trace_diff_matches_raw_names_and_never_a_rewritten_one(tmp_path):
    project = tmp_path / "project"
    agent = f"\U0001f916{VS16} helper"
    persian = f"کتاب{ZWNJ}ها"
    _write_project(project, {"srv": _server("srv", [persian, "run\tjob"])})
    (project / "agent.yaml").write_text(f'name: "{agent}"\n', encoding="utf-8")
    inventory = tmp_path / "bom.json"
    native = json.loads(_scan(project, inventory))
    names = {c["name"] for c in native["components"]}
    assert {agent, persian, "run job"} <= names

    def diff(*spans: dict[str, object]) -> tuple[int, dict[str, Any]]:
        trace = tmp_path / "trace.json"
        trace.write_text(json.dumps(otlp_export(*spans)), encoding="utf-8")
        result = CliRunner().invoke(
            main, ["trace-diff", str(inventory), str(trace), "--json-output"]
        )
        return result.exit_code, json.loads(result.stdout)

    def tool(name: str) -> dict[str, object]:
        return otlp_span({"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": name})

    invoke = otlp_span({"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": agent})
    code, evidence = diff(invoke, tool(persian), tool("run\tjob"))
    reconciliation = evidence["reconciliation"]
    assert code == 0, reconciliation
    assert sorted(e["kind"] for e in reconciliation["matched"]) == ["agent", "tool", "tool"]
    assert reconciliation["undeclared"] == []

    code, evidence = diff(tool("run job"))
    assert code == 1
    assert [e["name"] for e in evidence["reconciliation"]["undeclared"]] == ["run job"]
    code, evidence = diff(tool("run\ufffdjob"))
    assert code == 1


@pytest.mark.parametrize(
    ("declared", "reported", "matched"),
    [
        ("\ttrim", "\ttrim", True),
        ("\ttrim", "trim", True),
        ("\ttrim", " trim", True),
        ("job\t", "job\t", True),
        ("job\t", "job", True),
        ("mid\tdle", "mid\tdle", True),
        ("mid\tdle", "mid dle", False),
        (" x\x1b", " x\x1b", True),
        (" x\x1b", "x\x1b", True),
        (" x\x1b", "x\ufffd", False),
        ("\nx\x1b\t", "x\x1b", True),
        ("\nx\x1b\t", "x\x07", False),
    ],
)
def test_trace_diff_compares_raw_names_trimmed(tmp_path, declared, reported, matched):
    project = tmp_path / "project"
    _write_project(project, {"srv": _server("srv", [declared])})
    inventory = tmp_path / "bom.json"
    _scan(project, inventory)
    trace = tmp_path / "trace.json"
    span = otlp_span({"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": reported})
    trace.write_text(json.dumps(otlp_export(span)), encoding="utf-8")
    result = CliRunner().invoke(main, ["trace-diff", str(inventory), str(trace), "--json-output"])
    reconciliation = json.loads(result.stdout)["reconciliation"]
    assert (result.exit_code == 0) is matched, reconciliation
    assert bool(reconciliation["undeclared"]) is not matched


def test_name_keys_separate_every_raw_name():
    assert name_key("run job") == ("text", "run job")
    assert name_key("run\tjob") == ("raw", f"sha256:{raw_digest('run' + chr(9) + 'job')}")
    assert name_key("run\tjob") != name_key("run\x0bjob")
    tool = ToolComponent(bom_ref="tool:x", name="run\tjob")
    neutralize_identifiers(tool)
    assert tool.name == "run job"
    assert recorded_name_key(tool, tool.name) == name_key("run\tjob")
    tool.properties[RAW_DIGESTS] = {"name": "sha256:not-a-digest"}
    assert recorded_name_key(tool, tool.name) == ("text", "run job")
    legacy = ToolComponent(bom_ref="tool:y", name="run\tjob")
    assert recorded_name_key(legacy, legacy.name) == name_key("run\tjob")


def _all_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (k, *_all_strings(v))]
    return _strings(value)


def test_a2a_and_rag_references_escape_what_their_names_neutralize(tmp_path):
    project = tmp_path / "project"
    for directory, name in (("a", "browser\x1b[2K"), ("b", "browser\x07[2K")):
        card = project / directory / ".well-known" / "agent.json"
        card.parent.mkdir(parents=True)
        card.write_text(json.dumps({"name": name, "url": f"https://{directory}.example"}))
    (project / "a2a.json").write_text(
        json.dumps({"clients": [{"name": "client\u202e", "agentCardUrl": "https://c.example/c"}]})
    )
    (project / "rag_config.json").write_text(
        json.dumps({"sources": [{"name": "docs\u202etxt.exe", "type": "documents"}]})
    )
    output = tmp_path / "bom.json"
    native = json.loads(_scan(project, output))
    refs = {c["bom_ref"] for c in native["components"]}
    assert {
        "a2a-server:browser%1B[2K",
        "a2a-server:browser%07[2K",
        "a2a-client:client%E2%80%AE",
        "rag:docs%E2%80%AEtxt.exe",
    } <= refs
    exports: dict[str, Any] = {"json": native}
    for fmt in ("cyclonedx", "spdx", "sarif"):
        exports[fmt] = json.loads(_scan(project, tmp_path / f"bom.{fmt}", "-f", fmt))
    exports["vex"] = VEXGenerator().generate(AIBOM.model_validate(native))
    for command in (["graph", str(output), "--format", "json"], ["crosswalk", str(output)]):
        result = CliRunner().invoke(main, command)
        exports[command[0]] = json.loads(result.stdout)
    risk = CliRunner().invoke(main, ["risk", str(output), "--json-output", "--no-project-policy"])
    exports["risk"] = json.loads(risk.stdout)
    for fmt, document in exports.items():
        strings = _all_strings(document)
        assert not [text for text in strings if UNSAFE_TEXT.search(text)], fmt
        assert any("browser%1B[2K" in text for text in strings), fmt


def test_reference_text_escapes_only_what_neutralization_replaces():
    assert reference_text("plain 100% name") == "plain 100% name"
    assert reference_text(f"❤{VS16} ok") == f"❤{VS16} ok"
    assert reference_text("a\tb") == "a%09b"
    assert reference_text(f"a{VS16}") == "a%EF%B8%8F"
    assert reference_text("##[x") == "#%23[x"
    assert reference_text("\U000e0041") == "%F3%A0%81%81"
    assert reference_text("x\x1b") != reference_text("x\x07")


@pytest.mark.parametrize(
    ("raw", "literal"),
    [
        ("browser\x1b[2K", "browser%1B[2K"),
        ("docs\u202etxt.exe", "docs%E2%80%AEtxt.exe"),
        ("a\tb", "a%09b"),
    ],
)
def test_a_literal_percent_escape_never_shares_a_raw_names_reference(raw, literal):
    assert reference_text(literal) == literal.replace("%", "%25")
    assert reference_text(raw) == literal
    assert reference_text(f"{raw} 100%") == f"{literal} 100%25"
    assert reference_text("100% ok") == "100% ok"


def _owner_status(tmp_path: Path, owner: str) -> str:
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    (project / "agent.yaml").write_text(f'id: acme:x\nname: x\nowner: "{owner}"\n')
    output = tmp_path / "bom.json"
    _scan(project, output)
    result = CliRunner().invoke(main, ["minimum-elements", str(output), "-f", "json"])
    report = json.loads(result.stdout)
    (element,) = [e for e in report["elements"] if e["id"] == "g7ai-2026/slp/system-producer"]
    return str(element["status"])


@pytest.mark.parametrize(
    ("owner", "status"),
    [
        ("\\u200b", "missing"),
        ("\\u200b \\u202e", "missing"),
        ("acme", "present"),
        ("acme\\u200b", "present"),
    ],
)
def test_an_owner_left_with_only_replacement_characters_is_missing(tmp_path, owner, status):
    assert _owner_status(tmp_path, owner) == status


@pytest.mark.parametrize(
    ("field", "value"),
    [("name", "support-triage\\x1b[2K"), ("owner", "platform\\u202e"), ("name", "run\\tjob")],
)
def test_export_inventory_refuses_a_name_or_owner_that_collection_rewrote(tmp_path, field, value):
    project = tmp_path / "project"
    project.mkdir()
    values = {"name": "support-triage", "owner": "platform-security", field: value}
    (project / "agent.yaml").write_text(
        f'id: acme:support-triager\nname: "{values["name"]}"\nowner: "{values["owner"]}"\n'
    )
    inventory = tmp_path / "bom.json"
    _scan(project, inventory)
    output = tmp_path / "simple.json"
    result = CliRunner().invoke(
        main,
        [
            "export-inventory",
            str(inventory),
            "--format",
            "shadowscan-simple",
            "--resource-prefix",
            "github:acme/support-triager",
            "-o",
            str(output),
        ],
    )
    assert result.exit_code != 0
    label = "agent name" if field == "name" else "agent owner"
    assert f"The {label} contains a control, format" in result.output
    assert not output.exists()


@settings(max_examples=300)
@given(
    st.lists(
        st.characters(codec="utf-8")
        | st.sampled_from(["##[", "##vso[", "\x7f", "\x08", "\n", "\ufe0f", "\u200d", "\u200c"])
    ).map("".join)
)
def test_neutralized_text_is_never_longer_in_json_and_is_stable(value):
    text = neutral_text(value)
    assert len(json.dumps(text)) <= len(json.dumps(value))
    assert len(text) == len(value)
    assert neutral_text(text) == text
    assert character_classes(text) == {}
    assert (text == value) == (character_classes(value) == {})


@pytest.mark.parametrize("char", ["\t", "\n", "\r", "\x0b", "\x0c", "\x08", "\x7f"])
def test_characters_json_writes_short_become_a_space(char):
    assert neutral_text(f"a{char}b") == "a b"
    assert len(json.dumps(neutral_text(char))) <= len(json.dumps(char))


def test_two_long_introducer_names_still_fit_the_native_limit():
    raw = "##[" * 20_000
    tools = [ToolComponent(bom_ref=f"tool:{i}", name=raw + str(i)) for i in range(2)]
    before = len(AIBOM(components=[t.model_copy(deep=True) for t in tools]).to_native_json())
    for tool in tools:
        neutralize_identifiers(tool)
    after = len(AIBOM(components=tools).to_native_json())
    assert tools[0].name.startswith("# [# [")
    assert after - before < 4096
