"""The crosswalk report: the findings that risk scores, the references the catalog holds,
and inventory text that cannot become markup, a terminal escape or a CI log command."""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from markdown_it import MarkdownIt

from nexus_symbiote import crosswalk
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import (
    MCPServerComponent,
    ModelComponent,
    RAGSourceComponent,
    RiskAssessment,
)
from nexus_symbiote.crosswalk_cli import (
    FORMAT,
    MAX_MARKDOWN_FINDINGS,
    MAX_MARKDOWN_TEXT,
    build_report,
    render_markdown,
)
from nexus_symbiote.utils.terminal import OUTPUT_REFUSED, neutralize
from nexus_symbiote.validators.risk import RiskScorer
from tests.support import ROOT, scaling_ratio

HIGH, MEDIUM, LOW = RiskSeverity.HIGH, RiskSeverity.MEDIUM, RiskSeverity.LOW
PAGE = ROOT / "docs" / "framework-crosswalk.md"
HOSTILE = [
    "pipe | and \\| escaped pipe",
    "<script>alert(1)</script> <!-- comment --> <b>bold</b>",
    "``code`` and `tick` and ```fence```",
    "[click](https://evil.example) ![img](https://evil.example/x.png) <https://evil.example>",
    "https://evil.example/a www.evil.example user@evil.example",
    "\x1b[31mred\x1b[0m ‮evil‬ zero​width ﻿bom",
    "line\n::error::forged\n##[error]legacy ::warning::x ##vso[task.setvariable]y",
    "*em* _em_ **strong** ~~strike~~ $math$ &lt;entity&gt; \\ backslash",
    "# heading - list > quote 1. ordered",
    "x" * 5000,
]
MARKDOWN = MarkdownIt("commonmark", {"html": True}).enable(["table", "strikethrough"])


def _risk(category: str, severity: RiskSeverity = HIGH, detail: str = "detail") -> RiskAssessment:
    return RiskAssessment(severity=severity, category=category, detail=detail)


def _write(path: Path, *components: Any) -> Path:
    path.write_text(AIBOM(components=list(components)).to_json(), encoding="utf-8")
    return path


def _run(runner, *args: str) -> Any:
    return runner.invoke(main, ["crosswalk", *map(str, args)])


def _json(runner, *args: str) -> dict[str, Any]:
    result = _run(runner, *args)
    assert result.exit_code == 0, result.output
    document: dict[str, Any] = json.loads(result.stdout)
    return document


def _sample(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "bom.json",
        MCPServerComponent(
            bom_ref="mcp-server:a",
            name="a",
            risks=[
                _risk("version_pinning", HIGH, "MCP server 'a' uses an unpinned package."),
                _risk("local_process", MEDIUM, "MCP server 'a' uses stdio transport."),
            ],
        ),
        RAGSourceComponent(
            bom_ref="rag:notes",
            name="notes",
            risks=[
                _risk("transport_security", LOW, "RAG source 'notes' locator."),
                _risk("completeness", LOW, "RAG source 'notes' values not bound."),
            ],
        ),
        # No findings recorded: risk derives code_execution from the recorded field.
        ModelComponent(bom_ref="model:m", name="m", trust_remote_code=True),
    )


def _entries(document: dict[str, Any], key: str) -> dict[str, list[int]]:
    (edition,) = [item for item in document["frameworks"] if item["framework"] == key]
    return {entry["entry"]: entry["findings"] for entry in edition["entries"]}


def test_json_report_maps_exactly_the_findings_risk_scores(runner, tmp_path):
    inventory = _sample(tmp_path)
    document = _json(runner, inventory)
    scored = runner.invoke(main, ["risk", str(inventory), "--no-project-policy", "--json-output"])
    risk_findings = json.loads(scored.stdout)["findings"]
    keys = ("category", "severity", "component_ref", "detail")

    def rows(items: list[dict[str, Any]]) -> Counter[tuple[str, ...]]:
        return Counter(tuple(item[key] for key in keys) for item in items)

    assert rows(document["findings"]) == rows(risk_findings)
    assert ("code_execution", "critical", "model:m") in {f[:3] for f in rows(document["findings"])}
    assert document["format"] == FORMAT == "nexus-symbiote/crosswalk/v1"
    assert document["meaning"] == crosswalk.MEANING
    assert document["policy_source"] == "built-in"
    assert (document["suppressed_findings"], document["ignored_findings"]) == (0, 0)
    assert [item["framework"] for item in document["frameworks"]] == list(crosswalk.FRAMEWORK_KEYS)
    findings = document["findings"]
    assert [f["severity"] for f in findings] == ["critical", "high", "medium", "low", "low"]
    for edition in document["frameworks"]:
        held = set()
        for entry in edition["entries"]:
            assert entry["findings"] == sorted(set(entry["findings"]))
            for position in entry["findings"]:
                finding = findings[position]
                references = crosswalk.references(
                    finding["category"], RiskSeverity(finding["severity"]), {edition["framework"]}
                )
                assert entry["entry"] in {reference.entry for reference in references}
                held.add(position)
            counts = Counter(findings[position]["severity"] for position in entry["findings"])
            assert entry["severity_counts"] == {s: counts[s] for s in entry["severity_counts"]}
        assert edition["findings_with_reference"] == len(held)
        assert edition["findings_without_reference"] == len(findings) - len(held)
    cwe = _entries(document, "cwe")
    low_transport = findings.index(
        next(f for f in findings if f["category"] == "transport_security")
    )
    assert low_transport not in cwe.get("CWE-319", [])
    assert document["unmapped_categories"] == []


def test_entries_carry_their_rationale_and_display_title(runner, tmp_path):
    document = _json(runner, _sample(tmp_path), "--framework", "mitre-atlas-2026.10")
    (atlas,) = document["frameworks"]
    by_id = {entry["entry"]: entry for entry in atlas["entries"]}
    assert by_id["AML.T0010.005"]["title"] == "Supply Chain Compromise: AI Agent Tool"
    rationale = next(
        reference.rationale
        for reference in crosswalk.CROSSWALK["version_pinning"]
        if reference.entry == "AML.T0109"
    )
    assert by_id["AML.T0109"]["categories"] == [
        {"category": "version_pinning", "rationale": rationale}
    ]
    assert {item["category"] for item in document["unmapped_categories"]} == {
        "completeness",
        "transport_security",
    }


def _scan(runner, project: Path, inventory: Path) -> Path:
    result = runner.invoke(main, ["scan", str(project), "-o", str(inventory), "--report-only"])
    assert result.exit_code == 0, result.output
    return inventory


def test_references_kept_from_the_earlier_rules_say_which_findings_they_miss(runner, tmp_path):
    project = tmp_path / "project"
    (project / "models").mkdir(parents=True)
    (project / ".mcp.json").write_text(
        '{"mcpServers": {"remote": {"url": "https://user:secret@example.com/mcp"}}}',
        encoding="utf-8",
    )
    (project / "a2a.json").write_text(
        '{"clients": [{"name": "c", "agentCardUrl": '
        '"https://agents.example.com/.well-known/agent.json"}]}',
        encoding="utf-8",
    )
    (project / "models" / "classifier.pkl").write_bytes(b"x")
    inventory = _scan(runner, project, tmp_path / "bom.json")
    document = _json(runner, inventory, "--framework", "cwe", "--framework", "mitre-atlas-2026.10")
    findings = document["findings"]

    def position(category: str) -> int:
        (found,) = [index for index, item in enumerate(findings) if item["category"] == category]
        return found

    credentials, client = position("transport_security"), position("authentication")
    assert "embeds credentials: https://" in findings[credentials]["detail"]
    assert "A2A client" in findings[client]["detail"]
    atlas, cwe = document["frameworks"]
    assert all(client not in entry["findings"] for entry in atlas["entries"])
    by_id = {entry["entry"]: entry for entry in cwe["entries"]}
    assert "CWE-1336" not in by_id
    assert by_id["CWE-502"]["findings"] == [position("serialization_format")]
    for entry, finding, kind in (
        ("CWE-319", credentials, "an endpoint URL that uses HTTPS but embeds credentials"),
        ("CWE-306", client, "client findings"),
    ):
        assert by_id[entry]["findings"] == [finding]
        (category,) = by_id[entry]["categories"]
        kept = f"kept from the earlier SARIF rules, it does not hold for {kind}"
        assert kept in category["rationale"]


def test_project_packages_are_tied_to_no_supply_chain_entry(runner, tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    manifest = {"name": "agent", "version": "1.0.0", "dependencies": {"langchain-x": "workspace:*"}}
    (project / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    (project / "bun.lock").write_text("", encoding="utf-8")
    document = _json(runner, _scan(runner, project, tmp_path / "bom.json"))
    findings = document["findings"]
    member = {index for index, item in enumerate(findings) if "'langchain-x'" in item["detail"]}
    assert {findings[index]["category"] for index in member} == {
        "nonregistry_source",
        "lockfile_unread",
    }
    supply_chain = {
        "CWE-829",
        "LLM03:2025",
        "LLM04:2026",
        "ASI04",
        "AML.T0010.001",
        "MANAGE-3.1",
        "Art. 15",
        "A.10.3",
    }
    for edition in document["frameworks"]:
        for entry in edition["entries"]:
            assert entry["entry"] not in supply_chain or not member & set(entry["findings"])


def test_framework_filter_keeps_catalog_order_and_ignores_repetition(runner, tmp_path):
    inventory = _sample(tmp_path)
    args = ("--framework", "cwe", "--framework", "owasp-llm-2025", "--framework", "cwe")
    document = _json(runner, inventory, *args)
    assert [item["framework"] for item in document["frameworks"]] == ["owasp-llm-2025", "cwe"]
    unmapped = {item["category"]: item["findings"] for item in document["unmapped_categories"]}
    assert unmapped == {"completeness": 1, "local_process": 1, "transport_security": 1}
    reordered = _json(runner, inventory, "--framework", "owasp-llm-2025", "--framework", "cwe")
    assert reordered == document


@pytest.mark.parametrize("value", ["owasp-llm", "CWE", "eu-ai-act", ""])
def test_unknown_framework_names_are_usage_errors(runner, tmp_path, value):
    result = _run(runner, _sample(tmp_path), "--framework", value)
    assert result.exit_code == 2
    assert result.stdout == ""


def test_reports_are_deterministic_and_independent_of_inventory_order(runner, tmp_path):
    first = _sample(tmp_path)
    document = json.loads(first.read_text(encoding="utf-8"))
    document["components"].reverse()
    for component in document["components"]:
        component["risks"].reverse()
    second = tmp_path / "reversed.json"
    second.write_text(json.dumps(document), encoding="utf-8")
    for fmt in ("json", "markdown"):
        outputs = {_run(runner, path, "--format", fmt).stdout for path in (first, first, second)}
        assert len(outputs) == 1, fmt


def test_markdown_states_meaning_policy_and_coverage_in_fixed_text(runner, tmp_path):
    result = _run(runner, _sample(tmp_path), "--format", "markdown")
    assert result.exit_code == 0
    lines = result.stdout.splitlines()
    assert lines[:3] == ["# Framework crosswalk", "", crosswalk.MEANING]
    assert lines[4].startswith("Findings: 5, as `risk` scores them under the built-in policy")
    assert "Collection coverage, as `risk` assesses it: unknown." in lines[4]
    assert "### AML.T0109 AI Supply Chain Rug Pull" in lines
    assert "| completeness | 1 | yes |" not in lines


def _cells(source: str) -> list[list[str]]:
    """Every table row's cells as a CommonMark renderer reads them, as text.

    A renderer drops the cells beyond the header's count and pads missing ones, so a
    split cell shows as a changed text, which the callers compare.
    """
    rows: list[list[str]] = []
    inside = False
    for token in MARKDOWN.parse(source):
        if token.type in {"table_open", "table_close"}:
            inside = token.type == "table_open"
        elif inside and token.type == "tr_open":
            rows.append([])
        elif inside and token.type == "inline":
            rows[-1].append("".join(child.content for child in token.children or []))
    return rows


def _literal(value: str) -> str:
    text = neutralize(value)
    return text if len(text) <= MAX_MARKDOWN_TEXT else text[: MAX_MARKDOWN_TEXT - 3] + "..."


@pytest.mark.parametrize("hostile", HOSTILE)
def test_inventory_text_renders_literally_and_forms_no_markup(runner, tmp_path, hostile):
    inventory = _write(
        tmp_path / "bom.json",
        MCPServerComponent(
            bom_ref="ref " + hostile,
            name="n",
            risks=[_risk("version_pinning", HIGH, "detail " + hostile)],
        ),
        MCPServerComponent(
            bom_ref="mcp-server:b", name="b", risks=[_risk("cat " + hostile, LOW, "plain")]
        ),
    )
    result = _run(runner, inventory, "--format", "markdown", "--framework", "cwe")
    assert result.exit_code == 0, result.output
    text = result.stdout
    tokens = MARKDOWN.parse(text)
    kinds = {child.type for token in tokens for child in token.children or []}
    assert not {"html_inline", "em_open", "strong_open", "s_open", "image"} & kinds
    assert not {token.type for token in tokens} & {"html_block", "fence", "code_block"}
    links = [
        child.attrGet("href")
        for token in tokens
        for child in token.children or []
        if child.type == "link_open"
    ]
    assert links == [crosswalk.framework("cwe").source]
    code = [c.content for t in tokens for c in t.children or [] if c.type == "code_inline"]
    assert code == ["risk", "risk"]
    rows = _cells(text)
    finding = ["high", "version_pinning", _literal("ref " + hostile), _literal("detail " + hostile)]
    assert [row for row in rows if row[:1] == ["high"]] == [finding]
    unmapped = [row for row in rows if len(row) == 3 and row[2] in {"yes", "no"}]
    assert unmapped == [[_literal("cat " + hostile), "1", "no"]]
    for line in text.splitlines():
        assert not line.lstrip().startswith("::")
        assert not re.search(r"##[A-Za-z]*\[", line)
        assert not re.search(r"[\x00-\x08\x0a-\x1f\x7f​‪-‮﻿]", line)
        assert "://" not in line.replace("<https://", "") and "www." not in line


def test_json_neutralizes_details_and_keeps_identifiers_exact(runner, tmp_path):
    hostile = "\x1b[31m‮::error::x ##[error]y"
    inventory = _write(
        tmp_path / "bom.json",
        MCPServerComponent(
            bom_ref="ref " + hostile, name="n", risks=[_risk("version_pinning", HIGH, hostile)]
        ),
    )
    result = _run(runner, inventory)
    assert result.exit_code == 0
    assert "##[" not in result.stdout and "\x1b" not in result.stdout
    (finding,) = json.loads(result.stdout)["findings"]
    assert finding["detail"] == neutralize(hostile)
    assert finding["component_ref"] == "ref " + hostile
    written = tmp_path / "out.json"
    assert _run(runner, inventory, "-o", written).exit_code == 0
    assert json.loads(written.read_text(encoding="utf-8")) == json.loads(result.stdout)


def test_json_keeps_categories_exact_and_the_guide_says_which_fields_are_neutralized(
    runner, tmp_path
):
    hostile = "\x1b[2J\n::error::forged\u202e"
    inventory = _write(
        tmp_path / "bom.json",
        MCPServerComponent(
            bom_ref="ref" + hostile, name="n", risks=[_risk("pinning" + hostile, HIGH, hostile)]
        ),
    )
    (finding,) = _json(runner, inventory)["findings"]
    assert finding["category"] == "pinning" + hostile
    assert finding["component_ref"] == "ref" + hostile
    assert finding["detail"] == neutralize(hostile)
    guide = " ".join(PAGE.read_text(encoding="utf-8").split())
    assert (
        "Only in `detail` are control, bidirectional and invisible characters, including every "
        "default-ignorable code point, replaced as on a terminal; `category` and "
        "`component_ref` are kept exactly as the inventory records them" in guide
    )
    assert "Treat them as untrusted: escape them before you print them" in guide


def test_long_text_is_cut_and_long_entry_lists_are_counted(runner, tmp_path):
    count = MAX_MARKDOWN_FINDINGS + 7
    inventory = _write(
        tmp_path / "bom.json",
        MCPServerComponent(
            bom_ref="mcp-server:many",
            name="many",
            risks=[
                _risk("version_pinning", HIGH, f"{index:03d} " + "y" * 3000)
                for index in range(count)
            ],
        ),
    )
    document = _json(runner, inventory, "--framework", "mitre-atlas-2026.10")
    assert len(_entries(document, "mitre-atlas-2026.10")["AML.T0109"]) == count
    assert len(document["findings"][0]["detail"]) == 3004
    markdown = _run(runner, inventory, "--framework", "mitre-atlas-2026.10", "--format", "markdown")
    rows = [row for row in _cells(markdown.stdout) if row[:1] == ["high"]]
    assert len(rows) == MAX_MARKDOWN_FINDINGS
    assert all(len(row[3]) == MAX_MARKDOWN_TEXT and row[3].endswith("...") for row in rows)
    assert "7 more findings reference this entry; the JSON format lists every one." in (
        markdown.stdout.splitlines()
    )


def test_categories_outside_the_catalog_are_reported_unmapped(runner, tmp_path):
    inventory = _write(
        tmp_path / "bom.json",
        MCPServerComponent(
            bom_ref="mcp-server:a",
            name="a",
            risks=[_risk("made_up", HIGH), _risk("made_up", LOW), _risk("shadowscan-heuristic")],
        ),
    )
    document = _json(runner, inventory)
    assert document["unmapped_categories"] == [
        {"category": "made_up", "findings": 2, "in_catalog": False},
        {"category": "shadowscan-heuristic", "findings": 1, "in_catalog": True},
    ]
    assert all(not edition["entries"] for edition in document["frameworks"])
    markdown = _run(runner, inventory, "--format", "markdown").stdout
    assert "| made\\_up | 2 | no |" in markdown.splitlines()
    assert markdown.count("No finding references an entry of this framework edition.") == 8


def test_an_inventory_without_findings_is_reported_as_such(runner, tmp_path):
    inventory = _write(tmp_path / "bom.json")
    document = _json(runner, inventory)
    assert document["findings"] == [] and document["unmapped_categories"] == []
    markdown = _run(runner, inventory, "--format", "markdown").stdout
    assert "There are no findings." in markdown.splitlines()
    assert "Every finding references" not in markdown


def test_it_is_a_report_not_a_gate(runner, tmp_path):
    inventory = _write(
        tmp_path / "bom.json",
        MCPServerComponent(
            bom_ref="mcp-server:a", name="a", risks=[_risk("bidi_override", RiskSeverity.CRITICAL)]
        ),
    )
    assert runner.invoke(main, ["risk", str(inventory), "--no-project-policy"]).exit_code == 1
    assert _run(runner, inventory).exit_code == 0
    assert _run(runner, inventory, "--format", "markdown").exit_code == 0


def test_a_project_policy_beside_the_inventory_is_never_applied(runner, tmp_path):
    inventory = _sample(tmp_path)
    (tmp_path / ".nexus-symbiote.yaml").write_text(
        'version: "1.0"\nrisk:\n  ignore_categories: ["version_pinning"]\n'
        "  suppressions:\n"
        '    - {component_ref: "mcp-server:a", category: "local_process", reason: "r",'
        ' owner: "o", expires: 2999-01-01}\n',
        encoding="utf-8",
    )
    document = _json(runner, inventory)
    categories = {finding["category"] for finding in document["findings"]}
    assert {"version_pinning", "local_process"} <= categories
    assert (document["policy_source"], document["ignored_findings"]) == ("built-in", 0)
    assert document["suppressed_findings"] == 0


def test_output_files_hold_the_report_and_are_private(runner, tmp_path):
    inventory = _sample(tmp_path)
    for fmt in ("json", "markdown"):
        target = tmp_path / f"report.{fmt}"
        printed = _run(runner, inventory, "--format", fmt).stdout
        assert _run(runner, inventory, "--format", fmt, "-o", target).exit_code == 0
        written = target.read_text(encoding="utf-8")
        assert written == (printed if fmt == "markdown" else printed.removesuffix("\n"))
        if os.name == "posix":
            assert target.stat().st_mode & 0o077 == 0


def test_the_inventory_is_never_overwritten(runner, tmp_path):
    inventory = _sample(tmp_path)
    before = inventory.read_bytes()
    linked = tmp_path / "linked.json"
    os.link(inventory, linked)
    (tmp_path / "sub").mkdir()
    for target in (inventory, linked, tmp_path / "sub" / ".." / "bom.json"):
        result = _run(runner, inventory, "-o", target)
        assert result.exit_code == 2
        assert "must not overwrite the source inventory" in result.output
    assert inventory.read_bytes() == before


def test_an_output_link_is_replaced_never_followed(runner, tmp_path):
    inventory = _sample(tmp_path)
    victim = tmp_path / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(victim)
    assert _run(runner, inventory, "-o", link).exit_code == 0
    assert victim.read_text(encoding="utf-8") == "keep"
    assert not link.is_symlink()
    assert json.loads(link.read_text(encoding="utf-8"))["format"] == FORMAT


def test_output_paths_to_directories_or_through_links_are_refused(runner, tmp_path):
    inventory = _sample(tmp_path)
    (tmp_path / "real").mkdir()
    (tmp_path / "linked-dir").symlink_to(tmp_path / "real")
    (tmp_path / "dir-link.json").symlink_to(tmp_path / "real")
    for target in (
        tmp_path / "missing" / "out.json",
        tmp_path / "linked-dir" / "out.json",
        tmp_path / "dir-link.json",
        tmp_path / "real",
    ):
        result = _run(runner, inventory, "-o", target)
        assert result.exit_code == 1, target
        assert OUTPUT_REFUSED in result.output
    assert list((tmp_path / "real").iterdir()) == []


MARKER = "QUOTED-INPUT-MARKER"


@pytest.mark.parametrize(
    "content",
    [
        b'{"components": [], "metadata": {}, "metadata": {}}',
        b'{"components": [], "metadata": {"x": NaN}}',
        b"[" * 100_000 + b"]" * 100_000,
        f'{{"components": [], "{MARKER}": 1}}'.encode(),
        f"not json {MARKER}".encode(),
        b"\xff\xfe",
    ],
    ids=["duplicate-keys", "nan", "deep-nesting", "unknown-field", "not-json", "not-utf8"],
)
def test_invalid_inventories_fail_without_quoting_them(runner, tmp_path, content):
    inventory = tmp_path / "bom.json"
    inventory.write_bytes(content)
    result = _run(runner, inventory)
    assert result.exit_code == 1
    assert "is not a valid native AIBOM file" in result.output
    assert MARKER not in result.output and result.stdout == ""


def test_oversized_inventories_are_refused(runner, tmp_path):
    inventory = tmp_path / "bom.json"
    inventory.write_bytes(
        b'{"components": [], "metadata": {}, "pad": "' + b"x" * (16 << 20) + b'"}'
    )
    result = _run(runner, inventory)
    assert result.exit_code == 1
    assert "16 MiB" in result.output


def test_links_and_special_files_are_refused_without_blocking(runner, tmp_path):
    inventory = _sample(tmp_path)
    link = tmp_path / "link.json"
    link.symlink_to(inventory)
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    for path in (link, fifo):
        result = _run(runner, path)
        assert result.exit_code == 1, path
        assert "is not a valid native AIBOM file" in result.output
    for path in (tmp_path, tmp_path / "missing.json"):
        assert _run(runner, path).exit_code == 2


def test_the_documented_example_is_reproducible(runner, tmp_path):
    inventory = tmp_path / "demo.aibom.json"
    scanned = runner.invoke(
        main, ["scan", str(ROOT / "examples" / "demo-agent"), "-o", str(inventory)]
    )
    assert scanned.exit_code == 0, scanned.output
    shown = PAGE.read_text(encoding="utf-8").split("On the demo agent,", 1)[1]
    command = re.search(r"```bash\n(.*?)```", shown, re.S)
    output = re.search(r"```text\n(.*?)```", shown, re.S)
    assert command and output
    assert command.group(1).splitlines()[1] == (
        "nexus-symbiote crosswalk demo.aibom.json --framework mitre-atlas-2026.10 --format markdown"
    )
    result = _run(runner, inventory, "--framework", "mitre-atlas-2026.10", "--format", "markdown")
    assert result.stdout == output.group(1)


def test_report_building_scales_linearly():
    def report(scale: int) -> None:
        components = [
            MCPServerComponent(
                bom_ref=f"mcp-server:{index}",
                name=str(index),
                risks=[_risk("version_pinning", HIGH, f"d{index}"), _risk("local_process", MEDIUM)],
            )
            for index in range(300 * scale)
        ]
        scored = RiskScorer().score(AIBOM(components=components))
        document = build_report(scored, crosswalk.FRAMEWORK_KEYS)
        json.dumps(document, indent=2, sort_keys=True)
        render_markdown(document)

    assert scaling_ratio(report) < 10
