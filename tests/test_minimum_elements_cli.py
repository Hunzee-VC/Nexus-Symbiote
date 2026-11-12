"""The minimum-elements command: formats, the opt-in gate, hostile text and refusals."""

from __future__ import annotations

import json
import os
import re
import stat
from datetime import datetime
from pathlib import Path

import pytest
from click.testing import CliRunner
from markdown_it import MarkdownIt
from markdown_it.token import Token

from nexus_symbiote import minimum_elements as me
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, MAX_NATIVE_BYTES, DependencyEdge
from nexus_symbiote.core.models import (
    AgentComponent,
    MCPServerComponent,
    ModelComponent,
    RAGSourceComponent,
    ToolComponent,
)
from nexus_symbiote.minimum_elements_cli import EXPORT_FAILED, EXPORT_TOO_DEEP
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV
from nexus_symbiote.utils.terminal import neutralize

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "minimum-elements.md"
WORKFLOW_COMMAND = "x\n::error title=Spoofed::All checks passed\n::add-mask::CRITICAL\u2028y"
CONTROLS = "\x1b]8;;https://attacker.example\x07x\x1b]8;;\x07\x1b[1A\x1b[2K\rfake\u202egpj.exe"
MARKUP = "[approve](https://attacker.example) <script>alert(1)</script> **b** | `c` <!-- d -->"
LOG_COMMANDS = "##[error]forged ##vso[task.complete result=Succeeded]"
HOSTILE = [WORKFLOW_COMMAND, CONTROLS, MARKUP, LOG_COMMANDS, "``` fence ` tick", " padded "]
# References used whole: a backtick or space at either edge must not join or leave the fence.
EDGES = [
    "`",
    "```",
    "a`",
    "`a",
    "` [x](https://attacker.example/1) `",
    "b``[click me](https://attacker.example/2)",
    " leading",
    "trailing ",
    "   ",
]
REFERENCES = {"model:" + value for value in HOSTILE} | set(EDGES)
# A runner acts on "::" at the start of a line and on "##name[" anywhere in one.
LOG_COMMAND = re.compile(r"##[A-Za-z]*\[")


@pytest.fixture
def demo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    output = tmp_path / "demo.aibom.json"
    scanned = CliRunner().invoke(
        main, ["scan", str(ROOT / "examples" / "demo-agent"), "-o", str(output)]
    )
    assert scanned.exit_code == 0, scanned.output
    return output


@pytest.fixture
def hostile(tmp_path: Path) -> Path:
    path = tmp_path / "hostile.json"
    components = [ModelComponent(bom_ref="model:" + text, name="m") for text in HOSTILE]
    components += [ModelComponent(bom_ref=ref, name="m") for ref in EDGES]
    components.append(RAGSourceComponent(bom_ref="rag:" + MARKUP, name="r"))
    path.write_text(AIBOM(components=components).to_json())
    return path


def run(runner: CliRunner, *args: str):
    return runner.invoke(main, ["minimum-elements", *args])


def test_text_report_lists_each_missing_element_with_how_to_supply_it(runner, demo):
    result = run(runner, str(demo))
    assert result.exit_code == 0, result.output
    assert result.stderr == ""
    lines = result.stdout.splitlines()
    assert lines[0] == "G7 AI SBOM minimum-element coverage, edition g7-ai-sbom-2026-05-12"
    assert lines[1].startswith("Statement: Coverage is not compliance.")
    assert lines[4].startswith("Overall: 11 of 39 present (28.2%)")
    report = me.assess(AIBOM.load(demo))
    missing = [r for r in report.elements if r.status != me.PRESENT]
    assert len(missing) == 39
    for item in missing:
        label = item.status.replace("-", " ")
        heading = next(
            i for i, line in enumerate(lines) if line.startswith(f"  {label}: {item.element.name}")
        )
        hint = next(
            line for line in lines[heading + 1 :] if line.startswith("    how to supply it: ")
        )
        assert hint == "    how to supply it: " + item.element.hint
    assert "  present (generated): SBOM version; SBOM data format name;" in result.stdout


def test_json_report_is_versioned_complete_and_byte_for_byte_deterministic(runner, demo, tmp_path):
    first, second = run(runner, str(demo), "-f", "json"), run(runner, str(demo), "-f", "json")
    assert first.exit_code == 0 and first.stdout == second.stdout
    document = json.loads(first.stdout)
    assert document["format"] == "nexus-symbiote/minimum-elements/v1"
    assert document["edition"] == "g7-ai-sbom-2026-05-12"
    assert len(document["elements"]) == 50
    assert sum(document["counts"].values()) == 50
    assert document["coverage"] == {"present": 11, "assessable": 39, "percent": 28.2}
    assert [c["coverage"]["assessable"] for c in document["clusters"]] == [9, 7, 12, 7, 1, 3, 0]
    written = tmp_path / "report.json"
    assert run(runner, str(demo), "-f", "json", "-o", str(written)).stdout == ""
    assert written.read_text(encoding="utf-8") == first.stdout
    assert stat.S_IMODE(written.stat().st_mode) == 0o600


def test_markdown_report_has_a_summary_and_a_table_per_cluster(runner, demo, tmp_path):
    written = tmp_path / "report.md"
    result = run(runner, str(demo), "--format", "markdown", "--output", str(written))
    assert result.exit_code == 0 and result.stdout == ""
    text = written.read_text(encoding="utf-8")
    assert text == run(runner, str(demo), "-f", "markdown").stdout
    assert text.startswith("# G7 AI SBOM minimum-element coverage\n")
    assert [line[3:] for line in text.splitlines() if line.startswith("## ")] == [
        cluster.heading for cluster in me.CLUSTERS
    ]
    rows = [line for line in text.splitlines() if line.startswith("| ") and "---" not in line]
    assert len(rows) == 1 + len(me.CLUSTERS) + len(me.CLUSTERS) + 50
    assert "- Model version: `model:models/intent-classifier.safetensors`" in text
    assert "| Metadata | 6 of 9 present (66.6%) | 6 | 3 | 0 | 1 | 0 |" in text


def test_hostile_references_cannot_forge_lines_controls_or_log_commands(runner, hostile):
    for fmt in ("text", "markdown", "json"):
        result = run(runner, str(hostile), "-f", fmt)
        assert result.exit_code == 0, result.output
        output = result.output
        for character in ("\x1b", "\x07", "\r", "\u202e", "\u2028"):
            assert character not in output, (fmt, character)
        for line in output.splitlines():
            assert not line.lstrip().startswith("::"), (fmt, line)
            assert not LOG_COMMAND.search(line), (fmt, line)
    text = run(runner, str(hostile)).stdout
    for value in HOSTILE:
        assert "    without it: " + neutralize("model:" + value) in text
    document = json.loads(run(runner, str(hostile), "-f", "json").stdout)
    version = next(e for e in document["elements"] if e["id"].endswith("/model-version"))
    assert set(version["subjects"]["without"]["listed"]) == REFERENCES


def _tokens(tokens: list[Token]) -> list[Token]:
    flat = []
    for token in tokens:
        flat.append(token)
        flat += _tokens(token.children or [])
    return flat


def test_hostile_references_are_exact_inert_code_spans_to_a_commonmark_parser(runner, hostile):
    text = run(runner, str(hostile), "-f", "markdown").stdout
    parser = MarkdownIt("commonmark").enable("table")
    tokens = _tokens(parser.parse(text))
    active = {"link_open", "image", "html_inline", "html_block"}
    assert [token.type for token in tokens if token.type in active] == []
    item = next(line for line in text.splitlines() if line.startswith("- Model version: "))
    inline = next(token for token in _tokens(parser.parse(item)) if token.type == "inline")
    pieces = [(token.type, token.content) for token in inline.children or []]
    # Each reference is one code span, in reference order, joined only by fixed text.
    listed = sorted(REFERENCES)
    assert pieces[0] == ("text", "Model version: ")
    assert pieces[1::2] == [("code_inline", neutralize(ref)) for ref in listed]
    assert pieces[2::2] == [("text", ", ")] * (len(listed) - 1)


@pytest.mark.parametrize(
    ("threshold", "exit_code"),
    [("0", 0), ("28", 0), ("28.2", 0), ("28.205", 0), ("28.21", 1), ("28.3", 1), ("100", 1)],
)
def test_fail_under_gates_the_printed_ratio_exactly(runner, demo, threshold, exit_code):
    result = run(runner, str(demo), "--fail-under", threshold)
    assert result.exit_code == exit_code, result.output
    assert result.stdout.splitlines()[5].startswith("Gate: ")
    verdict = result.stderr.splitlines()
    if exit_code:
        assert verdict[0] == (
            f"Coverage gate failed: 11 of 39 present (28.2%), below the required {threshold}%"
        )
        listed = [line for line in verdict[1:] if line.startswith("  missing: ")]
        assert len(listed) == 28
        assert "  missing: SBOM author (g7ai-2026/metadata/sbom-author)" in verdict
    else:
        assert verdict == [
            f"Coverage gate passed: 11 of 39 present (28.2%), at or above the required {threshold}%"
        ]


def test_without_fail_under_a_low_ratio_still_exits_zero(runner, demo):
    result = run(runner, str(demo), "-f", "json")
    assert result.exit_code == 0 and result.stderr == ""
    assert json.loads(result.stdout)["gate"] is None


@pytest.mark.parametrize(
    "value",
    [
        "nan",
        "NaN",
        "inf",
        "-1",
        "-0",
        "+50",
        "101",
        "100.0000001",
        "1e2",
        " 50",
        "50.",
        "5,0",
        "50.1234567",
        "５０",
        "",
    ],
)
def test_fail_under_refuses_anything_but_a_plain_percentage(runner, demo, value):
    result = run(runner, str(demo), "--fail-under", value)
    assert result.exit_code == 2, result.output
    assert "must be a decimal number from 0 to 100" in result.output


def _deep(depth: int) -> str:
    return '{"components": ' + "[" * depth + "]" * depth + "}"


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ("not json", "not strict UTF-8 JSON"),
        ('{"components": [], "components": []}', "not strict UTF-8 JSON"),
        ('{"metadata": {"version": NaN}}', "not strict UTF-8 JSON"),
        (_deep(100_000), "not strict UTF-8 JSON"),
        ('{"components": [{"bom_ref": "x"}]}', "does not match the native AgentBOM schema"),
        ('{"metadata": {"spec_version": "9.0.0"}}', "is not supported by this build"),
    ],
)
def test_invalid_inventories_are_refused_without_quoting_them(runner, tmp_path, content, reason):
    path = tmp_path / "bom.json"
    path.write_text(content, encoding="utf-8")
    report = tmp_path / "report.txt"
    result = run(runner, str(path), "-o", str(report))
    assert result.exit_code == 1
    assert "is not a valid native AIBOM file" in result.output and reason in result.output
    assert not report.exists()


def test_a_symbolic_link_fifo_or_oversized_inventory_is_refused(runner, demo, tmp_path):
    link, report = tmp_path / "link.json", tmp_path / "report.txt"
    link.symlink_to(demo)
    refused = run(runner, str(link), "-o", str(report))
    assert refused.exit_code == 1 and "symbolic link" in refused.output
    assert not report.exists()
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    refused = run(runner, str(fifo))
    assert refused.exit_code == 1 and "not a regular file" in refused.output
    large = tmp_path / "large.json"
    large.write_bytes(b" " * (MAX_NATIVE_BYTES + 1))
    refused = run(runner, str(large))
    assert refused.exit_code == 1 and "exceeds the 16 MiB" in refused.output
    for path in (tmp_path / "missing.json", tmp_path):
        assert run(runner, str(path)).exit_code == 2


def test_an_inventory_that_cannot_be_exported_fails_closed(runner, tmp_path):
    bom = AIBOM(components=[AgentComponent(bom_ref="agent:repository:" + "2" * 24, name="a")])
    bom.metadata.timestamp = datetime(2026, 11, 10, 12, 0)
    path, report = tmp_path / "naive.json", tmp_path / "report.txt"
    path.write_text(bom.model_dump_json(exclude_none=True), encoding="utf-8")
    result = run(runner, str(path), "-o", str(report), "--fail-under", "0")
    assert result.exit_code == 1
    assert result.output.strip() == f"Error: {EXPORT_FAILED}"
    assert not report.exists()


def test_an_inventory_too_deep_to_export_fails_closed(runner, tmp_path):
    nested = '"Apache-2.0"'
    for _ in range(400):
        nested = '{"terms": [' + nested + "]}"
    path, report = tmp_path / "deep.json", tmp_path / "report.txt"
    path.write_text(
        '{"metadata": {"spec_version": "1.1.0"}, "components": [{"bom_ref": "model:w", '
        '"component_type": "model", "name": "w", "properties": {"license": ' + nested + "}}]}"
    )
    assert AIBOM.load(path).components[0].properties["license"]
    result = run(runner, str(path), "-o", str(report))
    assert result.exit_code == 1
    assert result.output.strip() == f"Error: {EXPORT_TOO_DEEP}"
    assert not report.exists()


def test_the_report_never_overwrites_its_inventory(runner, demo, tmp_path):
    before = demo.read_bytes()
    assert run(runner, str(demo), "-o", str(demo)).exit_code == 2
    alias = tmp_path / "alias.json"
    os.link(demo, alias)
    refused = run(runner, str(demo), "-o", str(alias))
    assert refused.exit_code == 2 and "must not overwrite the source inventory" in refused.output
    assert demo.read_bytes() == before


def _guide_table() -> list[list[str]]:
    rows = []
    for line in GUIDE.read_text(encoding="utf-8").splitlines():
        if line.startswith("| `g7ai-2026/"):
            rows.append([cell.strip().replace("`", "") for cell in line.strip("|").split("|")])
    return rows


def test_the_guide_element_table_is_the_catalog():
    assert _guide_table() == [
        [
            element.id,
            element.name,
            element.cluster.subject,
            element.assessable,
            element.rule,
            element.cyclonedx,
            element.spdx,
            element.carried,
        ]
        for element in me.ELEMENTS
    ]


def test_the_guide_names_every_native_value_the_evaluation_recognizes():
    section = GUIDE.read_text(encoding="utf-8").split("These native values are recognized", 1)[1]
    section = section.split("\n## ", 1)[0]
    for rule in me._SUBJECT_RULES.values():
        for field in rule.native:
            assert f"`{field}`" in section, field


def test_the_guide_example_is_the_real_demo_output(runner, demo):
    guide = GUIDE.read_text(encoding="utf-8")
    block = re.search(
        r"nexus-symbiote minimum-elements demo\.aibom\.json\n```\n\n.*?```text\n(.*?)```",
        guide,
        re.S,
    )
    assert block, "the guide no longer shows the demo report after its command"
    assert block.group(1) == run(runner, str(demo)).stdout


def test_the_guide_gated_example_is_the_real_demo_output(runner, demo):
    guide = GUIDE.read_text(encoding="utf-8")
    block = re.search(
        r"`--fail-under 50` the report gains one line after its `Overall:` line:\n\n"
        r"```text\n(.*?)```\n\nand is followed by this on standard error, and the command "
        r"exits 1:\n\n```text\n(.*?)```\n\nand (\d+) more `missing:` lines",
        guide,
        re.S,
    )
    assert block, "the guide no longer shows the gated demo output"
    plain = run(runner, str(demo)).stdout.splitlines(keepends=True)
    gated = run(runner, str(demo), "--fail-under", "50")
    assert gated.exit_code == 1
    assert gated.stdout == "".join([*plain[:5], block.group(1), *plain[5:]])
    shown = block.group(2).splitlines(keepends=True)
    errors = gated.stderr.splitlines(keepends=True)
    assert errors[: len(shown)] == shown
    assert len(errors) == len(shown) + int(block.group(3))


def test_text_names_inapplicable_clusters_and_counts_unlisted_subjects(runner, tmp_path):
    path = tmp_path / "bom.json"
    path.write_text(AIBOM(components=[AgentComponent(bom_ref="agent:a", name="a")]).to_json())
    text = run(runner, str(path)).stdout
    assert "Models: not applicable: The inventory records no model component.\n" in text
    assert "Datasets Properties: not applicable: The inventory records no dataset or" in text
    models = [ModelComponent(bom_ref=f"model:{i:02d}", name=f"m{i}") for i in range(25)]
    path.write_text(AIBOM(components=models).to_json())
    text = run(runner, str(path)).stdout
    assert "  missing: Model version (0 of 25 have it)\n" in text
    assert "    without it: 5 more not listed\n" in text


def test_a_partly_exported_relationship_set_states_its_coverage(runner, tmp_path):
    agent = AgentComponent(bom_ref="agent:repository:" + "3" * 24, name="a")
    server = MCPServerComponent(bom_ref="mcp:docs", name="docs")
    tool = ToolComponent(bom_ref="tool:search", name="search")
    edges = [
        DependencyEdge(
            source_ref=agent.bom_ref,
            target_ref="mcp:docs",
            relationship="configured-with",
            conditions="repository association",
        ),
        DependencyEdge(
            source_ref="mcp:docs", target_ref="tool:search", relationship="provides-tool"
        ),
    ]
    path = tmp_path / "bom.json"
    path.write_text(AIBOM(components=[agent, server, tool], dependencies=edges).to_json())
    exported = "1 of 2 relationships exported"
    text = run(runner, str(path)).stdout
    assert f"  present (declared): SBOM dependency relationship (partial; {exported})\n" in text
    markdown = run(runner, str(path), "-f", "markdown").stdout
    row = next(line for line in markdown.splitlines() if line.startswith("| SBOM dependency"))
    cells = [cell.strip() for cell in row.strip("|").split("|")]
    assert cells[:4] == ["SBOM dependency relationship", "present", "declared", exported]
    assert cells[4] == f"{me.REASONS['partial']} {me.REASONS['unexported-relationships']}"


def test_markdown_states_the_gate_it_was_run_with(runner, demo):
    result = run(runner, str(demo), "-f", "markdown", "--fail-under", "25")
    assert result.exit_code == 0
    assert (
        "**Gate:** passed: 11 of 39 present (28.2%), at or above the required 25%." in result.stdout
    )
