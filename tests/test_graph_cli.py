"""The graph command: usage, refusals, confined output, determinism and offline operation."""

from __future__ import annotations

import json
import os
import re
import socket
import stat
from pathlib import Path

import pytest

from nexus_symbiote import modes
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.models import AgentComponent, ToolComponent
from nexus_symbiote.graph_view import SCRIPT, build_view, view_document
from nexus_symbiote.utils.terminal import OUTPUT_REFUSED
from tests.conftest import ISOLATED_NAMES, ISOLATED_PREFIXES

ROOT = Path(__file__).resolve().parents[1]
UNSET = {modes.ENV_VAR: None}


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from click.testing import CliRunner

    output = tmp_path_factory.mktemp("demo") / "demo.aibom.json"
    # A module-scoped fixture runs before the per-test isolation, so it clears the ambient names itself.
    ambient = {
        name: None
        for name in os.environ
        if name.startswith(ISOLATED_PREFIXES) or name in ISOLATED_NAMES
    }
    scanned = CliRunner().invoke(
        main,
        ["scan", str(ROOT / "examples" / "demo-agent"), "-o", str(output)],
        env={**ambient, **UNSET},
    )
    assert scanned.exit_code == 0, scanned.output
    return output


def saved(tmp_path: Path, bom: AIBOM, name: str = "bom.json") -> Path:
    path = tmp_path / name
    bom.save(path)
    return path


def write_inventory(tmp_path: Path, content: bytes) -> Path:
    path = tmp_path / "inventory.json"
    path.write_bytes(content)
    return path


def test_html_is_written_to_a_private_file_with_a_summary_on_stderr(runner, demo, tmp_path):
    output = tmp_path / "graph.html"
    result = runner.invoke(main, ["graph", str(demo), "-o", str(output)], env=UNSET)
    assert result.exit_code == 0, result.output
    assert result.stdout == ""
    assert result.stderr == (
        "Graph view: 11 components, 13 edges, 3 exposure paths; coverage unknown\n"
    )
    text = output.read_text(encoding="utf-8")
    assert text.startswith('<!DOCTYPE html>\n<html lang="en">')
    assert text.count("<script>") == 1 and f"<script>{SCRIPT}</script>" in text
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_html_is_never_printed_to_standard_output(runner, demo):
    result = runner.invoke(main, ["graph", str(demo)], env=UNSET)
    assert result.exit_code == 2
    assert "the HTML view is written to a file: pass -o/--output" in result.output
    assert "<html" not in result.output
    explicit = runner.invoke(main, ["graph", str(demo), "--format", "html"], env=UNSET)
    assert explicit.exit_code == 2


def test_json_goes_to_standard_output_and_matches_the_model(runner, demo):
    result = runner.invoke(main, ["graph", str(demo), "--format", "json"], env=UNSET)
    assert result.exit_code == 0, result.output
    expected = view_document(build_view(AIBOM.load(demo), max_nodes=2_000))
    assert json.loads(result.stdout) == expected
    assert result.stderr == ""


def test_json_can_be_written_to_a_file(runner, demo, tmp_path):
    output = tmp_path / "graph.json"
    result = runner.invoke(main, ["graph", str(demo), "--format", "json", "-o", str(output)])
    assert result.exit_code == 0, result.output
    assert result.stdout == ""
    assert json.loads(output.read_text())["format"] == "nexus-symbiote/graph-view/v1"


def test_output_is_deterministic(runner, demo, tmp_path):
    outputs = []
    for name in ("a.html", "b.html"):
        result = runner.invoke(main, ["graph", str(demo), "-o", str(tmp_path / name)])
        assert result.exit_code == 0, result.output
        outputs.append((tmp_path / name).read_bytes())
    assert outputs[0] == outputs[1]
    documents = [runner.invoke(main, ["graph", str(demo), "--format", "json"]).stdout for _ in "ab"]
    assert documents[0] == documents[1]


@pytest.mark.parametrize("output_format", ["html", "json"])
def test_the_inventory_is_never_overwritten(runner, demo, tmp_path, output_format):
    before = demo.read_bytes()
    alias = tmp_path / "alias.json"
    os.link(demo, alias)
    for target in (demo, alias):
        result = runner.invoke(
            main, ["graph", str(demo), "--format", output_format, "-o", str(target)]
        )
        assert result.exit_code == 2
        assert "output must not overwrite the source inventory" in result.output
    assert demo.read_bytes() == before


def test_output_through_a_symlinked_directory_is_refused(runner, demo, tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real, target_is_directory=True)
    result = runner.invoke(main, ["graph", str(demo), "-o", str(tmp_path / "link" / "g.html")])
    assert result.exit_code == 1
    assert OUTPUT_REFUSED in result.output
    assert list(real.iterdir()) == []


def test_output_onto_a_directory_or_a_fifo_is_refused(runner, demo, tmp_path):
    (tmp_path / "dir").mkdir()
    os.mkfifo(tmp_path / "fifo")
    for target in ("dir", "fifo"):
        result = runner.invoke(main, ["graph", str(demo), "-o", str(tmp_path / target)])
        assert result.exit_code == 1, target
        assert OUTPUT_REFUSED in result.output


@pytest.mark.parametrize("value", ["0", "20001", "-1", "many"])
def test_max_nodes_outside_its_range_is_a_usage_error(runner, demo, value):
    result = runner.invoke(main, ["graph", str(demo), "--format", "json", "--max-nodes", value])
    assert result.exit_code == 2


def test_a_graph_over_max_nodes_fails_and_suggests_focus(runner, demo, tmp_path):
    output = tmp_path / "graph.html"
    result = runner.invoke(main, ["graph", str(demo), "-o", str(output), "--max-nodes", "10"])
    assert result.exit_code == 1
    assert (
        "The view would show 11 components, more than --max-nodes 10. Select part of the "
        "graph with --focus REF, or raise --max-nodes (at most 20000)."
    ) in result.output
    assert not output.exists()
    exact = runner.invoke(main, ["graph", str(demo), "--format", "json", "--max-nodes", "11"])
    assert exact.exit_code == 0


def test_focus_restricts_the_view(runner, tmp_path):
    bom = AIBOM(
        components=[
            AgentComponent(bom_ref="a1", name="one", tool_refs=["t1"]),
            ToolComponent(bom_ref="t1", name="t1"),
            AgentComponent(bom_ref="a2", name="two", tool_refs=["t2"]),
            ToolComponent(bom_ref="t2", name="t2"),
        ]
    )
    path = saved(tmp_path, bom)
    result = runner.invoke(main, ["graph", str(path), "--format", "json", "--focus", "t2"])
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["focus"] == "t2"
    assert sorted(node["ref"] for node in document["nodes"]) == ["a2", "t2"]
    limited = runner.invoke(
        main, ["graph", str(path), "--format", "json", "--focus", "t2", "--max-nodes", "2"]
    )
    assert limited.exit_code == 0


def test_an_unknown_focus_fails_naming_only_a_clipped_reference(runner, tmp_path):
    listed_name = "inventory-only-name"
    bom = AIBOM(components=[ToolComponent(bom_ref="t", name=listed_name)])
    path = saved(tmp_path, bom)
    focus = "missing\u202e\x1b[31m::error::" + "y" * 1_000
    result = runner.invoke(main, ["graph", str(path), "--format", "json", "--focus", focus])
    assert result.exit_code == 1
    assert "unknown component: missing\ufffd\ufffd[31m::error::yyy" in result.output
    assert listed_name not in result.output and "\x1b" not in result.output
    assert "\u202e" not in result.output
    assert len(result.output) < 400


def test_an_invalid_graph_fails_like_blast_radius(runner, tmp_path):
    bom = AIBOM(
        components=[AgentComponent(bom_ref="a", name="a")],
        dependencies=[DependencyEdge(source_ref="a", target_ref="gone", relationship="invokes")],
    )
    # Written as another producer could write it: this build refuses to save a dangling edge.
    with pytest.raises(ValueError, match="unknown component"):
        bom.save(tmp_path / "refused.json")
    document = bom.model_dump(mode="json", exclude_none=True)
    path = write_inventory(tmp_path, json.dumps(document).encode())
    result = runner.invoke(main, ["graph", str(path), "--format", "json"])
    assert result.exit_code == 1
    assert "invalid graph: invokes: dangling edge a -> gone" in result.output
    assert result.stdout == ""


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        (b'{"components": [], "components": []}', "duplicate keys"),
        (b"[" * 100_000 + b"]" * 100_000, "not strict UTF-8 JSON"),
        (b'{"metadata": {"spec_version": "1.1.0"}, "components": [{"bom_ref": "<b>"}]}', "schema"),
        (b"\xff\xfe not json", "not strict UTF-8 JSON"),
        (b'{"metadata": {"spec_version": "9.0.0"}}', "not supported"),
    ],
)
def test_an_invalid_inventory_is_refused_without_quoting_it(runner, tmp_path, content, reason):
    path = write_inventory(tmp_path, content)
    result = runner.invoke(main, ["graph", str(path), "--format", "json"])
    assert result.exit_code == 1
    assert "is not a valid native AIBOM file" in result.output
    assert reason in result.output
    assert "<b>" not in result.output


def test_an_oversized_inventory_is_refused(runner, tmp_path):
    path = write_inventory(tmp_path, b" " * (16 * 1024 * 1024 + 1))
    result = runner.invoke(main, ["graph", str(path), "--format", "json"])
    assert result.exit_code == 1
    assert "16 MiB" in result.output


def test_an_inventory_behind_a_link_or_a_fifo_is_refused(runner, demo, tmp_path):
    link = tmp_path / "link.json"
    link.symlink_to(demo)
    linked = runner.invoke(main, ["graph", str(link), "--format", "json"])
    assert linked.exit_code == 1
    assert "symbolic link" in linked.output
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    special = runner.invoke(main, ["graph", str(fifo), "--format", "json"])
    assert special.exit_code == 1
    assert "not a regular file" in special.output
    directory = runner.invoke(main, ["graph", str(tmp_path), "--format", "json"])
    assert directory.exit_code == 2


def test_hostile_text_stays_inert_in_files_and_on_standard_output(runner, tmp_path):
    hostile = '</script><script>alert(1)</script>"><img src=x>\u202e##[error]::error::x'
    bom = AIBOM(
        components=[
            AgentComponent(bom_ref=f"a:{hostile}", name=hostile, tool_refs=[f"t:{hostile}"]),
            ToolComponent(bom_ref=f"t:{hostile}", name=hostile, version=hostile),
        ],
        dependencies=[
            DependencyEdge(
                source_ref=f"a:{hostile}",
                target_ref=f"t:{hostile}",
                relationship="configured-with",
                conditions=hostile,
            )
        ],
    )
    path = saved(tmp_path, bom)
    output = tmp_path / "graph.html"
    result = runner.invoke(main, ["graph", str(path), "-o", str(output)])
    assert result.exit_code == 0, result.output
    page = output.read_text(encoding="utf-8")
    assert page.count("<script>") == 1 and "<img" not in page
    assert "\u202e" not in page and "##[" not in page
    assert "&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;&quot;&gt;&lt;img src=x&gt;" in page
    printed = runner.invoke(main, ["graph", str(path), "--format", "json"])
    assert printed.exit_code == 0
    assert "\u202e" not in printed.stdout and "##[" not in printed.stdout
    assert "##\\u005b" in printed.stdout
    assert json.loads(printed.stdout)["nodes"][0]["name"] == hostile


def test_the_command_stays_offline_even_in_live_mode(runner, demo, tmp_path, monkeypatch):
    import nexus_symbiote.graph_view as graph_view

    def resolving(*args: object, **kwargs: object) -> None:
        socket.getaddrinfo("example.com", 443)

    monkeypatch.setattr(graph_view, "render_html", resolving)
    result = runner.invoke(main, ["--live", "graph", str(demo), "-o", str(tmp_path / "g.html")])
    assert result.exit_code == 1
    assert "offline mode blocked" in result.output
    assert not (tmp_path / "g.html").exists()


def test_the_documented_demo_view_matches_a_real_run(runner, demo):
    text = (ROOT / "docs" / "graph-view.md").read_text(encoding="utf-8")
    quoted = re.search(
        r"shows (\d+) components, (\d+) edges \((\d+) recorded dependency edges and (\d+) "
        r"reference fields\) and (\w+) exposure paths".replace(" ", r"\s+"),
        text,
    )
    assert quoted, "docs/graph-view.md no longer states the demo view in the expected sentence"
    result = runner.invoke(main, ["graph", str(demo), "--format", "json"], env=UNSET)
    document = json.loads(result.stdout)
    kinds = [edge["kind"] for edge in document["edges"]]
    words = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]
    assert quoted.groups() == (
        str(len(document["nodes"])),
        str(len(kinds)),
        str(kinds.count("dependency")),
        str(kinds.count("reference")),
        words[len(document["exposure"]["paths"])],
    )
    stated = re.search(r"Graph view: [^\n]+", text)
    assert stated is not None
    html = runner.invoke(main, ["graph", str(demo), "-o", str(demo.parent / "g.html")])
    assert html.exit_code == 0, html.output
    assert html.stderr.strip() == stated.group(0)
