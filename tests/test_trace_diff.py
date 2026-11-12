"""The trace-diff command: exit codes, outputs, refusals and output safety."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

import pytest

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.generators.validation import validate_sarif
from tests.support import ROOT, otlp_export, otlp_span

DEMO = ROOT / "examples" / "demo-agent"
FIXTURE = ROOT / "examples" / "traces" / "demo-agent.otlp.json"
MARKER = "MARKER-51c0de"
CLIENT = 3
# A runner acts on "::" at the start of a line and on "##name[" anywhere in one.
LOG_COMMAND = re.compile(r"##[A-Za-z]*\[")


def _inventory(path: Path, *components: object) -> Path:
    path.write_text(AIBOM(components=list(components)).to_native_json())
    return path


def _trace(path: Path, *spans: dict[str, object]) -> Path:
    path.write_text(json.dumps(otlp_export(*spans)))
    return path


def _declared(tmp_path: Path) -> Path:
    return _inventory(
        tmp_path / "bom.json",
        MCPServerComponent(bom_ref="mcp:t", name="tickets", endpoint_url="https://mcp.example.com"),
        ToolComponent(bom_ref="tool:s", name="search", mcp_server_ref="mcp:t"),
    )


def _call(name: str, address: str = "mcp.example.com") -> dict[str, object]:
    attributes = {
        "gen_ai.operation.name": "execute_tool",
        "mcp.method.name": "tools/call",
        "gen_ai.tool.name": name,
        "network.transport": "tcp",
        "server.address": address,
        "server.port": 443,
    }
    return otlp_span(attributes, kind=CLIENT)


def test_the_demo_walkthrough_reports_the_undeclared_tool_and_fails(tmp_path, runner):
    inventory = tmp_path / "demo.aibom.json"
    scanned = runner.invoke(main, ["scan", str(DEMO), "-o", str(inventory)])
    assert scanned.exit_code == 0, scanned.output
    result = runner.invoke(main, ["trace-diff", str(inventory), str(FIXTURE)])
    assert result.exit_code == 1, result.output
    assert result.stderr == ""
    lines = result.stdout.splitlines()
    assert (
        "  Undeclared: tool 'search_tickets' on MCP endpoint mcp.example.com:443 (1 span)" in lines
    )
    assert lines[-1].startswith("Trace gate failed: 3 reported tool, model, agent or MCP")
    evidence = json.loads(
        runner.invoke(main, ["trace-diff", str(inventory), str(FIXTURE), "--json-output"]).stdout
    )
    reconciliation = evidence["reconciliation"]
    assert [(e["kind"], e.get("name") or e.get("model")) for e in reconciliation["undeclared"]] == [
        ("agent", "support-research-assistant"),
        ("model", "gpt-4o-mini"),
        ("tool", "search_tickets"),
    ]
    assert [(e["kind"], e["host"], e["port"], e["basis"]) for e in reconciliation["matched"]] == [
        ("mcp-endpoint", "mcp.example.com", "443", "host-and-port")
    ]
    assert sorted(e["name"] for e in reconciliation["unobserved"]) == ["memory", "notes"]
    assert evidence["coverage"]["spans_with_content_attributes"] == 2
    assert evidence["coverage"]["mcp_client_spans"]["stdio"] == 1
    assert "ticket 4113" not in result.stdout + json.dumps(evidence)


def test_report_only_and_a_clean_run_exit_zero(tmp_path, runner):
    inventory = _declared(tmp_path)
    undeclared = _trace(tmp_path / "undeclared.json", _call("delete_all"))
    reported = runner.invoke(
        main, ["trace-diff", str(inventory), str(undeclared), "--fail-on", "none"]
    )
    assert reported.exit_code == 0, reported.output
    assert (
        "  Undeclared: tool 'delete_all' on MCP endpoint mcp.example.com:443 (1 span)"
        in reported.stdout
    )
    assert reported.stdout.splitlines()[-1] == "Trace gate: not applied (--fail-on none)"
    clean = runner.invoke(
        main, ["trace-diff", str(inventory), str(_trace(tmp_path / "t.json", _call("search")))]
    )
    assert clean.exit_code == 0, clean.output
    assert clean.stdout.splitlines()[-1] == (
        "Trace gate passed: nothing undeclared appeared in these traces; this does not show "
        "that the agent is safe or that the traces are complete"
    )


def test_json_output_and_the_evidence_file_carry_the_same_deterministic_bytes(tmp_path, runner):
    inventory = _declared(tmp_path)
    trace = _trace(tmp_path / "trace.json", _call("search"), _call("delete_all"))
    evidence = tmp_path / "evidence.json"
    first = runner.invoke(
        main, ["trace-diff", str(inventory), str(trace), "--json-output", "-o", str(evidence)]
    )
    assert first.exit_code == 1
    assert first.stderr == ""
    assert first.stdout == evidence.read_text()
    assert stat.S_IMODE(evidence.stat().st_mode) == 0o600
    document = json.loads(first.stdout)
    assert document["format"] == "nexus-symbiote/trace-evidence/v1"
    assert document["assurance"] == "reported"
    assert "Absence of a span proves nothing" in " ".join(document["limitations"])
    second = runner.invoke(main, ["trace-diff", str(inventory), str(trace), "--json-output"])
    assert second.stdout == first.stdout
    summary = runner.invoke(main, ["trace-diff", str(inventory), str(trace), "-o", str(evidence)])
    assert summary.stdout.startswith("Trace evidence: ")
    assert evidence.read_text() == first.stdout


def test_sarif_is_valid_anchored_to_the_inventory_and_carries_the_category(
    tmp_path, runner, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "inventories").mkdir()
    inventory = _declared(tmp_path / "inventories")
    trace = _trace(tmp_path / "trace.json", _call("search"), _call("delete_all"))
    result = runner.invoke(
        main, ["trace-diff", "inventories/bom.json", "trace.json", "--sarif", "out.sarif"]
    )
    assert result.exit_code == 1
    sarif = json.loads((tmp_path / "out.sarif").read_text())
    assert validate_sarif(sarif) == []
    [finding] = sarif["runs"][0]["results"]
    assert finding["ruleId"] == "nexus_symbiote/runtime_undeclared/high"
    location = finding["locations"][0]["physicalLocation"]["artifactLocation"]
    assert location == {"uri": "inventories/bom.json", "uriBaseId": "%SRCROOT%"}
    assert "delete_all" in finding["message"]["text"]
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    monkeypatch.chdir(outside)
    runner.invoke(main, ["trace-diff", str(inventory), str(trace), "--sarif", "out.sarif"])
    sarif = json.loads((outside / "out.sarif").read_text())
    location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]
    assert location["uri"] == ".nexus-symbiote.yaml"


def test_content_never_reaches_any_output(tmp_path, runner):
    inventory = _declared(tmp_path)
    span = _call("search")
    span["attributes"] += [
        {"key": key, "value": {"stringValue": f"{MARKER} {key}"}}
        for key in (
            "gen_ai.input.messages",
            "gen_ai.output.messages",
            "gen_ai.system_instructions",
            "gen_ai.tool.call.arguments",
            "gen_ai.tool.call.result",
            "gen_ai.tool.definitions",
            "gen_ai.retrieval.documents",
            "gen_ai.memory.records",
            "gen_ai.prompt.variable.account",
            "gen_ai.prompt",
            "gen_ai.completion",
        )
    ]
    trace = _trace(tmp_path / "trace.json", span, _call("delete_all"))
    evidence, sarif = tmp_path / "evidence.json", tmp_path / "out.sarif"
    stdout = {}
    for mode, args in (("summary", []), ("json", ["--json-output"])):
        options = ["-o", str(evidence), "--sarif", str(sarif), *args]
        result = runner.invoke(main, ["trace-diff", str(inventory), str(trace), *options])
        assert result.exit_code == 1
        for text in (result.stdout, result.stderr, evidence.read_text(), sarif.read_text()):
            assert MARKER not in text
        stdout[mode] = result.stdout
    note = (
        "  Note: Spans with message, prompt or tool-call content attributes: 1. "
        "Protect these trace files."
    )
    assert note in stdout["summary"].splitlines()
    assert json.loads(stdout["json"])["coverage"]["spans_with_content_attributes"] == 1


HOSTILE = [
    "x\n::error title=Spoofed::All checks passed",
    "##[error]forged ##vso[task.complete result=Succeeded]",
    "evil\x1b[2K\rfake‮gpj.exe​",
    "<script>alert(1)</script> [link](https://attacker.example) www.attacker.example",
]


@pytest.mark.parametrize("name", HOSTILE)
def test_hostile_identifiers_print_inert_in_every_output(tmp_path, runner, name):
    inventory = _declared(tmp_path)
    trace = _trace(tmp_path / "trace.json", _call(name))
    sarif_path = tmp_path / "out.sarif"
    result = runner.invoke(
        main, ["trace-diff", str(inventory), str(trace), "--sarif", str(sarif_path)]
    )
    assert result.exit_code == 1
    for line in result.stdout.splitlines():
        assert not line.lstrip().startswith("::")
        assert not LOG_COMMAND.search(line)
        for character in ("\x1b", "\r", "‮", "​"):
            assert character not in line
    assert any(line.startswith("  Undeclared: tool '") for line in result.stdout.splitlines())
    as_json = runner.invoke(main, ["trace-diff", str(inventory), str(trace), "--json-output"])
    assert not LOG_COMMAND.search(as_json.stdout)
    assert [e["name"] for e in json.loads(as_json.stdout)["reconciliation"]["undeclared"]] == [name]
    sarif_text = sarif_path.read_text()
    message = json.loads(sarif_text)["runs"][0]["results"][0]["message"]["text"]
    assert "://" not in message and "www." not in message
    assert "\x1b" not in message and "\n" not in message
    assert validate_sarif(json.loads(sarif_text)) == []


def test_links_fifos_directories_and_missing_files_are_refused(tmp_path, runner):
    inventory = _declared(tmp_path)
    trace = _trace(tmp_path / "trace.json", _call("search"))
    trace_link, inventory_link = tmp_path / "trace-link.json", tmp_path / "bom-link.json"
    trace_link.symlink_to(trace)
    inventory_link.symlink_to(inventory)
    fifo = tmp_path / "trace.fifo"
    os.mkfifo(fifo)
    cases = [
        ([str(inventory), str(trace_link)], 1, "trace file 1 is reached through a symbolic link"),
        ([str(inventory_link), str(trace)], 1, "It is reached through a symbolic link"),
        ([str(inventory), str(fifo)], 1, "trace file 1 is not a regular file"),
        ([str(fifo), str(trace)], 1, "It is not a regular file"),
        ([str(inventory), str(tmp_path)], 2, "is a directory"),
        ([str(inventory), str(tmp_path / "missing.json")], 2, "does not exist"),
        ([str(inventory)], 2, "Missing argument"),
    ]
    for args, code, message in cases:
        result = runner.invoke(main, ["trace-diff", *args])
        assert result.exit_code == code, (args, result.output)
        assert message in result.stderr, (args, result.stderr)
        assert result.stdout == ""


def test_an_output_may_not_overwrite_an_input_or_the_other_output(tmp_path, runner):
    inventory = _declared(tmp_path)
    trace = _trace(tmp_path / "trace.json", _call("search"))
    alias = tmp_path / "alias.json"
    os.link(trace, alias)
    before = (inventory.read_bytes(), trace.read_bytes())
    cases = [
        ["-o", str(inventory)],
        ["--sarif", str(trace)],
        ["-o", str(alias)],
        ["-o", str(tmp_path / "out.json"), "--sarif", str(tmp_path / "." / "out.json")],
    ]
    for options in cases:
        result = runner.invoke(main, ["trace-diff", str(inventory), str(trace), *options])
        assert result.exit_code == 2, (options, result.output)
        assert "must" in result.stderr
    assert (inventory.read_bytes(), trace.read_bytes()) == before
    assert not (tmp_path / "out.json").exists()


def test_an_existing_output_beside_a_new_one_is_written(tmp_path, runner):
    inventory = _declared(tmp_path)
    trace = _trace(tmp_path / "trace.json", _call("search"))
    evidence, sarif = tmp_path / "evidence.json", tmp_path / "new.sarif"
    evidence.write_text("{}")
    for outputs in (
        ["-o", str(evidence), "--sarif", str(sarif)],
        ["--sarif", str(sarif), "-o", str(evidence)],
    ):
        sarif.unlink(missing_ok=True)
        result = runner.invoke(main, ["trace-diff", str(inventory), str(trace), *outputs])
        assert result.exit_code == 0, result.output
        assert json.loads(evidence.read_text())["format"] == "nexus-symbiote/trace-evidence/v1"
        assert validate_sarif(json.loads(sarif.read_text())) == []


def test_more_than_sixteen_trace_files_is_a_usage_error(tmp_path, runner):
    inventory = _declared(tmp_path)
    trace = _trace(tmp_path / "trace.json", _call("search"))
    result = runner.invoke(main, ["trace-diff", str(inventory), *[str(trace)] * 17])
    assert result.exit_code == 2
    assert "at most 16 trace files" in result.stderr
    assert runner.invoke(main, ["trace-diff", str(inventory), *[str(trace)] * 16]).exit_code == 0


def test_invalid_inputs_exit_one_without_quoting_them(tmp_path, runner):
    inventory = _declared(tmp_path)
    broken = tmp_path / "broken.json"
    broken.write_text(json.dumps({"components": [{"bom_ref": MARKER}]}))
    trace = tmp_path / "trace.json"
    trace.write_text(
        json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": [{"kind": MARKER}]}]}]})
    )
    cases = [
        (
            [str(broken), str(_trace(tmp_path / "ok.json", _call("search")))],
            "is not a valid native AIBOM file",
        ),
        (
            [str(inventory), str(trace)],
            "trace file 1 is malformed: resourceSpans[0].scopeSpans[0].spans[0].kind must be an integer",
        ),
    ]
    for args, message in cases:
        result = runner.invoke(main, ["trace-diff", *args])
        assert result.exit_code == 1
        assert message in result.stderr
        assert MARKER not in result.output
    second = tmp_path / "second.json"
    second.write_text('{"resourceSpans": []}\n{"resourceSpans": [], "x": NaN}\n')
    result = runner.invoke(
        main, ["trace-diff", str(inventory), str(trace.with_name("ok.json")), str(second)]
    )
    assert result.exit_code == 1
    assert "trace file 2 line 2 is not strict JSON" in result.stderr


def test_traces_without_genai_or_mcp_spans_fail_unless_report_only(tmp_path, runner):
    inventory = _declared(tmp_path)
    trace = _trace(tmp_path / "trace.json", otlp_span({"http.request.method": "GET"}))
    failed = runner.invoke(main, ["trace-diff", str(inventory), str(trace)])
    assert failed.exit_code == 1
    assert (
        "  Note: No span carries GenAI or MCP semantics: these traces cannot show any use."
        in failed.stdout
    )
    assert failed.stdout.splitlines()[-1] == (
        "Trace gate failed: no span carries GenAI or MCP semantics, so these traces cannot show "
        "undeclared use"
    )
    assert (
        runner.invoke(
            main, ["trace-diff", str(inventory), str(trace), "--fail-on", "none"]
        ).exit_code
        == 0
    )


@pytest.mark.parametrize(
    ("resource", "attributes", "reason"),
    [
        # A GenAI attribute of the resource does not make its plain spans GenAI spans.
        (
            {"gen_ai.agent.name": "support"},
            {"http.request.method": "GET"},
            "no span carries GenAI or MCP semantics",
        ),
        # An operation name longer than the bound cannot hide the tool call it names.
        (
            None,
            {"gen_ai.operation.name": "execute_tool" + " " * 600, "gen_ai.tool.name": "delete_all"},
            "1 span has an operation name, MCP method or MCP transport that could not be read",
        ),
    ],
)
def test_traces_that_cannot_show_or_classify_use_fail_the_command(
    tmp_path, runner, resource, attributes, reason
):
    inventory = _declared(tmp_path)
    trace = tmp_path / "trace.json"
    trace.write_text(json.dumps(otlp_export(otlp_span(attributes), resource=resource)))
    result = runner.invoke(main, ["trace-diff", str(inventory), str(trace)])
    assert result.exit_code == 1, result.output
    last = result.stdout.splitlines()[-1]
    assert last.startswith("Trace gate failed: ") and reason in last


def test_the_summary_lists_a_bounded_number_of_items_and_counts_the_rest(tmp_path, runner):
    inventory = _declared(tmp_path)
    trace = _trace(tmp_path / "trace.json", *[_call(f"tool-{index:02d}") for index in range(25)])
    result = runner.invoke(main, ["trace-diff", str(inventory), str(trace)])
    listed = [line for line in result.stdout.splitlines() if line.startswith("  Undeclared: ")]
    assert len(listed) == 20
    assert "  ... 5 more; -o FILE or --json-output records every one" in result.stdout.splitlines()


def test_help_says_what_exit_zero_means():
    from click.testing import CliRunner

    result = CliRunner().invoke(main, ["trace-diff", "--help"], terminal_width=200)
    text = " ".join(result.output.split())
    assert (
        "Exit 0 means that nothing undeclared appeared in these traces, not that the agent is safe"
        in text
    )
    assert "--fail-on [undeclared|none]" in text


def test_an_output_whose_identity_cannot_be_checked_is_not_written(tmp_path, runner, monkeypatch):
    import errno

    from nexus_symbiote import trace_cli

    inventory = _declared(tmp_path)
    trace = _trace(tmp_path / "trace.json", _call("search"))
    output = tmp_path / "evidence.json"
    output.write_text("{}")

    def unreadable(first: object, second: object) -> bool:
        raise PermissionError(errno.EACCES, "denied")

    monkeypatch.setattr(trace_cli.os.path, "samefile", unreadable)
    result = runner.invoke(main, ["trace-diff", str(inventory), str(trace), "-o", str(output)])
    assert result.exit_code == 1
    assert "Cannot write the output file: Permission denied." in result.stderr
    assert output.read_text() == "{}"


def test_a_call_after_the_attribute_bound_fails_the_command(tmp_path, runner):
    filler = {f"app.filler.{i:03d}": "x" for i in range(128)}
    hidden = otlp_span(
        {
            "gen_ai.operation.name": "execute_tool",
            **filler,
            "mcp.method.name": "tools/call",
            "gen_ai.tool.name": "exfiltrate_everything",
            "network.transport": "tcp",
            "server.address": "evil.example.net",
            "server.port": 443,
        },
        kind=CLIENT,
    )
    trace = _trace(tmp_path / "trace.json", _call("search"), hidden)
    sarif = tmp_path / "out.sarif"
    result = runner.invoke(
        main, ["trace-diff", str(_declared(tmp_path)), str(trace), "--sarif", str(sarif)]
    )
    assert result.exit_code == 1, result.output
    assert "Trace gate passed" not in result.output
    assert "more than 128 entries" in result.output


def test_a_call_to_another_address_without_a_transport_fails_the_command(tmp_path, runner):
    call = otlp_span(
        {
            "mcp.method.name": "tools/call",
            "gen_ai.tool.name": "search",
            "server.address": "evil.example.net",
            "server.port": 443,
        },
        kind=CLIENT,
    )
    trace = _trace(tmp_path / "trace.json", call)
    result = runner.invoke(main, ["trace-diff", str(_declared(tmp_path)), str(trace)])
    assert result.exit_code == 1, result.output
    assert "Undeclared: tool 'search' on MCP endpoint evil.example.net:443" in result.output
    assert "Undeclared: MCP endpoint evil.example.net:443" in result.output
