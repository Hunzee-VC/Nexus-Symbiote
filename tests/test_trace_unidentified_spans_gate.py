"""A tool or agent span that names no tool or agent cannot be compared, so it fails the gate.

Instrumentation that drops `gen_ai.tool.name` records calls to tools nobody can match
against the inventory; a passing gate would say nothing undeclared appeared.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.trace_evidence import collect
from tests.support import otlp_export, otlp_span


def _inputs(tmp_path: Path, *spans: dict[str, object]) -> tuple[Path, Path]:
    inventory = tmp_path / "bom.json"
    inventory.write_text(AIBOM().to_native_json())
    trace = tmp_path / "trace.json"
    trace.write_text(json.dumps(otlp_export(*spans)))
    return inventory, trace


def test_a_tool_span_without_a_tool_name_fails_the_gate(tmp_path: Path) -> None:
    inventory, trace = _inputs(tmp_path, otlp_span({"gen_ai.operation.name": "execute_tool"}))
    document = collect(inventory, [trace], fail_on="undeclared")
    assert document["coverage"]["spans_without_identifier"]["tool"] == 1
    assert not document["gate"]["passed"]
    assert any("1 tool span names no tool" in reason for reason in document["gate"]["reasons"])


def test_an_agent_span_without_an_agent_name_fails_the_gate(tmp_path: Path) -> None:
    inventory, trace = _inputs(tmp_path, otlp_span({"gen_ai.operation.name": "invoke_agent"}))
    document = collect(inventory, [trace], fail_on="undeclared")
    assert document["coverage"]["spans_without_identifier"]["agent"] == 1
    assert not document["gate"]["passed"]
    assert any("1 agent span names no agent" in reason for reason in document["gate"]["reasons"])


def test_fail_on_none_still_passes_and_the_cli_exits_1_by_default(tmp_path: Path) -> None:
    inventory, trace = _inputs(tmp_path, otlp_span({"gen_ai.operation.name": "execute_tool"}))
    assert collect(inventory, [trace], fail_on="none")["gate"]["passed"]
    run = CliRunner().invoke(main, ["trace-diff", str(inventory), str(trace)])
    assert run.exit_code == 1, run.output
    assert "names no tool" in run.output
    relaxed = CliRunner().invoke(
        main, ["trace-diff", str(inventory), str(trace), "--fail-on", "none"]
    )
    assert relaxed.exit_code == 0, relaxed.output
