"""`export-inventory` through the real CLI: golden bytes, refusals, exit codes and provenance."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.cli import main
from nexus_symbiote.utils.terminal import LOG_COMMAND, safe_line

FIXTURES = Path(__file__).resolve().parent / "fixtures"
DOCS = Path(__file__).resolve().parents[1] / "docs"
INVENTORY = FIXTURES / "shadowscan-inventory"
SHADOWSCAN_REPORT = FIXTURES / "shadowscan" / "code-report-0.1.4.json"
PREFIX = "github:acme/support-triager"
MANIFEST = (
    "id: acme:support-triager\n"
    "name: support-triager\n"
    'version: "1.4"\n'
    "purpose: Triage inbound support tickets\n"
    "framework: langgraph\n"
    "owner: platform-security\n"
    "autonomy_level: L2-agent\n"
)
MCP = '{"mcpServers": {"docs": {"command": "npx", "args": ["-y", "docs-mcp@1.2.3"]}}}\n'


def _args(inventory: Path, output: Path, *extra: str, prefix: str = PREFIX) -> list[str]:
    return [
        "export-inventory",
        str(inventory),
        "--format",
        "shadowscan-simple",
        "--resource-prefix",
        prefix,
        "-o",
        str(output),
        *extra,
    ]


def _project(root: Path, *, manifest: str | None = MANIFEST) -> Path:
    root.mkdir()
    (root / ".mcp.json").write_text(MCP)
    if manifest is not None:
        (root / "agent.yaml").write_text(manifest)
    return root


def _scan(runner, project: Path, output: Path) -> Path:
    result = runner.invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    )
    assert result.exit_code == 0, result.output
    return output


def _with_agent(tmp_path: Path, **changes: Any) -> Path:
    document = json.loads((INVENTORY / "declared-agent.aibom.json").read_text(encoding="utf-8"))
    for component in document["components"]:
        if component["component_type"] == "agent":
            component.update(changes)
    path = tmp_path / "edited.json"
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("inventory", "golden", "extra"),
    [
        ("declared-agent.aibom.json", "simple-list.json", ()),
        ("unnamed-agent.aibom.json", "simple-list-unnamed.json", ("--include-unnamed",)),
    ],
)
def test_the_export_matches_the_golden_file_byte_for_byte(
    runner, tmp_path, inventory, golden, extra
):
    output = tmp_path / "approved.json"
    result = runner.invoke(main, _args(INVENTORY / inventory, output, *extra))
    assert result.exit_code == 0, result.output
    assert output.read_bytes() == (INVENTORY / golden).read_bytes()
    assert result.stdout == ""


def test_a_fresh_scan_of_the_fixture_project_exports_the_golden_bytes(runner, tmp_path):
    # The fixture records a collection time and a fresh scan none; the export does not differ.
    inventory = _scan(runner, _project(tmp_path / "project"), tmp_path / "bom.json")
    fixture = json.loads((INVENTORY / "declared-agent.aibom.json").read_text())
    assert "timestamp" not in json.loads(inventory.read_text())["metadata"]
    assert "timestamp" in fixture["metadata"]
    for name in ("first.json", "second.json"):
        result = runner.invoke(main, _args(inventory, tmp_path / name))
        assert result.exit_code == 0, result.output
    golden = (INVENTORY / "simple-list.json").read_bytes()
    assert (tmp_path / "first.json").read_bytes() == (tmp_path / "second.json").read_bytes()
    assert (tmp_path / "first.json").read_bytes() == golden


def test_an_undeclared_agent_is_refused_with_a_hint_and_nothing_is_written(runner, tmp_path):
    inventory = _scan(runner, _project(tmp_path / "project", manifest=None), tmp_path / "bom.json")
    output = tmp_path / "approved.json"
    result = runner.invoke(main, _args(inventory, output))
    assert result.exit_code == 1
    assert "identity is not declared" in result.output
    assert "Declare `id` (and `name`) in agent.yaml" in result.output
    assert not output.exists()
    accepted = runner.invoke(main, _args(inventory, output, "--include-unnamed"))
    assert accepted.exit_code == 0, accepted.output
    assert "its id is derived from the inventory content digest" in accepted.stderr
    assert json.loads(output.read_text())["agents"][0]["id"].startswith("agent:unnamed:")


def test_stderr_carries_the_digests_and_the_signing_advice(runner, tmp_path):
    source = INVENTORY / "declared-agent.aibom.json"
    output = tmp_path / "approved.json"
    result = runner.invoke(main, _args(source, output))
    assert result.exit_code == 0, result.output
    lines = result.stderr.splitlines()
    assert lines[0] == f"Wrote a ShadowScan 999bef1 simple-list inventory: {output}"
    assert lines[1] == "Agent id: agent:repository:651468131b187c7b2734b11c"
    assert f"Inventory file SHA-256: sha256:{hashlib.sha256(source.read_bytes()).hexdigest()}" in (
        lines
    )
    assert (
        "Inventory content digest (nexus-symbiote/inventory-content/v1): "
        "sha256:0b70f2881535ed3334e4da35081126a3a86c89b5c189d4e9533eabeea5d76758"
    ) in lines
    assert lines[-1].startswith("Review and sign the exported file")
    assert not any(line.startswith("Not exported") for line in lines)


def test_the_file_is_private_to_its_owner(runner, tmp_path):
    output = tmp_path / "approved.json"
    result = runner.invoke(main, _args(INVENTORY / "declared-agent.aibom.json", output))
    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_imported_discovery_is_counted_and_not_exported(runner, tmp_path):
    project = _project(tmp_path / "project")
    shutil.copyfile(SHADOWSCAN_REPORT, project / "shadowscan.json")
    inventory = _scan(runner, project, tmp_path / "bom.json")
    agents = [
        c for c in json.loads(inventory.read_text())["components"] if c["component_type"] == "agent"
    ]
    assert len(agents) == 2
    output = tmp_path / "approved.json"
    result = runner.invoke(main, _args(inventory, output))
    assert result.exit_code == 0, result.output
    assert (
        "Not exported: 1 agent component(s) other than the repository agent, such as imported "
        "discovery."
    ) in result.stderr.splitlines()
    assert output.read_bytes() == (INVENTORY / "simple-list.json").read_bytes()


def test_an_import_only_inventory_has_no_agent_to_export(runner, tmp_path):
    imported = tmp_path / "imported.json"
    result = runner.invoke(
        main, ["import-shadowscan", str(SHADOWSCAN_REPORT), "--report-only", "-o", str(imported)]
    )
    assert result.exit_code == 0, result.output
    refused = runner.invoke(main, _args(imported, tmp_path / "approved.json", "--include-unnamed"))
    assert refused.exit_code == 1
    assert "The inventory records no repository agent" in refused.output
    assert not (tmp_path / "approved.json").exists()


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--resource-prefix"], "Missing option '--resource-prefix'"),
        (["--format"], "Missing option '--format'"),
        (["-o"], "Missing option '-o' / '--output'"),
    ],
)
def test_required_options_are_usage_errors(runner, tmp_path, args, message):
    full = _args(INVENTORY / "declared-agent.aibom.json", tmp_path / "approved.json")
    index = full.index(args[0])
    del full[index : index + 2]
    result = runner.invoke(main, full)
    assert result.exit_code == 2
    assert message in result.output
    assert not (tmp_path / "approved.json").exists()


def test_only_the_shadowscan_simple_format_exists(runner, tmp_path):
    args = _args(INVENTORY / "declared-agent.aibom.json", tmp_path / "approved.json")
    args[args.index("shadowscan-simple")] = "agentbom-0.1"
    result = runner.invoke(main, args)
    assert result.exit_code == 2
    assert "Invalid value for '--format'" in result.output


@pytest.mark.parametrize(
    ("prefix", "reason"),
    [
        ("", "is empty"),
        ("github:acme/agent ", "starts or ends with white space"),
        ("github:acme/agent\n::error::forged", "control, format, line-separator"),
        ("github:acme/‮agent", "control, format, line-separator"),
        ("github:acme/\udcffagent", "unencodable"),
        ("github:acme/[REDACTED]", "contains [REDACTED]"),
        ("x" * 4097, "longer than 4,096 characters"),
    ],
    ids=repr,
)
def test_an_unusable_resource_prefix_is_a_usage_error(runner, tmp_path, prefix, reason):
    output = tmp_path / "approved.json"
    result = runner.invoke(
        main, _args(INVENTORY / "declared-agent.aibom.json", output, prefix=prefix)
    )
    assert result.exit_code == 2
    assert "Invalid value for '--resource-prefix': The resource prefix" in result.output
    assert reason in result.output
    assert "forged" not in result.output and "‮" not in result.output
    assert not output.exists()


@pytest.mark.parametrize("name", ["approved.yaml", "approved", "approved.json.txt"])
def test_the_output_must_be_a_json_file(runner, tmp_path, name):
    result = runner.invoke(main, _args(INVENTORY / "declared-agent.aibom.json", tmp_path / name))
    assert result.exit_code == 2
    assert "the approved inventory must be a .json file" in result.output
    assert not (tmp_path / name).exists()


def test_the_json_suffix_is_matched_in_any_case_as_shadowscan_matches_it(runner, tmp_path):
    output = tmp_path / "approved.JSON"
    result = runner.invoke(main, _args(INVENTORY / "declared-agent.aibom.json", output))
    assert result.exit_code == 0, result.output
    assert output.read_bytes() == (INVENTORY / "simple-list.json").read_bytes()


def test_the_output_must_not_overwrite_the_inventory(runner, tmp_path):
    source = tmp_path / "bom.json"
    shutil.copyfile(INVENTORY / "declared-agent.aibom.json", source)
    before = source.read_bytes()
    (tmp_path / "alias.json").hardlink_to(source)
    for target in (source, tmp_path / "alias.json"):
        result = runner.invoke(main, _args(source, target))
        assert result.exit_code == 2
        assert "output must not overwrite the source inventory" in result.output
    assert source.read_bytes() == before


def test_an_output_link_is_replaced_never_written_through(runner, tmp_path):
    target = tmp_path / "elsewhere.json"
    target.write_text("{}")
    link = tmp_path / "approved.json"
    link.symlink_to(target)
    result = runner.invoke(main, _args(INVENTORY / "declared-agent.aibom.json", link))
    assert result.exit_code == 0, result.output
    assert target.read_text() == "{}"
    assert not link.is_symlink()
    assert link.read_bytes() == (INVENTORY / "simple-list.json").read_bytes()


def test_an_output_in_a_directory_reached_through_a_link_is_refused(runner, tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "linked").symlink_to(tmp_path / "real")
    output = tmp_path / "linked" / "approved.json"
    result = runner.invoke(main, _args(INVENTORY / "declared-agent.aibom.json", output))
    assert result.exit_code == 1
    assert "Cannot write the output file" in result.output
    assert not (tmp_path / "real" / "approved.json").exists()


@pytest.mark.parametrize("kind", ["symlink", "fifo", "duplicate-keys", "deep"])
def test_an_invalid_inventory_is_refused_by_class(runner, tmp_path, kind):
    source = tmp_path / "bom.json"
    if kind == "symlink":
        source.symlink_to(INVENTORY / "declared-agent.aibom.json")
    elif kind == "fifo":
        os.mkfifo(source)
    elif kind == "duplicate-keys":
        source.write_text('{"metadata": {}, "metadata": {}, "components": []}')
    else:
        source.write_text("[" * 100_000 + "]" * 100_000)
    output = tmp_path / "approved.json"
    result = runner.invoke(main, _args(source, output))
    assert result.exit_code == 1
    assert f"{source} is not a valid native AIBOM file." in result.output
    assert "Traceback" not in result.output
    assert not output.exists()


def test_an_oversized_inventory_is_refused(runner, tmp_path):
    source = tmp_path / "bom.json"
    source.write_bytes(b" " * (16 * 1024 * 1024 + 1))
    result = runner.invoke(main, _args(source, tmp_path / "approved.json"))
    assert result.exit_code == 1
    assert "It exceeds the 16 MiB native inventory limit." in result.output


def _nested(tmp_path: Path, depth: int) -> Path:
    document = json.loads((INVENTORY / "declared-agent.aibom.json").read_text(encoding="utf-8"))
    for component in document["components"]:
        if component["component_type"] == "agent":
            component["properties"]["deep"] = "@DEEP@"
    path = tmp_path / f"deep-{depth}.json"
    path.write_text(json.dumps(document).replace('"@DEEP@"', "[" * depth + "]" * depth))
    return path


def test_nesting_at_the_depth_limit_gets_the_fixed_refusal(runner, tmp_path):
    # The strict parse refuses at the boundary, so export ends there with the fixed refusal and
    # never with "internal error (RecursionError)". Bisection probes the depth where it ends.
    def exported(depth: int) -> bool:
        output = tmp_path / f"approved-{depth}.json"
        result = runner.invoke(main, _args(_nested(tmp_path, depth), output))
        if result.exit_code == 0:
            return True
        assert result.exit_code == 1
        assert "is not a valid native AIBOM file. It is not strict UTF-8 JSON" in result.output
        assert not output.exists()
        return False

    accepted, refused = 1, 100_000
    assert exported(accepted)
    while refused - accepted > 1:
        middle = (accepted + refused) // 2
        accepted, refused = (middle, refused) if exported(middle) else (accepted, middle)
    assert not exported(refused)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"name": "evil\x1b]8;;https://attacker.example\x07click\x1b]8;;\x07"}, "agent name"),
        ({"name": "Approved‮gpj.exe"}, "agent name"),
        ({"supplier": "team\n::error::forged"}, "agent owner"),
        ({"supplier": " team"}, "agent owner"),
    ],
)
def test_hostile_identifiers_are_refused_without_being_echoed(runner, tmp_path, changes, reason):
    output = tmp_path / "approved.json"
    result = runner.invoke(main, _args(_with_agent(tmp_path, **changes), output))
    assert result.exit_code == 1
    assert f"Error: The {reason} " in result.output
    for marker in ("attacker", "gpj", "forged", "\x1b", "‮"):
        assert marker not in result.output
    assert not output.exists()


@pytest.mark.parametrize(
    "name",
    [
        "x\n::error title=Forged::All gates passed.json",
        "##[error]forged.json",
        "##vso[task.setvariable variable=APPROVED]true.json",
        "esc\x1b]0;pwned-title\x07\x1b[2K\rFORGED.json",
    ],
    ids=repr,
)
def test_hostile_path_names_reach_the_terminal_only_as_inert_text(runner, tmp_path, name):
    # Workflows derive file names from checkout names, so the paths the command prints are input.
    output = tmp_path / name
    result = runner.invoke(main, _args(INVENTORY / "declared-agent.aibom.json", output))
    assert result.exit_code == 0, result.output
    assert output.read_bytes() == (INVENTORY / "simple-list.json").read_bytes()
    assert result.stderr.splitlines()[0] == safe_line(
        "Wrote a ShadowScan 999bef1 simple-list inventory: ", output
    )
    source = tmp_path / f"input-{name}"
    source.write_text('{"metadata": {}, "metadata": {}, "components": []}')
    refused = runner.invoke(main, _args(source, tmp_path / "approved.json"))
    assert refused.exit_code == 1
    assert "is not a valid native AIBOM file" in refused.output
    for text in (result.output, refused.output):
        for line in text.splitlines():
            assert not line.lstrip().startswith("::") and not LOG_COMMAND.search(line), line
        for character in ("\x1b", "\x07", "\r"):
            assert character not in text


def test_markup_and_log_commands_are_data_in_the_file_never_terminal_output(runner, tmp_path):
    name = "##[error]x ::error::y <b>bold</b> [link](https://attacker.example)"
    output = tmp_path / "approved.json"
    result = runner.invoke(main, _args(_with_agent(tmp_path, name=name), output))
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text(encoding="utf-8"))["agents"][0]["name"] == name
    for marker in ("##[error]", "::error::", "<b>", "attacker"):
        assert marker not in result.output


def test_the_help_and_the_reference_name_every_form_of_the_prefix(runner):
    # A bare code.filesystem label is the resource only with a single path: ShadowScan adds a
    # root to each labelled `paths` entry, even a list of one.
    forms = ("github:OWNER/REPO", "gitlab:NAMESPACE/PROJECT", "LABEL/root-id-ID")
    result = runner.invoke(main, ["export-inventory", "--help"])
    assert result.exit_code == 0, result.output
    reference = (DOCS / "cli-reference.md").read_text(encoding="utf-8").splitlines()
    (row,) = [line for line in reference if line.startswith("| `--resource-prefix` ")]
    for text in (" ".join(result.output.split()), row):
        for form in forms:
            assert form in text, form


def test_every_command_the_page_names_exists():
    page = (DOCS / "shadowscan-inventory-export.md").read_text(encoding="utf-8")
    named = set(re.findall(r"nexus-symbiote ([a-z][a-z-]*)", page))
    assert "export-inventory" in named
    assert named <= set(main.commands)


def test_the_documented_example_is_what_the_command_prints(runner, tmp_path, monkeypatch):
    page = (DOCS / "shadowscan-inventory-export.md").read_text(encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    source = INVENTORY / "declared-agent.aibom.json"
    result = runner.invoke(main, _args(source, Path("approved.json")))
    assert result.exit_code == 0, result.output
    assert "export-inventory tests/fixtures/shadowscan-inventory/declared-agent.aibom.json" in page
    for line in result.stderr.splitlines():
        assert f"\n{line}\n" in page, line
    assert (tmp_path / "approved.json").read_text(encoding="utf-8") in page
    unnamed = json.loads((INVENTORY / "simple-list-unnamed.json").read_text(encoding="utf-8"))
    assert json.dumps(unnamed["agents"][0]["names"][0]) in page
