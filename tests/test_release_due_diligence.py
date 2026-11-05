"""Regressions found by the 0.1.0 pre-publication review."""

from __future__ import annotations

import ast
import hashlib
import json
import sys
import warnings

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
