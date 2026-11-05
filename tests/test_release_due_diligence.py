"""Regressions found by the 0.1.0 pre-publication review."""

from __future__ import annotations

import ast
import errno
import hashlib
import json
import os
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


CONFLICT = "PyPI package '{}' is declared more than once with requirements that conflict."


def test_registry_keeps_one_component_per_package_across_requirements_files(tmp_path):
    (tmp_path / "AGENTS.md").write_text("Keep receipts.")
    (tmp_path / "requirements.txt").write_text(
        "openai==1.3.0\ntorch==2.3.0\ntransformers==4.40.0\nlangchain @ https://a.example/l.whl\n"
    )
    (tmp_path / "requirements-lock.txt").write_text(
        "openai==1.3.0\ntorch>=2\ntransformers<4.40\nlangchain==0.2.5\n"
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    by_name = {c.name: c for c in result.components}
    assert sorted(by_name) == ["langchain", "openai", "torch", "transformers"]
    assert str(by_name["openai"].source_path).endswith("requirements.txt")
    assert by_name["openai"].risks == []
    assert by_name["openai"].properties["declarations"] == [
        "requirements-lock.txt: openai==1.3.0",
        "requirements.txt: openai==1.3.0",
    ]
    # A range that the other file's pin satisfies is a compiled lock, not a conflict.
    assert by_name["torch"].version == "==2.3.0"
    assert by_name["torch"].risks == []
    assert by_name["torch"].properties["declarations"] == [
        "requirements-lock.txt: torch>=2",
        "requirements.txt: torch==2.3.0",
    ]
    for name in ("transformers", "langchain"):
        assert CONFLICT.format(name) in [r.detail for r in by_name[name].risks]
    scanned = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--no-project-policy", "-o", str(tmp_path / "bom.json")]
    )
    assert "conflicting duplicate component" not in scanned.output


@pytest.mark.parametrize(
    ("one", "other", "conflict"),
    [
        ("torch==2.3.0", "torch==2.3", False),
        ("torch==2.3.0", "torch>=2.2,<2.4", False),
        ("torch>=2.2", "torch==2.3.0+cu121", False),
        ("torch==2.3.0 ; sys_platform == 'linux'", "torch==2.3.0", False),
        ("torch[cuda]==2.3.0", "torch==2.3.0", False),
        ("torch>=2.2", "torch<2.2", False),
        ("torch", "torch==2.3.0", False),
        ("torch==2.3.0", "torch==2.2.2", True),
        ("torch==2.3.0+cpu", "torch==2.3.0+cu121", True),
        ("torch==2.1.0", "torch>=2.2", True),
        ("torch===2.3.0-custom", "torch==2.3.0", True),
        ("torch @ https://a.example/t.whl", "torch==2.3.0", True),
        ("torch @ https://a.example/t.whl", "torch @ https://b.example/t.whl", True),
        ("torch @ https://a.example/x.whl", "torch @ https://a.example/y.whl", False),
    ],
)
def test_only_declarations_that_cannot_both_hold_conflict(one, other, conflict):
    assert RegistryScanner._conflict(one, other) is conflict
    assert RegistryScanner._conflict(other, one) is conflict


def test_ranges_with_pins_in_a_lock_file_leave_the_default_gate_as_on_main(tmp_path):
    # Main read only requirements.txt here: seven ranges, 7 x 4 = 28. Reading the
    # lock file must record its pins without adding a finding per package.
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    pins = {
        "anthropic": ("0.34", "0.34.2"),
        "openai": ("1.40", "1.51.0"),
        "langchain": ("0.3", "0.3.3"),
        "langchain-anthropic": ("0.2", "0.2.3"),
        "chromadb": ("0.5", "0.5.11"),
        "transformers": ("4.40", "4.44.2"),
        "torch": ("2.2", "2.3.0"),
    }
    (project / "requirements.txt").write_text(
        "".join(f"{name}>={low}\n" for name, (low, _) in pins.items())
    )
    (project / "requirements-lock.txt").write_text(
        "".join(f"{name}=={pin}\n" for name, (_, pin) in pins.items())
    )
    runner = CliRunner()
    bom = tmp_path / "bom.json"
    scanned = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(bom)])
    assert scanned.exit_code == 0, scanned.output
    risk = runner.invoke(main, ["risk", str(bom), "--json-output"])
    assert risk.exit_code == 0, risk.output
    assert json.loads(risk.stdout)["overall_score"] == 28.0


def test_requirements_file_names_match_without_regard_to_case(tmp_path):
    # Main opened the fixed name requirements.txt, which macOS and Windows resolve
    # to Requirements.txt; the glob must not lose such a file on any platform.
    (tmp_path / "Requirements.txt").write_text("openai==1.30.1\n")
    (tmp_path / "REQUIREMENTS-GPU.TXT").write_text("torch==2.3.0\n")
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert {c.name: c.version for c in result.components} == {
        "openai": "==1.30.1",
        "torch": "==2.3.0",
    }


def test_differing_declarations_in_one_requirements_file_get_one_finding(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "torch==2.3.0 ; sys_platform == 'linux'\ntorch==2.2.2 ; sys_platform == 'darwin'\n"
    )
    (component,) = RegistryScanner().scan(tmp_path).components
    details = [r.detail for r in component.risks]
    assert details.count(CONFLICT.format("torch")) == 1
    assert len(component.properties["declarations"]) == 2


@pytest.mark.parametrize(
    "content",
    [
        "-e .\n",
        "-e .[dev]\n",
        "-c constraints.txt\n",
        "-r requirements/base.txt\n",
        "--index-url https://pypi.org/simple -r ../shared/ai.txt\n",
        "-e git+https://github.com/openai/openai-python@v1.3.0#egg=openai\n",
        "git+https://github.com/example/unknown\n",
        "https://files.example/python-dateutil-2.8.2.tar.gz\n",
        "./wheels/openai-1.3.0-py3-none-any.whl\n",
        "-r 'unbalanced\n",
    ],
)
def test_lines_the_collector_does_not_follow_leave_the_default_gate_as_on_main(tmp_path, content):
    # Includes, editable installs and URL, VCS or path references are not followed
    # and not reported, as before; the README and security model state the limit.
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (project / "requirements.txt").write_text("openai==1.3.0\n")
    (project / "requirements-dev.txt").write_text("\ufeff" + content)
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == [] and result.scan_failures == []
    assert [c.name for c in result.components] == ["openai"]
    scanned = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(tmp_path / "bom.json")]
    )
    assert scanned.exit_code == 0, scanned.output


def test_pyproject_ranges_with_compiled_pins_leave_the_default_gate_as_on_main(tmp_path):
    # pip-tools and uv keep ranges in pyproject.toml and the pins that satisfy them
    # in requirements.txt. Main dropped the pyproject.toml declaration without a
    # finding; it is now recorded, and a satisfied range is not a conflict.
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/data"],
                    },
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"},
                    },
                    "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
                }
            }
        )
    )
    ranges = ["anthropic>=0.34", "openai>=1.40", "langchain>=0.3,<0.4", "chromadb>=0.5"]
    (project / "pyproject.toml").write_text(
        '[project]\nname = "agent"\nversion = "0.1.0"\ndependencies = '
        + json.dumps([*ranges, "langchain-anthropic>=0.2"])
        + '\n[project.optional-dependencies]\nfast = ["openai>=1.50"]\n'
    )
    (project / "requirements.txt").write_text(
        "anthropic==0.34.2\nopenai==1.51.0\nlangchain==0.3.3\n"
        "langchain-anthropic==0.2.3\nchromadb==0.5.11\n"
    )
    result = RegistryScanner().scan(project)
    assert result.scan_failures == []
    by_name = {c.name: c for c in result.components}
    assert all(c.risks == [] for c in by_name.values())
    assert by_name["openai"].version == "==1.51.0"
    assert by_name["openai"].properties["declarations"] == [
        "pyproject.toml: openai>=1.40",
        "pyproject.toml: openai>=1.50",
        "requirements.txt: openai==1.51.0",
    ]
    runner = CliRunner()
    bom = tmp_path / "bom.json"
    scanned = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(bom)])
    assert scanned.exit_code == 0, scanned.output
    assert runner.invoke(main, ["risk", str(bom)]).exit_code == 0


def test_a_pyproject_pin_that_contradicts_a_requirements_pin_is_a_conflict(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "agent"\nversion = "0.1.0"\n'
        'dependencies = ["openai==1.52.0", "anthropic>=0.30"]\n'
    )
    (tmp_path / "requirements.txt").write_text("openai==1.51.0\nanthropic==0.34.2\n")
    by_name = {c.name: c for c in RegistryScanner().scan(tmp_path).components}
    assert [r.detail for r in by_name["openai"].risks] == [CONFLICT.format("openai")]
    assert by_name["anthropic"].risks == []


def test_a_utf8_byte_order_mark_does_not_hide_the_first_requirement(tmp_path):
    (tmp_path / "requirements.txt").write_text("\ufeffopenai==1.3.0\n", encoding="utf-8")
    assert [c.name for c in RegistryScanner().scan(tmp_path).components] == ["openai"]


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


def test_a_link_to_an_unreachable_target_is_replaced_not_refused(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (tmp_path / "regular").write_text("keep")
    (tmp_path / "dangling").symlink_to(tmp_path / "missing" / "bom.json")
    (tmp_path / "through-file").symlink_to(tmp_path / "regular" / "bom.json")
    runner = CliRunner()
    for name in ("dangling", "through-file"):
        result = runner.invoke(
            main,
            [
                "scan",
                str(project),
                "--no-project-policy",
                "--report-only",
                "-o",
                str(tmp_path / name),
            ],
        )
        assert result.exit_code == 0, result.output
        assert not (tmp_path / name).is_symlink()
    assert (tmp_path / "regular").read_text() == "keep"


@pytest.mark.skipif(not hasattr(__import__("os"), "mkfifo"), reason="needs FIFOs")
def test_no_command_replaces_a_fifo_or_a_link_to_one(tmp_path):
    import os

    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    (tmp_path / "to-pipe").symlink_to(fifo)
    runner = CliRunner()
    for target in (fifo, tmp_path / "to-pipe"):
        result = runner.invoke(
            main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(target)]
        )
        assert result.exit_code == 1 and "Cannot write the output file" in result.output
    assert fifo.is_fifo() and (tmp_path / "to-pipe").is_symlink()


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


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (PermissionError(errno.EACCES, "denied", "/private/x"), "file: Permission denied."),
        (OSError(errno.ENOSPC, "full", "/private/x"), "file: No space left on device."),
        (OSError(errno.ELOOP, "link", "/private/x"), "no directory on the path may be"),
        (OSError(errno.EINVAL, "special", "/private/x"), "must not be a directory, device"),
        (ValueError("bad"), "its directory must exist"),
    ],
)
def test_an_unwritable_output_reports_its_reason_without_the_path(
    tmp_path, monkeypatch, error, message
):
    def refuse(*_args, **_kwargs):
        raise error

    monkeypatch.setattr("nexus_symbiote.utils.terminal.write_output_file", refuse)
    (tmp_path / "AGENTS.md").write_text("Keep receipts.")
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--no-project-policy", "-o", str(tmp_path / "out.json")]
    )
    assert result.exit_code == 1 and result.exception.__class__ is SystemExit
    assert "Cannot write the output file" in result.output and message in result.output
    assert "/private/x" not in result.output


def test_a_requirements_file_with_an_undecodable_name_is_a_gap_not_a_crash(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (project / "requirements.txt").write_text("openai==1.40.0\n")
    try:
        fd = os.open(os.fsencode(project) + b"/requirements-\xff.txt", os.O_WRONLY | os.O_CREAT)
    except OSError:
        pytest.skip("file system rejects names that are not UTF-8")
    os.write(fd, b"openai==1.41.0\n")
    os.close(fd)
    result = RegistryScanner().scan(project)
    assert result.scan_failures == ["requirements file with an unprintable name: not read"]
    assert [c.version for c in result.components] == ["==1.40.0"]
    runner = CliRunner()
    for fmt in ("json", "cyclonedx", "spdx"):
        out = tmp_path / f"{fmt}.json"
        scanned = runner.invoke(
            main,
            [
                "scan",
                str(project),
                "--no-project-policy",
                "--report-only",
                "-f",
                fmt,
                "-o",
                str(out),
            ],
        )
        assert scanned.exit_code == 0, scanned.output
        json.loads(out.read_text(encoding="utf-8"))


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
