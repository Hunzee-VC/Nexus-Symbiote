"""The GitHub Action driver (``scripts/run_action.py``): inputs are untrusted data, exit codes map honestly."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run_action.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("run_action", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


run_action = _load()


def _env(workspace: Path, **extra: str) -> dict[str, str]:
    return {"GITHUB_WORKSPACE": str(workspace), **extra}


def _config(workspace: Path, **extra: str) -> run_action.Config:
    return run_action.Config.from_env(_env(workspace, **extra))


class FakeCli:
    """Records every CLI invocation, writes the documents ``scan`` would write, returns scripted exit codes."""

    def __init__(self, **codes: int) -> None:
        self.codes = codes
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        head = args[0] if args[0] != "policy" else "policy"
        rc = self.codes.get(head, 0)
        stdout = ""
        if head == "scan":
            out = Path(args[args.index("-o") + 1])
            for name in ("agentbom.json", "agentbom.cdx.json", "agentbom.spdx.json"):
                (out / name).write_text("{}", encoding="utf-8")
        elif head == "policy":
            Path(args[args.index("--sarif") + 1]).write_text('{"version": "2.1.0"}', encoding="utf-8")
            stdout = json.dumps({"findings": [], "counts": {}})
        elif head == "conformance":
            stdout = json.dumps({"requested": args[args.index("--level") + 1]})
        return subprocess.CompletedProcess(args, rc, stdout=stdout, stderr="scripted failure" if rc else "")


def _outputs(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        name, _, value = line.partition("=")
        values[name] = value
    return values


# --- Config.from_env -------------------------------------------------------------------------------------------


def test_defaults(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    assert cfg.project == tmp_path
    assert cfg.output_dir == tmp_path / "agentbom"
    assert (cfg.fail_on, cfg.fail_on_indeterminate, cfg.conformance_level, cfg.sarif) == (
        "high",
        False,
        "none",
        False,
    )


def test_explicit_values(tmp_path: Path) -> None:
    (tmp_path / "agent").mkdir()
    cfg = _config(
        tmp_path,
        SYMBIOTE_SCAN_PATH="agent",
        SYMBIOTE_OUTPUT_DIR="out/bom",
        SYMBIOTE_FAIL_ON="medium",
        SYMBIOTE_FAIL_ON_INDETERMINATE="true",
        SYMBIOTE_CONFORMANCE_LEVEL="standard",
        SYMBIOTE_SARIF="true",
    )
    assert cfg.project == tmp_path / "agent" and cfg.output_dir == tmp_path / "out" / "bom"
    assert (
        cfg.fail_on == "medium"
        and cfg.fail_on_indeterminate
        and cfg.conformance_level == "standard"
        and cfg.sarif
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"SYMBIOTE_SCAN_PATH": "../elsewhere"},
        {"SYMBIOTE_SCAN_PATH": "missing-dir"},
        {"SYMBIOTE_SCAN_PATH": "a\nb"},
        {"SYMBIOTE_OUTPUT_DIR": "../out"},
        {"SYMBIOTE_OUTPUT_DIR": "out/*"},
        {"SYMBIOTE_OUTPUT_DIR": "."},
        {"SYMBIOTE_OUTPUT_DIR": ""},
        {"SYMBIOTE_FAIL_ON": "severe"},
        {"SYMBIOTE_FAIL_ON_INDETERMINATE": "yes"},
        {"SYMBIOTE_CONFORMANCE_LEVEL": "gold"},
        {"SYMBIOTE_SARIF": "1"},
    ],
)
def test_rejects_hostile_or_invalid_inputs(tmp_path: Path, overrides: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        _config(tmp_path, **overrides)


def test_rejects_absolute_paths_outside_the_workspace(tmp_path: Path) -> None:
    outside = tmp_path.parent
    with pytest.raises(ValueError):
        _config(tmp_path, SYMBIOTE_SCAN_PATH=str(outside))


def test_rejects_symlink_escaping_the_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (tmp_path / "secret").mkdir()
    (workspace / "link").symlink_to(tmp_path / "secret", target_is_directory=True)
    with pytest.raises(ValueError):
        _config(workspace, SYMBIOTE_SCAN_PATH="link")


def test_missing_workspace_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(KeyError):
        run_action.Config.from_env({})
    with pytest.raises(OSError):
        run_action.Config.from_env({"GITHUB_WORKSPACE": str(tmp_path / "nope")})


# --- run() --------------------------------------------------------------------------------------------------------


def test_clean_run_sequences_the_cli_and_emits_outputs(tmp_path: Path) -> None:
    cli = FakeCli()
    outputs = tmp_path / "github_output"
    cfg = _config(tmp_path, SYMBIOTE_FAIL_ON="medium", SYMBIOTE_FAIL_ON_INDETERMINATE="true")
    assert run_action.run(cfg, command=cli, outputs=outputs) == 0
    assert [c[0] for c in cli.calls] == ["scan", "validate", "policy"]
    scan, validate, policy = cli.calls
    assert scan == ["scan", str(tmp_path), "-o", str(tmp_path / "agentbom"), "--format", "all"]
    assert validate[1:] == [
        str(tmp_path / "agentbom" / n) for n in ("agentbom.json", "agentbom.cdx.json", "agentbom.spdx.json")
    ]
    assert policy[:3] == ["policy", "check", str(tmp_path / "agentbom" / "agentbom.json")]
    assert "--fail-on" in policy and policy[policy.index("--fail-on") + 1] == "medium"
    assert "--fail-on-indeterminate" in policy and "--json" in policy
    values = _outputs(outputs)
    assert values["agentbom_path"] == str(tmp_path / "agentbom" / "agentbom.json")
    assert values["sarif_path"] == str(tmp_path / "agentbom" / "agentbom.sarif")
    assert values["policy_exit_code"] == "0" and values["conformance_exit_code"] == ""
    assert json.loads((tmp_path / "agentbom" / "findings.json").read_text()) == {"findings": [], "counts": {}}


def test_findings_fail_the_gate_after_writing_evidence(tmp_path: Path) -> None:
    cli = FakeCli(policy=1)
    outputs = tmp_path / "github_output"
    assert run_action.run(_config(tmp_path), command=cli, outputs=outputs) == 1
    values = _outputs(outputs)
    assert values["policy_exit_code"] == "1" and values["sarif_path"].endswith("agentbom.sarif")
    assert (tmp_path / "agentbom" / "findings.json").is_file()


def test_conformance_is_optional_and_maps_exit_codes(tmp_path: Path) -> None:
    cli = FakeCli(conformance=5)
    cfg = _config(tmp_path, SYMBIOTE_CONFORMANCE_LEVEL="verified")
    outputs = tmp_path / "github_output"
    assert run_action.run(cfg, command=cli, outputs=outputs) == 5
    assert cli.calls[-1] == [
        "conformance",
        str(tmp_path / "agentbom" / "agentbom.json"),
        "--level",
        "verified",
        "--json",
    ]
    assert _outputs(outputs)["conformance_exit_code"] == "5"
    assert json.loads((tmp_path / "agentbom" / "conformance.json").read_text())["requested"] == "verified"

    cli = FakeCli(conformance=1)
    assert run_action.run(cfg, command=cli) == 1
    cli = FakeCli(policy=1, conformance=5)
    assert run_action.run(cfg, command=cli) == 1, "findings take precedence over a coverage block"


@pytest.mark.parametrize(("scan_rc", "expected"), [(3, 3), (6, 6), (2, 6), (9, 6)])
def test_scan_failure_stops_the_pipeline(
    tmp_path: Path, scan_rc: int, expected: int, capsys: pytest.CaptureFixture[str]
) -> None:
    cli = FakeCli(scan=scan_rc)
    outputs = tmp_path / "github_output"
    assert run_action.run(_config(tmp_path), command=cli, outputs=outputs) == expected
    assert [c[0] for c in cli.calls] == ["scan"]
    assert _outputs(outputs)["agentbom_path"] == ""
    assert "scripted failure" in capsys.readouterr().err


def test_scan_without_documents_is_an_io_failure(tmp_path: Path) -> None:
    def silent_scan(args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    assert run_action.run(_config(tmp_path), command=silent_scan) == 6


def test_validation_failure_is_a_schema_failure(tmp_path: Path) -> None:
    cli = FakeCli(validate=3)
    assert run_action.run(_config(tmp_path), command=cli) == 3
    assert [c[0] for c in cli.calls] == ["scan", "validate"]


def test_unexpected_policy_exit_code_propagates(tmp_path: Path) -> None:
    cli = FakeCli(policy=2)
    assert run_action.run(_config(tmp_path), command=cli) == 2


def test_multiline_outputs_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        run_action.emit(tmp_path / "out", name="a\nb")
    run_action.emit(None, name="ignored when there is no GITHUB_OUTPUT")


def test_real_cli_is_invoked_in_isolated_mode() -> None:
    result = run_action._run(["version", "--json"])
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["symbiote"]


def test_main_reports_configuration_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(os, "environ", {"GITHUB_WORKSPACE": str(tmp_path), "SYMBIOTE_FAIL_ON": "bogus"})
    assert run_action.main() == 6
    assert "Symbiote action failed" in capsys.readouterr().err


def test_action_yml_matches_the_driver_contract() -> None:
    import yaml

    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    step = next(s for s in action["runs"]["steps"] if s.get("id") == "scan")
    assert "${{" not in step["run"], "inputs must travel through env, never shell source"
    assert set(step["env"]) >= {
        "SYMBIOTE_SCAN_PATH",
        "SYMBIOTE_OUTPUT_DIR",
        "SYMBIOTE_FAIL_ON",
        "SYMBIOTE_FAIL_ON_INDETERMINATE",
        "SYMBIOTE_CONFORMANCE_LEVEL",
        "SYMBIOTE_SARIF",
    }
    for name, default in (("fail-on", "high"), ("conformance-level", "none"), ("output-dir", "agentbom")):
        assert action["inputs"][name]["default"] == default
    emitted = {"output_dir", "agentbom_path", "sarif_path", "policy_exit_code", "conformance_exit_code"}
    for output in action["outputs"].values():
        assert any(f"steps.scan.outputs.{name}" in output["value"] for name in emitted)
    assert sys.version_info >= (3, 11)
