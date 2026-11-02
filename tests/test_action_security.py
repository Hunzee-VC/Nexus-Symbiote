"""Adversarial contract tests for the composite Action's actual runner."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

SPEC = importlib.util.spec_from_file_location(
    "action_runner", Path(__file__).parents[1] / "scripts" / "run_action.py"
)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


def configuration(tmp_path: Path, **inputs: str):
    return runner.Config.from_env({"GITHUB_WORKSPACE": str(tmp_path), **inputs})


@pytest.mark.parametrize("payload", ["$(touch PWNED)", "quote'and\"space", "--scanner=none"])
def test_path_input_is_one_literal_argument_and_collection_runs_once(tmp_path, payload):
    (tmp_path / payload).mkdir()
    config = configuration(tmp_path, SYMBIOTE_SCAN_PATH=payload, SYMBIOTE_SARIF="true")
    calls = []
    exports = []

    def command(args):
        calls.append(args)
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(args, 0, '{"overall_score": 0}', "")

    def export(native, output, fmt):
        exports.append((native.read_text(), fmt))
        output.write_text("evidence")

    assert runner.run(config, command=command, export=export) == 0
    assert [c[0] for c in calls] == ["scan", "validate", "risk"]
    assert calls[0][-2:] == ["--", str(tmp_path / payload)]
    assert exports == [("{}", "json"), ("{}", "sarif")]
    assert not (tmp_path / "PWNED").exists()


def test_command_runner_never_uses_shell(monkeypatch):
    captured = {}

    def invoke(args, **kwargs):
        captured.update(args=args, kwargs=kwargs)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(runner.subprocess, "run", invoke)
    runner._run(["scan", "$(touch PWNED)"])
    assert captured["args"] == [
        sys.executable,
        "-I",
        "-m",
        "nexus_symbiote",
        "scan",
        "$(touch PWNED)",
    ]
    assert captured["kwargs"].get("shell", False) is False


@pytest.mark.parametrize("status", [1, 7])
def test_validation_failure_fails_action_and_preserves_export(tmp_path, status):
    config = configuration(tmp_path)
    calls = []

    def command(args):
        calls.append(args[0])
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(
            args, status if args[0] == "validate" else 0, "", "failed"
        )

    outputs = tmp_path / "outputs"
    assert runner.run(config, command=command, outputs=outputs) == 1
    assert calls == ["scan", "validate"]
    assert config.output.exists()
    assert "aibom_path=" in outputs.read_text()


@pytest.mark.parametrize("report", ["{}", '{"overall_score": "0"}', '{"overall_score": NaN}'])
def test_malformed_risk_report_never_becomes_zero_score(tmp_path, report):
    config = configuration(tmp_path, SYMBIOTE_VALIDATE="false")

    def command(args):
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(args, 0, report, "")

    with pytest.raises(ValueError):
        runner.run(config, command=command)


@pytest.mark.parametrize(
    "key,value",
    [
        ("SYMBIOTE_FORMAT", "json; echo injected"),
        ("SYMBIOTE_SCANNERS", "mcp,$(whoami)"),
        ("SYMBIOTE_SCANNERS", "mcp,mcp"),
        ("SYMBIOTE_VALIDATE", "yes"),
        ("SYMBIOTE_RISK_THRESHOLD", "NaN"),
        ("SYMBIOTE_RISK_THRESHOLD", "-1"),
        ("SYMBIOTE_RISK_THRESHOLD", "101"),
        ("SYMBIOTE_OUTPUT_FILE", "../outside"),
        ("SYMBIOTE_OUTPUT_FILE", "*"),
        ("SYMBIOTE_OUTPUT_FILE", "[a-z]"),
        ("SYMBIOTE_OUTPUT_FILE", "!exclude"),
        ("SYMBIOTE_OUTPUT_FILE", "artifact\ninjected=value"),
    ],
)
def test_invalid_input_fails_before_collection(tmp_path, key, value):
    with pytest.raises(ValueError):
        configuration(tmp_path, **{key: value})


def test_output_symlink_outside_workspace_is_refused(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "escape").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        configuration(workspace, SYMBIOTE_OUTPUT_FILE="escape/result")


def test_action_expressions_are_never_embedded_in_shell_source():
    action = yaml.safe_load((Path(__file__).parents[1] / "action.yml").read_text())
    for step in action["runs"]["steps"]:
        if "run" in step:
            assert "${{" not in step["run"]
            assert "|| true" not in step["run"]
    install = next(
        s for s in action["runs"]["steps"] if s.get("name") == "Install reviewed Action source"
    )
    assert '"$SYMBIOTE_ACTION_PATH"' in install["run"]


def test_workflow_pins_structure_and_release_privilege_separation():
    checker_spec = importlib.util.spec_from_file_location(
        "workflow_checker", Path(__file__).parents[1] / "scripts" / "check_workflows.py"
    )
    assert checker_spec is not None and checker_spec.loader is not None
    checker = importlib.util.module_from_spec(checker_spec)
    checker_spec.loader.exec_module(checker)
    root = Path(__file__).parents[1]
    workflows = root / ".github/workflows"
    for path in [root / "action.yml", *workflows.glob("*.yml"), *workflows.glob("*.yaml")]:
        assert checker.check(path) == []
    release = yaml.safe_load((root / ".github/workflows/release.yml").read_text())
    events = release.get("on", release.get(True))
    assert set(events) == {"workflow_dispatch"}
    publish_input = events["workflow_dispatch"]["inputs"]["publish"]
    assert publish_input["type"] == "choice"
    assert publish_input["options"] == ["none", "testpypi", "pypi"]
    assert publish_input["default"] == "none"
    jobs = release["jobs"]
    assert jobs["build"]["permissions"] == {"contents": "read", "actions": "read"}
    build_steps = jobs["build"]["steps"]
    build_commands = [step.get("run", "") for step in build_steps]
    assert any("--require-hashes -r requirements-ci.lock" in command for command in build_commands)
    build = next(s for s in build_steps if s.get("run") == "python -m build --no-isolation")
    assert build["working-directory"].endswith("/release-source")
    assert any("git archive" in command for command in build_commands)

    def index(predicate):
        return next(i for i, step in enumerate(build_steps) if predicate(step))

    upload = index(lambda s: s.get("name") == "Upload distributions")
    # The attested bytes are uploaded before anything runs tests, writes evidence
    # or resolves unpinned dependencies for the wheel smoke test.
    assert upload < index(lambda s: s.get("run") == "python -m pytest")
    assert upload < index(lambda s: "evidence/" in s.get("run", ""))
    assert upload < index(
        lambda s: 'release-smoke/bin/python" -m pip install dist' in s.get("run", "")
    )
    assert jobs["publish"]["environment"]["name"] == "${{ inputs.publish }}"
    assert jobs["publish"]["if"].startswith("inputs.publish != 'none'")
    publish_step = next(s for s in jobs["publish"]["steps"] if "pypi-publish" in s["uses"])
    assert "test.pypi.org/legacy/" in publish_step["with"]["repository-url"]
    assert "upload.pypi.org/legacy/" in publish_step["with"]["repository-url"]
    assert set(jobs["publish"]["needs"]) == {"build", "attest"}
    for name in ["attest", "publish"]:
        assert all("run" not in step for step in jobs[name]["steps"])
        downloads = [s for s in jobs[name]["steps"] if "download-artifact" in s.get("uses", "")]
        assert downloads
        assert all(s["with"]["digest-mismatch"] == "error" for s in downloads)


@pytest.mark.parametrize("validate", [True, False])
def test_real_entry_point_ignores_untrusted_python_path_and_policy(tmp_path, validate):
    project = tmp_path / "$(touch PWNED)'quoted space"
    project.mkdir()
    package_root = tmp_path / "stub"
    package = package_root / "nexus_symbiote"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "__main__.py").write_text(
        "from pathlib import Path\nPath('PWNED').write_text('shadowed')\n"
    )
    (package_root / "sitecustomize.py").write_text(
        "from pathlib import Path\nPath('PWNED').write_text('startup')\n"
    )
    (project / ".nexus-symbiote.yaml").write_text(
        "scan:\n  scanners: [prompt]\nvalidate:\n  require_completeness: false\n  require_integrity: false\n"
    )
    (project / "CLAUDE.md").write_text("Review issues with read-only tools.\n")
    (project / "model.pkl").write_bytes(b"unsafe-format-fixture")
    env = {
        **os.environ,
        "GITHUB_WORKSPACE": str(tmp_path),
        "SYMBIOTE_SCAN_PATH": project.name,
        "SYMBIOTE_SCANNERS": "",
        "SYMBIOTE_FORMAT": "json",
        "SYMBIOTE_VALIDATE": str(validate).lower(),
        "SYMBIOTE_RISK_CHECK": "false",
        "SYMBIOTE_RISK_THRESHOLD": "50",
        "SYMBIOTE_SARIF": "false",
        "SYMBIOTE_OUTPUT_FILE": "result.json",
        "GITHUB_OUTPUT": str(tmp_path / "action-outputs"),
        "PYTHONPATH": str(package_root),
    }
    entry = Path(__file__).parents[1] / "scripts" / "run_action.py"
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", str(entry)], cwd=tmp_path, env=env, capture_output=True, check=False
    )
    assert result.returncode == (1 if validate else 0)
    assert not (tmp_path / "PWNED").exists()
    models = [
        c
        for c in json.loads((tmp_path / "result.json").read_text())["components"]
        if c["component_type"] == "model"
    ]
    assert [c["serialization_safety"] for c in models] == ["unsafe-code-execution"]
