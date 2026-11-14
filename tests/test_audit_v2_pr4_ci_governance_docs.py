"""Regression tests for PR 4: CI/Action hardening, repository controls, workflow checks, and docs."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import ssl
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.request import HTTPSHandler, ProxyHandler

import pytest
import yaml

import scripts.benchmark_security as benchmark_security
import scripts.check_coverage as check_coverage
import scripts.check_repository_controls as controls
import scripts.check_workflows as check_workflows
import scripts.run_action as run_action
from nexus_symbiote.utils.files import OutputRefusedError

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40


def _action_config(tmp_path: Path, **inputs: str) -> run_action.Config:
    return run_action.Config.from_env({"GITHUB_WORKSPACE": str(tmp_path), **inputs})


def _published_outputs(outputs: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in outputs.read_text(encoding="utf-8").splitlines())


def test_run_action_refused_primary_output_records_failed_gate_and_finishes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = _action_config(tmp_path)
    outputs = tmp_path / "github_output"
    calls: list[str] = []

    def fake_command(args: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(args[0])
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}", encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "{}", "")

    def refuse_primary(_native: Path, _target: Path, _fmt: str) -> None:
        raise OutputRefusedError("SECRET_INTERNAL_PATH_DETAIL")

    rc = run_action.run(config, command=fake_command, export=refuse_primary, outputs=outputs)
    captured = capsys.readouterr()
    published = _published_outputs(outputs)
    gates = json.loads(published["gates"])

    assert rc == 1
    assert calls == ["scan"]
    assert published["result"] == "failed"
    assert gates["collection"] == "failed"
    assert gates["completeness"] == "not-run"
    assert "SECRET_INTERNAL_PATH_DETAIL" not in captured.out
    assert "SECRET_INTERNAL_PATH_DETAIL" not in captured.err


def test_run_action_refused_sarif_output_records_failed_gate_and_finishes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = _action_config(tmp_path, SYMBIOTE_SARIF="true")
    outputs = tmp_path / "github_output"
    calls: list[str] = []

    def fake_command(args: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(args[0])
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}", encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "{}", "")

    def refuse_sarif(_native: Path, target: Path, fmt: str) -> None:
        if fmt == "sarif":
            raise OutputRefusedError("SARIF_SYMLINK_SECRET")
        target.write_text("{}", encoding="utf-8")

    rc = run_action.run(config, command=fake_command, export=refuse_sarif, outputs=outputs)
    captured = capsys.readouterr()
    published = _published_outputs(outputs)
    gates = json.loads(published["gates"])

    assert rc == 1
    assert calls == ["scan"]
    assert published["result"] == "failed"
    assert gates["collection"] == "failed"
    assert gates["completeness"] == "not-run"
    assert "SARIF_SYMLINK_SECRET" not in captured.out
    assert "SARIF_SYMLINK_SECRET" not in captured.err


def test_action_yml_isolates_pip_and_clarifies_validate_scope() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    validate_desc = action["inputs"]["validate"]["description"]
    assert "signature-policy" in validate_desc
    assert "reviewed-baseline" in validate_desc

    install_steps = [s for s in action["runs"]["steps"] if s.get("id") == "install"]
    assert len(install_steps) == 1
    script = install_steps[0]["run"]
    assert "PIP_CONFIG_FILE=/dev/null" in script
    assert "--isolated" in script
    assert "--no-index" in script
    assert 'HOME="$pip_home"' in script


def test_repository_controls_tls_strict_json_and_proxy_isolation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = controls._tls_context()
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert ctx.keylog_filename is None

    assert controls._strict_json(b'{"ok": 1}') == {"ok": 1}
    with pytest.raises(ValueError, match="duplicate JSON key"):
        controls._strict_json(b'{"ok": 1, "ok": 2}')
    with pytest.raises(ValueError, match="non-finite JSON constant"):
        controls._strict_json(b'{"bad": NaN}')
    with pytest.raises(ValueError, match="non-finite JSON constant"):
        controls._strict_json(b'{"bad": Infinity}')

    no_redirect = controls._NoRedirect()
    assert (
        no_redirect.redirect_request(None, None, 302, "Found", {}, "https://evil.example") is None
    )

    for bad_repo in ("../bad", "owner/..", "./bad", "owner/.", "owner/repo/extra"):
        with pytest.raises(ValueError, match="owner/name"):
            controls._fetch(bad_repo, "branches/main", "tok")
    for bad_token in ("", "tok\x00bad", "tok\nbad", "tok\rbad"):
        with pytest.raises(ValueError, match="GitHub token"):
            controls._fetch("Hunzee-VC/Nexus-Symbiote", "branches/main", bad_token)

    captured_handlers: list[Any] = []

    class FakeOpener:
        def open(self, request: Any, timeout: int = 15) -> io.BytesIO:
            assert request.full_url == "https://api.github.com/repos/Hunzee-VC/Nexus-Symbiote/x"
            assert timeout == 15
            return io.BytesIO(b'{"status": "ok"}')

    def fake_build_opener(*handlers: Any) -> FakeOpener:
        captured_handlers.extend(handlers)
        return FakeOpener()

    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setattr(controls, "build_opener", fake_build_opener)
    assert controls._fetch("Hunzee-VC/Nexus-Symbiote", "x", "valid-token") == {"status": "ok"}
    proxy_handlers = [h for h in captured_handlers if isinstance(h, ProxyHandler)]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}
    assert any(isinstance(h, HTTPSHandler) for h in captured_handlers)
    assert any(isinstance(h, controls._NoRedirect) for h in captured_handlers)


def test_repository_controls_requires_all_four_tag_rules_and_optional_tag_signer_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ruleset = json.loads((ROOT / "config" / "github-release-tag-ruleset.json").read_text("utf-8"))
    rule_types = {r["type"] for r in ruleset["rules"]}
    assert rule_types == {"update", "deletion", "non_fast_forward", "required_signatures"}

    for missing in ("non_fast_forward", "required_signatures"):
        weakened = {
            **ruleset,
            "id": 99,
            "current_user_can_bypass": "never",
            "rules": [r for r in ruleset["rules"] if r["type"] != missing],
        }
        errors, _ = controls.evaluate_tag_rulesets([weakened], verify_bypass_actors=True)
        assert errors

    ref = {"ref": "refs/tags/v0.2.0", "object": {"type": "tag", "sha": "b" * 40}}
    tag_obj = {
        "tag": "v0.2.0",
        "object": {"type": "commit", "sha": SHA},
        "verification": {"verified": True, "reason": "valid"},
        "tagger": {"name": "Lead", "email": "Maintainer@Example.org"},
    }
    assert controls.evaluate_release_tag(ref, tag_obj, version="0.2.0", sha=SHA) == []

    monkeypatch.setenv("ALLOWED_RELEASE_TAG_SIGNERS", "maintainer@example.org, backup@example.org")
    assert controls.evaluate_release_tag(ref, tag_obj, version="0.2.0", sha=SHA) == []

    untrusted_tag = {**tag_obj, "tagger": {"name": "Other", "email": "intruder@example.org"}}
    errors = controls.evaluate_release_tag(ref, untrusted_tag, version="0.2.0", sha=SHA)
    assert len(errors) == 1 and "allowed tag signer" in errors[0]

    missing_tagger = {k: v for k, v in tag_obj.items() if k != "tagger"}
    errors_missing = controls.evaluate_release_tag(ref, missing_tagger, version="0.2.0", sha=SHA)
    assert len(errors_missing) == 1 and "allowed tag signer" in errors_missing[0]


def test_workflow_checker_blocks_flow_mapping_count_balancing_and_neutralizing_flags_or_env(
    tmp_path: Path,
) -> None:
    pin_a = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    pin_b = "actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0"
    spoofed = tmp_path / "spoofed.yml"
    spoofed.write_text(
        "name: Spoof\n"
        "on: [push]\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-24.04\n"
        "    timeout-minutes: 10\n"
        "    steps:\n"
        f"      - {{uses: {pin_b}}}\n"
        "      - name: Decoy comment line inside shell block\n"
        "        run: |\n"
        f"          uses: {pin_a} # v7.0.1\n",
        encoding="utf-8",
    )
    pin_errors = check_workflows.pin_comments([spoofed])
    assert any("write each pinned uses on a line of its own" in err for err in pin_errors)

    locks_gates = check_workflows._gates(
        'python scripts/check_locks.py --title "Locks & pins"', True, True
    )
    assert any(g.runs("scripts/check_locks.py") for g in locks_gates)

    for bad_flag in ("--exit-zero", "--help", "-h", "--version", "-V", "--collect-only"):
        parsed_gates = check_workflows._gates(
            f"ruff check src tests scripts {bad_flag}", True, True
        )
        assert not any(g.runs("ruff check src tests scripts") for g in parsed_gates)

    assert (
        check_workflows._gates(
            "LD_PRELOAD=/nonexistent/evil.so ruff check src tests scripts", True, True
        )
        == []
    )
    assert (
        check_workflows._gates(
            "PYTHONHOME=/nonexistent/fake ruff check src tests scripts", True, True
        )
        == []
    )


def test_coverage_floors_include_tier0_runtime_live_and_supply_chain_modules() -> None:
    expected = {
        "nexus_symbiote/runtime_validation.py",
        "nexus_symbiote/supply_chain_cli.py",
        "nexus_symbiote/live/stdio.py",
        "nexus_symbiote/live/session.py",
        "nexus_symbiote/live/verify.py",
        "nexus_symbiote/scanners/live_mcp.py",
    }
    assert expected <= set(check_coverage.MODULE_FLOORS)


def test_benchmark_and_evidence_helpers_enforce_confined_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="duplicate JSON key"):
        benchmark_security._strict_json(b'{"a": 1, "a": 2}')
    with pytest.raises(ValueError, match="nonfinite JSON number"):
        benchmark_security._strict_json(b'{"a": NaN}')

    real_manifest = tmp_path / "real.json"
    real_manifest.write_text('{"schema_version": 1, "cases": []}', encoding="utf-8")
    manifest_link = tmp_path / "link.json"
    manifest_link.symlink_to(real_manifest)
    with pytest.raises(OSError):
        benchmark_security.load_manifest(manifest_link)

    monkeypatch.setattr(sys, "argv", ["benchmark_security.py", "--manifest", str(manifest_link)])
    assert benchmark_security.main() == 2

    out_target = tmp_path / "victim.json"
    out_target.write_text("keep", encoding="utf-8")
    out_link = tmp_path / "out-link.json"
    out_link.symlink_to(out_target)
    monkeypatch.setattr(
        benchmark_security,
        "run_benchmark",
        lambda _manifest: {
            "metrics": {"unknown_predictions": 0},
            "controls": {"unknown": 0},
            "case_failures": 0,
            "execution_errors": 0,
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["benchmark_security.py", "--manifest", str(real_manifest), "--out", str(out_link)],
    )
    assert benchmark_security.main() == 0
    assert out_target.read_text(encoding="utf-8") == "keep"
    assert not out_link.is_symlink()

    protected_dir = tmp_path / "protected-dir"
    protected_dir.mkdir()
    dir_link = tmp_path / "dir-link.json"
    dir_link.symlink_to(protected_dir)
    monkeypatch.setattr(
        sys,
        "argv",
        ["benchmark_security.py", "--manifest", str(real_manifest), "--out", str(dir_link)],
    )
    assert benchmark_security.main() == 2

    monkeypatch.syspath_prepend(str(ROOT / "benchmarks" / "inventory"))
    spec = importlib.util.spec_from_file_location(
        "inventory_evidence_v2_pr4", ROOT / "benchmarks" / "inventory" / "evidence.py"
    )
    assert spec is not None and spec.loader is not None
    evidence = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(evidence)

    ev_dir = tmp_path / "ev"
    (ev_dir / "fixtures").mkdir(parents=True)
    (ev_dir / "fixtures" / "good.json").write_text("{}", encoding="utf-8")
    (ev_dir / "fixtures" / "dangling.json").symlink_to(tmp_path / "nonexistent")
    monkeypatch.setattr(evidence, "DIRECTORY", ev_dir)
    mats = evidence.materials()
    assert "corpus/fixtures/good.json" in mats
    assert "corpus/fixtures/dangling.json" not in mats

    monkeypatch.setattr(evidence, "run", lambda: {"passed": True, "corpus_version": 1})
    ev_dir_link = tmp_path / "ev-link"
    ev_dir_link.symlink_to(protected_dir)
    with pytest.raises(ValueError, match="symlink"):
        evidence.prepare(ev_dir_link)


def test_conftest_isolates_proxy_env_and_normalizes_umask() -> None:
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "SSLKEYLOGFILE",
        "ALLOWED_RELEASE_TAG_SIGNERS",
    ):
        assert name not in os.environ
    current_umask = os.umask(0o022)
    os.umask(current_umask)
    assert current_umask == 0o022


def test_workflows_makefile_and_docs_security_invariants() -> None:
    ci_text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    release_text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    deps_text = (ROOT / ".github" / "workflows" / "dependencies.yml").read_text(encoding="utf-8")
    makefile_text = (ROOT / "Makefile").read_text(encoding="utf-8")

    assert "--lock requirements-floor.lock" in ci_text
    assert "--lock requirements-floor.lock" in release_text
    assert (
        "pip install --only-binary=:all: --no-index --no-deps --force-reinstall dist/*.whl"
        in ci_text
    )
    assert "pip install dist/*.whl --only-binary=:all:" in ci_text
    assert "pip install dist/*.whl --only-binary=:all:" in release_text
    assert "tests/test_registry_redirects.py" in deps_text
    assert "PYTHON ?= python" in makefile_text
    assert "--no-index --no-deps --only-binary=:all: dist/*.whl" in makefile_text

    threat_model = (ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
    assert "pull_request_target" not in threat_model

    releasing = (ROOT / "docs" / "releasing.md").read_text(encoding="utf-8")
    assert ("/" + "tmp/rehearsal") not in releasing
    assert "mktemp -d" in releasing

    coc = (ROOT / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")
    assert "[SECURITY.md](SECURITY.md)" in coc
