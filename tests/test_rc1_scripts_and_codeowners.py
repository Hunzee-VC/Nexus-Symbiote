"""Tests for precision gate, parser fuzz harness, and out-of-tree signed operator policy gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote.cli import main as cli_main


def test_precision_gate_enforces_complete_class_floors_and_cli(tmp_path: Path) -> None:
    import scripts.check_precision_gate as precision_gate

    assert precision_gate.verify_drift_kinds() == []
    # Missing expected classes must fail closed (never silently pass on renamed/omitted classes).
    missing = precision_gate.evaluate_class_floors({"per_class_recall": {"renamed-class": 0.0}})
    assert len(missing) == len(precision_gate.DEFAULT_CLASS_FLOORS)
    assert any("missing from scores document" in item for item in missing)

    all_passing = {
        "per_class_recall": {
            cls_name: {"recall": max(floor, 0.95)}
            for cls_name, floor in precision_gate.DEFAULT_CLASS_FLOORS.items()
        }
    }
    assert precision_gate.evaluate_class_floors(all_passing) == []

    below_floor = {
        "classes": {
            **dict.fromkeys(precision_gate.DEFAULT_CLASS_FLOORS, 1.0),
            "skill": 0.50,
            "a2a": True,
        }
    }
    failures = precision_gate.evaluate_class_floors(below_floor)
    assert any("skill:" in f for f in failures)
    assert any("a2a: invalid recall value" in f for f in failures)

    scores_path = tmp_path / "scores.json"
    scores_path.write_text(json.dumps(all_passing), encoding="utf-8")
    out_path = tmp_path / "precision-out.json"
    assert precision_gate.main(["--scores", str(scores_path), "--out", str(out_path)]) == 0
    summary = json.loads(out_path.read_text(encoding="utf-8"))
    assert summary["passed"] is True
    assert summary["aibom_bench_status"] == "passed"

    bad_scores = tmp_path / "bad-scores.json"
    bad_scores.write_text("not-json", encoding="utf-8")
    assert precision_gate.main(["--scores", str(bad_scores), "--out", str(out_path)]) == 1


def test_fuzz_harness_cli_and_rejection_accounting() -> None:
    import scripts.fuzz_parsers as fuzz_parsers

    rejected = fuzz_parsers.exercise_one_input(b"\xff\x00invalid: [yaml: {")
    assert rejected >= 1
    assert fuzz_parsers.main(["--iterations", "16"]) == 0
    with pytest.raises(SystemExit):
        fuzz_parsers.main(["--iterations", "-1"])


def test_verify_staged_policy_enforces_out_of_tree_signature_and_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.verify_staged_policy as staged

    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    project = repo / "service"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Follow approved tools only.\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    # 1. Policy inside project or enclosing git working tree is refused in-place (exit 2).
    in_project = project / "op.yaml"
    in_project.write_text("version: '1.0'\nrisk:\n  fail_threshold: 9999.0\n", encoding="utf-8")
    code, out = staged.run_staged_gate(project, in_project)
    assert code == 2
    assert "must lie outside the target checkout and every git working tree" in out

    in_repo = repo / "op.yaml"
    in_repo.write_text("version: '1.0'\nrisk:\n  fail_threshold: 9999.0\n", encoding="utf-8")
    code_repo, out_repo = staged.run_staged_gate(project, in_repo)
    assert code_repo == 2
    assert "must lie outside the target checkout and every git working tree" in out_repo

    # 2. Prepare trusted operator policy and Ed25519 keypair outside every repository.
    ops = tmp_path / "ops"
    ops.mkdir(mode=0o700)
    op_policy = ops / "operator-policy.yaml"
    op_policy.write_text(
        "version: '1.0'\nrisk:\n  fail_threshold: 50.0\n  fail_on_severity: critical\n",
        encoding="utf-8",
    )
    priv = Ed25519PrivateKey.generate()
    priv_path = ops / "op.key"
    priv_path.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    priv_path.chmod(0o600)
    pub_path = ops / "op.pub"
    pub_path.write_bytes(
        priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    pub_path.chmod(0o600)
    att_path = ops / "operator-policy.att.json"
    assert (
        CliRunner()
        .invoke(
            cli_main,
            [
                "attest",
                str(op_policy),
                "--key",
                str(priv_path),
                "--purpose",
                "reviewed",
                "--out",
                str(att_path),
            ],
        )
        .exit_code
        == 0
    )

    # 3. --require-signed-operator-policy fails closed without attestation/key.
    assert (
        staged.main(
            [
                "--project",
                str(project),
                "--operator-policy",
                str(op_policy),
                "--require-signed-operator-policy",
            ]
        )
        == 2
    )

    # 4. Valid out-of-tree signed operator policy passes on clean project.
    assert (
        staged.main(
            [
                "--project",
                str(project),
                "--operator-policy",
                str(op_policy),
                "--operator-policy-attestation",
                str(att_path),
                "--operator-policy-key",
                str(pub_path),
                "--require-signed-operator-policy",
            ]
        )
        == 0
    )

    # Save clean baseline outside repo before introducing hostile changes.
    baseline = ops / "baseline.json"
    assert CliRunner().invoke(cli_main, ["scan", str(project), "-o", str(baseline)]).exit_code == 0

    # 5a. Under CI=true, checkout attempts to hide files via scan.exclude_paths, disable
    # scanners, and weaken risk.fail_threshold/fail_on_severity while adding a shell MCP server:
    # operator floor ignores checkout scan exclusions and fails closed on the risk gate (exit 1).
    monkeypatch.setenv("CI", "true")
    (project / ".nexus-symbiote.yaml").write_text(
        "version: '1.0'\n"
        "scan:\n"
        "  scanners: [a2a]\n"
        "  exclude_paths: ['*']\n"
        "risk:\n"
        "  fail_threshold: 9999.0\n"
        "  fail_on_severity: none\n"
        "validate:\n"
        "  require_integrity: false\n",
        encoding="utf-8",
    )
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote-http": {
                        "url": "http://mcp.internal.example/sse",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    op_strict = ops / "operator-strict.yaml"
    op_strict.write_text(
        "version: '1.0'\nrisk:\n  fail_threshold: 1.0\n  fail_on_severity: high\n",
        encoding="utf-8",
    )
    att_strict = ops / "operator-strict.att.json"
    assert (
        CliRunner()
        .invoke(
            cli_main,
            [
                "attest",
                str(op_strict),
                "--key",
                str(priv_path),
                "--purpose",
                "reviewed",
                "--out",
                str(att_strict),
            ],
        )
        .exit_code
        == 0
    )
    risk_code, risk_out = staged.run_staged_gate(
        project,
        op_strict,
        baseline_source=baseline,
        attestation_source=att_strict,
        trusted_keys=(pub_path,),
        require_signed=True,
    )
    assert risk_code == 1
    assert "operator risk gate failed" in risk_out

    # 5b. Adding an unsafe pickle model while checkout sets validation.require_integrity: false
    # is caught by the clamped operator integrity gate (exit 1).
    (project / ".mcp.json").unlink()
    (project / "evil.pkl").write_bytes(b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00.")
    fail_code, fail_out = staged.run_staged_gate(
        project,
        op_policy,
        baseline_source=baseline,
        attestation_source=att_path,
        trusted_keys=(pub_path,),
        require_signed=True,
    )
    assert fail_code == 1
    assert "integrity validation failed under operator policy" in fail_out

    # 6. Tampered operator policy fails DSSE signature verification (exit 1).
    op_policy.write_text("version: '1.0'\nrisk:\n  fail_threshold: 9999.0\n", encoding="utf-8")
    tampered_code, tampered_out = staged.run_staged_gate(
        project,
        op_policy,
        attestation_source=att_path,
        trusted_keys=(pub_path,),
        require_signed=True,
    )
    assert tampered_code == 1
    assert "attestation verification failed" in tampered_out
