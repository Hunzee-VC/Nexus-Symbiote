"""Tests for CODEOWNERS, precision gate, fuzz harness, and staged policy scripts."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_codeowners_protects_scanners_validators_and_generators() -> None:
    codeowners = (REPO_ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    for required_dir in (
        "/src/nexus_symbiote/scanners/",
        "/src/nexus_symbiote/validators/",
        "/src/nexus_symbiote/generators/",
    ):
        assert required_dir in codeowners


def test_precision_gate_and_fuzz_harness_scripts() -> None:
    import scripts.check_precision_gate as precision_gate
    import scripts.fuzz_parsers as fuzz_parsers

    assert precision_gate.verify_drift_kinds() == []
    assert (
        precision_gate.evaluate_class_floors({"per_class_recall": {"skill": 1.0, "a2a": 1.0}}) == []
    )
    assert precision_gate.evaluate_class_floors({"per_class_recall": {"skill": 0.5}}) != []
    assert fuzz_parsers.main(["--iterations", "8"]) == 0


def test_verify_staged_policy_refuses_in_repo_operator_policy(tmp_path: Path) -> None:
    import scripts.verify_staged_policy as verify_staged_policy

    project = tmp_path / "pr_checkout"
    project.mkdir()
    in_repo_policy = project / "op.yaml"
    in_repo_policy.write_text("version: '1.0'\n", encoding="utf-8")
    code, out = verify_staged_policy.run_staged_gate(project, in_repo_policy)
    assert code != 0
    assert "inside" in out.lower() or "checkout" in out.lower() or "operator" in out.lower()
