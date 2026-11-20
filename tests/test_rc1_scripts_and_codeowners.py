"""Tests for precision gate, parser fuzz harness, and out-of-tree signed operator policy gate."""

from __future__ import annotations

import json
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, get_args

import click
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote import attestation, limits
from nexus_symbiote.cli import main as cli_main
from nexus_symbiote.core.aibom import AIBOM

PR_268_HEAD = "ec3eb549c589ca62593b27919959aff0314c6d38"
PR_268_OPERATOR_POLICY_CONTRACT = {
    "src/nexus_symbiote/operator_policy.py::_verify_policy_attestation": {
        "purpose": "policy",
        "match": "bytes",
        "threshold": 1,
        "max_age_days": 90,
    },
    "src/nexus_symbiote/cli.py::_operator_policy_options": (
        "--operator-policy",
        "--operator-policy-attestation",
        "--operator-policy-key",
        "--allow-unsigned-operator-policy",
        "--operator-policy-max-age-days",
    ),
}
SHADOWSCAN_REPORT = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"
EMPTY_GGUF = b"GGUF" + (3).to_bytes(4, "little") + bytes(16)


@pytest.fixture
def policy_purpose(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Give a tree without pull request #268 that change's `policy` attestation purpose."""
    if "policy" in get_args(attestation.Purpose):
        yield
        return
    field = attestation.InventoryPredicate.model_fields["purpose"]
    monkeypatch.setattr(attestation, "Purpose", Literal["generated", "reviewed", "policy"])
    monkeypatch.setattr(field, "annotation", attestation.Purpose)
    attestation.InventoryPredicate.model_rebuild(force=True)
    try:
        yield
    finally:
        monkeypatch.undo()
        attestation.InventoryPredicate.model_rebuild(force=True)


def _attest(
    subject: Path,
    key: Ed25519PrivateKey,
    out: Path,
    *,
    purpose: str = "policy",
    signed_at: datetime | None = None,
) -> None:
    statement = attestation.build_statement(
        subject.read_bytes(),
        name=subject.name,
        purpose=purpose,
        signed_at=signed_at or datetime.now(UTC).replace(microsecond=0),
    )
    envelope = attestation.sign_statement(statement, [key])
    out.write_text(json.dumps(envelope.model_dump(mode="json", by_alias=True)), encoding="utf-8")


def _operator_key(ops: Path) -> tuple[Ed25519PrivateKey, Path]:
    key = Ed25519PrivateKey.generate()
    public = ops / "op.pub"
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    public.chmod(0o600)
    return key, public


def _staged_layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy: str = "") -> tuple:
    project, ops = tmp_path / "project", tmp_path / "ops"
    project.mkdir()
    ops.mkdir(mode=0o700)
    (project / "CLAUDE.md").write_text("Follow approved tools only.\n", encoding="utf-8")
    operator_policy = ops / "operator-policy.yaml"
    operator_policy.write_text("version: '1.0'\n" + policy, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return project, ops, operator_policy


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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy_purpose: None
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
    priv, pub_path = _operator_key(ops)
    att_path = ops / "operator-policy.att.json"
    _attest(op_policy, priv, att_path)

    # 3. An unsigned operator policy fails closed unless it is accepted explicitly, and
    # that acceptance cannot be combined with an attestation.
    assert staged.main(["--project", str(project), "--operator-policy", str(op_policy)]) == 2
    unsigned = ["--project", str(project), "--operator-policy", str(op_policy)]
    assert staged.main([*unsigned, "--allow-unsigned-operator-policy"]) == 0
    assert (
        staged.main(
            [
                *unsigned,
                "--allow-unsigned-operator-policy",
                "--operator-policy-attestation",
                str(att_path),
                "--operator-policy-key",
                str(pub_path),
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
    _attest(op_strict, priv, att_strict)
    risk_code, risk_out = staged.run_staged_gate(
        project,
        op_strict,
        baseline_source=baseline,
        attestation_source=att_strict,
        trusted_keys=(pub_path,),
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
    )
    assert tampered_code == 1
    assert "attestation verification failed" in tampered_out


def test_staged_policy_names_are_those_of_pull_request_268() -> None:
    import scripts.verify_staged_policy as staged

    envelope = PR_268_OPERATOR_POLICY_CONTRACT[
        "src/nexus_symbiote/operator_policy.py::_verify_policy_attestation"
    ]
    flags = PR_268_OPERATOR_POLICY_CONTRACT["src/nexus_symbiote/cli.py::_operator_policy_options"]
    assert isinstance(envelope, dict)
    assert len(PR_268_HEAD) == 40
    assert envelope["purpose"] == staged.POLICY_PURPOSE
    assert envelope["max_age_days"] == staged.DEFAULT_MAX_AGE_DAYS
    assert staged.ALLOW_UNSIGNED_FLAG in flags
    assert staged.MAX_AGE_FLAG in flags
    options = {o for action in staged._parser()._actions for o in action.option_strings}
    assert set(flags) <= options
    assert "--require-signed-operator-policy" not in options


def test_staged_policy_forwards_only_options_the_operator_policy_cli_defines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy_purpose: None
) -> None:
    import scripts.verify_staged_policy as staged

    project, ops, operator_policy = _staged_layout(tmp_path, monkeypatch)
    key, public = _operator_key(ops)
    envelope = ops / "operator-policy.att.json"
    _attest(operator_policy, key, envelope)
    flags = PR_268_OPERATOR_POLICY_CONTRACT["src/nexus_symbiote/cli.py::_operator_policy_options"]
    calls: list[tuple[str, dict[str, object]]] = []

    def operator_options(command: click.Command) -> click.Command:
        command.params.extend(
            [
                click.Option([flags[0]]),
                click.Option([flags[1]]),
                click.Option([flags[2]], multiple=True),
                click.Option([flags[3]], is_flag=True),
                click.Option([flags[4]], type=click.IntRange(min=0), default=90),
            ]
        )
        return command

    @click.group()
    def fake_cli() -> None:
        pass

    @fake_cli.command()
    @click.argument("root")
    @click.option("-o", "out")
    @click.option("--report-only", is_flag=True)
    def scan(root: str, out: str, report_only: bool, **operator: object) -> None:
        calls.append(("scan", operator))
        result = CliRunner().invoke(cli_main, ["scan", root, "-o", out, "--report-only"])
        assert result.exit_code == 0, result.output

    @fake_cli.command()
    @click.argument("bom")
    @click.option("--project")
    def risk(bom: str, project: str, **operator: object) -> None:
        calls.append(("risk", operator))

    operator_options(scan)
    operator_options(risk)
    monkeypatch.setattr(staged, "cli_main", fake_cli)

    code, output = staged.run_staged_gate(
        project, operator_policy, attestation_source=envelope, trusted_keys=(public,)
    )
    assert code == 0, output
    assert [name for name, _ in calls] == ["scan", "risk"]
    for _, operator in calls:
        assert operator == {
            "operator_policy": str(operator_policy),
            "operator_policy_attestation": str(envelope),
            "operator_policy_key": (str(public),),
            "allow_unsigned_operator_policy": False,
            "operator_policy_max_age_days": 90,
        }

    calls.clear()
    code, output = staged.run_staged_gate(project, operator_policy, allow_unsigned=True)
    assert code == 0, output
    assert [operator["allow_unsigned_operator_policy"] for _, operator in calls] == [True, True]
    assert all(operator["operator_policy_attestation"] is None for _, operator in calls)


def test_staged_policy_accepts_only_a_fresh_policy_purpose_attestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy_purpose: None
) -> None:
    import scripts.verify_staged_policy as staged

    project, ops, operator_policy = _staged_layout(tmp_path, monkeypatch)
    key, public = _operator_key(ops)
    reviewed = ops / "reviewed.att.json"
    _attest(operator_policy, key, reviewed, purpose="reviewed")
    code, output = staged.run_staged_gate(
        project, operator_policy, attestation_source=reviewed, trusted_keys=(public,)
    )
    assert (code, "purpose-mismatch" in output) == (1, True), output

    stale = ops / "stale.att.json"
    signed_at = datetime.now(UTC).replace(microsecond=0) - timedelta(days=91)
    _attest(operator_policy, key, stale, signed_at=signed_at)
    code, output = staged.run_staged_gate(
        project, operator_policy, attestation_source=stale, trusted_keys=(public,)
    )
    assert code == 1, output
    assert "attestation verification failed" in output
    code, output = staged.run_staged_gate(
        project, operator_policy, attestation_source=stale, trusted_keys=(public,), max_age_days=0
    )
    assert code == 0, output
    code, output = staged.run_staged_gate(
        project, operator_policy, attestation_source=stale, trusted_keys=(public,), max_age_days=-1
    )
    assert code == 2, output


def test_staged_policy_refuses_a_signed_policy_where_the_purpose_is_undefined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy_purpose: None
) -> None:
    import scripts.verify_staged_policy as staged

    project, ops, operator_policy = _staged_layout(tmp_path, monkeypatch)
    key, public = _operator_key(ops)
    envelope = ops / "operator-policy.att.json"
    _attest(operator_policy, key, envelope)
    monkeypatch.setattr(attestation, "Purpose", Literal["generated", "reviewed"])
    code, output = staged.run_staged_gate(
        project, operator_policy, attestation_source=envelope, trusted_keys=(public,)
    )
    assert code == 2, output
    assert "no 'policy' purpose" in output


@pytest.mark.parametrize("ci", [None, "true"])
def test_staged_gate_fails_unsigned_discovery_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ci: str | None
) -> None:
    import scripts.verify_staged_policy as staged

    project, _, operator_policy = _staged_layout(tmp_path, monkeypatch)
    if ci is not None:
        monkeypatch.setenv("CI", ci)
    (project / ".shadowscan").mkdir()
    shutil.copy(SHADOWSCAN_REPORT, project / ".shadowscan/report.json")
    code, output = staged.run_staged_gate(project, operator_policy, allow_unsigned=True)
    assert code == 1, output
    assert "Error: unsigned ShadowScan discovery evidence" in output


def test_staged_gate_fails_unknown_integrity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.verify_staged_policy as staged

    project, _, operator_policy = _staged_layout(tmp_path, monkeypatch)
    (project / "model.gguf").write_bytes(EMPTY_GGUF)
    code, output = staged.run_staged_gate(project, operator_policy, allow_unsigned=True)
    assert code == 1, output
    assert "integrity validation failed under operator policy (status: unknown)" in output


def test_staged_gate_enforces_minimum_assurance_level(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.verify_staged_policy as staged

    project, ops, verified = _staged_layout(
        tmp_path, monkeypatch, "validate:\n  minimum_assurance_level: verified\n"
    )
    code, output = staged.run_staged_gate(project, verified, allow_unsigned=True)
    assert code == 1, output
    assert "minimum_assurance_level: verified cannot be established" in output

    observed = ops / "observed.yaml"
    observed.write_text(
        "version: '1.0'\nvalidate:\n  minimum_assurance_level: observed\n", encoding="utf-8"
    )
    code, output = staged.run_staged_gate(project, observed, allow_unsigned=True)
    assert code == 0, output
    (project / "agent.yaml").write_text(
        "name: triage\ninstructions: [CLAUDE.md]\n"
        "models: {chat: {provider: example, requested_ref: latest}}\n",
        encoding="utf-8",
    )
    code, output = staged.run_staged_gate(project, observed, allow_unsigned=True)
    assert code == 1, output
    assert "minimum observed assurance not attained (1 declared component)" in output

    default = ops / "default.yaml"
    default.write_text("version: '1.0'\n", encoding="utf-8")
    (project / "agent.yaml").unlink()
    (project / ".nexus-symbiote.yaml").write_text(
        "version: '1.0'\nvalidate:\n  minimum_assurance_level: verified\n", encoding="utf-8"
    )
    code, output = staged.run_staged_gate(project, default, allow_unsigned=True)
    assert code == 1, output


def test_staged_gate_enforces_require_discovery_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.verify_staged_policy as staged
    from nexus_symbiote.policy import Policy, ValidatePolicy

    project, ops, _ = _staged_layout(tmp_path, monkeypatch)
    (project / ".shadowscan").mkdir()
    shutil.copy(SHADOWSCAN_REPORT, project / ".shadowscan/report.json")
    without_report = ops / "prompt-only.json"
    scan = ["scan", str(project), "--scanner", "prompt", "--report-only", "--no-project-policy"]
    assert CliRunner().invoke(cli_main, [*scan, "-o", str(without_report)]).exit_code == 0
    bom = AIBOM.load(without_report)

    def failures(required: bool) -> list[str]:
        validation = ValidatePolicy(
            require_completeness=False, require_discovery_signature=required
        )
        return staged.validation_failures(bom, project, Policy(validate=validation))

    assert failures(False) == []
    assert failures(True) == [
        "The inventory omits the ShadowScan report present beneath the project root."
    ]


def test_staged_gate_neutralizes_checkout_text_in_its_own_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.verify_staged_policy as staged

    project, _, operator_policy = _staged_layout(tmp_path, monkeypatch)
    (project / ".nexus-symbiote.yaml").write_text(
        "version: '1.0'\n\"\\n::error title=forged::owned\\e[2J##[warning]x\": 1\n",
        encoding="utf-8",
    )
    code, output = staged.run_staged_gate(project, operator_policy, allow_unsigned=True)
    assert code == 1, output
    assert "Error: invalid " in output
    assert "\x1b" not in output
    assert "##[" not in output
    assert not any(line.lstrip().startswith("::") for line in output.splitlines())


def test_staged_gate_collects_under_the_operator_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.verify_staged_policy as staged

    project, _, operator_policy = _staged_layout(tmp_path, monkeypatch)
    seen: list[int] = []
    validate = staged.CompletenessValidator.validate_against_project

    def spy(self: object, bom: AIBOM, root: Path, **kwargs: object) -> object:
        seen.append(limits.current().entries)
        return validate(self, bom, root, **kwargs)

    monkeypatch.setattr(staged.CompletenessValidator, "validate_against_project", spy)
    monkeypatch.setenv(limits.ENV_VAR, "entries=4321")
    code, output = staged.run_staged_gate(project, operator_policy, allow_unsigned=True)
    assert code == 0, output
    assert set(seen) == {4321}
    assert limits.current() == limits.DEFAULTS

    monkeypatch.setenv(limits.ENV_VAR, "entries=1")
    code, output = staged.run_staged_gate(project, operator_policy, allow_unsigned=True)
    assert code == 1, output
    assert "entries limit of 1 exceeded" in output

    monkeypatch.setenv(limits.ENV_VAR, "no-such-limit=1")
    code, output = staged.run_staged_gate(project, operator_policy, allow_unsigned=True)
    assert code == 2, output


def test_documented_attestation_commands_name_the_repository_and_real_checksum_paths() -> None:
    text = (Path(__file__).parent.parent / "docs/releasing.md").read_text(encoding="utf-8")
    commands = [
        command
        for command in text.replace("\\\n", " ").splitlines()
        if "gh attestation verify " in command
    ]
    assert len(commands) >= 2
    for command in commands:
        if command.lstrip().startswith("gh attestation verify"):
            assert " --repo " in command or " --owner " in command, command
    assert "sha256sum -c SHA256SUMS" not in text
    assert "gh attestation trusted-root" in text


def test_staged_policy_refuses_a_trusted_key_inside_the_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy_purpose: None
) -> None:
    import scripts.verify_staged_policy as staged

    project, ops, operator_policy = _staged_layout(tmp_path, monkeypatch)
    (project / ".git").mkdir()
    key, public = _operator_key(ops)
    envelope = ops / "operator-policy.att.json"
    _attest(operator_policy, key, envelope)
    planted = project / "op.pub"
    shutil.copy(public, planted)
    code, output = staged.run_staged_gate(
        project, operator_policy, attestation_source=envelope, trusted_keys=(planted,)
    )
    assert code == 2, output
    assert "--operator-policy-key must lie outside the target checkout" in output


def test_staged_policy_accepts_a_baseline_beside_the_policy_in_an_operator_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.verify_staged_policy as staged

    project, ops, operator_policy = _staged_layout(tmp_path, monkeypatch)
    (ops / ".git").mkdir()
    baseline = ops / "baseline.json"
    scan = ["scan", str(project), "--no-project-policy", "-o", str(baseline)]
    assert CliRunner().invoke(cli_main, scan).exit_code == 0
    code, output = staged.run_staged_gate(
        project, operator_policy, baseline_source=baseline, allow_unsigned=True
    )
    assert code != 2, output
    assert "must lie outside" not in output
    inside = project / "baseline.json"
    shutil.copy(baseline, inside)
    code, output = staged.run_staged_gate(
        project, operator_policy, baseline_source=inside, allow_unsigned=True
    )
    assert code == 2, output
