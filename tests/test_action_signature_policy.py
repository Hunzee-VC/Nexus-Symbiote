"""The Action's signer policy is a caller-owned trust root, never checkout content."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/sigstore-python"
SPEC = importlib.util.spec_from_file_location(
    "action_signature_policy_runner", ROOT / "scripts/run_action.py"
)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)

SUBJECT_SHA256 = "c4e92e9ecc828bef2aa7dba1de8ac983511f7532a0df11c770d39099a25cf201"
SIGNER = "https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml@refs/tags/v0.1.2"
ISSUER = "https://token.actions.githubusercontent.com"
UNTRUSTED = "No trusted artifact-bound signer policy was supplied"
STAND_IN_FORMAT = "No bounded structural validator for this format/loader"


def policy_document(identity: str = SIGNER) -> str:
    record = {
        "artifact_path": "models/signed-model.onnx",
        "bundle_path": "models/signed-model.onnx.sigstore",
        "expected_identity": identity,
        "expected_issuer": ISSUER,
    }
    return json.dumps({"version": 1, "artifacts": [record]})


def test_action_passes_the_policy_only_as_data() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    assert action["inputs"]["signature-policy"]["default"] == ""
    scan = next(step for step in action["runs"]["steps"] if step.get("id") == "scan")
    assert scan["env"]["SYMBIOTE_SIGNATURE_POLICY"] == "${{ inputs.signature-policy }}"
    assert "${{" not in scan["run"] and "signature" not in scan["run"]
    output = action["outputs"]["signature-policy-digest"]
    assert output["value"] == "${{ steps.scan.outputs.signature_policy_digest }}"


def test_one_policy_snapshot_reaches_collection_and_validation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    policy = tmp_path / "caller" / "signers.json"
    policy.parent.mkdir()
    policy.write_text(policy_document())
    config = runner.Config.from_env(
        {"GITHUB_WORKSPACE": str(workspace), "SYMBIOTE_SIGNATURE_POLICY": str(policy)}
    )
    policy.write_text(policy_document("https://attacker.invalid/replaced-after-validation"))
    calls: list[list[str]] = []
    seen: list[str] = []

    def command(args: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if "--signature-policy" in args:
            seen.append(Path(args[args.index("--signature-policy") + 1]).read_text())
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(args, 0, '{"overall_score": 0}', "")

    outputs = tmp_path / "outputs"
    assert runner.run(config, command=command, outputs=outputs) == 0
    scan, validate, risk = calls
    assert [scan[0], validate[0], risk[0]] == ["scan", "validate", "risk"]
    assert scan.count("--signature-policy") == validate.count("--signature-policy") == 1
    assert scan.index("--signature-policy") < scan.index("--")
    snapshot = Path(scan[scan.index("--signature-policy") + 1])
    assert validate[validate.index("--signature-policy") + 1] == str(snapshot)
    assert snapshot != policy and not snapshot.is_relative_to(workspace)
    assert not snapshot.exists()
    assert seen == [policy_document(), policy_document()]
    assert "--signature-policy" not in risk
    digest = hashlib.sha256(policy_document().encode()).hexdigest()
    assert f"signature_policy_digest=sha256:{digest}\n" in outputs.read_text()


def test_empty_policy_input_supplies_no_trust_root(tmp_path: Path) -> None:
    config = runner.Config.from_env(
        {"GITHUB_WORKSPACE": str(tmp_path), "SYMBIOTE_SIGNATURE_POLICY": ""}
    )
    calls: list[list[str]] = []

    def command(args: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(args, 0, '{"overall_score": 0}', "")

    outputs = tmp_path / "outputs"
    assert runner.run(config, command=command, outputs=outputs) == 0
    assert len(calls) == 3 and all("--signature-policy" not in args for args in calls)
    assert "signature_policy_digest" not in outputs.read_text()


OUTSIDE = "outside GITHUB_WORKSPACE"
NOT_REGULAR = "regular file reached without symlinks"


def _relative(tmp_path: Path, workspace: Path) -> str:
    return "signers.json"


def _in_workspace(tmp_path: Path, workspace: Path) -> str:
    return str(workspace / "signers.json")


def _in_scan_path(tmp_path: Path, workspace: Path) -> str:
    return str(workspace / "agent" / "signers.json")


def _dot_dot_into_workspace(tmp_path: Path, workspace: Path) -> str:
    return f"{tmp_path}/caller/../workspace/signers.json"


def _case_alias_of_workspace(tmp_path: Path, workspace: Path) -> str:
    alias = workspace.with_name(workspace.name.upper())
    if not alias.exists():
        pytest.skip("the file system is case-sensitive, so the alias does not exist")
    return str(alias / "signers.json")


def _newline(tmp_path: Path, workspace: Path) -> str:
    return f"{tmp_path}/caller/signers.json\nSYMBIOTE_VALIDATE=false"


def _nul(tmp_path: Path, workspace: Path) -> str:
    return f"{tmp_path}/caller/signers.json\x00"


def _symlink_into_workspace(tmp_path: Path, workspace: Path) -> str:
    link = tmp_path / "caller" / "link.json"
    link.symlink_to(workspace / "signers.json")
    return str(link)


def _symlink_to_caller_file(tmp_path: Path, workspace: Path) -> str:
    link = tmp_path / "caller" / "link.json"
    link.symlink_to(tmp_path / "caller" / "signers.json")
    return str(link)


def _parent_symlink_into_workspace(tmp_path: Path, workspace: Path) -> str:
    (tmp_path / "alias").symlink_to(workspace, target_is_directory=True)
    return str(tmp_path / "alias" / "signers.json")


def _directory(tmp_path: Path, workspace: Path) -> str:
    return str(tmp_path / "caller")


def _missing(tmp_path: Path, workspace: Path) -> str:
    return str(tmp_path / "caller" / "missing.json")


def _fifo(tmp_path: Path, workspace: Path) -> str:
    if not hasattr(os, "mkfifo"):
        pytest.skip("named pipes are unavailable")
    os.mkfifo(tmp_path / "caller" / "pipe.json")
    return str(tmp_path / "caller" / "pipe.json")


def _oversized(tmp_path: Path, workspace: Path) -> str:
    from nexus_symbiote.signature_policy import MAX_POLICY_BYTES

    big = tmp_path / "caller" / "big.json"
    big.write_bytes(b" " * (MAX_POLICY_BYTES + 1))
    return str(big)


@pytest.mark.parametrize(
    "build,message",
    [
        (_relative, OUTSIDE),
        (_in_workspace, OUTSIDE),
        (_in_scan_path, OUTSIDE),
        (_dot_dot_into_workspace, OUTSIDE),
        (_case_alias_of_workspace, OUTSIDE),
        (_newline, OUTSIDE),
        (_nul, OUTSIDE),
        (_symlink_into_workspace, NOT_REGULAR),
        (_symlink_to_caller_file, NOT_REGULAR),
        (_parent_symlink_into_workspace, NOT_REGULAR),
        (_directory, NOT_REGULAR),
        (_missing, NOT_REGULAR),
        (_fifo, NOT_REGULAR),
        (_oversized, "byte limit"),
    ],
)
def test_signature_policy_must_be_a_caller_owned_regular_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, build, message: str
) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "agent").mkdir(parents=True)
    (tmp_path / "caller").mkdir()
    for path in [
        tmp_path / "signers.json",
        tmp_path / "caller" / "signers.json",
        workspace / "signers.json",
        workspace / "agent" / "signers.json",
    ]:
        path.write_text(policy_document())
    monkeypatch.chdir(tmp_path)
    value = build(tmp_path, workspace)
    with pytest.raises(ValueError, match=message):
        runner.Config.from_env(
            {
                "GITHUB_WORKSPACE": str(workspace),
                "SYMBIOTE_SCAN_PATH": "agent",
                "SYMBIOTE_SIGNATURE_POLICY": value,
            }
        )


@pytest.mark.parametrize("mode", ["none", "caller", "wrong-signer", "checkout"])
def test_real_entry_point_verifies_signed_model_only_with_caller_policy(
    tmp_path: Path, mode: str
) -> None:
    pytest.importorskip("sigstore")
    subject = (FIXTURES / "rfc8785-0.1.2-py3-none-any.whl.subject").read_bytes()
    assert hashlib.sha256(subject).hexdigest() == SUBJECT_SHA256
    workspace = tmp_path / "workspace"
    models = workspace / "agent" / "models"
    models.mkdir(parents=True)
    (models / "signed-model.onnx").write_bytes(subject)
    shutil.copyfile(
        FIXTURES / "bundle_v3_github.whl.sigstore", models / "signed-model.onnx.sigstore"
    )
    (tmp_path / "caller").mkdir()
    policy = {
        "none": None,
        "caller": tmp_path / "caller" / "signers.json",
        "wrong-signer": tmp_path / "caller" / "signers.json",
        "checkout": workspace / "agent" / "signers.json",
    }[mode]
    if policy is not None:
        identity = SIGNER if mode != "wrong-signer" else SIGNER.replace("v0.1.2", "v9.9.9")
        policy.write_text(policy_document(identity))
    outputs = tmp_path / "action-outputs"
    env = {
        **os.environ,
        "HOME": str(tmp_path / "home"),
        "GITHUB_WORKSPACE": str(workspace),
        "SYMBIOTE_SCAN_PATH": "agent",
        "SYMBIOTE_SCANNERS": "",
        "SYMBIOTE_FORMAT": "json",
        "SYMBIOTE_VALIDATE": "true",
        "SYMBIOTE_RISK_CHECK": "false",
        "SYMBIOTE_RISK_THRESHOLD": "50",
        "SYMBIOTE_SARIF": "false",
        "SYMBIOTE_OUTPUT_FILE": "result.json",
        "SYMBIOTE_SIGNATURE_POLICY": "" if policy is None else str(policy),
        "GITHUB_OUTPUT": str(outputs),
    }
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", str(ROOT / "scripts/run_action.py")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    # The stand-in subject is a wheel, so its format stays unknown even when
    # its signature verifies; only a signed SafeTensors model can pass fully.
    assert result.returncode == 1
    if mode == "checkout":
        assert "signature-policy must be an absolute path outside GITHUB_WORKSPACE" in (
            result.stderr
        )
        assert not (workspace / "result.json").exists()
        assert not outputs.exists()
        return
    findings = [
        line.strip()
        for line in result.stderr.splitlines()
        if line.lstrip().startswith(("UNKNOWN [", "ERROR [", "CRITICAL ["))
    ]
    [model] = [
        c
        for c in json.loads((workspace / "result.json").read_text())["components"]
        if c["component_type"] == "model"
    ]
    recorded = outputs.read_text()
    if mode == "none":
        assert f"UNKNOWN [{model['bom_ref']}] {UNTRUSTED}" in findings
        assert model["signing_status"] != "sigstore-signed"
        assert "signing_identity" not in model
        assert "signature_policy_digest" not in recorded
    elif mode == "caller":
        assert findings == [f"UNKNOWN [{model['bom_ref']}] {STAND_IN_FORMAT}"]
        assert "Hashes verified: 1, failed: 0" in result.stderr
        assert model["signing_status"] == "sigstore-signed"
        assert model["signing_identity"] == SIGNER
        digest = hashlib.sha256(policy.read_bytes()).hexdigest()
        assert f"signature_policy_digest=sha256:{digest}\n" in recorded
    else:
        stand_in, rejected = findings
        assert stand_in == f"UNKNOWN [{model['bom_ref']}] {STAND_IN_FORMAT}"
        assert rejected.startswith(
            f"ERROR [{model['bom_ref']}] Sigstore artifact verification failed"
        )
        assert model["signing_status"] == "verification-failed"
        assert "signing_identity" not in model
