"""Test the release publication gate without treating a stub as cryptographic evidence."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("case", ["success", "missing-bundle", "missing-wheel", "bad-subject"])
def test_publish_verification_gate_checks_every_distribution(tmp_path, case):
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    publish = workflow["jobs"]["publish"]
    steps = publish["steps"]
    verify = next(
        step for step in steps if step.get("name") == "Verify exact distributions and source provenance"
    )
    publish_index = next(
        i for i, step in enumerate(steps) if step.get("name") == "Publish with OIDC trusted publishing"
    )
    assert steps.index(verify) < publish_index
    assert "attest" in publish["needs"]
    (tmp_path / "dist").mkdir()
    (tmp_path / "attestation").mkdir()
    (tmp_path / "bin").mkdir()
    (tmp_path / "dist" / "candidate.tar.gz").write_text("sdist")
    if case != "missing-wheel":
        (tmp_path / "dist" / "candidate.whl").write_text("wheel")
    if case != "missing-bundle":
        (tmp_path / "attestation" / "distribution-attestation.jsonl").write_text("bundle")
    gh = tmp_path / "bin" / "gh"
    gh.write_text(
        '#!/bin/bash\nprintf "%s\\n" "$*" >> "$CALLS"\n'
        'if [[ "$FAIL_SUBJECT" == 1 && "$3" == *.tar.gz ]]; then exit 1; fi\n'
    )
    gh.chmod(0o755)
    calls = tmp_path / "calls"
    process = subprocess.run(
        ["bash", "-c", verify["run"]],
        cwd=tmp_path,
        env={
            **os.environ,
            "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}",
            "CALLS": str(calls),
            "FAIL_SUBJECT": str(int(case == "bad-subject")),
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_SHA": "a" * 40,
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert (process.returncode == 0) == (case == "success")
    if case in {"success", "bad-subject"}:
        rows = calls.read_text().splitlines()
        assert len(rows) == 2
        for row in rows:
            assert "--bundle attestation/distribution-attestation.jsonl" in row
            assert "--repo owner/repo" in row
            assert "--signer-workflow owner/repo/.github/workflows/release.yml" in row
            assert "--source-ref refs/heads/main" in row
            assert f"--source-digest {'a' * 40}" in row
            assert "--deny-self-hosted-runners" in row


def test_distribution_bundle_is_retained_and_downloaded_for_publish():
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    attest = workflow["jobs"]["attest"]["steps"]
    publish = workflow["jobs"]["publish"]["steps"]
    assert any(step.get("id") == "distributions" for step in attest)
    assert any(step.get("with", {}).get("name") == "distribution-attestation" for step in attest)
    assert any(step.get("with", {}).get("name") == "distribution-attestation" for step in publish)
