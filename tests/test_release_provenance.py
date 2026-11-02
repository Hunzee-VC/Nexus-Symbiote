"""Test the release publication gate without treating a stub as cryptographic evidence."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
VERIFY_STEP = "Verify exact distributions and source provenance"


def release_jobs() -> dict:
    return yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())["jobs"]


@pytest.mark.parametrize(
    "case", ["success", "missing-bundle", "extra-bundle", "missing-wheel", "bad-subject"]
)
def test_publish_verification_gate_checks_every_distribution(tmp_path, case):
    jobs = release_jobs()
    verify_job = jobs["verify-provenance"]
    verify = next(step for step in verify_job["steps"] if step.get("name") == VERIFY_STEP)
    assert "verify-provenance" in jobs["publish"]["needs"]
    (tmp_path / "dist").mkdir()
    (tmp_path / "attestation").mkdir()
    (tmp_path / "bin").mkdir()
    (tmp_path / "dist" / "candidate.tar.gz").write_text("sdist")
    if case != "missing-wheel":
        (tmp_path / "dist" / "candidate.whl").write_text("wheel")
    if case != "missing-bundle":
        (tmp_path / "attestation" / "bundle.jsonl").write_text("bundle")
    if case == "extra-bundle":
        (tmp_path / "attestation" / "other.jsonl").write_text("bundle")
    gh = tmp_path / "bin" / "gh"
    gh.write_text(
        '#!/bin/bash\nprintf "%s\\n" "$*" >> "$CALLS"\n'
        'if [[ "$FAIL_SUBJECT" == 1 && "$3" == *.tar.gz ]]; then exit 1; fi\n'
    )
    gh.chmod(0o755)
    calls = tmp_path / "calls"
    # Exercise the reviewed workflow shell with a local stub, never live credentials.
    process = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", verify["run"]],
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
            assert "--bundle attestation/bundle.jsonl" in row
            assert "--repo owner/repo" in row
            assert "--signer-workflow owner/repo/.github/workflows/release.yml" in row
            assert "--source-ref refs/heads/main" in row
            assert f"--source-digest {'a' * 40}" in row
            assert "--deny-self-hosted-runners" in row
    else:
        assert not calls.exists()


def test_distribution_bundle_is_retained_and_verified_before_publish():
    jobs = release_jobs()
    attest = jobs["attest"]
    retain = next(s for s in attest["steps"] if s.get("id") == "distribution-attestation")
    assert retain["uses"].startswith("actions/upload-artifact@")
    assert retain["with"]["path"] == "${{ steps.distributions.outputs.bundle-path }}"
    assert retain["with"]["if-no-files-found"] == "error"
    assert attest["outputs"]["distribution_attestation_id"] == (
        "${{ steps.distribution-attestation.outputs.artifact-id }}"
    )
    verify = jobs["verify-provenance"]
    assert set(verify["needs"]) == {"build", "attest"}
    # The shell-running verifier gets read access only: no OIDC, no writes.
    assert verify["permissions"] == {"contents": "read", "attestations": "read"}
    downloads = [s["with"] for s in verify["steps"] if "download-artifact" in s.get("uses", "")]
    assert [d["path"] for d in downloads] == ["dist", "attestation"]
    assert [d["artifact-ids"] for d in downloads] == [
        "${{ needs.build.outputs.distributions_id || 'missing' }}",
        "${{ needs.attest.outputs.distribution_attestation_id || 'missing' }}",
    ]
    assert all(d["digest-mismatch"] == "error" for d in downloads)
    assert set(jobs["publish"]["needs"]) == {"build", "attest", "verify-provenance"}
