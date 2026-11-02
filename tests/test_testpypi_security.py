"""Test-index publication must preserve the release verification boundary."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow():
    return yaml.safe_load((ROOT / ".github/workflows/publish-testpypi.yml").read_text())


def commands(job):
    return "\n".join(step.get("run", "") for step in job["steps"])


def test_testpypi_publication_requires_the_same_source_and_wheel_gates():
    doc = workflow()
    build = doc["jobs"]["build"]
    steps = build["steps"]
    preflight = next((s for s in steps if "check_repository_controls.py" in s.get("run", "")), None)
    assert preflight is not None, "TestPyPI publication must verify exact-source CI"
    assert preflight["if"] == "inputs.publish"
    assert '--sha "$GITHUB_SHA"' in preflight["run"]
    assert preflight["env"]["GH_TOKEN"] == "${{ github.token }}"  # noqa: S105 - expression, not a credential
    assert build["permissions"] == {"contents": "read", "actions": "read"}
    source = commands(build)
    assert "--require-hashes -r requirements-ci.lock" in source
    assert "python scripts/check_repository_hygiene.py" in source
    assert "python scripts/check_security_regressions.py" in source
    assert "python -m build --no-isolation" in source
    assert "python -I scripts/check_wheel_security.py dist/*.whl" in source
    assert "--no-index --no-deps --force-reinstall dist/*.whl" in source
    assert source.index("check_repository_controls.py") < source.index("python -m build")


def test_testpypi_is_opt_in_main_only_and_keeps_oidc_away_from_source_execution():
    doc = workflow()
    events = doc.get("on", doc.get(True))
    assert set(events) == {"workflow_dispatch"}
    assert events["workflow_dispatch"]["inputs"]["publish"]["default"] is False
    jobs = doc["jobs"]
    assert jobs["build"]["if"] == "github.ref == 'refs/heads/main'"
    publish = jobs["publish"]
    assert publish["if"] == "inputs.publish && github.ref == 'refs/heads/main'"
    assert publish["environment"]["name"] == "testpypi"
    assert publish["permissions"] == {"id-token": "write"}
    assert publish["needs"] == "build"
    assert not any("run" in step for step in publish["steps"])
    assert not any("checkout" in step.get("uses", "") for step in publish["steps"])
    upload = next(
        s for s in publish["steps"] if s.get("uses", "").startswith("pypa/gh-action-pypi-publish@")
    )
    assert upload["with"]["repository-url"] == "https://test.pypi.org/legacy/"
    assert upload["with"]["attestations"] is True
