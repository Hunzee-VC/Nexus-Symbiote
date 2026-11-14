"""Run the published source/rehearsal fences with inert installers and real checksums."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
BASH = shutil.which("bash")
COMMIT = "a" * 40
VERSION = "0.2.0"
WHEEL = f"nexus_symbiote-{VERSION}-py3-none-any.whl"
WHEEL_BYTES = b"reviewed-wheel\n"

STUBS = {
    "git": """#!/bin/sh
case "$1" in
  clone) [ "$FAIL" != clone ] || exit 1; mkdir Nexus-Symbiote ;;
  checkout) echo checkout >> "$CALLS"; [ "$FAIL" != checkout ] || exit 1 ;;
  rev-parse) printf '%s\\n' "$HEAD_SHA" ;;
  *) exit 99 ;;
esac
""",
    "python3": """#!/bin/sh
[ "$FAIL" != venv ] || exit 1
for target do :; done
mkdir -p "$target/bin"
cp "$STUBS/venv-python" "$target/bin/python"
cp "$STUBS/nexus-symbiote" "$target/bin/nexus-symbiote"
""",
    "venv-python": """#!/bin/sh
printf '%s\\n' "$*" >> "$CALLS"
case "$*" in
  *'pip download'*)
    [ "$FAIL" != download ] || exit 1
    while [ "$1" != -d ]; do shift; done
    shift
    [ "$FAIL" != absent-wheel ] || exit 0
    printf 'reviewed-wheel\\n' > "$1/$WHEEL"
    if [ "$FAIL" = bad-digest ]; then printf changed >> "$1/$WHEEL"; fi
    if [ "$FAIL" = extra-wheel ]; then : > "$1/other-1-py3-none-any.whl"; fi
    if [ "$FAIL" = hidden-file ]; then : > "$1/.unexpected"; fi
    ;;
  *'--require-hashes'*) [ "$FAIL" != lock ] || exit 1 ;;
  *'pip install'*) [ "$FAIL" != install ] || exit 1 ;;
  *) exit 99 ;;
esac
""",
    "nexus-symbiote": """#!/bin/sh
echo version >> "$CALLS"
echo 'verified environment'
""",
}
STUBS["python"] = STUBS["venv-python"]
STUBS["pip"] = '#!/bin/sh\nexec "$STUBS/venv-python" -m pip "$@"\n'

pytestmark = pytest.mark.skipif(BASH is None or os.name != "posix", reason="needs bash")


def _fence(path: str, section: str) -> str:
    text = (ROOT / path).read_text(encoding="utf-8").split(section, 1)[1]
    found = re.search(r"(?m)^\s*```bash\n(.*?)^\s*```", text, re.S)
    assert found
    return "\n".join(line.removeprefix("   ") for line in found.group(1).splitlines())


def _run(tmp_path: Path, block: str, fail: str = "", head: str = COMMIT):
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for name, body in STUBS.items():
        path = stubs / name
        path.write_text(body)
        path.chmod(0o755)
    work = tmp_path / "work"
    work.mkdir()
    calls = tmp_path / "calls"
    calls.touch()
    temp = tmp_path / "temp"
    temp.mkdir()
    env = {
        "PATH": f"{stubs}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "TMPDIR": str(temp),
        "STUBS": str(stubs),
        "CALLS": str(calls),
        "FAIL": fail,
        "HEAD_SHA": head,
        "WHEEL": WHEEL,
    }
    result = subprocess.run(  # noqa: S603 - exact reviewed fence, inert external commands
        [BASH or "bash", "-c", block],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    return result, calls.read_text()


def _source_block(commit: str = COMMIT) -> str:
    return _fence("README.md", "### Install from reviewed source").replace(
        "REVIEWED_COMMIT_SHA", commit
    )


def test_source_install_requires_the_exact_reviewed_head(tmp_path):
    result, calls = _run(tmp_path, _source_block())
    assert result.returncode == 0, result.stderr
    assert "checkout" in calls and "--require-hashes" in calls
    assert "--no-deps --no-build-isolation ." in calls
    assert result.stdout.strip() == "verified environment"


@pytest.mark.parametrize("failure", ["clone", "checkout", "venv", "lock", "install"])
def test_source_install_stops_at_each_failed_step(tmp_path, failure):
    result, calls = _run(tmp_path, _source_block(), fail=failure)
    assert result.returncode != 0
    assert "version" not in calls
    if failure in {"clone", "checkout", "venv"}:
        assert "pip install" not in calls
    if failure == "lock":
        assert "--no-deps --no-build-isolation ." not in calls


@pytest.mark.parametrize("commit,head", [(COMMIT, "b" * 40), ("bad-ref", COMMIT)])
def test_source_install_rejects_an_invalid_or_mismatched_reviewed_ref(tmp_path, commit, head):
    result, calls = _run(tmp_path, _source_block(commit), head=head)
    assert result.returncode != 0
    assert "pip install" not in calls and "version" not in calls


def _rehearsal_block(tmp_path: Path, failure: str) -> str:
    manifest = tmp_path / "SHA256SUMS"
    digest = hashlib.sha256(WHEEL_BYTES).hexdigest()
    line = f"{digest}  dist/{WHEEL}\n"
    manifest.write_text(
        "" if failure == "missing-entry" else line * (2 if failure == "duplicate-entry" else 1)
    )
    if failure == "missing-manifest":
        manifest.unlink()
    return (
        _fence("docs/releasing.md", "3. Dispatch with `publish=testpypi`")
        .replace("REPLACE_WITH_VERSION", VERSION)
        .replace("/path/to/run/SHA256SUMS", str(manifest))
    )


def test_rehearsal_installs_only_the_exact_checked_wheel(tmp_path):
    result, calls = _run(tmp_path, _rehearsal_block(tmp_path, ""))
    assert result.returncode == 0, result.stderr
    assert f"{WHEEL}: OK" in result.stdout
    installs = [line for line in calls.splitlines() if "pip install" in line]
    assert len(installs) == 1
    assert installs[0].endswith("/" + WHEEL)
    assert "*" not in installs[0]
    assert "verified environment" in result.stdout


@pytest.mark.parametrize(
    "failure",
    [
        "venv",
        "download",
        "absent-wheel",
        "extra-wheel",
        "hidden-file",
        "bad-digest",
        "missing-entry",
        "duplicate-entry",
        "missing-manifest",
    ],
)
def test_rehearsal_verification_failure_never_reaches_install(tmp_path, failure):
    result, calls = _run(tmp_path, _rehearsal_block(tmp_path, failure), fail=failure)
    assert result.returncode != 0
    assert "pip install" not in calls and "version" not in calls


def test_rehearsal_install_failure_never_reports_success(tmp_path):
    result, calls = _run(tmp_path, _rehearsal_block(tmp_path, "install"), fail="install")
    assert result.returncode != 0
    assert "pip install" in calls and "version" not in calls
