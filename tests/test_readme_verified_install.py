"""The README's verified-install block fails closed when run as published, under bash."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

README = Path(__file__).parents[1] / "README.md"
BASH = shutil.which("bash")
COMMIT = "0" * 40

STUBS = {
    "python": """#!/bin/sh
mkdir -p .venv/bin
cp "$STUB_DIR/venv-python" .venv/bin/python
echo 'PATH="$PWD/.venv/bin:$PATH"' > .venv/bin/activate
""",
    "venv-python": """#!/bin/sh
echo "pip $*" >> "$STUB_LOG"
case "$*" in
  *"pip download"*)
    if [ "$STUB_FAIL" = download ]; then exit 1; fi
    mkdir -p dist && : > dist/nexus_symbiote-0.1.0-py3-none-any.whl ;;
  *"--require-hashes"*) if [ "$STUB_FAIL" = lock ]; then exit 1; fi ;;
  *"--no-deps dist/"*)
    if [ "$STUB_FAIL" = wheel ]; then exit 1; fi
    printf '#!/bin/sh\\necho "nexus-symbiote, version 0.1.0 (verified venv)"\\n' \\
      > .venv/bin/nexus-symbiote
    chmod +x .venv/bin/nexus-symbiote ;;
esac
""",
    "git": """#!/bin/sh
if [ "$STUB_FAIL" = git ]; then exit 128; fi
if [ -n "$STUB_TAG" ]; then printf '%s\\trefs/tags/v0.1.0^{}\\n' "$STUB_TAG"; fi
""",
    "gh": """#!/bin/sh
echo "gh $*" >> "$STUB_LOG"
exit "${STUB_GH_STATUS:-0}"
""",
    "curl": """#!/bin/sh
if [ "$STUB_FAIL" = curl ]; then exit 22; fi
while [ $# -gt 0 ]; do
  if [ "$1" = -o ]; then : > "$2"; shift; fi
  shift
done
""",
    "nexus-symbiote": """#!/bin/sh
echo "nexus-symbiote, version 0.0.9 (stale install on PATH)"
""",
}


def _block() -> str:
    # The whole published fence, exactly as a reader pastes it.
    section = README.read_text(encoding="utf-8").split("### Install a verified release", 1)[1]
    match = re.search(r"```bash\n(.*?)\n```", section, re.S)
    assert match
    return match.group(1)


def _run(tmp_path: Path, *, tag: str = COMMIT, gh_status: int = 0, gh: bool = True, fail: str = ""):
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for name, body in STUBS.items():
        if name == "gh" and not gh:
            continue
        (stubs / name).write_text(body)
        (stubs / name).chmod(0o755)
    work = tmp_path / "work"
    work.mkdir()
    log = tmp_path / "calls.log"
    log.touch()
    env = {
        "PATH": f"{stubs}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "STUB_DIR": str(stubs),
        "STUB_LOG": str(log),
        "STUB_TAG": tag,
        "STUB_GH_STATUS": str(gh_status),
        "STUB_FAIL": fail,
    }
    result = subprocess.run(  # noqa: S603 - the README block under a fixed interpreter
        [BASH or "bash", "-c", _block()],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return result, log.read_text(), work


pytestmark = pytest.mark.skipif(BASH is None or os.name != "posix", reason="needs bash")


def test_verified_install_prints_the_venv_version_after_every_step_succeeds(tmp_path):
    result, calls, work = _run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "nexus-symbiote, version 0.1.0 (verified venv)"
    assert "--source-digest " + COMMIT in calls
    assert (work / ".venv/bin/nexus-symbiote").exists()


@pytest.mark.parametrize(
    ("failure", "before_attestation"),
    [
        ({"gh_status": 1}, True),
        ({"gh": False}, True),
        ({"tag": ""}, True),
        ({"fail": "git"}, True),
        ({"fail": "download"}, True),
        ({"fail": "curl"}, False),
        ({"fail": "lock"}, False),
        ({"fail": "wheel"}, False),
    ],
    ids=[
        "attestation-fails",
        "gh-missing",
        "tag-missing",
        "git",
        "download",
        "curl",
        "lock",
        "wheel",
    ],
)
def test_verified_install_stops_and_installs_nothing_after_a_failed_step(
    tmp_path, failure, before_attestation
):
    result, calls, work = _run(tmp_path, **failure)
    assert result.returncode != 0
    assert "version" not in result.stdout
    assert not (work / ".venv/bin/nexus-symbiote").exists()
    if before_attestation:
        assert "--require-hashes" not in calls and "--no-deps dist/" not in calls
