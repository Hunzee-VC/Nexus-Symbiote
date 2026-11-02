"""Record checksums without including the checksum manifest itself."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path


def main() -> None:
    sha = os.environ.get("GITHUB_SHA", "")
    git = shutil.which("git")
    if git is None:
        raise ValueError("git executable is unavailable")
    checkout = subprocess.check_output([git, "rev-parse", "HEAD"], text=True).strip()  # noqa: S603
    if re.fullmatch(r"[0-9a-f]{40}", sha) is None or sha != checkout:
        raise ValueError("candidate source must match the workflow's exact commit SHA")
    subprocess.run([git, "diff", "--exit-code", "HEAD", "--"], check=True, capture_output=True)  # noqa: S603
    source = {
        "schema_version": 1,
        "source_sha": sha,
        "source_ref": os.environ.get("GITHUB_REF"),
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "workflow": os.environ.get("GITHUB_WORKFLOW"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
    }
    Path("evidence/source-revision.json").write_text(
        json.dumps(source, indent=2) + "\n", encoding="utf-8"
    )
    paths = sorted([*Path("dist").glob("*"), *Path("evidence").glob("*")])
    lines = []
    for path in paths:
        if path.name == "SHA256SUMS" or not path.is_file():
            continue
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        lines.append(f"{digest}  {path.as_posix()}")
    Path("evidence/SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
