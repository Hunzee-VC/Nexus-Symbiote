"""Record SHA-256 checksums of dist/ and evidence/ without including the checksum manifest itself."""

from __future__ import annotations

import hashlib
from pathlib import Path


def main() -> None:
    paths = sorted([*Path("dist").glob("*"), *Path("evidence").rglob("*")])
    lines = []
    for path in paths:
        if path.name == "SHA256SUMS" or not path.is_file():
            continue
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        lines.append(f"{digest}  {path.as_posix()}")
    Path("evidence").mkdir(exist_ok=True)
    Path("evidence/SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
