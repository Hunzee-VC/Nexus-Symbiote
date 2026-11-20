#!/usr/bin/env python3
"""Report files a tool added, changed or removed inside a materialized corpus.

    python corpus_delta.py CORPUS_DIR MANIFEST_JSON

Prints JSON with ``added``, ``modified`` and ``removed`` lists. A scanner that
writes into the project it inventories is a finding for the benchmark's
tool-safety dimension, so the runner calls this after every run.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path


def main() -> None:
    root = Path(sys.argv[1])
    manifest = json.loads(Path(sys.argv[2]).read_text())
    expected: dict[str, str] = dict(manifest["files"])
    large = set(manifest.get("large", {}))
    symlinks = set(manifest.get("symlinks", {}))
    seen: set[str] = set()
    added: list[str] = []
    modified: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
        for name in filenames:
            path = Path(dirpath) / name
            rel = str(path.relative_to(root))
            if path.is_symlink():
                if rel not in symlinks:
                    added.append(rel)
                continue
            seen.add(rel)
            if rel in large:
                continue
            if rel not in expected:
                added.append(rel)
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != expected[rel]:
                modified.append(rel)
    removed = sorted(set(expected) - seen)
    print(
        json.dumps(
            {"added": sorted(added), "modified": sorted(modified), "removed": removed}, indent=2
        )
    )


if __name__ == "__main__":
    main()
