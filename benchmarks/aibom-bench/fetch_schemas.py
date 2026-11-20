#!/usr/bin/env python3
"""Copy the vendored schemas score.py validates against, or check them against upstream.

    python3 fetch_schemas.py DIR            # copy schemas/ to DIR, checking every digest
    python3 fetch_schemas.py --refresh DIR  # also download each source and compare

Every schema is vendored under schemas/ with its source, retrieval date, SHA-256 and
licence in SOURCES.json, so scoring runs offline: pass schemas/ (or DIR) to score.py as
--schemas. A copy whose digest differs from the record is reported and not written; with
--refresh, a source whose bytes no longer match the record is reported too, since the
published scores were produced with the recorded bytes. A copy changed on purpose
records its upstream digest as upstream_sha256 and says what changed under modified.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    arguments = [argument for argument in sys.argv[1:] if argument != "--refresh"]
    refresh = "--refresh" in sys.argv[1:]
    if len(arguments) != 1:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    target = Path(arguments[0])
    target.mkdir(parents=True, exist_ok=True)
    sources = json.loads((HERE / "SOURCES.json").read_text(encoding="utf-8"))
    failed = 0
    for name, record in sources["schemas"].items():
        copy = HERE / "schemas" / name
        digest = hashlib.sha256(copy.read_bytes()).hexdigest()
        if digest != record["sha256"]:
            failed += 1
            print(
                f"{name}: vendored copy {digest[:16]}... differs from the record", file=sys.stderr
            )
            continue
        shutil.copyfile(copy, target / name)
        status = "ok"
        if refresh:
            with urllib.request.urlopen(record["source"], timeout=60) as response:  # noqa: S310
                upstream = hashlib.sha256(response.read(16 * 1024 * 1024)).hexdigest()
            recorded = record.get("upstream_sha256", digest)
            status = (
                "ok, upstream unchanged" if upstream == recorded else "ok, upstream now differs"
            )
        print(f"{name}: {status}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
