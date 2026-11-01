"""Prepare reproducible benchmark evidence or verify an operator-signed evidence package."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from importlib.metadata import version
from pathlib import Path
from typing import Any

from run_inventory import DIRECTORY, run

import nexus_symbiote


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def materials() -> dict[str, str]:
    package = Path(nexus_symbiote.__file__).resolve().parent
    files = {f"package/{p.relative_to(package).as_posix()}": p for p in package.rglob("*.py")}
    for path in [
        DIRECTORY / "evidence.py",
        DIRECTORY / "run_inventory.py",
        DIRECTORY / "manifest.json",
        *sorted((DIRECTORY / "fixtures").rglob("*")),
    ]:
        if path.is_file():
            files["corpus/" + path.relative_to(DIRECTORY).as_posix()] = path
    return {key: digest(path.read_bytes()) for key, path in sorted(files.items())}


def prepare(directory: Path) -> None:
    before = materials()
    report = run()
    if not report["passed"] or before != materials():
        raise ValueError("benchmark failed or material changed during the run")
    results = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "results.json", "digest": {"sha256": digest(results)}}],
        "predicateType": "https://github.com/aisecnomad/nexus-symbiote/benchmark/inventory/v1",
        "predicate": {
            "materialsSha256": before,
            "pythonVersion": sys.version,
            "packageVersions": {
                name: version(name)
                for name in (
                    "safetensors",
                    "pydantic",
                    "tree-sitter",
                    "tree-sitter-typescript",
                    "numpy",
                    "rfc8785",
                )
            },
            "corpusVersion": report["corpus_version"],
        },
    }
    directory.mkdir(exist_ok=False)
    (directory / "results.json").write_bytes(results)
    (directory / "statement.json").write_text(
        json.dumps(statement, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


def verify(
    directory: Path, identity: str, issuer: str, *, compare_installation: bool = False
) -> None:
    from nexus_symbiote.utils.crypto import verify_sigstore_digest

    statement = (directory / "statement.json").read_bytes()
    # Parse precisely the bytes that were verified; do not reopen after verification.
    verified = verify_sigstore_digest(
        digest(statement), (directory / "statement.sigstore.json").read_bytes(), identity, issuer
    )
    if not verified.verified:
        raise ValueError(verified.error or "benchmark signature verification failed")
    body: dict[str, Any] = json.loads(statement)
    results = (directory / "results.json").read_bytes()
    if (
        body.get("_type") != "https://in-toto.io/Statement/v1"
        or body.get("predicateType")
        != "https://github.com/aisecnomad/nexus-symbiote/benchmark/inventory/v1"
        or body.get("subject") != [{"name": "results.json", "digest": {"sha256": digest(results)}}]
    ):
        raise ValueError("signed statement does not bind these benchmark results")
    if compare_installation and body["predicate"]["materialsSha256"] != materials():
        raise ValueError("installed scanner or benchmark differs from signed materials")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("prepare", "verify"):
        sub = commands.add_parser(command)
        sub.add_argument("directory", type=Path)
        if command == "verify":
            sub.add_argument("--identity", required=True)
            sub.add_argument("--issuer", required=True)
            sub.add_argument("--compare-installation", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args.directory)
        else:
            verify(
                args.directory,
                args.identity,
                args.issuer,
                compare_installation=args.compare_installation,
            )
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
