"""Prepare reproducible benchmark evidence and check it.

`check` validates an archive whose provenance was verified separately, such as a release's
inventory-benchmark.tar.gz after `gh attestation verify`: the statement must bind the results
and, with --compare-installation, the local scanner, corpus and installed distributions.
`verify` does the same for an operator-signed statement with its Sigstore bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from importlib.metadata import distributions
from pathlib import Path

from run_inventory import DIRECTORY, run

import nexus_symbiote
from nexus_symbiote.core.hashing import parse_json_strict
from nexus_symbiote.scanners.base import read_regular_text
from nexus_symbiote.utils.files import write_output_file


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# Historical predicate URI prefix retained so published release benchmark attestations verify unchanged.
PREDICATE_TYPE = "https://github.com/aisecnomad/nexus-symbiote/benchmark/inventory/v1"
# Seeded by whichever tool created the environment (venv, virtualenv, uv) at its own
# version, never imported by the scanner and pinned by no lock: comparing them would fail
# every consumer whose Python patch release or environment tool differs from the release's.
BOOTSTRAP = frozenset({"pip", "setuptools", "wheel"})


def materials() -> dict[str, str]:
    """Every installed package file, schemas included, and the corpus; never bytecode caches."""
    package = Path(nexus_symbiote.__file__).resolve().parent
    files = {
        f"package/{p.relative_to(package).as_posix()}": p
        for p in package.rglob("*")
        if not p.is_symlink() and p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
    }
    for path in [
        DIRECTORY / "evidence.py",
        DIRECTORY / "run_inventory.py",
        DIRECTORY / "manifest.json",
        *sorted((DIRECTORY / "fixtures").rglob("*")),
    ]:
        if not path.is_symlink() and path.is_file():
            files["corpus/" + path.relative_to(DIRECTORY).as_posix()] = path
    return {key: digest(path.read_bytes()) for key, path in sorted(files.items())}


def installed_versions() -> dict[str, str]:
    """Every distribution the scanner ran with: the environment without its bootstrap tools.

    A name installed twice records the first copy on sys.path, the one Python imports.
    """
    versions: dict[str, str] = {}
    for distribution in distributions():
        name = (distribution.metadata.get_all("Name") or [""])[0]
        normalized = name.lower().replace("_", "-")
        if normalized and normalized not in BOOTSTRAP:
            versions.setdefault(normalized, distribution.version)
    return dict(sorted(versions.items()))


def prepare(directory: Path) -> None:
    before = materials()
    report = run()
    if not report["passed"]:
        raise ValueError("benchmark failed")
    if before != materials():
        raise ValueError("material changed during the run")
    results_text = json.dumps(report, sort_keys=True, indent=2) + "\n"
    results = results_text.encode("utf-8")
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "results.json", "digest": {"sha256": digest(results)}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "materialsSha256": before,
            "pythonVersion": sys.version,
            "packageVersions": installed_versions(),
            "corpusVersion": report["corpus_version"],
        },
    }
    if directory.is_symlink():
        raise ValueError("output directory must not be a symlink")
    directory.mkdir(exist_ok=False)
    write_output_file(directory / "results.json", results_text)
    write_output_file(
        directory / "statement.json", json.dumps(statement, sort_keys=True, indent=2) + "\n"
    )


def check(directory: Path, *, compare_installation: bool = False) -> None:
    """Require the statement to bind these results, and optionally this installation."""
    statement = read_regular_text(directory / "statement.json").encode("utf-8")
    _check_statement(statement, directory, compare_installation=compare_installation)


def _check_statement(statement: bytes, directory: Path, *, compare_installation: bool) -> None:
    body = parse_json_strict(statement)
    if not isinstance(body, dict):
        raise ValueError("statement does not bind these benchmark results")
    results = read_regular_text(directory / "results.json").encode("utf-8")
    if (
        body.get("_type") != "https://in-toto.io/Statement/v1"
        or body.get("predicateType") != PREDICATE_TYPE
        or body.get("subject") != [{"name": "results.json", "digest": {"sha256": digest(results)}}]
    ):
        raise ValueError("statement does not bind these benchmark results")
    if not compare_installation:
        return
    predicate = body.get("predicate")
    if not isinstance(predicate, dict):
        raise ValueError("statement predicate must be a JSON object")
    if predicate.get("materialsSha256") != materials():
        raise ValueError("installed scanner or benchmark differs from the recorded materials")
    if predicate.get("packageVersions") != installed_versions():
        raise ValueError("installed distributions differ from the recorded ones")


def verify(
    directory: Path, identity: str, issuer: str, *, compare_installation: bool = False
) -> None:
    from nexus_symbiote.utils.crypto import verify_sigstore_digest

    statement = read_regular_text(directory / "statement.json").encode("utf-8")
    # Parse precisely the bytes that were verified; do not reopen after verification.
    verified = verify_sigstore_digest(
        digest(statement),
        read_regular_text(directory / "statement.sigstore.json").encode("utf-8"),
        identity,
        issuer,
    )
    if not verified.verified:
        raise ValueError(verified.error or "benchmark signature verification failed")
    _check_statement(statement, directory, compare_installation=compare_installation)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("prepare", "check", "verify"):
        sub = commands.add_parser(command)
        sub.add_argument("directory", type=Path)
        if command == "verify":
            sub.add_argument("--identity", required=True)
            sub.add_argument("--issuer", required=True)
        if command != "prepare":
            sub.add_argument("--compare-installation", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args.directory)
        elif args.command == "check":
            check(args.directory, compare_installation=args.compare_installation)
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
