"""Typer application: version, schema, digest, validate, merkle, attest, verify."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console

from symbiote import __version__
from symbiote.cli import exit_codes

app = typer.Typer(
    name="symbiote",
    help="Symbiote — the Agent Bill of Materials (AgentBOM) toolkit. Generates, validates, diffs, verifies, attests and enforces AgentBOMs; extends CycloneDX 1.7 and SPDX 3.0.1 without forking them.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
schema_app = typer.Typer(help="Export the schemas and vocabularies Symbiote implements.")
digest_app = typer.Typer(help="Compute digests exactly as the BOM does (spec/digests.md).")
merkle_app = typer.Typer(help="Merkle commitment: verify documents and produce inclusion proofs.")
attest_app = typer.Typer(help="Build and sign in-toto statements (DSSE).")
app.add_typer(schema_app, name="schema")
app.add_typer(digest_app, name="digest")
app.add_typer(merkle_app, name="merkle")
app.add_typer(attest_app, name="attest")

console = Console(stderr=True)
JsonFlag = Annotated[bool, typer.Option("--json", help="Machine-readable JSON on stdout.")]


def emit(data: Any, as_json: bool, human: str | None = None) -> None:
    if as_json or human is None:
        sys.stdout.write(json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n")
    else:
        console.print(human)


@app.command()
def version(as_json: JsonFlag = False) -> None:
    """Show the tool and profile versions."""
    from symbiote import SPEC_VERSION

    emit(
        {"symbiote": __version__, "agentbomSpecVersion": SPEC_VERSION},
        as_json,
        f"symbiote {__version__} (AgentBOM profile {SPEC_VERSION})",
    )


@schema_app.command("export")
def schema_export(
    which: Annotated[str, typer.Argument(help="companion | predicates | taxonomy")] = "companion",
    out: Annotated[
        Path | None, typer.Option("-o", "--out", help="Write to this file instead of stdout.")
    ] = None,
) -> None:
    """Export the companion JSON Schema or other vocabularies."""
    if which == "companion":
        from symbiote.model.schema import companion_json_schema_text

        text = companion_json_schema_text()
    elif which == "predicates":
        from symbiote.attest.statements import predicate_type

        kinds = [
            "agentbom-snapshot",
            "tool-definition-set",
            "coverage",
            "evaluation",
            "registry-resolution",
            "observed-delta",
            "trust-status",
            "approval",
        ]
        text = json.dumps({k: predicate_type(k) for k in kinds}, indent=2) + "\n"
    elif which == "taxonomy":
        text = (
            (Path(__file__).resolve().parents[3] / "spec" / "taxonomy.md").read_text(encoding="utf-8")
            if (Path(__file__).resolve().parents[3] / "spec" / "taxonomy.md").exists()
            else "see spec/taxonomy.md\n"
        )
    else:
        console.print(f"[red]unknown schema {which!r}[/red]")
        raise typer.Exit(exit_codes.USAGE)
    if out:
        out.write_text(text, encoding="utf-8")
        console.print(f"wrote {out}")
    else:
        sys.stdout.write(text)


def _read_json_arg(source: str) -> Any:
    from symbiote.digest import parse_json_strict

    raw = sys.stdin.buffer.read() if source == "-" else Path(source).read_bytes()
    return parse_json_strict(raw)


@digest_app.command("tooldef")
def digest_tooldef(
    source: Annotated[str, typer.Argument(help="Raw MCP tool definition JSON file, or '-' for stdin.")],
    full: bool = False,
    as_json: JsonFlag = False,
) -> None:
    """tooldef/v1 digest of a raw MCP tool definition (fail-closed)."""
    from symbiote.digest import tool_text_flags, tooldef_digest, tooldef_full_digest

    raw = _read_json_arg(source)
    result = tooldef_full_digest(raw) if full else tooldef_digest(raw)
    data = {**result.to_json_dict(), "textFlags": [f.value for f in tool_text_flags(raw)]}
    emit(
        data,
        as_json,
        f"{result.algorithm}: {result.value or 'UNDIGESTABLE'}"
        + (f" ({result.reason})" if result.reason else ""),
    )
    if not result.ok:
        raise typer.Exit(exit_codes.FINDINGS)


@digest_app.command("file")
def digest_file(path: Path, as_json: JsonFlag = False) -> None:
    """SHA-256 of the exact bytes plus line-ending and triage facts."""
    from symbiote.digest import file_digest, line_endings, triage_digest

    data_bytes = path.read_bytes()
    digest, size = file_digest(path)
    data = {
        "path": str(path),
        "digest": digest,
        "size": size,
        "lineEndings": line_endings(data_bytes).value,
        "triageDigest": triage_digest(data_bytes),
    }
    emit(data, as_json, f"{digest}  {path}  ({size} bytes, {data['lineEndings']})")


@digest_app.command("dir")
def digest_dir(path: Path, allow_symlinks: bool = False, as_json: JsonFlag = False) -> None:
    """dirmanifest/v1 manifest with an OpenSSF model-signing compatible root."""
    from symbiote.digest import build_dir_manifest, dirmanifest_digest

    manifest = build_dir_manifest(path, allow_symlinks=allow_symlinks)
    env = dirmanifest_digest(manifest)
    data = {
        "root": manifest.root,
        "manifestDigest": env.value,
        "files": len(manifest.resources),
        "resources": [r.to_json_dict() for r in manifest.resources],
    }
    emit(data, as_json, f"root {manifest.root}  ({len(manifest.resources)} files; manifest {env.value})")


@digest_app.command("prompt")
def digest_prompt(
    path: Path,
    engine: str = "none",
    role: str = "system",
    variables_schema: Path | None = None,
    as_json: JsonFlag = False,
) -> None:
    """prompt/v1 digest of a prompt template."""
    from symbiote.digest import prompt_digest

    schema = json.loads(variables_schema.read_text()) if variables_schema else None
    result = prompt_digest(
        engine=engine, role=role, template=path.read_text(encoding="utf-8"), variables_schema=schema
    )
    emit(result.to_json_dict(), as_json, f"{result.algorithm}: {result.value}")


@app.command()
def validate(files: list[Path], as_json: JsonFlag = False) -> None:
    """Validate companion documents against the AgentBOM schema (CycloneDX/SPDX validators arrive with WP6/WP7)."""
    from symbiote.export.companion import validate_companion

    results = []
    failed = False
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            results.append({"file": str(f), "format": "unknown", "ok": False, "errors": [str(exc)]})
            failed = True
            continue
        if isinstance(data, dict) and data.get("specVersion") and "snapshot" in data:
            errors = validate_companion(data)
            results.append(
                {"file": str(f), "format": "agentbom-companion", "ok": not errors, "errors": errors[:50]}
            )
            failed |= bool(errors)
        else:
            results.append(
                {
                    "file": str(f),
                    "format": "unknown",
                    "ok": False,
                    "errors": ["not a companion document (CycloneDX/SPDX validation: see WP6/WP7)"],
                }
            )
            failed = True
    emit(
        results,
        as_json,
        "\n".join(
            ("[green]ok[/green]  " if r["ok"] else "[red]FAIL[/red] ")
            + f"{r['file']} ({r['format']})"
            + ("" if r["ok"] else "\n   " + "\n   ".join(r["errors"][:5]))
            for r in results
        ),
    )
    if failed:
        raise typer.Exit(exit_codes.SCHEMA)


@merkle_app.command("verify")
def merkle_verify(companion: Path, as_json: JsonFlag = False) -> None:
    """Recompute the Merkle root of a companion document (disclosed leaves + redacted leaf hashes) and compare."""
    from symbiote.export.companion import load_companion
    from symbiote.snapshot import verify_document

    bom = load_companion(companion)
    ok = verify_document(bom)
    emit(
        {
            "file": str(companion),
            "root": bom.snapshot.digest,
            "verified": ok,
            "redactedLeaves": sum(
                1 for leaf in (bom.merkle.leaves if bom.merkle else []) if leaf.salt is None
            ),
        },
        as_json,
        ("[green]verified[/green] " if ok else "[red]MISMATCH[/red] ") + bom.snapshot.digest,
    )
    if not ok:
        raise typer.Exit(exit_codes.VERIFICATION)


@attest_app.command("snapshot")
def attest_snapshot(
    companion: Path,
    key: Annotated[Path, typer.Option("--key", help="PEM private key (ECDSA P-256 or Ed25519).")],
    out: Annotated[Path, typer.Option("-o", "--out")] = Path("snapshot.dsse.json"),
    as_json: JsonFlag = False,
) -> None:
    """Sign an agentbom-snapshot/v1 statement over a finalised companion document (key-based DSSE)."""
    from symbiote.attest import PAYLOAD_TYPE, load_private_key, sign_envelope, snapshot_statement
    from symbiote.attest.statements import statement_bytes
    from symbiote.digest import bytes_digest
    from symbiote.export.companion import load_companion

    raw = companion.read_bytes()
    bom = load_companion(raw)
    stmt = snapshot_statement(bom, companion_digest=bytes_digest(raw))
    env = sign_envelope(statement_bytes(stmt), PAYLOAD_TYPE, load_private_key(key))
    out.write_text(json.dumps(env.to_json(), indent=2) + "\n", encoding="utf-8")
    emit(
        {
            "out": str(out),
            "predicateType": stmt["predicateType"],
            "subjects": stmt["subject"],
            "signatures": [s.keyid for s in env.signatures],
        },
        as_json,
        f"signed {stmt['predicateType']} -> {out}",
    )


@app.command()
def verify(
    envelope: Path,
    public_key: Annotated[list[Path], typer.Option("--public-key", help="Trusted PEM public key(s).")],
    companion: Annotated[
        Path | None, typer.Option(help="Companion document the statement must bind to.")
    ] = None,
    as_json: JsonFlag = False,
) -> None:
    """Verify a key-based DSSE envelope and, when given, its binding to a companion document."""
    from cryptography.exceptions import InvalidSignature

    from symbiote.attest import Envelope, KeyRing, load_public_key, verify_envelope
    from symbiote.digest import bytes_digest
    from symbiote.snapshot import verify_document

    env = Envelope.model_validate(json.loads(envelope.read_text(encoding="utf-8")))
    ring = KeyRing.from_public_keys([load_public_key(p) for p in public_key])
    result: dict[str, Any] = {"envelope": str(envelope), "outcome": "failed", "bindings": [], "warnings": []}
    try:
        payload, accepted = verify_envelope(env, ring)
    except InvalidSignature as exc:
        result["reason"] = str(exc)
        emit(result, as_json, f"[red]signature failed[/red]: {exc}")
        raise typer.Exit(exit_codes.VERIFICATION) from None
    stmt = json.loads(payload)
    result["predicateType"] = stmt.get("predicateType")
    result["acceptedKeyIds"] = accepted
    ok = True
    if companion is not None:
        from symbiote.export.companion import load_companion

        raw = companion.read_bytes()
        bom = load_companion(raw)
        subjects = {s["name"]: s["digest"]["sha256"] for s in stmt.get("subject", [])}
        root_ok = subjects.get(f"snapshot:{bom.subject}") == bom.snapshot.digest.split(":", 1)[1]
        companion_ok = subjects.get("companion") in (None, bytes_digest(raw).split(":", 1)[1])
        merkle_ok = verify_document(bom)
        result["bindings"] = [
            {"subject": "snapshot", "ok": root_ok},
            {"subject": "companion", "ok": companion_ok},
            {"subject": "merkle", "ok": merkle_ok},
        ]
        ok = root_ok and companion_ok and merkle_ok
    result["outcome"] = "verified-constrained" if ok else "digest-mismatch"
    emit(
        result,
        as_json,
        ("[green]verified[/green] " if ok else "[red]digest mismatch[/red] ")
        + f"{result['predicateType']} by {', '.join(k[:12] for k in accepted)}",
    )
    if not ok:
        raise typer.Exit(exit_codes.VERIFICATION)


def main() -> None:
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
