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
allowlist_app = typer.Typer(help="Enforcement exports for tool gateways and policy engines.")
app.add_typer(schema_app, name="schema")
app.add_typer(allowlist_app, name="allowlist")
app.add_typer(digest_app, name="digest")
app.add_typer(merkle_app, name="merkle")
app.add_typer(attest_app, name="attest")
policy_app = typer.Typer(help="Built-in policy checks (SYM-*), SARIF output and check documentation.")
app.add_typer(policy_app, name="policy")

console = Console(stderr=True)
JsonFlag = Annotated[bool, typer.Option("--json", help="Machine-readable JSON on stdout.")]


def load_companion_or_exit(path: Path) -> Any:
    """Load a companion document, mapping failures to the stable exit codes (6 = I/O, 3 = schema)."""
    from symbiote.export.companion import CompanionValidationError, load_companion

    try:
        return load_companion(path)
    except FileNotFoundError:
        console.print(
            f"[red]{path}: not found[/red] (run `symbiote scan` first or pass a companion document)"
        )
        raise typer.Exit(exit_codes.IO) from None
    except CompanionValidationError as exc:
        console.print(f"[red]{path} is not a valid AgentBOM companion document[/red]: {exc}")
        raise typer.Exit(exit_codes.SCHEMA) from None
    except OSError as exc:
        console.print(f"[red]{path}[/red]: {exc.strerror or exc}")
        raise typer.Exit(exit_codes.IO) from None
    except ValueError as exc:  # JSON syntax, encoding and model validation errors
        console.print(f"[red]{path} is not a valid AgentBOM companion document[/red]: {str(exc)[:500]}")
        raise typer.Exit(exit_codes.SCHEMA) from None


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
def scan(
    path: Annotated[Path, typer.Argument(help="Repository or agent directory to scan.")] = Path("."),
    out: Annotated[Path, typer.Option("-o", "--out", help="Output directory.")] = Path("."),
    name: Annotated[
        str | None,
        typer.Option(
            "--name", help="Agent name (defaults to symbiote.yaml/agent.yaml or the directory name)."
        ),
    ] = None,
    fmt: Annotated[str, typer.Option("--format", help="companion | cyclonedx | spdx | all")] = "all",
    include_text: Annotated[
        bool,
        typer.Option("--include-text", help="Embed tool descriptions and schemas (digests only by default)."),
    ] = False,
    deterministic: Annotated[
        bool,
        typer.Option(
            "--deterministic", help="Pin timestamps and the Merkle nonce for byte-identical output."
        ),
    ] = False,
    user_scope: Annotated[
        bool,
        typer.Option(
            "--user-scope", help="Also read user-scope client configuration from the home directory."
        ),
    ] = False,
    store: Annotated[
        Path | None,
        typer.Option(
            "--store", help="Chain store directory: allocate serial/prev and enforce anti-rollback."
        ),
    ] = None,
    no_policy: Annotated[
        bool,
        typer.Option(
            "--no-policy", help="Skip the built-in policy checks (derived flags/findings stay empty)."
        ),
    ] = False,
    as_json: JsonFlag = False,
) -> None:
    """Zero-config collection: produce a declared AgentBOM snapshot (companion, CycloneDX 1.7, SPDX 3.0.1) from a repository."""
    from symbiote.digest import bytes_digest
    from symbiote.export.companion import companion_bytes
    from symbiote.scan import scan as run_scan
    from symbiote.snapshot.state import ChainConflictError

    if fmt not in ("companion", "cyclonedx", "spdx", "all"):
        console.print(f"[red]unknown format {fmt!r}[/red]")
        raise typer.Exit(exit_codes.USAGE)
    try:
        outcome = run_scan(
            path,
            agent_name=name,
            home=Path.home() if user_scope else None,
            deterministic=deterministic,
            include_text=include_text,
            policy=not no_policy,
            store=store,
        )
    except ChainConflictError as exc:
        console.print(f"[red]anti-rollback conflict[/red]: {exc}")
        raise typer.Exit(exit_codes.ROLLBACK) from None
    bom = outcome.bom
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    companion = companion_bytes(bom)
    companion_path = out / "agentbom.json"
    companion_path.write_bytes(companion)
    written["companion"] = str(companion_path)
    companion_digest = bytes_digest(companion)
    errors: dict[str, list[str]] = {}
    if fmt in ("cyclonedx", "all"):
        from symbiote.export.cdx import export_cyclonedx, validate_cyclonedx

        doc, loss = export_cyclonedx(
            bom,
            include_text=include_text,
            companion_digest=companion_digest,
            companion_ref=companion_path.name,
        )
        errors["cyclonedx"] = validate_cyclonedx(doc)
        (out / "agentbom.cdx.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        (out / "agentbom.cdx.loss.json").write_text(
            json.dumps(loss.to_json_dict(), indent=2) + "\n", encoding="utf-8"
        )
        written["cyclonedx"] = str(out / "agentbom.cdx.json")
    if fmt in ("spdx", "all"):
        from symbiote.export.spdx import export_spdx, validate_spdx

        sdoc, sloss = export_spdx(
            bom,
            include_text=include_text,
            companion_digest=companion_digest,
            companion_ref=companion_path.name,
        )
        errors["spdx"] = validate_spdx(sdoc)
        (out / "agentbom.spdx.json").write_text(json.dumps(sdoc, indent=2) + "\n", encoding="utf-8")
        (out / "agentbom.spdx.loss.json").write_text(
            json.dumps(sloss.to_json_dict(), indent=2) + "\n", encoding="utf-8"
        )
        written["spdx"] = str(out / "agentbom.spdx.json")
    coverage = {s.value: c.status.value for s, c in bom.coverage.surfaces.items()}
    summary = {
        "agent": bom.subject,
        "snapshot": bom.snapshot.digest,
        "serial": bom.snapshot.serial,
        "kind": bom.snapshot.kind.value,
        "entities": outcome.counts,
        "edges": len(bom.edges),
        "coverage": coverage,
        "collectors": [c.to_json_dict() for c in bom.coverage.collectors],
        "warnings": outcome.warnings,
        "written": written,
        "cyclonedxValid": not errors.get("cyclonedx"),
        "cyclonedxErrors": errors.get("cyclonedx", [])[:20],
        "spdxValid": not errors.get("spdx"),
        "spdxErrors": errors.get("spdx", [])[:20],
        "findings": outcome.policy.counts() if outcome.policy else None,
        "flags": {f.flag.value: f.value.value for f in bom.derived.flags if f.value.value != "false"},
        "chainIssues": [
            {"check": i.check_id, "severity": i.severity.value, "message": i.message}
            for i in outcome.chain_issues
        ],
    }
    lines = [
        f"[bold]{bom.subject}[/bold]  snapshot {bom.snapshot.digest[:23]}…  ({bom.snapshot.kind.value}, serial {bom.snapshot.serial})",
        "entities: " + ", ".join(f"{k}={v}" for k, v in outcome.counts.items()),
        "coverage: "
        + ", ".join(f"{k}={v}" for k, v in coverage.items() if v != "not-attempted")
        + "  (other surfaces: not-attempted)",
        "collectors: " + ", ".join(f"{c.name}:{c.status.value}" for c in bom.coverage.collectors),
        *(f"[yellow]warning[/yellow] {w}" for w in outcome.warnings[:10]),
        *(f"written: {v}" for v in written.values()),
    ]
    if outcome.policy:
        fails = [f for f in outcome.policy.findings if f.state.value == "fail"]
        indet = [f for f in outcome.policy.findings if f.state.value == "indeterminate"]
        lines.append(
            f"policy: {len(fails)} failing finding(s), {len(indet)} indeterminate — run `symbiote policy check {companion_path}` for details"
        )
        for f in fails[:8]:
            lines.append(
                f"  [red]{f.severity.value:8s}[/red] {f.check_id}  {', '.join(f.subject_refs[:2])}  {f.message[:90]}"
            )
    for i in outcome.chain_issues:
        lines.append(f"[yellow]{i.check_id}[/yellow] {i.message}")
    for label, key in (("CycloneDX 1.7", "cyclonedx"), ("SPDX 3.0.1", "spdx")):
        if key in errors:
            lines.append(
                f"[green]{label} validates against the official schema[/green]"
                if not errors[key]
                else f"[red]{label} validation errors[/red]: " + "; ".join(errors[key][:3])
            )
    emit(summary, as_json, "\n".join(lines))
    if any(errors.values()):
        raise typer.Exit(exit_codes.SCHEMA)


@app.command()
def validate(files: list[Path], as_json: JsonFlag = False) -> None:
    """Validate companion documents (AgentBOM schema) and CycloneDX 1.6/1.7 documents (official schemas)."""
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
        if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
            from symbiote.export.cdx import validate_cyclonedx

            errors = validate_cyclonedx(data)
            fmt = f"cyclonedx-{data.get('specVersion')}"
        elif isinstance(data, dict) and data.get("specVersion") and "snapshot" in data:
            errors = validate_companion(data)
            fmt = "agentbom-companion"
        elif isinstance(data, dict) and "@context" in data and "spdx" in str(data.get("@context")):
            from symbiote.export.spdx import validate_spdx

            errors = validate_spdx(data)
            fmt = "spdx-3.0.1"
        else:
            errors = ["not a companion, CycloneDX or SPDX 3 document"]
            fmt = "unknown"
        results.append({"file": str(f), "format": fmt, "ok": not errors, "errors": errors[:50]})
        failed |= bool(errors)
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
    key: Annotated[
        Path | None,
        typer.Option("--key", help="PEM private key (ECDSA P-256 or Ed25519) for key-based DSSE."),
    ] = None,
    keyless: Annotated[
        bool, typer.Option("--keyless", help="Sign with Sigstore (OIDC identity); writes a Sigstore bundle.")
    ] = False,
    staging: Annotated[bool, typer.Option("--staging", help="Use the Sigstore staging instance.")] = False,
    identity_token: Annotated[
        str | None, typer.Option("--identity-token", help="OIDC identity token for keyless signing.")
    ] = None,
    issuer_url: Annotated[
        str | None, typer.Option("--issuer-url", help="OIDC issuer to obtain a token from interactively.")
    ] = None,
    out: Annotated[Path | None, typer.Option("-o", "--out")] = None,
    as_json: JsonFlag = False,
) -> None:
    """Sign an agentbom-snapshot/v1 statement over a finalised companion document (key-based DSSE or Sigstore keyless)."""
    from symbiote.attest import PAYLOAD_TYPE, load_private_key, sign_envelope, snapshot_statement
    from symbiote.attest.statements import statement_bytes
    from symbiote.digest import bytes_digest
    from symbiote.export.companion import load_companion

    raw = companion.read_bytes()
    bom = load_companion(raw)
    stmt = snapshot_statement(bom, companion_digest=bytes_digest(raw))
    if keyless:
        from symbiote.attest.sigstore_backend import sign_keyless

        bundle = sign_keyless(stmt, staging=staging, identity_token=identity_token, issuer_url=issuer_url)
        out = out or Path("snapshot.sigstore.json")
        out.write_text(bundle.to_json() + "\n", encoding="utf-8")
        emit(
            {
                "out": str(out),
                "predicateType": stmt["predicateType"],
                "subjects": stmt["subject"],
                "mode": "sigstore-keyless",
            },
            as_json,
            f"signed {stmt['predicateType']} (Sigstore) -> {out}",
        )
        return
    if key is None:
        console.print("[red]pass --key for key-based signing or --keyless for Sigstore[/red]")
        raise typer.Exit(exit_codes.USAGE)
    env = sign_envelope(statement_bytes(stmt), PAYLOAD_TYPE, load_private_key(key))
    out = out or Path("snapshot.dsse.json")
    out.write_text(json.dumps(env.to_json(), indent=2) + "\n", encoding="utf-8")
    emit(
        {
            "out": str(out),
            "predicateType": stmt["predicateType"],
            "subjects": stmt["subject"],
            "signatures": [s.keyid for s in env.signatures],
            "mode": "key-based",
        },
        as_json,
        f"signed {stmt['predicateType']} -> {out}",
    )


def _check_bindings(stmt: dict[str, Any], companion: Path) -> tuple[bool, list[dict[str, Any]]]:
    from symbiote.digest import bytes_digest
    from symbiote.export.companion import load_companion
    from symbiote.snapshot import verify_document

    raw = companion.read_bytes()
    bom = load_companion(raw)
    subjects = {s["name"]: s["digest"]["sha256"] for s in stmt.get("subject", [])}
    root_ok = subjects.get(f"snapshot:{bom.subject}") == bom.snapshot.digest.split(":", 1)[1]
    companion_ok = subjects.get("companion") in (None, bytes_digest(raw).split(":", 1)[1])
    merkle_ok = verify_document(bom)
    return root_ok and companion_ok and merkle_ok, [
        {"subject": "snapshot", "ok": root_ok},
        {"subject": "companion", "ok": companion_ok},
        {"subject": "merkle", "ok": merkle_ok},
    ]


@app.command()
def verify(
    envelope: Path,
    public_key: Annotated[
        list[Path] | None,
        typer.Option("--public-key", help="Trusted PEM public key(s) for key-based DSSE envelopes."),
    ] = None,
    policy: Annotated[
        Path | None,
        typer.Option(
            "--policy", help="YAML verification policy (identities, issuer, staging) for Sigstore bundles."
        ),
    ] = None,
    companion: Annotated[
        Path | None, typer.Option(help="Companion document the statement must bind to.")
    ] = None,
    insecure_unconstrained: Annotated[
        bool,
        typer.Option(
            "--insecure-unconstrained",
            help="Accept a Sigstore signature without identity constraints (outcome: signature-valid-unconstrained).",
        ),
    ] = False,
    store: Annotated[
        Path | None,
        typer.Option(
            "--store", help="Chain store directory for anti-rollback checks of the companion's snapshot."
        ),
    ] = None,
    as_json: JsonFlag = False,
) -> None:
    """Verify a DSSE envelope (key-based) or a Sigstore bundle (keyless) and its binding to a companion document."""
    result: dict[str, Any] = {"envelope": str(envelope), "outcome": "failed", "bindings": [], "warnings": []}
    stmt: dict[str, Any] | None = None
    if policy is not None:
        from symbiote.attest.sigstore_backend import VerifyPolicySpec, verify_bundle
        from symbiote.model.enums import SignatureOutcome

        spec = VerifyPolicySpec.from_yaml(policy)
        if insecure_unconstrained:
            spec = spec.replace(insecure_unconstrained=True)
        res = verify_bundle(envelope, spec)
        result.update(
            {
                "outcome": res.outcome.value,
                "identity": res.identity,
                "issuer": res.issuer,
                "logIndex": res.log_index,
                "reason": res.reason,
            }
        )
        if res.outcome not in (SignatureOutcome.VERIFIED, SignatureOutcome.SIGNATURE_VALID_UNCONSTRAINED):
            emit(result, as_json, f"[red]{res.outcome.value}[/red]: {res.reason}")
            raise typer.Exit(exit_codes.VERIFICATION)
        if res.outcome is SignatureOutcome.SIGNATURE_VALID_UNCONSTRAINED:
            result["warnings"].append("SYM-ATT-001 signature-valid-unconstrained: assurance stays observed")
        stmt = res.statement
    elif public_key:
        from cryptography.exceptions import InvalidSignature

        from symbiote.attest import Envelope, KeyRing, load_public_key, verify_envelope

        env = Envelope.model_validate(json.loads(envelope.read_text(encoding="utf-8")))
        ring = KeyRing.from_public_keys([load_public_key(p) for p in public_key])
        try:
            payload, accepted = verify_envelope(env, ring)
        except InvalidSignature as exc:
            result["reason"] = str(exc)
            emit(result, as_json, f"[red]signature failed[/red]: {exc}")
            raise typer.Exit(exit_codes.VERIFICATION) from None
        stmt = json.loads(payload)
        result["acceptedKeyIds"] = accepted
        result["outcome"] = "verified-constrained"
    else:
        console.print("[red]pass --public-key (key-based) or --policy (Sigstore)[/red]")
        raise typer.Exit(exit_codes.USAGE)
    assert stmt is not None
    result["predicateType"] = stmt.get("predicateType")
    ok = True
    rollback = False
    if companion is not None:
        ok, result["bindings"] = _check_bindings(stmt, companion)
        if not ok:
            result["outcome"] = "digest-mismatch"
        if store is not None:
            from symbiote.export.companion import load_companion
            from symbiote.snapshot.state import ChainStore

            issues = ChainStore(store).check(load_companion(companion).snapshot)
            result["chainIssues"] = [
                {"check": i.check_id, "severity": i.severity.value, "message": i.message} for i in issues
            ]
            rollback = any(i.check_id == "SYM-SNAP-001" for i in issues)
    emit(
        result,
        as_json,
        ("[green]" + result["outcome"] + "[/green] " if ok else "[red]digest mismatch[/red] ")
        + str(result["predicateType"])
        + ("  [red]SERIAL REGRESSION[/red]" if rollback else ""),
    )
    if rollback:
        raise typer.Exit(exit_codes.ROLLBACK)
    if not ok:
        raise typer.Exit(exit_codes.VERIFICATION)


@allowlist_app.command("export")
def allowlist_export(
    companion: Path,
    fmt: Annotated[str, typer.Option("--format", help="gab | opa-data | mcp-gateway-generic")] = "gab",
    out: Annotated[Path | None, typer.Option("-o", "--out")] = None,
    attestation: Annotated[
        list[str] | None,
        typer.Option("--attestation", help="Attestation file names to reference from the bundle."),
    ] = None,
) -> None:
    """Export a Gateway Allowlist Bundle (or OPA data / generic name-digest pairs) from a companion document."""
    from symbiote.enforce import export_allowlist
    from symbiote.export.companion import load_companion

    bom = load_companion(companion)
    if fmt not in ("gab", "opa-data", "mcp-gateway-generic"):
        console.print(f"[red]unknown format {fmt!r}[/red]")
        raise typer.Exit(exit_codes.USAGE)
    data = export_allowlist(bom, fmt, attestations=attestation or [])  # type: ignore[arg-type]
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if out:
        out.write_text(text, encoding="utf-8")
        console.print(f"wrote {out} ({fmt})")
    else:
        sys.stdout.write(text)


@allowlist_app.command("check")
def allowlist_check(
    gab: Path,
    server: str,
    tools_json: Annotated[
        Path,
        typer.Argument(help="JSON array of raw served tool definitions (a tools/list result's 'tools')."),
    ],
    as_json: JsonFlag = False,
) -> None:
    """Reference enforcement: decide allow/block/drop for served tools against a GAB."""
    from symbiote.enforce import check_served_toolset

    bundle = json.loads(gab.read_text(encoding="utf-8"))
    served = json.loads(tools_json.read_text(encoding="utf-8"))
    if isinstance(served, dict) and "tools" in served:
        served = served["tools"]
    decisions = check_served_toolset(bundle, server, served)
    emit(
        [d.to_json_dict() for d in decisions],
        as_json,
        "\n".join(f"{d.action:5s} {d.tool or '-':30s} {d.reason}" for d in decisions),
    )
    if any(d.action != "allow" for d in decisions):
        raise typer.Exit(exit_codes.FINDINGS)


@policy_app.command("check")
def policy_check(
    companion: Path,
    fail_on: Annotated[str, typer.Option("--fail-on", help="critical | high | medium | low | info")] = "high",
    select: Annotated[
        list[str] | None, typer.Option("--select", help="Check id glob(s) to run, e.g. SYM-MCP-*")
    ] = None,
    exclude: Annotated[list[str] | None, typer.Option("--exclude", help="Check id glob(s) to skip")] = None,
    baseline: Annotated[
        Path | None,
        typer.Option(
            "--baseline",
            help="Approved/declared companion to compare against (undeclared-component findings)",
        ),
    ] = None,
    sarif: Annotated[Path | None, typer.Option("--sarif", help="Write SARIF 2.1.0 to this file")] = None,
    rego: Annotated[
        Path | None,
        typer.Option(
            "--rego",
            help="Also evaluate data.agentbom.findings from the Rego policies in this directory (needs `opa`)",
        ),
    ] = None,
    fail_on_indeterminate: Annotated[
        bool, typer.Option("--fail-on-indeterminate", help="Treat indeterminate findings as failures")
    ] = False,
    as_json: JsonFlag = False,
) -> None:
    """Run the built-in SYM-* checks over a companion document (spec/checks.md)."""
    import dataclasses

    from symbiote.model.enums import Severity
    from symbiote.policy import run_policy, to_sarif
    from symbiote.policy.rego import RegoError, evaluate_with_opa

    try:
        threshold = Severity(fail_on.lower())
    except ValueError:
        console.print("[red]--fail-on must be one of critical, high, medium, low, info[/red]")
        raise typer.Exit(exit_codes.USAGE) from None
    bom = load_companion_or_exit(companion)
    base = load_companion_or_exit(baseline) if baseline else None
    result = run_policy(bom, select=select, exclude=exclude or (), baseline=base)
    if rego is not None:
        try:
            extra, warnings = evaluate_with_opa(bom, rego)
        except RegoError as exc:
            console.print(f"[red]--rego[/red]: {exc}")
            raise typer.Exit(exit_codes.IO) from None
        seen = {(f.check_id, tuple(sorted(f.subject_refs))) for f in result.findings}
        merged = tuple(f for f in extra if (f.check_id, tuple(sorted(f.subject_refs))) not in seen)
        result = dataclasses.replace(
            result, findings=result.findings + merged, errors=result.errors + tuple(warnings)
        )
    if sarif:
        sarif.write_text(
            json.dumps(to_sarif(result.findings, artifact_root=str(companion.parent)), indent=2) + "\n",
            encoding="utf-8",
        )
    data = {
        "companion": str(companion),
        "checksRun": list(result.checks_run),
        "counts": result.counts(),
        "findings": [f.to_json_dict() for f in result.findings],
        "flags": [f.to_json_dict() for f in result.flags],
        "errors": list(result.errors),
        "sarif": str(sarif) if sarif else None,
    }
    lines = [
        f"{len(result.findings)} finding(s) from {len(result.checks_run)} checks; flags: "
        + ", ".join(f"{f.flag.value}={f.value.value}" for f in result.flags if f.value.value != "false")
    ]
    for f in result.findings:
        colour = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan", "info": "white"}[
            f.severity.value
        ]
        lines.append(
            f"[{colour}]{f.severity.value:8s}[/{colour}] {f.state.value:13s} {f.check_id:14s} {', '.join(f.subject_refs[:2])}\n           {f.message[:160]}"
        )
    emit(data, as_json, "\n".join(lines))
    if result.exit_code(threshold, include_indeterminate=fail_on_indeterminate):
        raise typer.Exit(exit_codes.FINDINGS)


@policy_app.command("list")
def policy_list(as_json: JsonFlag = False) -> None:
    """List the built-in checks (``rego`` marks the ones `policy export-rego` exports)."""
    from symbiote.policy import REGO_RULES, list_checks

    rows = []
    for c in list_checks():
        sev = getattr(c, "severity", None)
        rows.append(
            {
                "id": c.id,
                "severity": sev.value if sev is not None else None,
                "title": getattr(c, "title", ""),
                "rego": c.id in REGO_RULES,
            }
        )
    emit(
        rows,
        as_json,
        "\n".join(
            f"{r['id']:14s} {r['severity'] or ''!s:8s} {'rego' if r['rego'] else '    '} {r['title']}"
            for r in rows
        ),
    )


@policy_app.command("explain")
def policy_explain(check_id: str, as_json: JsonFlag = False) -> None:
    """Explain one check: inputs, logic, threat mappings."""
    from symbiote.policy import CHECKS, explain

    if check_id.upper() not in CHECKS:
        console.print(f"[red]unknown check {check_id!r}[/red]; `symbiote policy list` shows every id")
        raise typer.Exit(exit_codes.USAGE)
    info = explain(check_id.upper())
    emit(info, as_json, json.dumps(info, indent=2, default=str))


@policy_app.command("export-rego")
def policy_export_rego(
    directory: Annotated[Path, typer.Argument(help="Output directory for agentbom.rego and manifest.json")],
    as_json: JsonFlag = False,
) -> None:
    """Write `package agentbom` (Rego v1) for OPA, Conftest or a gateway, plus a manifest of what it covers."""
    from symbiote.policy import CHECKS, REGO_RULES, export_rego
    from symbiote.policy.rego import QUERY

    try:
        manifest = export_rego(directory)
    except OSError as exc:
        console.print(f"[red]{directory}[/red]: {exc.strerror or exc}")
        raise typer.Exit(exit_codes.IO) from None
    emit(
        {**manifest, "directory": str(directory)},
        as_json,
        f"wrote {directory / 'agentbom.rego'} and {directory / 'manifest.json'}: {len(REGO_RULES)} checks in Rego, "
        f"{len(set(CHECKS) - set(REGO_RULES))} built-in only (run `symbiote policy check` for those)\n"
        f"OPA:      opa eval -d {directory} -i agentbom.json {QUERY}\n"
        f"Conftest: conftest test --policy {directory} --namespace agentbom agentbom.json",
    )


@app.command()
def conformance(
    companion: Path,
    level: Annotated[str, typer.Option("--level", help="minimal | standard | verified")] = "minimal",
    as_json: JsonFlag = False,
) -> None:
    """Evaluate AgentBOM conformance requirements (spec/conformance.md) up to the requested level."""
    from symbiote.policy import evaluate_conformance

    if level not in ("minimal", "standard", "verified"):
        console.print("[red]level must be minimal, standard or verified[/red]")
        raise typer.Exit(exit_codes.USAGE)
    report = evaluate_conformance(load_companion_or_exit(companion), level)  # type: ignore[arg-type]
    data = report.to_json()
    lines = [
        f"requested {report.requested}; attained {report.attained or 'none'} — {'PASS' if report.passed else 'NOT ATTAINED'}",
        data["note"],
    ]
    for r in report.requirements:
        mark = {
            "pass": "[green]pass[/green]",
            "fail": "[red]fail[/red]",
            "unknown": "[yellow]unknown[/yellow]",
        }.get(r.status, r.status)
        lines.append(
            f"{mark:22s} {r.id:10s} {r.title}" + ("" if not r.reasons else "  — " + "; ".join(r.reasons[:2]))
        )
    emit(data, as_json, "\n".join(lines))
    if not report.passed:
        statuses = {r.status for r in report.requirements}
        raise typer.Exit(exit_codes.FINDINGS if "fail" in statuses else exit_codes.COVERAGE)


@app.command()
def score(companion: Path, as_json: JsonFlag = False) -> None:
    """Completeness score (a BOM-quality number, never a trust score) with per-area reasons."""
    from symbiote.policy import completeness_score

    report = completeness_score(load_companion_or_exit(companion))
    data = report.to_json()
    lines = [
        f"completeness {report.score}/100 — {data['note']}",
        "assurance: " + ", ".join(f"{k}={v:.0%}" for k, v in report.assurance.items()),
    ]
    for a in report.areas:
        lines.append(
            f"{a.area:14s} {a.present}/{a.total} (weight {a.weight})"
            + ("" if not a.missing else "  missing: " + ", ".join(a.missing[:4]))
        )
    emit(data, as_json, "\n".join(lines))


@app.command()
def diff(
    before: Path,
    after: Path,
    fail_on_change: Annotated[
        list[str] | None,
        typer.Option(
            "--fail-on-change",
            help="Delta event type(s) that make the command exit 1, e.g. tool-definition-changed",
        ),
    ] = None,
    out: Annotated[Path | None, typer.Option("-o", "--out", help="Write the Delta JSON here")] = None,
    as_json: JsonFlag = False,
) -> None:
    """Typed delta between two companion documents of any snapshot kinds — the diff is the finding."""
    from symbiote.export.companion import load_companion
    from symbiote.snapshot import diff as snapshot_diff

    a, b = load_companion(before), load_companion(after)
    delta = snapshot_diff(a, b)
    data = delta.to_json_dict()
    if out:
        out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    lines = [
        f"{len(delta.events)} event(s): {a.snapshot.digest[:19]}… ({a.snapshot.kind.value}) -> {b.snapshot.digest[:19]}… ({b.snapshot.kind.value})"
    ]
    for e in delta.events:
        lines.append(
            f"[yellow]{e.severity_hint.value:8s}[/yellow] {e.type.value:28s} {e.subject_ref}"
            + (f"  {e.detail[:80]}" if e.detail else "")
        )
    emit(data, as_json, "\n".join(lines))
    wanted = set(fail_on_change or [])
    if wanted and any(e.type.value in wanted for e in delta.events):
        raise typer.Exit(exit_codes.FINDINGS)


def main() -> None:
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
