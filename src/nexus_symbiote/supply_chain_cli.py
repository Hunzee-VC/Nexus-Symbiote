"""Explicit supply-chain reports and reviewed-baseline operations."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import click

from nexus_symbiote import exits
from nexus_symbiote.cli_common import load_bom, require_live
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.utils.files import write_output_file

RECORDED_MAX_BYTES = 16 * 1024 * 1024


def _read_json(path: Path, maximum: int) -> Any:
    from nexus_symbiote.core.hashing import open_regular_file, parse_json_strict

    with open_regular_file(path) as stream:
        return parse_json_strict(stream.read(maximum + 1), max_bytes=maximum)


def register_supply_chain_commands(main: click.Group) -> None:
    @main.command("verify-live")
    @click.argument("aibom_path", type=click.Path(exists=True))
    @click.option("--project", type=click.Path(exists=True), default=".")
    @click.option(
        "--launch-policy",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="Live: operator-owned JSON outside the project mapping exact server references to absolute commands and SHA-256 pins.",
    )
    @click.option(
        "--input",
        "input_path",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="Offline: compare descriptors recorded by --save-descriptors instead of launching servers.",
    )
    @click.option(
        "--save-descriptors",
        type=click.Path(path_type=Path),
        help="Live: also write the observed descriptors for a later offline --input comparison.",
    )
    @click.option("--json-output", is_flag=True)
    @click.option("--record", is_flag=True)
    def verify_live(
        aibom_path: str,
        project: str,
        launch_policy: Path | None,
        input_path: Path | None,
        save_descriptors: Path | None,
        json_output: bool,
        record: bool,
    ) -> None:
        """Compare served MCP tool descriptors with the inventory; optionally emit an unsigned candidate.

        Live (needs --live): starts private copies of independently pinned stdio
        launchers. The operator provisions the launch policy outside the untrusted
        checkout; pins cover launcher bytes, so use an externally isolated worker
        to restrict host dependencies, filesystem, identity and egress. Offline:
        --input compares a recorded export and launches nothing. Descriptor
        matches do not establish safety.
        """
        from nexus_symbiote.live.verify import (
            parse_recorded,
            record_candidate,
            recorded_descriptors,
            verify_mcp_servers,
        )

        if record and json_output:
            raise click.UsageError("choose a candidate BOM or a JSON verification report")
        if input_path is not None:
            if launch_policy is not None or save_descriptors is not None:
                raise click.UsageError(
                    "--launch-policy and --save-descriptors apply to live verification, not --input"
                )
            try:
                recorded = parse_recorded(_read_json(input_path, RECORDED_MAX_BYTES))
                bom = AIBOM.model_validate(_read_json(Path(aibom_path), 16 * 1024 * 1024))
            except (OSError, ValueError, TypeError, RecursionError) as exc:
                raise click.ClickException(f"invalid BOM or recorded descriptors: {exc}") from None
            report = verify_mcp_servers(bom, recorded=recorded)
        else:
            require_live("verify-live", "starts operator-pinned launchers", replay="--input")
            if launch_policy is None:
                raise click.UsageError(
                    "live verification needs --launch-policy; use --input for recorded descriptors"
                )
            if launch_policy.resolve().is_relative_to(Path(project).resolve()):
                raise click.UsageError(
                    "launch policy must be provisioned outside the untrusted project"
                )
            try:
                policy = _read_json(launch_policy, 4 * 1024 * 1024)
                if not isinstance(policy, dict):
                    raise ValueError("launch policy must be an object")
                bom = AIBOM.model_validate(_read_json(Path(aibom_path), 16 * 1024 * 1024))
            except (OSError, ValueError, TypeError, RecursionError):
                raise click.ClickException("invalid BOM or operator launch policy") from None
            report = verify_mcp_servers(bom, trusted_launchers=policy)
            if save_descriptors is not None:
                write_output_file(
                    save_descriptors, json.dumps(recorded_descriptors(report), indent=2) + "\n"
                )
        if record:
            try:
                record_candidate(bom, report, observed=input_path is None)
            except ValueError:
                raise exits.Incomplete("incomplete inventory; candidate not emitted") from None
            click.echo(bom.to_json())
            return
        if json_output:
            payload = report.to_dict()
            payload["collection_mode"] = "offline" if input_path is not None else "live"
            click.echo(json.dumps(payload, indent=2))
        else:
            source = (
                "Recorded descriptor comparison" if input_path else "Live descriptor observation"
            )
            click.echo(
                f"{source}: {report.servers_reachable}/{report.servers_checked} servers; "
                f"complete={report.complete}; drift={report.has_drift}"
            )
        if not report.complete:
            raise click.exceptions.Exit(exits.INCOMPLETE)
        if report.has_drift:
            raise click.exceptions.Exit(exits.GATE)

    @main.command()
    @click.argument("project_path", type=click.Path(exists=True), default=".")
    @click.option(
        "-o",
        "--baseline-path",
        type=click.Path(path_type=Path),
        default=".nexus-symbiote-baseline.json",
    )
    @click.pass_context
    def baseline(ctx: click.Context, project_path: str, baseline_path: Path) -> None:
        """Stage a static snapshot for review; publish it only after the scan gate passes.

        The file is unsigned. Operators must review and authenticate the baseline
        before using it as an authority for runtime admission.
        """
        from nexus_symbiote.cli import scan
        from nexus_symbiote.validators.risk import RiskScorer

        target = baseline_path.absolute()
        fd, temporary = tempfile.mkstemp(prefix=".nexus-baseline-", dir=target.parent)
        os.close(fd)
        staged = Path(temporary)
        try:
            ctx.invoke(
                scan,
                project_path=project_path,
                output=str(staged),
                output_format="json",
                scanners=(),
                report_only=False,
                signature_policy=None,
            )
            # A project policy may select report-only mode; it cannot authorize
            # promotion of incomplete evidence into an approved baseline.
            snapshot = AIBOM.load(staged)
            claim = snapshot.metadata.completeness
            if claim is not None and claim.scan_failures:
                raise exits.Incomplete("Baseline was not written: collection was incomplete")
            passed, _ = RiskScorer().passes_gate(snapshot)
            if not passed:
                raise exits.GateFailed("Baseline was not written: static scan gate failed")
            write_output_file(target, staged.read_text(encoding="utf-8"))
        finally:
            staged.unlink(missing_ok=True)
        click.echo(f"Unsigned baseline staged for review: {target}")

    @main.command()
    @click.argument("aibom_path", type=click.Path(exists=True, path_type=Path))
    @click.option("-o", "--output", type=click.Path(path_type=Path))
    def vex(aibom_path: Path, output: Path | None) -> None:
        """Export schema-validated findings in triage, without asserting exploitability."""
        from nexus_symbiote.generators.vex import VEXGenerator

        if output and output.resolve() == aibom_path.resolve():
            raise click.BadParameter("output must not overwrite the source inventory")
        bom = load_bom(aibom_path)
        try:
            text = VEXGenerator().generate_json(bom)
        except (OSError, ValueError) as exc:
            raise click.ClickException(str(exc)) from exc
        if output:
            write_output_file(output, text)
        else:
            click.echo(text)

    @main.command()
    @click.argument("aibom_path", type=click.Path(exists=True, path_type=Path))
    @click.option("-o", "--output", type=click.Path(path_type=Path))
    @click.option(
        "--input",
        "input_path",
        type=click.Path(exists=True, path_type=Path),
        help="Offline: match a saved OSV export (all.zip, a directory of records or a JSON file).",
    )
    def advisories(aibom_path: Path, output: Path | None, input_path: Path | None) -> None:
        """Find OSV advisories for the exact PyPI/npm package URLs in the inventory.

        Live (needs --live): queries the OSV API over pinned HTTPS. Offline:
        --input matches a saved OSV export, evaluating listed versions and
        ECOSYSTEM/SEMVER ranges; entries it cannot evaluate make the result
        incomplete instead of clean.
        """
        from nexus_symbiote.advisories import fetch_advisories, match_export

        if output and output.resolve() == aibom_path.resolve():
            raise click.BadParameter("output must not overwrite the source inventory")
        if input_path is None:
            require_live("advisories", "queries the OSV API over HTTPS", replay="--input")
        bom = load_bom(aibom_path)
        try:
            report = (
                match_export(bom, input_path) if input_path is not None else fetch_advisories(bom)
            )
        except (OSError, ValueError) as exc:
            raise click.ClickException(str(exc)) from exc
        text = json.dumps(report.to_dict(), indent=2)
        if output:
            write_output_file(output, text)
        else:
            click.echo(text)
        if report.errors:
            raise click.exceptions.Exit(exits.INCOMPLETE)
