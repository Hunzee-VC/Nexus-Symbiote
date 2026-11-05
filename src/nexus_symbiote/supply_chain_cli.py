"""Explicit supply-chain reports and reviewed-baseline operations."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import click

from nexus_symbiote import modes
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.utils.terminal import neutralize, output_failure, write_cli_output


def _load_inventory(path: Path) -> AIBOM:
    # Parser and validation messages can quote attacker-controlled input; keep them out.
    try:
        return AIBOM.load(path)
    except (OSError, ValueError, RecursionError) as exc:
        raise click.ClickException(f"{neutralize(path)} is not a valid native AIBOM file.") from exc


def _refuse_source_overwrite(output: Path | None, source: Path) -> None:
    if output is None:
        return
    try:
        # Path text alone misses a second name for the same file (a hard link, a bind
        # mount or a case variant), so an existing output is also compared by identity.
        same = output.resolve() == source.resolve() or (
            output.exists() and os.path.samefile(output, source)
        )
    except (OSError, RuntimeError) as exc:
        raise output_failure(exc) from exc
    if same:
        raise click.BadParameter("output must not overwrite the source inventory")


def register_supply_chain_commands(main: click.Group) -> None:
    @main.command("verify-live")
    @click.argument("aibom_path", type=click.Path(exists=True))
    @click.option(
        "--project",
        type=click.Path(exists=True),
        default=".",
        help="Untrusted project root (default: current directory); the launch policy must be outside it.",
    )
    @click.option(
        "--launch-policy",
        required=True,
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="Operator-owned JSON outside the project: exact server references to absolute commands and SHA-256 pins.",
    )
    @click.option("--json-output", is_flag=True, help="Output the verification report as JSON.")
    @click.option(
        "--record",
        is_flag=True,
        help="Print an unsigned candidate BOM with the observed descriptors instead of a report.",
    )
    def verify_live(
        aibom_path: str, project: str, launch_policy: Path, json_output: bool, record: bool
    ) -> None:
        """Live: observe independently pinned stdio launchers; optionally emit an unsigned candidate.

        The operator must provision policy outside the untrusted checkout. Pins
        cover launcher bytes; use an externally isolated worker to restrict its
        host dependencies, filesystem, identity and egress. Project settings do
        not supply launch authority. Descriptor matches do not establish safety.
        """
        modes.require_live("verify-live")
        from nexus_symbiote.core.hashing import open_regular_file, parse_json_strict
        from nexus_symbiote.live.verify import record_candidate, verify_mcp_servers

        if launch_policy.resolve().is_relative_to(Path(project).resolve()):
            raise click.UsageError(
                "launch policy must be provisioned outside the untrusted project"
            )
        if record and json_output:
            raise click.UsageError("choose a candidate BOM or a JSON verification report")
        try:
            with open_regular_file(launch_policy) as stream:
                policy = parse_json_strict(stream.read(4 * 1024 * 1024 + 1))
            if not isinstance(policy, dict):
                raise ValueError("launch policy must be an object")
            with open_regular_file(Path(aibom_path)) as stream:
                document = parse_json_strict(
                    stream.read(16 * 1024 * 1024 + 1), max_bytes=16 * 1024 * 1024
                )
            bom = AIBOM.model_validate(document)
        except (OSError, ValueError, TypeError, RecursionError):
            raise click.ClickException("invalid BOM or operator launch policy") from None
        report = verify_mcp_servers(bom, trusted_launchers=policy)
        if record:
            try:
                record_candidate(bom, report)
            except ValueError:
                raise click.ClickException("incomplete inventory; candidate not emitted") from None
            click.echo(bom.to_json())
            return
        if json_output:
            click.echo(json.dumps(report.to_dict(), indent=2))
        else:
            click.echo(
                f"Live descriptor observation: {report.servers_reachable}/{report.servers_checked} servers; "
                f"complete={report.complete}; drift={report.has_drift}"
            )
        if not report.complete or report.has_drift:
            raise click.exceptions.Exit(1)

    @main.command()
    @click.argument("project_path", type=click.Path(exists=True), default=".")
    @click.option(
        "-o",
        "--baseline-path",
        type=click.Path(path_type=Path),
        default=".nexus-symbiote-baseline.json",
        help="Where to write the unsigned baseline (default: .nexus-symbiote-baseline.json).",
    )
    @click.pass_context
    def baseline(ctx: click.Context, project_path: str, baseline_path: Path) -> None:
        """Stage a static snapshot for review; publish it only after the scan gate passes.

        The file is unsigned. Operators must review and authenticate the baseline
        before using it as an authority for runtime admission.
        """
        from nexus_symbiote.validators.risk import RiskScorer

        # Resolve the registered command instead of importing cli, which imports this module.
        root = ctx.find_root()
        scan = (
            root.command.get_command(root, "scan")
            if isinstance(root.command, click.Group)
            else None
        )
        if scan is None:
            raise click.ClickException("scan command is unavailable")

        target = baseline_path.absolute()
        try:
            fd, temporary = tempfile.mkstemp(prefix=".nexus-baseline-", dir=target.parent)
        except OSError as exc:
            raise output_failure(exc) from exc
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
            passed, _ = RiskScorer().passes_gate(AIBOM.load(staged))
            if not passed:
                raise click.ClickException("Baseline was not written: static scan gate failed")
            write_cli_output(target, staged.read_text(encoding="utf-8"))
        finally:
            staged.unlink(missing_ok=True)
        click.echo(f"Unsigned baseline staged for review: {target}")

    @main.command()
    @click.argument("aibom_path", type=click.Path(exists=True, path_type=Path))
    @click.option(
        "-o",
        "--output",
        type=click.Path(path_type=Path),
        help="Write the VEX document to this file instead of standard output.",
    )
    def vex(aibom_path: Path, output: Path | None) -> None:
        """Export schema-validated findings in triage, without asserting exploitability."""
        from nexus_symbiote.generators.vex import VEXGenerator

        _refuse_source_overwrite(output, aibom_path)
        bom = _load_inventory(aibom_path)
        try:
            text = VEXGenerator().generate_json(bom)
        except (OSError, ValueError, RecursionError) as exc:
            raise click.ClickException(neutralize(exc)) from exc
        if output:
            write_cli_output(output, text)
        else:
            click.echo(text)

    @main.command()
    @click.argument("aibom_path", type=click.Path(exists=True, path_type=Path))
    @click.option(
        "-o",
        "--output",
        type=click.Path(path_type=Path),
        help="Write the advisory report to this file instead of standard output.",
    )
    def advisories(aibom_path: Path, output: Path | None) -> None:
        """Live: query OSV for exact PyPI/npm package URLs in the inventory."""
        modes.require_live("advisories")
        from nexus_symbiote.advisories import fetch_advisories

        _refuse_source_overwrite(output, aibom_path)
        bom = _load_inventory(aibom_path)
        try:
            report = fetch_advisories(bom)
        except (OSError, ValueError) as exc:
            raise click.ClickException(neutralize(exc)) from exc
        text = json.dumps(report.to_dict(), indent=2)
        if output:
            write_cli_output(output, text)
        else:
            click.echo(text)
        if report.errors:
            raise click.exceptions.Exit(1)
