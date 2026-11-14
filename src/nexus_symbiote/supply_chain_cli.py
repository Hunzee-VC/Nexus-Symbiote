"""Explicit supply-chain reports and reviewed-baseline operations."""

from __future__ import annotations

import contextlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import click

from nexus_symbiote import modes
from nexus_symbiote.core.aibom import AIBOM, NativeFormatError
from nexus_symbiote.live_cli import review_notice
from nexus_symbiote.utils.terminal import (
    echo_line,
    json_text,
    neutralize,
    output_failure,
    write_cli_output,
)

if TYPE_CHECKING:
    from nexus_symbiote.live.verify import LiveVerifyReport

# Set while `baseline` runs `scan` into a staged inventory that it discards on failure.
STAGED_INVENTORY = "nexus_symbiote.staged-inventory"


def _load_inventory(path: Path) -> AIBOM:
    # Parser and validation messages can quote attacker-controlled input; keep them out.
    try:
        return AIBOM.load(path)
    except NativeFormatError as exc:
        raise click.ClickException(
            f"{neutralize(path)} is not a valid native AIBOM file. {neutralize(exc)}"
        ) from exc
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


def _repository_root(path: Path) -> Path | None:
    """The nearest directory at or above ``path`` that holds a ``.git`` entry."""
    for candidate in (path, *path.parents):
        if os.path.lexists(candidate / ".git"):
            return candidate
    return None


def _check_launch_policy(policy: Path, project: Path, inventory: Path) -> None:
    """Refuse a launch policy that the change under review could have written.

    The policy must lie outside the project, outside the repositories that hold the
    project and the inventory, be a single-link regular file owned by the caller or
    root that only its owner can write, in a directory owned by you or root that
    others cannot write unless it is sticky. This catches misplacement; it does not
    authenticate the policy.
    """
    resolved = policy.resolve()
    untrusted = [project.resolve()]
    for start in (project.resolve(), inventory.resolve().parent):
        root = _repository_root(start)
        if root is not None:
            untrusted.append(root)
    if any(resolved.is_relative_to(root) for root in untrusted):
        raise click.UsageError(
            "launch policy must be provisioned outside the untrusted project and outside "
            "the repository that holds the project or the inventory"
        )
    if os.name != "posix":
        return
    try:
        info = resolved.lstat()
        parent = resolved.parent.stat()
    except OSError as exc:
        raise click.UsageError("launch policy cannot be inspected") from exc
    owners = {0, os.geteuid()}
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid not in owners
        or info.st_mode & 0o022
        or parent.st_uid not in owners
        or (parent.st_mode & 0o022 and not parent.st_mode & stat.S_ISVTX)
    ):
        raise click.UsageError(
            "launch policy must be a single-link regular file owned by you or root and "
            "writable only by its owner, in a directory owned by you or root that others "
            "cannot write unless it is sticky"
        )


def _drift_summary(report: LiveVerifyReport) -> None:
    """Print each drifted server and tool to standard error, one neutralized line each."""
    for result in report.results:
        changes = [
            f"{finding.status} tool {finding.name}"
            for finding in result.tool_findings
            if finding.status != "match"
        ]
        if result.declaration_status in {"changed", "new"}:
            changes.append(f"{result.declaration_status} server declarations")
        if result.identity_status == "changed":
            changes.append("changed server identity or capabilities")
        if changes:
            echo_line("Drift in server ", result.server_ref, ": ", "; ".join(changes), err=True)


def register_supply_chain_commands(main: click.Group) -> None:
    @main.command("verify-live")
    @click.argument("aibom_path", type=click.Path(exists=True, dir_okay=False))
    @click.option(
        "--project",
        type=click.Path(exists=True, file_okay=False),
        required=True,
        help=(
            "Untrusted project root; the launch policy must be outside it and outside "
            "the repository that holds the project or the inventory."
        ),
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
        help=(
            "Print an unsigned candidate BOM with the observed descriptors instead of a "
            "report; exits 1 when served tools, declarations or the server identity "
            "drifted, unless --accept-drift."
        ),
    )
    @click.option(
        "--accept-drift",
        is_flag=True,
        help=(
            "With --record, exit 0 although changed or new tools, declarations or server "
            "identity were recorded."
        ),
    )
    @click.option(
        "--no-isolation",
        is_flag=True,
        help=(
            "Explicitly allow execution without a PID namespace. On Linux the launcher is "
            "still a child subreaper, so a double-fork is killed with the session; elsewhere "
            "cleanup is best effort. Printed as a warning."
        ),
    )
    def verify_live(
        aibom_path: str,
        project: str,
        launch_policy: Path,
        json_output: bool,
        record: bool,
        accept_drift: bool,
        no_isolation: bool,
    ) -> None:
        """Live: observe independently pinned stdio launchers; optionally emit an unsigned candidate.

        The operator must provision policy outside the untrusted checkout. Pins
        cover launcher bytes; use an externally isolated worker to restrict its
        host dependencies, filesystem, identity and egress. Project settings do
        not supply launch authority. Descriptor matches do not establish safety.
        Remote MCP servers in the inventory are reported as not verifiable here;
        observe them with discover-mcp --record.
        """
        modes.require_live("verify-live")
        from nexus_symbiote.core.hashing import hash_bytes, open_regular_file, parse_json_strict
        from nexus_symbiote.live.pinned_process import isolation_off
        from nexus_symbiote.live.verify import record_candidate, verify_mcp_servers

        if record and json_output:
            raise click.UsageError("choose a candidate BOM or a JSON verification report")
        if accept_drift and not record:
            raise click.UsageError("--accept-drift applies only to --record")
        _check_launch_policy(launch_policy, Path(project), Path(aibom_path))
        try:
            with open_regular_file(launch_policy) as stream:
                if os.fstat(stream.fileno()).st_nlink != 1:
                    raise ValueError("launch policy has more than one link")
                policy_bytes = stream.read(4 * 1024 * 1024 + 1)
            policy = parse_json_strict(policy_bytes)
            if not isinstance(policy, dict):
                raise ValueError("launch policy must be an object")
            with open_regular_file(Path(aibom_path)) as stream:
                inventory_bytes = stream.read(16 * 1024 * 1024 + 1)
            document = parse_json_strict(inventory_bytes, max_bytes=16 * 1024 * 1024)
            bom = AIBOM.from_document(document)
        except (OSError, ValueError, TypeError, RecursionError):
            raise click.ClickException("invalid BOM or operator launch policy") from None
        if no_isolation:
            click.echo(
                "warning: --no-isolation: kernel PID containment is disabled; on Linux the "
                "launcher is a child subreaper, so a double-fork is still killed with the "
                "session, and elsewhere a daemonized child can outlive cleanup.",
                err=True,
            )
        with isolation_off() if no_isolation else contextlib.nullcontext():
            report = verify_mcp_servers(bom, trusted_launchers=policy)
        report.inputs = {
            "inventory_sha256": hash_bytes(inventory_bytes),
            "launch_policy_sha256": hash_bytes(policy_bytes),
        }
        if record:
            try:
                record_candidate(bom, report)
            except ValueError:
                raise click.ClickException("incomplete inventory; candidate not emitted") from None
            try:
                candidate = bom.to_native_json()
            except NativeFormatError as exc:
                raise click.ClickException(f"Inventory not written. {exc}") from exc
            click.echo(json_text(candidate))
            _drift_summary(report)
            review_notice(
                [
                    finding.name
                    for result in report.results
                    for finding in result.tool_findings
                    if finding.display_differs
                ]
            )
            if report.has_drift and not accept_drift:
                click.echo(
                    "Candidate differs from the inventory; review it, then rerun with "
                    "--accept-drift to record it with exit status 0.",
                    err=True,
                )
                raise click.exceptions.Exit(1)
            return
        if json_output:
            click.echo(json_text(json.dumps(report.to_dict(), indent=2)))
        else:
            echo_line(
                "Live descriptor observation: ",
                f"{report.servers_reachable}/{report.servers_checked} servers; ",
                f"{report.servers_skipped} remote not verifiable here; ",
                f"complete={report.complete}; drift={report.has_drift}",
            )
            for result in report.results:
                if result.reason is not None:
                    echo_line(
                        "Server ", f"{result.server_ref}: {result.reason}: {result.error}", err=True
                    )
        if not report.complete or report.has_drift:
            raise click.exceptions.Exit(1)

    @main.command()
    @click.argument("project_path", type=click.Path(exists=True, file_okay=False), default=".")
    @click.option(
        "-o",
        "--baseline-path",
        type=click.Path(path_type=Path),
        default=".nexus-symbiote-baseline.json",
        help="Where to write the unsigned baseline (default: .nexus-symbiote-baseline.json).",
    )
    @click.option(
        "--no-project-policy",
        is_flag=True,
        help="Use built-in policy without reading configuration from the target, as scan does.",
    )
    @click.option(
        "--accept-project-policy",
        is_flag=True,
        help=(
            "In CI, accept a project policy that weakens the built-in gates explicitly for "
            "collection, as scan does; the staged inventory is still re-gated by the built-in "
            "policy."
        ),
    )
    @click.option(
        "--signature-policy",
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="Explicit operator signer policy JSON, kept outside the project, as for scan.",
    )
    @click.pass_context
    def baseline(
        ctx: click.Context,
        project_path: str,
        baseline_path: Path,
        no_project_policy: bool = False,
        accept_project_policy: bool = False,
        signature_policy: Path | None = None,
    ) -> None:
        """Stage a static snapshot for review; publish it only after the scan gate passes.

        The file is unsigned. Operators must review and authenticate the baseline
        before using it as an authority for runtime admission. Take the baseline and
        the snapshots compared with it under the same policy: pass --no-project-policy
        here when the candidate scan uses it.
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
        ctx.meta[STAGED_INVENTORY] = True
        try:
            ctx.invoke(
                scan,
                project_path=project_path,
                output=str(staged),
                output_format="json",
                scanners=(),
                report_only=False,
                signature_policy=signature_policy,
                no_project_policy=no_project_policy,
                accept_project_policy=accept_project_policy,
            )
            # A project policy may select report-only mode; it cannot authorize
            # promotion of incomplete evidence into an approved baseline.
            try:
                staged_bom = AIBOM.load(staged)
            except NativeFormatError as exc:
                raise click.ClickException(f"Baseline was not written. {exc}") from exc
            scorer = RiskScorer()
            passed, report = scorer.passes_gate(staged_bom)
            if not passed:
                from nexus_symbiote.reporting import gate_reason_lines, print_lines

                document = {
                    **report.to_dict(),
                    "fail_on_severity": scorer.fail_on_severity,
                    "score_threshold": scorer.fail_threshold,
                }
                heading = "Built-in scan gate failed; a project policy cannot relax it here:"
                print_lines([(heading, "red"), *gate_reason_lines(document)], err=True)
                raise click.ClickException("Baseline was not written: static scan gate failed")
            write_cli_output(target, staged.read_text(encoding="utf-8"))
        finally:
            ctx.meta.pop(STAGED_INVENTORY, None)
            # A directory that forbids removal keeps the staged copy; that must not
            # replace the command's result.
            with contextlib.suppress(OSError):
                staged.unlink(missing_ok=True)
        echo_line("Unsigned baseline staged for review: ", target)

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
            click.echo(json_text(text))

    @main.command()
    @click.argument("aibom_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option(
        "-o",
        "--output",
        type=click.Path(path_type=Path),
        help="Write the advisory report to this file instead of standard output.",
    )
    @click.option(
        "--fail-on-advisory/--no-fail-on-advisory",
        default=True,
        show_default=True,
        help="Exit with status 1 when an advisory is found.",
    )
    @click.option(
        "--exclude",
        multiple=True,
        metavar="NAME",
        help="Never send this package name to OSV; a trailing * matches a prefix (repeatable).",
    )
    @click.option(
        "--exclude-private-origins",
        is_flag=True,
        help=(
            "Send only packages whose lockfile resolution records the public PyPI or npm "
            "registry. A Python package that no uv.lock or poetry.lock resolves has no "
            "recorded origin, so it is withheld; withhold private names with --exclude "
            "instead to keep public ones checked."
        ),
    )
    @click.option(
        "--dry-run",
        is_flag=True,
        help="List the package identities that would be sent, without contacting OSV (works offline).",
    )
    def advisories(
        aibom_path: Path,
        output: Path | None,
        fail_on_advisory: bool,
        exclude: tuple[str, ...],
        exclude_private_origins: bool,
        dry_run: bool,
    ) -> None:
        """Live: query OSV for exact PyPI/npm package URLs in the inventory.

        Sends each package's ecosystem, normalized name and exact version to
        api.osv.dev, including packages from private registries unless excluded.
        Exits 1 when an advisory is found (unless --no-fail-on-advisory) or when
        not every package in scope was looked up, including when none was; with
        --dry-run, only when the report lists an error.
        """
        if not dry_run:
            modes.require_live("advisories")
        from nexus_symbiote.advisories import fetch_advisories
        from nexus_symbiote.core.hashing import hash_bytes

        _refuse_source_overwrite(output, aibom_path)
        try:
            bom, data = AIBOM.load_with_bytes(aibom_path)
        except NativeFormatError as exc:
            raise click.ClickException(
                f"{neutralize(aibom_path)} is not a valid native AIBOM file. {neutralize(exc)}"
            ) from exc
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            raise click.ClickException(
                f"{neutralize(aibom_path)} is not a valid native AIBOM file."
            ) from exc
        try:
            report = fetch_advisories(
                bom,
                exclude=exclude,
                exclude_private_origins=exclude_private_origins,
                dry_run=dry_run,
                inventory_sha256=hash_bytes(data),
            )
        except (OSError, ValueError) as exc:
            raise click.ClickException(neutralize(exc)) from exc
        text = json.dumps(report.to_dict(), indent=2)
        if output:
            write_cli_output(output, text)
        else:
            click.echo(json_text(text))
        if dry_run:
            if report.errors:
                raise click.exceptions.Exit(1)
            return
        if not report.complete or (fail_on_advisory and report.advisories):
            raise click.exceptions.Exit(1)
