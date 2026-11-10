"""Nexus SymBiote CLI — Agent Bill of Materials for AI supply chain security."""

from __future__ import annotations

import json
import math
import os
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from nexus_symbiote import __version__, limits, modes
from nexus_symbiote.core.aibom import AIBOM, NativeFormatError
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import AIBOMMetadata, CompletenessClaim
from nexus_symbiote.graph import validate_graph
from nexus_symbiote.live_cli import register_live_commands
from nexus_symbiote.policy import Policy
from nexus_symbiote.reporting import (
    ReportLine,
    diff_report_lines,
    print_lines,
    risk_report_lines,
    scan_gate_lines,
    validation_report_lines,
)
from nexus_symbiote.runtime_cli import register_runtime_commands
from nexus_symbiote.supply_chain_cli import STAGED_INVENTORY, register_supply_chain_commands
from nexus_symbiote.utils.files import write_output_file
from nexus_symbiote.utils.terminal import (
    echo_line,
    json_text,
    neutralize,
    output_failure,
    safe_line,
    write_cli_output,
)

if TYPE_CHECKING:
    from nexus_symbiote.scanners.base import ScanResult
    from nexus_symbiote.utils.crypto import SigstoreArtifactPolicy

DEBUG_KEY = "nexus_symbiote.debug"
BUILTIN_SCANNERS = "mcp, model, prompt, rag, registry, a2a, ide_agents, shadowscan"
# Gate reports name the agent manifest and the graph check like collectors.
MANIFEST = "agent.yaml"


def _debug_enabled() -> bool:
    ctx = click.get_current_context(silent=True)
    return bool(ctx is not None and ctx.meta.get(DEBUG_KEY))


def _staged_inventory() -> bool:
    ctx = click.get_current_context(silent=True)
    return bool(ctx is not None and ctx.meta.get(STAGED_INVENTORY))


def _print_traceback(exc: BaseException) -> None:
    import traceback

    # An error's message can quote project or inventory text, secrets included; its
    # class and where it was raised are what a defect report needs, so only those print.
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        echo_line("Debug: ", type(current).__name__, " raised at:", err=True)
        for frame in traceback.extract_tb(current.__traceback__):
            echo_line("Debug:   ", frame.filename, ":", frame.lineno, " in ", frame.name, err=True)
        cause = current.__cause__
        current = (
            cause if cause is not None or current.__suppress_context__ else current.__context__
        )


def _scanner_error_summary(exc: Exception) -> str:
    # Exception messages can include Pydantic input values, parser snippets or
    # credentials. Only application-owned diagnostic codes cross this boundary.
    from pydantic import ValidationError

    if isinstance(exc, ValidationError):
        return "component validation failed (scanner-validation-error)"
    if isinstance(exc, OSError):
        return "collection I/O failed (scanner-io-error)"
    if isinstance(exc, (ValueError, TypeError, RecursionError)):
        return "invalid or unsupported input (scanner-input-error)"
    return "collector failed (scanner-internal-error)"


def _input_problem(exc: BaseException) -> str:
    """Name the class of an input failure without quoting the input."""
    from pydantic import ValidationError

    if isinstance(exc, OSError):
        return "it cannot be read"
    if isinstance(exc, RecursionError):
        return "it is nested too deeply"
    if isinstance(exc, UnicodeError):
        return "it is not UTF-8 text"
    if isinstance(exc, ValidationError):
        return "it does not match the native AIBOM schema"
    if isinstance(exc, json.JSONDecodeError):
        return "it is not valid JSON"
    return (
        "it is not strict JSON (duplicate keys and non-finite numbers are refused) "
        "or exceeds the size limit"
    )


def _policy_with_source(
    root: Path, *, ignore_project: bool = False, warn: bool = True
) -> tuple[Policy, str, list[str]]:
    """Load the governing policy and say where it came from and what it relaxes.

    A gate that a checkout-supplied file switched off must be a visible choice, so
    every relaxation is returned for machine-readable output and, unless the caller
    emits JSON that already carries it, printed on stderr.
    """
    from nexus_symbiote.policy import (
        PolicyError,
        default_policy,
        load_policy_file,
        weakened_settings,
    )

    if ignore_project:
        return default_policy(), "built-in", []
    try:
        loaded = load_policy_file(root)
    except PolicyError as exc:
        raise _failure(exc) from exc
    if loaded is None:
        return default_policy(), "built-in", []
    policy, path, _ = loaded
    weaker = weakened_settings(policy)
    if weaker and warn:
        # The path and the relaxed values come from the checkout, so neither may move
        # the cursor or start a new line that hides this warning or forges a CI command.
        echo_line(
            "WARNING: policy ", path, " weakens the built-in gates: ", "; ".join(weaker), err=True
        )
    return policy, f"project:{path}", weaker


def _inventory_policy(
    project: Path | None, aibom_path: str, *, ignore_project: bool, warn: bool = True
) -> tuple[Policy, str, list[str]]:
    """Policy for a command that reads an inventory: only a named project supplies one.

    An inventory can be written anywhere, including shared directories such as /tmp,
    so its location never selects the policy that gates it.
    """
    from nexus_symbiote.policy import default_policy, nearest_policy_file

    if project is not None:
        return _policy_with_source(project, ignore_project=ignore_project, warn=warn)
    if not ignore_project:
        unapplied = nearest_policy_file(Path(aibom_path).resolve().parent)
        if unapplied is not None:
            echo_line(
                "Note: ",
                unapplied,
                " was not applied. Without --project the built-in policy is used; "
                "name a trusted project with --project to apply its policy.",
                err=True,
            )
    return default_policy(), "built-in", []


def _gate_sources(
    policy: Policy, policy_source: str, threshold_from_cli: bool, fail_on_severity: str | None
) -> dict[str, str]:
    """Where each effective risk-gate parameter came from: cli, project policy or built-in."""

    def origin(name: str) -> str:
        if policy_source.startswith("project:") and name in policy.risk.model_fields_set:
            return "project policy"
        return "built-in"

    return {
        "fail_threshold_source": "cli" if threshold_from_cli else origin("fail_threshold"),
        "fail_on_severity_source": "cli" if fail_on_severity else origin("fail_on_severity"),
        "warn_threshold_source": origin("warn_threshold"),
        "ignore_categories_source": origin("ignore_categories"),
        "suppressions_source": origin("suppressions"),
    }


def _failure(exc: Exception) -> click.ClickException:
    # Policy, graph and inventory errors quote keys, file names and paths from the
    # checkout or the inventory, so they get the same neutralization as other output.
    return click.ClickException(neutralize(exc))


def _load_bom(path: str | Path) -> AIBOM:
    # Parser and validation messages can quote attacker-controlled input; name only the
    # class of the problem. A NativeFormatError names it without quoting the document.
    try:
        return AIBOM.load(Path(path))
    except NativeFormatError as exc:
        raise click.ClickException(
            f"{neutralize(path)} is not a valid native AIBOM file. {neutralize(exc)}"
        ) from exc
    except (OSError, ValueError, RecursionError) as exc:
        raise click.ClickException(
            f"{neutralize(path)} is not a valid native AIBOM file. Reason: {_input_problem(exc)}."
        ) from exc


def _project_root(value: str | Path, *, label: str) -> Path:
    """Resolve a project directory, saying so when a symbolic link redirects it.

    The confined collectors refuse a root reached through a symbolic link, so the CLI
    resolves the path first. A checkout can replace a directory it contains with a
    link to any directory on the machine, and a plain relative path can only leave
    the working directory through such a link, so that case is refused.
    """
    requested = Path(value)
    resolved = requested.resolve()
    if Path(os.path.normpath(requested.absolute())) == resolved:
        return resolved
    if (
        not requested.is_absolute()
        and ".." not in requested.parts
        and not resolved.is_relative_to(Path.cwd().resolve())
    ):
        raise click.BadParameter(
            f"{value} leads outside the current directory through a symbolic link; "
            f"name the directory it resolves to, {resolved}, to collect that directory",
            param_hint=label,
        )
    echo_line(
        "Note: ", label, " ", value, " resolves through a symbolic link to ", resolved, err=True
    )
    return resolved


def _require_binding_key() -> None:
    """A malformed operator key is a usage error, not a failure of the scanned files."""
    from nexus_symbiote.scanners.mcp import _MIN_SOURCE_BINDING_KEY_LENGTH, SOURCE_BINDING_KEY_ENV

    key = os.environ.get(SOURCE_BINDING_KEY_ENV, "")
    if key and len(key) < _MIN_SOURCE_BINDING_KEY_LENGTH:
        raise click.UsageError(
            f"{SOURCE_BINDING_KEY_ENV} must contain at least "
            f"{_MIN_SOURCE_BINDING_KEY_LENGTH} characters"
        )


SCANNER_REGISTRY: dict[str, type] = {}


def _signer_policies(path: Path | None, project: Path | None) -> list[SigstoreArtifactPolicy]:
    from nexus_symbiote.signature_policy import load_signature_policies

    if path is None:
        return []
    if project is None:
        raise click.BadParameter("--signature-policy requires --project")
    try:
        return load_signature_policies(path, project)
    except ValueError as exc:
        raise _failure(exc) from None


def _get_scanners() -> dict[str, type]:
    if not SCANNER_REGISTRY:
        from nexus_symbiote.scanners.a2a import A2AScanner
        from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
        from nexus_symbiote.scanners.mcp import MCPScanner
        from nexus_symbiote.scanners.model import ModelScanner
        from nexus_symbiote.scanners.prompt import PromptScanner
        from nexus_symbiote.scanners.rag import RAGScanner
        from nexus_symbiote.scanners.registry import RegistryScanner
        from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

        SCANNER_REGISTRY.update(
            {
                "shadowscan": ShadowScanImporter,
                "mcp": MCPScanner,
                "model": ModelScanner,
                "prompt": PromptScanner,
                "rag": RAGScanner,
                "registry": RegistryScanner,
                "a2a": A2AScanner,
                "ide_agents": IDEAgentScanner,
            }
        )
    return SCANNER_REGISTRY


_MODE_FLAGS = frozenset({"--offline", "--live"})
# Click 8.2+ shows a group's own help, which carries no input, through this error.
_HELP_ERRORS = tuple(
    error
    for error in (getattr(click.exceptions, "NoArgsIsHelpError", None),)
    if isinstance(error, type)
)


def _neutralized(exc: click.ClickException) -> click.ClickException:
    """The same error with neutralized text: it can quote checkout or inventory text."""
    message = neutralize(exc.format_message())
    if isinstance(exc, click.UsageError):
        return click.UsageError(message, ctx=exc.ctx)
    return click.ClickException(message)


def _declared_text_only(exc: click.ClickException) -> bool:
    """Click's own missing-parameter error, worded only from the parameter's declaration.

    Its lines (such as one per allowed choice) come from this program, never from input,
    so they keep Click's layout instead of being joined into one neutralized line.
    """
    return (
        type(exc) is click.MissingParameter
        and not exc.message
        and exc.param is not None
        and exc.param_hint is None
        and exc.param_type is None
    )


class _RootGroup(click.Group):
    """Root group: clear mode refusals, neutralized error text and no tracebacks."""

    def _main_shell_completion(
        self,
        ctx_args: Any,
        prog_name: str,
        complete_var: str | None = None,
    ) -> None:
        # Shell completion is not offered: an inherited _NEXUS_SYMBIOTE_COMPLETE would
        # make every command, gates included, print a script and exit 0 without running.
        return None

    def invoke(self, ctx: click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except click.NoSuchOption as exc:
            if exc.option_name == limits.OPTION:
                raise click.UsageError(
                    f"No such option: {limits.OPTION}. Limits go before the command: "
                    f"nexus-symbiote {limits.OPTION} NAME=VALUE <command> ...",
                    ctx=exc.ctx,
                ) from None
            if exc.option_name not in _MODE_FLAGS:
                raise _neutralized(exc) from None
            raise click.UsageError(
                f"No such option: {exc.option_name}. Mode flags go before the command: "
                f"nexus-symbiote {exc.option_name} <command> ...",
                ctx=exc.ctx,
            ) from None
        except modes.LiveModeRequiredError as exc:
            raise click.UsageError(neutralize(exc)) from None
        except modes.OfflineViolation as exc:
            raise click.ClickException(
                f"offline mode blocked {neutralize(exc)} before the command completed. This "
                "command never needs the network or a subprocess; please report this as a defect."
            ) from None
        except click.ClickException as exc:
            if isinstance(exc, _HELP_ERRORS) or _declared_text_only(exc):
                raise
            raise _neutralized(exc) from None
        except (click.exceptions.Exit, click.Abort):
            raise
        except Exception as exc:
            # A traceback can quote project or inventory text, so it is shown only on
            # request; the command still fails closed.
            if ctx.meta.get(DEBUG_KEY):
                _print_traceback(exc)
            raise click.ClickException(
                f"internal error ({type(exc).__name__}); nothing was approved. Rerun with "
                "--debug before the command to see where it was raised, and please report it."
            ) from None


@click.group(cls=_RootGroup)
@click.version_option(version=__version__, prog_name="nexus-symbiote")
@click.option(
    "--offline",
    "offline_flag",
    is_flag=True,
    help="Refuse network access and process creation (the default).",
)
@click.option(
    "--live",
    "live_flag",
    is_flag=True,
    help=(
        "Allow the network and process steps of the live commands "
        "(discover-mcp, advisories, verify-live). Other commands stay offline."
    ),
)
@click.option(
    "--debug",
    "debug_flag",
    is_flag=True,
    help=(
        "Print where a collector or internal error was raised (its class, files, lines and "
        "functions) on standard error, without its message, which can quote input."
    ),
)
@click.option(
    limits.OPTION,
    "limit_settings",
    multiple=True,
    metavar="NAME=VALUE",
    help=(
        "Set one collection limit for this command, for example entries=200000 or "
        "model-bytes=128GiB. Repeatable; overrides NEXUS_SYMBIOTE_LIMITS for that name. "
        "Limits: " + ", ".join(limits.SPECS) + "."
    ),
)
@click.pass_context
def main(
    ctx: click.Context,
    offline_flag: bool,
    live_flag: bool,
    debug_flag: bool,
    limit_settings: tuple[str, ...] = (),
) -> None:
    """Nexus SymBiote — Agent Bill of Materials for AI supply chain security.

    Every command runs offline by default: no name resolution, network
    connections or subprocesses. Only discover-mcp, advisories and verify-live
    reach outside local files, and only in live mode: pass --live before the
    command or set NEXUS_SYMBIOTE_MODE=live.

    Collection limits bound what one command reads from a project. Reaching one
    fails the scan and names the limit; raise it with --limit before the command
    or with NEXUS_SYMBIOTE_LIMITS=NAME=VALUE,NAME=VALUE. A project's own files
    never change a limit.
    """
    ctx.meta[DEBUG_KEY] = debug_flag
    try:
        requested = modes.resolve(offline=offline_flag, live=live_flag, environ=os.environ)
        collection_limits = limits.resolve(limit_settings, os.environ)
    except ValueError as exc:
        raise click.UsageError(str(exc), ctx=ctx) from None
    ctx.meta["nexus_symbiote.mode"] = requested
    ctx.with_resource(limits.applied(collection_limits))
    ctx.with_resource(modes.enforce(modes.command_mode(requested.mode, ctx.invoked_subcommand)))


def _merge_scan_result(
    name: str,
    result: ScanResult,
    aibom: AIBOM,
    collected: dict[str, Any],
    scan_failures: list[str],
) -> None:
    from nexus_symbiote.core.collection import merge_collected

    accepted_refs: set[str] = set()
    for comp in result.components:
        # Discovery of a file/configuration does not verify every supplier assertion.
        outcome = merge_collected(collected, comp, name, aibom.metadata.timestamp)
        if outcome == "conflict":
            scan_failures.append(f"{name}: conflicting duplicate component {comp.bom_ref}")
            continue
        if outcome == "added":
            aibom.components.append(comp)
        accepted_refs.add(comp.bom_ref)
    for edge in result.dependencies:
        if edge.source_ref in accepted_refs and edge.target_ref in accepted_refs:
            aibom.add_dependency(edge)
        else:
            scan_failures.append(f"{name}: dependency endpoint was not imported")


def _render_aibom(aibom: AIBOM, output_format: str, root: Path) -> str:
    if output_format == "cyclonedx":
        from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator

        return CycloneDXGenerator().generate_json(aibom)
    if output_format == "spdx":
        from nexus_symbiote.generators.spdx import SPDXGenerator

        return SPDXGenerator().generate_json(aibom)
    if output_format == "sarif":
        from nexus_symbiote.generators.sarif import SARIFGenerator

        # Inventory paths are relative to the scanned root; SARIF URIs to the working
        # directory, or to the scanned root when the scan starts outside it.
        return SARIFGenerator(scan_root=root).generate_json(aibom)
    try:
        return aibom.to_native_json()
    except NativeFormatError as exc:
        raise click.ClickException(f"Inventory not written. {exc}") from exc


@main.command()
@click.argument("project_path", type=click.Path(exists=True, file_okay=False), default=".")
@click.option(
    "-o", "--output", type=click.Path(), help="Output file path (default: standard output)"
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "cyclonedx", "spdx", "sarif"]),
    default=None,
    help="Output format (default: json, or from .nexus-symbiote.yaml)",
)
@click.option(
    "--scanner",
    "scanners",
    multiple=True,
    help=(
        f"Collector to run, once each: {BUILTIN_SCANNERS} (default: all, or from "
        ".nexus-symbiote.yaml). A collector left out makes coverage partial."
    ),
)
@click.option(
    "--report-only", is_flag=True, help="Emit findings and collection failures without a CI failure"
)
@click.option(
    "--check",
    "check_only",
    is_flag=True,
    help="Collect and apply the scan gate without writing an inventory.",
)
@click.option(
    "--signature-policy",
    type=click.Path(exists=True, path_type=Path),
    help="Explicit operator signer policy JSON",
)
@click.option(
    "--no-project-policy",
    is_flag=True,
    help="Use built-in policy without reading configuration from the target.",
)
def scan(
    project_path: str,
    output: str | None,
    output_format: str | None,
    scanners: tuple[str, ...],
    report_only: bool = False,
    signature_policy: Path | None = None,
    no_project_policy: bool = False,
    check_only: bool = False,
) -> None:
    """Scan a project and generate an AIBOM."""
    if check_only and output:
        raise click.UsageError("--check writes no inventory; drop -o/--output or --check")
    _require_binding_key()
    root = _project_root(project_path, label="PROJECT_PATH")
    if not root.is_dir():
        raise click.ClickException(f"{neutralize(project_path)} is not a directory")

    from nexus_symbiote.graph import assemble_repository_agent
    from nexus_symbiote.policy import PolicyError
    from nexus_symbiote.utils.confined import DEFAULT_EXCLUDES
    from nexus_symbiote.validators.risk import RiskScorer

    policy, policy_source, policy_weakened = _policy_with_source(
        root, ignore_project=no_project_policy
    )
    signature_policies = _signer_policies(signature_policy, root)
    output_format = output_format or policy.output.default_format
    all_scanners = _get_scanners()
    selected = scanners or tuple(policy.scan.scanners)
    unknown = set(selected) - set(all_scanners)
    if unknown:
        raise click.BadParameter(
            "Unknown scanner: " + ", ".join(sorted(unknown)), param_hint="--scanner"
        )
    if len(set(selected)) != len(selected):
        raise click.BadParameter("each collector may be selected only once", param_hint="--scanner")
    if output_format not in {"json", "cyclonedx", "spdx", "sarif"}:
        raise click.BadParameter("Unknown output format", param_hint="--format")
    echo_line("Scanning ", root, err=True)
    # The policy file always sits in the scan root; record it relative to that root.
    aibom = AIBOM(
        metadata=AIBOMMetadata(
            authors=[],
            policy_source=(
                "project:" + policy_source.rsplit("/", 1)[-1]
                if policy_source.startswith("project:")
                else policy_source
            ),
            policy_weakened=policy_weakened,
        )
    )
    aibom.finalize()
    surfaces_scanned: list[str] = []
    surfaces_excluded: list[str] = []
    scan_failures: list[str] = []
    failures_by: dict[str, list[str]] = {}
    excluded_by: dict[str, list[str]] = {}
    completed: list[str] = []
    source_report_digest = None
    source_report_content_digest = None
    source_report_content_profile = None
    source_report_format = None
    source_report_status = None
    source_projection_limitations = None
    source_unmapped_count = 0
    source_unmapped_indexes: list[int] = []
    scanner_status: dict[str, str] = dict.fromkeys(all_scanners, "unknown")
    # AIBOM lookups scan the whole list; a project can declare tens of thousands of
    # tools, so index what this loop adds instead of searching for each component.
    collected: dict[str, Any] = {}
    for name in selected:
        scanner = (
            all_scanners[name](signature_policies=signature_policies)
            if name == "model"
            else all_scanners[name]()
        )
        echo_line("  Running ", name, " scanner...", err=True)
        failure_count = len(scan_failures)
        try:
            configure = getattr(scanner, "configure", None)
            if configure:
                configure(exclude_paths=policy.scan.exclude_paths)
            elif policy.scan.exclude_paths:
                raise ValueError("scanner does not support configured exclude_paths")
            result = scanner.scan(root)
            result.make_portable(root)
            if name == "shadowscan":
                source_report_digest = result.source_report_digest
                source_report_content_digest = result.source_report_content_digest
                source_report_content_profile = result.source_report_content_profile
                source_report_format = result.source_report_format
                source_report_status = result.source_report_status
                source_projection_limitations = result.source_projection_limitations
                source_unmapped_count = result.source_unmapped_count
                source_unmapped_indexes = result.source_unmapped_indexes
            _merge_scan_result(name, result, aibom, collected, scan_failures)
            surfaces_scanned.extend(result.surfaces_scanned)
            surfaces_excluded.extend(result.surfaces_excluded)
            scan_failures.extend(result.scan_failures)
            failures_by[name] = scan_failures[failure_count:]
            excluded_by[name] = list(result.surfaces_excluded)
            # A collector that produced a conflicting duplicate component or a
            # dangling dependency edge has failed even when its own ScanResult
            # reports no failure. Derive both coverage records from the same
            # delta so the emitted claim cannot list a failed collector as
            # completed, or call the inventory OBSERVED on the strength of it.
            scanner_status[name] = (
                "failed"
                if len(scan_failures) > failure_count
                else "partial"
                if result.surfaces_excluded
                else "complete"
            )
            if scanner_status[name] != "failed":
                completed.append(name)
            state = "" if scanner_status[name] == "complete" else f" ({scanner_status[name]})"
            click.echo(f"    Found {len(result.components)} components{state}", err=True)
        except Exception as exc:
            summary = _scanner_error_summary(exc)
            echo_line("  Scanner '", name, "' failed: ", summary, err=True)
            if _debug_enabled():
                _print_traceback(exc)
            scan_failures.append(f"{name}: {summary}")
            failures_by[name] = scan_failures[failure_count:]
            scanner_status[name] = "failed"
    failure_count, exclusion_count = len(scan_failures), len(surfaces_excluded)
    try:
        # Manifest problems are recorded like collector failures; the inventory is still written.
        assemble_repository_agent(
            aibom,
            root,
            exclude_paths=policy.scan.exclude_paths,
            failures=scan_failures,
            exclusions=surfaces_excluded,
            surfaces=surfaces_scanned,
        )
    except (PolicyError, ValueError, OSError) as exc:
        raise _failure(exc) from exc
    if len(scan_failures) > failure_count:
        failures_by[MANIFEST] = scan_failures[failure_count:]
    if len(surfaces_excluded) > exclusion_count:
        excluded_by[MANIFEST] = surfaces_excluded[exclusion_count:]
    graph_failures = validate_graph(aibom)
    scan_failures.extend(graph_failures)
    if graph_failures:
        failures_by["graph"] = graph_failures
    aibom.metadata.completeness = CompletenessClaim(
        scope="repository+shadowscan" if source_report_digest else "repository",
        source_report_digest=source_report_digest,
        source_report_content_digest=source_report_content_digest,
        source_report_content_profile=source_report_content_profile,
        source_report_format=source_report_format,
        source_report_status=source_report_status,
        source_projection_limitations=source_projection_limitations,
        source_unmapped_count=source_unmapped_count,
        source_unmapped_indexes=source_unmapped_indexes,
        surfaces_scanned=sorted(set(surfaces_scanned)),
        surfaces_excluded=sorted(set(surfaces_excluded)),
        scan_failures=scan_failures,
        timestamp=aibom.metadata.timestamp,
        assurance_level=AssuranceLevel.OBSERVED if completed else AssuranceLevel.DECLARED,
        scanner_status=scanner_status,
        collectors_requested=list(selected),
        collectors_completed=completed,
        exclusions=sorted(
            {*policy.scan.exclude_paths, *(f"**/{name}" for name in DEFAULT_EXCLUDES)}
        ),
        unobserved_surfaces=[
            "runtime",
            "effective-identity",
            "effective-authorization",
            "live-tools",
            "network",
        ],
    )
    scorer = RiskScorer.from_policy(policy.risk)
    passed, risk_report = scorer.passes_gate(aibom)
    report_mode = report_only or policy.scan.failure_mode == "report-only"
    staged = _staged_inventory()

    if not check_only:
        if source_report_digest and output_format == "sarif":
            raise click.ClickException(
                "SARIF cannot preserve imported discovery coverage; use native JSON, CycloneDX "
                "or SPDX."
            )
        try:
            out_data = _render_aibom(aibom, output_format, root)
        except (ValueError, RecursionError) as exc:
            # Export checks quote inventory values; name the format, never the values.
            if _debug_enabled():
                _print_traceback(exc)
            raise click.ClickException(
                f"The inventory cannot be exported as {output_format}: the export failed its "
                "schema or consistency checks. Write native JSON to inspect the inventory, or "
                "rerun with --debug before the command for details."
            ) from exc
        if output:
            write_cli_output(Path(output), out_data)
            if not staged:
                echo_line("Saved ", output, err=True)
        else:
            click.echo(json_text(out_data))

    if risk_report.warning_threshold_exceeded:
        click.echo(f"Risk warning: score {risk_report.overall_score:.1f}", err=True)
    if not scan_failures and passed:
        print_lines([("Scan gate passed", "green")], err=True)
        return
    heading = "Scan gate failed (report only: exit status 0)" if report_mode else "Scan gate failed"
    document = {
        **risk_report.to_dict(),
        "fail_on_severity": scorer.fail_on_severity,
        "score_threshold": scorer.fail_threshold,
    }
    not_collected = sorted(set(all_scanners) - set(selected))
    gate = scan_gate_lines(
        document, failures_by, excluded_by, not_collected, recorded=not (check_only or staged)
    )
    print_lines([(heading, "yellow" if report_mode else "red"), *gate], err=True)
    if not report_mode:
        raise click.exceptions.Exit(1)


@main.command("import-shadowscan")
@click.argument("report_path", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), required=True, help="Output AIBOM path")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "cyclonedx", "spdx", "sarif"]),
    default="json",
    help="Output format (default: json). sarif is refused: it cannot carry imported coverage.",
)
@click.option("--report-only", is_flag=True, help="Emit imported claims without a CI gate failure")
def import_shadowscan(
    report_path: str, output: str, output_format: str, report_only: bool = False
) -> None:
    """Import a Nexus-ShadowScan report and generate an AIBOM of imported claims.

    This is the recommended primary workflow: run ShadowScan for discovery,
    then Nexus SymBiote for verification, integrity, and BOM emission.
    """
    from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

    importer = ShadowScanImporter()
    try:
        imported = importer.read_report(Path(report_path))
    except (ValueError, TypeError, OSError, UnicodeError, RecursionError) as exc:
        raise click.ClickException("Failed to safely import the ShadowScan report") from exc

    aibom = imported.to_native_bom()
    aibom.finalize()

    if output_format == "sarif":
        raise click.ClickException(
            "SARIF cannot preserve imported discovery coverage; use native JSON, CycloneDX or SPDX."
        )
    if output_format == "cyclonedx":
        from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator

        out_data = CycloneDXGenerator().generate_json(aibom)
    elif output_format == "spdx":
        from nexus_symbiote.generators.spdx import SPDXGenerator

        out_data = SPDXGenerator().generate_json(aibom)
    else:
        try:
            out_data = aibom.to_native_json()
        except NativeFormatError as exc:
            raise click.ClickException(f"Inventory not written. {exc}") from exc

    try:
        write_output_file(Path(output), out_data, overwrite=False)
    except FileExistsError as exc:
        raise click.ClickException("Cannot create output; choose a new output path") from exc
    except (OSError, ValueError) as exc:
        raise output_failure(exc) from exc
    echo_line(
        "Imported ",
        len(imported.components),
        " components and saved ",
        output,
        "; discovery coverage remains partial.",
        err=True,
    )
    if report_only:
        return
    if imported.source_status != "complete":
        raise click.ClickException("ShadowScan source report is incomplete; the BOM is partial")
    raise click.ClickException("Imported claims do not establish complete verified coverage")


@main.command("verify-artifact")
@click.argument("artifact_path")
@click.option(
    "--project",
    required=True,
    type=click.Path(exists=True, file_okay=False),
    help="Trusted project root; ARTIFACT_PATH is relative to it",
)
@click.option(
    "--sha256", "expected_digest", required=True, help="Expected sha256:<hex> from a trusted source"
)
@click.option(
    "--bundle", type=click.Path(exists=True, dir_okay=False), help="Optional Sigstore bundle"
)
@click.option("--signer-identity", help="Expected Sigstore signing identity")
@click.option("--issuer", help="Expected Sigstore OIDC issuer")
def verify_artifact(
    artifact_path: str,
    project: str,
    expected_digest: str,
    bundle: str | None,
    signer_identity: str | None,
    issuer: str | None,
) -> None:
    """Verify a local artifact's digest and optionally its Sigstore bundle."""
    import hmac

    from nexus_symbiote.scanners.base import read_regular_text
    from nexus_symbiote.utils.confined import hash_confined_file
    from nexus_symbiote.utils.crypto import SIGSTORE_MISSING, verify_sigstore_digest

    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest):
        raise click.BadParameter(
            "Expected SHA-256 must be sha256:<64 lowercase hexadecimal characters>",
            param_hint="'--sha256'",
        )
    if bool(bundle) != bool(signer_identity and issuer) or (
        not bundle and (signer_identity or issuer)
    ):
        raise click.UsageError("--bundle, --signer-identity and --issuer must be supplied together")
    try:
        digest = hash_confined_file(_project_root(project, label="--project"), artifact_path)
    except OSError as exc:
        raise click.ClickException(
            "Cannot safely hash the artifact within the project root"
        ) from exc
    if not hmac.compare_digest(digest, expected_digest):
        raise click.ClickException("Artifact digest mismatch")
    if bundle:
        try:
            bundle_bytes = read_regular_text(Path(bundle)).encode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise click.ClickException("Cannot safely read the Sigstore bundle") from exc
        if signer_identity is None or issuer is None:
            raise click.UsageError(
                "--bundle, --signer-identity and --issuer must be supplied together"
            )
        verified = verify_sigstore_digest(digest, bundle_bytes, signer_identity, issuer)
        if not verified.verified:
            if verified.error == SIGSTORE_MISSING:
                raise click.ClickException(SIGSTORE_MISSING)
            raise click.ClickException("Sigstore signature or signer policy verification failed")
        click.echo(
            "Artifact digest and Sigstore signer policy verified. This does not establish artifact safety or a deployment binding."
        )
    else:
        click.echo(
            "Artifact bytes match the expected digest. Signer, artifact safety, and deployment binding were not verified."
        )


@main.command("verify-discovery")
@click.argument("aibom_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("report_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--projection", is_flag=True, help="Rebuild and compare the direct native import.")
@click.option(
    "--bundle",
    type=click.Path(exists=True, dir_okay=False),
    help="Verify the report producer's Sigstore bundle and the direct native projection.",
)
@click.option("--signer-identity", help="Expected report signer from operator policy.")
@click.option("--issuer", help="Expected OIDC issuer from operator policy.")
def verify_discovery(
    aibom_path: str,
    report_path: str,
    projection: bool,
    bundle: str | None,
    signer_identity: str | None,
    issuer: str | None,
) -> None:
    """Verify source bytes and optionally their native projection and producer."""
    import hashlib
    import hmac

    from nexus_symbiote.core.hashing import parse_json_strict
    from nexus_symbiote.scanners.base import read_regular_text
    from nexus_symbiote.scanners.shadowscan import MAX_REPORT_BYTES, ShadowScanImporter
    from nexus_symbiote.utils.crypto import SIGSTORE_MISSING, verify_sigstore_digest

    if any(x is not None for x in (bundle, signer_identity, issuer)) and not all(
        (bundle, signer_identity, issuer)
    ):
        raise click.UsageError("--bundle, --signer-identity and --issuer must be supplied together")
    try:
        doc = parse_json_strict(
            read_regular_text(Path(aibom_path), max_bytes=MAX_REPORT_BYTES),
            max_bytes=MAX_REPORT_BYTES,
        )
        bom = AIBOM.model_validate(doc)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise click.ClickException(f"Cannot safely read the BOM: {_input_problem(exc)}") from exc
    try:
        text = read_regular_text(Path(report_path), max_bytes=MAX_REPORT_BYTES)
    except (OSError, ValueError, UnicodeError) as exc:
        raise click.ClickException(
            f"Cannot safely read the discovery report: {_input_problem(exc)}"
        ) from exc
    claim = bom.metadata.completeness
    expected = claim.source_report_digest if claim else None
    if not isinstance(expected, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected):
        raise click.ClickException("BOM does not contain a valid ShadowScan report digest")
    actual = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise click.ClickException("Discovery report digest mismatch")
    if projection or bundle:
        try:
            projected = ShadowScanImporter().parse_report(text).to_native_bom().to_dict()
            # Import time and UUID are generated on each run. Everything else,
            # including unknown fields in the original JSON, must match.
            for field in ("timestamp", "serial_number"):
                projected["metadata"].pop(field)
                if not isinstance(doc["metadata"].pop(field, None), str):
                    raise ValueError("missing generated metadata")
            if json.dumps(projected, sort_keys=True) != json.dumps(doc, sort_keys=True):
                raise ValueError("projection differs")
        except (KeyError, TypeError, ValueError, RecursionError) as exc:
            raise click.ClickException(
                "BOM does not match the direct native ShadowScan projection"
            ) from exc
    if bundle and signer_identity and issuer:
        try:
            bundle_bytes = read_regular_text(Path(bundle)).encode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise click.ClickException("Cannot safely read the Sigstore bundle") from exc
        verified = verify_sigstore_digest(actual, bundle_bytes, signer_identity, issuer)
        if not verified.verified:
            if verified.error == SIGSTORE_MISSING:
                raise click.ClickException(SIGSTORE_MISSING)
            raise click.ClickException(
                "ShadowScan report signature or signer policy verification failed"
            )
        click.echo(
            "Report signer and direct native projection verified. Discovery claims retain declared assurance."
        )
    elif projection:
        click.echo(
            "Report bytes and direct native projection match. Producer identity is unverified."
        )
    else:
        click.echo(
            "Report bytes match the recorded digest. Source identity, signature, and truth were not verified."
        )


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option(
    "--project",
    type=click.Path(exists=True, file_okay=False),
    help="Project root for cross-validation; the only source of a project policy",
)
@click.option(
    "--signature-policy",
    type=click.Path(exists=True, path_type=Path),
    help="Explicit operator signer policy JSON; requires --project",
)
@click.option(
    "--no-project-policy",
    is_flag=True,
    help="Use built-in policy without reading configuration from the target.",
)
@click.option(
    "--skip-integrity",
    is_flag=True,
    help=(
        "Check completeness only and report integrity as skipped, for a repository whose "
        "models cannot be signed yet. The skip is printed and recorded in --json-output."
    ),
)
@click.option("--json-output", is_flag=True, help="Print the validation report as JSON.")
@click.option(
    "--require-discovery-signature",
    is_flag=True,
    help=(
        "Require the operator signature policy to verify any ShadowScan report the inventory "
        "records or the project contains, whatever the project policy says; requires --project."
    ),
)
def validate(
    aibom_path: str,
    project: str | None,
    signature_policy: Path | None = None,
    no_project_policy: bool = False,
    skip_integrity: bool = False,
    json_output: bool = False,
    require_discovery_signature: bool = False,
) -> None:
    """Validate an AIBOM for completeness and integrity.

    Without --project only the inventory's own claims are checked: its coverage claim
    and its self-consistency. With --project the inventory is compared with a fresh
    local collection of that project, unless the policy skips the completeness check.
    """
    bom = _load_bom(aibom_path)

    from nexus_symbiote.validators.completeness import (
        CompletenessValidator,
        assurance_problems,
        carries_discovery_evidence,
        discovery_producer_check,
        discovery_signature_required,
    )
    from nexus_symbiote.validators.integrity import IntegrityValidator

    if require_discovery_signature and not project:
        raise click.BadParameter(
            "--require-discovery-signature requires --project",
            param_hint="--require-discovery-signature",
        )
    root = _project_root(project, label="--project") if project else None
    if root is not None:
        _require_binding_key()
    signature_policies = _signer_policies(signature_policy, root)
    policy, policy_source, policy_weakened = _inventory_policy(
        root, aibom_path, ignore_project=no_project_policy, warn=not json_output
    )
    minimum = policy.validation.minimum_assurance_level
    if minimum == "verified":
        raise click.ClickException(
            "offline validate cannot establish verified assurance; use subject-bound cryptographic verification"
        )
    passed = True
    # Only the reconciliation below may claim that the inventory was compared with the project.
    basis = "project-not-reconciled" if root is not None else "supplied-bom"
    bound_imports: frozenset[str] = frozenset()
    completeness: dict[str, Any] = {"status": "skipped", "skipped_by": "policy"}
    if policy.validation.require_completeness:
        cv = CompletenessValidator()
        c_report = (
            cv.validate_against_project(
                bom,
                root,
                exclude_paths=policy.scan.exclude_paths,
                signature_policies=signature_policies,
            )
            if root is not None
            else cv.validate(bom)
        )
        completeness = {"status": "pass" if c_report.is_complete else "fail", **c_report.to_dict()}
        bound_imports = c_report.bound_imports
        if root is not None:
            # The risk command's vocabulary: reconciled, with supplier claims, or failed.
            basis = c_report.basis
        passed = passed and c_report.is_complete
    integrity: dict[str, Any] = {"status": "skipped", "skipped_by": "--skip-integrity"}
    if not skip_integrity:
        if policy.validation.require_integrity:
            i_report = IntegrityValidator(signature_policies=signature_policies).validate(
                bom, root, exclude_paths=policy.scan.exclude_paths, bound_imports=bound_imports
            )
            integrity = i_report.to_dict()
            passed = passed and i_report.is_valid
        else:
            integrity = {"status": "skipped", "skipped_by": "policy"}
    discovery: dict[str, Any] | None = None
    if root is not None and discovery_signature_required(
        policy.validation.require_discovery_signature or require_discovery_signature,
        root,
        signature_policies,
    ):
        status, problems = discovery_producer_check(
            bom, root, signature_policies, exclude_paths=policy.scan.exclude_paths
        )
        discovery = {"status": status, "problems": problems}
        passed = passed and not problems
    elif carries_discovery_evidence(bom):
        discovery = {"status": "not-verified", "problems": []}
    assurance_errors = assurance_problems(bom, minimum, imported_claims=bound_imports)
    # Graph integrity is structural and cannot be disabled by a coverage policy.
    graph_issues = validate_graph(bom)
    passed = passed and not assurance_errors and not graph_issues
    document = {
        "passed": passed,
        "assessment_basis": basis,
        "policy_source": policy_source,
        "policy_weakened": policy_weakened,
        "completeness": completeness,
        "integrity": integrity,
        "discovery_producer": discovery,
        "minimum_assurance_level": minimum,
        "assurance_errors": assurance_errors,
        "graph_issues": graph_issues,
    }
    if json_output:
        click.echo(json_text(json.dumps(document, indent=2)))
    else:
        print_lines(validation_report_lines(document, project=root))
    if not passed:
        raise click.exceptions.Exit(1)


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option(
    "--threshold",
    type=float,
    default=None,
    help="Fail when the aggregate score reaches this positive value (default: from policy, built-in 50).",
)
@click.option(
    "--no-score-threshold",
    is_flag=True,
    help=(
        "Do not gate on the aggregate score. Findings at or above --fail-on-severity, "
        "unverified SafeTensors, incomplete coverage and missing evidence still fail the gate."
    ),
)
@click.option("--json-output", is_flag=True, help="Output as JSON")
@click.option(
    "--project",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help=(
        "Reconcile the supplied BOM against this project's static evidence before scoring; "
        "the only source of a project policy."
    ),
)
@click.option(
    "--signature-policy",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Explicit operator signer policy for model recollection; requires --project.",
)
@click.option(
    "--fail-on-severity",
    type=click.Choice(["critical", "high", "medium", "low", "info", "none"]),
    default=None,
    help="Fail on any finding at or above this severity (default: from policy, built-in critical); none disables it.",
)
@click.option(
    "--no-project-policy",
    is_flag=True,
    help="Use built-in policy without reading configuration from the target.",
)
@click.option(
    "--require-discovery-signature",
    is_flag=True,
    help=(
        "Require the operator signature policy to verify any ShadowScan report the inventory "
        "records or the project contains, whatever the project policy says; requires --project."
    ),
)
def risk(
    aibom_path: str,
    threshold: float | None,
    json_output: bool,
    fail_on_severity: str | None,
    no_project_policy: bool = False,
    project: Path | None = None,
    signature_policy: Path | None = None,
    no_score_threshold: bool = False,
    require_discovery_signature: bool = False,
) -> None:
    """Score supply-chain risks in an AIBOM."""
    bom = _load_bom(aibom_path)

    from nexus_symbiote.validators.completeness import carries_discovery_evidence
    from nexus_symbiote.validators.risk import RiskReport, RiskScorer

    if no_score_threshold and threshold is not None:
        raise click.UsageError("--threshold and --no-score-threshold cannot be combined")
    if require_discovery_signature and project is None:
        raise click.BadParameter(
            "--require-discovery-signature requires --project",
            param_hint="--require-discovery-signature",
        )
    root = _project_root(project, label="--project") if project else None
    if root is not None:
        _require_binding_key()
    signature_policies = _signer_policies(signature_policy, root)
    policy, policy_source, policy_weakened = _inventory_policy(
        root, aibom_path, ignore_project=no_project_policy, warn=not json_output
    )
    threshold_from_cli = threshold is not None or no_score_threshold
    threshold = threshold if threshold is not None else policy.risk.fail_threshold
    if threshold <= 0 or not math.isfinite(threshold):
        raise click.BadParameter("threshold must be positive and finite", param_hint="--threshold")
    severity = fail_on_severity or policy.risk.fail_on_severity
    context = {
        "fail_on_severity": severity,
        "score_threshold": None if no_score_threshold else threshold,
        "policy_source": policy_source,
        "policy_weakened": policy_weakened,
    }
    basis = "supplied-bom"
    supplier_claims: list[dict[str, str]] = []
    supplier_claims_omitted = 0
    producer = "not-verified" if carries_discovery_evidence(bom) else "not-applicable"
    if root is not None:
        from nexus_symbiote.validators.completeness import (
            CompletenessValidator,
            discovery_producer_check,
            discovery_signature_required,
        )

        checked = CompletenessValidator().validate_against_project(
            bom,
            root,
            exclude_paths=policy.scan.exclude_paths,
            signature_policies=signature_policies,
        )
        discovery: list[str] = []
        if discovery_signature_required(
            policy.validation.require_discovery_signature or require_discovery_signature,
            root,
            signature_policies,
        ):
            producer, discovery = discovery_producer_check(
                bom, root, signature_policies, exclude_paths=policy.scan.exclude_paths
            )
        if not checked.is_complete or discovery:
            reasons = [
                issue.description
                for issue in checked.issues
                if issue.severity in {"error", "unknown"}
            ]
            reasons.extend(discovery)
            # The same keys as a scored report, so consumers need not special-case it.
            failed = {
                **RiskReport().to_dict(),
                "passed": False,
                "assessment_basis": "project-reconciliation-failed",
                "overall_score": None,
                "risk_level": "unknown",
                "coverage_status": "unreconciled",
                "gate_reasons": reasons,
                "total_components": len(bom.components),
                "supplier_claims": [],
                "supplier_claims_omitted": 0,
                "discovery_producer": producer,
                **context,
            }
            if json_output:
                click.echo(json_text(json.dumps(failed, indent=2)))
            else:
                print_lines(risk_report_lines(failed))
            raise click.exceptions.Exit(1)
        basis = checked.basis
        supplier_claims = [
            {"subject": c.subject, "kind": c.kind, "detail": c.detail}
            for c in checked.supplier_claims
        ]
        supplier_claims_omitted = checked.supplier_claims_omitted
    scorer = RiskScorer.from_policy(
        policy.risk,
        # The scorer requires a finite threshold; none can be reached by a sum of weights.
        fail_threshold=sys.float_info.max if no_score_threshold else threshold,
        fail_on_severity=fail_on_severity,
    )
    passed, report = scorer.passes_gate(bom)
    gate = {
        **report.gate,
        **_gate_sources(policy, policy_source, threshold_from_cli, fail_on_severity),
    }
    if no_score_threshold:
        gate["fail_threshold"] = None
    document = {
        **report.to_dict(),
        "gate": gate,
        "passed": passed,
        "assessment_basis": basis,
        "supplier_claims": supplier_claims,
        "supplier_claims_omitted": supplier_claims_omitted,
        "discovery_producer": producer,
        **context,
    }
    if json_output:
        click.echo(json_text(json.dumps(document, indent=2)))
    else:
        # Upstream's gate report lists the inventory's own collection failures.
        coverage = bom.metadata.completeness
        failures = list(coverage.scan_failures) if coverage else []
        print_lines(risk_report_lines(document, failures=failures))
    if not passed:
        raise click.exceptions.Exit(1)


@main.command()
@click.argument("old_path", type=click.Path(exists=True))
@click.argument("new_path", type=click.Path(exists=True))
@click.option("--json-output", is_flag=True, help="Output as JSON")
@click.option(
    "--fail-on-alert", is_flag=True, help="Exit with status 1 if the diff reports a security alert."
)
def diff(old_path: str, new_path: str, json_output: bool, fail_on_alert: bool = False) -> None:
    """Compare two AIBOM snapshots for supply-chain drift."""
    old_bom = _load_bom(old_path)
    new_bom = _load_bom(new_path)

    from nexus_symbiote.diff.differ import AIBOMDiffer

    result = AIBOMDiffer().diff(old_bom, new_bom)
    document = result.to_dict()
    if json_output:
        click.echo(json_text(json.dumps(document, indent=2)))
    else:
        print_lines(diff_report_lines(document))
    if fail_on_alert and result.security_alerts:
        raise click.exceptions.Exit(1)


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option("--json-output", is_flag=True, help="Print the summary as JSON.")
def summary(aibom_path: str, json_output: bool = False) -> None:
    """Print a summary of an AIBOM."""
    bom = _load_bom(aibom_path)
    s = bom.summary()
    if json_output:
        claim = bom.metadata.completeness
        document = {
            **s,
            "completeness": claim.model_dump(mode="json", exclude_none=True) if claim else None,
        }
        click.echo(json_text(json.dumps(document, indent=2)))
        return
    lines: list[ReportLine] = [
        ("AIBOM Summary", "bold"),
        (f"  Components: {s['total_components']}", None),
        (f"  Dependencies: {s['total_dependencies']}", None),
        (f"  Risks: {s['total_risks']}", None),
    ]
    if s["component_types"]:
        lines.append(("  Component types:", None))
        for ctype, count in sorted(s["component_types"].items()):
            lines.append((safe_line("    - ", ctype, ": ", count), None))
    if s["risk_breakdown"]:
        lines.append(("  Risk breakdown:", None))
        for sev, count in sorted(s["risk_breakdown"].items()):
            lines.append((safe_line("    - ", sev, ": ", count), None))
    print_lines(lines)


@main.command("blast-radius")
@click.argument("aibom_path", type=click.Path(exists=True))
@click.argument("component_ref")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def blast_radius_command(aibom_path: str, component_ref: str, json_output: bool) -> None:
    """Show repository dependencies potentially affected by a component compromise."""
    from nexus_symbiote.graph import blast_radius

    bom = _load_bom(aibom_path)
    try:
        result = blast_radius(bom, component_ref)
    except ValueError as exc:
        raise _failure(exc) from exc
    if json_output:
        click.echo(json_text(json.dumps(result, indent=2)))
        return
    print_lines(
        [
            (
                "Potential blast radius (repository association; effective authority unknown)",
                "bold",
            ),
            (safe_line("  Agents: ", ", ".join(result["affected_agents"])), None),
            (safe_line("  Dependents: ", ", ".join(result["dependent_components"])), None),
            (safe_line("  Components: ", ", ".join(result["reachable_components"])), None),
            *((safe_line("  Note: ", note), None) for note in result["limitations"][1:]),
        ]
    )


@main.command()
@click.option("--force", is_flag=True, help="Overwrite the existing project policy file")
@click.option(
    "--path",
    type=click.Path(),
    default=".",
    help="Directory to create .nexus-symbiote.yaml in",
)
def init(force: bool, path: str) -> None:
    """Initialize a .nexus-symbiote.yaml policy configuration."""
    from nexus_symbiote.policy import DEFAULT_POLICY_YAML, POLICY_FILE_NAMES

    # absolute(), not resolve(): a symlinked directory is refused like any other output.
    directory = Path(path).absolute()
    try:
        existing = [
            directory / name
            for name in POLICY_FILE_NAMES
            if (directory / name).exists() or (directory / name).is_symlink()
        ]
    except OSError as exc:
        raise output_failure(exc) from exc
    # A second policy name would shadow, or be shadowed by, the existing one.
    target = existing[0] if len(existing) == 1 else directory / POLICY_FILE_NAMES[0]
    if len(existing) > 1:
        echo_line(
            "Warning: both ",
            POLICY_FILE_NAMES[0],
            " and ",
            POLICY_FILE_NAMES[1],
            " exist in ",
            directory,
            "; keep one policy file.",
            err=True,
        )
        sys.exit(1)
    if existing and not force:
        echo_line("Warning: ", target, " already exists. Use --force to overwrite.", err=True)
        sys.exit(1)

    write_cli_output(target, DEFAULT_POLICY_YAML, overwrite=force)
    echo_line("Created ", target)
    click.echo("  Edit this file to customize scan, risk, and validation policies.")


register_runtime_commands(main)
register_live_commands(main)
register_supply_chain_commands(main)

if __name__ == "__main__":
    main()
