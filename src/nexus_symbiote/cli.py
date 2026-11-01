"""Nexus SymBiote CLI — Agent Bill of Materials for AI supply chain security.

Architecture: Nexus-ShadowScan is the primary multi-surface discovery engine.
Nexus SymBiote consumes its reports (or local project files) to perform verification,
integrity checks, risk scoring, policy evaluation, and standards-grade BOM
generation (native, CycloneDX 1.7, SPDX 3.0, SARIF).

Exit codes: 0 pass; 1 gate, validation, or diff-threshold failure; 2 usage or input
error; 3 unexpected internal error.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from nexus_symbiote import __version__
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import (
    AIBOMMetadata,
    CompletenessClaim,
    IDEAgentComponent,
    MCPClientComponent,
)
from nexus_symbiote.core.redact import redact_aibom, redact_string
from nexus_symbiote.core.vocab import (
    SCANNER_COMPLETE,
    SCANNER_FAILED,
    SCANNER_NAMES,
    SCANNER_PARTIAL,
    SCANNER_UNKNOWN,
)
from nexus_symbiote.utils.fsio import write_text_safely

if TYPE_CHECKING:
    from nexus_symbiote.policy import Policy
    from nexus_symbiote.scanners.base import Scanner

console = Console(stderr=True)
err_console = Console(stderr=True)

PROVENANCE_NOTE = (
    "Provenance: self-asserted. Completeness and risk findings in this document are not "
    "independently verified."
)
SCANNER_REGISTRY: dict[str, type[Scanner]] = {}

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_ASSURANCE_ORDER = (AssuranceLevel.DECLARED, AssuranceLevel.OBSERVED, AssuranceLevel.VERIFIED)


class _Group(click.Group):
    """Top-level group. An unexpected error prints one line and exits 3, unless debugging."""

    def main(self, *args: Any, **kwargs: Any) -> Any:
        try:
            return super().main(*args, **kwargs)
        except Exception as exc:
            if os.environ.get("NEXUS_SYMBIOTE_DEBUG") == "1":
                raise
            click.echo(f"internal error: {type(exc).__name__}", err=True)
            sys.exit(3)


@click.group(cls=_Group)
@click.version_option(version=__version__, prog_name="nexus-symbiote")
def main() -> None:
    """Nexus SymBiote — Agent Bill of Materials for AI supply chain security."""


def _get_scanners() -> dict[str, type[Scanner]]:
    """Built-in scanner classes keyed by name. Entries already in SCANNER_REGISTRY win."""
    from nexus_symbiote.scanners import ALL_SCANNERS

    built_in = {cls.name: cls for cls in ALL_SCANNERS}
    if set(built_in) != set(SCANNER_NAMES):
        raise RuntimeError("scanner registry does not match SCANNER_NAMES")
    for name, cls in built_in.items():
        SCANNER_REGISTRY.setdefault(name, cls)
    return SCANNER_REGISTRY


def _build_scanner(
    name: str, cls: type[Scanner], policy: Policy | None, shadowscan_report: Path | None
) -> Scanner:
    kwargs: dict[str, Any] = {}
    if policy is not None:
        kwargs["exclude_paths"] = policy.scan.exclude_paths
    if name == "shadowscan" and shadowscan_report is not None:
        kwargs["trusted_report"] = shadowscan_report
    return cls(**kwargs)


def _resolve_policy(
    policy_arg: str | None, discover_from: Path | None
) -> tuple[Policy | None, Path | None]:
    """Resolve --policy. 'none' disables policy; when omitted, discover only if asked to."""
    from nexus_symbiote.policy import PolicyError, discover_policy, load_policy_file

    if policy_arg == "none":
        return None, None
    if policy_arg is not None:
        path = Path(policy_arg)
    else:
        found = discover_policy(discover_from) if discover_from is not None else None
        if found is None:
            return None, None
        path = found
    try:
        return load_policy_file(path), path
    except (PolicyError, OSError) as exc:
        raise click.UsageError(str(exc)) from exc


def _load_aibom(path: Path) -> AIBOM:
    try:
        return AIBOM.load(path)
    except (OSError, ValueError) as exc:
        raise click.UsageError(
            f"{path} is not a valid native AIBOM file ({type(exc).__name__})"
        ) from exc


def _write_file(path: Path, text: str, *, overwrite: bool = True) -> None:
    try:
        write_text_safely(path, text, overwrite=overwrite)
    except OSError as exc:
        raise click.UsageError(f"cannot write {path}: {exc}") from exc


def _render(aibom: AIBOM, output_format: str) -> str:
    if output_format == "cyclonedx":
        from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator

        return CycloneDXGenerator().generate_json(aibom)
    if output_format == "spdx":
        from nexus_symbiote.generators.spdx import SPDXGenerator

        return SPDXGenerator().generate_json(aibom)
    if output_format == "sarif":
        from nexus_symbiote.generators.sarif import SARIFGenerator

        return SARIFGenerator().generate_json(aibom)
    return aibom.to_json()


def _make_paths_relative(aibom: AIBOM, root: Path) -> None:
    """Make absolute paths under the scanned root project-relative (POSIX)."""
    from nexus_symbiote.scanners.base import relative_posix

    def relative(value: str) -> str:
        path = Path(value)
        return relative_posix(path, root) if path.is_absolute() else value

    for comp in aibom.components:
        if comp.source_path:
            comp.source_path = relative(comp.source_path)
        if isinstance(comp, MCPClientComponent) and comp.config_path:
            comp.config_path = relative(comp.config_path)
        if isinstance(comp, IDEAgentComponent):
            comp.config_files = [relative(entry) for entry in comp.config_files]


def _assurance_rank(level: str) -> int:
    return _ASSURANCE_ORDER.index(AssuranceLevel(level))


def _at_or_above(severity: str | None, level: str) -> bool:
    if level == "none" or severity is None:
        return False
    return _SEVERITY_RANK.get(severity, -1) >= _SEVERITY_RANK[level]


@main.command()
@click.argument("project_path", type=click.Path(exists=True), default=".")
@click.option("-o", "--output", type=click.Path(), help="Output file path (default: stdout)")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "cyclonedx", "spdx", "sarif"]),
    default=None,
    help="Output format (default: json, or the policy's default_format)",
)
@click.option(
    "--scanner",
    "scanners",
    type=click.Choice(list(SCANNER_NAMES)),
    multiple=True,
    help="Scanner to run; repeat for several (default: all, or the policy's list). "
    "Prefer 'shadowscan' for primary discovery.",
)
@click.option(
    "--policy",
    "policy_arg",
    default=None,
    help="Policy file, or 'none' to ignore policy. Default: discover .nexus-symbiote.yaml "
    "from the project root upward.",
)
@click.option(
    "--shadowscan-report",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="ShadowScan report to import. Used only by the shadowscan scanner.",
)
def scan(
    project_path: str,
    output: str | None,
    output_format: str | None,
    scanners: tuple[str, ...],
    policy_arg: str | None,
    shadowscan_report: str | None,
) -> None:
    """Scan a project and generate an AIBOM.

    Prefer Nexus-ShadowScan as the primary discovery source. Place a report at
    .shadowscan/report.json or use the import-shadowscan command.
    """
    root = Path(project_path).resolve()
    if not root.is_dir():
        raise click.UsageError(f"'{project_path}' is not a directory")

    policy, policy_path = _resolve_policy(policy_arg, discover_from=root)
    if not output_format:
        output_format = policy.output.default_format if policy is not None else "json"
    if scanners:
        requested = list(scanners)
    elif policy is not None:
        requested = list(policy.scan.scanners)
    else:
        requested = list(SCANNER_NAMES)
    selected = list(dict.fromkeys(requested))
    shadow_report = Path(shadowscan_report) if shadowscan_report else None
    registry = _get_scanners()

    err_console.print(f"[bold]Scanning[/] {escape(str(root))}")
    if policy_path is not None:
        err_console.print(f"  Policy: {escape(str(policy_path))}")

    aibom = AIBOM(metadata=AIBOMMetadata(authors=[]))
    surfaces_scanned: list[str] = []
    surfaces_excluded: list[str] = []
    scan_failures: list[str] = []
    scanner_status: dict[str, str] = dict.fromkeys(SCANNER_NAMES, SCANNER_UNKNOWN)

    for name in selected:
        err_console.print(f"  Running [cyan]{escape(name)}[/] scanner...")
        try:
            result = _build_scanner(name, registry[name], policy, shadow_report).scan(root)
        except Exception as exc:
            err_console.print(f"  [red]Scanner '{escape(name)}' failed:[/] {escape(str(exc))}")
            scan_failures.append(f"{name}: {exc}")
            scanner_status[name] = SCANNER_FAILED
            continue

        surfaces_scanned.extend(result.surfaces_scanned)
        surfaces_excluded.extend(result.surfaces_excluded)
        scan_failures.extend(result.scan_failures)
        status = SCANNER_COMPLETE
        if result.surfaces_excluded:
            status = SCANNER_PARTIAL
        if result.scan_failures:
            status = SCANNER_FAILED
        for comp in result.components:
            try:
                aibom.add_component(comp)
            except ValueError as exc:
                status = SCANNER_FAILED
                failure = f"{name}: component {comp.bom_ref} not added: {exc}"
                scan_failures.append(failure)
                err_console.print(f"  [red]{escape(failure)}[/]")
        scanner_status[name] = status
        err_console.print(f"    Found [green]{len(result.components)}[/] components")

    _make_paths_relative(aibom, root)
    redact_aibom(aibom)
    aibom.metadata.completeness = CompletenessClaim(
        scope="project:" + ",".join(sorted(set(selected))),
        surfaces_scanned=[redact_string(s) for s in surfaces_scanned],
        surfaces_excluded=[redact_string(s) for s in surfaces_excluded],
        scan_failures=[redact_string(s) for s in scan_failures],
        scanner_status=scanner_status,
        assurance_level=AssuranceLevel.OBSERVED,
    )

    out_data = _render(aibom, output_format)
    if output:
        _write_file(Path(output), out_data)
        err_console.print(f"[bold green]Saved[/] {escape(output)}")
    else:
        click.echo(out_data)

    if scan_failures:
        raise click.ClickException("Collection incomplete; see scan failures in the output")


@main.command("import-shadowscan")
@click.argument("report_path", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), required=True, help="Output AIBOM path")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "cyclonedx", "spdx", "sarif"]),
    default="json",
    help="Output format (default: json)",
)
def import_shadowscan(report_path: str, output: str, output_format: str) -> None:
    """Import a Nexus-ShadowScan report and generate an AIBOM.

    This is the recommended primary workflow: run ShadowScan for discovery,
    then SymBiote for verification, integrity, and BOM emission.
    """
    from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

    report = Path(report_path)
    try:
        components = ShadowScanImporter().import_report(report)
    except Exception as exc:
        raise click.UsageError(f"Failed to import ShadowScan report: {exc}") from exc

    aibom = AIBOM(metadata=AIBOMMetadata(authors=[]))
    failures: list[str] = []
    for comp in components:
        try:
            aibom.add_component(comp)
        except ValueError as exc:
            failures.append(f"shadowscan: component {comp.bom_ref} not added: {exc}")

    redact_aibom(aibom)
    scanner_status: dict[str, str] = dict.fromkeys(SCANNER_NAMES, SCANNER_UNKNOWN)
    scanner_status["shadowscan"] = SCANNER_FAILED if failures else SCANNER_COMPLETE
    aibom.metadata.completeness = CompletenessClaim(
        scope="shadowscan-import",
        surfaces_scanned=[report.name],
        scan_failures=[redact_string(s) for s in failures],
        scanner_status=scanner_status,
        assurance_level=AssuranceLevel.DECLARED,
    )

    _write_file(Path(output), _render(aibom, output_format))
    err_console.print(
        f"[bold green]Imported {len(components)} components and saved[/] {escape(output)}"
    )
    if failures:
        raise click.ClickException("Import incomplete; see scan failures in the output")


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option("--project", type=click.Path(exists=True), help="Project root for cross-validation")
@click.option(
    "--policy",
    "policy_arg",
    default=None,
    help="Policy file whose validation section sets the required checks, or 'none'. "
    "Never discovered.",
)
def validate(aibom_path: str, project: str | None, policy_arg: str | None) -> None:
    """Validate an AIBOM for completeness, integrity, and assurance."""
    from nexus_symbiote.policy import default_policy
    from nexus_symbiote.validators.completeness import CompletenessValidator
    from nexus_symbiote.validators.integrity import IntegrityValidator

    bom = _load_aibom(Path(aibom_path))
    policy, _ = _resolve_policy(policy_arg, discover_from=None)
    rules = (policy if policy is not None else default_policy()).validation

    console.print("[bold]Completeness check[/]")
    cv = CompletenessValidator()
    if project:
        c_report = cv.validate_against_project(bom, Path(project).resolve())
    else:
        c_report = cv.validate(bom)
    status = "[green]PASS[/]" if c_report.is_complete else "[red]FAIL[/]"
    console.print(f"  Status: {status}")
    if not c_report.is_complete and not rules.require_completeness:
        console.print("  [yellow]Not enforced:[/] require_completeness is false in the policy")
    console.print(f"  Components: {c_report.total_components}")
    for ci in c_report.issues:
        color = {"error": "red", "warning": "yellow", "info": "blue"}.get(ci.severity, "white")
        label = escape(f"[{ci.surface}] {ci.description}")
        console.print(f"  [{color}]{ci.severity.upper()}[/] {label}")
    completeness_ok = c_report.is_complete or not rules.require_completeness

    console.print("\n[bold]Integrity check[/]")
    iv = IntegrityValidator()
    project_root = Path(project).resolve() if project else None
    i_report = iv.validate(bom, project_root)
    status = "[green]PASS[/]" if i_report.is_valid else "[red]FAIL[/]"
    console.print(f"  Status: {status}")
    if not i_report.is_valid and not rules.require_integrity:
        console.print("  [yellow]Not enforced:[/] require_integrity is false in the policy")
    console.print(
        f"  Hashes verified: {i_report.hashes_verified}, failed: {i_report.hashes_failed}"
    )
    for ii in i_report.issues:
        color = {"critical": "red", "error": "red", "warning": "yellow"}.get(ii.severity, "white")
        label = escape(f"[{ii.component_ref}] {ii.detail}")
        console.print(f"  [{color}]{ii.severity.upper()}[/] {label}")
    integrity_ok = i_report.is_valid or not rules.require_integrity

    minimum = AssuranceLevel(rules.minimum_assurance_level)
    assurance_ok = True
    if minimum is not AssuranceLevel.DECLARED:
        console.print(f"\n[bold]Assurance check[/] (minimum: {minimum.value})")
        for comp in bom.components:
            if _assurance_rank(comp.assurance_level) < _assurance_rank(minimum.value):
                assurance_ok = False
                label = escape(f"[{comp.bom_ref}] assurance is {comp.assurance_level.value}")
                console.print(f"  [red]ERROR[/] {label}")
        status = "[green]PASS[/]" if assurance_ok else "[red]FAIL[/]"
        console.print(f"  Status: {status}")

    console.print(PROVENANCE_NOTE, soft_wrap=True)
    if not (completeness_ok and integrity_ok and assurance_ok):
        sys.exit(1)


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option(
    "--threshold",
    type=click.FloatRange(0, 100),
    default=None,
    help="Fail threshold score, 0-100 (default: the policy's fail_threshold, or 50).",
)
@click.option(
    "--policy",
    "policy_arg",
    default=None,
    help="Policy file for thresholds and ignored categories, or 'none'. Never discovered.",
)
@click.option("--json-output", is_flag=True, help="Output as JSON")
def risk(
    aibom_path: str, threshold: float | None, policy_arg: str | None, json_output: bool
) -> None:
    """Score supply-chain risks in an AIBOM."""
    from nexus_symbiote.policy import default_policy
    from nexus_symbiote.validators.risk import RiskScorer

    bom = _load_aibom(Path(aibom_path))
    policy, policy_path = _resolve_policy(policy_arg, discover_from=None)
    rules = (policy if policy is not None else default_policy()).risk
    fail_threshold = threshold if threshold is not None else rules.fail_threshold
    scorer = RiskScorer(
        fail_threshold=fail_threshold,
        warn_threshold=rules.warn_threshold,
        ignore_categories=tuple(rules.ignore_categories),
    )
    passed, report = scorer.passes_gate(bom)

    if json_output:
        payload = report.to_dict()
        payload["provenance"] = "self-asserted"
        payload["policy"] = str(policy_path) if policy_path is not None else None
        click.echo(json.dumps(payload, indent=2))
    else:
        level_colors = {
            "critical": "red",
            "high": "red",
            "moderate": "yellow",
            "clean": "green",
            "unknown": "yellow",
        }
        color = level_colors.get(report.risk_level, "yellow")
        console.print(
            f"[bold]Risk Score:[/] [{color}]{report.overall_score:.1f}[/] "
            f"({escape(report.risk_level)})"
        )
        console.print(
            f"  Components: {report.total_components} total, "
            f"{report.components_with_risks} with risks"
        )
        console.print(f"  Coverage: {escape(report.coverage_status)}")
        for reason in report.coverage_reasons:
            console.print(f"    - {escape(reason)}")
        if report.suppressed:
            console.print(f"  Suppressed by policy: {report.suppressed}")

        if report.severity_counts:
            console.print("  Severity breakdown:")
            for sev, count in sorted(report.severity_counts.items()):
                console.print(f"    {sev}: {count}")

        if report.findings:
            table = Table(title="Top Findings", show_lines=True)
            table.add_column("Severity", style="bold", width=10)
            table.add_column("Component", width=30)
            table.add_column("Category", width=20)
            table.add_column("Detail", width=50)

            for finding in report.findings[:15]:
                sev_color = {
                    "critical": "red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                }.get(finding.severity.value, "white")
                table.add_row(
                    f"[{sev_color}]{finding.severity.value}[/]",
                    escape(finding.component_name[:30]),
                    escape(finding.category),
                    escape(finding.detail[:50]),
                )
            console.print(table)

        gate = "[green]PASSED[/]" if passed else "[red]FAILED[/]"
        console.print(f"\nGate (threshold={fail_threshold}): {gate}")
        console.print(PROVENANCE_NOTE, soft_wrap=True)

    if not passed:
        sys.exit(1)


@main.command()
@click.argument("old_path", type=click.Path(exists=True))
@click.argument("new_path", type=click.Path(exists=True))
@click.option("--json-output", is_flag=True, help="Output as JSON")
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "info", "none"]),
    default="high",
    show_default=True,
    help="Exit 1 when the highest change severity is at or above this level. "
    "'none' never fails.",
)
def diff(old_path: str, new_path: str, json_output: bool, fail_on: str) -> None:
    """Compare two AIBOM snapshots for supply-chain drift."""
    from nexus_symbiote.diff.differ import AIBOMDiffer

    old_bom = _load_aibom(Path(old_path))
    new_bom = _load_aibom(Path(new_path))
    result = AIBOMDiffer().diff(old_bom, new_bom)
    highest = result.highest_severity()
    failed = _at_or_above(highest, fail_on)

    if json_output:
        click.echo(json.dumps(result.to_dict(), indent=2))
    elif not result.has_changes:
        console.print("[green]No changes detected.[/]")
    else:
        console.print(f"[bold]{result.total_changes} changes detected[/]")

        if result.security_alerts:
            console.print("\n[bold red]Security Alerts:[/]")
            for alert in result.security_alerts:
                label = escape(f"[{alert['severity'].upper()}] {alert['alert']}")
                console.print(f"  {label}")

        if result.components_added:
            console.print(f"\n[green]+{len(result.components_added)} added[/]")
            for c in result.components_added:
                console.print(f"  + {escape(c.name)} ({escape(c.component_type)})")
        if result.components_removed:
            console.print(f"\n[red]-{len(result.components_removed)} removed[/]")
            for c in result.components_removed:
                console.print(f"  - {escape(c.name)} ({escape(c.component_type)})")
        if result.components_modified:
            console.print(f"\n[yellow]~{len(result.components_modified)} modified[/]")
            for c in result.components_modified:
                details = escape("; ".join(c.details))
                console.print(f"  ~ {escape(c.name)}: {details}")

        if failed:
            console.print(
                f"\nHighest change severity: {highest} (--fail-on {fail_on}): [red]FAILED[/]"
            )

    if failed:
        sys.exit(1)


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
def summary(aibom_path: str) -> None:
    """Print a summary of an AIBOM."""
    bom = _load_aibom(Path(aibom_path))
    s = bom.summary()

    console.print("[bold]AIBOM Summary[/]")
    console.print(f"  Components: {s['total_components']}")
    console.print(f"  Dependencies: {s['total_dependencies']}")
    console.print(f"  Risks: {s['total_risks']}")

    if s["component_types"]:
        console.print("  Component types:")
        for ctype, count in sorted(s["component_types"].items()):
            console.print(f"    {escape(ctype)}: {count}")
    if s["risk_breakdown"]:
        console.print("  Risk breakdown:")
        for sev, count in sorted(s["risk_breakdown"].items()):
            console.print(f"    {escape(sev)}: {count}")


@main.command()
@click.option("--force", is_flag=True, help="Overwrite an existing .nexus-symbiote.yaml")
@click.option(
    "--path",
    type=click.Path(),
    default=".",
    help="Directory to create .nexus-symbiote.yaml in",
)
def init(force: bool, path: str) -> None:
    """Initialize a .nexus-symbiote.yaml policy configuration."""
    from nexus_symbiote.policy import DEFAULT_POLICY_YAML

    target = Path(path).resolve() / ".nexus-symbiote.yaml"
    if target.exists() and not force:
        raise click.UsageError(f"{target} already exists. Use --force to overwrite.")
    _write_file(target, DEFAULT_POLICY_YAML, overwrite=force)
    console.print(f"[bold green]Created[/] {escape(str(target))}")
    console.print("  Edit this file to customize scan, risk, and validation policies.")


@main.command("verify-signature")
@click.argument("artifact", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option(
    "--bundle",
    "bundle_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, readable=True),
    help="Sigstore bundle (JSON) that signs the artifact",
)
@click.option("--identity", required=True, help="Expected signer identity")
@click.option("--issuer", required=True, help="Expected OIDC issuer URL")
def verify_signature(artifact: str, bundle_path: str, identity: str, issuer: str) -> None:
    """Verify an artifact against a Sigstore bundle for an expected identity and issuer."""
    from nexus_symbiote.utils.crypto import verify_sigstore_bundle

    if not identity.strip() or not issuer.strip():
        raise click.UsageError("--identity and --issuer must not be empty")
    result = verify_sigstore_bundle(
        Path(artifact), Path(bundle_path), expected_identity=identity, expected_issuer=issuer
    )
    if not result.verified:
        console.print(f"[bold red]Not verified[/] {escape(artifact)}")
        if result.error:
            console.print(f"  {escape(result.error)}")
        sys.exit(1)
    console.print(f"[bold green]Verified[/] {escape(artifact)}")
    console.print(f"  Identity: {escape(identity)}")
    console.print(f"  Issuer: {escape(issuer)}")


if __name__ == "__main__":
    main()
