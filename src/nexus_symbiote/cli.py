"""Nexus SymBiote CLI — Agent Bill of Materials for AI supply chain security.

Architecture: Nexus-ShadowScan is the primary multi-surface discovery engine.
Nexus SymBiote consumes its reports (or local project files) to perform verification,
integrity checks, risk scoring, policy evaluation, and standards-grade BOM
generation (native, CycloneDX 1.7, SPDX 3.0, SARIF).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from nexus_symbiote import __version__
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import AIBOMMetadata, CompletenessClaim

if TYPE_CHECKING:
    from nexus_symbiote.policy import Policy

console = Console(stderr=True)
err_console = Console(stderr=True)

SCANNER_REGISTRY: dict[str, type] = {}


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


def _render_output(aibom: AIBOM, output_format: str) -> str:
    """Render an AIBOM to the requested output format as a string."""
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


def _resolve_policy(policy_path: str | None) -> Policy | None:
    """Load policy from a TRUSTED location — an explicit --policy file, else a
    search upward from the current working directory — never from the scanned
    project or the BOM's own directory, which may be attacker-controlled (NS-06)."""
    from nexus_symbiote.policy import load_policy, load_policy_file

    try:
        if policy_path:
            return load_policy_file(Path(policy_path))
        return load_policy(Path.cwd())
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc


def _load_bom(aibom_path: str) -> AIBOM:
    """Load a native AIBOM, turning malformed/oversized input into a clean error (NS-16)."""
    try:
        return AIBOM.load(Path(aibom_path))
    except (ValueError, OSError, ValidationError) as exc:
        raise click.ClickException(f"{aibom_path}: not a valid AIBOM — {exc}") from exc


@click.group()
@click.version_option(version=__version__, prog_name="nexus-symbiote")
def main() -> None:
    """Nexus SymBiote — Agent Bill of Materials for AI supply chain security."""


@main.command()
@click.argument("project_path", type=click.Path(exists=True), default=".")
@click.option("-o", "--output", type=click.Path(), help="Output file path")
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
    help="Specific scanners to run (default: all, or from policy). Prefer 'shadowscan' for primary discovery.",
)
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(),
    default=None,
    help="Policy file (trusted). Default: search upward from the current directory.",
)
def scan(
    project_path: str,
    output: str | None,
    output_format: str | None,
    scanners: tuple[str, ...],
    policy_path: str | None,
) -> None:
    """Scan a project and generate an AIBOM.

    Prefer Nexus-ShadowScan as the primary discovery source. Place a report at
    .shadowscan/report.json or use the import-shadowscan command.
    """
    root = Path(project_path).resolve()
    if not root.is_dir():
        err_console.print(f"[red]Error:[/] '{project_path}' is not a directory")
        sys.exit(1)

    # Scan configuration (which scanners run, output format) may come from the
    # project; it cannot weaken a gate (fewer scanners => partial coverage =>
    # gate fails). Gating policy (risk/validate) is loaded from a trusted
    # location instead — see _resolve_policy. (NS-06)
    from nexus_symbiote.policy import load_policy, load_policy_file

    try:
        policy = load_policy_file(Path(policy_path)) if policy_path else load_policy(root)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    if not output_format:
        output_format = policy.output.default_format if policy else "json"

    console.print(f"[bold]Scanning[/] {root}")

    aibom = AIBOM(metadata=AIBOMMetadata(authors=[]))
    all_scanners = _get_scanners()

    if scanners:
        selected = scanners
    elif policy:
        selected = tuple(policy.scan.scanners)
    else:
        selected = tuple(all_scanners.keys())

    surfaces_scanned: list[str] = []
    surfaces_excluded: list[str] = []
    scan_failures: list[str] = []
    # Only scanners that actually run get a status; a scanner that ran and found
    # nothing is 'complete' coverage of an absent surface, not 'partial' (NS-02).
    scanner_status: dict[str, str] = {}

    for name in selected:
        if name not in all_scanners:
            scan_failures.append(f"Unknown scanner: {name}")
            scanner_status[name] = "failed"
            continue

        scanner_cls = all_scanners[name]
        scanner = scanner_cls()
        console.print(f"  Running [cyan]{name}[/] scanner...")

        try:
            result = scanner.scan(root)
            for comp in result.components:
                aibom.add_component(comp)
            surfaces_scanned.extend(result.surfaces_scanned)
            surfaces_excluded.extend(result.surfaces_excluded)
            scan_failures.extend(result.scan_failures)
            scanner_status[name] = "failed" if result.scan_failures else "complete"
            console.print(f"    Found [green]{len(result.components)}[/] components")
        except Exception as e:
            err_console.print(f"  [red]Scanner '{name}' failed:[/] {e}")
            scan_failures.append(f"{name}: {e}")
            scanner_status[name] = "failed"

    aibom.metadata.completeness = CompletenessClaim(
        scope="local-static-project+shadowscan",
        surfaces_scanned=surfaces_scanned,
        surfaces_excluded=surfaces_excluded,
        scan_failures=scan_failures,
        scanner_status=scanner_status,
        assurance_level=AssuranceLevel.OBSERVED,
    )

    out_data = _render_output(aibom, output_format)

    if output:
        Path(output).write_text(out_data, encoding="utf-8")
        console.print(f"[bold green]Saved[/] {output}")
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
)
def import_shadowscan(report_path: str, output: str, output_format: str) -> None:
    """Import a Nexus-ShadowScan report and generate a verified AIBOM.

    This is the recommended primary workflow: run ShadowScan for discovery,
    then SymBiote for verification, integrity, and BOM emission.
    """
    from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

    importer = ShadowScanImporter()
    try:
        components = importer.import_report(Path(report_path))
    except Exception as exc:
        raise click.ClickException(f"Failed to import ShadowScan report: {exc}") from exc

    aibom = AIBOM(metadata=AIBOMMetadata(authors=[]))
    for comp in components:
        aibom.add_component(comp)

    aibom.metadata.completeness = CompletenessClaim(
        scope="shadowscan-imported",
        surfaces_scanned=[report_path],
        assurance_level=AssuranceLevel.DECLARED,
    )

    out_data = _render_output(aibom, output_format)

    Path(output).write_text(out_data, encoding="utf-8")
    console.print(f"[bold green]Imported {len(components)} components and saved[/] {output}")


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option(
    "--project",
    type=click.Path(exists=True),
    help="Project root for cross-validation",
)
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(),
    default=None,
    help="Policy file (trusted); enforces validate.require_* and minimum_assurance_level (NS-06).",
)
def validate(aibom_path: str, project: str | None, policy_path: str | None) -> None:
    """Validate an AIBOM for completeness and integrity."""
    bom = _load_bom(aibom_path)
    policy = _resolve_policy(policy_path)

    from nexus_symbiote.validators.completeness import CompletenessValidator
    from nexus_symbiote.validators.integrity import IntegrityValidator

    console.print("[bold]Completeness check[/]")
    cv = CompletenessValidator()
    if project:
        c_report = cv.validate_against_project(bom, Path(project).resolve())
    else:
        c_report = cv.validate(bom)

    status = "[green]PASS[/]" if c_report.is_complete else "[red]FAIL[/]"
    console.print(f"  Status: {status}")
    console.print(f"  Components: {c_report.total_components}")
    for ci in c_report.issues:
        color = {"error": "red", "warning": "yellow", "info": "blue"}.get(ci.severity, "white")
        sev = ci.severity.upper()
        console.print(f"  [{color}]{sev}[/] [{ci.surface}] {ci.description}")

    console.print("\n[bold]Integrity check[/]")
    iv = IntegrityValidator()
    project_root = Path(project).resolve() if project else None
    i_report = iv.validate(bom, project_root)
    status = "[green]PASS[/]" if i_report.is_valid else "[red]FAIL[/]"
    console.print(f"  Status: {status}")
    v, f = i_report.hashes_verified, i_report.hashes_failed
    console.print(f"  Hashes verified: {v}, failed: {f}")
    for ii in i_report.issues:
        sev_colors = {"critical": "red", "error": "red", "warning": "yellow"}
        color = sev_colors.get(ii.severity, "white")
        sev = ii.severity.upper()
        console.print(f"  [{color}]{sev}[/] [{ii.component_ref}] {ii.detail}")

    # Enforce the validate policy (NS-06: these fields were previously parsed but ignored).
    vpol = policy.validation if policy else None
    failed = (vpol is None or vpol.require_completeness) and not c_report.is_complete
    failed = failed or ((vpol is None or vpol.require_integrity) and not i_report.is_valid)
    if vpol is not None:
        order = {"declared": 0, "observed": 1, "verified": 2}
        if order.get(c_report.assurance_level.value, 0) < order.get(
            vpol.minimum_assurance_level, 0
        ):
            failed = True
            console.print(
                f"  [red]ERROR[/] [assurance] assurance '{c_report.assurance_level.value}' is "
                f"below the required minimum '{vpol.minimum_assurance_level}'"
            )
    if failed:
        sys.exit(1)


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option(
    "--threshold", type=float, default=None, help="Fail threshold score (overrides policy)"
)
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(),
    default=None,
    help="Policy file (trusted). Default: search upward from the current directory.",
)
@click.option(
    "--allow-partial-coverage",
    is_flag=True,
    help="Let the gate pass on risk alone even when collection coverage is incomplete.",
)
@click.option("--json-output", is_flag=True, help="Output as JSON")
def risk(
    aibom_path: str,
    threshold: float | None,
    policy_path: str | None,
    allow_partial_coverage: bool,
    json_output: bool,
) -> None:
    """Score supply-chain risks in an AIBOM and evaluate the CI gate."""
    bom = _load_bom(aibom_path)

    from nexus_symbiote.validators.risk import RiskScorer

    policy = _resolve_policy(policy_path)
    if threshold is None:
        threshold = policy.risk.fail_threshold if policy else 50.0
    scorer = RiskScorer(
        fail_threshold=threshold,
        warn_threshold=(policy.risk.warn_threshold if policy else 25.0),
        ignore_categories=(set(policy.risk.ignore_categories) if policy else None),
    )
    passed, report = scorer.passes_gate(bom, require_coverage=not allow_partial_coverage)

    if json_output:
        click.echo(json.dumps(report.to_dict(), indent=2))
        sys.exit(0 if passed else 1)

    level_colors = {
        "critical": "red",
        "high": "red",
        "moderate": "yellow",
        "clean": "green",
        "unknown": "yellow",
    }
    color = level_colors.get(report.risk_level, "yellow")
    score = report.overall_score
    level = report.risk_level
    console.print(f"[bold]Risk Score:[/] [{color}]{score:.1f}[/] ({level})")
    total = report.total_components
    risky = report.components_with_risks
    console.print(f"  Components: {total} total, {risky} with risks")

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
            sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(
                finding.severity.value, "white"
            )
            table.add_row(
                f"[{sev_color}]{finding.severity.value}[/]",
                finding.component_name[:30],
                finding.category,
                finding.detail[:50],
            )
        console.print(table)

    gate = "[green]PASSED[/]" if passed else "[red]FAILED[/]"
    console.print(f"\nGate (threshold={threshold:g}): {gate}  [dim]{report.gate_reason}[/]")
    if report.coverage_status != "reported":
        console.print(f"  [yellow]Coverage:[/] {report.coverage_status}")

    if not passed:
        sys.exit(1)


@main.command()
@click.argument("old_path", type=click.Path(exists=True))
@click.argument("new_path", type=click.Path(exists=True))
@click.option("--json-output", is_flag=True, help="Output as JSON")
@click.option(
    "--fail-on",
    type=click.Choice(["none", "low", "medium", "high", "critical"]),
    default="high",
    help="Exit non-zero when a change at/above this severity is detected "
    "(default: high; 'none' disables). (NS-03)",
)
def diff(old_path: str, new_path: str, json_output: bool, fail_on: str) -> None:
    """Compare two AIBOM snapshots for supply-chain drift."""
    old_bom = _load_bom(old_path)
    new_bom = _load_bom(new_path)

    from nexus_symbiote.diff.differ import AIBOMDiffer

    differ = AIBOMDiffer()
    result = differ.diff(old_bom, new_bom)

    if json_output:
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        if not result.has_changes:
            console.print("[green]No changes detected.[/]")
            return

        console.print(f"[bold]{result.total_changes} changes detected[/]")

        if result.security_alerts:
            console.print("\n[bold red]Security Alerts:[/]")
            for alert in result.security_alerts:
                console.print(f"  [{alert['severity'].upper()}] {alert['alert']}")

        if result.components_added:
            console.print(f"\n[green]+{len(result.components_added)} added[/]")
            for c in result.components_added:
                console.print(f"  + {c.name} ({c.component_type})")
        if result.components_removed:
            console.print(f"\n[red]-{len(result.components_removed)} removed[/]")
            for c in result.components_removed:
                console.print(f"  - {c.name} ({c.component_type})")
        if result.components_modified:
            console.print(f"\n[yellow]~{len(result.components_modified)} modified[/]")
            for c in result.components_modified:
                console.print(f"  ~ {c.name}: {'; '.join(c.details)}")

    # Drift gate: exit non-zero when a change meets the --fail-on severity (NS-03).
    if fail_on != "none":
        order = ["info", "low", "medium", "high", "critical"]
        severities = [a["severity"] for a in result.security_alerts]
        severities += [c.severity for c in result.components_modified]
        severities += [c.severity for c in result.components_added]
        worst = max((order.index(s) for s in severities if s in order), default=-1)
        if worst >= order.index(fail_on):
            if not json_output:
                console.print(
                    f"\n[red]Drift gate FAILED[/] (change at or above '{fail_on}' detected)."
                )
            sys.exit(1)


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
def summary(aibom_path: str) -> None:
    """Print a summary of an AIBOM."""
    bom = _load_bom(aibom_path)
    s = bom.summary()

    console.print("[bold]AIBOM Summary[/]")
    console.print(f"  Components: {s['total_components']}")
    console.print(f"  Dependencies: {s['total_dependencies']}")
    console.print(f"  Risks: {s['total_risks']}")

    if s["component_types"]:
        console.print("  Component types:")
        for ctype, count in sorted(s["component_types"].items()):
            console.print(f"    {ctype}: {count}")
    if s["risk_breakdown"]:
        console.print("  Risk breakdown:")
        for sev, count in sorted(s["risk_breakdown"].items()):
            console.print(f"    {sev}: {count}")


@main.command()
@click.option("--force", is_flag=True, help="Overwrite existing .nexus-symbiote.yaml")
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
        err_console.print(f"[yellow]Warning:[/] {target} already exists. Use --force to overwrite.")
        sys.exit(1)

    target.write_text(DEFAULT_POLICY_YAML, encoding="utf-8")
    console.print(f"[bold green]Created[/] {target}")
    console.print("  Edit this file to customize scan, risk, and validation policies.")


if __name__ == "__main__":
    main()
