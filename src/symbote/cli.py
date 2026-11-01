"""SymBiote CLI — Agent Bill of Materials for AI supply chain security."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from symbote import __version__
from symbote.core.aibom import AIBOM
from symbote.core.enums import AssuranceLevel
from symbote.core.models import AIBOMMetadata, CompletenessClaim

console = Console(stderr=True)
err_console = Console(stderr=True)

SCANNER_REGISTRY: dict[str, type] = {}


def _get_scanners() -> dict[str, type]:
    if not SCANNER_REGISTRY:
        from symbote.scanners.mcp import MCPScanner
        from symbote.scanners.model import ModelScanner
        from symbote.scanners.prompt import PromptScanner
        from symbote.scanners.rag import RAGScanner
        from symbote.scanners.registry import RegistryScanner

        SCANNER_REGISTRY.update({
            "mcp": MCPScanner,
            "model": ModelScanner,
            "prompt": PromptScanner,
            "rag": RAGScanner,
            "registry": RegistryScanner,
        })
    return SCANNER_REGISTRY


@click.group()
@click.version_option(version=__version__, prog_name="symbote")
def main() -> None:
    """SymBiote — Agent Bill of Materials for AI supply chain security."""


@main.command()
@click.argument("project_path", type=click.Path(exists=True), default=".")
@click.option("-o", "--output", type=click.Path(), help="Output file path")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "cyclonedx", "spdx"]),
    default="json",
    help="Output format",
)
@click.option(
    "--scanner",
    "scanners",
    multiple=True,
    help="Specific scanners to run (default: all)",
)
def scan(
    project_path: str,
    output: str | None,
    output_format: str,
    scanners: tuple[str, ...],
) -> None:
    """Scan a project and generate an AIBOM."""
    root = Path(project_path).resolve()
    if not root.is_dir():
        err_console.print(f"[red]Error:[/] '{project_path}' is not a directory")
        sys.exit(1)

    console.print(f"[bold]Scanning[/] {root}")

    aibom = AIBOM(metadata=AIBOMMetadata(authors=[]))
    all_scanners = _get_scanners()
    selected = scanners or tuple(all_scanners.keys())
    surfaces_scanned: list[str] = []
    surfaces_excluded: list[str] = []
    scan_failures: list[str] = []

    for name in selected:
        if name not in all_scanners:
            err_console.print(f"[yellow]Warning:[/] Unknown scanner '{name}', skipping")
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
            console.print(f"    Found [green]{len(result.components)}[/] components")
        except Exception as e:
            err_console.print(f"  [red]Scanner '{name}' failed:[/] {e}")
            scan_failures.append(f"{name}: {e}")

    aibom.metadata.completeness = CompletenessClaim(
        scope="full-agent",
        surfaces_scanned=surfaces_scanned,
        surfaces_excluded=surfaces_excluded,
        scan_failures=scan_failures,
        assurance_level=AssuranceLevel.OBSERVED,
    )

    if output_format == "cyclonedx":
        from symbote.generators.cyclonedx import CycloneDXGenerator
        out_data = CycloneDXGenerator().generate_json(aibom)
    elif output_format == "spdx":
        from symbote.generators.spdx import SPDXGenerator
        out_data = SPDXGenerator().generate_json(aibom)
    else:
        out_data = aibom.to_json()

    if output:
        Path(output).write_text(out_data, encoding="utf-8")
        console.print(f"[bold green]Saved[/] {output}")
    else:
        click.echo(out_data)


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option(
    "--project",
    type=click.Path(exists=True),
    help="Project root for cross-validation",
)
def validate(aibom_path: str, project: str | None) -> None:
    """Validate an AIBOM for completeness and integrity."""
    bom = AIBOM.load(Path(aibom_path))

    from symbote.validators.completeness import CompletenessValidator
    from symbote.validators.integrity import IntegrityValidator

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

    if not c_report.is_complete or not i_report.is_valid:
        sys.exit(1)


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option("--threshold", type=float, default=50.0, help="Fail threshold score")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def risk(aibom_path: str, threshold: float, json_output: bool) -> None:
    """Score supply-chain risks in an AIBOM."""
    bom = AIBOM.load(Path(aibom_path))

    from symbote.validators.risk import RiskScorer

    scorer = RiskScorer(fail_threshold=threshold)
    passed, report = scorer.passes_gate(bom)

    if json_output:
        click.echo(json.dumps(report.to_dict(), indent=2))
        sys.exit(0 if passed else 1)

    level_colors = {
        "critical": "red", "high": "red", "moderate": "yellow", "clean": "green",
    }
    color = level_colors[report.risk_level]
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

        for f in report.findings[:15]:
            sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(
                f.severity.value, "white"
            )
            table.add_row(
                f"[{sev_color}]{f.severity.value}[/]",
                f.component_name[:30],
                f.category,
                f.detail[:50],
            )
        console.print(table)

    gate = "[green]PASSED[/]" if passed else "[red]FAILED[/]"
    console.print(f"\nGate (threshold={threshold}): {gate}")

    if not passed:
        sys.exit(1)


@main.command()
@click.argument("old_path", type=click.Path(exists=True))
@click.argument("new_path", type=click.Path(exists=True))
@click.option("--json-output", is_flag=True, help="Output as JSON")
def diff(old_path: str, new_path: str, json_output: bool) -> None:
    """Compare two AIBOM snapshots for supply-chain drift."""
    old_bom = AIBOM.load(Path(old_path))
    new_bom = AIBOM.load(Path(new_path))

    from symbote.diff.differ import AIBOMDiffer

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


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
def summary(aibom_path: str) -> None:
    """Print a summary of an AIBOM."""
    bom = AIBOM.load(Path(aibom_path))
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


if __name__ == "__main__":
    main()
