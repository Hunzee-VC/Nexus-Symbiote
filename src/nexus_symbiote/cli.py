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
from typing import TYPE_CHECKING, Any

import click
from rich.console import Console
from rich.table import Table

from nexus_symbiote import __version__
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import AIBOMMetadata, CompletenessClaim

if TYPE_CHECKING:
    from nexus_symbiote.live import LiveVerifyReport

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


@click.group()
@click.version_option(version=__version__, prog_name="nexus-symbiote")
def main() -> None:
    """Nexus SymBiote — Agent Bill of Materials for AI supply chain security."""


def _collect_aibom(root: Path, selected: tuple[str, ...] | None = None) -> AIBOM:
    """Run scanners over root and return the assembled AIBOM with completeness metadata."""
    aibom = AIBOM(metadata=AIBOMMetadata(authors=[]))
    all_scanners = _get_scanners()

    if selected:
        chosen = selected
    else:
        from nexus_symbiote.policy import load_policy

        try:
            policy = load_policy(root)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        chosen = tuple(policy.scan.scanners) if policy else tuple(all_scanners.keys())

    surfaces_scanned: list[str] = []
    surfaces_excluded: list[str] = []
    scan_failures: list[str] = []
    scanner_status: dict[str, str] = dict.fromkeys(all_scanners, "unknown")

    for name in chosen:
        if name not in all_scanners:
            scan_failures.append(f"Unknown scanner: {name}")
            scanner_status[name] = "failed"
            continue

        scanner_cls = all_scanners[name]
        scanner = scanner_cls()

        try:
            result = scanner.scan(root)
            for comp in result.components:
                aibom.add_component(comp)
            surfaces_scanned.extend(result.surfaces_scanned)
            surfaces_excluded.extend(result.surfaces_excluded)
            scan_failures.extend(result.scan_failures)
            scanner_status[name] = (
                "failed"
                if result.scan_failures
                else "partial"
                if result.surfaces_excluded
                else "complete"
            )
        except Exception as e:
            err_console.print(f"  [red]Scanner '{name}' failed:[/] {e}")
            scan_failures.append(f"{name}: {e}")
            scanner_status[name] = "failed"

    aibom.metadata.completeness = CompletenessClaim(
        scope="local-static-project",
        surfaces_scanned=surfaces_scanned,
        surfaces_excluded=surfaces_excluded,
        scan_failures=scan_failures,
        scanner_status=scanner_status,
        assurance_level=AssuranceLevel.OBSERVED,
    )

    return aibom


def _load_mcp_configs(root: Path) -> dict[str, dict[str, Any]]:
    """Read the project's MCP server configs, returning name -> raw server config."""
    from nexus_symbiote.scanners.mcp import MCP_CONFIG_FILES

    configs: dict[str, dict[str, Any]] = {}
    for config_name in MCP_CONFIG_FILES:
        path = root / config_name
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        servers = data.get("mcpServers", data.get("servers", {}))
        if isinstance(servers, dict):
            for name, cfg in servers.items():
                if isinstance(cfg, dict):
                    configs[name] = cfg
    return configs


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
    help="Specific scanners to run (default: all, or from .nexus-symbiote.yaml). Prefer 'shadowscan' for primary discovery.",
)
def scan(
    project_path: str,
    output: str | None,
    output_format: str | None,
    scanners: tuple[str, ...],
) -> None:
    """Scan a project and generate an AIBOM.

    Prefer Nexus-ShadowScan as the primary discovery source. Place a report at
    .shadowscan/report.json or use the import-shadowscan command.
    """
    root = Path(project_path).resolve()
    if not root.is_dir():
        err_console.print(f"[red]Error:[/] '{project_path}' is not a directory")
        sys.exit(1)

    from nexus_symbiote.policy import load_policy

    try:
        policy = load_policy(root)
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
    scanner_status: dict[str, str] = dict.fromkeys(all_scanners, "unknown")

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
            scanner_status[name] = (
                "failed"
                if result.scan_failures
                else "partial"
                if result.surfaces_excluded
                else "complete"
            )
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

    if output_format == "cyclonedx":
        from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator

        out_data = CycloneDXGenerator().generate_json(aibom)
    elif output_format == "spdx":
        from nexus_symbiote.generators.spdx import SPDXGenerator

        out_data = SPDXGenerator().generate_json(aibom)
    elif output_format == "sarif":
        from nexus_symbiote.generators.sarif import SARIFGenerator

        out_data = SARIFGenerator().generate_json(aibom)
    else:
        out_data = aibom.to_json()

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
    then Nexus SymBiote for verification, integrity, and BOM emission.
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

    if output_format == "cyclonedx":
        from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator

        out_data = CycloneDXGenerator().generate_json(aibom)
    elif output_format == "spdx":
        from nexus_symbiote.generators.spdx import SPDXGenerator

        out_data = SPDXGenerator().generate_json(aibom)
    elif output_format == "sarif":
        from nexus_symbiote.generators.sarif import SARIFGenerator

        out_data = SARIFGenerator().generate_json(aibom)
    else:
        out_data = aibom.to_json()

    Path(output).write_text(out_data, encoding="utf-8")
    console.print(f"[bold green]Imported {len(components)} components and saved[/] {output}")


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

    if not c_report.is_complete or not i_report.is_valid:
        sys.exit(1)


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option("--threshold", type=float, default=None, help="Fail threshold score")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def risk(aibom_path: str, threshold: float | None, json_output: bool) -> None:
    """Score supply-chain risks in an AIBOM."""
    bom = AIBOM.load(Path(aibom_path))

    from nexus_symbiote.policy import load_policy
    from nexus_symbiote.validators.risk import RiskScorer

    if threshold is None:
        try:
            policy = load_policy(Path(aibom_path).parent)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        threshold = policy.risk.fail_threshold if policy else 50.0

    scorer = RiskScorer(fail_threshold=threshold)
    passed, report = scorer.passes_gate(bom)

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
    console.print(f"\nGate (threshold={threshold}): {gate}")

    if not passed:
        sys.exit(1)


@main.command()
@click.argument("old_path", type=click.Path(exists=True))
@click.argument("new_path", type=click.Path(exists=True))
@click.option("--json-output", is_flag=True, help="Output as JSON")
def diff(old_path: str, new_path: str, json_output: bool) -> None:
    """Compare two AIBOM snapshots for supply-chain drift."""
    try:
        old_bom = AIBOM.load(Path(old_path))
    except Exception:
        click.echo(f"Error: {old_path} is not a valid native AIBOM file.", err=True)
        sys.exit(1)
    try:
        new_bom = AIBOM.load(Path(new_path))
    except Exception:
        click.echo(f"Error: {new_path} is not a valid native AIBOM file.", err=True)
        sys.exit(1)

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


@main.command("verify-live")
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option(
    "--project",
    type=click.Path(exists=True),
    default=".",
    help="Project root containing the MCP configs to launch",
)
@click.option("--json-output", is_flag=True, help="Output as JSON")
@click.option(
    "--record",
    is_flag=True,
    help="Write live-observed tool fingerprints into the BOM for approval. "
    "Use once after human review; subsequent runs verify against them.",
)
def verify_live(aibom_path: str, project: str, json_output: bool, record: bool) -> None:
    """Connect to running MCP servers and detect rug-pull drift.

    Launches each configured MCP server, lists its live tool definitions,
    recomputes canonical fingerprints, and compares them against the approved
    BOM. A changed or new tool definition is a rug-pull: the server altered
    its behavior after approval.

    Static scans often cannot enumerate tools (they exist only at runtime).
    Run once with --record after human review to capture the approved
    definitions; every later run verifies against them.
    """
    from nexus_symbiote.live import verify_mcp_servers

    bom = AIBOM.load(Path(aibom_path))
    root = Path(project).resolve()

    console.print(f"[bold]Live verification[/] against {root}")
    config_lookup = _load_mcp_configs(root)
    report = verify_mcp_servers(bom, config_lookup)

    if record:
        recorded = _record_live_tools(bom, report)
        if recorded:
            Path(aibom_path).write_text(bom.to_json(), encoding="utf-8")
            console.print(
                f"[bold green]Recorded[/] {recorded} live tool definition(s) "
                f"into {aibom_path} — review the diff before committing."
            )

    if json_output:
        click.echo(json.dumps(report.to_dict(), indent=2))
    else:
        for result in report.results:
            if not result.reachable:
                console.print(f"  [yellow]unreachable[/] {result.server_name}: {result.error}")
                continue
            for finding in result.tool_findings:
                if finding.status == "match":
                    console.print(f"  [green]match[/]    {result.server_name}/{finding.name}")
                elif finding.status == "changed":
                    console.print(
                        f"  [red]CHANGED[/]  {result.server_name}/{finding.name} — "
                        "tool definition differs from the approved BOM (rug-pull)"
                    )
                elif finding.status == "new":
                    console.print(
                        f"  [red]NEW[/]      {result.server_name}/{finding.name} — "
                        "tool not present in the approved BOM"
                    )
                elif finding.status == "missing":
                    console.print(f"  [yellow]missing[/]  {result.server_name}/{finding.name}")

    if report.has_drift:
        console.print("\n[bold red]Rug-pull drift detected.[/]")
        if not record:
            sys.exit(1)


def _record_live_tools(bom: AIBOM, report: LiveVerifyReport) -> int:
    """Write live-observed tool definitions into the BOM. Returns count recorded."""
    from nexus_symbiote.core.enums import TrustTier
    from nexus_symbiote.core.models import MCPServerComponent, ToolComponent

    recorded = 0
    for result in report.results:
        if not result.reachable:
            continue
        for finding in result.tool_findings:
            if finding.status not in ("new", "changed"):
                continue
            bom_ref = f"tool:{result.server_name}/{finding.name}"
            existing = next((c for c in bom.components if c.bom_ref == bom_ref), None)
            if isinstance(existing, ToolComponent):
                existing.definition_hash = finding.definition_hash
                existing.definition_hash_version = "rfc8785-jcs-v1"
                recorded += 1
            else:
                bom.add_component(
                    ToolComponent(
                        bom_ref=bom_ref,
                        name=finding.name,
                        mcp_server_ref=f"mcp-server:{result.server_name}",
                        definition_hash=finding.definition_hash,
                        definition_hash_version="rfc8785-jcs-v1",
                        trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                        source_path=f"live:{result.server_name}",
                    )
                )
                recorded += 1

        for comp in bom.components:
            if isinstance(comp, MCPServerComponent) and comp.name == result.server_name:
                if result.live_schema_hash:
                    comp.schema_hash = result.live_schema_hash
                break

    return recorded


@main.command()
@click.argument("project_path", type=click.Path(exists=True), default=".")
@click.option(
    "-o",
    "--baseline-path",
    type=click.Path(),
    default=".symbiote-baseline.json",
    help="Where to write the baseline",
)
def baseline(project_path: str, baseline_path: str) -> None:
    """Create a signed-drift baseline from the current project state.

    The baseline is the approved snapshot. `symbiote diff baseline current`
    in CI then fails on trust downgrades, tool mutations, or pin removals.
    """
    root = Path(project_path).resolve()
    console.print(f"[bold]Creating baseline[/] from {root}")

    aibom = _collect_aibom(root)
    target = Path(baseline_path)
    target.write_text(aibom.to_json(), encoding="utf-8")

    console.print(f"[bold green]Baseline written[/] {target}")
    console.print("  Commit this file; diff against it in CI to gate drift.")


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Output file path")
def vex(aibom_path: str, output: str | None) -> None:
    """Generate a CycloneDX VEX document from AIBOM risk findings.

    Statements are keyed to artifact digests and adaptation events (fine-tune,
    LoRA, quantization), so a finding tracks the exact weight revision it
    was observed on.
    """
    from nexus_symbiote.generators.vex import VEXGenerator

    bom = AIBOM.load(Path(aibom_path))
    vex_doc = VEXGenerator().generate_json(bom)

    if output:
        Path(output).write_text(vex_doc, encoding="utf-8")
        console.print(f"[bold green]VEX written[/] {output}")
    else:
        click.echo(vex_doc)


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Output file path")
def advisories(aibom_path: str, output: str | None) -> None:
    """Query OSV.dev for known vulnerabilities in discovered registry packages.

    Network use is explicit: this command contacts api.osv.dev. Static `scan`
    never does.
    """
    from nexus_symbiote.advisories import fetch_advisories

    bom = AIBOM.load(Path(aibom_path))
    report = fetch_advisories(bom)

    if output:
        Path(output).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[bold green]Advisory report written[/] {output}")
    else:
        click.echo(json.dumps(report.to_dict(), indent=2))

    for adv in report.advisories:
        cves = ", ".join(adv.aliases) if adv.aliases else "no CVE aliases"
        console.print(f"  [red]{adv.advisory_id}[/] {adv.component_name}@{adv.version} ({cves})")
    if report.errors:
        for err in report.errors:
            console.print(f"  [yellow]lookup error:[/] {err}")


if __name__ == "__main__":
    main()
