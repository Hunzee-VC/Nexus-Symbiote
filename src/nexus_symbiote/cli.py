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

import click
from rich.console import Console
from rich.table import Table

from nexus_symbiote import __version__
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import AIBOMMetadata, CompletenessClaim

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
    source_report_digest = None
    source_report_format = None
    source_report_status = None
    source_unmapped_count = 0
    source_unmapped_indexes: list[int] = []
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
            if name == "shadowscan":
                source_report_digest = result.source_report_digest
                source_report_format = result.source_report_format
                source_report_status = result.source_report_status
                source_unmapped_count = result.source_unmapped_count
                source_unmapped_indexes = result.source_unmapped_indexes
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
        scope="local-static-project+shadowscan" if source_report_digest else "local-static-project",
        surfaces_scanned=surfaces_scanned,
        surfaces_excluded=surfaces_excluded,
        scan_failures=scan_failures,
        scanner_status=scanner_status,
        source_report_digest=source_report_digest,
        source_report_format=source_report_format,
        source_report_status=source_report_status,
        source_unmapped_count=source_unmapped_count,
        source_unmapped_indexes=source_unmapped_indexes,
        assurance_level=AssuranceLevel.OBSERVED,
    )

    if source_report_digest and output_format in ("spdx", "sarif"):
        raise click.ClickException(
            "ShadowScan import supports native JSON and CycloneDX; SPDX and SARIF "
            "cannot yet preserve discovery coverage."
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
    """Import a Nexus-ShadowScan report as unverified discovery evidence.

    This is the recommended primary workflow: run ShadowScan for discovery,
    then SymBiote for verification, integrity, and BOM emission.
    """
    from nexus_symbiote.scanners.shadowscan import ShadowScanImporter

    importer = ShadowScanImporter()
    try:
        imported = importer.read_report(Path(report_path))
    except (ValueError, OSError, UnicodeError, RecursionError) as exc:
        raise click.ClickException("Failed to safely import the ShadowScan report") from exc

    aibom = imported.to_native_bom()

    if output_format in ("spdx", "sarif"):
        raise click.ClickException(
            "ShadowScan import supports native JSON and CycloneDX; SPDX and SARIF "
            "cannot yet preserve discovery coverage."
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

    try:
        with Path(output).open("x", encoding="utf-8") as stream:
            stream.write(out_data)
    except OSError as exc:
        raise click.ClickException("Cannot create output; choose a new output path") from exc
    console.print(
        f"Imported {len(imported.components)} components and saved {output}; discovery and BOM coverage remain unverified."
    )
    if imported.source_status != "complete":
        raise click.ClickException("ShadowScan source report is incomplete; the BOM is partial")


@main.command("verify-artifact")
@click.argument("artifact_path")
@click.option(
    "--project",
    required=True,
    type=click.Path(exists=True, file_okay=False),
    help="Trusted project root",
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
    import re

    from nexus_symbiote.scanners.base import read_regular_text
    from nexus_symbiote.utils.confined import hash_confined_file
    from nexus_symbiote.utils.crypto import verify_sigstore_digest

    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest):
        raise click.ClickException(
            "Expected SHA-256 must be sha256:<64 lowercase hexadecimal characters>"
        )
    if bool(bundle) != bool(signer_identity and issuer) or (
        not bundle and (signer_identity or issuer)
    ):
        raise click.ClickException("Bundle verification requires both signer identity and issuer")
    try:
        digest = hash_confined_file(Path(project), artifact_path)
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
            raise click.ClickException(
                "Bundle verification requires both signer identity and issuer"
            )
        verified = verify_sigstore_digest(digest, bundle_bytes, signer_identity, issuer)
        if not verified.verified:
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
    import re

    from nexus_symbiote.scanners.base import read_regular_text
    from nexus_symbiote.scanners.shadowscan import (
        MAX_REPORT_BYTES,
        ShadowScanImporter,
        _object_no_duplicates,
        _reject_constant,
    )
    from nexus_symbiote.utils.crypto import verify_sigstore_digest

    if any(x is not None for x in (bundle, signer_identity, issuer)) and not all(
        (bundle, signer_identity, issuer)
    ):
        raise click.UsageError("--bundle, --signer-identity and --issuer must be supplied together")
    try:
        doc = json.loads(
            read_regular_text(Path(aibom_path), max_bytes=MAX_REPORT_BYTES),
            object_pairs_hook=_object_no_duplicates,
            parse_constant=_reject_constant,
        )
        bom = AIBOM.model_validate(doc)
        text = read_regular_text(Path(report_path), max_bytes=MAX_REPORT_BYTES)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise click.ClickException("Cannot safely read the BOM or discovery report") from exc
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
        if not verify_sigstore_digest(actual, bundle_bytes, signer_identity, issuer).verified:
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


if __name__ == "__main__":
    main()
