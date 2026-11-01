"""Nexus SymBiote CLI — Agent Bill of Materials for AI supply chain security."""

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
from nexus_symbiote.live_cli import register_live_commands
from nexus_symbiote.policy import Policy
from nexus_symbiote.runtime_cli import register_runtime_commands
from nexus_symbiote.supply_chain_cli import register_supply_chain_commands
from nexus_symbiote.utils.files import write_output_file

console = Console(stderr=True)


err_console = Console(stderr=True)


def _policy(root: Path) -> Policy:
    from nexus_symbiote.policy import PolicyError, default_policy, load_policy

    try:
        return load_policy(root) or default_policy()
    except PolicyError as exc:
        raise click.ClickException(str(exc)) from exc


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
    help="Specific scanners to run (default: all, or from .nexus-symbiote.yaml)",
)
@click.option(
    "--report-only", is_flag=True, help="Emit findings and collection failures without a CI failure"
)
@click.option(
    "--signature-policy",
    type=click.Path(exists=True, path_type=Path),
    help="Explicit operator signer policy JSON",
)
def scan(
    project_path: str,
    output: str | None,
    output_format: str | None,
    scanners: tuple[str, ...],
    report_only: bool = False,
    signature_policy: Path | None = None,
) -> None:
    """Scan a project and generate an AIBOM."""
    root = Path(project_path).resolve()
    if not root.is_dir():
        err_console.print(f"[red]Error:[/] '{project_path}' is not a directory")
        sys.exit(1)

    from nexus_symbiote.core.models import ClaimEvidence
    from nexus_symbiote.graph import assemble_repository_agent, validate_graph
    from nexus_symbiote.policy import PolicyError
    from nexus_symbiote.signature_policy import load_signature_policies
    from nexus_symbiote.validators.risk import RiskScorer

    policy = _policy(root)
    try:
        signature_policies = (
            load_signature_policies(signature_policy, root) if signature_policy else []
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from None
    output_format = output_format or policy.output.default_format
    all_scanners = _get_scanners()
    selected = scanners or tuple(policy.scan.scanners)
    unknown = set(selected) - set(all_scanners)
    if unknown:
        raise click.BadParameter(
            "Unknown scanner: " + ", ".join(sorted(unknown)), param_hint="--scanner"
        )
    if output_format not in {"json", "cyclonedx", "spdx", "sarif"}:
        raise click.BadParameter("Unknown output format", param_hint="--format")
    console.print(f"[bold]Scanning[/] {root}")
    aibom = AIBOM(metadata=AIBOMMetadata(authors=[]))
    aibom.finalize()
    surfaces_scanned: list[str] = []
    surfaces_excluded: list[str] = []
    scan_failures: list[str] = []
    completed: list[str] = []
    source_report_digest = None
    source_report_format = None
    source_report_status = None
    source_unmapped_count = 0
    source_unmapped_indexes: list[int] = []
    scanner_status: dict[str, str] = dict.fromkeys(all_scanners, "unknown")
    for name in selected:
        scanner = (
            all_scanners[name](signature_policies=signature_policies)
            if name == "model"
            else all_scanners[name]()
        )
        console.print(f"  Running [cyan]{name}[/] scanner...")
        try:
            configure = getattr(scanner, "configure", None)
            if configure:
                configure(exclude_paths=policy.scan.exclude_paths)
            elif policy.scan.exclude_paths:
                raise ValueError("scanner does not support configured exclude_paths")
            failure_count = len(scan_failures)
            result = scanner.scan(root)
            if name == "shadowscan":
                source_report_digest = result.source_report_digest
                source_report_format = result.source_report_format
                source_report_status = result.source_report_status
                source_unmapped_count = result.source_unmapped_count
                source_unmapped_indexes = result.source_unmapped_indexes
            for comp in result.components:
                # Discovery of a file/configuration does not verify every supplier assertion.
                imported = name == "shadowscan"
                comp.claims["discovery_report_entry" if imported else "repository_presence"] = (
                    ClaimEvidence(
                        assurance=AssuranceLevel.DECLARED if imported else AssuranceLevel.OBSERVED,
                        method="imported-discovery-report" if imported else "filesystem-inventory",
                        scope="source-report" if imported else "repository",
                        collector=name,
                        locator=comp.source_path,
                        observed_at=aibom.metadata.timestamp,
                    )
                )
                if comp.assurance_level is AssuranceLevel.VERIFIED:
                    comp.assurance_level = AssuranceLevel.DECLARED
                existing = aibom.get_component(comp.bom_ref)
                if existing is not None and existing != comp:
                    scan_failures.append(f"{name}: conflicting duplicate component {comp.bom_ref}")
                    continue
                aibom.add_component(comp)
            surfaces_scanned.extend(result.surfaces_scanned)
            surfaces_excluded.extend(result.surfaces_excluded)
            scan_failures.extend(result.scan_failures)
            scanner_status[name] = (
                "failed"
                if len(scan_failures) > failure_count
                else "partial"
                if result.surfaces_excluded
                else "complete"
            )
            if not result.scan_failures:
                completed.append(name)
            console.print(f"    Found [green]{len(result.components)}[/] components")
        except Exception as exc:
            err_console.print(f"  [red]Scanner '{name}' failed:[/] {exc}")
            scan_failures.append(f"{name}: {exc}")
            scanner_status[name] = "failed"
    try:
        assemble_repository_agent(aibom, root)
    except (PolicyError, ValueError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    scan_failures.extend(validate_graph(aibom))
    aibom.metadata.completeness = CompletenessClaim(
        scope="repository+shadowscan" if source_report_digest else "repository",
        source_report_digest=source_report_digest,
        source_report_format=source_report_format,
        source_report_status=source_report_status,
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
        exclusions=list(policy.scan.exclude_paths),
        unobserved_surfaces=[
            "runtime",
            "effective-identity",
            "effective-authorization",
            "live-tools",
            "network",
        ],
    )
    passed, risk_report = RiskScorer(
        fail_threshold=policy.risk.fail_threshold,
        warn_threshold=policy.risk.warn_threshold,
        ignore_categories=policy.risk.ignore_categories,
        fail_on_severity=policy.risk.fail_on_severity,
    ).passes_gate(aibom)
    report_mode = report_only or policy.scan.failure_mode == "report-only"

    if source_report_digest and output_format == "sarif":
        raise click.ClickException(
            "SARIF cannot preserve imported discovery coverage; use native JSON, CycloneDX or SPDX."
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
        write_output_file(Path(output), out_data)
        console.print(f"[bold green]Saved[/] {output}")
    else:
        click.echo(out_data)

    if risk_report.warning_threshold_exceeded:
        err_console.print(f"[yellow]Risk warning:[/] score {risk_report.overall_score:.1f}")
    if scan_failures or not passed:
        err_console.print("[yellow]Report only[/]" if report_mode else "[red]Scan gate failed[/]")
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

    policy = _policy(Path(report_path).parent)
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
    elif output_format == "sarif":
        from nexus_symbiote.generators.sarif import SARIFGenerator

        out_data = SARIFGenerator().generate_json(aibom)
    else:
        out_data = aibom.to_json()

    try:
        write_output_file(Path(output), out_data, overwrite=False)
    except OSError as exc:
        raise click.ClickException("Cannot create output; choose a new output path") from exc
    console.print(
        f"Imported {len(imported.components)} components and saved {output}; discovery coverage remains partial."
    )
    if imported.source_status != "complete" and not report_only:
        raise click.ClickException("ShadowScan source report is incomplete; the BOM is partial")

    from nexus_symbiote.validators.risk import RiskScorer

    passed, report = RiskScorer(
        fail_threshold=policy.risk.fail_threshold,
        warn_threshold=policy.risk.warn_threshold,
        ignore_categories=policy.risk.ignore_categories,
        fail_on_severity=policy.risk.fail_on_severity,
    ).passes_gate(aibom)
    if not passed and not (report_only or policy.scan.failure_mode == "report-only"):
        err_console.print("[red]Imported claims do not establish complete verified coverage[/]")
        raise click.exceptions.Exit(1)


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

    from nexus_symbiote.core.hashing import parse_json_strict
    from nexus_symbiote.scanners.base import read_regular_text
    from nexus_symbiote.scanners.shadowscan import MAX_REPORT_BYTES, ShadowScanImporter
    from nexus_symbiote.utils.crypto import verify_sigstore_digest

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
@click.option(
    "--signature-policy",
    type=click.Path(exists=True, path_type=Path),
    help="Explicit operator signer policy JSON; requires --project",
)
def validate(aibom_path: str, project: str | None, signature_policy: Path | None = None) -> None:
    """Validate an AIBOM for completeness and integrity."""
    bom = AIBOM.load(Path(aibom_path))

    from nexus_symbiote.signature_policy import load_signature_policies
    from nexus_symbiote.validators.completeness import CompletenessValidator
    from nexus_symbiote.validators.integrity import IntegrityValidator

    if signature_policy and not project:
        raise click.BadParameter("--signature-policy requires --project")
    try:
        signature_policies = (
            load_signature_policies(signature_policy, Path(project))
            if signature_policy and project
            else []
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from None

    policy = _policy(Path(project).resolve() if project else Path(aibom_path).parent)
    valid = True
    console.print("[bold]Completeness check[/]")
    if policy.validation.require_completeness:
        cv = CompletenessValidator()
        c_report = (
            cv.validate_against_project(bom, Path(project).resolve())
            if project
            else cv.validate(bom)
        )
        console.print("  Status: " + ("[green]PASS[/]" if c_report.is_complete else "[red]FAIL[/]"))
        console.print(f"  Components: {c_report.total_components}")
        for issue in c_report.issues:
            console.print(f"  {issue.severity.upper()} [{issue.surface}] {issue.description}")
        valid = valid and c_report.is_complete
    else:
        console.print("  SKIPPED by explicit policy")
    console.print("\n[bold]Integrity check[/]")
    if policy.validation.require_integrity:
        i_report = IntegrityValidator(signature_policies=signature_policies).validate(
            bom, Path(project).resolve() if project else None
        )
        console.print("  Status: " + ("[green]PASS[/]" if i_report.is_valid else "[red]FAIL[/]"))
        console.print(
            f"  Hashes verified: {i_report.hashes_verified}, failed: {i_report.hashes_failed}"
        )
        for integrity_issue in i_report.issues:
            console.print(
                f"  {integrity_issue.severity.upper()} [{integrity_issue.component_ref}] {integrity_issue.detail}"
            )
        valid = valid and i_report.is_valid
    else:
        console.print("  SKIPPED by explicit policy")
    minimum = policy.validation.minimum_assurance_level
    if minimum == "verified":
        raise click.ClickException(
            "offline validate cannot establish verified assurance; use subject-bound cryptographic verification"
        )
    if minimum == "observed":
        levels = [c.assurance_level for c in bom.components]
        if (
            not bom.metadata.completeness
            or not levels
            or any(level is AssuranceLevel.DECLARED for level in levels)
        ):
            console.print("  ERROR: minimum observed assurance not attained")
            valid = False
        elif any(not c.claims for c in bom.components):
            console.print("  ERROR: observed assurance requires claim provenance")
            valid = False
    # Graph integrity is structural and cannot be disabled by a coverage policy.
    if bom.graph_issues():
        console.print("  ERROR: " + "; ".join(bom.graph_issues()))
        valid = False
    if not valid:
        raise click.exceptions.Exit(1)


@main.command()
@click.argument("aibom_path", type=click.Path(exists=True))
@click.option("--threshold", type=float, default=None, help="Fail threshold score")
@click.option("--json-output", is_flag=True, help="Output as JSON")
@click.option(
    "--fail-on-severity",
    type=click.Choice(["critical", "high", "medium", "low", "info", "none"]),
    default=None,
)
def risk(
    aibom_path: str, threshold: float | None, json_output: bool, fail_on_severity: str | None
) -> None:
    """Score supply-chain risks in an AIBOM."""
    bom = AIBOM.load(Path(aibom_path))

    from nexus_symbiote.validators.risk import RiskScorer

    policy = _policy(Path(aibom_path).parent)
    threshold = threshold if threshold is not None else policy.risk.fail_threshold
    if threshold <= 0 or not __import__("math").isfinite(threshold):
        raise click.BadParameter("threshold must be positive and finite", param_hint="--threshold")
    scorer = RiskScorer(
        fail_threshold=threshold,
        warn_threshold=policy.risk.warn_threshold,
        ignore_categories=policy.risk.ignore_categories,
        fail_on_severity=fail_on_severity or policy.risk.fail_on_severity,
    )
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


@main.command("blast-radius")
@click.argument("aibom_path", type=click.Path(exists=True))
@click.argument("component_ref")
@click.option("--json-output", is_flag=True)
def blast_radius_command(aibom_path: str, component_ref: str, json_output: bool) -> None:
    """Show repository dependencies potentially affected by a component compromise."""
    from nexus_symbiote.graph import blast_radius

    try:
        result = blast_radius(AIBOM.load(Path(aibom_path)), component_ref)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        console.print(
            "[bold]Potential blast radius[/] (repository association; effective authority unknown)"
        )
        console.print("  Agents: " + ", ".join(result["affected_agents"]))
        console.print("  Components: " + ", ".join(result["reachable_components"]))


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

    write_output_file(target, DEFAULT_POLICY_YAML, overwrite=force)
    console.print(f"[bold green]Created[/] {target}")
    console.print("  Edit this file to customize scan, risk, and validation policies.")


register_runtime_commands(main)
register_live_commands(main)
register_supply_chain_commands(main)

if __name__ == "__main__":
    main()
