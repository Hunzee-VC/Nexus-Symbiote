"""CLI commands for foreign SBOM import and per-component evidence profiles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from nexus_symbiote.core.aibom import AIBOM, ContentSerialError, NativeFormatError, prepare
from nexus_symbiote.evidence_profile import build_evidence_profile
from nexus_symbiote.sbom_import import (
    classify_pinning_state,
    import_foreign_sbom,
    unread_shape_census,
    walk_nested_manifests,
)
from nexus_symbiote.supply_chain_cli import _refuse_source_overwrite
from nexus_symbiote.utils.terminal import (
    echo_line,
    json_text,
    neutralize,
    safe_line,
    write_cli_output,
)


def _load_native(path: Path) -> AIBOM:
    try:
        return AIBOM.load(path)
    except NativeFormatError as exc:
        raise click.ClickException(
            f"{neutralize(path)} is not a valid native AIBOM file. {neutralize(exc)}"
        ) from exc


@click.command("import-sbom")
@click.argument("foreign_bom_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Write the resulting native AgentBOM JSON to this file.",
)
@click.option(
    "--into",
    "into_bom",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Existing native AgentBOM to merge imported SBOM claims into.",
)
@click.option(
    "--project",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Trusted project root for SHA-256 local file binding, nested manifests, and shape census.",
)
@click.option(
    "--reveal-names",
    is_flag=True,
    help="Retain plain component names from the foreign SBOM instead of sha256-hashed names.",
)
@click.option(
    "--walk-manifests",
    is_flag=True,
    help="Walk nested manifests below --project and record manifest-only vs locked pinning state.",
)
@click.option(
    "--census",
    is_flag=True,
    help="Count unread non-control-plane artifact shapes (*.ipynb, n8n/*.json, *.tf, Chart.yaml).",
)
@click.option(
    "--json-output",
    is_flag=True,
    help="Print a structured JSON summary of imported, bound, and conflicting entries.",
)
def import_sbom_cmd(
    foreign_bom_path: Path,
    output: Path | None,
    into_bom: Path | None,
    project: Path | None,
    reveal_names: bool,
    walk_manifests: bool,
    census: bool,
    json_output: bool,
) -> None:
    """Import a foreign CycloneDX or SPDX SBOM as DECLARED evidence without picking silent winners."""
    from nexus_symbiote.cli import _project_root

    if (walk_manifests or census) and project is None:
        raise click.UsageError("--walk-manifests and --census require --project")
    _refuse_source_overwrite(output, foreign_bom_path)
    if into_bom is not None:
        _refuse_source_overwrite(output, into_bom)

    root = _project_root(str(project), label="--project") if project is not None else None
    base_bom = _load_native(into_bom) if into_bom is not None else None

    try:
        summary = import_foreign_sbom(
            foreign_bom_path,
            target_aibom=base_bom,
            project_root=root,
            reveal_names=reveal_names,
        )
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        raise click.ClickException(
            f"Cannot safely import foreign SBOM: {neutralize(type(exc).__name__)}"
        ) from exc

    bom = summary.aibom
    nested_count = 0
    manifest_failures: list[str] = []
    if walk_manifests and root is not None:
        nested_items, manifest_failures = walk_nested_manifests(root)
        existing_refs = {c.bom_ref for c in bom.components}
        for comp in nested_items:
            if comp.bom_ref not in existing_refs:
                bom.components.append(comp)
                existing_refs.add(comp.bom_ref)
                nested_count += 1
        if manifest_failures and bom.metadata.completeness is not None:
            for fail in manifest_failures:
                if fail not in bom.metadata.completeness.scan_failures:
                    bom.metadata.completeness.scan_failures.append(fail)

    classify_pinning_state(bom)
    shapes_payload: list[dict[str, Any]] = []
    if census and root is not None:
        shapes = unread_shape_census(root)
        shapes_payload = [{"shape": s.shape, "count": s.count, "owner": s.owner} for s in shapes]
        if bom.metadata.completeness is not None:
            for item in shapes:
                marker = f"unread-shape:{item.shape}:{item.count}"
                if marker not in bom.metadata.completeness.unobserved_surfaces:
                    bom.metadata.completeness.unobserved_surfaces.append(marker)

    try:
        prepare(bom)
        serialized = bom.to_native_json()
    except (ContentSerialError, NativeFormatError) as exc:
        raise click.ClickException(neutralize(str(exc))) from exc

    if output is not None:
        write_cli_output(output, serialized)
        echo_line("Imported ", summary.imported_count, " components into ", output, err=True)

    if json_output:
        report = {
            "source_format": summary.source_format,
            "document_sha256": summary.document_sha256,
            "imported_count": summary.imported_count,
            "bound_local_count": summary.bound_local_count,
            "conflict_count": summary.conflict_count,
            "nested_manifest_components": nested_count,
            "unread_shapes": shapes_payload,
        }
        click.echo(json_text(json.dumps(report, indent=2)))
    elif output is None:
        click.echo(json_text(serialized))


@click.command("evidence-profile")
@click.argument("aibom_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Write the evidence profile report to this file instead of standard output.",
)
@click.option(
    "--json-output",
    is_flag=True,
    help="Emit the per-component evidence profile as JSON.",
)
def evidence_profile_cmd(
    aibom_path: Path,
    output: Path | None,
    json_output: bool,
) -> None:
    """Report concrete evidence attributes per component without a scalar TrustScore."""
    _refuse_source_overwrite(output, aibom_path)
    bom = _load_native(aibom_path)
    profile = build_evidence_profile(bom)

    if json_output:
        payload = json.dumps(profile, indent=2) + "\n"
        if output is not None:
            write_cli_output(output, payload)
        else:
            click.echo(json_text(payload), nl=False)
        return

    lines = [
        safe_line("Evidence profile schema: ", profile["schema"]),
        safe_line("Components evaluated: ", str(profile["component_count"])),
    ]
    for entry in profile["components"]:
        ev = entry["evidence"]
        present_flags = [k for k, v in ev.items() if v]
        missing_flags = entry["missing_evidence"]
        lines.append(
            safe_line(
                "  component: ",
                entry["bom_ref"],
                " (",
                entry["component_type"],
                ", assurance=",
                entry["assurance_level"],
                ")",
            )
        )
        lines.append(
            safe_line(
                "    present: ",
                ", ".join(present_flags) if present_flags else "none",
            )
        )
        lines.append(
            safe_line(
                "    missing: ",
                ", ".join(missing_flags) if missing_flags else "none",
            )
        )
        lines.append(
            safe_line(
                "    findings: ",
                str(entry["finding_count"]),
                f" (highest={entry['highest_finding_severity']})"
                if entry["highest_finding_severity"]
                else "",
            )
        )
    rendered = "\n".join(lines) + "\n"
    if output is not None:
        write_cli_output(output, rendered)
    else:
        click.echo(rendered, nl=False)


def register_sbom_commands(main: click.Group) -> None:
    main.add_command(import_sbom_cmd)
    main.add_command(evidence_profile_cmd)
