"""The ``inspect-provenance`` command: model forensics, alias indirection, guardrails, and lineage."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import click

from nexus_symbiote.core.aibom import NativeFormatError
from nexus_symbiote.core.hashing import open_directory_nofollow
from nexus_symbiote.provenance_surfaces import ProvenanceInputError, inspect_provenance_surfaces
from nexus_symbiote.utils.terminal import (
    echo_line,
    json_text,
    neutralize,
    refuse_dash_output,
    write_cli_output,
)

_FILE_PATH = click.Path(exists=True, dir_okay=False, path_type=Path)
_DIR_PATH = click.Path(exists=True, file_okay=False, path_type=Path)
_OUT_PATH = click.Path(path_type=Path)
_SEVERITIES = click.Choice(["critical", "high", "medium", "low", "info", "none"])


def _same_path(first: Path, second: Path) -> bool:
    return os.path.abspath(first) == os.path.abspath(second) or (
        first.exists() and second.exists() and os.path.samefile(first, second)
    )


def _resolve_project_root(project: Path) -> Path:
    try:
        fd = open_directory_nofollow(project)
    except OSError as exc:
        msg = "--project must name an existing directory without traversing symbolic links"
        raise click.ClickException(msg) from exc
    os.close(fd)
    return Path(os.path.abspath(project))


def _refuse_unsafe_outputs(
    outputs: Sequence[Path], inputs: Sequence[Path], project_root: Path | None
) -> None:
    for idx, out in enumerate(outputs):
        refuse_dash_output(out)
        if any(_same_path(out, src) for src in inputs):
            raise click.BadParameter("an output file must not overwrite any input file")
        if any(_same_path(out, other) for other in outputs[idx + 1 :]):
            raise click.BadParameter("-o and --bom-output must name different files")
        if project_root is not None:
            resolved_out = Path(os.path.abspath(out))
            if resolved_out == project_root or resolved_out.is_relative_to(project_root):
                raise click.BadParameter("an output file must not lie inside --project")


def _print_summary(doc: Mapping[str, Any]) -> None:
    counts = (
        f"{len(doc['findings'])} finding(s), {len(doc['pickle_inspections'])} pickle(s), "
        f"{len(doc['gguf_inspections'])} GGUF file(s), {len(doc['alias_routes'])} alias route(s), "
        f"{len(doc['guardrails'])} guardrail(s), {len(doc['lineage_edges'])} lineage edge(s)"
    )
    echo_line("Provenance inspection: ", counts)
    for f in doc["findings"][:15]:
        echo_line(
            f"  [{f['severity']}] ", f["category"], " on ", f["component_ref"], ": ", f["detail"]
        )
    gate = doc["gate"]
    if gate["fail_on"] == "none":
        echo_line("Provenance gate: ", "not applied (--fail-on none)")
    elif gate["passed"]:
        echo_line("Provenance gate passed: ", f"no findings at or above {gate['fail_on']}")
    else:
        echo_line("Provenance gate failed: ", "; ".join(gate["reasons"]))


@click.command("inspect-provenance")
@click.option("--inventory", type=_FILE_PATH, help="Existing native AgentBOM file to enrich.")
@click.option("--project", type=_DIR_PATH, help="Project root to inspect through confined reads.")
@click.option("--claims", "claim_paths", multiple=True, type=_FILE_PATH, help="Claim JSON file(s).")
@click.option(
    "--attestation",
    "attestation_paths",
    multiple=True,
    type=_FILE_PATH,
    help="Attestation JSON file(s).",
)
@click.option("-o", "--output", type=_OUT_PATH, help="Write the provenance JSON document here.")
@click.option("--bom-output", type=_OUT_PATH, help="Write the enriched native AgentBOM JSON here.")
@click.option(
    "--json-output", is_flag=True, help="Print the provenance document as JSON on stdout."
)
@click.option(
    "--fail-on",
    type=_SEVERITIES,
    default="high",
    show_default=True,
    help="Severity gate threshold.",
)
def inspect_provenance_cmd(
    inventory: Path | None,
    project: Path | None,
    claim_paths: tuple[Path, ...],
    attestation_paths: tuple[Path, ...],
    output: Path | None,
    bom_output: Path | None,
    json_output: bool,
    fail_on: str,
) -> None:
    """Inspect pickle/GGUF forensics, alias routing, guardrails, memory, and training lineage."""
    if inventory is None and project is None and not claim_paths and not attestation_paths:
        msg = "Provide at least one of --inventory, --project, --claims or --attestation"
        raise click.UsageError(msg)
    project_root = _resolve_project_root(project) if project is not None else None
    inputs = [*([inventory] if inventory is not None else []), *claim_paths, *attestation_paths]
    outputs = [p for p in (output, bom_output) if p is not None]
    _refuse_unsafe_outputs(outputs, inputs, project_root)

    try:
        document, bom = inspect_provenance_surfaces(
            inventory_path=inventory,
            project_root=project_root,
            claim_paths=claim_paths,
            attestation_paths=attestation_paths,
            fail_on=fail_on,
        )
    except NativeFormatError as exc:
        msg = f"{neutralize(inventory)} is not a valid native AIBOM file. {neutralize(exc)}"
        raise click.ClickException(msg) from None
    except ProvenanceInputError as exc:
        raise click.ClickException(neutralize(exc)) from None

    rendered = json.dumps(document, indent=2) + "\n"
    if output is not None:
        write_cli_output(output, rendered)
    if bom_output is not None:
        write_cli_output(bom_output, bom.to_native_json() + "\n")

    if json_output:
        click.echo(json_text(rendered), nl=False)
    else:
        _print_summary(document)

    if not document["gate"]["passed"]:
        raise click.exceptions.Exit(1)


def register_provenance_commands(main: click.Group) -> None:
    main.add_command(inspect_provenance_cmd)
