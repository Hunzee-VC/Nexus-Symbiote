"""CLI command for typed CycloneDX (1.6/1.7) and SPDX 3.0.1 standard exports (R1.0.0-rc.1-3 & R1.3-4)."""

from __future__ import annotations

import os
from pathlib import Path

import click

from nexus_symbiote.core.aibom import AIBOM, ContentSerialError, NativeFormatError
from nexus_symbiote.policy import PolicyError
from nexus_symbiote.spdx_profiles import apply_agent_yaml_declarations
from nexus_symbiote.supply_chain_cli import _refuse_source_overwrite
from nexus_symbiote.utils.secrets import redact_text
from nexus_symbiote.utils.terminal import echo_line, json_text, neutralize, write_cli_output


def _load_native(path: Path) -> AIBOM:
    try:
        return AIBOM.load(path)
    except NativeFormatError as exc:
        raise click.ClickException(
            f"{neutralize(path)} is not a valid native AIBOM file. {neutralize(exc)}"
        ) from exc
    except (OSError, ValueError, RecursionError) as exc:
        raise click.ClickException(
            f"{neutralize(path)} is not a valid native AIBOM file. "
            f"Reason: {neutralize(type(exc).__name__)}."
        ) from exc


def _resolve_project_root(value: Path, *, label: str) -> Path:
    """Resolve a project directory without importing cli.py, refusing symlink escapes."""
    resolved = value.resolve()
    if Path(os.path.normpath(value.absolute())) == resolved:
        return resolved
    if (
        not value.is_absolute()
        and ".." not in value.parts
        and not resolved.is_relative_to(Path.cwd().resolve())
    ):
        raise click.BadParameter(
            f"{neutralize(value)} leads outside the current directory through a symbolic link; "
            f"name the directory it resolves to, {neutralize(resolved)}, to collect that directory",
            param_hint=label,
        )
    echo_line(
        "Note: ", label, " ", value, " resolves through a symbolic link to ", resolved, err=True
    )
    return resolved


@click.command("export-standard")
@click.argument("aibom_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["cyclonedx", "spdx"]),
    required=True,
    help="Target standard export format.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Write the exported document to this file instead of standard output.",
)
@click.option(
    "--cyclonedx-projection",
    type=click.Choice(["2", "3"]),
    default="3",
    show_default=True,
    help="CycloneDX projection version (3 emits typed AI edges, services, modelCard, pedigree).",
)
@click.option(
    "--spec-version",
    type=click.Choice(["1.6", "1.7"]),
    default="1.7",
    show_default=True,
    help="CycloneDX specification version when --format cyclonedx is selected.",
)
@click.option(
    "--spdx-projection",
    type=click.Choice(["3", "4"]),
    default="4",
    show_default=True,
    help="SPDX 3.0.1 projection version (4 emits typed AI/Dataset relationships and profile conformance).",
)
@click.option(
    "--spdx-namespace",
    help="Explicit HTTPS namespace base URI for SPDX 3.0.1 element IDs.",
)
@click.option(
    "--author",
    multiple=True,
    help="Operator-supplied author name(s) recorded in CycloneDX metadata.authors or SPDX Person.",
)
@click.option(
    "--agent-yaml",
    help="Relative path under --project to an agent.yaml 1.1 producer declaration file.",
)
@click.option(
    "--project",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Trusted project root used to confine --agent-yaml declarations.",
)
def export_standard_cmd(
    aibom_path: Path,
    output_format: str,
    output: Path | None,
    cyclonedx_projection: str,
    spec_version: str,
    spdx_projection: str,
    spdx_namespace: str | None,
    author: tuple[str, ...],
    agent_yaml: str | None,
    project: Path | None,
) -> None:
    """Export a native AgentBOM to CycloneDX (1.6/1.7) or SPDX 3.0.1 with typed AI projections."""
    from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
    from nexus_symbiote.generators.spdx import SPDXGenerator

    _refuse_source_overwrite(output, aibom_path)
    if agent_yaml is not None and project is None:
        raise click.UsageError("--agent-yaml requires --project")
    if project is not None and agent_yaml is None:
        raise click.UsageError("--project requires --agent-yaml")
    if output_format == "spdx" and spdx_projection == "3" and author:
        raise click.UsageError("--author with --format spdx requires --spdx-projection 4")
    if output_format == "cyclonedx" and spec_version == "1.6" and cyclonedx_projection == "2":
        raise click.UsageError("--spec-version 1.6 requires --cyclonedx-projection 3")

    bom = _load_native(aibom_path)
    if agent_yaml is not None and project is not None:
        root = _resolve_project_root(project, label="--project")
        try:
            notices = apply_agent_yaml_declarations(
                bom,
                root,
                relative_path=agent_yaml,
            )
        except (OSError, ValueError, UnicodeError, PolicyError) as exc:
            raise click.ClickException(
                f"Cannot safely read agent.yaml declarations: {neutralize(type(exc).__name__)}"
            ) from exc
        for notice in notices:
            echo_line("Declaration conflict: ", notice, err=True)

    if author:
        seen = set(bom.metadata.authors)
        for item in author:
            cleaned = neutralize(redact_text(item.strip()))
            if cleaned and cleaned not in seen:
                bom.metadata.authors.append(cleaned)
                seen.add(cleaned)

    try:
        if output_format == "cyclonedx":
            gen_cdx = CycloneDXGenerator(
                projection_version=int(cyclonedx_projection),
                spec_version=spec_version,
            )
            rendered = gen_cdx.generate_json(bom)
        else:
            gen_spdx = SPDXGenerator(
                namespace=spdx_namespace,
                projection_version=int(spdx_projection),
            )
            rendered = gen_spdx.generate_json(bom)
    except (ContentSerialError, ValueError, RecursionError) as exc:
        raise click.ClickException(
            f"Export failed schema or consistency checks: {neutralize(type(exc).__name__)}"
        ) from exc

    if output is not None:
        write_cli_output(output, rendered)
    else:
        click.echo(json_text(rendered))


def register_export_standard_commands(main: click.Group) -> None:
    main.add_command(export_standard_cmd)
