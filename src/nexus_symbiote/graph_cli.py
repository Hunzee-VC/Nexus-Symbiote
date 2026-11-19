"""The ``graph`` command: an inventory's associations, risk classes and exposure paths.

It writes one self-contained HTML file or a JSON document, offline. It restates the
native inventory and its recorded edges; it does not observe runtime reachability or
effective authority.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from nexus_symbiote.core.aibom import AIBOM, NativeFormatError
from nexus_symbiote.supply_chain_cli import _refuse_source_overwrite
from nexus_symbiote.utils.terminal import echo_line, json_text, neutralize, write_cli_output

DEFAULT_MAX_NODES = 2_000
MAX_NODES = 20_000


def register_graph_commands(main: click.Group) -> None:
    @main.command("graph")
    @click.argument("inventory", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option(
        "-o",
        "--output",
        type=click.Path(path_type=Path),
        help="Write the view to this file; required for HTML. JSON goes to standard output without it.",
    )
    @click.option(
        "--format",
        "output_format",
        type=click.Choice(["html", "json"]),
        default="html",
        show_default=True,
        help="A self-contained HTML page, or the view as a JSON document.",
    )
    @click.option(
        "--focus",
        metavar="REF",
        help=(
            "Show only this component's potential blast radius: it, what depends on it, and "
            "what it and the components of type agent among those reach."
        ),
    )
    @click.option(
        "--max-nodes",
        type=click.IntRange(1, MAX_NODES),
        default=DEFAULT_MAX_NODES,
        show_default=True,
        help=f"Fail rather than show more components than this (at most {MAX_NODES}).",
    )
    def graph(
        inventory: Path,
        output: Path | None,
        output_format: str,
        focus: str | None,
        max_nodes: int,
    ) -> None:
        """Write a view of an inventory's associations, risk classes and exposure paths.

        Exposure paths are the shortest recorded paths from agents and IDE agents to
        components with a code-exec, exfil-capable, write-capable or secret-access class
        or a high or critical finding. Edges are static repository associations; runtime
        use and effective authority are not observed.
        """
        from nexus_symbiote.graph_view import (
            GraphViewError,
            TooManyComponentsError,
            build_view,
            render_html,
            view_document,
        )

        if output_format == "html" and output is None:
            raise click.UsageError("the HTML view is written to a file: pass -o/--output")
        _refuse_source_overwrite(output, inventory)
        bom = _load_inventory(inventory)
        try:
            view = build_view(bom, max_nodes=max_nodes, focus=focus)
        except TooManyComponentsError as exc:
            raise click.ClickException(
                f"The view would show {exc.count} components, more than --max-nodes "
                f"{exc.limit}. Select part of the graph with --focus REF, or raise "
                f"--max-nodes (at most {MAX_NODES})."
            ) from exc
        except GraphViewError as exc:
            raise click.ClickException(neutralize(exc)) from exc
        if output_format == "html":
            text = render_html(view)
        else:
            text = json.dumps(view_document(view), indent=2)
        if output is None:
            click.echo(json_text(text))
            return
        write_cli_output(output, text)
        echo_line(
            "Graph view: ",
            f"{len(view.nodes)} components, {len(view.edges)} edges, "
            f"{len(view.paths)} exposure paths; coverage {view.coverage.status}",
            err=True,
        )

    @main.command("export-policy")
    @click.argument("inventory", type=click.Path(exists=True, dir_okay=False, path_type=Path))
    @click.option(
        "--format",
        "policy_format",
        type=click.Choice(["cedar", "rego", "json"]),
        default="cedar",
        show_default=True,
        help="Target authorization policy language.",
    )
    @click.option(
        "--verified-only/--include-declared",
        default=True,
        show_default=True,
        help="Allowlist only observed/verified components with pinned digests, or include declared entries.",
    )
    @click.option(
        "-o",
        "--output",
        type=click.Path(path_type=Path),
        help="Write the policy to this file instead of standard output.",
    )
    def export_policy(
        inventory: Path,
        policy_format: str,
        verified_only: bool,
        output: Path | None,
    ) -> None:
        """Export a default-deny Cedar, Rego, or JSON runtime allowlist from an inventory."""
        _refuse_source_overwrite(output, inventory)
        bom = _load_inventory(inventory)
        text = render_authorization_policy(bom, policy_format, verified_only=verified_only)
        if output is None:
            click.echo(
                json_text(text) if policy_format == "json" else text, nl=policy_format == "json"
            )
            return
        write_cli_output(output, text)


def render_authorization_policy(
    bom: AIBOM, policy_format: str = "cedar", *, verified_only: bool = True
) -> str:
    """Render a deterministic Cedar, Rego v1, or JSON authorization policy from an inventory."""
    from nexus_symbiote.core.enums import AssuranceLevel
    from nexus_symbiote.core.models import MCPServerComponent, ModelComponent, ToolComponent
    from nexus_symbiote.utils.crypto import VERIFIED_SIGNING_STATUSES

    allowed_assurance = {AssuranceLevel.OBSERVED, AssuranceLevel.VERIFIED}
    tools = [
        {
            "bom_ref": c.bom_ref,
            "name": c.name,
            "mcp_server_ref": c.mcp_server_ref,
            "definition_hash": c.definition_hash,
        }
        for c in sorted(bom.components, key=lambda x: x.bom_ref)
        if isinstance(c, ToolComponent)
        and c.definition_hash
        and (not verified_only or c.assurance_level in allowed_assurance)
    ]
    servers = [
        {
            "bom_ref": c.bom_ref,
            "name": c.name,
            "transport": c.transport,
            "version_pinned": c.version_pinned,
            "mcp_role": c.properties.get("mcp_role", "server"),
        }
        for c in sorted(bom.components, key=lambda x: x.bom_ref)
        if isinstance(c, MCPServerComponent)
        and (
            not verified_only
            or (c.version_pinned is True and c.assurance_level in allowed_assurance)
        )
    ]
    models = [
        {
            "bom_ref": c.bom_ref,
            "name": c.name,
            "sha256": c.hashes.get("sha256"),
            "signing_status": c.signing_status,
        }
        for c in sorted(bom.components, key=lambda x: x.bom_ref)
        if isinstance(c, ModelComponent)
        and c.hashes.get("sha256")
        and (not verified_only or c.signing_status in VERIFIED_SIGNING_STATUSES)
    ]
    bundle = {
        "format": "nexus-symbiote/authorization-policy/v1",
        "serial_number": bom.metadata.serial_number,
        "verified_only": verified_only,
        "allowed_tools": tools,
        "allowed_mcp_servers": servers,
        "allowed_models": models,
    }
    if policy_format == "json":
        return json.dumps(bundle, indent=2)
    if policy_format == "rego":
        return (
            "package nexus_symbiote.authz\n\nimport rego.v1\n\n"
            "default allow_tool := false\ndefault allow_model := false\n\n"
            f"allowed_tools := {json.dumps({t['bom_ref']: t['definition_hash'] for t in tools}, sort_keys=True)}\n"
            f"allowed_models := {json.dumps({m['bom_ref']: m['sha256'] for m in models}, sort_keys=True)}\n\n"
            "allow_tool if {\n"
            "  expected := allowed_tools[input.tool_ref]\n"
            "  input.definition_hash == expected\n"
            "}\n\n"
            "allow_model if {\n"
            "  expected := allowed_models[input.model_ref]\n"
            "  input.sha256 == expected\n"
            "}\n"
        )
    lines = ["// Nexus SymBiote generated default-deny Cedar policy (v1)"]
    for t in tools:
        lines.append(
            f'permit (principal, action == NexusSymbiote::Action::"InvokeTool", '
            f"resource == NexusSymbiote::Tool::{json.dumps(t['bom_ref'])}) when {{\n"
            f"  context.definition_hash == {json.dumps(t['definition_hash'])}\n}};"
        )
    for m in models:
        lines.append(
            f'permit (principal, action == NexusSymbiote::Action::"UseModel", '
            f"resource == NexusSymbiote::Model::{json.dumps(m['bom_ref'])}) when {{\n"
            f"  context.sha256 == {json.dumps(m['sha256'])}\n}};"
        )
    return "\n".join(lines) + "\n"


def _load_inventory(path: str | Path) -> AIBOM:
    # The error names the class of problem; it never quotes the document.
    try:
        return AIBOM.load(Path(path))
    except NativeFormatError as exc:
        raise click.ClickException(
            f"{neutralize(path)} is not a valid native AIBOM file. {neutralize(exc)}"
        ) from exc
