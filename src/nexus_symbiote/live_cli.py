"""MCP descriptor discovery: a live HTTPS observation, or a saved export read offline."""

from __future__ import annotations

import json
import os
from pathlib import Path

import click

from nexus_symbiote import exits
from nexus_symbiote.cli_common import require_live
from nexus_symbiote.core.hashing import open_regular_file
from nexus_symbiote.scanners.live_mcp import EXPORT_MAX_BYTES, discover_tools, read_tools_export
from nexus_symbiote.utils.files import write_output_file


@click.command("discover-mcp")
@click.argument("endpoint", required=False)
@click.option(
    "--allowed-origin",
    multiple=True,
    help="Exact HTTPS origin explicitly approved by the operator; required for live discovery",
)
@click.option(
    "--token-env",
    help="Environment variable holding a bearer token; the token is never written to evidence",
)
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Analyze a saved tools/list result offline instead of contacting ENDPOINT",
)
@click.option("-o", "--output", type=click.Path(path_type=Path))
def discover_mcp(
    endpoint: str | None,
    allowed_origin: tuple[str, ...],
    token_env: str | None,
    input_path: Path | None,
    output: Path | None,
) -> None:
    """Observe tools/list without executing tools or starting local servers.

    Live (needs --live): one bounded HTTPS session to ENDPOINT, whose origin must
    be approved with --allowed-origin. Offline: --input reads a saved tools/list
    result, a JSON-RPC response carrying one, or a JSON list of result pages, and
    applies the same checks; ENDPOINT then only labels the report.
    """
    if input_path is not None:
        if allowed_origin or token_env:
            raise click.UsageError(
                "--allowed-origin and --token-env apply to live discovery, not to --input"
            )
        try:
            with open_regular_file(input_path) as stream:
                data = stream.read(EXPORT_MAX_BYTES + 1)
        except OSError as exc:
            raise click.ClickException("cannot safely read the tools/list export") from exc
        result = read_tools_export(data, label=endpoint)
    else:
        require_live("discover-mcp", "contacts the MCP endpoint over HTTPS", replay="--input")
        if not endpoint or not allowed_origin:
            raise click.UsageError(
                "live discovery needs ENDPOINT and --allowed-origin; use --input for a saved export"
            )
        token = os.environ.get(token_env) if token_env else None
        if token_env and not token:
            raise click.ClickException(
                "the explicitly selected token environment variable is empty"
            )
        result = discover_tools(endpoint, allowed_origins=allowed_origin, bearer_token=token)
    text = json.dumps(result.to_dict(), indent=2) + "\n"
    if output:
        write_output_file(output, text)
    else:
        click.echo(text, nl=False)
    if not result.complete:
        raise click.exceptions.Exit(exits.INCOMPLETE)


def register_live_commands(main: click.Group) -> None:
    main.add_command(discover_mcp)
