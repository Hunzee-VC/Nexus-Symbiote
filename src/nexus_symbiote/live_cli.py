"""Explicit opt-in served-interface observations; static scans remain offline."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import click

from nexus_symbiote import modes
from nexus_symbiote.scanners.live_mcp import (
    DEFAULT_CLIENT_NAME,
    DEFAULT_CLIENT_VERSION,
    DiscoveryResult,
    discover_tools,
)
from nexus_symbiote.utils.terminal import neutralize, write_cli_output

_REFERENCE = re.compile(r"[!-~]{1,256}")


def _server_ref(_ctx: click.Context, _param: click.Parameter, value: str | None) -> str | None:
    if value is not None and not _REFERENCE.fullmatch(value):
        raise click.BadParameter("use 1 to 256 printable ASCII characters without spaces")
    return value


def review_notice(names: list[str]) -> None:
    """Name the tools whose displayed descriptor omits content the fingerprint binds."""
    if names:
        click.echo(
            "Review: the displayed descriptor of these tools omits schema literals or "
            "reduces URLs that the fingerprint covers; inspect the server's original "
            "descriptor before approving: " + ", ".join(neutralize(name) for name in names),
            err=True,
        )


@click.command("discover-mcp")
@click.argument("endpoint")
@click.option(
    "--allowed-origin",
    multiple=True,
    required=True,
    help="Exact HTTPS origin explicitly approved by the operator",
)
@click.option(
    "--token-env",
    help="Environment variable holding a bearer token; the token is never written to evidence",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    help="Write the observation to this file instead of standard output.",
)
@click.option(
    "--record",
    is_flag=True,
    help=(
        "Write a native AgentBOM inventory of a complete observation, for diff, instead "
        "of the observation report; an incomplete observation writes nothing."
    ),
)
@click.option(
    "--server-ref",
    callback=_server_ref,
    help="Component reference of the observed server in the inventory (default: derived from the endpoint).",
)
@click.option(
    "--client-name",
    default=DEFAULT_CLIENT_NAME,
    show_default=True,
    help="clientInfo name sent in initialize; use your production host's so the server cannot single out the observer.",
)
@click.option(
    "--client-version",
    default=DEFAULT_CLIENT_VERSION,
    show_default=True,
    help="clientInfo version sent in initialize.",
)
@click.option("--user-agent", help="User-Agent header to send; none is sent by default.")
def discover_mcp(
    endpoint: str,
    allowed_origin: tuple[str, ...],
    token_env: str | None,
    output: Path | None,
    record: bool,
    server_ref: str | None,
    client_name: str,
    client_version: str,
    user_agent: str | None,
) -> None:
    """Live: observe tools/list without executing tools or starting local servers.

    The initialize result (protocol version, server identity, capabilities and
    instructions) and, when declared, prompts/list and resources/templates/list
    are observed too. With --record, two observations of one endpoint can be
    compared with diff: a changed tool definition, tool set or server instructions,
    prompts or resource templates raise a critical drift alert.
    """
    modes.require_live("discover-mcp")
    if server_ref is not None and not record:
        raise click.UsageError("--server-ref applies only to --record")
    token = os.environ.get(token_env) if token_env else None
    if token_env and not token:
        raise click.ClickException("the explicitly selected token environment variable is empty")
    result = discover_tools(
        endpoint,
        allowed_origins=allowed_origin,
        bearer_token=token,
        client_name=client_name,
        client_version=client_version,
        user_agent=user_agent,
    )
    if record:
        _record(result, output, server_ref)
        return
    text = json.dumps(result.to_dict(), indent=2) + "\n"
    if output:
        write_cli_output(output, text)
    else:
        click.echo(text, nl=False)
    if not result.complete:
        raise click.exceptions.Exit(1)


def _record(result: DiscoveryResult, output: Path | None, server_ref: str | None) -> None:
    from nexus_symbiote.live.inventory import observation_inventory

    if not result.complete:
        for failure in result.failures:
            click.echo("Observation failure: " + neutralize(failure), err=True)
        raise click.ClickException("the observation is incomplete; no inventory was written")
    try:
        bom = observation_inventory(result, server_ref=server_ref)
    except ValueError as exc:
        # Messages are fixed local strings; neutralize them all the same.
        raise click.ClickException(neutralize(exc)) from None
    text = bom.to_json() + "\n"
    if output:
        write_cli_output(output, text)
    else:
        click.echo(text, nl=False)
    review_notice([tool.name for tool in result.tools if tool.display_differs])


def register_live_commands(main: click.Group) -> None:
    main.add_command(discover_mcp)
