"""Helpers shared by the command modules: the active mode, refusals and BOM loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from nexus_symbiote import exits, modes
from nexus_symbiote.core.aibom import AIBOM


def current_mode() -> modes.ResolvedMode:
    """The mode of the running command; offline when none was resolved."""
    context = click.get_current_context(silent=True)
    found = context.find_object(modes.ResolvedMode) if context else None
    return found or modes.ResolvedMode(modes.Mode.OFFLINE, "default")


def require_live(command: str, operation: str, *, replay: str | None = None) -> None:
    """Refuse a live step unless live mode is in effect (exit 3, nothing written)."""
    resolved = current_mode()
    if not resolved.offline:
        return
    reason = {
        "flag": "--offline was given",
        "environment": f"{modes.ENV_VAR}=offline",
    }.get(resolved.source, "offline is the default")
    alternative = f", or pass {replay} to analyze a saved export offline" if replay else ""
    raise exits.Incomplete(
        f"refused: {command} {operation}, and offline mode forbids it ({reason}). "
        f"Rerun as 'nexus-symbiote --live {command} ...' or set {modes.ENV_VAR}=live{alternative}."
    )


def collection_evidence(*, live: list[Any] | None = None) -> dict[str, Any]:
    """Completeness fields that record how this run collected its evidence."""
    return {
        "collection_mode": "live" if live else "offline",
        "offline_enforced": modes.current() is modes.Mode.OFFLINE,
        "live_operations": live or [],
    }


def load_bom(path: str | Path) -> AIBOM:
    """Load a native AgentBOM or fail with exit 1 and a bounded message."""
    try:
        return AIBOM.load(Path(path))
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        detail = str(exc).splitlines()[0][:200] if str(exc) else type(exc).__name__
        raise click.ClickException(f"{path} is not a readable native AgentBOM: {detail}") from None
