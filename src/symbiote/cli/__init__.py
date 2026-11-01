"""The ``symbiote`` command-line interface (``spec/cli.md``)."""

from __future__ import annotations

from symbiote.cli.app import app, main
from symbiote.cli.incident import incident_app

app.add_typer(incident_app, name="incident")

__all__ = ["app", "main"]
