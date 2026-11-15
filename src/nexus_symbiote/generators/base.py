"""Abstract generator interface for AIBOM output formats."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nexus_symbiote.core.aibom import AIBOM


@dataclass(frozen=True)
class ExportResult:
    document: dict[str, Any]
    loss_report: dict[str, Any]


class Generator(ABC):
    """Base class for all output format generators."""

    format_name: str = "base"

    @abstractmethod
    def generate(self, bom: AIBOM) -> dict[str, Any]:
        """Convert an AIBOM into the target format as a dict."""

    def generate_json(self, bom: AIBOM, indent: int = 2) -> str:
        """Convert an AIBOM into the target format as a JSON string.

        A document that holds NaN or an infinity raises ValueError: written out, those
        are not JSON, and a strict reader refuses the whole export.
        """
        import json

        return json.dumps(self.generate(bom), indent=indent, allow_nan=False)

    def generate_with_report(self, bom: AIBOM) -> ExportResult:
        from nexus_symbiote.generators._common import loss_report

        document = self.generate(bom)
        return ExportResult(document, loss_report(bom, self.format_name))

    def save(self, bom: AIBOM, path: Path, indent: int = 2) -> None:
        """Replace ``path`` atomically, never writing through a symbolic link."""
        from nexus_symbiote.utils.files import write_output_file

        write_output_file(path, self.generate_json(bom, indent=indent))
