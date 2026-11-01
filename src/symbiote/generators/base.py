"""Abstract generator interface for AIBOM output formats."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from symbiote.core.aibom import AIBOM


class Generator(ABC):
    """Base class for all output format generators."""

    format_name: str = "base"

    @abstractmethod
    def generate(self, bom: AIBOM) -> dict[str, Any]:
        """Convert an AIBOM into the target format as a dict."""
        ...

    def generate_json(self, bom: AIBOM, indent: int = 2) -> str:
        """Convert an AIBOM into the target format as a JSON string."""
        import json

        return json.dumps(self.generate(bom), indent=indent, default=str)

    def save(self, bom: AIBOM, path: Path, indent: int = 2) -> None:
        """Write the generated AIBOM to a file."""
        path.write_text(self.generate_json(bom, indent=indent), encoding="utf-8")
