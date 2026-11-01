"""Abstract scanner interface for discovering agent supply chain components."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from symbote.core.models import AnyComponent


@dataclass
class ScanResult:
    """The output of a single scanner pass."""

    scanner_name: str
    components: list[AnyComponent] = field(default_factory=list)
    surfaces_scanned: list[str] = field(default_factory=list)
    surfaces_excluded: list[str] = field(default_factory=list)
    scan_failures: list[str] = field(default_factory=list)


class Scanner(ABC):
    """Base class for all component scanners."""

    name: str = "base"

    @abstractmethod
    def scan(self, project_root: Path) -> ScanResult:
        """Scan a project directory and return discovered components."""
        ...

    def _safe_read_json(self, path: Path) -> dict[str, Any] | list[Any] | None:
        import json

        try:
            data: dict[str, Any] | list[Any] = json.loads(path.read_text(encoding="utf-8"))
            return data
        except (json.JSONDecodeError, OSError):
            return None
