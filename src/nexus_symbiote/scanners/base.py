"""Abstract scanner interface for discovering agent supply chain components."""

from __future__ import annotations

import ast
import os
import warnings
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from nexus_symbiote.core.aibom import DependencyEdge
from nexus_symbiote.core.models import AnyComponent, MCPClientComponent
from nexus_symbiote.utils.confined import ConfinedCollection

MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_MODEL_BYTES = 1024 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024


def read_regular_text(path: Path, *, max_bytes: int = MAX_CONFIG_BYTES) -> str:
    """Legacy explicit-file reader, bounded and no-follow for all path parts."""
    with ConfinedCollection(
        path.parent, [], max_file_bytes=max_bytes, max_total_bytes=max_bytes
    ) as files:
        content = files.read_text(path.name)
    if content is None:
        raise OSError("bounded regular-file read refused")
    return content


def hash_regular_file(path: Path, *, max_bytes: int = MAX_MODEL_BYTES) -> str:
    """Legacy explicit-file hash; automatic scans use their project-root boundary."""
    with ConfinedCollection(path.parent, [], max_total_bytes=max_bytes) as files:
        digest = files.hash_file(path.name, max_bytes=max_bytes)
    if digest is None:
        raise OSError("bounded regular-file hash refused")
    return digest


def sanitized_origin(value: str) -> str:
    """Omit paths as well as userinfo, queries and fragments from URL output."""
    try:
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.hostname:
            return "[redacted]"
        host = parsed.hostname
        host = f"[{host}]" if ":" in host else host
        port = parsed.port
        return f"{parsed.scheme.lower()}://{host}" + (f":{port}" if port is not None else "")
    except ValueError:
        return "[redacted]"


def parse_python(source: str) -> ast.Module:
    """Parse scanned source without printing compiler warnings, which quote its raw bytes."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        warnings.simplefilter("ignore", DeprecationWarning)
        return ast.parse(source)


def project_relative(root: Path) -> Callable[[str], str]:
    """Map a location inside ``root`` to project-relative POSIX text; others stay as given.

    The one rule for paths in an inventory: collection applies it before recording,
    and readers apply it to records an earlier release wrote with absolute paths.
    """
    base = os.path.abspath(root)
    prefix = base.rstrip(os.sep) + os.sep

    def relative(value: str) -> str:
        if value == base:
            return "."
        if not value.startswith(prefix):
            return value
        return value[len(prefix) :].replace(os.sep, "/")

    return relative


@dataclass
class ScanResult:
    """The output of a single scanner pass."""

    scanner_name: str
    components: list[AnyComponent] = field(default_factory=list)
    dependencies: list[DependencyEdge] = field(default_factory=list)
    surfaces_scanned: list[str] = field(default_factory=list)
    surfaces_excluded: list[str] = field(default_factory=list)
    scan_failures: list[str] = field(default_factory=list)
    source_report_digest: str | None = None
    source_report_content_digest: str | None = None
    source_report_content_profile: str | None = None
    source_report_path: str | None = None
    source_report_format: str | None = None
    source_report_status: str | None = None
    source_projection_limitations: list[str] | None = None
    source_unmapped_count: int = 0
    source_unmapped_indexes: list[int] = field(default_factory=list)

    def make_portable(self, root: Path) -> None:
        """Record locations inside the project rather than where it was checked out.

        A checkout path is not a property of the project: recorded, it made the
        same tree collected in CI differ from its baseline on every component.
        """
        relative = project_relative(root)
        for component in self.components:
            if component.source_path is not None:
                component.source_path = relative(component.source_path)
            if isinstance(component, MCPClientComponent) and component.config_path is not None:
                component.config_path = relative(component.config_path)
            for key in ("config_paths", "source_paths"):
                values = component.properties.get(key)
                if isinstance(values, list):
                    component.properties[key] = [
                        relative(value) if isinstance(value, str) else value for value in values
                    ]
        for records in (self.surfaces_scanned, self.surfaces_excluded, self.scan_failures):
            records[:] = [relative(record) for record in records]


class SourceBudget:
    """Bound the source text a collector reads while it looks for references.

    A file count says nothing about cost and made ordinary projects fail, so the
    bound is the text read. What does not fit is one named coverage gap.
    """

    def __init__(self, label: str, result: ScanResult, limit: int = MAX_SOURCE_BYTES) -> None:
        self._label = label
        self._result = result
        self._remaining = limit
        self.exhausted = False

    def admit(self, size: int) -> bool:
        if self.exhausted:
            return False
        self._remaining -= size
        if self._remaining < 0:
            self.exhausted = True
            self._result.scan_failures.append(
                f"{self._label} exceed the combined size limit: the rest were not read"
            )
        return not self.exhausted


class Scanner(ABC):
    """Base class for all component scanners."""

    name: str = "base"
    _exclude_paths: tuple[str | Path, ...] = ()
    _files: ConfinedCollection | None = None

    def configure(self, exclude_paths: Iterable[str | Path] = ()) -> None:
        """Set root-relative or absolute collection exclusions before ``scan``."""
        self._exclude_paths = tuple(exclude_paths)

    @contextmanager
    def _collection(
        self, root: Path, result: ScanResult, **limits: Any
    ) -> Iterator[ConfinedCollection]:
        with ConfinedCollection(
            root,
            result.scan_failures,
            result.surfaces_excluded,
            exclude_paths=self._exclude_paths,
            **limits,
        ) as files:
            self._files = files
            try:
                yield files
            finally:
                self._files = None

    @abstractmethod
    def scan(self, project_root: Path) -> ScanResult:
        """Scan a project directory and return discovered components."""

    def _safe_read_json(self, path: Path) -> dict[str, Any] | list[Any] | None:
        # Compatibility for scanner helpers; scans should open a _collection so
        # every failure is retained on the ScanResult and the project root pinned.
        if self._files is not None:
            data = self._files.read_json(path)
        else:
            with ConfinedCollection(path.parent, []) as files:
                data = files.read_json(path.name)
        return data if isinstance(data, (dict, list)) else None

    def _read_mapping(
        self, path: Path, result: ScanResult, *, missing_ok: bool = True
    ) -> dict[str, Any] | None:
        """Read a bounded static JSON/YAML mapping and retain parse failures."""
        if self._files is None:
            raise RuntimeError("_read_mapping called outside a _collection context")
        if path.suffix.lower() == ".json":
            data = self._files.read_json(path, missing_ok=missing_ok)
        else:
            text = self._files.read_text(path, missing_ok=missing_ok)
            if text is None:
                return None
            try:
                import yaml
            except ImportError:
                result.scan_failures.append(f"{path.name}: YAML parser unavailable")
                return None
            from nexus_symbiote.policy import parse_yaml_mapping

            try:
                for index, token in enumerate(yaml.scan(text)):
                    if index >= 20_000 or isinstance(
                        token, (yaml.AliasToken, yaml.AnchorToken, yaml.TagToken)
                    ):
                        raise ValueError("unsupported YAML graph")
                data = parse_yaml_mapping(text)
            except (ValueError, RecursionError, yaml.YAMLError):
                result.scan_failures.append(
                    f"{path.name}: YAML mapping parse failed or unsupported"
                )
                return None
        if data is None:
            return None
        if not isinstance(data, dict):
            result.scan_failures.append(f"{path.name}: expected a mapping")
            return None
        return data
