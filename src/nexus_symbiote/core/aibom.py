"""The AIBOM document model — the top-level container for an AgentBOM."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator

from nexus_symbiote import __version__
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.models import (
    AIBOMMetadata,
    AnyComponent,
)

_MAX_BOM_BYTES = 64 * 1024 * 1024


def _document_timestamp() -> datetime:
    """Return a UTC timestamp, honoring SOURCE_DATE_EPOCH for reproducibility."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        try:
            return datetime.fromtimestamp(int(epoch), tz=UTC)
        except (ValueError, OSError, OverflowError):
            pass
    return datetime.now(UTC)


class DependencyEdge(BaseModel):
    """A typed relationship between two components."""

    source_ref: str
    target_ref: str
    relationship: str = Field(
        description=(
            "invokes, delegates-to, retrieves-from, acts-as-identity, "
            "registered-as, approved-under, observed-using, trained-on, "
            "fine-tuned-from, quantized-from, merged-from, depends-on"
        )
    )
    assurance_level: str | None = None
    conditions: str | None = None


class AIBOM(BaseModel):
    """Agent Bill of Materials — the complete supply chain inventory."""

    metadata: AIBOMMetadata = Field(default_factory=AIBOMMetadata)
    components: list[AnyComponent] = Field(default_factory=list)
    dependencies: list[DependencyEdge] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_components(self) -> AIBOM:
        refs = [component.bom_ref for component in self.components]
        if len(refs) != len(set(refs)):
            raise ValueError("Duplicate component references in AIBOM")
        return self

    def replace_component(self, component: AnyComponent) -> None:
        """Explicitly replace an existing component in an edited snapshot."""
        for index, existing in enumerate(self.components):
            if existing.bom_ref == component.bom_ref:
                self.components[index] = component
                return
        raise ValueError(f"No component with reference: {component.bom_ref}")

    def add_component(self, component: AnyComponent) -> None:
        for existing in self.components:
            if existing.bom_ref == component.bom_ref:
                if existing == component:
                    return
                raise ValueError(f"Duplicate component reference: {component.bom_ref}")
        self.components.append(component)

    def add_dependency(self, edge: DependencyEdge) -> None:
        self.dependencies.append(edge)

    def get_component(self, bom_ref: str) -> AnyComponent | None:
        for c in self.components:
            if c.bom_ref == bom_ref:
                return c
        return None

    def get_components_by_type(self, ctype: ComponentType) -> list[AnyComponent]:
        return [c for c in self.components if c.component_type == ctype]

    def get_all_risks(self) -> list[tuple[str, Any]]:
        results = []
        for c in self.components:
            if hasattr(c, "risks"):
                for risk in c.risks:
                    results.append((c.bom_ref, risk))
        return results

    def finalize(self) -> None:
        """Stamp document metadata once; idempotent so repeated emits are stable.

        Honors SOURCE_DATE_EPOCH for a reproducible timestamp and derives a
        content-addressed serial number in deterministic mode, so the same
        inventory produces byte-identical output across runs (NS-13).
        """
        if self.metadata.tool_version is None:
            self.metadata.tool_version = __version__
        if self.metadata.timestamp is None:
            self.metadata.timestamp = _document_timestamp()
        if self.metadata.serial_number is None:
            self.metadata.serial_number = self._document_serial()

    def _document_serial(self) -> str:
        """urn:uuid serial — deterministic (content-addressed) under SOURCE_DATE_EPOCH."""
        if os.environ.get("SOURCE_DATE_EPOCH"):
            payload = json.dumps(
                [c.model_dump(mode="json", exclude_none=True) for c in self.components],
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
            digest = hashlib.sha256(payload.encode("utf-8")).digest()
            return f"urn:uuid:{uuid.UUID(bytes=digest[:16], version=5)}"
        return f"urn:uuid:{uuid.uuid4()}"

    def to_dict(self) -> dict[str, Any]:
        self.finalize()
        return self.model_dump(mode="json", exclude_none=True)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save(self, path: Path) -> None:
        path.write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> AIBOM:
        """Load and validate a native AIBOM, bounding size and surfacing a clean
        error on malformed input rather than an uncaught traceback. (NS-16)"""
        try:
            if path.stat().st_size > _MAX_BOM_BYTES:
                raise ValueError(f"AIBOM file exceeds {_MAX_BOM_BYTES} bytes; refusing to load")
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"not valid JSON: {exc}") from exc
        return cls.model_validate(data)

    def summary(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for c in self.components:
            key = c.component_type.value
            type_counts[key] = type_counts.get(key, 0) + 1
        all_risks = self.get_all_risks()
        risk_counts: dict[str, int] = {}
        for _, risk in all_risks:
            sev = risk.severity.value if hasattr(risk.severity, "value") else str(risk.severity)
            risk_counts[sev] = risk_counts.get(sev, 0) + 1
        return {
            "total_components": len(self.components),
            "component_types": type_counts,
            "total_dependencies": len(self.dependencies),
            "total_risks": len(all_risks),
            "risk_breakdown": risk_counts,
            "completeness": (
                self.metadata.completeness.model_dump(exclude_none=True)
                if self.metadata.completeness
                else None
            ),
        }
