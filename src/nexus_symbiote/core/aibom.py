"""The AIBOM document model — the top-level container for an AgentBOM."""

from __future__ import annotations

import errno
import json
from pathlib import Path
from typing import Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from nexus_symbiote import __version__
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.models import (
    MAX_REFERENCE_CHARS,
    AIBOMMetadata,
    AnyComponent,
    UnsupportedSpecVersionError,
    check_spec_version,
)

MAX_NATIVE_BYTES = 16 * 1024 * 1024
"""The largest native document any command reads, and therefore the largest one written."""

SCHEMA_ID = (
    "https://github.com/Hunzee-VC/Nexus-Symbiote/blob/main/schemas/"
    "nexus-symbiote-aibom-1.0.schema.json"
)

UNDECLARED_SPEC_VERSION = "1.0.0"
"""The format of a native document that declares no version, as release 0.1.0 read it."""

Relationship = Literal[
    "invokes",
    "delegates-to",
    "retrieves-from",
    "acts-as-identity",
    "registered-as",
    "approved-under",
    "observed-using",
    "trained-on",
    "fine-tuned-from",
    "quantized-from",
    "merged-from",
    "depends-on",
    "configured-with",
    "provides-tool",
    "uses-model",
    "reads-instructions",
    "loads-skill",
    "uses-memory",
    "uses-guardrail",
]


class NativeFormatError(ValueError):
    """A native AgentBOM document cannot be read; the message never quotes its content."""


def _open_failure(exc: OSError) -> str:
    """Why a native document could not be opened, without the operating system's text."""
    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
        return (
            "It is reached through a symbolic link or a path component that is not a "
            "directory; inventories are read without following links, so pass the real path."
        )
    if exc.errno is None:
        return (
            "It is not a regular file; FIFOs, devices, directories and standard input are refused."
        )
    if exc.errno == errno.ENOENT:
        return "It does not exist."
    if exc.errno in {errno.EACCES, errno.EPERM}:
        return "It cannot be read: permission denied."
    return "It cannot be opened for reading."


class DependencyEdge(BaseModel):
    """A typed relationship between two components."""

    model_config = ConfigDict(extra="forbid")

    source_ref: str = Field(max_length=MAX_REFERENCE_CHARS)
    target_ref: str = Field(max_length=MAX_REFERENCE_CHARS)
    relationship: Relationship = Field(description=", ".join(get_args(Relationship)))
    assurance_level: Literal["declared", "observed", "verified"] | None = None
    conditions: str | None = None


class AIBOM(BaseModel):
    """Agent Bill of Materials — the complete supply chain inventory."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": SCHEMA_ID,
        },
    )

    metadata: AIBOMMetadata = Field(default_factory=AIBOMMetadata)
    components: list[AnyComponent] = Field(default_factory=list)
    dependencies: list[DependencyEdge] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def undeclared_format_version(cls, data: Any) -> Any:
        """Read a metadata object that declares no spec_version as format 1.0.0.

        Objects built in process pass an AIBOMMetadata instance, or none, and keep the
        format this build writes.
        """
        if isinstance(data, dict):
            metadata = data.get("metadata")
            if isinstance(metadata, dict) and "spec_version" not in metadata:
                return {**data, "metadata": {**metadata, "spec_version": UNDECLARED_SPEC_VERSION}}
        return data

    @classmethod
    def model_json_schema(cls, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """The native schema, whose default is the version an undeclared document is read as."""
        schema = super().model_json_schema(*args, **kwargs)
        version = schema["$defs"]["AIBOMMetadata"]["properties"]["spec_version"]
        version["default"] = UNDECLARED_SPEC_VERSION
        return schema

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
        """Fill the deterministic tool stamp only.

        The serial number and the observation timestamp are export concerns
        owned by :func:`nexus_symbiote.core.canonical.prepare`: the
        serial is a content-derived uuid5, and no wall-clock timestamp is
        stamped here, so two exports of the same inventory are identical.
        A timestamp set explicitly by a caller is preserved untouched.
        """
        if self.metadata.tool_version is None:
            self.metadata.tool_version = __version__

    def to_dict(self) -> dict[str, Any]:
        from nexus_symbiote.core.canonical import native_document, prepare

        prepare(self)
        return native_document(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_native_json(self) -> str:
        """Render a document every reader accepts, or refuse with the limit it exceeds.

        Indented output is preferred; a document that only fits without indentation is
        written compactly rather than being written in a form ``load`` rejects.
        """
        text = self.to_json()
        if len(text.encode("utf-8")) <= MAX_NATIVE_BYTES:
            return text
        text = json.dumps(self.to_dict(), separators=(",", ":"))
        if len(text.encode("utf-8")) <= MAX_NATIVE_BYTES:
            return text
        raise NativeFormatError(
            f"The inventory exceeds the {MAX_NATIVE_BYTES // (1024 * 1024)} MiB limit "
            "that native readers accept."
        )

    def save(self, path: Path) -> None:
        """Replace ``path`` atomically, never writing through a symbolic link."""
        from nexus_symbiote.utils.files import write_output_file

        write_output_file(path, self.to_native_json())

    @classmethod
    def load(cls, path: Path) -> AIBOM:
        """Read a native document without following links or blocking on special files.

        Every failure is a ``NativeFormatError`` whose message names the class of
        problem and never quotes the document.
        """
        from nexus_symbiote.core.hashing import open_regular_file, parse_json_strict

        try:
            with open_regular_file(path) as stream:
                raw = stream.read(MAX_NATIVE_BYTES + 1)
        except OSError as exc:
            raise NativeFormatError(_open_failure(exc)) from exc
        if len(raw) > MAX_NATIVE_BYTES:
            raise NativeFormatError(
                f"It exceeds the {MAX_NATIVE_BYTES // (1024 * 1024)} MiB native inventory limit."
            )
        try:
            data = parse_json_strict(raw.decode("utf-8"), max_bytes=MAX_NATIVE_BYTES)
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise NativeFormatError(
                "It is not strict UTF-8 JSON; duplicate keys and nonfinite numbers are refused."
            ) from exc
        if isinstance(data, dict) and "metadata" not in data:
            data = {**data, "metadata": {}}
        metadata = data.get("metadata") if isinstance(data, dict) else None
        if isinstance(metadata, dict) and "spec_version" in metadata:
            try:
                check_spec_version(metadata["spec_version"])
            except UnsupportedSpecVersionError as exc:
                raise NativeFormatError(str(exc)) from exc
        try:
            return cls.model_validate(data)
        except (ValidationError, RecursionError) as exc:
            raise NativeFormatError("It does not match the native AgentBOM schema.") from exc

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
