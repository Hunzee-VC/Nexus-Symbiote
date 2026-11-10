"""Recover the native inventory from exported CycloneDX or SPDX text.

The text is parsed like a native AgentBOM file: bounded, with duplicate keys and
non-finite numbers rejected. Every failure is a ValueError. Recovery checks the
embedded inventory's digest and its agreement with the standard fields; it does
not authenticate the producer.
"""

from __future__ import annotations

from pathlib import Path

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import parse_json_strict
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator

# An export carries the native document twice (whole and per component) beside its
# standard fields, so it is allowed to be several times the native file limit.
MAX_EXPORT_BYTES = 64 * 1024 * 1024


def recover_export(text: str | bytes, *, allow_legacy_relationships: bool = False) -> AIBOM:
    """Recover a CycloneDX or SPDX export written by Nexus SymBiote."""
    try:
        document = parse_json_strict(text, max_bytes=MAX_EXPORT_BYTES)
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("export is not bounded, well-formed JSON") from exc
    if isinstance(document, dict) and document.get("bomFormat") == "CycloneDX":
        return CycloneDXGenerator.recover(
            document, allow_legacy_relationships=allow_legacy_relationships
        )
    if isinstance(document, dict) and "@graph" in document:
        if allow_legacy_relationships:
            raise ValueError("legacy relationship recovery applies to CycloneDX only")
        return SPDXGenerator.recover(document)
    raise ValueError("export is neither a CycloneDX nor an SPDX document")


def load_export(path: Path, *, allow_legacy_relationships: bool = False) -> AIBOM:
    with path.open("rb") as stream:
        raw = stream.read(MAX_EXPORT_BYTES + 1)
    return recover_export(raw, allow_legacy_relationships=allow_legacy_relationships)
