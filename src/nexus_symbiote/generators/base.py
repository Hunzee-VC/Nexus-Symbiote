"""Abstract generator interface for AIBOM output formats."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from nexus_symbiote.core.aibom import AIBOM


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


# Native wire names and digest sizes shared by both projections. Reject malformed
# evidence instead of emitting a hash that a consumer could mistake for verified.
_HASH_FORMS = (
    ("MD5", "md5", 32),
    ("SHA-1", "sha1", 40),
    ("SHA-256", "sha256", 64),
    ("SHA-384", "sha384", 96),
    ("SHA-512", "sha512", 128),
    ("SHA3-256", "sha3_256", 64),
    ("SHA3-384", "sha3_384", 96),
    ("SHA3-512", "sha3_512", 128),
    ("BLAKE2b-256", "blake2b256", 64),
    ("BLAKE2b-384", "blake2b384", 96),
    ("BLAKE2b-512", "blake2b512", 128),
    ("BLAKE3", "blake3", 64),
    ("Streebog-256", None, 64),
    ("Streebog-512", None, 128),
    (None, "sha224", 56),
    (None, "sha3_224", 56),
)


def _algorithm_key(value: str) -> str:
    return value.lower().replace("-", "").replace("_", "")


def wire_hashes(hashes: dict[str, str], *, spdx: bool) -> Iterator[tuple[str, str]]:
    """Yield format-native algorithm names and unprefixed hexadecimal values."""
    algorithms = {
        _algorithm_key(cdx or sd or ""): (sd if spdx else cdx, size)
        for cdx, sd, size in _HASH_FORMS
    }
    for algorithm, value in hashes.items():
        key = _algorithm_key(algorithm)
        name, size = algorithms.get(key, (None, 0))
        if name is None:
            raise ValueError(f"unsupported hash algorithm for this projection: {algorithm}")
        prefix, separator, digest = value.partition(":")
        if not separator:
            digest = value
        elif _algorithm_key(prefix) != key:
            raise ValueError(f"hash algorithm prefix does not match {algorithm}")
        if len(digest) != size or re.fullmatch(r"[A-Fa-f0-9]+", digest) is None:
            raise ValueError(f"invalid {name} digest")
        yield name, digest.lower()


def validate_references(bom: AIBOM) -> None:
    refs = {component.bom_ref for component in bom.components}
    if len(refs) != len(bom.components) or "" in refs:
        raise ValueError("component identifiers must be non-empty and unique")
    for edge in bom.dependencies:
        if edge.source_ref not in refs or edge.target_ref not in refs:
            raise ValueError(f"unresolved dependency: {edge.source_ref} -> {edge.target_ref}")
