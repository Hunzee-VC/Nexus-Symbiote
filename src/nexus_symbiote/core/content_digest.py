"""Run-independent digest of a native inventory's content.

Two collections of the same project differ only in the fields that record the
collection event: the serial number, the collection time and the location an
imported report was read from. The content digest leaves exactly those fields out,
so equal content gives an equal digest whenever and wherever it was collected; it
is also what a missing serial number is derived from (``core.aibom.prepare``). It
identifies content for comparison; it is neither authentication of a producer nor
a substitute for the digest of a file's bytes.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from nexus_symbiote.core.hashing import hash_canonical

INVENTORY_CONTENT_PROFILE = "nexus-symbiote/inventory-content/v1"
"""Names the rule below. A change to what is left out is a new profile version."""

# The list of collection-event fields is closed, and each is dropped only where the
# native format records it and only when its value has the expected shape: any other
# key of the same name, and any other value under these keys, stays content, so a
# change cannot hide behind a field the digest ignores.
_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})", re.ASCII
)
_SERIAL_NUMBER = re.compile(r"urn:uuid:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}")
NOT_AN_INVENTORY = "the document is not a native inventory object"
NESTED_TOO_DEEPLY = "the document is nested too deeply to canonicalize"


def _event_value(value: object, shape: re.Pattern[str]) -> bool:
    return value is None or (isinstance(value, str) and shape.fullmatch(value) is not None)


def _without(
    record: Mapping[str, Any], name: str, shape: re.Pattern[str] = _TIMESTAMP
) -> dict[str, Any]:
    return {
        key: value for key, value in record.items() if key != name or not _event_value(value, shape)
    }


def _component_content(component: object) -> object:
    if not isinstance(component, Mapping):
        return component
    claims = component.get("claims")
    if not isinstance(claims, Mapping):
        return component
    return {
        **component,
        "claims": {
            name: _without(claim, "observed_at") if isinstance(claim, Mapping) else claim
            for name, claim in claims.items()
        },
    }


def inventory_content(document: Mapping[str, Any]) -> dict[str, Any]:
    """A copy of a parsed native document without its collection-event fields.

    A document without a ``metadata`` key is read with an empty metadata object, as
    every reader of native documents reads it (``AIBOM.from_document``), so it has the
    content of the same document with ``"metadata": {}``.

    Left out: ``metadata.serial_number`` when null or a URN UUID;
    ``metadata.completeness.source_report_path`` when a string; and, when null
    or an RFC 3339 timestamp, ``metadata.timestamp``, ``metadata.completeness.timestamp``
    and the ``observed_at`` of each component claim. The argument is not changed; the
    values the copy keeps are shared with it, not copied.
    """
    metadata = document.get("metadata", {}) if isinstance(document, Mapping) else None
    components = document.get("components") if isinstance(document, Mapping) else None
    if not isinstance(metadata, Mapping) or not isinstance(components, list):
        raise ValueError(NOT_AN_INVENTORY)
    reduced = _without(_without(metadata, "serial_number", _SERIAL_NUMBER), "timestamp")
    completeness = reduced.get("completeness")
    if isinstance(completeness, Mapping):
        reduced["completeness"] = {
            key: value
            for key, value in _without(completeness, "timestamp").items()
            if key != "source_report_path" or not isinstance(value, str)
        }
    return {
        **document,
        "metadata": reduced,
        "components": [_component_content(component) for component in components],
    }


def inventory_content_digest(document: Mapping[str, Any]) -> str:
    """Digest a strictly parsed native document under ``INVENTORY_CONTENT_PROFILE``.

    SHA-256 of the RFC 8785 canonical JSON of ``inventory_content(document)``. Pass the
    object as parsed from the file: a document rendered again from the model is a
    different document. Raises ``ValueError`` with ``NOT_AN_INVENTORY``, or with
    ``NESTED_TOO_DEEPLY`` for a document deeper than canonicalization can recurse.
    """
    content = inventory_content(document)
    try:
        return hash_canonical(content)
    except RecursionError:
        raise ValueError(NESTED_TOO_DEEPLY) from None
