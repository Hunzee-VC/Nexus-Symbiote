"""The canonical native document and its content-derived serial number.

Core owns these because ``AIBOM.to_dict`` renders them; the standard exporters
in ``nexus_symbiote.generators`` reuse them, so core never imports a generator.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import TYPE_CHECKING, Any

from nexus_symbiote import __version__

if TYPE_CHECKING:
    from nexus_symbiote.core.aibom import AIBOM

NAMESPACE = uuid.UUID("ccaa2a43-8ba9-58e6-8f22-f8793a2039d5")


def json_text(value: Any) -> str:
    """Deterministic UTF-8 JSON representation; not a claim of RFC 8785 canonicalization."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def content_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json_text(value).encode("utf-8")).hexdigest()


_SERIAL_EXCLUDED_CLAIM_FIELDS = frozenset({"timestamp", "source_report_path"})


def prepare(bom: AIBOM) -> AIBOM:
    """Fill missing export metadata once; never reset an existing observation timestamp.

    The serial number is a uuid5 over the inventory content only: the
    observation timestamps (``metadata.timestamp`` and the completeness
    claim's ``timestamp``) and the location an imported report was read
    from (``source_report_path``) are excluded from the digest, so
    re-exporting the same inventory at a different time or from a
    different checkout keeps the same serial. Two documents that differ
    only in those fields therefore share a serial by design. No
    wall-clock timestamp is stamped here, so two exports of the same
    inventory are byte-identical; a timestamp set explicitly by a caller
    is preserved. Formats whose schema requires a timestamp (SPDX
    ``CreationInfo.created``) supply it at render time.
    """
    if bom.metadata.timestamp is not None and bom.metadata.timestamp.tzinfo is None:
        raise ValueError("export timestamps must include a timezone")
    if bom.metadata.tool_version is None:
        bom.metadata.tool_version = __version__
    if bom.metadata.serial_number is None:
        body = native_document(bom)
        metadata = {key: value for key, value in body["metadata"].items() if key != "timestamp"}
        completeness = metadata.get("completeness")
        if isinstance(completeness, dict):
            metadata["completeness"] = {
                key: value
                for key, value in completeness.items()
                if key not in _SERIAL_EXCLUDED_CLAIM_FIELDS
            }
        body["metadata"] = metadata
        bom.metadata.serial_number = "urn:uuid:" + str(uuid.uuid5(NAMESPACE, content_digest(body)))
    ids = [c.bom_ref for c in bom.components]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate component references")
    known = set(ids)
    for edge in bom.dependencies:
        if edge.source_ref not in known or edge.target_ref not in known:
            raise ValueError("dependency references an unknown component")
    return bom


def native_document(bom: AIBOM) -> dict[str, Any]:
    document = bom.model_dump(mode="json", exclude_none=True)
    document["components"] = sorted(document["components"], key=lambda c: c["bom_ref"])
    document["dependencies"] = sorted(document["dependencies"], key=json_text)
    return document
