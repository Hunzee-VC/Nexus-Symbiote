"""Exporters and importers. Every exporter returns ``(document, LossReport)`` (``spec/companion.md §4``)."""

from __future__ import annotations

import re

from symbiote.model.entities import LossItem
from symbiote.model.enums import LossPreservedIn


def account_for_companion(items: list[LossItem], ref: str | None, digest: str | None) -> list[LossItem]:
    """A companion-only field is dropped from a delivery unless the projection links its bytes.

    The link records availability by reference. Authenticating the referenced file and the
    authority of its signer is the responsibility of the consumer.
    """
    if ref and digest and re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        return items
    return [
        item.replace(preserved_in=LossPreservedIn.DROPPED)
        if item.preserved_in is LossPreservedIn.COMPANION
        else item
        for item in items
    ]
