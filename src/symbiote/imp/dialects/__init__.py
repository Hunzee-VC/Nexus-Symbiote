"""Dialect adapters for foreign CycloneDX vocabularies (``spec/companion.md §6``, ``spec/taxonomy.md`` aliases)."""

from __future__ import annotations

from collections.abc import Iterable

from symbiote.imp.dialects.cdxgen import PREFIXES as CDXGEN_PREFIXES
from symbiote.imp.dialects.cdxgen import CdxgenAdapter
from symbiote.imp.dialects.harness_aibom import PREFIXES as HARNESS_PREFIXES
from symbiote.imp.dialects.harness_aibom import HarnessAibomAdapter
from symbiote.imp.dialects.k8s_aibom import PREFIXES as K8S_PREFIXES
from symbiote.imp.dialects.k8s_aibom import K8sAibomAdapter

#: Dialect name → adapter class (``symbiote`` and ``generic`` need no adapter).
DIALECTS = {
    "k8s-aibom": K8sAibomAdapter,
    "cdxgen": CdxgenAdapter,
    "harness-aibom": HarnessAibomAdapter,
}


def detect_dialect_from_names(names: Iterable[str]) -> str | None:
    """The first dialect whose property namespace appears among ``names`` (k8s-aibom, cdxgen, harness)."""
    lowered = {n.lower() for n in names}
    for dialect, prefixes in (
        ("k8s-aibom", K8S_PREFIXES),
        ("cdxgen", CDXGEN_PREFIXES),
        ("harness-aibom", HARNESS_PREFIXES),
    ):
        if any(n.startswith(prefixes) for n in lowered):
            return dialect
    return None


__all__ = ["DIALECTS", "CdxgenAdapter", "HarnessAibomAdapter", "K8sAibomAdapter", "detect_dialect_from_names"]
