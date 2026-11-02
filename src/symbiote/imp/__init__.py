"""Importers: foreign documents → AgentBOM entities with honest assurance tagging (``spec/companion.md §6``)."""

from __future__ import annotations

from symbiote.imp.cdx import NATIVE, CycloneDXImportError, detect_dialect, import_cyclonedx
from symbiote.imp.k8s_aibom import K8sAibomImport, extract_bom_document, import_k8s_aibom
from symbiote.imp.shadowscan import (
    ShadowScanImport,
    ShadowScanImportError,
    import_shadowscan,
)
from symbiote.imp.spdx import SpdxImportError, import_spdx

__all__ = [
    "NATIVE",
    "CycloneDXImportError",
    "K8sAibomImport",
    "ShadowScanImport",
    "ShadowScanImportError",
    "SpdxImportError",
    "detect_dialect",
    "extract_bom_document",
    "import_cyclonedx",
    "import_k8s_aibom",
    "import_shadowscan",
    "import_spdx",
]
