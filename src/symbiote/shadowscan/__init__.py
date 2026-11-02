"""Native integration with `Nexus ShadowScan <https://github.com/aisecnomad/Nexus-ShadowScan>`_.

ShadowScan **discovers** evidence of AI agents across nine surfaces and reconciles it against an inventory of
approved agents; Symbiote **describes** one agent with per-claim assurance and seals the description. The two
meet in both directions (``spec/shadowscan-mapping.md``):

* :func:`import_report` turns a ShadowScan JSON report (or its CycloneDX 1.6 output) into an *observed*
  AgentBOM snapshot — findings become entities with ``assurance=observed``, the L0-L5 autonomy interval becomes
  an :class:`~symbiote.model.entities.AutonomyAssessment`, connector status becomes coverage, and nothing a
  scan did not read is ever presented as absent.
* :func:`export_inventory` turns an AgentBOM into the inventory ShadowScan reconciles against (Agent Capability
  Cards, ``agents.yaml`` or CSV), so "shadow" means "not in the AgentBOM".
* :func:`reconcile` compares a declared or approved AgentBOM with a ShadowScan report: observed-but-undeclared
  servers, declared-but-unobserved servers, and declared autonomy against the observed interval.

Nothing here executes ShadowScan or any discovered component; the integration reads reports and writes files.
"""

from __future__ import annotations

from symbiote.shadowscan.autonomy import (
    LEVELS,
    SCALE,
    Level,
    assessment_from_metadata,
    from_iso,
    to_iso,
    widen,
)
from symbiote.shadowscan.inventory import InventoryFormat, export_inventory, inventory_cards
from symbiote.shadowscan.mapping import ShadowScanImport, import_report, map_report
from symbiote.shadowscan.reconcile import Reconciliation, reconcile
from symbiote.shadowscan.report import (
    ReportError,
    ShadowScanFinding,
    ShadowScanReport,
    detect_cyclonedx,
    load_report,
    read_report,
)

__all__ = [
    "LEVELS",
    "SCALE",
    "InventoryFormat",
    "Level",
    "Reconciliation",
    "ReportError",
    "ShadowScanFinding",
    "ShadowScanImport",
    "ShadowScanReport",
    "assessment_from_metadata",
    "detect_cyclonedx",
    "export_inventory",
    "from_iso",
    "import_report",
    "inventory_cards",
    "load_report",
    "map_report",
    "read_report",
    "reconcile",
    "to_iso",
    "widen",
]
