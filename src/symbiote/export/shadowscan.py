"""Compatibility façade: ShadowScan inventory export (``symbiote.shadowscan.inventory`` is the implementation).

Kept so ``from symbiote.export.shadowscan import to_capability_card`` keeps working; new code should use
:func:`symbiote.shadowscan.export_inventory` / :func:`symbiote.shadowscan.inventory.card_for`, which also
cover sub-agents, the simple list and CSV formats, scan-root bindings and the ``symbiote shadowscan inventory``
command.
"""

from __future__ import annotations

from typing import Any

from symbiote.model.document import AgentBOM
from symbiote.model.enums import IsoAutomationLevel
from symbiote.shadowscan.autonomy import LEVELS
from symbiote.shadowscan.inventory import ZONE_FROM_TIER, card_for, export_inventory
from symbiote.shadowscan.inventory import declared_level as _declared_level
from symbiote.shadowscan.inventory import discovery_resources as _discovery_resources

#: ISO/IEC 22989 ladder → ShadowScan L0-L5 (``autonomous`` narrows to L5; see ``spec/shadowscan-mapping.md §3``).
LEVEL_FROM_ISO: dict[IsoAutomationLevel, int] = {lv.iso: lv.number for lv in LEVELS} | {
    IsoAutomationLevel.AUTONOMOUS: 5
}


def declared_level(bom: AgentBOM) -> int | None:
    """The card-declared L0-L5 level of the root agent, or ``None`` when the BOM does not state one."""
    return _declared_level(bom.root_agent)[0]


def discovery_resources(bom: AgentBOM) -> list[str]:
    """Approval bindings for the root agent (literal; derived like ShadowScan's own AgentBOM loader)."""
    return _discovery_resources(bom, bom.root_agent)


def to_capability_card(bom: AgentBOM) -> dict[str, Any]:
    """A schema-version-2 Agent Capability Card for the root agent."""
    return card_for(bom, bom.root_agent)


def to_simple_inventory(bom: AgentBOM) -> dict[str, Any]:
    """An ``agents:`` list document (root and sub-agents)."""
    import yaml

    return yaml.safe_load(export_inventory(bom, "agents")["agents.yaml"])


__all__ = [
    "LEVEL_FROM_ISO",
    "ZONE_FROM_TIER",
    "declared_level",
    "discovery_resources",
    "to_capability_card",
    "to_simple_inventory",
]
