"""Drift alerts quote a component's name only up to the length every other field is clipped to.

A candidate inventory whose component names are megabytes long would otherwise repeat each
name in every alert, in the JSON report and in the terminal, once per alert it raises.
"""

from __future__ import annotations

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.diff.differ import _SHOWN, AIBOMDiffer

LONG = "n" * 100_000


def _inventory(name: str, *, version: str) -> AIBOM:
    bom = AIBOM()
    bom.add_component(MCPServerComponent(bom_ref="mcp-server:x", name=name, version=version))
    return bom


def test_alert_text_clips_a_long_component_name() -> None:
    report = AIBOMDiffer().diff(_inventory(LONG, version="1"), _inventory(LONG, version="2"))
    assert report.security_alerts
    for alert in report.security_alerts:
        assert len(alert["alert"]) < _SHOWN + 512


def test_added_and_removed_component_alerts_are_clipped_too() -> None:
    empty = AIBOM()
    for old, new in (
        (empty, _inventory(LONG, version="1")),
        (_inventory(LONG, version="1"), empty),
    ):
        report = AIBOMDiffer().diff(old, new)
        assert report.security_alerts
        for alert in report.security_alerts:
            assert len(alert["alert"]) < _SHOWN + 512
