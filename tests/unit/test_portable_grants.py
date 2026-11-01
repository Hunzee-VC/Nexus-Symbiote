"""Security constraints must survive both portable projections without consuming the companion."""

from __future__ import annotations

import json

import pytest

from symbiote.export import account_for_companion
from symbiote.export.cdx import export_cyclonedx, validate_cyclonedx
from symbiote.export.spdx import export_spdx, validate_spdx
from symbiote.model import AgentBOM
from symbiote.model import enums as E
from symbiote.model.entities import Condition, EnforcementPoint, Grant, LossItem, Scope, SpendCeiling


def test_consumer_recovers_complete_payment_authority(minimal_bom: AgentBOM) -> None:
    scope = Scope(
        resources=["ledger/uk"],
        egress=["ledger.internal"],
        data_classes=["restricted"],
        spend_ceiling=SpendCeiling(amount=101.05, currency="GBP", period="month"),
        rate_limit="2/min",
    )
    grant = Grant(
        id="grant:transfer",
        subject_ref=minimal_bom.subject,
        layer=E.GrantLayer.EFFECTIVE,
        capability=E.CapabilityClass.PAYMENT,
        scope=scope,
        conditions=[Condition(kind=E.ConditionKind.TENANT, expr="tenant == 'finance'")],
        enforcement_point=EnforcementPoint(kind=E.EnforcementPointKind.GATEWAY, locator="payments/uk"),
    )
    bom = minimal_bom.replace(grants=[grant])
    cdx, cdx_loss = export_cyclonedx(bom)
    spdx, spdx_loss = export_spdx(bom)
    assert not validate_cyclonedx(cdx) and not validate_spdx(spdx)
    cdx_props = [(p["name"], p["value"]) for p in cdx["metadata"]["properties"]]
    sbom = next(n for n in spdx["@graph"] if n["type"] == "software_Sbom")
    mirror = next(e for e in sbom["extension"] if e["type"] == "extension_CdxPropertiesExtension")
    spdx_props = [
        (p["extension_cdxPropName"], p["extension_cdxPropValue"]) for p in mirror["extension_cdxProperty"]
    ]
    for props in [cdx_props, spdx_props]:
        assert ("agentbom:authorization-use", "requires-externally-authenticated-companion") in props
        records = [json.loads(value) for name, value in props if name == "agentbom:authz:grant-record"]
        assert records == [grant.to_json_dict()]
    for loss in [cdx_loss, spdx_loss]:
        item = next(i for i in loss.items if i.entity == grant.id)
        assert item.path == "/grants/0" and item.preserved_in in {
            E.LossPreservedIn.PROPERTY,
            E.LossPreservedIn.EXTENSION,
        }


@pytest.mark.parametrize(
    ("ref", "digest"), [(None, None), ("agentbom.json", None), ("agentbom.json", "broken")]
)
def test_absent_or_unbound_companion_reports_loss(ref: str | None, digest: str | None) -> None:
    item = LossItem(
        path="/approvals/0",
        reason=E.LossReason.NO_NATIVE_CONSTRUCT,
        preserved_in=E.LossPreservedIn.COMPANION,
        severity=E.LossSeverity.SECURITY_RELEVANT,
    )
    assert account_for_companion([item], ref, digest)[0].preserved_in is E.LossPreservedIn.DROPPED
    assert account_for_companion([item], "agentbom.json", "sha256:" + "ab" * 32) == [item]
