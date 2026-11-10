"""The VEX document has its own identity, names its inventory and agrees with the BOM export."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import (
    MCPServerComponent,
    ModelComponent,
    RegistryEntryComponent,
    RiskAssessment,
)
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.generators.validation import validate_cyclonedx
from nexus_symbiote.generators.vex import VEXGenerator

SERIAL = "urn:uuid:3c7a1d8e-2b5f-4c1a-9e0d-7f6b5a4c3d21"


def _risk(detail: str, severity: RiskSeverity = RiskSeverity.HIGH) -> RiskAssessment:
    return RiskAssessment(
        severity=severity,
        category="signing_status",
        detail=detail,
        recommendation="Sign the artifact.",
    )


def inventory() -> AIBOM:
    bom = AIBOM(
        components=[
            ModelComponent(
                bom_ref="model:weights",
                name="weights.safetensors",
                hashes={"sha256": "sha256:" + "ab" * 32},
                risks=[_risk("Model 'weights.safetensors' has no verified signature.")],
            ),
            RegistryEntryComponent(
                bom_ref="registry:pypi/openai",
                name="openai",
                registry_type="pypi",
                version="==1.2.3",
                package_url="pkg:pypi/openai@1.2.3",
                risks=[_risk("PyPI package 'openai' is unsigned.", RiskSeverity.LOW)],
            ),
            RegistryEntryComponent(
                bom_ref="registry:docker/ollama/ollama:latest",
                name="ollama/ollama:latest",
                registry_type="docker-hub",
                risks=[_risk("Docker image 'ollama/ollama:latest' lacks a digest.")],
            ),
            MCPServerComponent(bom_ref="server:clean", name="clean"),
        ]
    )
    bom.metadata.serial_number = SERIAL
    bom.metadata.version = 3
    bom.metadata.timestamp = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
    return bom


def test_vex_has_its_own_identity_and_names_its_inventory():
    vex = VEXGenerator().generate(inventory())
    assert validate_cyclonedx(vex) == []
    assert vex == VEXGenerator().generate(inventory())
    assert vex["serialNumber"].startswith("urn:uuid:")
    assert vex["serialNumber"] not in {
        SERIAL,
        CycloneDXGenerator().generate(inventory())["serialNumber"],
    }
    assert vex["version"] == 3
    assert vex["metadata"]["timestamp"] == "2026-11-10T12:00:00+00:00"
    assert vex["metadata"]["tools"]["components"][0]["name"] == "nexus-symbiote"
    assert vex["externalReferences"] == [
        {
            "type": "bom",
            "url": "urn:cdx:3c7a1d8e-2b5f-4c1a-9e0d-7f6b5a4c3d21/3",
            "comment": "The inventory whose findings this document lists",
        }
    ]
    assert all(v["analysis"]["state"] == "in_triage" for v in vex["vulnerabilities"])
    assert all(
        v["analysis"]["lastUpdated"] == "2026-11-10T12:00:00+00:00" for v in vex["vulnerabilities"]
    )


def test_vex_components_carry_the_inventory_exports_standard_identity():
    vex = VEXGenerator().generate(inventory())
    exported = {c["bom-ref"]: c for c in CycloneDXGenerator().generate(inventory())["components"]}
    assert [c["bom-ref"] for c in vex["components"]] == [
        "model:weights",
        "registry:docker/ollama/ollama:latest",
        "registry:pypi/openai",
    ]
    for component in vex["components"]:
        expected = exported[component["bom-ref"]]
        for field in ("type", "name", "version", "purl", "hashes"):
            assert component.get(field) == expected.get(field), field
    types = {c["bom-ref"]: c["type"] for c in vex["components"]}
    assert types == {
        "model:weights": "machine-learning-model",
        "registry:docker/ollama/ollama:latest": "container",
        "registry:pypi/openai": "library",
    }


def test_vex_ids_survive_artifact_and_severity_changes_and_match_sarif():
    first = VEXGenerator().generate(inventory())
    changed = inventory()
    model = changed.get_component("model:weights")
    assert isinstance(model, ModelComponent)
    model.hashes = {"sha256": "sha256:" + "cd" * 32}
    model.risks[0].severity = RiskSeverity.CRITICAL
    second = VEXGenerator().generate(changed)
    assert [v["id"] for v in first["vulnerabilities"]] == [
        v["id"] for v in second["vulnerabilities"]
    ]
    sarif = SARIFGenerator().generate(inventory())
    fingerprints = {
        "NEXUS-" + r["partialFingerprints"]["nexus_symbiote/v1"]
        for r in sarif["runs"][0]["results"]
    }
    assert {v["id"] for v in first["vulnerabilities"]} == fingerprints


def test_vex_text_cannot_render_links_or_controls():
    bom = inventory()
    model = bom.get_component("model:weights")
    assert isinstance(model, ModelComponent)
    model.risks[0].detail = "Model '[approved](https://evil.example)\x1b[2J' is unsigned."
    vulnerability: dict[str, Any] = next(
        v for v in VEXGenerator().generate(bom)["vulnerabilities"] if "approved" in v["description"]
    )
    text = json.dumps(vulnerability["description"])
    assert "](" not in vulnerability["description"].replace("\\]", "")
    assert "://" not in vulnerability["description"]
    assert "\\u001b" not in text


def test_vex_without_a_uuid_serial_omits_the_bom_link():
    bom = inventory()
    bom.metadata.serial_number = "urn:uuid:not-a-uuid"
    vex = VEXGenerator().generate(bom)
    assert "externalReferences" not in vex
    assert vex["serialNumber"] != bom.metadata.serial_number


def test_vex_omits_imported_discovery_findings_and_counts_them():
    bom = inventory()
    bom.components.append(
        MCPServerComponent(
            bom_ref="shadowscan:server",
            name="imported",
            risks=[_risk("ShadowScan heuristic risk: high.")],
        )
    )
    vex = VEXGenerator().generate(bom)
    assert not any(v["affects"][0]["ref"].startswith("shadowscan:") for v in vex["vulnerabilities"])
    assert vex["metadata"]["properties"] == [
        {"name": "nexus-symbiote:omittedImportedFindings", "value": "1"}
    ]
    assert "properties" not in VEXGenerator().generate(inventory())["metadata"]
