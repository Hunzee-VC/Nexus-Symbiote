"""Tests for the Model VEX generator and OSV advisory lookups."""

from __future__ import annotations

import json
from pathlib import Path

from nexus_symbiote.advisories import fetch_advisories
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity, SerializationSafety
from nexus_symbiote.core.models import ModelComponent, RegistryEntryComponent, RiskAssessment
from nexus_symbiote.generators.vex import VEXGenerator


def _model_bom() -> AIBOM:
    bom = AIBOM()
    bom.add_component(
        ModelComponent(
            bom_ref="model:llama/weights",
            name="llama/weights",
            serialization_format="safetensors",
            serialization_safety=SerializationSafety.UNKNOWN,
            signing_status="unsigned",
            derivation_type="lora",
            base_model_ref="model:llama/base",
            hashes={
                "sha256": "sha256:" + "a" * 64,
                "tensor_inventory_sha256": "sha256:" + "b" * 64,
            },
            risks=[
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="signing_status",
                    detail="Model has no verified signature.",
                    recommendation="Verify a signature.",
                )
            ],
        )
    )
    return bom


def test_vex_keys_statement_to_weight_digest() -> None:
    doc = VEXGenerator().generate(_model_bom())

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.7"
    assert len(doc["vulnerabilities"]) == 1

    vuln = doc["vulnerabilities"][0]
    assert vuln["id"].startswith("SYM-SIGNING-STATUS-")
    assert vuln["analysis"]["state"] == "affected"

    props = {p["name"]: p["value"] for p in vuln["properties"]}
    assert props["nexus-symbiote:weightDigest"] == "sha256:" + "a" * 64
    assert props["nexus-symbiote:tensorInventoryDigest"] == "sha256:" + "b" * 64
    assert props["nexus-symbiote:adaptationEvent"] == "lora"
    assert props["nexus-symbiote:baseModelRef"] == "model:llama/base"


def test_vex_json_output() -> None:
    text = VEXGenerator().generate_json(_model_bom())
    parsed = json.loads(text)
    assert parsed["bomFormat"] == "CycloneDX"


def test_vex_empty_bom_has_no_statements() -> None:
    doc = VEXGenerator().generate(AIBOM())
    assert doc["vulnerabilities"] == []


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_advisories_maps_osv_results(tmp_path: Path, monkeypatch) -> None:
    bom = AIBOM()
    bom.add_component(
        RegistryEntryComponent(
            bom_ref="registry:pypi:requests",
            name="requests",
            version="2.19.0",
            registry_type="pypi",
        )
    )

    def fake_urlopen(request, timeout=None):  # noqa: ANN001
        return _FakeResponse(
            {
                "vulns": [
                    {
                        "id": "GHSA-abc",
                        "aliases": ["CVE-2018-1234"],
                        "summary": "Requests cookie leak",
                        "affected": [
                            {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}
                        ],
                    }
                ]
            }
        )

    import nexus_symbiote.advisories

    monkeypatch.setattr(nexus_symbiote.advisories.urllib.request, "urlopen", fake_urlopen)
    report = fetch_advisories(bom)

    assert report.components_checked == 1
    assert len(report.advisories) == 1
    adv = report.advisories[0]
    assert adv.advisory_id == "GHSA-abc"
    assert adv.aliases == ["CVE-2018-1234"]
    assert adv.fixed_versions == ["2.20.0"]
    assert adv.component_ref == "registry:pypi:requests"


def test_advisories_network_failure_is_reported_not_raised(monkeypatch) -> None:
    bom = AIBOM()
    bom.add_component(
        RegistryEntryComponent(
            bom_ref="registry:pypi:requests",
            name="requests",
            version="2.19.0",
            registry_type="pypi",
        )
    )

    import urllib.error

    import nexus_symbiote.advisories

    def failing_urlopen(request, timeout=None):  # noqa: ANN001
        raise urllib.error.URLError("no network")

    monkeypatch.setattr(nexus_symbiote.advisories.urllib.request, "urlopen", failing_urlopen)
    report = fetch_advisories(bom)

    assert report.lookups_failed == 1
    assert len(report.errors) == 1
    assert report.advisories == []


def test_advisories_skips_unsupported_registries() -> None:
    bom = AIBOM()
    bom.add_component(
        RegistryEntryComponent(
            bom_ref="registry:custom:thing",
            name="thing",
            registry_type="internal-registry",
        )
    )
    report = fetch_advisories(bom)
    assert report.components_checked == 0
