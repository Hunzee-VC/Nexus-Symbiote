"""Project the actual ShadowScan MCP observation type, without trusting it.

Producer contract reviewed at ShadowScan commit 1a821e5763e9340ea96564b0606d1ab581fde90e:
shadowscan/connectors/endpoint/runtime.py emits kind=MCP_SERVER and
resource_type=mcp-tool. reporters/cyclonedx.py exports both as properties.
The examples below are synthetic and intentionally include hostile metadata.
"""

import json

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.enums import AssuranceLevel, ComponentType, TrustTier
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.scanners.shadowscan import PROJECTION_PROFILE, ShadowScanImporter


def native(kind="mcp-server", resource_type="mcp-tool"):
    return {
        "version": "0.1.4",
        "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
        "stats": [{"errors": [], "skipped": False, "incomplete": False}],
        "findings": [
            {
                "id": "tool-1",
                "kind": kind,
                "surface": "endpoint",
                "resource_type": resource_type,
                "metadata": {"server": "SECRET", "tool": "SECRET"},
            }
        ],
    }


def cdx(kind="mcp-server", resource_type="mcp-tool", component_type="application"):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "metadata": {"properties": [{"name": "shadowscan:scan:status", "value": "complete"}]},
        "components": [
            {
                "bom-ref": "tool-1",
                "type": component_type,
                "properties": [
                    {"name": "shadowscan:kind", "value": kind},
                    {"name": "shadowscan:resource-type", "value": resource_type},
                ],
            }
        ],
    }


def parse(report):
    return ShadowScanImporter().parse_report(json.dumps(report))


def test_native_and_cyclonedx_tool_observations_remain_unverified():
    # The producer emits an MCP finding as a CycloneDX service, not a
    # component; its generic component representation is accepted too.
    service_report = cdx()
    service_report["services"] = service_report.pop("components")
    del service_report["services"][0]["type"]
    for report in (native(), cdx(), service_report):
        result = parse(report)
        assert result.unmapped_count == 0
        tool = result.components[0]
        assert tool.component_type == ComponentType.TOOL
        assert tool.assurance_level == AssuranceLevel.DECLARED
        assert tool.trust_tier == TrustTier.UNKNOWN
        assert tool.mcp_server_ref is None and tool.definition_hash is None
        assert tool.properties["shadowscan:projection-profile"] == PROJECTION_PROFILE
        assert tool.properties["shadowscan:resource-type"] == "mcp-tool"
        assert "SECRET" not in repr(result)


def test_conflicting_tool_type_is_unmapped_and_no_server_inferred():
    for report in (
        native(kind="agent"),
        cdx(kind="agent"),
        cdx(component_type="machine-learning-model"),
    ):
        result = parse(report)
        assert result.components == []
        assert result.unmapped_indexes == [0]


def test_only_exact_tool_resource_type_is_a_tool():
    for report in (native(resource_type="mcp-server"), cdx(resource_type="mcp-server")):
        assert parse(report).components[0].component_type == ComponentType.MCP_SERVER


def test_portable_exports_keep_tool_type_and_partial_coverage():
    bom = parse(native()).to_native_bom()
    for generator in (CycloneDXGenerator(), SPDXGenerator()):
        recovered = generator.recover(generator.generate(bom))
        assert recovered.components[0].component_type == ComponentType.TOOL
        assert recovered.components[0].trust_tier == TrustTier.UNKNOWN
        assert recovered.metadata.completeness.scanner_status["shadowscan"] == "partial"


def test_v1_projection_requires_its_original_importer_for_reverification(tmp_path):
    source = tmp_path / "source.json"
    bom = tmp_path / "bom.json"
    source.write_text(json.dumps(native(resource_type="mcp-server")))
    runner = CliRunner()
    assert (
        runner.invoke(
            main,
            [
                "import-shadowscan",
                str(source),
                "-o",
                str(bom),
                "--report-only",
                "--allow-unsigned-discovery",
            ],
        ).exit_code
        == 0
    )
    doc = json.loads(bom.read_text())
    doc["components"][0]["properties"]["shadowscan:projection-profile"] = (
        "nexus-symbiote/shadowscan-projection/v1"
    )
    bom.write_text(json.dumps(doc))
    assert runner.invoke(main, ["verify-discovery", str(bom), str(source)]).exit_code == 0
    assert (
        runner.invoke(main, ["verify-discovery", str(bom), str(source), "--projection"]).exit_code
        != 0
    )
