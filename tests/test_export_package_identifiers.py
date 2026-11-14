"""Ordinary BOM consumers can read package identities without native extension decoding."""

from __future__ import annotations

import io
import json

import pytest

from nexus_symbiote.core.aibom import AIBOM, native_document
from nexus_symbiote.core.enums import AssuranceLevel, TrustTier
from nexus_symbiote.core.models import MCPServerComponent, RegistryEntryComponent
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.package_identifiers import package_identifier
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.generators.validation import validate_cyclonedx, validate_spdx


def component(**changes) -> RegistryEntryComponent:
    values = {
        "bom_ref": "registry:package",
        "name": "openai",
        "registry_type": "pypi",
        "version": "==1.2.3",
        "package_url": "pkg:pypi/openai@1.2.3",
    }
    return RegistryEntryComponent(**(values | changes))


@pytest.mark.parametrize(
    "registry,name,version,purl,expected",
    [
        ("pypi", "OpenAI", "==1.2.3", "pkg:pypi/OpenAI@1.2.3", "pkg:pypi/openai@1.2.3"),
        ("pypi", "foo_bar", "===1.2.3", "pkg:pypi/foo_bar@1.2.3", "pkg:pypi/foo-bar@1.2.3"),
        ("pypi", "openai", "==1!2.3", "pkg:pypi/openai@1%212.3", "pkg:pypi/openai@1%212.3"),
        (
            "npm",
            "@modelcontextprotocol/sdk",
            "1.2.3",
            "pkg:npm/%40modelcontextprotocol/sdk@1.2.3",
            "pkg:npm/%40modelcontextprotocol/sdk@1.2.3",
        ),
    ],
)
def test_declared_package_ids_have_standard_fields_and_keep_native_assurance(
    registry, name, version, purl, expected
):
    original = component(registry_type=registry, name=name, version=version, package_url=purl)
    bom = AIBOM(components=[original])
    cdx = CycloneDXGenerator().generate(bom)
    assert validate_cyclonedx(cdx) == []
    assert cdx["components"][0]["purl"] == expected
    assert cdx["components"][0]["version"] == version.lstrip("=")
    spdx = SPDXGenerator().generate(bom)
    assert validate_spdx(spdx) == []
    projected = next(node for node in spdx["@graph"] if node["type"] == "software_Package")
    assert projected["software_packageUrl"] == expected
    assert projected["software_packageVersion"] == version.lstrip("=")
    assert projected["externalIdentifier"][0] == {
        "type": "ExternalIdentifier",
        "externalIdentifierType": "packageUrl",
        "identifier": expected,
        "comment": "Declared package identity; not authenticated by the exporter.",
    }
    for exporter, document in [(CycloneDXGenerator, cdx), (SPDXGenerator, spdx)]:
        restored = exporter.recover(document)
        assert native_document(restored) == native_document(bom)
        assert restored.components[0].trust_tier is TrustTier.UNKNOWN
        assert restored.components[0].assurance_level is AssuranceLevel.DECLARED


@pytest.mark.parametrize(
    "changes",
    [
        {"package_url": "https://pypi.org/project/openai"},
        {"package_url": "pkg:pypi/openai@1.2.3\n"},
        {"package_url": "pkg:pypi/openai@1.2.3%0A"},
        {"package_url": "pkg:pypi/openai@1.2%zz"},
        {"package_url": "pkg:pypi//openai@1.2.3"},
        {"package_url": "pkg:pypi/openai@1.2.3?a=one&a=two"},
        {"package_url": "pkg:pypi/openai@1.2.3?a="},
        {"package_url": "pkg:pypi/..@1.2.3", "name": ".."},
        {"package_url": "pkg:pypi/openai@1.2.3#../secret"},
        {"package_url": "pkg:pypi/openai@1.2.invalid", "version": "==1.2.invalid"},
        {"package_url": "pkg:pypi/other@1.2.3"},
        {"package_url": "pkg:pypi/openai@9.9.9"},
        {"package_url": "pkg:pypi/openai@1.2.3", "registry_type": "npm"},
        {"registry_type": None},
        {"registry_type": "docker-hub"},
        {"registry_type": "huggingface"},
        {"package_url": "pkg:npm/openai@1.2.3", "registry_type": "PyPI", "version": "1.2.3"},
        {
            "package_url": "pkg:npm/%40scope/name@latest",
            "registry_type": "npm",
            "name": "@scope/name",
            "version": "latest",
        },
    ],
)
def test_invalid_or_conflicting_ids_are_omitted_and_loss_is_explicit(changes):
    bom = AIBOM(components=[component(**changes)])
    assert package_identifier(bom.components[0]).status == "unavailable-invalid"
    for exporter in [CycloneDXGenerator(), SPDXGenerator()]:
        result = exporter.generate_with_report(bom)
        if isinstance(exporter, CycloneDXGenerator):
            assert "purl" not in result.document["components"][0]
        else:
            projected = next(
                node for node in result.document["@graph"] if node["type"] == "software_Package"
            )
            assert "externalIdentifier" not in projected
            assert "software_packageUrl" not in projected
        assert native_document(exporter.recover(result.document)) == native_document(bom)
        assert any(
            item["path"] == "/components/0/package_url" and item["severity"] == "warning"
            for item in result.loss_report["items"]
        )


def test_projection_1_keeps_the_0_1_0_ecosystem_rule():
    # 0.1.0 checked only a PyPI or npm entry's ecosystem; its exports must still recover.
    from nexus_symbiote.generators import _legacy

    entry = component(registry_type="docker-hub")
    assert package_identifier(entry).value is None
    assert _legacy.package_identifier(entry).value == "pkg:pypi/openai@1.2.3"
    assert _legacy.package_identifier(component(registry_type="npm")).value is None


def server(**changes) -> MCPServerComponent:
    values = {
        "bom_ref": "mcp-server:fs",
        "name": "fs",
        "version": "1.2.3",
        "launcher_package": "npm:@modelcontextprotocol/server-filesystem",
        "package_url": "pkg:npm/%40modelcontextprotocol/server-filesystem@1.2.3",
    }
    return MCPServerComponent(**(values | changes))


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({}, "pkg:npm/%40modelcontextprotocol/server-filesystem@1.2.3"),
        (
            {
                "version": "0.6.2",
                "launcher_package": "pypi:mcp_server_git",
                "package_url": "pkg:pypi/mcp-server-git@0.6.2",
            },
            "pkg:pypi/mcp-server-git@0.6.2",
        ),
    ],
)
def test_an_mcp_server_exports_the_package_it_launches(changes, expected):
    bom = AIBOM(components=[server(**changes)])
    cdx = CycloneDXGenerator().generate_with_report(bom)
    assert cdx.document["components"][0]["purl"] == expected
    assert cdx.document["components"][0]["version"] == bom.components[0].version
    assert not any(item["path"].endswith("/package_url") for item in cdx.loss_report["items"])
    spdx = SPDXGenerator().generate(bom)
    projected = next(node for node in spdx["@graph"] if node["type"] == "software_Package")
    assert projected["software_packageUrl"] == expected
    assert projected["externalIdentifier"][0]["identifier"] == expected
    for exporter, document in [(CycloneDXGenerator, cdx.document), (SPDXGenerator, spdx)]:
        assert native_document(exporter.recover(document)) == native_document(bom)
    from nexus_symbiote.generators import _legacy

    assert _legacy.package_identifier(bom.components[0]).status == "unknown"


@pytest.mark.parametrize(
    "changes",
    [
        {"launcher_package": None},
        {"launcher_package": "npm:@modelcontextprotocol/server-memory"},
        {"launcher_package": "pypi:@modelcontextprotocol/server-filesystem"},
        {"version": "1.2.4"},
        {"version": None},
        {"package_url": "pkg:npm/%40modelcontextprotocol/server-filesystem"},
        {
            "package_url": "pkg:npm/%40modelcontextprotocol/server-filesystem@1.2.3"
            "?repository_url=https://npm.example.com"
        },
        {"launcher_package": "oci:ghcr.io/example/server", "package_url": "pkg:oci/server@1.2.3"},
    ],
)
def test_an_mcp_server_package_url_that_disagrees_is_omitted_and_reported(changes):
    bom = AIBOM(components=[server(**changes)])
    for exporter in [CycloneDXGenerator(), SPDXGenerator()]:
        result = exporter.generate_with_report(bom)
        if isinstance(exporter, CycloneDXGenerator):
            assert "purl" not in result.document["components"][0]
        else:
            assert all("software_packageUrl" not in node for node in result.document["@graph"])
            assert all("externalIdentifier" not in node for node in result.document["@graph"])
        assert native_document(exporter.recover(result.document)) == native_document(bom)
        assert any(
            item["path"] == "/components/0/package_url" and item["severity"] == "warning"
            for item in result.loss_report["items"]
        )


def test_unknown_identity_does_not_invent_an_external_identifier():
    bom = AIBOM(components=[component(package_url=None, version=None)])
    assert package_identifier(bom.components[0]).status == "unknown"
    cdx = CycloneDXGenerator().generate(bom)
    assert "purl" not in cdx["components"][0]
    spdx = SPDXGenerator().generate(bom)
    assert all("externalIdentifier" not in node for node in spdx["@graph"])


@pytest.mark.parametrize(
    "declaration,purl_version,status",
    [
        ("===1.0", "1", "unavailable-invalid"),
        ("===1.0", "1.0", "declared"),
        ("===1.0", "1.0.0", "unavailable-invalid"),
        ("==1.0", "1", "declared"),
    ],
)
def test_arbitrary_equality_preserves_exact_version_spelling(declaration, purl_version, status):
    bom = AIBOM(
        components=[component(version=declaration, package_url="pkg:pypi/openai@" + purl_version)]
    )
    assert package_identifier(bom.components[0]).status == status
    cdx = CycloneDXGenerator().generate(bom)
    spdx = SPDXGenerator().generate(bom)
    projected = next(node for node in spdx["@graph"] if node["type"] == "software_Package")
    if status == "declared":
        assert cdx["components"][0]["purl"] == "pkg:pypi/openai@" + purl_version
        assert projected["software_packageUrl"] == "pkg:pypi/openai@" + purl_version
    else:
        assert "purl" not in cdx["components"][0]
        assert "externalIdentifier" not in projected
    for exporter, document in [(CycloneDXGenerator, cdx), (SPDXGenerator, spdx)]:
        assert native_document(exporter.recover(document)) == native_document(bom)


def test_independent_standard_consumers_retain_package_identifiers():
    from cyclonedx.model.bom import Bom
    from spdx_python_model.bindings import v3_0_1 as spdx

    bom = AIBOM(components=[component()])
    cdx = Bom.from_json(CycloneDXGenerator().generate(bom))
    assert cdx is not None
    assert str(next(iter(cdx.components)).purl) == "pkg:pypi/openai@1.2.3"
    objects = spdx.SHACLObjectSet()
    objects_json = SPDXGenerator().generate(bom)
    spdx.JSONLDDeserializer().read(io.BytesIO(json.dumps(objects_json).encode()), objects)
    output = io.BytesIO()
    spdx.JSONLDSerializer().write(objects, output)
    consumed = json.loads(output.getvalue())
    projected = next(node for node in consumed["@graph"] if node["type"] == "software_Package")
    assert projected["software_packageUrl"] == "pkg:pypi/openai@1.2.3"
    assert projected["externalIdentifier"][0]["externalIdentifierType"] == "packageUrl"
    assert projected["externalIdentifier"][0]["identifier"] == "pkg:pypi/openai@1.2.3"
    assert validate_spdx(consumed) == []
