"""What the standard fields of CycloneDX and SPDX exports say without the extension."""

from __future__ import annotations

import io
import json
import re
from datetime import UTC, datetime
from typing import Any

import pytest

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge, native_document
from nexus_symbiote.core.models import (
    AgentComponent,
    CompletenessClaim,
    DataSourceComponent,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    RAGSourceComponent,
    RegistryEntryComponent,
    ToolComponent,
)
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.generators.validation import _schema, validate_cyclonedx, validate_spdx
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES

AGENT = "agent:repository:0123456789abcdef01234567"
DIGEST = "sha256:" + "cd" * 32
SRI = "sha512-" + "q" * 86 + "=="


def _inventory() -> AIBOM:
    bom = AIBOM(
        components=[
            AgentComponent(bom_ref=AGENT, name="repo", description="Repository agent definition"),
            MCPServerComponent(
                bom_ref="server",
                name="files",
                source_path=".mcp.json",
                version="2025.8.21",
                version_pinned=True,
                tool_count=0,
            ),
            ToolComponent(bom_ref="tool", name="read", mcp_server_ref="server"),
            PromptComponent(bom_ref="prompt", name="CLAUDE.md", content_hash=DIGEST),
            RAGSourceComponent(bom_ref="rag", name="docs", index_snapshot_hash=DIGEST),
            DataSourceComponent(bom_ref="data", name="tickets", content_hash="sha256:not-a-digest"),
            ModelComponent(bom_ref="model", name="m.safetensors", model_type="classifier"),
        ]
    )
    bom.metadata.timestamp = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
    names = sorted(BUILTIN_SCANNER_NAMES)
    bom.metadata.completeness = CompletenessClaim(
        scope="repository",
        collectors_requested=names,
        collectors_completed=names,
        scanner_status=dict.fromkeys(names, "complete"),
    )
    bom.dependencies = [
        DependencyEdge(source_ref="server", target_ref="tool", relationship="provides-tool"),
        DependencyEdge(
            source_ref=AGENT,
            target_ref="server",
            relationship="configured-with",
            conditions="repository association; runtime use and authority unobserved",
        ),
        DependencyEdge(source_ref=AGENT, target_ref="model", relationship="depends-on"),
    ]
    return bom


def _registry(**changes: Any) -> RegistryEntryComponent:
    values: dict[str, Any] = {
        "bom_ref": "registry:package",
        "name": "openai",
        "registry_type": "pypi",
    }
    return RegistryEntryComponent(**(values | changes))


def _cdx_component(bom: AIBOM, ref: str) -> dict[str, Any]:
    document = CycloneDXGenerator().generate(bom)
    assert validate_cyclonedx(document) == []
    return next(c for c in document["components"] if c["bom-ref"] == ref)


def _properties(component: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p["value"] for p in component.get("properties", [])}


@pytest.mark.parametrize(
    "registry,name,expected",
    [
        ("pypi", "openai", "library"),
        ("npm", "@modelcontextprotocol/sdk", "library"),
        ("docker-hub", "ollama/ollama:latest", "container"),
        ("oci", "ghcr.io/org/image", "container"),
        ("huggingface", "org/model", "library"),
        (None, "unknown", "library"),
    ],
)
def test_registry_entries_are_libraries_or_containers(registry, name, expected):
    bom = AIBOM(components=[_registry(name=name, registry_type=registry)])
    assert _cdx_component(bom, "registry:package")["type"] == expected


@pytest.mark.parametrize(
    "registry,name,declared,exact",
    [
        ("pypi", "openai", "==1.2.3", "1.2.3"),
        ("pypi", "openai", "===1.0", "1.0"),
        ("pypi", "openai", "1.4", "1.4"),
        ("pypi", "openai", "<2,>=1.0", None),
        ("pypi", "openai", '==1.2.3; python_version >= "3.11"', None),
        ("pypi", "openai", "@ https://host/openai.whl", None),
        ("npm", "@scope/sdk", "^1.2.3", None),
        ("npm", "@scope/sdk", "latest", None),
        ("npm", "@scope/sdk", "git+https://host/repo.git", None),
        ("npm", "@scope/sdk", "1.2.3", "1.2.3"),
        ("npm", "@scope/sdk", "npm:other@" + "9" * 2000, None),
        ("huggingface", "org/model", "main", None),
    ],
)
def test_standard_version_fields_carry_exact_versions_only(registry, name, declared, exact):
    bom = AIBOM(components=[_registry(name=name, registry_type=registry, version=declared)])
    component = _cdx_component(bom, "registry:package")
    assert component.get("version") == exact
    requested = _properties(component).get("nexus-symbiote:requestedVersion")
    assert requested == (None if exact else declared)
    spdx = SPDXGenerator().generate(bom)
    (package,) = [n for n in spdx["@graph"] if n["type"] == "software_Package"]
    assert package.get("software_packageVersion") == exact
    loss = json.loads(
        next(
            p["value"]
            for p in CycloneDXGenerator().generate(bom)["metadata"]["properties"]
            if p["name"] == "nexus-symbiote:lossReport"
        )
    )
    assert any(item["path"] == "/components/0/version" for item in loss["items"]) == (exact is None)


def test_a_package_url_version_is_the_exported_version():
    bom = AIBOM(components=[_registry(version="==1.2.3", package_url="pkg:pypi/openai@1.2.3")])
    component = _cdx_component(bom, "registry:package")
    assert (component["version"], component["purl"]) == ("1.2.3", "pkg:pypi/openai@1.2.3")


@pytest.mark.parametrize(
    "registry,name,version",
    [
        ("npm", "@scope/sdk", "1.0.0-" + "a" * 1100),
        ("pypi", "openai", "1." + "0" * 1100),
    ],
)
def test_a_package_url_version_beyond_the_schema_limit_is_a_requested_version(
    registry, name, version
):
    package_url = f"pkg:{registry}/{name.replace('@', '%40')}@{version}"
    bom = AIBOM(
        components=[
            _registry(name=name, registry_type=registry, version=version, package_url=package_url)
        ]
    )
    component = _cdx_component(bom, "registry:package")
    assert "version" not in component and component["purl"] == package_url
    assert _properties(component)["nexus-symbiote:requestedVersion"] == version
    spdx = SPDXGenerator().generate(bom)
    (package,) = [n for n in spdx["@graph"] if n["type"] == "software_Package"]
    assert "software_packageVersion" not in package


def test_the_loss_report_says_that_only_registry_versions_are_made_exact():
    bom = AIBOM(
        components=[
            AgentComponent(bom_ref="agent:card", name="card", version=">=2.0, latest"),
            _registry(version="1." + "0" * 1100),
        ]
    )
    document = CycloneDXGenerator().generate(bom)
    versions = {c["bom-ref"]: c.get("version") for c in document["components"]}
    assert versions == {"agent:card": ">=2.0, latest", "registry:package": None}
    loss = json.loads(
        next(
            p["value"]
            for p in document["metadata"]["properties"]
            if p["name"] == "nexus-symbiote:lossReport"
        )
    )
    assert not any("exact versions only" in text for text in loss["normalizations"])
    assert any("declared versions of other kinds" in text for text in loss["normalizations"])
    (item,) = [i for i in loss["items"] if i["path"].endswith("/version")]
    assert item["path"] == "/components/1/version" and "1024 characters" in item["reason"]


def test_the_repository_agent_is_the_subject_and_unconditional_edges_form_the_graph():
    bom = _inventory()
    document = CycloneDXGenerator().generate(bom)
    assert validate_cyclonedx(document) == []
    subject = document["metadata"]["component"]
    assert (subject["bom-ref"], subject["type"], subject["name"]) == (AGENT, "application", "repo")
    assert AGENT not in {c["bom-ref"] for c in document["components"]}
    assert document["dependencies"] == [
        {"ref": AGENT, "dependsOn": ["model"]},
        {"ref": "tool", "dependsOn": ["server"]},
    ]
    assert document["compositions"] == [
        {"aggregate": "unknown", "assemblies": [AGENT], "dependencies": [AGENT]}
    ]
    assert document["metadata"]["lifecycles"] == [{"phase": "pre-build"}]
    assert native_document(CycloneDXGenerator.recover(document)) == native_document(bom)


def test_recovery_tolerates_only_a_dropped_unknown_composition():
    from cyclonedx.model.bom import Bom
    from cyclonedx.output.json import JsonV1Dot7

    document = CycloneDXGenerator().generate(_inventory())
    expected = CycloneDXGenerator.recover(json.loads(json.dumps(document)))
    consumed = json.loads(JsonV1Dot7(Bom.from_json(document)).output_as_string())
    assert "compositions" not in consumed
    assert CycloneDXGenerator.recover(consumed) == expected
    for edited in (
        [{"aggregate": "unknown", "assemblies": ["server"], "dependencies": ["server"]}],
        [{"aggregate": "unknown"}],
        [{"aggregate": "unknown", "assemblies": [AGENT]}],
        [],
    ):
        with pytest.raises(ValueError, match="projection conflicts"):
            CycloneDXGenerator.recover({**document, "compositions": edited})


def test_without_a_repository_agent_there_is_no_subject():
    bom = _inventory()
    bom.components = [c for c in bom.components if c.bom_ref != AGENT]
    bom.dependencies = [d for d in bom.dependencies if AGENT not in {d.source_ref, d.target_ref}]
    bom.metadata.completeness = None
    document = CycloneDXGenerator().generate(bom)
    assert "component" not in document["metadata"] and "lifecycles" not in document["metadata"]
    assert document["compositions"] == [{"aggregate": "unknown"}]


def test_digests_with_a_standard_home_are_standard_hashes():
    bom = _inventory()
    bom.components.append(
        _registry(
            bom_ref="registry:npm/zod",
            name="zod",
            registry_type="npm",
            version="3.23.8",
            properties={"lockfile_integrity": SRI},
        )
    )
    document = CycloneDXGenerator().generate(bom)
    hashes = {c["bom-ref"]: c.get("hashes") for c in document["components"]}
    assert hashes["prompt"] == [{"alg": "SHA-256", "content": "cd" * 32}]
    assert hashes["rag"] == [{"alg": "SHA-256", "content": "cd" * 32}]
    assert hashes["data"] is None
    (zod,) = hashes["registry:npm/zod"]
    assert zod["alg"] == "SHA-512" and len(zod["content"]) == 128
    spdx = SPDXGenerator().generate(bom)
    prompt = next(n for n in spdx["@graph"] if n.get("name") == "CLAUDE.md")
    assert prompt["type"] == "software_File"
    assert prompt["verifiedUsing"] == [
        {"type": "Hash", "algorithm": "sha256", "hashValue": "cd" * 32}
    ]


def test_conflicting_digests_for_one_algorithm_fail_the_export():
    bom = AIBOM(
        components=[
            PromptComponent(
                bom_ref="p", name="p", hashes={"sha256": DIGEST, "SHA-256": "sha256:" + "ef" * 32}
            )
        ]
    )
    for generator in (CycloneDXGenerator(), SPDXGenerator()):
        with pytest.raises(ValueError, match="conflicting"):
            generator.generate(bom.model_copy(deep=True))


def test_blake_digests_are_exported_and_empty_digests_fail_in_both_formats():
    bom = AIBOM(components=[ModelComponent(bom_ref="m", name="m", hashes={"blake3": "ab" * 32})])
    assert _cdx_component(bom, "m")["hashes"] == [{"alg": "BLAKE3", "content": "ab" * 32}]
    spdx = SPDXGenerator().generate(bom)
    model = next(n for n in spdx["@graph"] if n.get("name") == "m")
    assert model["verifiedUsing"][0]["algorithm"] == "blake3"
    empty = AIBOM(components=[ModelComponent(bom_ref="m", name="m", hashes={"sha256": ""})])
    for generator in (CycloneDXGenerator(), SPDXGenerator()):
        with pytest.raises(ValueError, match="digest"):
            generator.generate(empty.model_copy(deep=True))


def test_source_paths_are_standard_evidence_and_properties_use_json_spelling():
    document = CycloneDXGenerator().generate(_inventory())
    server = next(c for c in document["components"] if c["bom-ref"] == "server")
    assert server["evidence"] == {"occurrences": [{"location": ".mcp.json"}]}
    properties = _properties(server)
    assert properties["nexus-symbiote:versionPinned"] == "true"
    # The native default of 0 also means "not observed".
    assert "nexus-symbiote:toolCount" not in properties
    tool = ToolComponent(bom_ref="t", name="t", annotations={"hint": {"a": 1}, "flag": False})
    properties = _properties(_cdx_component(AIBOM(components=[tool]), "t"))
    assert properties["nexus-symbiote:annotation.hint"] == '{"a":1}'
    assert properties["nexus-symbiote:annotation.flag"] == "false"


def _spdx_terms(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key.startswith("extension_cdxPropValue"):
                continue
            found |= _spdx_terms(item)
    elif isinstance(value, list):
        for item in value:
            found |= _spdx_terms(item)
    elif isinstance(value, str) and (
        value.startswith("https://spdx.org/rdf/") or re.fullmatch(r"[a-z]+_[A-Za-z]+", value)
    ):
        found.add(value)
    return found


def test_spdx_uses_only_terms_the_vendored_vocabulary_defines():
    context = _schema("spdx/spdx-context-3.0.1.jsonld")["@context"]
    defined = set(context) | {v for v in context.values() if isinstance(v, str)}
    document = SPDXGenerator().generate(_inventory())
    assert validate_spdx(document) == []
    terms = _spdx_terms(document["@graph"])
    assert "expandedlicensing_NoAssertionLicense" in terms
    assert terms <= defined
    licenses = [
        n["to"] for n in document["@graph"] if n.get("relationshipType") == "hasDeclaredLicense"
    ]
    assert licenses and all(to == ["expandedlicensing_NoAssertionLicense"] for to in licenses)


def test_spdx_omits_unknown_fields_instead_of_placeholders():
    document = SPDXGenerator().generate(_inventory())
    text = json.dumps([n for n in document["@graph"] if n["type"] != "SpdxDocument"])
    assert "Not supplied by the inventory producer" not in text
    assert "NOASSERTION" not in text and "software_downloadLocation" not in text
    model = next(n for n in document["@graph"] if n.get("name") == "m.safetensors")
    assert model["type"] == "ai_AIPackage" and model["ai_typeOfModel"] == ["classifier"]
    assert not {"ai_limitation", "ai_informationAboutTraining", "ai_autonomyType"} & set(model)
    rag = next(n for n in document["@graph"] if n.get("name") == "docs")
    assert rag["dataset_datasetType"] == ["noAssertion"]
    assert not {"dataset_intendedUse", "dataset_dataCollectionProcess"} & set(rag)
    agent = next(n for n in document["@graph"] if n.get("name") == "repo")
    assert agent["ai_informationAboutApplication"] == "Repository agent definition"


def test_spdx_declares_profiles_and_roots_the_document_in_an_sbom():
    document = SPDXGenerator().generate(_inventory())
    doc = document["@graph"][0]
    assert doc["profileConformance"] == ["core", "software", "expandedLicensing", "extension"]
    nodes = {n.get("spdxId", n.get("@id")): n for n in document["@graph"]}
    (root,) = doc["rootElement"]
    sbom = nodes[root]
    assert sbom["type"] == "software_Sbom" and sbom["software_sbomType"] == ["source"]
    (subject,) = sbom["rootElement"]
    assert nodes[subject]["name"] == "repo"
    no_ai = AIBOM(components=[ToolComponent(bom_ref="t", name="t")])
    assert SPDXGenerator().generate(no_ai)["@graph"][0]["profileConformance"] == [
        "core",
        "software",
        "extension",
    ]


def test_spdx_identifiers_are_minted_in_the_operator_namespace_or_a_uuid_urn():
    bom = _inventory()
    default = SPDXGenerator().generate(bom)
    assert re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", default["@graph"][0]["spdxId"])
    assert "spdx.org/spdxdocs" not in json.dumps(default)
    custom = SPDXGenerator("https://sbom.example.com/agents/").generate(bom)
    assert custom["@graph"][0]["spdxId"].startswith("https://sbom.example.com/agents/document/")
    for document in (default, custom):
        assert native_document(SPDXGenerator.recover(document)) == native_document(bom)
    for namespace in (
        "https://spdx.org/spdxdocs/x",
        "https://spdx.org./spdxdocs/x",
        "https://SPDX.ORG.../x",
        "https://spdx%2Eorg/spdxdocs/x",
        "https://www.spdx.org./x",
        "not an iri",
        "https://x.example/#frag",
        "",
    ):
        with pytest.raises(ValueError):
            SPDXGenerator(namespace)
    assert SPDXGenerator("https://spdx.org.example.com/x").generate(bom)


def test_spdx_validation_rejects_undefined_vocabulary_references():
    document = SPDXGenerator().generate(_inventory())
    relation = next(
        n for n in document["@graph"] if n.get("relationshipType") == "hasDeclaredLicense"
    )
    relation["to"] = ["https://spdx.org/rdf/3.0.1/terms/Licensing/NoAssertion"]
    assert any("unresolved" in error for error in validate_spdx(document))
    relation["to"] = ["https://spdx.org/rdf/3.0.1/terms/ExpandedLicensing/NoAssertionLicense"]
    assert validate_spdx(document) == []


def test_independent_consumers_keep_the_new_standard_fields():
    from cyclonedx.model.bom import Bom
    from cyclonedx.output.json import JsonV1Dot7
    from spdx_python_model.bindings import v3_0_1 as spdx

    cdx = CycloneDXGenerator().generate(_inventory())
    consumed = json.loads(JsonV1Dot7(Bom.from_json(cdx)).output_as_string())
    assert validate_cyclonedx(consumed) == []
    assert consumed["metadata"]["component"]["bom-ref"] == AGENT
    assert CycloneDXGenerator.recover(consumed) == CycloneDXGenerator.recover(cdx)
    document = SPDXGenerator().generate(_inventory())
    objects = spdx.SHACLObjectSet()
    spdx.JSONLDDeserializer().read(io.BytesIO(json.dumps(document).encode()), objects)
    output = io.BytesIO()
    spdx.JSONLDSerializer().write(objects, output)
    reserialized = json.loads(output.getvalue())
    assert validate_spdx(reserialized) == []
    assert SPDXGenerator.recover(reserialized) == SPDXGenerator.recover(document)
