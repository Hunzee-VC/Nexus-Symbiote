"""sbom-merge collector: CycloneDX import, schema validation, redaction, dependency edges and coverage."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from symbiote.collect import sbom_merge
from symbiote.collect.base import CollectContext, CollectionResult, load_collectors, run_collectors
from symbiote.collect.sbom_merge import (
    SbomMergeCollector,
    auto_detected_sboms,
    sbom_dialect,
    schema_warnings,
)
from symbiote.digest import bytes_digest
from symbiote.model.entities import SoftwareComponent
from symbiote.model.enums import CoverageStatus, EdgeType, EvidenceKind, Surface

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
FAKE_PAT = "ghp_" + "X" * 36  # obviously fake, credential-shaped: must be redacted


def _write(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return path


def _ctx(root: Path, **kwargs: Any) -> CollectContext:
    return CollectContext(root=root, agent_id="agent:triage", now=NOW, **kwargs)


def _run(root: Path, **kwargs: Any) -> CollectionResult:
    return run_collectors(_ctx(root, **kwargs), [SbomMergeCollector()], only_detected=False)[0]


def _components(result: CollectionResult) -> dict[str, SoftwareComponent]:
    return {e.id: e for e in result.entities if isinstance(e, SoftwareComponent)}


def _edges(result: CollectionResult) -> set[tuple[str, str]]:
    return {(e.from_ref, e.to_ref) for e in result.edges if e.type is EdgeType.DEPENDS_ON}


def _bom(spec: str = "1.6", **extra: Any) -> dict[str, Any]:
    return {"bomFormat": "CycloneDX", "specVersion": spec, "version": 1, **extra}


CDXGEN_BOM = _bom(
    "1.6",
    metadata={
        "tools": {"components": [{"type": "application", "group": "@cyclonedx", "name": "cdxgen"}]},
        "component": {"type": "application", "name": "triage", "bom-ref": "pkg:npm/triage@1.0.0"},
    },
    components=[
        {
            "type": "library",
            "name": "left-pad",
            "version": "1.3.0",
            "purl": "pkg:npm/left-pad@1.3.0",
            "bom-ref": "pkg:npm/left-pad@1.3.0",
            "hashes": [
                {"alg": "SHA-256", "content": "AB" * 32},
                {"alg": "SHA-1", "content": "ab" * 20},
                {"alg": "SHA-256", "content": "not-hex"},
                "junk",
            ],
            "properties": [{"name": "cdx:npm:registry-token", "value": FAKE_PAT}],
        },
        {
            "type": "application",
            "name": "server-github",
            "group": "@modelcontextprotocol",
            "version": "0.5.0",
            "purl": "pkg:npm/%40modelcontextprotocol/server-github@0.5.0",
            "bom-ref": "mcp-github",
            "properties": [
                {"name": "cdx:mcp:transport", "value": "stdio"},
                {"name": "cdx:agent:framework", "value": "claude-agent-sdk"},
                {"name": "plain"},
                "junk",
            ],
            "components": [
                {"type": "library", "name": "zod", "version": "3.23.8", "bom-ref": "zod"},
                {"type": "library", "group": "org.example", "name": "util", "bom-ref": "util"},
            ],
        },
        {
            "type": "library",
            "name": "left-pad",
            "version": "1.3.0",
            "purl": "pkg:npm/left-pad@1.3.0",
            "bom-ref": "dup",
        },
        {"type": "library", "version": "9.9.9"},
        "not-a-component",
    ],
    dependencies=[
        {"ref": "pkg:npm/triage@1.0.0", "dependsOn": ["pkg:npm/left-pad@1.3.0", "mcp-github", "ghost"]},
        {"ref": "mcp-github", "dependsOn": ["zod", "util", "mcp-github", "missing"]},
        {"ref": "dup", "dependsOn": ["zod"]},
        {"ref": "unknown-ref", "dependsOn": ["zod"]},
        {"ref": "zod"},
        {"ref": 7},
        "junk",
    ],
)


def test_cdxgen_sbom_is_merged_verbatim_with_graph_and_evidence(tmp_path: Path) -> None:
    raw = _write(tmp_path / "bom.json", CDXGEN_BOM).read_bytes()
    result = _run(tmp_path)
    comps = _components(result)
    assert set(comps) == {
        "sw:pkg-npm-left-pad-1.3.0",
        "sw:pkg-npm-40modelcontextprotocol-server-github-0.5.0",
        "sw:zod-3.23.8",
        "sw:org.example-util",
    }
    pad = comps["sw:pkg-npm-left-pad-1.3.0"]
    assert (pad.name, pad.version, pad.purl, pad.component_type) == (
        "left-pad",
        "1.3.0",
        "pkg:npm/left-pad@1.3.0",
        "library",
    )
    assert pad.hashes == ["sha256:" + "ab" * 32]
    assert pad.cyclonedx["properties"] == [{"name": "cdx:npm:registry-token", "value": "<redacted>"}]
    assert "redacted:credential-shaped-token" in pad.tags
    digest = bytes_digest(raw)
    assert pad.provenance.locator == "bom.json#/components/0"
    assert pad.provenance.evidence[0].digest == digest
    assert pad.foreign == {"agentbom:import:dialect": "cdxgen", "agentbom:import:source-digest": digest}

    mcp = comps["sw:pkg-npm-40modelcontextprotocol-server-github-0.5.0"]
    assert {"cdxgen-ai-component", "cdxgen:mcp", "cdxgen:agent"} <= set(mcp.tags)
    assert "components" not in mcp.cyclonedx  # nested components become their own entities
    assert comps["sw:zod-3.23.8"].provenance.locator == "bom.json#/components/1/components/0"
    assert comps["sw:zod-3.23.8"].purl is None and not comps["sw:zod-3.23.8"].tags

    assert _edges(result) == {
        ("agent:triage", "sw:pkg-npm-left-pad-1.3.0"),
        ("agent:triage", "sw:pkg-npm-40modelcontextprotocol-server-github-0.5.0"),
        ("sw:pkg-npm-40modelcontextprotocol-server-github-0.5.0", "sw:zod-3.23.8"),
        ("sw:pkg-npm-40modelcontextprotocol-server-github-0.5.0", "sw:org.example-util"),
        ("sw:pkg-npm-left-pad-1.3.0", "sw:zod-3.23.8"),  # via the duplicate's bom-ref
    }
    root_edge = next(e for e in result.edges if e.to_ref == "sw:pkg-npm-left-pad-1.3.0")
    assert root_edge.qualifiers == {"purl": "pkg:npm/left-pad@1.3.0"}
    assert root_edge.declared_by == "bom.json#/dependencies/0"

    [evidence] = result.evidence
    assert evidence.evidence_kind is EvidenceKind.SCAN_REPORT and evidence.digest == digest
    assert evidence.id == "ev:" + digest[7:19]
    [redaction] = result.redactions
    assert redaction.ids == ["sw:pkg-npm-left-pad-1.3.0"] and redaction.count == 1
    dump = json.dumps([e.to_json_dict() for e in result.entities]) + json.dumps(result.warnings)
    assert FAKE_PAT not in dump
    assert any("unknown bom-refs" in w for w in result.warnings)
    assert any("without purl or name" in w for w in result.warnings)
    cov = result.coverage[Surface.CODE]
    # one component lacked both purl and name: the SBOM is imported, but coverage is partial, not complete
    assert cov.status is CoverageStatus.PARTIAL
    # every entry is examined, including the malformed one that was skipped
    assert cov.sources[0].locator == "bom.json" and cov.sources[0].items == 7


def test_without_a_graph_the_agent_depends_on_every_top_level_component(tmp_path: Path) -> None:
    bom = _bom(
        "1.5",
        metadata={"tools": [{"vendor": "anchore", "name": "syft", "version": "1.0"}]},
        components=[
            {
                "type": "library",
                "name": "a",
                "version": "1",
                "purl": "pkg:pypi/a@1",
                "components": [{"name": "inner"}],
            },
            {"type": "library", "name": "b", "version": "2", "purl": "pkg:pypi/b@2"},
        ],
    )
    _write(tmp_path / "sbom" / "app.cdx.json", bom)
    result = _run(tmp_path)
    assert _edges(result) == {("agent:triage", "sw:pkg-pypi-a-1"), ("agent:triage", "sw:pkg-pypi-b-2")}
    edge = next(e for e in result.edges if e.to_ref == "sw:pkg-pypi-b-2")
    assert edge.declared_by == "sbom/app.cdx.json#/components/1"
    assert "sw:inner" in _components(result)
    assert _components(result)["sw:inner"].foreign["agentbom:import:dialect"] == "syft"
    assert any("no vendored CycloneDX 1.5 schema" in w for w in result.warnings)


def test_explicit_paths_override_auto_detection(tmp_path: Path) -> None:
    _write(tmp_path / "bom.json", _bom(components=[{"type": "library", "name": "auto"}]))
    outside = _write(
        tmp_path / "elsewhere" / "x.json", _bom(components=[{"type": "library", "name": "given"}])
    )
    result = _run(tmp_path, options={"sbom": [str(outside), "elsewhere/x.json", "missing.json", 7, ""]})
    assert set(_components(result)) == {"sw:given"}
    sources = {s.locator: s for s in result.coverage[Surface.CODE].sources}
    assert sources["elsewhere/x.json"].ok
    assert sources["missing.json"].error_class == "not-found"
    assert result.coverage[Surface.CODE].status is CoverageStatus.PARTIAL
    single = _run(tmp_path, options={"sbom": Path("elsewhere/x.json")})
    assert set(_components(single)) == {"sw:given"}


@pytest.mark.parametrize(
    ("content", "error_class", "warning"),
    [
        ('{"spdxVersion": "SPDX-2.3"}', "unsupported-source", "SPDX documents are not merged"),
        ('{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}', "unsupported-source", "SPDX"),
        ('{"bomFormat": "Other"}', "unsupported-source", "not a CycloneDX document"),
        ('{"bomFormat": "CycloneDX", "specVersion": "1.3"}', "unsupported-source", "specVersion"),
        ('{"bomFormat": "CycloneDX", "specVersion": 1.6}', "unsupported-source", "specVersion"),
        ('["CycloneDX"]', "unsupported-source", "not a JSON object"),
        ("{ broken", "parse-error", "not valid JSON"),
        ('{"bomFormat": "CycloneDX", "bomFormat": "CycloneDX"}', "parse-error", "not valid JSON"),
    ],
)
def test_unsupported_and_malformed_inputs(
    tmp_path: Path, content: str, error_class: str, warning: str
) -> None:
    _write(tmp_path / "sbom.json", content)
    result = _run(tmp_path)
    [source] = result.coverage[Surface.CODE].sources
    assert not source.ok and source.error_class == error_class
    assert any(warning in w for w in result.warnings)
    assert not result.entities


def test_schema_errors_are_warnings_and_the_document_is_still_imported(tmp_path: Path) -> None:
    bad = _bom(
        "1.6",
        version="one",
        components=[
            {"type": "gadget", "name": "x", "purl": "pkg:npm/x@1"},
            {"type": "library", "name": "y", "licenses": [{"license": {"id": "NOT-A-LICENSE"}}]},
            {"type": 5, "name": "z"},
            {"type": "library", "name": "dup"},
            {"type": "library", "name": "dup"},
        ],
    )
    _write(tmp_path / "bom.json", bad)
    result = _run(tmp_path)
    assert {"sw:pkg-npm-x-1", "sw:y", "sw:z", "sw:dup"} == set(_components(result))
    text = "\n".join(result.warnings)
    assert "/version" in text
    assert "/components/0/type" in text
    assert "violates 'enum'" in text  # rule named, instance value never quoted
    assert "violates 'uniqueItems'" in text  # the linear-time uniqueItems check
    assert result.coverage[Surface.CODE].sources[0].ok


def test_schema_warnings_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sbom_merge, "MAX_SCHEMA_COMPONENTS", 3)
    monkeypatch.setattr(sbom_merge, "MAX_SCHEMA_DEPENDENCIES", 2)
    monkeypatch.setattr(sbom_merge, "MAX_SCHEMA_WARNINGS", 2)
    doc = _bom(
        "1.6",
        version="x",
        components=[
            {"type": "nope", "name": "a", "components": [{"type": "nope", "name": "a1"}]},
            {"type": "nope", "name": "b", "components": [{"type": "nope", "name": "b1"}]},
            {"type": "nope", "name": "c"},
        ],
        dependencies=[{"ref": "a"}, {"ref": "b"}, {"ref": "c"}],
    )
    warnings = schema_warnings(doc, "1.6", json.dumps(doc).encode())
    assert (
        warnings[0] == "schema validation covered only 1 of 3 top-level components, 2 of 3 dependency entries"
    )
    assert sum(w.startswith("schema: /") for w in warnings) == 2
    assert warnings[-1] == "schema: 1 more errors not shown"


def test_schema_error_messages_never_echo_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    doc = _bom("1.7", version=FAKE_PAT, components=[{"type": "library", "name": "x", "description": 5}])
    warnings = schema_warnings(doc, "1.7", json.dumps(doc).encode())
    assert any(w.startswith("schema: /version: violates 'type'") for w in warnings)
    assert FAKE_PAT not in json.dumps(warnings)
    monkeypatch.setattr(sbom_merge, "_MAX_SCHEMA_ERRORS", 1)
    capped = schema_warnings(doc, "1.7", json.dumps(doc).encode())
    assert sum(w.startswith("schema: /") for w in capped) == 1


def test_validation_runs_once_per_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = sbom_merge._schema_bundle("1.6")
    assert real is not None
    calls: list[int] = []

    class _Spy:
        def iter_errors(self, instance: Any) -> Any:
            calls.append(1)
            return real.validator.iter_errors(instance)

    monkeypatch.setattr(sbom_merge, "_schema_bundle", lambda _v: sbom_merge._SchemaBundle(_Spy(), ()))
    _write(tmp_path / "bom.json", _bom(components=[{"type": "library", "name": "a"}]))
    _write(tmp_path / "sbom" / "other.cdx.json", _bom(components=[{"type": "library", "name": "b"}]))
    _run(tmp_path)
    assert len(calls) == 2


def test_cryptography_definitions_stub_warns_only_when_used(tmp_path: Path) -> None:
    crypto = _bom(
        "1.7",
        components=[
            {
                "type": "cryptographic-asset",
                "name": "aes",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {"algorithmFamily": "AES"},
                },
            }
        ],
    )
    _write(tmp_path / "bom.json", crypto)
    result = _run(tmp_path)
    assert any("cryptography-defs.schema.json is not vendored" in w for w in result.warnings)
    assert "sw:aes" in _components(result)
    plain = _bom("1.7", components=[{"type": "library", "name": "p"}])
    assert not schema_warnings(plain, "1.7", json.dumps(plain).encode())


def test_secret_shaped_keys_and_unsafe_integers(tmp_path: Path) -> None:
    bom = _bom(
        "1.6",
        components=[
            {
                "type": "library",
                "name": "weird",
                "purl": f"pkg:npm/weird@1?token={FAKE_PAT}",
                "properties": [{"name": "size", "value": "1"}],
                "evidence": {FAKE_PAT: 1, f"{FAKE_PAT}x": [2**60, True, None]},
            }
        ],
    )
    _write(tmp_path / "bom.json", bom)
    result = _run(tmp_path)
    [comp] = _components(result).values()
    assert comp.id == "sw:weird" and comp.purl is None  # a credential-shaped purl is withheld
    assert comp.cyclonedx["evidence"] == {"<redacted>": 1, "<redacted>-2": [str(2**60), True, None]}
    assert {"redacted:credential-shaped-token", "cyclonedx-number-stringified"} <= set(comp.tags)
    assert result.redactions[0].count == 3
    assert FAKE_PAT not in json.dumps(comp.to_json_dict())


def test_large_integer_without_secrets_is_stringified(tmp_path: Path) -> None:
    _write(tmp_path / "bom.json", _bom(components=[{"type": "library", "name": "big", "x": [2**60]}]))
    [comp] = _components(_run(tmp_path)).values()
    assert comp.cyclonedx["x"] == [str(2**60)] and "cyclonedx-number-stringified" in comp.tags


def test_slug_collisions_and_cross_file_dedupe(tmp_path: Path) -> None:
    first = _bom(
        components=[
            {"type": "library", "name": "a", "purl": "pkg:npm/a+b@1", "bom-ref": "1"},
            {"type": "library", "name": "a", "purl": "pkg:npm/a=b@1", "bom-ref": "2"},
        ],
        dependencies=[{"ref": "1", "dependsOn": ["2"]}],
    )
    second = _bom(
        components=[{"type": "library", "name": "a", "purl": "pkg:npm/a+b@1", "bom-ref": "x"}],
        dependencies=[{"ref": "x", "dependsOn": ["x"]}],
    )
    _write(tmp_path / "bom.json", first)
    _write(tmp_path / "sbom" / "again.cdx.json", second)
    result = _run(tmp_path)
    ids = sorted(_components(result))
    assert ids[0] == "sw:pkg-npm-a-b-1" and ids[1].startswith("sw:pkg-npm-a-b-1-") and len(ids) == 2
    assert (ids[0], ids[1]) in _edges(result)
    assert len([e for e in result.edges if e.from_ref == "agent:triage"]) == 2  # deduplicated across files
    assert len(result.evidence) == 2


def test_detect_and_auto_detection(tmp_path: Path) -> None:
    collector = SbomMergeCollector()
    assert not collector.detect(_ctx(tmp_path))
    assert collector.detect(_ctx(tmp_path, options={"sbom": "given.json"}))
    _write(tmp_path / "sbom" / "service.cdx.json", "{}")
    _write(tmp_path / "sbom" / "notes.json", "{}")
    _write(tmp_path / "package.json", "{}")
    (tmp_path / "sbom.json").symlink_to(tmp_path / "package.json")
    assert collector.detect(_ctx(tmp_path))
    assert [p.name for p in auto_detected_sboms(tmp_path)] == ["service.cdx.json"]


def test_no_sbom_leaves_the_code_surface_not_attempted(tmp_path: Path) -> None:
    result = _run(tmp_path)
    assert result.coverage[Surface.CODE].status is CoverageStatus.NOT_ATTEMPTED
    assert not result.coverage[Surface.CODE].sources
    assert any("software layer not collected" in w for w in result.warnings)
    skipped = run_collectors(_ctx(tmp_path), [SbomMergeCollector()])[0]
    assert skipped.reason == "not-detected"


def test_unreadable_sbom(tmp_path: Path) -> None:
    _write(tmp_path / "bom.json", _bom(components=[{"type": "library", "name": "x" * 500}]))
    result = _run(tmp_path, max_file_bytes=100)
    assert result.coverage[Surface.CODE].sources[0].error_class == "too-large"


@pytest.mark.parametrize(
    ("tools", "dialect"),
    [
        ([{"name": "syft"}], "syft"),
        ({"services": [{"name": "k8s-aibom"}], "components": "nope"}, "k8s-aibom"),
        ({"components": [{"vendor": "acme", "name": "scanner"}, "junk"]}, "generic"),
        ("cdxgen", "generic"),
    ],
)
def test_sbom_dialect(tools: Any, dialect: str) -> None:
    assert sbom_dialect({"metadata": {"tools": tools}}) == dialect


def test_registered_as_builtin(tmp_path: Path) -> None:
    [collector] = load_collectors(["sbom-merge"], include_plugins=False)
    assert isinstance(collector, SbomMergeCollector)
    assert collector.record().surfaces == [Surface.CODE]


# --------------------------------------------------------------------------------------------- review regressions


def _sbom(components: list[dict[str, Any]]) -> dict[str, Any]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}


def test_url_credentials_never_reach_ids_purls_or_copies(tmp_path: Path) -> None:
    comps = [
        {
            "type": "library",
            "name": "internal-lib",
            "version": "1.0",
            "purl": "pkg:pypi/internal-lib@1.0?repository_url=https://deploy:hunter2-Pa55w0rd@pypi.internal.example/simple",
            "externalReferences": [{"type": "vcs", "url": "https://bob:pw123@git.example.com/x.git"}],
        },
        {
            "type": "library",
            "name": "enc",
            "version": "1",
            "purl": "pkg:npm/enc@1?repository_url=https%3A%2F%2Fu%3Asecretpw%40npm.example.com%2F",
        },
    ]
    _write(tmp_path / "bom.json", _sbom(comps))
    result = _run(tmp_path)
    blob = json.dumps([e.to_json_dict() for e in result.entities]) + json.dumps(
        [e.model_dump(mode="json") for e in result.edges]
    )
    for secret in ("hunter2", "pw123", "secretpw"):
        assert secret not in blob, secret
    assert result.redactions


def test_token_after_escaped_whitespace_is_redacted(tmp_path: Path) -> None:
    token = "ghp_" + "Z" * 36
    comps = [
        {"type": "library", "name": n, "version": "1", "purl": f"pkg:pypi/{n}@1", "description": text}
        for n, text in (
            ("nl", f"Deploy key:\n{token}"),
            ("tab", f"key\t{token}"),
            ("nbsp", f"key{chr(0xA0)}{token}"),
        )
    ]
    _write(tmp_path / "bom.json", _sbom(comps))
    blob = json.dumps([e.to_json_dict() for e in _run(tmp_path).entities], ensure_ascii=False)
    assert token not in blob


def test_imported_agentbom_properties_are_not_laundered(tmp_path: Path) -> None:
    comp = {
        "type": "library",
        "name": "c",
        "version": "1",
        "purl": "pkg:pypi/c@1",
        "properties": [{"name": "agentbom:assurance", "value": "verified"}, {"name": "cdx:x", "value": "1"}],
    }
    _write(tmp_path / "bom.json", _sbom([comp]))
    (entity,) = [e for e in _run(tmp_path).entities if isinstance(e, SoftwareComponent)]
    assert entity.foreign["imported:agentbom:assurance"] == "verified"
    assert [p["name"] for p in entity.cyclonedx["properties"]] == ["cdx:x"]
    assert "imported-agentbom-properties" in entity.tags


def test_symlinked_sbom_directory_and_deep_nesting(tmp_path: Path) -> None:
    import os

    root, other = tmp_path / "scanned", tmp_path / "other"
    root.mkdir()
    other.mkdir()
    _write(other / "bom.json", _sbom([{"type": "library", "name": "outside", "purl": "pkg:pypi/outside@1"}]))
    os.symlink(other, root / "sbom")
    deep: dict[str, Any] = {"type": "library", "name": "d", "purl": "pkg:pypi/d@1"}
    cur = deep
    for i in range(300):
        nxt: dict[str, Any] = {"type": "library", "name": f"d{i}", "purl": f"pkg:pypi/d{i}@1"}
        cur["components"] = [nxt]
        cur = nxt
    _write(root / "deep.cdx.json", _sbom([deep]))
    _write(root / "bom.json", _sbom([{"type": "library", "name": "healthy", "purl": "pkg:pypi/healthy@1"}]))
    result = _run(root)
    ids = {e.id for e in result.entities}
    assert "sw:pkg-pypi-healthy-1" in ids and not any("outside" in i for i in ids)
    assert any("nests too deeply" in w for w in result.warnings)
