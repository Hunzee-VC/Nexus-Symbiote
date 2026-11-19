"""Tests for foreign SBOM import, nested manifest walking, shape census, and evidence-profile (R1.2-2, R1.1-8)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, RiskSeverity, TrustTier
from nexus_symbiote.core.models import (
    AgentComponent,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    RegistryEntryComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.evidence_profile import EVIDENCE_PROFILE_SCHEMA, build_evidence_profile
from nexus_symbiote.sbom_import import (
    MAX_FOREIGN_COMPONENTS,
    classify_pinning_state,
    import_foreign_sbom,
    unread_shape_census,
    walk_nested_manifests,
)


def _sample_aibom() -> AIBOM:
    return AIBOM(
        components=[
            AgentComponent(
                bom_ref="agent:repo",
                name="customer-support-agent",
                version="1.2.0",
                supplier="Acme AI",
                assurance_level=AssuranceLevel.OBSERVED,
                trust_tier=TrustTier.INTERNAL_VERIFIED,
            ),
            ModelComponent(
                bom_ref="model:tuned",
                name="support-llama-8b-ft",
                version="1.0.0",
                resolved_revision="a" * 40,
                signing_status="sigstore-signed",
                safetensors_header_hash="sha256:" + "1" * 64,
                hashes={"sha256": "sha256:" + "2" * 64},
                assurance_level=AssuranceLevel.VERIFIED,
                trust_tier=TrustTier.INTERNAL_VERIFIED,
            ),
            MCPServerComponent(
                bom_ref="mcp:remote-crm",
                name="crm-mcp",
                transport="streamable-http",
                endpoint_url="https://mcp.example.com/v1",
                version_pinned=False,
                assurance_level=AssuranceLevel.OBSERVED,
            ),
            ToolComponent(
                bom_ref="tool:lookup-ticket",
                name="lookup_ticket",
                definition_hash="sha256:" + "3" * 64,
                assurance_level=AssuranceLevel.OBSERVED,
            ),
            PromptComponent(
                bom_ref="prompt:sys",
                name="CLAUDE.md",
                content_hash="sha256:" + "5" * 64,
                assurance_level=AssuranceLevel.OBSERVED,
            ),
            RegistryEntryComponent(
                bom_ref="pkg:mcp-sdk",
                name="mcp",
                version="1.4.0",
                registry_type="pypi",
                package_url="pkg:pypi/mcp@1.4.0",
                hashes={"sha256": "sha256:" + "6" * 64},
                assurance_level=AssuranceLevel.OBSERVED,
            ),
        ]
    )


def test_import_foreign_sbom_conflicts_local_binding_privacy_and_census(
    tmp_path: Path,
) -> None:
    (tmp_path / "models").mkdir()
    local_weights = b"safetensors-mock-bytes"
    local_sha = "sha256:" + hashlib.sha256(local_weights).hexdigest()
    (tmp_path / "models" / "embed.bin").write_bytes(local_weights)

    (tmp_path / "mcp-server").mkdir()
    (tmp_path / "mcp-server" / "package.json").write_text(
        json.dumps({"name": "sub-mcp", "dependencies": {"@modelcontextprotocol/sdk": "^1.2.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "setup.cfg").write_text(
        "[options]\ninstall_requires =\n    langchain>=0.3.0\n",
        encoding="utf-8",
    )
    (tmp_path / "rust-worker").mkdir()
    (tmp_path / "rust-worker" / "Cargo.toml").write_text(
        '[package]\nname = "w"\n[dependencies]\ncandle-core = "0.8.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "go-svc").mkdir()
    (tmp_path / "go-svc" / "go.mod").write_text(
        "module example.com/svc\ngo 1.22\nrequire github.com/sashabaranov/go-openai v1.32.0\n",
        encoding="utf-8",
    )
    (tmp_path / "notebooks").mkdir()
    (tmp_path / "notebooks" / "exp.ipynb").write_text("{}", encoding="utf-8")
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "main.tf").write_text("# terraform\n", encoding="utf-8")
    (tmp_path / "chart").mkdir()
    (tmp_path / "chart" / "Chart.yaml").write_text("name: demo\nversion: 0.1.0\n", encoding="utf-8")
    (tmp_path / "workflows").mkdir()
    (tmp_path / "workflows" / "flow.json").write_text(
        '{"nodes": [], "connections": {}}', encoding="utf-8"
    )

    base_bom = AIBOM(
        components=[
            RegistryEntryComponent(
                bom_ref="pkg:openai",
                name="openai",
                version="1.52.0",
                registry_type="pypi",
                package_url="pkg:pypi/openai@1.52.0",
                assurance_level=AssuranceLevel.OBSERVED,
            )
        ]
    )
    foreign_cdx = tmp_path / "syft.cdx.json"
    foreign_cdx.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "type": "library",
                        "name": "openai",
                        "version": "1.40.0",
                        "purl": "pkg:pypi/openai@1.40.0",
                    },
                    {
                        "type": "machine-learning-model",
                        "name": "internal-secret-embedder",
                        "version": "1.0.0",
                        "supplier": {"name": "Private Division Alpha"},
                        "hashes": [
                            {
                                "alg": "SHA-256",
                                "content": local_sha.removeprefix("sha256:"),
                            }
                        ],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    summary = import_foreign_sbom(
        foreign_cdx, target_aibom=base_bom, project_root=tmp_path, reveal_names=False
    )
    assert summary.imported_count == 2
    assert summary.bound_local_count == 1
    assert summary.conflict_count == 1
    imported_items = [c for c in summary.aibom.components if c.bom_ref.startswith("sbom:")]
    assert all(c.assurance_level == AssuranceLevel.DECLARED for c in imported_items)
    assert all(c.name.startswith("imported-") for c in imported_items)
    assert all(getattr(c, "package_url", None) is None for c in imported_items)
    assert all(getattr(c, "supplier", None) is None for c in imported_items)
    serialized = summary.aibom.to_native_json()
    assert "internal-secret-embedder" not in serialized
    assert "Private Division Alpha" not in serialized

    assert len(summary.aibom.components) == 3
    conflicting = [
        c
        for c in summary.aibom.components
        if any(r.category == "source_conflict" for r in getattr(c, "risks", []))
    ]
    assert len(conflicting) == 2

    nested, failures = walk_nested_manifests(tmp_path)
    assert not failures
    nested_names = {c.name for c in nested}
    assert {
        "@modelcontextprotocol/sdk",
        "langchain",
        "candle-core",
        "github.com/sashabaranov/go-openai",
    } <= nested_names
    assert all(c.properties.get("pinning_state") == "manifest-only" for c in nested)
    states = classify_pinning_state(summary.aibom)
    assert states["pkg:openai"] == "pinned-version"

    census = {row.shape: row.count for row in unread_shape_census(tmp_path)}
    assert census == {"*.ipynb": 1, "*.tf": 1, "Chart.yaml": 1, "n8n/*.json": 1}


def test_import_sbom_adversarial_symlink_large_json_component_cap_and_malformed_manifests(
    tmp_path: Path,
) -> None:
    # 1. Symlinked foreign SBOM is refused fail-closed.
    real_sbom = tmp_path / "real.cdx.json"
    real_sbom.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}),
        encoding="utf-8",
    )
    linked_sbom = tmp_path / "linked.cdx.json"
    linked_sbom.symlink_to(real_sbom)
    with pytest.raises(OSError):
        import_foreign_sbom(linked_sbom)

    # 2. Foreign SBOM larger than 4 MiB (up to 16 MiB) parses cleanly without hitting default 4 MiB cap.
    large_sbom = tmp_path / "large.cdx.json"
    large_sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "metadata": {"comment": "x" * (4 * 1024 * 1024 + 65536)},
                "components": [{"type": "library", "name": "openai", "version": "1.52.0"}],
            }
        ),
        encoding="utf-8",
    )
    large_summary = import_foreign_sbom(large_sbom, reveal_names=True)
    assert large_summary.imported_count == 1

    # 3. Foreign SBOM exceeding MAX_FOREIGN_COMPONENTS fails closed instead of silently truncating.
    over_cap = tmp_path / "over_cap.cdx.json"
    over_cap.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {"type": "library", "name": f"pkg-{i}", "version": "1.0.0"}
                    for i in range(MAX_FOREIGN_COMPONENTS + 1)
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="exceeds maximum component count"):
        import_foreign_sbom(over_cap)

    # 4. Malformed nested manifests and deeply nested YAML flow brackets record failures instead of crashing.
    proj = tmp_path / "hostile_proj"
    (proj / "broken-js").mkdir(parents=True)
    (proj / "broken-js" / "package.json").write_text("{not-json", encoding="utf-8")
    (proj / "deep-conda").mkdir()
    (proj / "deep-conda" / "environment.yml").write_text(
        "dependencies: " + ("[" * 200) + ("x" + "]" * 200),
        encoding="utf-8",
    )
    (proj / "good-py").mkdir()
    (proj / "good-py" / "requirements.txt").write_text("openai==1.52.0\n", encoding="utf-8")

    nested, failures = walk_nested_manifests(proj)
    assert any(c.name == "openai" for c in nested)
    assert len(failures) == 2
    assert any("broken-js/package.json" in f for f in failures)
    assert any("deep-conda/environment.yml" in f for f in failures)


def test_evidence_profile_and_cli_commands_end_to_end(tmp_path: Path) -> None:
    bom = _sample_aibom()
    bom.components[2].risks.append(
        RiskAssessment(
            severity=RiskSeverity.HIGH,
            category="version_pinning",
            detail="Unpinned dependency.",
        )
    )
    bom_path = tmp_path / "aibom.json"
    bom.save(bom_path)

    profile = build_evidence_profile(bom, runtime_matched_refs={"model:tuned"})
    assert profile["schema"] == EVIDENCE_PROFILE_SCHEMA
    serialized_profile = json.dumps(profile)
    assert "trust_score" not in serialized_profile.lower()
    assert "trustscore" not in serialized_profile.lower()
    tuned_entry = next(c for c in profile["components"] if c["bom_ref"] == "model:tuned")
    assert tuned_entry["evidence"] == {
        "pinned": True,
        "digest_bound": True,
        "signed_under_policy": True,
        "observed_by_collector": True,
        "reported_at_runtime": True,
    }
    assert tuned_entry["missing_evidence"] == []

    runner = CliRunner()
    res_ep = runner.invoke(main, ["evidence-profile", str(bom_path), "--json-output"])
    assert res_ep.exit_code == 0, res_ep.output
    ep_doc = json.loads(res_ep.stdout)
    assert ep_doc["component_count"] == len(bom.components)

    # Test SPDX 2.3 and SPDX 3.0.1 import via CLI.
    spdx23_path = tmp_path / "foreign.spdx23.json"
    spdx23_path.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "name": "transformers",
                        "versionInfo": "4.45.0",
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/transformers@4.45.0",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    merged_out = tmp_path / "imported.aibom.json"
    res_imp = runner.invoke(
        main,
        [
            "import-sbom",
            str(spdx23_path),
            "--into",
            str(bom_path),
            "-o",
            str(merged_out),
            "--reveal-names",
            "--json-output",
        ],
    )
    assert res_imp.exit_code == 0, res_imp.output
    imp_doc = json.loads(res_imp.stdout)
    assert imp_doc["source_format"] == "spdx-2.3"
    assert imp_doc["imported_count"] == 1
