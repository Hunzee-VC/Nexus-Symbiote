"""Regression tests for the audit remediation (NS-05/08/09/11/14/04)."""

from __future__ import annotations

import os

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.hashing import extract_version_pin
from nexus_symbiote.core.models import (
    AIBOMMetadata,
    ModelComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.scanners.base import safe_rglob
from nexus_symbiote.scanners.model import ModelScanner


@pytest.mark.parametrize(
    "ref,expected_pinned",
    [
        ("pkg==1.2.3", True),
        ("mcp-server-git==2.0.1", True),
        ("image@sha256:" + "a" * 64, True),
        ("node@18.1.0", True),
        ("docker.io/x:1.2.3", True),
        ("pkg>=1.2.3", False),
        ("^1.0.0", False),
        ("~1.2.3", False),
        ("latest", False),
        ("@modelcontextprotocol/server-filesystem", False),
    ],
)
def test_extract_version_pin_classification(ref: str, expected_pinned: bool) -> None:
    # NS-05: exact/digest pins must read as pinned; ranges/floating as not.
    assert (extract_version_pin(ref) is not None) is expected_pinned


def test_model_scanner_flags_disguised_pickle(tmp_path) -> None:
    # NS-11: a pickle renamed to a 'safe' extension is caught by content sniff.
    (tmp_path / "evil.safetensors").write_bytes(b"\x80\x04\x95 pickle payload")
    result = ModelScanner().scan(tmp_path)
    categories = {r.category for c in result.components for r in c.risks}
    assert "format_mismatch" in categories


def test_diff_detects_rugpull_via_ref_rename() -> None:
    # NS-08: a definition change hidden behind a bom_ref rename is still flagged.
    def tool(ref: str, h: str) -> ToolComponent:
        return ToolComponent(
            bom_ref=ref,
            name="search",
            description_text="d",
            definition_hash=f"sha256:{h * 64}",
            definition_hash_version="rfc8785-jcs-v1",
        )

    old = AIBOM(components=[tool("tool:srv/search", "a")])
    new = AIBOM(components=[tool("tool:srv/search__v2", "b")])
    report = AIBOMDiffer().diff(old, new)
    assert any(a["severity"] == "high" and "rug-pull" in a["alert"] for a in report.security_alerts)


def test_sarif_result_always_has_location_and_fingerprint() -> None:
    # NS-09: a finding with no source_path still gets a location + fingerprint.
    bom = AIBOM(metadata=AIBOMMetadata(authors=[]))
    bom.add_component(
        ModelComponent(
            bom_ref="m1",
            name="x",
            source_path=None,
            risks=[
                RiskAssessment(
                    severity=RiskSeverity.CRITICAL, category="unsafe_format", detail="rce"
                )
            ],
        )
    )
    sarif = SARIFGenerator().generate(bom)
    result = sarif["runs"][0]["results"][0]
    assert "locations" in result and result["locations"]
    assert "partialFingerprints" in result
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "9.5"


def test_safe_rglob_does_not_follow_directory_symlinks(tmp_path) -> None:
    # NS-14: discovery must not descend into symlinked directories.
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    root = tmp_path / "root"
    root.mkdir()
    (root / "here.txt").write_text("here")
    try:
        os.symlink(outside, root / "link")
    except OSError:
        pytest.skip("symlinks unavailable")
    names = {p.name for p in safe_rglob(root)}
    assert "here.txt" in names
    assert "secret.txt" not in names


def test_verify_fails_closed_without_a_valid_bundle(tmp_path) -> None:
    # NS-04: verify must fail (never silently pass) when a bundle does not verify.
    import json

    (tmp_path / "model.safetensors").write_text("weights")
    (tmp_path / "model.sigstore").write_text("{}")
    bom = tmp_path / "bom.json"
    bom.write_text(
        json.dumps(
            {
                "metadata": {"spec_version": "1.0.0"},
                "components": [
                    {
                        "bom_ref": "m",
                        "component_type": "model",
                        "name": "w",
                        "source_path": "model.safetensors",
                    }
                ],
            }
        )
    )
    result = CliRunner().invoke(
        main,
        [
            "verify",
            str(bom),
            "--project",
            str(tmp_path),
            "--identity",
            "me@example.com",
            "--issuer",
            "https://accounts.google.com",
        ],
    )
    assert result.exit_code == 1
