"""Cited models in a report whose credential pseudonyms are keyed to one scan.

A merged scan names the models a report cites, and a report that declares run-scoped
credential identities is projected under its own profiles. The two meet in every
default ShadowScan code report: each projection keeps its own profile identifier,
every component of one import carries the same one, and a rerun that only renames
pseudonyms keeps the cited models and is not drift.
"""

import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.scanners.shadowscan import (
    CONTENT_PROFILE,
    MODEL_REF_PREFIX,
    PROJECTION_PROFILE,
    RUN_SCOPED_CONTENT_PROFILE,
    RUN_SCOPED_PROJECTION_PROFILE,
    ShadowScanImporter,
)

SCHEMA = Path(__file__).parents[1] / "schemas/nexus-symbiote-aibom-1.0.schema.json"
MODEL = "gpt-4o-mini"
MODEL_REF = MODEL_REF_PREFIX + hashlib.sha256(MODEL.encode()).hexdigest()
SOURCE = f'import openai\n\nreply = client.chat(model="{MODEL}")\n'
PROFILE = "shadowscan:projection-profile"


def _pseudonym(run: str, credential: str, prefix: str = "credential") -> str:
    return f"{prefix}:hmac-sha256:" + hashlib.sha256(f"{run}/{credential}".encode()).hexdigest()


def _report(run: str, scope: str | None = "run") -> dict:
    """An agent that cites a model and names a credential, as one ShadowScan run reports it.

    ``run`` stands for the per-scan key: it changes the pseudonyms and the run times only.
    """
    started = f"2026-11-18T16:0{len(run)}:55+00:00"
    collection_scope: dict = {"schema": "shadowscan.collection-scope/v1", "comparable": True}
    if scope is not None:
        collection_scope |= {
            "credential_identity_schema": "shadowscan.credential-identity/v1",
            "credential_identity_scope": scope,
        }
    credential = _pseudonym(run, "openai")
    return {
        "version": "0.1.4",
        "started_at": started,
        "finished_at": started,
        "collection_scope": collection_scope,
        "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
        "stats": [
            {
                "connector": "code.filesystem",
                "started_at": started,
                "finished_at": started,
                "errors": [],
                "skipped": False,
                "incomplete": False,
            }
        ],
        "findings": [
            {
                "id": "ss-agent",
                "kind": "agent",
                "surface": "code",
                "last_seen": started,
                "risk": {"level": "medium"},
                "evidence": [
                    {
                        "signal": "model:provider.openai",
                        "location": "app.py:3",
                        "attributes": {"category": "provider", "value": MODEL},
                    },
                    {"attributes": {"value": credential}, "description": f"key: {credential}"},
                ],
            },
            {
                "id": "ss-mcp",
                "kind": "mcp-server",
                "surface": "code",
                "last_seen": started,
                "evidence": [{"attributes": {"caller": _pseudonym(run, "client", "caller")}}],
            },
        ],
    }


def _project(tmp_path: Path, name: str, data: dict) -> Path:
    project = tmp_path / name
    project.mkdir()
    (project / "app.py").write_text(SOURCE)
    (project / "requirements.txt").write_text("openai\n")
    (project / "shadowscan.json").write_text(json.dumps(data))
    return project


def _scan(tmp_path: Path, name: str, data: dict) -> Path:
    out = tmp_path / f"{name}.json"
    project = _project(tmp_path, name, data)
    CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(out)])
    assert out.is_file()
    return out


def _load(path: Path) -> AIBOM:
    return AIBOM.model_validate(json.loads(path.read_text()))


def _imported(bom: AIBOM) -> dict:
    return {c.bom_ref: c for c in bom.components if c.bom_ref.startswith("shadowscan:")}


def test_each_projection_has_its_own_profile():
    # diff compares finding digests only under one profile, and validate --project
    # reproduces a projection from its profile's rules: two rules need two identifiers.
    assert PROJECTION_PROFILE == "nexus-symbiote/shadowscan-projection/v5"
    assert RUN_SCOPED_PROJECTION_PROFILE == "nexus-symbiote/shadowscan-projection/v6"
    assert (CONTENT_PROFILE, RUN_SCOPED_CONTENT_PROFILE) == (
        "nexus-symbiote/shadowscan-content/v1",
        "nexus-symbiote/shadowscan-content/v2",
    )


@pytest.mark.parametrize(
    ("scope", "projection", "content"),
    [
        ("run", RUN_SCOPED_PROJECTION_PROFILE, RUN_SCOPED_CONTENT_PROFILE),
        ("keyed", PROJECTION_PROFILE, CONTENT_PROFILE),
        (None, PROJECTION_PROFILE, CONTENT_PROFILE),
    ],
)
def test_a_cited_model_carries_the_profile_of_its_report(tmp_path, scope, projection, content):
    result = ShadowScanImporter().scan(_project(tmp_path, "project", _report("a", scope)))
    assert len(result.components) == 3
    assert [c.name for c in result.components if c.bom_ref == MODEL_REF] == [MODEL]
    assert {c.properties[PROFILE] for c in result.components} == {projection}
    assert result.source_report_content_profile == content


def test_a_rerun_with_new_pseudonyms_keeps_the_cited_model_and_is_not_drift(tmp_path):
    first = _scan(tmp_path, "s0", _report("a"))
    second = _scan(tmp_path, "s1", _report("bb"))
    boms = [_load(first), _load(second)]
    claims = [bom.metadata.completeness for bom in boms]
    assert claims[0].source_report_digest != claims[1].source_report_digest
    assert claims[0].source_report_content_digest == claims[1].source_report_content_digest
    models = [_imported(bom)[MODEL_REF] for bom in boms]
    assert models[0].properties == models[1].properties
    assert models[0].properties[PROFILE] == RUN_SCOPED_PROJECTION_PROFILE
    report = AIBOMDiffer().diff(*boms)
    assert report.security_alerts == []
    assert not report.components_added and not report.components_removed
    result = CliRunner().invoke(main, ["diff", "--fail-on-alert", str(first), str(second)])
    assert result.exit_code == 0, result.output
    assert "[INFO] ShadowScan report regenerated; normalized content unchanged." in result.output
    schema = Draft202012Validator(json.loads(SCHEMA.read_text()))
    assert not list(schema.iter_errors(json.loads(first.read_text())))


def test_project_validation_reproduces_a_run_scoped_import_with_a_cited_model(tmp_path):
    bom = _scan(tmp_path, "project", _report("a"))
    assert MODEL_REF in _imported(_load(bom))
    args = ["--project", str(tmp_path / "project"), "--no-project-policy"]
    result = CliRunner().invoke(main, ["validate", str(bom), *args, "--allow-unsigned-discovery"])
    assert "discovery report" not in result.output
    assert "discovery content digest" not in result.output


def test_an_identity_scope_switch_is_a_profile_change_on_every_imported_component(tmp_path):
    # The finding digests of a keyed and a run-scoped report follow different rules, so
    # diff must not compare them: each imported component falls back to the strict
    # comparison, which names the changed profile.
    keyed = _load(_scan(tmp_path, "s0", _report("a", "keyed")))
    run = _load(_scan(tmp_path, "s1", _report("a")))
    assert set(_imported(keyed)) == set(_imported(run)) and len(_imported(run)) == 3
    report = AIBOMDiffer().diff(keyed, run)
    for ref in _imported(run):
        alerts = [a["alert"] for a in report.security_alerts if a["component"] == ref]
        assert any(f"properties.{PROFILE} changed" in alert for alert in alerts), (ref, alerts)
    assert not any("finding content changed" in a["alert"] for a in report.security_alerts)
    assert any("no comparable content digest" in a["alert"] for a in report.security_alerts)


def test_sarif_without_imported_discovery_leaves_the_cited_model_out_and_counts_it(tmp_path):
    project = _project(tmp_path, "project", _report("a"))
    output = tmp_path / "bom.sarif"
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-f", "sarif"]
    result = CliRunner().invoke(main, [*args, "--sarif-omit-imported-discovery", "-o", str(output)])
    assert result.exit_code == 0, result.output
    text = output.read_text()
    run = json.loads(text)["runs"][0]
    assert run["results"], "local findings are still exported"
    assert not any(
        r["properties"]["component_ref"].startswith("shadowscan:") for r in run["results"]
    )
    # The model's identifier and the cited location stay in the native inventory.
    assert MODEL not in text and MODEL_REF_PREFIX not in text and "app.py:3" not in text
    assert run["properties"]["nexus-symbiote:omittedImportedFindings"] == 1
    warnings = [
        n["message"]["text"]
        for n in run["invocations"][0]["toolExecutionNotifications"]
        if n["level"] == "warning"
    ]
    assert (
        "This run leaves out 3 imported ShadowScan component(s) and their 1 finding(s); the "
        "native inventory and the ShadowScan report keep them."
    ) in warnings
