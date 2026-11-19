"""A ShadowScan rerun without SHADOWSCAN_IDENTITY_KEY is not drift.

Such a report declares run-scoped credential identities: ShadowScan keyed every
credential and caller pseudonym with a random per-scan key, so the same
credential gets a new pseudonym on each run. The content digest renames those
pseudonyms by order of first appearance, under its own versioned profile.
"""

import hashlib
import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.scanners import shadowscan
from nexus_symbiote.scanners.shadowscan import (
    CONTENT_PROFILE,
    PROJECTION_PROFILE,
    RUN_SCOPED_CONTENT_PROFILE,
    RUN_SCOPED_IDENTITIES_GAP,
    RUN_SCOPED_PROJECTION_PROFILE,
    ShadowScanImporter,
    report_content_digest,
)

SCHEMA = Path(__file__).parents[1] / "schemas/nexus-symbiote-aibom-1.0.schema.json"
IDENTITY_SCHEMA = "shadowscan.credential-identity/v1"


def _pseudonym(run: str, credential: str, prefix: str = "credential") -> str:
    return f"{prefix}:hmac-sha256:" + hashlib.sha256(f"{run}/{credential}".encode()).hexdigest()


def _report(
    run: str,
    *,
    scope: str | None = "run",
    schema: str = IDENTITY_SCHEMA,
    second_credential: str = "openai",
) -> dict:
    """Two findings sharing one credential, as ShadowScan reports them."""
    shared, other = _pseudonym(run, "github"), _pseudonym(run, second_credential)
    caller = _pseudonym(run, "gateway-client", "caller")
    started = f"2026-11-18T16:0{len(run)}:55+00:00"
    collection_scope = {"schema": "shadowscan.collection-scope/v1", "comparable": True}
    if scope is not None:
        collection_scope |= {
            "credential_identity_schema": schema,
            "credential_identity_scope": scope,
        }
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
                "id": "ss-mcp",
                "kind": "mcp-server",
                "surface": "code",
                "last_seen": started,
                "evidence": [
                    {"attributes": {"value": shared}, "description": f"credential: {shared}"},
                    {"attributes": {"caller": caller}},
                ],
            },
            {
                "id": "ss-secret",
                "kind": "secret",
                "surface": "code",
                "last_seen": started,
                "evidence": [
                    {"attributes": {"value": shared}},
                    {"attributes": {"value": other}, "description": f"OpenAI API key: {other}"},
                ],
            },
        ],
    }


def _import(data: dict):
    return ShadowScanImporter().parse_report(json.dumps(data))


def _scan(tmp_path: Path, name: str, data: dict) -> Path:
    project, out = tmp_path / name, tmp_path / f"{name}.json"
    (project / ".shadowscan").mkdir(parents=True)
    (project / ".shadowscan/report.json").write_text(json.dumps(data))
    CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(out)])
    assert out.is_file()
    return out


def _load(path: Path) -> AIBOM:
    return AIBOM.model_validate(json.loads(path.read_text()))


def test_content_vector_renames_pseudonyms_by_first_appearance():
    first, second = _pseudonym("a", "x"), _pseudonym("a", "y")
    caller = _pseudonym("a", "z", "caller")
    data = {
        "version": "0.1.4",
        "collection_scope": {
            "credential_identity_schema": IDENTITY_SCHEMA,
            "credential_identity_scope": "run",
        },
        "summary": {"complete": True},
        "stats": [],
        "findings": [
            {
                "id": "ss-1",
                "evidence": [{"value": first}, {"note": f"key {second}0"}, {"value": first}],
                "caller": caller,
            }
        ],
    }
    one, two, three = (
        f"{prefix}:hmac-sha256:" + f"{ordinal:064x}"
        for prefix, ordinal in (("caller", 1), ("credential", 2), ("credential", 3))
    )
    # Keys are visited in sorted order, so "caller" is numbered before "evidence".
    # The digit after the second pseudonym stays text.
    canonical = (
        '{"collection_scope":{"credential_identity_schema":"shadowscan.credential-identity/v1",'
        '"credential_identity_scope":"run"},"findings":[{"caller":"' + one + '","evidence":'
        '[{"value":"' + two + '"},{"note":"key ' + three + '0"},{"value":"' + two + '"}],'
        '"id":"ss-1"}],"stats":[],"summary":{"complete":true},"version":"0.1.4"}'
    ).encode()
    assert report_content_digest(data) == "sha256:" + hashlib.sha256(canonical).hexdigest()
    assert report_content_digest(data) == (
        "sha256:547f53e0948b65547398fb2681469f5feea3e63512567c7a5e98bd8a702cf4bc"
    )
    assert RUN_SCOPED_CONTENT_PROFILE == "nexus-symbiote/shadowscan-content/v2"
    assert RUN_SCOPED_PROJECTION_PROFILE == "nexus-symbiote/shadowscan-projection/v4+run-scoped"


def test_run_scoped_projection_profile_is_the_mapping_profile_with_a_suffix():
    assert RUN_SCOPED_PROJECTION_PROFILE == PROJECTION_PROFILE + "+run-scoped"


@pytest.mark.parametrize("version", ["v4", "v5", "v12"])
def test_a_mapping_change_moves_the_run_scoped_projection_profile(monkeypatch, version):
    mapping = f"nexus-symbiote/shadowscan-projection/{version}"
    monkeypatch.setattr(shadowscan, "PROJECTION_PROFILE", mapping)
    (run_scoped,) = _import(_report("a")).components
    (keyed,) = _import(_report("a", scope="keyed")).components
    profile = run_scoped.properties["shadowscan:projection-profile"]
    assert profile == mapping + "+run-scoped"
    assert keyed.properties["shadowscan:projection-profile"] == mapping
    assert not re.fullmatch(r"nexus-symbiote/shadowscan-projection/v[0-9]+", profile)


def test_new_run_scoped_pseudonyms_do_not_change_content_digests():
    first, second = _import(_report("a")), _import(_report("bb"))
    assert first.digest != second.digest
    assert first.content_profile == second.content_profile == RUN_SCOPED_CONTENT_PROFILE
    assert first.content_digest == second.content_digest
    for imported in (first, second):
        (server,) = imported.components
        assert server.properties["shadowscan:projection-profile"] == RUN_SCOPED_PROJECTION_PROFILE
        assert RUN_SCOPED_IDENTITIES_GAP in imported.limitations
    first_finding, second_finding = (
        imported.components[0].properties["shadowscan:finding-sha256"]
        for imported in (first, second)
    )
    assert first_finding == second_finding
    assert _import(json.loads(json.dumps(_report("a"), sort_keys=True))).content_digest == (
        first.content_digest
    )


@pytest.mark.parametrize(
    "edit",
    [
        # The second finding now names a credential distinct from the shared one.
        lambda d: d["findings"][1]["evidence"][0]["attributes"].update(
            value=_pseudonym("a", "another")
        ),
        lambda d: d["findings"][1]["evidence"].append({"value": _pseudonym("a", "added")}),
        lambda d: d["findings"][1]["evidence"].pop(),
        lambda d: d["findings"][0]["evidence"][0].update(description="credential: changed"),
        lambda d: d["collection_scope"].update(credential_identity_scope="keyed"),
    ],
)
def test_renaming_keeps_which_findings_share_a_credential(edit):
    baseline = _import(_report("a")).content_digest
    changed = _report("a")
    edit(changed)
    assert _import(changed).content_digest != baseline


@pytest.mark.parametrize(
    ("scope", "schema"),
    [
        ("keyed", IDENTITY_SCHEMA),
        ("run", "shadowscan.credential-identity/v2"),
        (None, IDENTITY_SCHEMA),
    ],
)
def test_other_identity_scopes_keep_exact_pseudonyms(scope, schema):
    first = _import(_report("a", scope=scope, schema=schema))
    second = _import(_report("bb", scope=scope, schema=schema))
    assert first.content_profile == CONTENT_PROFILE
    assert first.content_digest != second.content_digest
    assert first.components[0].properties["shadowscan:projection-profile"] == PROJECTION_PROFILE
    assert RUN_SCOPED_IDENTITIES_GAP not in first.limitations


def test_rerun_without_identity_key_raises_no_drift_alert(tmp_path):
    first = _scan(tmp_path, "s0", _report("a"))
    second = _scan(tmp_path, "s1", _report("bb"))
    result = CliRunner().invoke(main, ["diff", "--fail-on-alert", str(first), str(second)])
    assert result.exit_code == 0, result.output
    assert "[INFO] ShadowScan report regenerated; normalized content unchanged." in result.output
    assert AIBOMDiffer().diff(_load(first), _load(second)).security_alerts == []
    claim = json.loads(first.read_text())["metadata"]["completeness"]
    assert claim["source_report_content_profile"] == RUN_SCOPED_CONTENT_PROFILE
    assert RUN_SCOPED_IDENTITIES_GAP in claim["source_projection_limitations"]
    assert not list(
        Draft202012Validator(json.loads(SCHEMA.read_text())).iter_errors(
            json.loads(first.read_text())
        )
    )
    verified = CliRunner().invoke(
        main, ["verify-discovery", str(first), str(tmp_path / "s0/.shadowscan/report.json")]
    )
    assert verified.exit_code == 0, verified.output


def test_changed_credential_sharing_still_alerts(tmp_path):
    first = _scan(tmp_path, "s0", _report("a"))
    second = _scan(tmp_path, "s1", _report("bb", second_credential="github"))
    report = AIBOMDiffer().diff(_load(first), _load(second))
    assert any(
        alert["component"] == "metadata" and alert["severity"] == "high"
        for alert in report.security_alerts
    )


def test_identity_scope_switch_falls_back_to_the_strict_comparison(tmp_path):
    keyed = _scan(tmp_path, "s0", _report("a", scope="keyed"))
    run = _scan(tmp_path, "s1", _report("a"))
    report = AIBOMDiffer().diff(_load(keyed), _load(run))
    assert any("no comparable content digest" in alert["alert"] for alert in report.security_alerts)
