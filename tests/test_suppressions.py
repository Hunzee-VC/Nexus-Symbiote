"""Targeted, accountable, expiring suppressions instead of category-wide switches."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.policy import Policy, PolicyError, Suppression, load_policy, weakened_settings
from nexus_symbiote.validators.risk import RiskScorer

TODAY = date(2026, 11, 10)


def _two_pickles(tmp_path: Path) -> tuple[Path, Path, dict]:
    project = tmp_path / "project"
    (project / "fixtures").mkdir(parents=True)
    (project / "models").mkdir()
    (project / "AGENTS.md").write_text("Use read-only tools.\n")
    (project / "fixtures" / "firmware.pkl").write_bytes(b"fixture bytes")
    (project / "models" / "classifier.pkl").write_bytes(b"model bytes")
    inventory = tmp_path / "bom.json"
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(inventory)]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    return project, inventory, json.loads(inventory.read_text())


def _ref(doc: dict, name: str) -> str:
    return next(c["bom_ref"] for c in doc["components"] if c.get("source_path", "").endswith(name))


def _suppression(component_ref: str, expires: str = "2999-12-31") -> str:
    return (
        "risk:\n  suppressions:\n"
        f'    - component_ref: "{component_ref}"\n'
        '      category: "serialization_format"\n'
        '      reason: "Test fixture, never loaded"\n'
        '      owner: "security@example.test"\n'
        f"      expires: {expires}\n"
    )


def test_a_suppression_accepts_one_component_while_the_same_category_still_fails(tmp_path):
    project, inventory, doc = _two_pickles(tmp_path)
    fixture = _ref(doc, "firmware.pkl")
    (project / ".nexus-symbiote.yaml").write_text(_suppression(fixture))
    args = ["risk", str(inventory), "--project", str(project), "--json-output"]
    result = CliRunner().invoke(main, args)
    payload = json.loads(result.stdout)
    assert result.exit_code == 1
    assert payload["gate_reasons"] == ["finding at or above critical"]
    remaining = {(f["component_ref"], f["category"]) for f in payload["findings"]}
    assert (_ref(doc, "classifier.pkl"), "serialization_format") in remaining
    assert (fixture, "serialization_format") not in remaining
    (suppressed,) = payload["suppressed_findings"]
    assert suppressed["component_ref"] == fixture and suppressed["severity"] == "critical"
    assert suppressed["reason"] == "Test fixture, never loaded"
    assert suppressed["owner"] == "security@example.test" and suppressed["expires"] == "2999-12-31"
    assert any(
        "risk.suppressions: serialization_format on " in w for w in payload["policy_weakened"]
    )
    assert payload["gate"]["suppressions"] == 1
    assert payload["gate"]["suppressions_source"] == "project policy"
    # The operator can always ignore checkout-supplied acceptances.
    ignored = CliRunner().invoke(main, [*args, "--no-project-policy"])
    assert json.loads(ignored.stdout)["suppressed_findings"] == []


def test_an_expired_suppression_no_longer_suppresses_and_fails_the_gate(tmp_path):
    project, inventory, doc = _two_pickles(tmp_path)
    fixture = _ref(doc, "firmware.pkl")
    (project / ".nexus-symbiote.yaml").write_text(_suppression(fixture, expires="2026-01-01"))
    args = ["risk", str(inventory), "--project", str(project), "--json-output"]
    payload = json.loads(CliRunner().invoke(main, args).stdout)
    assert payload["suppressed_findings"] == []
    assert any(f["component_ref"] == fixture for f in payload["findings"])
    assert (
        f"suppression of serialization_format on {fixture} expired on 2026-01-01"
        in payload["gate_reasons"]
    )
    assert payload["suppressions_expired"][0]["owner"] == "security@example.test"


def test_scorer_applies_exact_matches_only_and_reports_unused_entries(tmp_path):
    from nexus_symbiote.core.aibom import AIBOM

    _, inventory, doc = _two_pickles(tmp_path)
    fixture = _ref(doc, "firmware.pkl")
    entries = [
        Suppression(
            component_ref=fixture,
            category="serialization_format",
            reason="fixture",
            owner="sec",
            expires=TODAY,
        ),
        Suppression(
            component_ref=fixture.upper(),
            category="serialization_format",
            reason="fixture",
            owner="sec",
            expires=TODAY,
        ),
    ]
    report = RiskScorer(suppressions=entries, today=TODAY).score(AIBOM.load(inventory))
    assert [item.finding.component_ref for item in report.suppressed] == [fixture]
    assert [entry.component_ref for entry in report.suppressions_unused] == [fixture.upper()]
    assert not report.suppressions_expired


@pytest.mark.parametrize(
    "entry",
    [
        {"category": "serialization_format", "reason": "r", "owner": "o", "expires": "2027-01-01"},
        {
            "component_ref": "model:*",
            "category": "x",
            "reason": "r",
            "owner": "o",
            "expires": "2027-01-01",
        },
        {
            "component_ref": "m",
            "category": "x",
            "reason": " ",
            "owner": "o",
            "expires": "2027-01-01",
        },
        {"component_ref": "m", "category": "x", "reason": "r", "owner": "o", "expires": "20270101"},
        {"component_ref": "m", "category": "x", "reason": "r", "owner": "o"},
        {"component_ref": "m", "category": "x", "reason": "r", "owner": "o", "expires": "soon"},
    ],
)
def test_malformed_suppressions_fail_closed_with_the_setting_named(tmp_path, entry):
    (tmp_path / ".nexus-symbiote.yaml").write_text(json.dumps({"risk": {"suppressions": [entry]}}))
    with pytest.raises(PolicyError, match="risk.suppressions"):
        load_policy(tmp_path)


def test_suppression_dates_accept_yaml_dates_and_quoted_text_and_refuse_times(tmp_path):
    base = (
        "risk: {suppressions: [{component_ref: m, category: x, reason: r, owner: o, expires: %s}]}"
    )
    for value in ("2027-01-31", '"2027-01-31"'):
        (tmp_path / ".nexus-symbiote.yaml").write_text(base % value)
        policy = load_policy(tmp_path)
        assert policy is not None and policy.risk.suppressions[0].expires == date(2027, 1, 31)
    (tmp_path / ".nexus-symbiote.yaml").write_text(base % "2027-01-31T10:00:00Z")
    with pytest.raises(PolicyError, match="calendar date"):
        load_policy(tmp_path)
    duplicate = base % "2027-01-31"
    duplicate = duplicate.replace(
        "]}", ", {component_ref: m, category: x, reason: r, owner: o, expires: 2027-02-01}]}"
    )
    (tmp_path / ".nexus-symbiote.yaml").write_text(duplicate)
    with pytest.raises(PolicyError, match="only once"):
        load_policy(tmp_path)


def test_every_suppression_is_listed_as_a_weakened_setting():
    policy = Policy.model_validate(
        {
            "risk": {
                "suppressions": [
                    {
                        "component_ref": "model:a",
                        "category": "serialization_format",
                        "reason": "r",
                        "owner": "sec",
                        "expires": date(2027, 1, 31),
                    }
                ]
            }
        }
    )
    assert weakened_settings(policy) == [
        "risk.suppressions: serialization_format on model:a until 2027-01-31 (owner sec)"
    ]


def test_scan_records_the_governing_policy_and_its_relaxations(tmp_path):
    project, _, doc = _two_pickles(tmp_path)
    assert doc["metadata"]["policy_source"] == "built-in"
    assert doc["metadata"]["policy_weakened"] == []
    (project / ".nexus-symbiote.yaml").write_text(_suppression(_ref(doc, "firmware.pkl")))
    inventory = tmp_path / "governed.json"
    result = CliRunner().invoke(main, ["scan", str(project), "--report-only", "-o", str(inventory)])
    assert result.exit_code == 0, result.output
    metadata = json.loads(inventory.read_text())["metadata"]
    assert metadata["policy_source"] == "project:.nexus-symbiote.yaml"
    assert len(metadata["policy_weakened"]) == 1
    assert metadata["policy_weakened"][0].startswith("risk.suppressions: serialization_format")
