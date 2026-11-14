"""A lossy scheme-name projection must never silently erase requirements."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import A2AServerComponent
from nexus_symbiote.scanners.a2a import A2AScanner
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV

FIRST = "ghp_" + "A" * 36
SECOND = "ghp_" + "B" * 36
FAILURE = (
    ".well-known/agent-card.json: security scheme names collide after redaction; "
    "use distinct non-secret scheme identifiers"
)


def _card(
    names: tuple[str, str],
    *,
    form: str = "security",
    skill: bool = False,
    declared: bool = True,
    split: bool = False,
) -> dict[str, Any]:
    first, second = names
    requirements = (
        [{first: ["reader"]}, {second: ["fixed-role"]}]
        if split
        else [{first: ["reader"], second: ["fixed-role"]}]
    )
    if form != "security":
        requirements = [
            {"schemes": {name: {"list": values} for name, values in entry.items()}}
            for entry in requirements
        ]
    card: dict[str, Any] = {
        "name": "agent",
        "url": "https://agent.example",
        "skills": [{"id": "lookup"}],
    }
    if declared:
        card["securitySchemes"] = {
            name: {"type": "apiKey", "in": "header", "name": f"X-Key-{index}"}
            for index, name in enumerate(names)
        }
    target = card["skills"][0] if skill else card
    target[form] = requirements
    return card


def _write(root: Path, card: dict[str, Any]) -> None:
    directory = root / ".well-known"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "agent-card.json").write_text(json.dumps(card))


@pytest.mark.parametrize("form", ["security", "securityRequirements", "security_requirements"])
@pytest.mark.parametrize("skill", [False, True])
@pytest.mark.parametrize("declared", [False, True])
@pytest.mark.parametrize("keyed", [False, True])
@pytest.mark.parametrize("split", [False, True])
def test_colliding_names_fail_collection_across_forms_and_alternatives(
    tmp_path, monkeypatch, form, skill, declared, keyed, split
):
    if keyed:
        monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "synthetic-a2a-source-binding-key-2026")
    _write(tmp_path, _card((FIRST, SECOND), form=form, skill=skill, declared=declared, split=split))
    result = A2AScanner().scan(tmp_path)
    assert result.scan_failures == [FAILURE]
    assert not any(isinstance(component, A2AServerComponent) for component in result.components)
    assert FIRST not in str(result.scan_failures) and SECOND not in str(result.scan_failures)
    assert "reader" not in str(result.scan_failures) and "fixed-role" not in str(
        result.scan_failures
    )


@pytest.mark.parametrize("names", [(FIRST, "***"), ("***", FIRST), (FIRST, SECOND)])
def test_collisions_between_card_and_skill_requirements_fail_collection(tmp_path, names):
    first, second = names
    card = _card((first, second), declared=False)
    card["security"] = [{first: ["reader"]}]
    card["skills"][0]["securityRequirements"] = [{"schemes": {second: {"list": ["fixed-role"]}}}]
    _write(tmp_path, card)
    assert A2AScanner().scan(tmp_path).scan_failures == [FAILURE]


def test_a_declared_scheme_cannot_hide_a_different_requirement_name(tmp_path):
    card = _card((FIRST, SECOND), declared=False)
    card["securitySchemes"] = {FIRST: {"type": "oauth2"}}
    card["security"] = [{SECOND: ["admin"]}]
    _write(tmp_path, card)
    assert A2AScanner().scan(tmp_path).scan_failures == [FAILURE]


@pytest.mark.parametrize("kind", ["oauth2", "openIdConnect", "http", "mutualTLS", "x-custom"])
def test_collision_refusal_does_not_depend_on_the_declared_scheme_type(tmp_path, kind):
    card = _card((FIRST, SECOND))
    for scheme in card["securitySchemes"].values():
        scheme["type"] = kind
    _write(tmp_path, card)
    assert A2AScanner().scan(tmp_path).scan_failures == [FAILURE]


@pytest.mark.parametrize("keyed", [False, True])
@pytest.mark.parametrize("names", [("first", "second"), (FIRST, "ordinary")])
def test_distinct_projected_names_and_repeated_references_remain_supported(
    tmp_path, monkeypatch, keyed, names
):
    if keyed:
        monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "synthetic-a2a-source-binding-key-2026")
    card = _card(names, split=True)
    card["skills"][0]["security"] = [{names[0]: ["reader"]}]
    _write(tmp_path / "first", card)
    first = A2AScanner().scan(tmp_path / "first")
    assert not first.scan_failures
    (before,) = first.components
    reordered = json.loads(json.dumps(card, sort_keys=True))
    _write(tmp_path / "reordered", reordered)
    second = A2AScanner().scan(tmp_path / "reordered")
    assert not second.scan_failures
    (after,) = second.components
    assert before.properties["static_card_hash"] == after.properties["static_card_hash"]
    if keyed:
        assert before.properties["static_value_binding"] == after.properties["static_value_binding"]
    else:
        assert "static_value_binding" not in before.properties
    assert FIRST not in before.model_dump_json()


@pytest.mark.parametrize("changed", [0, 1])
def test_cli_reconciliation_and_risk_refuse_an_ambiguous_card(tmp_path, changed):
    project = tmp_path / "project"
    (project).mkdir()
    (project / "CLAUDE.md").write_text("Fixed reviewed instructions.\n")
    _write(project, _card(("first", "second")))
    runner = CliRunner()
    baseline = tmp_path / "baseline.json"
    result = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(baseline)])
    assert result.exit_code == 0, result.output
    card = _card((FIRST, SECOND))
    card["security"][0][(FIRST, SECOND)[changed]] = ["admin"]
    _write(project, card)
    candidate = tmp_path / "candidate.json"
    result = runner.invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(candidate)]
    )
    assert result.exit_code == 1, result.output
    assert "security scheme names collide after redaction" in result.output
    for command in ("validate", "risk"):
        result = runner.invoke(
            main, [command, str(baseline), "--project", str(project), "--no-project-policy"]
        )
        assert result.exit_code == 1, result.output
    result = runner.invoke(
        main, ["diff", str(baseline), str(candidate), "--fail-on-alert", "--json-output"]
    )
    assert result.exit_code == 1, result.output
    assert json.loads(result.output)["has_changes"]


def test_noncolliding_requirement_value_changes_remain_detectable(tmp_path):
    card = _card(("first", "second"))
    _write(tmp_path / "before", card)
    (before,) = A2AScanner().scan(tmp_path / "before").components
    changed = copy.deepcopy(card)
    changed["security"][0]["first"] = ["admin"]
    _write(tmp_path / "after", changed)
    (after,) = A2AScanner().scan(tmp_path / "after").components
    assert before.properties["static_card_hash"] != after.properties["static_card_hash"]
