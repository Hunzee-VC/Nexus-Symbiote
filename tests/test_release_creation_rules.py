"""Release creators cannot bypass the independent tag immutability boundary."""

import json

import pytest

from tests.support import ROOT, load_script

controls = load_script("check_repository_controls")


def immutable():
    data = json.loads((ROOT / "config/github-release-tag-ruleset.json").read_text())
    return {**data, "current_user_can_bypass": "never"}


def creation():
    return json.loads((ROOT / "config/github-release-tag-creation-ruleset.json").read_text())


def test_no_bypass_immutability_rule_does_not_deadlock_creation():
    rule = immutable()
    assert rule["rules"] == [{"type": "update"}, {"type": "deletion"}]
    assert rule["bypass_actors"] == []


def test_only_repository_administrators_can_create_but_cannot_move_release_tags():
    rule = creation()
    assert rule["enforcement"] == "active" and rule["target"] == "tag"
    assert rule["conditions"] == immutable()["conditions"]
    assert rule["rules"] == [{"type": "creation"}]
    assert rule["bypass_actors"] == [
        {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}
    ]
    assert controls.evaluate_tag_rulesets(
        [{**rule, "current_user_can_bypass": "always"}, immutable()],
        verify_bypass_actors=True,
    ) == ([], [])


@pytest.mark.parametrize("first", [False, True])
def test_preflight_rejects_a_creation_deadlock_even_beside_a_good_immutability_rule(first):
    good = immutable()
    blocked = {**good, "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}]}
    rules = [blocked, good] if first else [good, blocked]
    errors, _ = controls.evaluate_tag_rulesets(rules, verify_bypass_actors=True)
    assert any("creation" in error for error in errors)


def test_creator_bypass_does_not_satisfy_tag_immutability():
    creator = {**creation(), "current_user_can_bypass": "always"}
    assert controls.evaluate_tag_rulesets([creator], verify_bypass_actors=True)[0]
    weakened = {**immutable(), "bypass_actors": creator["bypass_actors"]}
    assert controls.evaluate_tag_rulesets([creator, weakened], verify_bypass_actors=True)[0]
