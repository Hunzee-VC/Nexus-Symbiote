"""Approved input schemas are evaluated in their declared dialect with ECMA-262 patterns."""

from __future__ import annotations

import re

import pytest

import nexus_symbiote.runtime_validation as validation


def outcome(schema, arguments):
    try:
        validation.validate_arguments(schema, arguments)
    except validation.ValidationBudgetError as exc:
        return exc.reason
    return "valid"


def string_schema(pattern):
    return {"type": "object", "properties": {"value": {"type": "string", "pattern": pattern}}}


@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        # Python's $ also matches before a final newline; ECMA-262's does not.
        ("^[a-z0-9.-]+$", "example.org", "valid"),
        ("^[a-z0-9.-]+$", "example.org\n", "arguments-invalid"),
        # \d and \w are ASCII in ECMA-262, Unicode-aware in Python.
        (r"^\d+$", "34", "valid"),
        (r"^\d+$", "٣٤", "arguments-invalid"),
        (r"^\w+$", "café", "arguments-invalid"),
        # "." excludes all ECMA-262 line terminators, including U+2028.
        ("^.+$", "a b", "arguments-invalid"),
        # \s includes NO-BREAK SPACE in ECMA-262, so \S must not match it.
        (r"^\S+$", "a b", "arguments-invalid"),
        (r"^[\d-]+$", "12-34", "valid"),
        (r"^[\d-]+$", "١-2", "arguments-invalid"),
        (r"^(?<year>\d{4})-\k<year>$", "2026-2026", "valid"),
        (r"^(?<year>\d{4})-\k<year>$", "2026-2027", "arguments-invalid"),
    ],
)
def test_patterns_have_ecma_262_meaning(pattern, value, expected):
    assert outcome(string_schema(pattern), {"value": value}) == expected


def test_pattern_properties_and_additional_properties_use_ecma_anchors():
    schema = {
        "type": "object",
        "patternProperties": {"^x$": {"type": "integer"}},
        "additionalProperties": False,
    }
    assert outcome(schema, {"x": 1}) == "valid"
    assert outcome(schema, {"x\n": 1}) == "arguments-invalid"


@pytest.mark.parametrize(
    "pattern",
    ["(?i)abc", "(?P<name>a)", "(?#comment)a", r"\Aabc", r"abc\Z", "[]a]", r"[\S]", "a\\"],
)
def test_pattern_syntax_without_an_ecma_262_meaning_makes_the_schema_invalid(pattern):
    with pytest.raises(re.error):
        validation.ecma_pattern(pattern)
    assert outcome(string_schema(pattern), {"value": "abc"}) == "schema-invalid"


def test_draft_07_schema_is_evaluated_as_draft_07():
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "dependencies": {"delete": ["confirm"]},
    }
    assert outcome(schema, {"delete": True, "confirm": True}) == "valid"
    assert outcome(schema, {"delete": True}) == "arguments-invalid"


@pytest.mark.parametrize("dialect", validation.DIALECTS)
def test_every_supported_dialect_validates(dialect):
    schema = {"$schema": dialect, "type": "object", "required": ["to"]}
    assert outcome(schema, {"to": "team@example.test"}) == "valid"
    assert outcome(schema, {}) == "arguments-invalid"


@pytest.mark.parametrize(
    "declared",
    [
        "http://json-schema.org/draft-03/schema#",
        "https://example.test/custom-dialect",
        "http://json-schema.org/schema#",
        7,
    ],
)
def test_unknown_or_unsupported_dialect_is_refused(declared):
    assert outcome({"$schema": declared, "type": "object"}, {}) == "schema-invalid"
