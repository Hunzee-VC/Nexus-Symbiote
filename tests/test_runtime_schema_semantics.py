"""Approved input schemas are evaluated in their declared dialect with ECMA-262 patterns."""

from __future__ import annotations

import os
import re
import subprocess
import sys

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
        # A hyphen next to a class escape is a literal when it cannot form a range.
        (r"^[\w-]+$", "a-b_c", "valid"),
        (r"^[-\w]+$", "-a", "valid"),
        (r"^[\w.-]+$", "a.b-c", "valid"),
        (r"^[a-z-\d]+$", "a-1", "valid"),
        (r"^[a-z-\d]+$", "A", "arguments-invalid"),
        # Class complements: [\s\S] is any character, [^\S] whitespace only.
        (r"^[\s\S]+$", "a\nb\u2028", "valid"),
        (r"^[^\S]+$", " \t\ufeff", "valid"),
        (r"^[^\S]+$", "a", "arguments-invalid"),
        (r"^[\S^]+$", "^a", "valid"),
        (r"^[\S^]+$", " ", "arguments-invalid"),
        (r"^[^a\S]+$", " ", "valid"),
        (r"^[^a\S]+$", "a", "arguments-invalid"),
        # An octal escape keeps its own meaning next to a \d expansion.
        (r"^[\0\d]+$", "\x0009", "valid"),
        (r"^[\0\d]+$", "-", "arguments-invalid"),
        (r"^[\12\d]$", "\n", "valid"),
        (r"^[\12\d]$", ".", "arguments-invalid"),
        # Python's \B never matches an empty string; ECMA-262's does.
        (r"^\B$", "", "valid"),
        ("^a{2}$", "aa", "valid"),
        ("^a{2}$", "aaa", "arguments-invalid"),
        # A brace that cannot be a quantifier is a literal in both engines.
        ("^a{1$", "a{1", "valid"),
        # With the u flag, an escaped surrogate pair is one code point.
        (r"^\uD83D\uDE00+$", "\U0001f600\U0001f600", "valid"),
        (r"^[\uD83D\uDE00-\uD83D\uDE4F]$", "\U0001f64f", "valid"),
        (r"^[\uD83D\uDE00-\uD83D\uDE4F]$", "\ue000", "arguments-invalid"),
        # Annex B syntax keeps its meaning while a pattern names only BMP characters.
        (r"^\-?\d+$", "-12", "valid"),
        (r"^\-?\d+$", "12-", "arguments-invalid"),
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
    [
        "(?i)abc",
        "(?P<name>a)",
        "(?#comment)a",
        r"\Aabc",
        r"abc\Z",
        "[]a]",
        "a\\",
        # Python reads these as possessive quantifiers; ECMA-262 rejects them.
        "^a*+$",
        "^a++$",
        "^a?+$",
        "^a{2}+$",
        # Python reads these as {0,2} and {0,}; ECMA-262 reads literal braces or rejects them.
        "^a{,2}$",
        "^a{,}$",
        # Quantified assertions, and escapes without a meaning in a class.
        "^(?=a)*a$",
        "(?<=a)+b",
        r"\b+",
        r"[\B]",
        r"^\x4$",
        r"^\u{41}$",
        r"^[\400]$",
        # Annex B syntax counts UTF-16 code units, so it is refused next to characters
        # outside the BMP.
        r"[\7-\uD83D\uDE4F]",
        r"^\-[\uD83D\uDE00-\uD83D\uDE4F]$",
        "^]\U0001f600$",
        "^\U0001f600{$",
        r"^\01\uD83D\uDE00$",
    ],
)
def test_pattern_syntax_without_an_ecma_262_meaning_makes_the_schema_invalid(pattern):
    with pytest.raises(re.error):
        validation.ecma_pattern(pattern)
    assert outcome(string_schema(pattern), {"value": "abc"}) == "schema-invalid"


@pytest.mark.parametrize(
    ("pattern", "outside"),
    [
        (r"^[%-\w]+$", "<script>"),
        (r"^[\w-z]+$", "a`b"),
        (r"^[.-\w]+$", ":;<=>?@"),
        (r"^[+-\d]+$", ",./"),
        (r"^[^\w-z]+$", "-"),
        (r"^[--\w]+$", "."),
        (r"^[\x00-\s]+$", "\x01"),
    ],
)
def test_class_escape_as_a_range_bound_makes_the_schema_invalid(pattern, outside):
    # Python would read the expansion of \w, \d or \s as a wider range and admit
    # characters the class excludes. ECMA-262 with the u flag rejects the pattern.
    with pytest.raises(re.error, match="range"):
        validation.ecma_pattern(pattern)
    assert outcome(string_schema(pattern), {"value": outside}) == "schema-invalid"


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


DRAFT_04 = "http://json-schema.org/draft-04/schema#"
DRAFT_07 = "http://json-schema.org/draft-07/schema#"


@pytest.mark.parametrize(
    "schema",
    [
        # Draft-04 to draft-07 ignore the siblings of "$ref".
        {
            "$schema": DRAFT_07,
            "definitions": {"id": {"type": "string"}},
            "properties": {"v": {"$ref": "#/definitions/id", "maxLength": 3}},
        },
        # Keywords that the declared draft does not define are not applied.
        {"$schema": DRAFT_04, "properties": {"v": {"const": "read"}}},
        {"$schema": DRAFT_07, "properties": {"v": {"dependentRequired": {"a": ["b"]}}}},
        {"properties": {"v": {}}, "dependencies": {"v": ["confirm"]}},
        {"properties": {"v": {"type": "array", "additionalItems": False}}},
        # A reference target outside the usual keywords is checked too.
        {
            "$schema": DRAFT_04,
            "properties": {"v": {"$ref": "#/x-shared/read"}},
            "x-shared": {"read": {"const": "read"}},
        },
    ],
)
def test_constraint_the_declared_dialect_ignores_makes_the_schema_invalid(schema):
    # An approver reads these constraints, but the declared dialect would not enforce
    # them, so the call is denied instead of admitted without them.
    assert outcome({"type": "object", **schema}, {"v": "toolong"}) == "schema-invalid"


def test_annotations_next_to_ref_and_root_references_stay_valid():
    schema = {
        "$schema": DRAFT_07,
        "$ref": "#/definitions/mail",
        "definitions": {
            "mail": {
                "type": "object",
                "properties": {
                    "to": {"$ref": "#/definitions/address", "description": "Recipient"},
                    "at": {"$ref": "#/definitions/address", "format": "email"},
                },
                "required": ["to"],
            },
            "address": {"type": "string", "maxLength": 20},
        },
    }
    assert outcome(schema, {"to": "team@example.test"}) == "valid"
    assert outcome(schema, {"to": "x" * 21}) == "arguments-invalid"
    assert outcome(schema, {}) == "arguments-invalid"


def test_siblings_of_ref_apply_from_2019_09():
    schema = {
        "type": "object",
        "$defs": {"id": {"type": "string"}},
        "properties": {"v": {"$ref": "#/$defs/id", "maxLength": 3}},
    }
    assert outcome(schema, {"v": "abc"}) == "valid"
    assert outcome(schema, {"v": "toolong"}) == "arguments-invalid"


def test_ecma_self_check_detects_python_regex_semantics():
    # The worker installs the translation on private jsonschema modules. If one of
    # them evaluated patterns with Python's re again, the self-check must notice.
    probe = (
        "import re, jsonschema._keywords, jsonschema._utils\n"
        "from nexus_symbiote import runtime_validation as v\n"
        "dialects = v._load_dialects()\n"
        "results = [v._ecma_semantics_hold(dialects)]\n"
        "for module in (jsonschema._keywords, jsonschema._utils):\n"
        "    patched, module.re = module.re, re\n"
        "    results.append(v._ecma_semantics_hold(dialects))\n"
        "    module.re = patched\n"
        "print(results)\n"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", probe],
        capture_output=True,
        text=True,
        env={"PATH": os.defpath},
        timeout=60,
        check=True,
    )
    assert result.stdout.strip() == "[True, False, False]"


def test_worker_whose_self_check_fails_does_not_start(monkeypatch):
    script = (
        "import re, jsonschema._keywords\n"
        "from nexus_symbiote import runtime_validation as v\n"
        "load = v._load_dialects\n"
        "def python_semantics():\n"
        "    dialects = load()\n"
        "    jsonschema._keywords.re = re\n"
        "    return dialects\n"
        "v._load_dialects = python_semantics\n"
        "raise SystemExit(v._worker())\n"
    )
    monkeypatch.setattr(validation, "_WORKER_COMMAND", (sys.executable, "-I", "-c", script))
    with pytest.raises(validation.ValidationBudgetError) as denied:
        validation.validate_arguments(string_schema("^a$"), {"value": "a\n"})
    assert denied.value.reason == "validation-unavailable"
