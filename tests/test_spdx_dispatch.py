"""Fast dispatch must accept exactly the unmodified official schema's documents."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from nexus_symbiote.generators import _spdx_dispatch as dispatch
from nexus_symbiote.generators.validation import _schema


def _digest(schema):
    return hashlib.sha256(
        json.dumps(schema, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _small_schema():
    return {
        "$defs": {
            "Common": {"type": "object", "required": ["type"]},
            "A": {
                "allOf": [
                    {"$ref": "#/$defs/Common"},
                    {
                        "properties": {
                            "type": {"oneOf": [{"const": "A"}]},
                            "payload": {"type": "integer"},
                        },
                        "required": ["payload"],
                    },
                ]
            },
            "B": {
                "allOf": [
                    {"$ref": "#/$defs/Common"},
                    {
                        "properties": {"type": {"enum": ["B"]}, "name": {"type": "string"}},
                        "required": ["name"],
                    },
                ]
            },
            "AnyClass": {"anyOf": [{"$ref": "#/$defs/A"}, {"$ref": "#/$defs/B"}]},
        },
        "$ref": "#/$defs/AnyClass",
        "unevaluatedProperties": False,
    }


def _compile_for_proof(schema, monkeypatch):
    # Production is pinned to the official resource. Test-only pin injection
    # exercises the structural proof and its conservative fallback independently.
    monkeypatch.setattr(dispatch, "_PINNED_SCHEMA_DIGEST", _digest(schema))
    return dispatch.dispatched_spdx_schema(schema)


def _accepts(schema, value):
    return Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(value)


def test_pinned_schema_dispatch_preserves_every_exact_branch_and_source():
    official = _schema("spdx/spdx-json-schema-3.0.1.json")
    before = deepcopy(official)
    compiled = dispatch.dispatched_spdx_schema(official)
    assert compiled is not official
    assert official == before
    assert len(official["$defs"]["AnyClass"]["anyOf"]) == 78
    assert compiled["$defs"]["AnyClass"]["else"] == official["$defs"]["AnyClass"]

    def leaves(node):
        if "$ref" in node:
            return [node]
        return leaves(node["then"]) + leaves(node["else"])

    assert leaves(compiled["$defs"]["AnyClass"]["then"]) == official["$defs"]["AnyClass"]["anyOf"]
    assert compiled["$defs"].keys() == official["$defs"].keys()
    split = 0
    for name, definition in official["$defs"].items():
        if name == "AnyClass":
            continue
        if not name.endswith("_derived"):
            assert compiled["$defs"][name] == definition
            continue
        # Reference unions keep their exact alternatives, split by instance type.
        rest = definition["anyOf"][1:]
        assert compiled["$defs"][name] == {
            "if": {"type": "object"},
            "then": definition,
            "else": {"anyOf": rest} if rest else False,
        }
        split += 1
    assert split == 90
    assert {k: v for k, v in compiled.items() if k != "$defs"} == {
        k: v for k, v in official.items() if k != "$defs"
    }


@pytest.mark.parametrize(
    "value",
    [
        {"type": "A", "payload": 1},
        {"type": "B", "name": "n"},
        {"type": "A", "payload": "wrong"},
        {"type": "B", "name": False},
        {"type": "A"},
        {"type": "B"},
        {"payload": 1},
        {},
        {"type": "Unknown", "payload": 1},
        {"type": ["A"], "payload": 1},
        {"type": 0, "payload": 1},
        {"type": {}, "payload": 1},
        {"type": "A", "payload": 1, "name": "not-evaluated"},
        {"type": "B", "name": "n", "payload": 1},
        None,
        [],
        "A",
        0,
    ],
)
def test_conjunctive_reference_proof_and_evaluated_keys_are_equivalent(monkeypatch, value):
    schema = _small_schema()
    compiled = _compile_for_proof(schema, monkeypatch)
    assert compiled is not schema
    assert _accepts(compiled, value) == _accepts(schema, value)


@pytest.mark.parametrize(
    "change",
    [
        "unconstrained",
        "optional-type",
        "conditional-type",
        "duplicate-tag",
        "conflicting-tag",
        "cycle",
        "scoped",
        "anchor",
        "dynamic-ref",
        "union-sibling",
        "union-interior-ref",
        "encoded-interior-ref",
    ],
)
def test_unsupported_proofs_fall_back_to_exact_official_behavior(monkeypatch, change):
    schema = _small_schema()
    if change == "unconstrained":
        schema["$defs"]["AnyClass"]["anyOf"].append({})
    elif change == "optional-type":
        schema["$defs"]["Common"].pop("required")
    elif change == "conditional-type":
        schema["$defs"]["B"]["allOf"][1]["properties"]["type"] = {
            "if": True,
            "then": {"const": "B"},
        }
    elif change == "duplicate-tag":
        schema["$defs"]["B"]["allOf"][1]["properties"]["type"] = {"const": "A"}
    elif change == "conflicting-tag":
        schema["$defs"]["B"]["allOf"].append({"properties": {"type": {"const": "A"}}})
    elif change == "cycle":
        schema["$defs"]["Common"]["$ref"] = "#/$defs/Common"
    elif change == "scoped":
        schema["$defs"]["A"]["$id"] = "https://example.invalid/scoped"
    elif change == "anchor":
        schema["$defs"]["A"]["$anchor"] = "changed"
    elif change == "dynamic-ref":
        schema["$defs"]["Common"]["$dynamicRef"] = "#anchor"
    elif change == "union-sibling":
        schema["$defs"]["AnyClass"].update({"if": True, "then": False})
    elif change in {"union-interior-ref", "encoded-interior-ref"}:
        target = "AnyClass" if change == "union-interior-ref" else "%41nyClass"
        schema["allOf"] = [{"$ref": f"#/$defs/{target}/anyOf/0"}]
    assert _compile_for_proof(schema, monkeypatch) is schema


def test_vendor_change_is_not_optimized_without_a_reviewed_pin():
    schema = _schema("spdx/spdx-json-schema-3.0.1.json")
    schema["$comment"] += " changed resource"
    assert dispatch.dispatched_spdx_schema(schema) is schema


def test_official_schema_type_and_property_adversaries_are_equivalent():
    official = _schema("spdx/spdx-json-schema-3.0.1.json")
    compiled = dispatch.dispatched_spdx_schema(official)
    context = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
    original = Draft202012Validator(official, format_checker=FormatChecker())
    fast = Draft202012Validator(compiled, format_checker=FormatChecker())
    nodes = [
        {
            "type": "extension_CdxPropertyEntry",
            "extension_cdxPropName": "n",
            "extension_cdxPropValue": "v",
        },
        {
            "type": "extension_CdxPropertyEntry",
            "extension_cdxPropName": 3,
            "extension_cdxPropValue": "v",
        },
        {"type": "Hash", "algorithm": "sha256", "hashValue": "ab" * 32},
        {"type": "Hash", "algorithm": "bogus", "hashValue": "bad"},
        {"type": "Tool", "spdxId": "urn:tool:1", "creationInfo": "_:creation"},
        {"type": "Tool", "spdxId": "not-an-iri", "creationInfo": "_:creation"},
        {"type": "Tool", "spdxId": "urn:tool:1"},
        {"type": "Tool", "spdxId": "urn:tool:1", "creationInfo": "_:creation", "unexpected": True},
        {
            "type": "Tool",
            "spdxId": "urn:tool:1",
            "creationInfo": {"type": "CreationInfo", "created": "not-a-time"},
        },
        {"type": "SpdxDocument", "spdxId": "urn:doc:1", "creationInfo": "_:creation", "element": 3},
        {},
        {"type": "Unknown"},
        {"type": None},
        {"type": ["Tool"]},
        None,
        "Tool",
        0,
    ]
    documents = [{"@context": context, "@graph": [node]} for node in nodes]
    documents += [
        None,
        [],
        {},
        {"@context": context},
        {"@context": "wrong", "@graph": []},
        {"@context": context, "@graph": False},
    ]
    for document in documents:
        assert fast.is_valid(document) == original.is_valid(document), document
    # Every official class participates in dispatch, including classes not
    # generated by Nexus. Minimal objects can be invalid, but acceptance agrees.
    for branch in official["$defs"]["AnyClass"]["anyOf"]:
        tag = dispatch._tag(official, branch)
        document = {"@context": context, "@graph": [{"type": tag}]}
        assert fast.is_valid(document) == original.is_valid(document), tag


def _reference_schema():
    schema = _small_schema()
    schema["$defs"]["Ref_derived"] = {
        "anyOf": [
            {
                "type": "object",
                "unevaluatedProperties": False,
                "anyOf": [{"$ref": "#/$defs/A"}, {"$ref": "#/$defs/B"}],
            },
            {"const": "Named"},
            {"type": "string", "pattern": "^urn:"},
        ]
    }
    schema["$defs"]["B"]["allOf"][1]["properties"]["link"] = {"$ref": "#/$defs/Ref_derived"}
    return schema


@pytest.mark.parametrize(
    "link",
    [
        "Named",
        "urn:x",
        "other",
        3,
        None,
        [],
        True,
        {"type": "A", "payload": 1},
        {"type": "A", "payload": "bad"},
        {"type": "A", "payload": 1, "extra": 1},
        {"type": "B", "name": "n"},
        {},
    ],
)
def test_reference_union_type_split_is_equivalent(monkeypatch, link):
    schema = _reference_schema()
    compiled = _compile_for_proof(schema, monkeypatch)
    assert compiled["$defs"]["Ref_derived"]["if"] == {"type": "object"}
    value = {"type": "B", "name": "n", "link": link}
    assert _accepts(compiled, value) == _accepts(schema, value)


@pytest.mark.parametrize("change", ["first-not-object", "extra-keyword", "sibling", "interior-ref"])
def test_unsupported_reference_unions_keep_the_official_union(monkeypatch, change):
    schema = _reference_schema()
    union = schema["$defs"]["Ref_derived"]
    if change == "first-not-object":
        union["anyOf"][0]["type"] = ["object", "string"]
    elif change == "extra-keyword":
        union["anyOf"][0]["required"] = ["type"]
    elif change == "sibling":
        union["not"] = {"const": "Named"}
    else:
        schema["allOf"] = [{"$ref": "#/$defs/Ref_derived/anyOf/1"}]
    compiled = _compile_for_proof(schema, monkeypatch)
    if change == "interior-ref":
        assert compiled is schema
    else:
        assert compiled["$defs"]["Ref_derived"] == union


@pytest.mark.parametrize(
    "reference",
    [
        "urn:x",
        "_:blank",
        "NoneElement",
        "SpdxOrganization",
        "expandedlicensing_NoAssertionLicense",
        "no-colon",
        3,
        None,
        [],
        {"type": "Tool", "spdxId": "urn:t", "creationInfo": "_:creation"},
        {"type": "Tool", "spdxId": "urn:t", "creationInfo": "_:creation", "extra": 1},
        {"type": "Hash", "algorithm": "sha256", "hashValue": "ab" * 32},
        {"type": "Tool"},
        {},
    ],
)
def test_official_reference_values_are_equivalent(reference):
    official = _schema("spdx/spdx-json-schema-3.0.1.json")
    original = Draft202012Validator(official, format_checker=FormatChecker())
    fast = Draft202012Validator(
        dispatch.dispatched_spdx_schema(official), format_checker=FormatChecker()
    )
    context = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
    nodes = [
        {"type": "SpdxDocument", "spdxId": "urn:d", "creationInfo": "_:c", "element": [reference]},
        {
            "type": "Relationship",
            "spdxId": "urn:r",
            "creationInfo": "_:c",
            "relationshipType": "other",
            "from": reference,
            "to": [reference],
        },
        {
            "type": "software_Package",
            "spdxId": "urn:p",
            "creationInfo": "_:c",
            "suppliedBy": reference,
        },
    ]
    for node in nodes:
        document = {"@context": context, "@graph": [node]}
        assert fast.is_valid(document) == original.is_valid(document), node
