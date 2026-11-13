"""The ShadowScan approved-inventory export: the field contract, literal bindings, identity rules.

ShadowScan is not a dependency. Its contract at the checked commit is embedded here: the simple
entry fields ``shadowscan.registry._SIMPLE_FIELDS`` allows, and the glob matcher it applies to
resource patterns, ``fnmatch.fnmatchcase``.
"""

from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
import os
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from nexus_symbiote.core.aibom import MAX_NATIVE_BYTES, NativeFormatError
from nexus_symbiote.core.content_digest import NESTED_TOO_DEEPLY, inventory_content_digest
from nexus_symbiote.graph import INFERRED_AGENT_REF
from nexus_symbiote.inventory_export import (
    LEGACY_IDENTITY,
    MAX_TEXT_CHARS,
    SHADOWSCAN_COMMIT,
    UNDECLARED_IDENTITY,
    InventoryExportError,
    SimpleEntry,
    checked_resource_prefix,
    checked_text,
    literal_resource_pattern,
    read_native_inventory,
    shadowscan_simple_inventory,
)
from tests.support import scaling_ratio

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "shadowscan-inventory"
DECLARED = FIXTURES / "declared-agent.aibom.json"
UNNAMED = FIXTURES / "unnamed-agent.aibom.json"
PREFIX = "github:acme/support-triager"
# Nexus-ShadowScan at this commit (release 0.1.4) is what the export was checked against.
SHADOWSCAN_COMMIT_CHECKED = "999bef1a277cfbcdc44fdbca925e54c07efa278d"
# shadowscan/registry.py at that commit: _SIMPLE_FIELDS = _LIST_FIELDS | {...}. A simple entry
# with any other key fails ShadowScan's inventory validation.
SHADOWSCAN_SIMPLE_FIELDS = frozenset(
    {
        "resources",
        "names",
        "aliases",
        "frameworks",
        "surfaces",
        "providers",
        "accounts",
        "regions",
        "discriminators",
        "tags",
        "id",
        "agent_id",
        "name",
        "owner",
        "owner_team",
        "autonomy_level",
    }
)
# shadowscan/models.py Surface values at that commit.
SHADOWSCAN_SURFACES = frozenset(
    {"code", "identity", "gateway", "lowcode", "saas", "cloud", "endpoint", "network", "runtime"}
)


def _document(path: Path = DECLARED) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def _agent(document: dict[str, Any]) -> dict[str, Any]:
    (agent,) = [c for c in document["components"] if c["component_type"] == "agent"]
    return agent


def _written(tmp_path: Path, document: dict[str, Any], name: str = "bom.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    return path


def _export(path: Path, *, prefix: str = PREFIX, include_unnamed: bool = False) -> Any:
    return shadowscan_simple_inventory(
        read_native_inventory(path), resource_prefix=prefix, include_unnamed=include_unnamed
    )


def _imported_agent(index: int) -> dict[str, Any]:
    return {
        "bom_ref": f"shadowscan:{index:024x}",
        "component_type": "agent",
        "name": f"ShadowScan agent {index:012x}",
        "trust_tier": "unknown",
        "assurance_level": "declared",
        "properties": {"collection_mode": "imported-unverified-report"},
    }


def test_the_checked_shadowscan_commit_is_recorded():
    assert SHADOWSCAN_COMMIT == SHADOWSCAN_COMMIT_CHECKED


def test_the_export_writes_only_fields_shadowscan_allows():
    assert {item.name for item in fields(SimpleEntry)} <= SHADOWSCAN_SIMPLE_FIELDS
    for golden in ("simple-list.json", "simple-list-unnamed.json"):
        document = json.loads((FIXTURES / golden).read_text(encoding="utf-8"))
        assert set(document) == {"agents"}
        for entry in document["agents"]:
            assert set(entry) <= SHADOWSCAN_SIMPLE_FIELDS
            assert "autonomy_level" not in entry
            assert set(entry["surfaces"]) <= SHADOWSCAN_SURFACES
            for value in entry.values():
                assert isinstance(value, str) or (
                    isinstance(value, list) and value and all(isinstance(v, str) for v in value)
                )


def test_a_declared_agent_exports_its_reference_name_and_owner():
    export = _export(DECLARED)
    agent = _agent(_document())
    assert export.declared is True
    assert export.other_agents == 0
    assert export.entry.as_json() == {
        "id": agent["bom_ref"],
        "name": "support-triager",
        "owner": "platform-security",
        "resources": [PREFIX],
        "surfaces": ["code"],
        "discriminators": ["project"],
    }
    assert agent["bom_ref"] == (
        "agent:repository:" + hashlib.sha256(b"acme:support-triager").hexdigest()[:24]
    )


def test_an_inferred_agent_is_refused_without_the_opt_in():
    with pytest.raises(InventoryExportError) as refusal:
        _export(UNNAMED)
    assert str(refusal.value) == UNDECLARED_IDENTITY
    assert "`id`" in UNDECLARED_IDENTITY and "agent.yaml" in UNDECLARED_IDENTITY


def test_an_inferred_agent_exports_under_a_content_digest_id_on_request():
    export = _export(UNNAMED, include_unnamed=True)
    digest = inventory_content_digest(_document(UNNAMED))
    assert _agent(_document(UNNAMED))["bom_ref"] == INFERRED_AGENT_REF
    assert digest == "sha256:59153bc238b0ab3dd8f507f16b2ea44a634a33129eda2a72ed66c2bf604d3f7e"
    assert export.declared is False
    assert export.entry.id == "agent:unnamed:59153bc238b0ab3dd8f507f1"
    assert export.entry.names == (
        f"unnamed repository agent; id from inventory content digest {digest}",
    )
    # The inferred name "repository" is a placeholder, not a declaration: it is not exported.
    assert export.entry.name is None and export.entry.owner is None


def test_the_unnamed_id_follows_the_content_not_the_collection_event(tmp_path):
    document = _document(UNNAMED)
    later = copy.deepcopy(document)
    later["metadata"]["timestamp"] = "2030-01-01T00:00:00Z"
    later["metadata"]["serial_number"] = "urn:uuid:00000000-0000-4000-8000-000000000000"
    changed = copy.deepcopy(document)
    changed["components"][0]["name"] = "renamed"
    ids = [
        _export(_written(tmp_path, value, f"{index}.json"), include_unnamed=True).entry.id
        for index, value in enumerate((document, later, changed))
    ]
    assert ids[0] == ids[1] != ids[2]


def test_a_manifest_without_id_exports_its_declared_name_only_on_request(tmp_path):
    document = _document()
    agent = _agent(document)
    agent["bom_ref"] = INFERRED_AGENT_REF
    path = _written(tmp_path, document)
    with pytest.raises(InventoryExportError, match="not declared"):
        _export(path)
    export = _export(path, include_unnamed=True)
    assert export.declared is False
    assert export.entry.id.startswith("agent:unnamed:")
    assert (export.entry.name, export.entry.owner) == ("support-triager", "platform-security")


def test_a_reference_without_a_manifest_source_is_not_a_declaration(tmp_path):
    document = _document()
    _agent(document)["properties"]["identity_source"] = "repository-path"
    path = _written(tmp_path, document)
    with pytest.raises(InventoryExportError, match="not declared"):
        _export(path)
    # Only agent.yaml declares a name and an owner; the record's own values are not exported.
    export = _export(path, include_unnamed=True)
    assert (export.entry.name, export.entry.owner) == (None, None)
    assert set(export.entry.as_json()) == {"id", "names", "resources", "surfaces", "discriminators"}


def test_a_format_1_0_inventory_never_counts_as_declared(tmp_path):
    # Release 0.1.0 derived the reference of an agent without an id from the checkout path.
    document = _document()
    document["metadata"]["spec_version"] = "1.0.0"
    path = _written(tmp_path, document)
    with pytest.raises(InventoryExportError) as refusal:
        _export(path)
    assert str(refusal.value) == LEGACY_IDENTITY
    export = _export(path, include_unnamed=True)
    assert export.declared is False
    assert export.entry.name == "support-triager"


def test_an_owner_is_omitted_only_when_none_was_declared(tmp_path):
    document = _document()
    del _agent(document)["supplier"]
    export = _export(_written(tmp_path, document))
    assert export.entry.owner is None
    assert "owner" not in export.entry.as_json()


def test_other_agents_are_counted_and_never_exported(tmp_path):
    document = _document()
    document["components"] += [_imported_agent(1), _imported_agent(2)]
    export = _export(_written(tmp_path, document))
    assert export.other_agents == 2
    assert [json.loads(export.text)["agents"][0]["id"]] == [_agent(_document())["bom_ref"]]


def test_an_inventory_without_a_repository_agent_is_refused(tmp_path):
    document = _document()
    document["components"] = [c for c in document["components"] if c["component_type"] != "agent"]
    document["components"].append(_imported_agent(1))
    with pytest.raises(InventoryExportError, match="no repository agent"):
        _export(_written(tmp_path, document))


def test_an_imported_record_is_never_the_repository_agent(tmp_path):
    document = _document()
    _agent(document)["properties"]["collection_mode"] = "imported-unverified-report"
    with pytest.raises(InventoryExportError, match="no repository agent"):
        _export(_written(tmp_path, document))


@pytest.mark.parametrize(
    "suffix",
    ["0", "\n", "‮​forged", "\x1b[31m", " x"],
    ids=repr,
)
def test_only_an_exact_repository_reference_is_the_repository_agent(tmp_path, suffix):
    # The exported id is the reference itself and is not checked as text: only its exact form,
    # 24 lowercase hexadecimal digits after the prefix, keeps the id inert.
    document = _document()
    reference = _agent(document)["bom_ref"]
    text = json.dumps(document).replace(json.dumps(reference), json.dumps(reference + suffix))
    with pytest.raises(InventoryExportError, match="no repository agent"):
        _export(_written(tmp_path, json.loads(text)))


def test_two_repository_agents_are_ambiguous_and_refused(tmp_path):
    document = _document()
    twin = copy.deepcopy(_agent(document))
    twin["bom_ref"] = "agent:repository:" + "0" * 24
    document["components"].append(twin)
    with pytest.raises(InventoryExportError, match="more than one repository agent"):
        _export(_written(tmp_path, document), include_unnamed=True)


@pytest.mark.parametrize(
    ("resource", "pattern"),
    [
        ("github:acme/agent", "github:acme/agent"),
        ("/srv/a*b", "/srv/a[*]b"),
        ("/srv/a?b", "/srv/a[?]b"),
        ("/srv/[x]", "/srv/[[]x]"),
        ("/srv/x]", "/srv/x]"),
        ("/srv/[!a-z]*?", "/srv/[[]!a-z][*][?]"),
        ("C:\\work\\repo", "C:\\work\\repo"),
    ],
)
def test_glob_metacharacters_are_escaped_as_shadowscan_expects(resource, pattern):
    assert literal_resource_pattern(resource) == pattern
    assert fnmatch.fnmatchcase(resource, pattern)


@pytest.mark.parametrize(
    ("resource", "lookalikes"),
    [
        ("/srv/a*b", ["/srv/ab", "/srv/aXYZb", "/srv/a/b"]),
        ("/srv/a?b", ["/srv/aXb", "/srv/a/b"]),
        ("/srv/[xy]", ["/srv/x", "/srv/y"]),
        ("/srv/[!a]", ["/srv/b", "/srv/c"]),
        ("/srv/x]", ["/srv/x", "/srv/x]]"]),
        ("github:acme/agent", ["github:acme/agent/x", "GITHUB:acme/agent", "github:acme/agen"]),
    ],
)
def test_an_escaped_binding_matches_nothing_the_raw_glob_would_add(resource, lookalikes):
    pattern = literal_resource_pattern(resource)
    for other in lookalikes:
        assert not fnmatch.fnmatchcase(other, pattern), other
    if pattern != resource:
        # The unescaped string, used as a pattern, would have approved a lookalike.
        assert any(fnmatch.fnmatchcase(other, resource) for other in lookalikes)


GLOB_TEXT = st.text(alphabet="*?[]!-^a/\\", max_size=12)


@given(GLOB_TEXT, GLOB_TEXT)
def test_a_binding_matches_exactly_its_own_resource(resource, other):
    assert fnmatch.fnmatchcase(other, literal_resource_pattern(resource)) == (other == resource)


def test_escaping_cannot_form_a_citation_marker_shadowscan_rejects():
    pattern = literal_resource_pattern("github:acme/[cite_start]repo[cite: 1]")
    assert "[cite" not in pattern
    assert fnmatch.fnmatchcase("github:acme/[cite_start]repo[cite: 1]", pattern)


@pytest.mark.parametrize(
    "value",
    [
        "a\x00b",
        "a\x1b[31mb",
        "a\x7fb",
        "a\x85b",
        "a\tb",
        "a\nb",
        "a\rb",
        "a\u202eb",
        "a\u2066b",
        "a\u200bb",
        "a\ufeffb",
        "a\u2028b",
        "a\udcffb",
    ],
    ids=repr,
)
def test_control_format_and_unencodable_characters_are_refused(value):
    with pytest.raises(InventoryExportError) as refusal:
        checked_text("agent name", value)
    message = str(refusal.value)
    assert message == (
        "The agent name contains a control, format, line-separator or unencodable character, "
        "which ShadowScan would reject or misread."
    )


@pytest.mark.parametrize("value", [" a", "a ", "\u00a0a", "a\u3000", "   "])
def test_padding_shadowscan_would_strip_is_refused(value):
    with pytest.raises(InventoryExportError, match="starts or ends with white space"):
        checked_text("agent owner", value)


def test_empty_and_overlong_text_is_refused():
    with pytest.raises(InventoryExportError, match="is empty"):
        checked_text("agent owner", "")
    assert checked_text("agent name", "x" * MAX_TEXT_CHARS) == "x" * MAX_TEXT_CHARS
    with pytest.raises(InventoryExportError, match="longer than 4,096 characters"):
        checked_text("agent name", "x" * (MAX_TEXT_CHARS + 1))


@pytest.mark.parametrize(
    "value",
    [
        'Agent "für" \\ Tickets',
        "##[error]x ::error::y",
        "<script>alert(1)</script> [l](https://e.example)",
        "中文 ağent",
        "inner  spaces kept",
    ],
)
def test_ordinary_text_is_exported_unchanged(value):
    assert checked_text("agent name", value) == value


def test_a_prefix_no_shadowscan_finding_can_carry_is_refused():
    assert checked_resource_prefix("github:acme/agent") == "github:acme/agent"
    with pytest.raises(InventoryExportError, match=r"contains \[REDACTED\]"):
        checked_resource_prefix("github:acme/[REDACTED]")
    with pytest.raises(InventoryExportError, match="resource prefix"):
        checked_resource_prefix("github:acme/agent\n")


@pytest.mark.parametrize(
    "prefix",
    ["", "github:acme/agent ", "github:acme/agent\n::error::forged", "github:acme/[REDACTED]"],
    ids=repr,
)
def test_the_library_refuses_a_prefix_without_relying_on_the_command(prefix):
    with pytest.raises(InventoryExportError, match="^The resource prefix "):
        shadowscan_simple_inventory(read_native_inventory(DECLARED), resource_prefix=prefix)


def test_hostile_inventory_text_is_refused_by_field_without_quoting_it(tmp_path):
    document = _document()
    _agent(document)["name"] = "evil\u202egpj.exe"
    with pytest.raises(InventoryExportError) as refusal:
        _export(_written(tmp_path, document))
    assert str(refusal.value).startswith("The agent name contains a control")
    assert "evil" not in str(refusal.value)
    document = _document()
    _agent(document)["supplier"] = "team\n::error::forged"
    with pytest.raises(InventoryExportError) as refusal:
        _export(_written(tmp_path, document))
    assert str(refusal.value).startswith("The agent owner contains a control")


def test_the_digests_come_from_the_bytes_that_were_read(tmp_path):
    raw = DECLARED.read_bytes()
    native = read_native_inventory(DECLARED)
    assert native.file_sha256 == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert native.content_digest == inventory_content_digest(json.loads(raw))
    # The same content in other bytes: another file digest, the same content digest. The file
    # digest covers every byte, white space around the document included, as sha256sum does.
    reformatted = tmp_path / "reformatted.json"
    reformatted.write_bytes(b"\n" + json.dumps(json.loads(raw)).encode() + b"\n")
    other = read_native_inventory(reformatted)
    assert other.file_sha256 == "sha256:" + hashlib.sha256(reformatted.read_bytes()).hexdigest()
    assert other.file_sha256 != native.file_sha256
    assert other.content_digest == native.content_digest


def test_text_is_written_as_utf8_with_only_the_escapes_json_requires(tmp_path):
    document = _document()
    _agent(document)["name"] = 'Agent "für" \\ 中文'
    text = _export(_written(tmp_path, document)).text
    assert '"name": "Agent \\"für\\" \\\\ 中文"' in text
    assert "\\u" not in text


def test_the_export_is_deterministic(tmp_path):
    first, second = _export(DECLARED).text, _export(DECLARED).text
    assert first == second == (FIXTURES / "simple-list.json").read_text(encoding="utf-8")
    assert first.endswith("}\n") and "\t" not in first


def _invalid(tmp_path: Path, kind: str) -> Path:
    path = tmp_path / f"{kind}.json"
    if kind == "symlink":
        path.symlink_to(DECLARED)
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "oversized":
        path.write_bytes(b" " * (MAX_NATIVE_BYTES + 1))
    elif kind == "duplicate-keys":
        path.write_text('{"metadata": {}, "metadata": {}, "components": []}')
    elif kind == "nonfinite":
        path.write_text('{"metadata": {"version": NaN}, "components": []}')
    elif kind == "deep":
        path.write_text("[" * 100_000 + "]" * 100_000)
    elif kind == "not-utf8":
        path.write_bytes(DECLARED.read_text(encoding="utf-8").encode("utf-16"))
    elif kind == "byte-order-mark":
        path.write_bytes(b"\xef\xbb\xbf" + DECLARED.read_bytes())
    elif kind == "schema":
        path.write_text('{"metadata": {}, "components": [{"component_type": "agent"}]}')
    elif kind == "no-components":
        document = _document()
        del document["components"]
        path.write_text(json.dumps(document))
    return path


@pytest.mark.parametrize(
    ("kind", "reason"),
    [
        ("symlink", "symbolic link"),
        ("fifo", "not a regular file"),
        ("oversized", "16 MiB"),
        ("duplicate-keys", "duplicate keys"),
        ("nonfinite", "nonfinite numbers"),
        ("deep", "strict UTF-8 JSON"),
        ("not-utf8", "strict UTF-8 JSON"),
        ("byte-order-mark", "strict UTF-8 JSON"),
        ("schema", "native AgentBOM schema"),
        ("no-components", "no content digest"),
    ],
)
def test_an_unreadable_or_invalid_inventory_is_refused(tmp_path, kind, reason):
    with pytest.raises(NativeFormatError) as refusal:
        read_native_inventory(_invalid(tmp_path, kind))
    assert reason in str(refusal.value)


def test_an_oversized_inventory_is_read_only_up_to_the_limit(monkeypatch):
    # An unbounded read would take all of a much larger file into memory before refusing it.
    delivered: list[int] = []

    class FourTimesTheLimit:
        remaining = 4 * MAX_NATIVE_BYTES

        def __enter__(self) -> FourTimesTheLimit:
            return self

        def __exit__(self, *exc_info: object) -> None:
            return None

        def read(self, size: int = -1) -> bytes:
            count = self.remaining if size < 0 else min(size, self.remaining)
            self.remaining -= count
            delivered.append(count)
            return b" " * count

    monkeypatch.setattr(
        "nexus_symbiote.core.hashing.open_regular_file", lambda _path: FourTimesTheLimit()
    )
    with pytest.raises(NativeFormatError, match="exceeds the 16 MiB"):
        read_native_inventory(DECLARED)
    assert sum(delivered) == MAX_NATIVE_BYTES + 1


def test_an_unsupported_format_version_is_named(tmp_path):
    document = _document()
    document["metadata"]["spec_version"] = "2.0.0"
    with pytest.raises(NativeFormatError, match=r"version 2\.0\.0 is not supported"):
        read_native_inventory(_written(tmp_path, document))


def _nested(tmp_path: Path, depth: int) -> Path:
    document = _document()
    _agent(document)["properties"]["deep"] = "@DEEP@"
    path = tmp_path / f"deep-{depth}.json"
    path.write_text(json.dumps(document).replace('"@DEEP@"', "[" * depth + "]" * depth))
    return path


def test_nesting_at_the_depth_limit_is_refused_never_raised(tmp_path):
    # The strict parse refuses at the boundary: it canonicalizes at the same depth as the
    # content digest. Bisection probes the depth where acceptance ends, where a digest one
    # call deeper once escaped as a bare RecursionError.
    def refusal(depth: int) -> str | None:
        try:
            read_native_inventory(_nested(tmp_path, depth))
        except NativeFormatError as exc:
            return str(exc)
        return None

    accepted, refused = 1, 100_000
    assert refusal(accepted) is None
    while refused - accepted > 1:
        middle = (accepted + refused) // 2
        accepted, refused = (middle, refused) if refusal(middle) is None else (accepted, middle)
    message = "It is not strict UTF-8 JSON; duplicate keys and nonfinite numbers are refused."
    assert refusal(refused) == refusal(refused + 1) == message


def test_a_digest_too_deep_for_the_stack_is_refused_as_the_parse_refuses_it(tmp_path, monkeypatch):
    # Which of the parse and the digest reaches the stack limit first depends on the depth
    # of the caller's stack, so the bisection above may never reach the digest's refusal.
    def too_deep(document: Any) -> str:
        raise ValueError(NESTED_TOO_DEEPLY)

    monkeypatch.setattr("nexus_symbiote.inventory_export.inventory_content_digest", too_deep)
    with pytest.raises(NativeFormatError) as refused:
        read_native_inventory(_written(tmp_path, _document()))
    assert str(refused.value) == (
        "It is not strict UTF-8 JSON; duplicate keys and nonfinite numbers are refused."
    )
    assert refused.value.__cause__ is not None
    assert refused.value.__cause__.args == (NESTED_TOO_DEEPLY,)


def test_export_time_is_linear_in_the_number_of_agents(tmp_path):
    paths = {}
    for scale in (1, 4):
        document = _document()
        document["components"] += [_imported_agent(i) for i in range(400 * scale)]
        paths[scale] = _written(tmp_path, document, f"scale-{scale}.json")
    # Four times the agents: about four times the work if linear, sixteen if quadratic.
    assert scaling_ratio(lambda scale: _export(paths[scale])) < 10
    assert _export(paths[4]).other_agents == 1600
