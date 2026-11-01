"""Tests for JCS hashing and version extraction edge cases."""

from __future__ import annotations

from nexus_symbiote.core.hashing import (
    canonical_json,
    extract_version_pin,
    hash_bytes,
    hash_canonical,
    hash_file,
    hash_tool_definition,
)


class TestCanonicalJsonEdgeCases:
    def test_deeply_nested(self):
        obj = {"a": {"b": {"c": {"d": [1, 2, 3]}}}}
        result = canonical_json(obj)
        assert '"a"' in result
        assert '"d":[1,2,3]' in result

    def test_empty_object(self):
        assert canonical_json({}) == "{}"

    def test_empty_array_in_value(self):
        result = canonical_json({"arr": []})
        assert '"arr":[]' in result

    def test_boolean_values(self):
        result = canonical_json({"flag": True, "other": False})
        assert "true" in result
        assert "false" in result

    def test_integer_vs_float(self):
        int_result = canonical_json({"n": 42})
        float_result = canonical_json({"n": 42.0})
        assert '"n":42' in int_result
        assert '"n":4.2e1' in float_result or '"n":42' in float_result

    def test_unicode_strings(self):
        result = canonical_json({"emoji": "☃", "cjk": "世界"})
        assert result  # should not raise

    def test_ecmascript_number_and_utf16_sort(self):
        assert canonical_json({"v": 1e-6}) == '{"v":0.000001}'
        assert canonical_json({"\ue000": 0, "😀": 1}) == '{"😀":1,"\ue000":0}'

    def test_null_value_preserved(self):
        result = canonical_json({"key": None, "other": 1})
        assert '"key":null' in result
        assert '"other":1' in result

    def test_mixed_array_in_value(self):
        result = canonical_json({"arr": [1, "two", True, {"nested": 3}]})
        assert '"arr":[' in result

    def test_key_ordering(self):
        result = canonical_json({"z": 1, "a": 2, "m": 3})
        z_pos = result.index('"z"')
        a_pos = result.index('"a"')
        m_pos = result.index('"m"')
        assert a_pos < m_pos < z_pos


class TestHashToolDefinition:
    def test_minimal_tool(self):
        h = hash_tool_definition("test_tool", "A test tool", {})
        assert h.startswith("sha256:")
        assert len(h) == 71  # sha256: + 64 hex chars

    def test_complex_schema(self):
        schema = {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            "required": ["query"],
        }
        h = hash_tool_definition("search", "Search for items", schema)
        assert h.startswith("sha256:")

    def test_deterministic(self):
        h1 = hash_tool_definition("t", "d", {"a": 1})
        h2 = hash_tool_definition("t", "d", {"a": 1})
        assert h1 == h2

    def test_different_names_different_hashes(self):
        h1 = hash_tool_definition("tool_a", "desc", {})
        h2 = hash_tool_definition("tool_b", "desc", {})
        assert h1 != h2


class TestHashFile:
    def test_text_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        h = hash_file(f)
        assert h is not None
        assert h.startswith("sha256:")

    def test_binary_file(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(bytes(range(256)))
        h = hash_file(f)
        assert h is not None

    def test_missing_file(self, tmp_path):
        result = hash_file(tmp_path / "nope")
        assert result is None

    def test_deterministic(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"data")
        assert hash_file(f) == hash_file(f)


class TestHashBytes:
    def test_basic(self):
        h = hash_bytes(b"hello")
        assert h.startswith("sha256:")
        assert len(h) == 71

    def test_deterministic(self):
        assert hash_bytes(b"data") == hash_bytes(b"data")

    def test_different_input_different_hash(self):
        assert hash_bytes(b"a") != hash_bytes(b"b")

    def test_empty_bytes(self):
        h = hash_bytes(b"")
        assert h.startswith("sha256:")


class TestHashCanonical:
    def test_basic(self):
        h = hash_canonical({"key": "value"})
        assert h.startswith("sha256:")

    def test_key_order_insensitive(self):
        h1 = hash_canonical({"b": 2, "a": 1})
        h2 = hash_canonical({"a": 1, "b": 2})
        assert h1 == h2


class TestExtractVersionPin:
    def test_bare_version_is_not_a_pin(self):
        assert extract_version_pin("1.2.3") is None

    def test_npm_caret_not_pinned(self):
        v = extract_version_pin("^1.2.3")
        assert v is None

    def test_npm_tilde_not_pinned(self):
        v = extract_version_pin("~1.2.3")
        assert v is None

    def test_at_version(self):
        v = extract_version_pin("pkg@4.40.0")
        assert v == "4.40.0"

    def test_at_version_with_v_prefix(self):
        assert extract_version_pin("pkg@v1.2.3") == "1.2.3"

    def test_colon_tag_is_not_a_pin(self):
        assert extract_version_pin("image:2.5.0") is None

    def test_scoped_package_version(self):
        v = extract_version_pin("@modelcontextprotocol/server-filesystem@1.2.3")
        assert v == "1.2.3"

    def test_no_version(self):
        v = extract_version_pin("latest")
        assert v is None

    def test_at_latest_is_not_a_pin(self):
        assert extract_version_pin("pkg@latest") is None

    def test_npm_range_after_at_is_not_a_pin(self):
        assert extract_version_pin("pkg@^1.2.3") is None

    def test_prerelease_after_at(self):
        assert extract_version_pin("pkg@1.0.0-beta.1") == "1.0.0-beta.1"

    def test_pep508_exact(self):
        assert extract_version_pin("requests==2.31.0") == "2.31.0"

    def test_pep508_exact_with_extra_and_marker(self):
        assert extract_version_pin("requests[socks]==2.31.0; python_version > '3'") == "2.31.0"

    def test_pep508_range_is_not_a_pin(self):
        assert extract_version_pin("requests>=2.31.0") is None

    def test_docker_digest(self):
        digest = "sha256:" + "a" * 64
        assert extract_version_pin(f"registry.example/img@{digest}") == digest

    def test_url_is_not_a_pin(self):
        assert extract_version_pin("https://example.com/pkg@1.2.3") is None

    def test_wildcard_is_not_a_pin(self):
        assert extract_version_pin("*") is None
