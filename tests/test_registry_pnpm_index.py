"""A pnpm package the root importer does not list is found through one index of the keys.

Matching every component against every `packages` key cost their product: hours of CPU
for a package.json and a pnpm-lock.yaml that are both well inside the read limits.
"""

from __future__ import annotations

import base64
import json
import re
import time
import tracemalloc
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from nexus_symbiote import policy
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.registry import RegistryScanner

SHA512 = "sha512-" + base64.b64encode(b"p" * 64).decode()
# The names one key can be the record of: a name without "@" or "/", or a scope and a
# name. npm accepts no other; the index selects nothing for them.
CANDIDATE = re.compile(r"[^@/]+|@[^/]*/[^@/]*")


def _reference(name: str, packages: dict[Any, Any]) -> tuple[str, str] | str | None:
    """What the resolver selected before the index, by matching the name to every key."""
    prefix_matches: list[tuple[str, str]] = []
    for k in packages:
        if not isinstance(k, str):
            continue
        clean_k = k.lstrip("/")
        for sep in ("@", "/"):
            if clean_k.startswith(name + sep):
                suffix = clean_k[len(name) + 1 :]
                if suffix and not suffix.startswith("/"):
                    prefix_matches.append((k, suffix))
                    break
    if len({s.split("(", 1)[0] for _, s in prefix_matches}) > 1:
        return "ambiguous"
    return prefix_matches[0] if len(prefix_matches) == 1 else None


def _selected(selections: dict[str, tuple[str, str] | None], name: str) -> Any:
    if name not in selections:
        return None
    return "ambiguous" if selections[name] is None else selections[name]


# Names that are prefixes of one another, scoped and not; "@s" is no npm name.
POOL = ["a", "a.b", "mcp-p1", "mcp-p10", "@s/a", "@s/a-b", "@s"]
SHAPED_KEYS = st.tuples(
    st.sampled_from(["", "", "/", "//"]),
    st.sampled_from(POOL),
    st.sampled_from(["@", "@", "/", "@/", "("]),
    st.sampled_from(
        ["1.0.0", "2.0.0", "1.0.0(p@1)", "1.0.0(@s/p@2)", "2.0.0_p@1.0.0", "/1.0.0", ""]
    ),
).map("".join)
ODD_KEYS = st.one_of(
    st.text(alphabet="@/(_a1.-s", max_size=10),
    st.integers(),
    st.none(),
    st.booleans(),
    st.tuples(st.integers()),
)


@given(
    st.lists(SHAPED_KEYS, max_size=16),
    st.lists(ODD_KEYS, max_size=4),
    st.lists(st.text(alphabet="@/_a1.-s", min_size=1, max_size=6), max_size=4),
)
@example(
    shaped=[
        "mcp-p1@1.0.0",
        "/mcp-p1/2.0.0",
        "mcp-p10@1.0.0(p@1)",
        "/mcp-p10@1.0.0(@s/p@2)",
        "//@s/a/1.0.0",
        "@s/a-b@2.0.0_p@1.0.0",
        "a.b@/1.0.0",
        "a@",
    ],
    odd=[7, None, ("a@1.0.0",), "@s@1.0.0"],
    extra=["mcp-p1@1.0.0", "@s/a/1.0.0"],
)
def test_the_index_selects_what_matching_every_key_selected(shaped, odd, extra):
    packages = dict.fromkeys([*shaped, *odd], {})
    names = [*POOL, *extra]
    selections = RegistryScanner._pnpm_selections(packages, set(names))
    for name in names:
        expected = _reference(name, packages) if CANDIDATE.fullmatch(name) else None
        assert _selected(selections, name) == expected, (name, list(packages))


def test_the_index_answers_only_for_the_names_it_is_asked_about():
    packages = {"mcp-p1@1.0.0": {}, "mcp-p2@1.0.0": {}, 7: {}}
    assert RegistryScanner._pnpm_selections(packages, {"mcp-p1"}) == {
        "mcp-p1": ("mcp-p1@1.0.0", "1.0.0")
    }
    assert RegistryScanner._pnpm_selections(packages, set()) == {}


def _scan(root: Path, dependencies: dict[str, str], lock: str) -> ScanResult:
    (root / "package.json").write_text(json.dumps({"dependencies": dependencies}))
    (root / "pnpm-lock.yaml").write_text(lock)
    return RegistryScanner().scan(root)


def _packages(*keys: str) -> str:
    """A lockfile whose root importer lists nothing, so every package is found by key."""
    records = "".join(f"  '{key}':\n    resolution: {{integrity: {SHA512}}}\n" for key in keys)
    return "lockfileVersion: '9.0'\npackages:\n" + records


@pytest.mark.parametrize(
    ("name", "key", "pointer"),
    [
        ("mcp-p1", "mcp-p1@1.0.0", "mcp-p1@1.0.0"),
        ("mcp-p1", "/mcp-p1@1.0.0(peer@2.0.0)", "~1mcp-p1@1.0.0(peer@2.0.0)"),
        ("mcp-p1", "/mcp-p1/1.0.0", "~1mcp-p1~11.0.0"),
        ("@ai/mcp", "@ai/mcp@1.0.0", "@ai~1mcp@1.0.0"),
        ("@ai/mcp", "/@ai/mcp/1.0.0", "~1@ai~1mcp~11.0.0"),
    ],
)
def test_a_package_the_importer_does_not_list_is_selected_by_its_key(tmp_path, name, key, pointer):
    result = _scan(tmp_path, {name: "^1.0.0"}, _packages(key, "other@1.0.0"))
    assert not result.scan_failures and not result.surfaces_excluded
    (component,) = result.components
    assert component.version == "1.0.0"
    assert component.properties["lockfile_record"] == "pnpm-lock.yaml#/packages/" + pointer
    assert component.claims["package_resolution"].method == "pnpm-lockfile"


def test_a_longer_name_does_not_select_a_shorter_names_records(tmp_path):
    result = _scan(
        tmp_path,
        {"mcp-p1": "^1.0.0", "mcp-p10": "^1.0.0", "@ai/mcp": "^1.0.0"},
        _packages("mcp-p10@1.0.0", "mcp-p100/2.0.0", "@ai/mcp-p1@1.0.0", "@ai/mcpx/1.0.0"),
    )
    assert not result.scan_failures and not result.surfaces_excluded
    versions = {c.name: c.version for c in result.components}
    assert versions == {"mcp-p1": "^1.0.0", "mcp-p10": "1.0.0", "@ai/mcp": "^1.0.0"}


def test_records_of_two_versions_are_ambiguous_and_of_one_version_bind_nothing(tmp_path):
    result = _scan(
        tmp_path,
        {"mcp-p1": "^1.0.0", "mcp-p2": "^1.0.0"},
        _packages(
            "mcp-p1@1.0.0", "/mcp-p1/2.0.0", "mcp-p2@1.0.0(a@1.0.0)", "mcp-p2@1.0.0(a@2.0.0)"
        ),
    )
    assert result.surfaces_excluded == [
        "pnpm-lock.yaml: multiple package resolutions for mcp-p1 are ambiguous"
    ]
    for component in result.components:
        assert component.version == "^1.0.0" and component.package_url is None
        assert "package_resolution" not in component.claims


# Distinct keys become one component name when redaction rewrites the text they differ in.
REDACTED_ALIKE = {"mcp-token=1": "^1.0.0", "mcp-token=2": "^1.0.0"}
SHARED_GAP = "pnpm-lock.yaml: packages whose names redact to mcp-token=*** are unresolved"


@pytest.mark.parametrize(
    "lock",
    [
        _packages("mcp-token=***@1.0.0"),
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      'mcp-token=***':\n"
        "        specifier: ^1.0.0\n"
        "        version: 1.0.0\n"
        "packages:\n"
        f"  'mcp-token=***@1.0.0':\n    resolution: {{integrity: {SHA512}}}\n",
    ],
)
def test_one_record_is_not_bound_to_dependencies_whose_names_redact_alike(tmp_path, lock):
    result = _scan(tmp_path, REDACTED_ALIKE, lock)
    assert [c.name for c in result.components] == ["mcp-token=***"] * 2
    assert result.surfaces_excluded == [SHARED_GAP] * 2
    assert not result.scan_failures
    for component in result.components:
        assert component.version == "^1.0.0" and component.package_url is None
        assert "lockfile_record" not in component.properties
        assert "package_resolution" not in component.claims


def test_records_of_two_versions_stay_ambiguous_for_names_that_redact_alike(tmp_path):
    result = _scan(tmp_path, REDACTED_ALIKE, _packages("mcp-token=***@1.0.0", "mcp-token=***@2"))
    assert (
        result.surfaces_excluded
        == ["pnpm-lock.yaml: multiple package resolutions for mcp-token=*** are ambiguous"] * 2
    )


def test_a_long_record_shared_by_names_that_redact_alike_is_recorded_for_none(tmp_path):
    # Binding the record to each name copied its key into every component: memory grew
    # with their product. An explicit key escapes PyYAML's limit on simple keys.
    peers = "(peer@1.0.0)" * 20_000
    lock = "lockfileVersion: '9.0'\npackages:\n  ? 'mcp-token=***@1.0.0" + peers + "'\n  : {}\n"
    dependencies = {f"mcp-token={index}": "^1.0.0" for index in range(200)}
    result = _scan(tmp_path, dependencies, lock)
    assert set(result.surfaces_excluded) == {SHARED_GAP}
    assert all(len(c.model_dump_json()) < len(peers) for c in result.components)


class _CountingKeys(dict[Any, Any]):
    def __init__(self, items: dict[Any, Any]) -> None:
        super().__init__(items)
        self.visits = 0

    def __iter__(self) -> Iterator[Any]:
        for key in super().__iter__():
            self.visits += 1
            yield key


@pytest.mark.parametrize(
    "dependencies",
    [
        {f"mcp-p{index}": "^1.0.0" for index in range(300)},
        {f"mcp-token={index}": "^1.0.0" for index in range(300)},
    ],
)
def test_each_package_key_is_read_once_however_many_components_there_are(
    tmp_path, monkeypatch, dependencies
):
    parse = policy.parse_yaml_mapping
    seen: dict[str, _CountingKeys] = {}

    def counting(text: str) -> dict[str, Any]:
        document = parse(text)
        document["packages"] = seen["packages"] = _CountingKeys(document["packages"])
        return document

    monkeypatch.setattr(policy, "parse_yaml_mapping", counting)
    keys = [f"q{index}@1.0.0" for index in range(300)] + ["mcp-p7@1.0.0", "mcp-token=***@1"]
    result = _scan(tmp_path, dependencies, _packages(*keys))
    assert len(result.components) == 300
    assert seen["packages"].visits <= len(keys)


def test_one_long_separator_dense_key_is_indexed_in_linear_space():
    key = "mcp-p0" + "@a" * 50_000
    tracemalloc.start()
    try:
        selections = RegistryScanner._pnpm_selections({key: {}, "/" * 50_000: {}}, {"mcp-p0"})
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert selections == {"mcp-p0": (key, key[len("mcp-p0@") :])}
    # Slicing a name at every separator held 50,000 prefixes: over 2 GB.
    assert peak < 4 * len(key)


def test_a_long_separator_dense_explicit_key_is_the_record_of_one_name(tmp_path):
    lock = "lockfileVersion: '9.0'\npackages:\n  ? mcp-p0" + "@a" * 50_000 + "\n  : {}\n"
    result = _scan(tmp_path, {"mcp-p0": "^1.0.0", "mcp-p0@a": "^1.0.0"}, lock)
    assert result.scan_failures == ["pnpm-lock.yaml: selected package lacks an exact version"]
    assert all("package_resolution" not in c.claims for c in result.components)


def _timed_scan(root: Path, dependencies: dict[str, str], keys: list[str]) -> ScanResult:
    lock = "lockfileVersion: '9.0'\npackages:\n" + "".join(f"  '{key}': {{}}\n" for key in keys)
    started = time.process_time()
    result = _scan(root, dependencies, lock)
    assert time.process_time() - started < 20
    return result


# The bound tells the linear index from the product of components and keys, which took
# minutes at this size. Coverage tracing triples the time, so the coverage job runs these
# tests untraced.
@pytest.mark.no_cover
def test_twenty_thousand_components_and_keys_are_resolved_in_linear_time(tmp_path):
    dependencies = {f"mcp-p{index}": "^1.0.0" for index in range(20_000)}
    keys = [f"q{index}@1.0.0" for index in range(20_000)]
    result = _timed_scan(tmp_path, dependencies, keys + ["mcp-p7@1.0.7"])
    assert len(result.components) == 20_000
    assert [c.version for c in result.components if "package_resolution" in c.claims] == ["1.0.7"]


@pytest.mark.no_cover
def test_twenty_thousand_names_that_redact_alike_are_resolved_in_linear_time(tmp_path):
    dependencies = {f"mcp-token={index}": "^1.0.0" for index in range(20_000)}
    keys = [f"mcp-token=***@1.0.{index}" for index in range(20_000)]
    result = _timed_scan(tmp_path, dependencies, keys)
    assert set(result.surfaces_excluded) == {
        "pnpm-lock.yaml: multiple package resolutions for mcp-token=*** are ambiguous"
    }
