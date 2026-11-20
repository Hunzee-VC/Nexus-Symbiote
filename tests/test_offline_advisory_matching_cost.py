"""Offline advisory matching: indexed cost, the advisory-matches budget, and equivalence.

The indexed matcher must report exactly what pairwise matching reported: the same matches,
and the same error for every block it cannot decide. The reference below is the pairwise
matcher this module replaced, as of fd259a7f (which made it fail closed), kept word for word
apart from its names as the oracle.
"""

from __future__ import annotations

import json
import random
from collections import Counter
from dataclasses import replace
from typing import Any

import pytest
from click.testing import CliRunner
from packaging.version import InvalidVersion, Version

import nexus_symbiote.offline_advisories as offline
from nexus_symbiote import limits
from nexus_symbiote.advisories import package_identity
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import RegistryEntryComponent
from tests.support import scaling_ratio

_SUPPORTED_RANGE_TYPES = frozenset({"ECOSYSTEM", "SEMVER"})


def _reference_compare(ecosystem: str, left: str, right: str) -> int | None:
    if ecosystem == "PyPI":
        try:
            lv, rv = Version(left), Version(right)
        except InvalidVersion:
            return None
        return -1 if lv < rv else (1 if lv > rv else 0)
    if ecosystem == "npm":
        lk, rk = offline._semver_key(left), offline._semver_key(right)
        if lk is None or rk is None:
            return None
        return -1 if lk < rk else (1 if lk > rk else 0)
    return None


def _reference_range_matches(
    ecosystem: str, version: str, rng: dict[str, Any]
) -> tuple[bool, list[str]]:
    """Evaluate one OSV range by version intervals (order-independent per OSV spec)."""
    raw_type = rng.get("type")
    if raw_type is not None and (
        not isinstance(raw_type, str) or raw_type.upper() not in _SUPPORTED_RANGE_TYPES
    ):
        return False, []
    events = rng.get("events")
    if not isinstance(events, list):
        raise ValueError("OSV range events are not a list")

    def cmp(left: str, right: str) -> int:
        if (result := _reference_compare(ecosystem, left, right)) is None:
            raise ValueError("OSV range version cannot be compared")
        return result

    has_zero_intro = False
    found: dict[str, list[str]] = {"introduced": [], "fixed": [], "last_affected": [], "limit": []}
    for ev in events:
        kind, raw = next(iter(ev.items())) if isinstance(ev, dict) and len(ev) == 1 else ("", "")
        if kind == "introduced" and raw in ("0", 0) and not isinstance(raw, bool):
            has_zero_intro = True
        elif kind in found and isinstance(raw, str) and raw.strip():
            found[kind].append(raw.strip())
        else:
            raise ValueError("OSV range event cannot be parsed")
    intros, fixed_versions, last_affected, limits = found.values()

    if any(lim != "*" and cmp(version, lim) >= 0 for lim in limits):
        return False, []

    best_intro: str | None = None
    found_intro = has_zero_intro
    for intro in intros:
        if cmp(intro, version) > 0:
            continue
        found_intro = True
        if best_intro is None or cmp(intro, best_intro) > 0:
            best_intro = intro
    if not found_intro:
        return False, []

    for fix in fixed_versions:
        if cmp(fix, version) <= 0 and (best_intro is None or cmp(best_intro, fix) <= 0):
            return False, []
    for last in last_affected:
        if cmp(last, version) < 0 and (best_intro is None or cmp(best_intro, last) <= 0):
            return False, []
    return True, [fix for fix in fixed_versions if cmp(fix, version) > 0]


def _reference_matches_affected_version(
    affected: dict[str, Any], ecosystem: str, version: str
) -> tuple[bool, list[str]]:
    """Evaluate a package-matched affected block; raise ``ValueError`` when it cannot decide."""
    fixed_versions: list[str] = []
    raw_versions, raw_ranges = affected.get("versions", []), affected.get("ranges", [])
    if not isinstance(raw_versions, list) or not isinstance(raw_ranges, list):
        raise ValueError("OSV affected versions or ranges are not a list")
    matched = any(
        isinstance(ver, str) and _reference_compare(ecosystem, version, ver) == 0
        for ver in raw_versions
    )
    for rng in raw_ranges:
        in_range, rng_fixed = _reference_range_matches(
            ecosystem, version, rng if isinstance(rng, dict) else {}
        )
        if in_range:
            matched = True
            fixed_versions.extend(rng_fixed)
    return matched, sorted(set(fixed_versions))


def _merged(found: list[tuple[str, list[str]]]) -> list[tuple[str, list[str]]]:
    """Merge blocks by record id in first-seen order, as the report does before deduplication."""
    by_id: dict[str, list[str]] = {}
    for record_id, fixed in found:
        by_id.setdefault(record_id, []).extend(fixed)
    return [(record_id, sorted(set(fixed))) for record_id, fixed in by_id.items()]


def _reference_blocks(
    blocks: list[tuple[str, dict[str, Any]]], ecosystem: str, version: str
) -> tuple[list[tuple[str, list[str]]], list[tuple[str, str]], list[str | None]]:
    """Pairwise matching of one version: merged matches, each undecided block in order, and
    every block's reason (None when decided).
    """
    found: list[tuple[str, list[str]]] = []
    undecided: list[tuple[str, str]] = []
    outcomes: list[str | None] = []
    for record_id, affected in blocks:
        try:
            hit, fixed = _reference_matches_affected_version(affected, ecosystem, version)
        except ValueError as exc:
            undecided.append((record_id, str(exc)))
            outcomes.append(str(exc))
            continue
        outcomes.append(None)
        if hit:
            found.append((record_id, fixed))
    return _merged(found), undecided, outcomes


_VERSIONS = {
    "PyPI": [
        *(f"{major}.{minor}" for major in range(4) for minor in range(4)),
        *("1.0.0", "1.2.0rc1", "1.2.0.dev3", "1.2.post1", "1!0.5", "2.0a1", "v2.1", " 1.3 "),
        *("01.2", "1.0.0.0", "3.0+local", "2.0-alpha.1", "not-a-version", "1.x", "", "0"),
    ],
    "npm": [
        *(
            f"{major}.{minor}.{patch}"
            for major in range(3)
            for minor in range(3)
            for patch in (0, 4)
        ),
        *("1", "1.2", "v2.1.0", "1.2.3-alpha.1", "1.2.3-alpha.beta", "1.2.3-1", "1.2.3-rc.10"),
        *("1.2.3+build", " 2.0.0 ", "01.2.3", "1.0.0.0", "1!0.5", "not-a-version", "1.x", "", "0"),
    ],
}
# Event versions are mostly ones the ecosystem parses, so most ranges can be decided and
# the ones that cannot are each about one unparseable version, whose effect depends on
# which comparisons the component version leads evaluation to make.
_PARSEABLE = {
    eco: [v for v in vs if offline._version_key(eco, v) is not None]
    for eco, vs in _VERSIONS.items()
}
_UNPARSEABLE = {
    eco: [v for v in vs if v.strip() and offline._version_key(eco, v) is None]
    for eco, vs in _VERSIONS.items()
}
# Each event shape fd259a7f refuses: several keys, no key, not an object, an unknown key, a
# value that is not a non-empty string, and the integers and booleans "0" must not admit.
_MALFORMED_EVENTS: list[object] = [
    {"introduced": "1.0", "fixed": "2.0"},
    {"fixed": "1.0", "limit": "2.0"},
    {},
    "event",
    None,
    ["introduced", "0"],
    {"withdrawn": "1.0"},
    {"fixed": 3},
    {"last_affected": None},
    {"limit": "  "},
    {"introduced": ""},
    {"introduced": True},
    {"introduced": False},
    {"introduced": 5},
    {"introduced": "0", "limit": "*"},
]


def _random_event(rng: random.Random, ecosystem: str) -> object:
    pool = _UNPARSEABLE if rng.random() < 0.04 else _PARSEABLE
    version = rng.choice(pool[ecosystem])
    roll = rng.random()
    if roll < 0.30:
        return {"introduced": rng.choice([version, version, version, "0", "0", 0, 0.0])}
    if roll < 0.58:
        return {"fixed": version}
    if roll < 0.73:
        return {"last_affected": version}
    if roll < 0.83:
        return {"limit": rng.choice([version, version, "*", " * "])}
    if roll < 0.97:
        return {"introduced": version}
    return rng.choice(_MALFORMED_EVENTS)


def _random_block(rng: random.Random, ecosystem: str) -> dict[str, Any]:
    versions = _VERSIONS[ecosystem]
    block: dict[str, Any] = {}
    if rng.random() < 0.4:
        block["versions"] = [rng.choice([*versions, 7, None]) for _ in range(rng.randint(0, 4))]
    if rng.random() < 0.03:
        block["versions"] = rng.choice(["1.0", None, {"1.0": True}])
    if rng.random() < 0.9:
        ranges: list[object] = []
        for _ in range(rng.randint(0, 3)):
            roll = rng.random()
            events: list[object] = (
                [{"introduced": "0"}, *rng.choice([[], [{"limit": "*"}]])]
                if roll < 0.08
                else [_random_event(rng, ecosystem) for _ in range(rng.randint(0, 6))]
            )
            if 0.08 <= roll < 0.2:
                # One version that cannot be compared, among ones that can: whether a
                # component reaches it depends on how it compares with the others.
                kind = rng.choice(["introduced", "fixed", "last_affected", "limit"])
                bad = {kind: rng.choice(_UNPARSEABLE[ecosystem])}
                events.insert(rng.randint(0, len(events)), bad)
            entry: dict[str, Any] = {"events": events}
            kind = rng.choice(["ECOSYSTEM", "SEMVER", "semver", None, None, "GIT", 7])
            if kind is not None:
                entry["type"] = kind
            if rng.random() < 0.04:
                entry["events"] = rng.choice([None, "events", {"introduced": "0"}])
            if rng.random() < 0.02:
                del entry["events"]
            ranges.append(entry if rng.random() < 0.96 else rng.choice(["range", 7, None, []]))
        block["ranges"] = (
            ranges if rng.random() < 0.97 else rng.choice([{"type": "ECOSYSTEM"}, "ranges", None])
        )
    return block


def _advisory(record_id: str) -> offline._ParsedAdvisory:
    return offline._ParsedAdvisory(record_id, (), "", "unknown", ())


@pytest.mark.parametrize("ecosystem", ["PyPI", "npm"])
def test_the_indexed_matcher_reports_what_pairwise_matching_reported(ecosystem):
    rng = random.Random(273)  # noqa: S311 - a reproducible corpus, not a secret
    versions = _VERSIONS[ecosystem]
    budget = offline._MatchBudget(10**9)
    matched = unmatched = undecidable = with_fixes = mixed = reached_only_by_some = 0
    reasons: Counter[str] = Counter()
    for _ in range(600):
        blocks = [
            (f"GHSA-{rng.randint(0, 5)}", _random_block(rng, ecosystem))
            for _ in range(rng.randint(1, 8))
        ]
        matcher = offline._PackageMatcher(
            ecosystem, [(_advisory(record_id), block) for record_id, block in blocks], budget
        )
        parsed_outcomes: list[set[str | None]] = [set() for _ in blocks]
        for version in versions:
            expected, expected_undecided, outcomes = _reference_blocks(blocks, ecosystem, version)
            if offline._version_key(ecosystem, version) is not None:
                for seen, outcome in zip(parsed_outcomes, outcomes, strict=True):
                    seen.add(outcome)
            found, undecided = matcher.matches(version, budget)
            assert _merged([(adv.record_id, fixed) for adv, fixed in found]) == expected, (
                ecosystem,
                version,
                blocks,
            )
            assert [(adv.record_id, reason) for adv, reason in undecided] == expected_undecided, (
                ecosystem,
                version,
                blocks,
            )
            reasons.update(reason for _, reason in expected_undecided)
            matched += bool(expected)
            unmatched += not expected
            mixed += bool(expected) and bool(expected_undecided)
            with_fixes += any(fixed for _, fixed in expected)
            undecidable += bool(expected) and offline._version_key(ecosystem, version) is None
        # Blocks decided for some versions and not comparable for others: the short-circuit
        # order of the comparisons is what the index has to reproduce there.
        reached_only_by_some += sum(
            {None, "OSV range version cannot be compared"} <= seen for seen in parsed_outcomes
        )
    assert min(matched, unmatched) > 2_000
    assert reached_only_by_some > 50
    assert with_fixes > 500
    assert undecidable > 50
    assert mixed > 500
    assert min(reasons.values()) > 300
    assert set(reasons) == {
        "OSV affected versions or ranges are not a list",
        "OSV range events are not a list",
        "OSV range event cannot be parsed",
        "OSV range version cannot be compared",
    }


def _component(name: str, version: str, kind: str = "pypi") -> RegistryEntryComponent:
    return RegistryEntryComponent(
        bom_ref=f"pkg:{kind}:{name}@{version}",
        name=name,
        version=version,
        registry_type=kind,
        package_url=f"pkg:{kind}/{name}@{version}",
    )


def test_a_random_bundle_gives_the_report_pairwise_matching_gave(tmp_path):
    rng = random.Random(20)  # noqa: S311 - a reproducible corpus, not a secret
    pinned = {
        "pypi": [v for v in _VERSIONS["PyPI"] if v == v.strip() and v[:1].isdigit()],
        "npm": [v for v in _VERSIONS["npm"] if v.count(".") == 2 and v[:1].isdigit()],
    }
    names = [f"package-{index}" for index in range(12)]
    records = []
    for index in range(300):
        kind = rng.choice(["pypi", "npm"])
        ecosystem = "PyPI" if kind == "pypi" else "npm"
        affected = []
        for _ in range(rng.randint(1, 3)):
            block = _random_block(rng, ecosystem)
            block["package"] = {
                "ecosystem": rng.choice([ecosystem, ecosystem.lower()]),
                "name": rng.choice(names),
            }
            affected.append(block)
        records.append(
            {
                "id": f"GHSA-{rng.randint(0, 250):04d}",
                "aliases": [f"CVE-2026-{rng.randint(0, 150):04d}"] if rng.random() < 0.5 else [],
                "summary": f"summary {index}",
                "affected": affected,
            }
        )
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps(records), encoding="utf-8")
    components = []
    for kind, versions in pinned.items():
        for name in names:
            for version in versions:
                component = _component(name, version, kind)
                try:
                    package_identity(component)
                except ValueError:
                    continue
                components.append(component)

    report, _ = offline.match_offline_advisories(AIBOM(components=components), db_path=db_file)

    assert report.components_checked == len(components) > 400
    parsed = offline._parse_osv_records(records)
    expected = []
    errors = []
    for component in sorted(components, key=lambda item: item.bom_ref):
        ecosystem = "PyPI" if component.registry_type == "pypi" else "npm"
        raw: dict[str, tuple[offline._ParsedAdvisory, list[str]]] = {}
        for adv in parsed:
            for block in adv.affected:
                package = block["package"]
                if (package["ecosystem"].lower(), package["name"]) != (
                    component.registry_type,
                    component.name,
                ):
                    continue
                try:
                    hit, fixed = _reference_matches_affected_version(
                        block, ecosystem, component.version
                    )
                except ValueError as exc:
                    errors.append(f"{component.bom_ref}: offline advisory {adv.record_id}: {exc}")
                    continue
                if hit:
                    raw.setdefault(adv.record_id, (adv, []))[1].extend(fixed)
        for entry in offline._deduplicate_matches(
            [(adv, sorted(set(fixed))) for adv, fixed in raw.values()]
        ):
            expected.append({**entry, "component_ref": component.bom_ref})
    keys = ("component_ref", "id", "aliases", "matched_ids", "summary", "fixed_versions")
    assert [{key: entry[key] for key in keys} for entry in report.advisories] == [
        {key: entry[key] for key in keys} for entry in expected
    ]
    assert report.errors == errors
    assert report.complete is False
    assert len(expected) > 1_000
    assert len(errors) > 1_000
    assert sum(bool(entry["fixed_versions"]) for entry in expected) > 100


def _range_record(index: int, events: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {
        "id": f"GHSA-{index:06d}",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "victim"},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ],
        **extra,
    }


def test_advisories_that_do_not_match_cost_no_comparison_per_component(tmp_path):
    inputs = {}
    for scale in (1, 4):
        db_file = tmp_path / f"osv-{scale}.json"
        db_file.write_text(
            json.dumps(
                [
                    _range_record(
                        index, [{"introduced": f"9000.{index}.0"}, {"fixed": f"9000.{index}.5"}]
                    )
                    for index in range(2_500 * scale)
                ]
            ),
            encoding="utf-8",
        )
        bom = AIBOM(components=[_component("victim", f"1.{i}.0") for i in range(60 * scale)])
        inputs[scale] = (bom, db_file)

    def run(scale: int) -> None:
        bom, db_file = inputs[scale]
        report, _ = offline.match_offline_advisories(bom, db_path=db_file)
        assert report.complete is True
        assert report.components_checked == 60 * scale
        assert report.advisories == []

    assert scaling_ratio(run) < 10


def _matching_inputs(tmp_path, components: int, advisories: int):
    db_file = tmp_path / "osv.json"
    db_file.write_text(
        json.dumps(
            [
                _range_record(index, [{"introduced": "0"}], aliases=["CVE-2026-0001"])
                for index in range(advisories)
            ]
        ),
        encoding="utf-8",
    )
    return AIBOM(components=[_component("victim", f"1.{i}.0") for i in range(components)]), db_file


def test_matches_beyond_the_budget_stop_with_one_error(tmp_path):
    bom, db_file = _matching_inputs(tmp_path, components=5, advisories=4)

    with limits.applied(replace(limits.DEFAULTS, advisory_matches=20)):
        report, _ = offline.match_offline_advisories(bom, db_path=db_file)
    assert report.complete is True
    assert len(report.advisories) == 5
    assert all(len(entry["matched_ids"]) == 4 for entry in report.advisories)

    with limits.applied(replace(limits.DEFAULTS, advisory_matches=19)):
        report, _ = offline.match_offline_advisories(bom, db_path=db_file)
    assert report.errors == [
        "Offline advisory matching stopped: advisory-matches limit of 19 exceeded; "
        "raise it with --limit advisory-matches=N"
    ]
    assert report.complete is False
    assert len(report.advisories) == 4
    assert report.components_checked == 5


def test_the_budget_is_an_operator_limit_and_the_command_exits_1(tmp_path):
    bom, db_file = _matching_inputs(tmp_path, components=5, advisories=4)
    bom_path = tmp_path / "aibom.json"
    bom.save(bom_path)
    arguments = ["advisories", str(bom_path), "--offline-db", str(db_file)]
    runner = CliRunner()

    stopped = runner.invoke(main, ["--limit", "advisory-matches=19", *arguments])
    assert stopped.exit_code == 1
    payload = json.loads(stopped.output)
    assert payload["complete"] is False
    assert len(payload["errors"]) == 1
    assert "advisory-matches limit of 19 exceeded" in payload["errors"][0]

    complete = json.loads(runner.invoke(main, arguments).output)
    assert complete["complete"] is True
    assert len(complete["advisories"]) == 5
    assert limits.DEFAULTS.advisory_matches == 2_000_000


def test_a_range_with_many_events_spends_the_budget_before_it_is_evaluated(tmp_path):
    events = [
        {"introduced": f"5.{index}.0"} if index % 2 == 0 else {"fixed": f"5.{index}.0"}
        for index in range(400)
    ]
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps([_range_record(0, events)]), encoding="utf-8")
    bom = AIBOM(components=[_component("victim", "5.10.3"), _component("victim", "5.11.3")])

    report, _ = offline.match_offline_advisories(bom, db_path=db_file)
    assert report.complete is True
    assert [entry["version"] for entry in report.advisories] == ["5.10.3"]
    assert report.advisories[0]["fixed_versions"] == sorted(
        f"5.{index}.0" for index in range(11, 400, 2)
    )

    with limits.applied(replace(limits.DEFAULTS, advisory_matches=1_000)):
        report, _ = offline.match_offline_advisories(bom, db_path=db_file)
    assert report.advisories == []
    assert len(report.errors) == 1
    assert report.complete is False
