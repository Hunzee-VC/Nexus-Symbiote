"""Offline advisory matching: indexed cost, the advisory-matches budget, and equivalence.

The indexed matcher must report exactly what pairwise matching reported. The reference
below is the pairwise matcher this module replaced, kept word for word as the oracle.
"""

from __future__ import annotations

import json
import random
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
    raw_type = rng.get("type")
    if raw_type is not None and (
        not isinstance(raw_type, str) or raw_type.upper() not in _SUPPORTED_RANGE_TYPES
    ):
        return False, []
    events = rng.get("events")
    if not isinstance(events, list):
        return False, []

    has_zero_intro = False
    intros: list[str] = []
    fixed_versions: list[str] = []
    last_affected: list[str] = []
    limit_versions: list[str] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        if "introduced" in ev:
            raw_intro = ev["introduced"]
            if raw_intro == "0" or (
                isinstance(raw_intro, int) and not isinstance(raw_intro, bool) and raw_intro == 0
            ):
                has_zero_intro = True
            elif isinstance(raw_intro, str) and raw_intro.strip():
                intros.append(raw_intro.strip())
        elif "fixed" in ev and isinstance(ev["fixed"], str) and ev["fixed"].strip():
            fixed_versions.append(ev["fixed"].strip())
        elif (
            "last_affected" in ev
            and isinstance(ev["last_affected"], str)
            and ev["last_affected"].strip()
        ):
            last_affected.append(ev["last_affected"].strip())
        elif "limit" in ev and isinstance(ev["limit"], str) and ev["limit"].strip():
            limit_versions.append(ev["limit"].strip())

    if any(
        (c := _reference_compare(ecosystem, version, lim)) is not None and c >= 0
        for lim in limit_versions
    ):
        return False, []

    best_intro: str | None = None
    found_intro = has_zero_intro
    for intro in intros:
        cmp_v = _reference_compare(ecosystem, intro, version)
        if cmp_v is None or cmp_v > 0:
            continue
        found_intro = True
        if best_intro is None or (
            (cb := _reference_compare(ecosystem, intro, best_intro)) is not None and cb > 0
        ):
            best_intro = intro
    if not found_intro:
        return False, []

    for fix in fixed_versions:
        cmp_v = _reference_compare(ecosystem, fix, version)
        if cmp_v is None or cmp_v > 0:
            continue
        if best_intro is None or (
            (ci := _reference_compare(ecosystem, best_intro, fix)) is not None and ci <= 0
        ):
            return False, []

    for last in last_affected:
        cmp_v = _reference_compare(ecosystem, last, version)
        if cmp_v is None or cmp_v >= 0:
            continue
        if best_intro is None or (
            (ci := _reference_compare(ecosystem, best_intro, last)) is not None and ci <= 0
        ):
            return False, []

    relevant_fixes = [
        fix
        for fix in fixed_versions
        if (cf := _reference_compare(ecosystem, fix, version)) is not None and cf > 0
    ]
    return True, relevant_fixes


def _reference_matches_affected_version(
    affected: dict[str, Any], ecosystem: str, version: str
) -> tuple[bool, list[str]]:
    fixed_versions: list[str] = []
    matched = False
    raw_versions = affected.get("versions")
    if isinstance(raw_versions, list) and any(
        isinstance(ver, str) and _reference_compare(ecosystem, version, ver) == 0
        for ver in raw_versions
    ):
        matched = True
    raw_ranges = affected.get("ranges")
    if isinstance(raw_ranges, list):
        for rng in raw_ranges:
            if not isinstance(rng, dict):
                continue
            in_range, rng_fixed = _reference_range_matches(ecosystem, version, rng)
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


def _random_event(rng: random.Random, versions: list[str]) -> object:
    version = rng.choice(versions)
    roll = rng.random()
    if roll < 0.30:
        return {"introduced": rng.choice([version, version, version, "0", "0", 0, True, 5, ""])}
    if roll < 0.55:
        return {"fixed": version}
    if roll < 0.70:
        return {"last_affected": version}
    if roll < 0.80:
        return {"limit": version}
    if roll < 0.88:
        return {"introduced": version, "fixed": rng.choice(versions)}
    if roll < 0.94:
        return {"fixed": version, "limit": rng.choice(versions)}
    return rng.choice(["event", None, {"fixed": 3}, {"last_affected": None}, {}])


def _random_block(rng: random.Random, versions: list[str]) -> dict[str, Any]:
    block: dict[str, Any] = {}
    if rng.random() < 0.4:
        block["versions"] = [
            rng.choice([*versions, 7, None]) for _ in range(rng.randint(0, 4))
        ] or rng.choice([[], "1.0"])
    if rng.random() < 0.9:
        ranges: list[object] = []
        for _ in range(rng.randint(0, 3)):
            entry: dict[str, Any] = {
                "events": [_random_event(rng, versions) for _ in range(rng.randint(0, 6))]
            }
            kind = rng.choice(["ECOSYSTEM", "SEMVER", "semver", None, None, "GIT", 7])
            if kind is not None:
                entry["type"] = kind
            if rng.random() < 0.05:
                entry["events"] = rng.choice([None, "events", {"introduced": "0"}])
            ranges.append(entry if rng.random() < 0.95 else "range")
        block["ranges"] = ranges if rng.random() < 0.95 else {"type": "ECOSYSTEM"}
    return block


def _advisory(record_id: str) -> offline._ParsedAdvisory:
    return offline._ParsedAdvisory(record_id, (), "", "unknown", ())


@pytest.mark.parametrize("ecosystem", ["PyPI", "npm"])
def test_the_indexed_matcher_reports_what_pairwise_matching_reported(ecosystem):
    rng = random.Random(273)  # noqa: S311 - a reproducible corpus, not a secret
    versions = _VERSIONS[ecosystem]
    budget = offline._MatchBudget(10**9)
    matched = unmatched = undecidable = with_fixes = 0
    for _ in range(400):
        blocks = [
            (_advisory(f"GHSA-{rng.randint(0, 5)}"), _random_block(rng, versions))
            for _ in range(rng.randint(1, 8))
        ]
        matcher = offline._PackageMatcher(ecosystem, blocks, budget)
        for version in versions:
            expected = _merged(
                [
                    (adv.record_id, fixed)
                    for adv, affected in blocks
                    for hit, fixed in [
                        _reference_matches_affected_version(affected, ecosystem, version)
                    ]
                    if hit
                ]
            )
            found = _merged(
                [(adv.record_id, fixed) for adv, fixed in matcher.matches(version, budget)]
            )
            assert found == expected, (ecosystem, version, blocks)
            matched += bool(expected)
            unmatched += not expected
            with_fixes += any(fixed for _, fixed in expected)
            undecidable += bool(expected) and offline._version_key(ecosystem, version) is None
    assert min(matched, unmatched) > 2_000
    assert with_fixes > 500
    assert undecidable > 100


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
            block = _random_block(rng, _VERSIONS[ecosystem])
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

    assert report.complete is True
    assert report.components_checked == len(components) > 400
    parsed = offline._parse_osv_records(records)
    expected = []
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
                hit, fixed = _reference_matches_affected_version(
                    block, ecosystem, component.version
                )
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
    assert len(expected) > 1_000
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
