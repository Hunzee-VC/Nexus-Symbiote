"""Offline advisory feeds state their own date, and a stale or undated one is not complete."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import RegistryEntryComponent
from nexus_symbiote.offline_advisories import match_offline_advisories

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
FRESH = "2026-11-15T08:30:00Z"
STALE = "2025-10-04T00:00:00Z"
FUTURE = "2026-11-22T12:00:01Z"
FEEDS = ("osv", "kev", "epss")


def _bom() -> AIBOM:
    return AIBOM(
        components=[
            RegistryEntryComponent(
                bom_ref="pkg:pypi:transformers@4.48.0",
                name="transformers",
                version="4.48.0",
                registry_type="pypi",
                package_url="pkg:pypi/transformers@4.48.0",
            )
        ]
    )


def _feeds(tmp_path: Path, **dates: object) -> dict[str, Path]:
    """Write the three feeds, each dated FRESH unless named; None leaves the date out."""
    osv, kev, epss = (dates.get(feed, FRESH) for feed in FEEDS)
    record = {
        "id": "CVE-2024-99999",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "transformers"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.48.0"}]}
                ],
            }
        ],
    }
    paths = {"osv": tmp_path / "osv.json", "kev": tmp_path / "kev.json"}
    paths["epss"] = tmp_path / "epss.csv"
    undated = {**record, "id": "GHSA-aaaa-bbbb-cccc", "modified": None}
    paths["osv"].write_text(
        json.dumps([undated, record if osv is None else {**record, "modified": osv}]),
        encoding="utf-8",
    )
    catalog: dict[str, object] = {"vulnerabilities": [{"cveID": "CVE-2024-99999"}]}
    paths["kev"].write_text(
        json.dumps(catalog if kev is None else {**catalog, "dateReleased": kev}), encoding="utf-8"
    )
    comment = "#model_version:v2026.01" + ("" if epss is None else f",score_date:{epss}")
    paths["epss"].write_text(
        f"{comment}\ncve,epss,percentile\nCVE-2024-99999,0.5,0.9\n", encoding="utf-8"
    )
    return paths


def _match(paths: dict[str, Path], **options: object):
    return match_offline_advisories(
        _bom(),
        db_path=paths["osv"],
        kev_paths=[paths["kev"]],
        epss_path=paths["epss"],
        **{"now": NOW, **options},
    )


def _cli(tmp_path: Path, paths: dict[str, Path], *extra: str):
    bom_path = tmp_path / "aibom.json"
    _bom().save(bom_path)
    arguments = ["advisories", str(bom_path), "--offline-db", str(paths["osv"])]
    arguments += ["--kev", str(paths["kev"]), "--epss", str(paths["epss"]), *extra]
    return CliRunner().invoke(main, arguments)


def _today(days_ago: int = 0) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_fresh_feeds_are_complete_and_provenance_carries_their_dates(tmp_path):
    report, provenance = _match(_feeds(tmp_path, epss="2026-11-01T00:00:00+0000"))
    assert report.errors == []
    assert report.complete is True
    assert provenance["db_newest_record"] == "2026-11-15T08:30:00+00:00"
    assert provenance["kev_catalogs"][0]["date_released"] == "2026-11-15T08:30:00+00:00"
    assert provenance["epss_catalog"]["score_date"] == "2026-11-01T00:00:00+00:00"
    assert provenance["max_feed_age_days"] == 30
    assert provenance["feed_age_evaluated_at"] == "2026-11-20T12:00:00+00:00"


STALE_ERRORS = {
    "osv": "offline advisory DB is 412 days old (newest record 2025-10-04); limit 30",
    "kev": "KEV catalog kev.json is 412 days old (dateReleased 2025-10-04); limit 30",
    "epss": "EPSS catalog epss.csv is 412 days old (score_date 2025-10-04); limit 30",
}


@pytest.mark.parametrize("feed", FEEDS)
def test_a_stale_feed_is_incomplete_with_a_named_error(tmp_path, feed):
    report, _ = _match(_feeds(tmp_path, **{feed: STALE}))
    assert report.errors == [STALE_ERRORS[feed]]
    assert report.complete is False
    assert report.advisories == []


def test_the_age_limit_is_inclusive_and_counts_utc_days(tmp_path):
    paths = _feeds(tmp_path, osv="2026-10-21", kev="2026-10-21", epss="2026-10-21")
    assert _match(paths)[0].complete is True
    report, _ = _match(paths, max_feed_age_days=29)
    assert [error.split(" (")[0] for error in report.errors] == [
        "offline advisory DB is 30 days old",
        "KEV catalog kev.json is 30 days old",
        "EPSS catalog epss.csv is 30 days old",
    ]


def test_the_database_date_is_its_newest_record_with_published_as_fallback(tmp_path):
    paths = _feeds(tmp_path)
    records = [
        {"id": "CVE-2024-1", "published": "2019-01-01T00:00:00Z"},
        {"id": "CVE-2024-2", "modified": "2019-03-01T00:00:00Z", "published": FRESH},
        {"id": "CVE-2024-3", "modified": "2019-02-01T00:00:00+05:30"},
        *json.loads(paths["osv"].read_text(encoding="utf-8"))[:1],
    ]
    paths["osv"].write_text(json.dumps(records), encoding="utf-8")
    report, provenance = _match(paths)
    assert provenance["db_newest_record"] == "2019-03-01T00:00:00+00:00"
    assert report.errors == [
        "offline advisory DB is 2821 days old (newest record 2019-03-01); limit 30"
    ]


UNDATED_ERRORS = {
    "osv": "offline advisory DB carries no record 'modified' or 'published' date",
    "kev": "KEV catalog kev.json carries no dateReleased",
    "epss": "EPSS catalog epss.csv carries no score_date",
}


@pytest.mark.parametrize("feed", FEEDS)
def test_an_undated_feed_is_incomplete_whatever_the_limit(tmp_path, feed):
    paths = _feeds(tmp_path, **{feed: None})
    report, provenance = _match(paths, max_feed_age_days=36_500)
    assert report.errors == [f"{UNDATED_ERRORS[feed]}, so its age is unknown; limit 36500 days"]
    assert report.complete is False
    dates = {
        "osv": provenance["db_newest_record"],
        "kev": provenance["kev_catalogs"][0]["date_released"],
        "epss": provenance["epss_catalog"]["score_date"],
    }
    assert dates[feed] is None
    assert all(value is not None for name, value in dates.items() if name != feed)


MALFORMED = ["", "yesterday", "2026-13-01", "20261115", "2026-11-15T08:30:00", "2026-W46-7"]


@pytest.mark.parametrize(
    ("feed", "value"),
    [
        *((feed, value) for feed in FEEDS for value in MALFORMED),
        *((feed, value) for feed in ("osv", "kev") for value in (" 2026-11-15", 1794000000)),
    ],
)
def test_an_unparseable_date_refuses_the_feed(tmp_path, feed, value):
    paths = _feeds(tmp_path, **{feed: value})
    with pytest.raises(ValueError, match="is not an RFC 3339 date or date-time"):
        _match(paths, max_feed_age_days=36_500)
    result = _cli(tmp_path, paths, "--max-feed-age-days", "36500")
    assert result.exit_code == 1
    assert "is not an RFC 3339 date or date-time" in result.output
    assert '"complete"' not in result.output


def test_an_epss_json_catalog_states_its_score_date_in_a_field(tmp_path):
    paths = _feeds(tmp_path)
    rows = {"data": [{"cve": "CVE-2024-99999", "epss": 0.5}]}
    paths["epss"].write_text(json.dumps({**rows, "score_date": STALE}), encoding="utf-8")
    assert _match(paths)[0].errors == [STALE_ERRORS["epss"]]
    paths["epss"].write_text(json.dumps({**rows, "score_date": "soon"}), encoding="utf-8")
    with pytest.raises(ValueError, match="EPSS catalog 'score_date' is not an RFC 3339"):
        _match(paths)
    paths["epss"].write_text(json.dumps(rows), encoding="utf-8")
    assert _match(paths)[0].errors[0].startswith("EPSS catalog epss.csv carries no score_date")


@pytest.mark.parametrize("feed", FEEDS)
def test_a_feed_dated_more_than_a_day_ahead_is_an_error(tmp_path, feed):
    report, _ = _match(_feeds(tmp_path, **{feed: FUTURE}), max_feed_age_days=36_500)
    assert len(report.errors) == 1
    assert report.errors[0].endswith("2026-11-22 is in the future")
    assert report.complete is False

    within_tolerance = _feeds(tmp_path, **{feed: "2026-11-21T12:00:00Z"})
    assert _match(within_tolerance)[0].complete is True


def test_a_larger_explicit_limit_accepts_an_old_feed(tmp_path):
    paths = _feeds(tmp_path, osv=STALE, kev=STALE, epss=STALE)
    assert len(_match(paths, max_feed_age_days=411)[0].errors) == 3
    report, provenance = _match(paths, max_feed_age_days=412)
    assert report.complete is True
    assert provenance["max_feed_age_days"] == 412


@pytest.mark.parametrize("limit", [0, -1, 36_501, True, 30.0, None])
def test_the_library_refuses_a_limit_that_would_disable_the_check(tmp_path, limit):
    with pytest.raises(ValueError, match="max_feed_age_days must be an integer from 1 to 36500"):
        _match(_feeds(tmp_path), max_feed_age_days=limit)


def test_the_library_needs_an_aware_clock_from_its_caller(tmp_path):
    paths = _feeds(tmp_path)
    with pytest.raises(ValueError, match="now must be timezone-aware"):
        _match(paths, now=datetime(2026, 11, 20))
    with pytest.raises(TypeError, match="now"):
        match_offline_advisories(_bom(), db_path=paths["osv"])


def test_cli_passes_fresh_feeds_and_reports_their_dates(tmp_path):
    result = _cli(tmp_path, _feeds(tmp_path, osv=_today(1), kev=_today(2), epss=_today(3)))
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["complete"] is True
    assert payload["errors"] == []
    assert payload["provenance"]["max_feed_age_days"] == 30
    assert payload["provenance"]["db_newest_record"] is not None


@pytest.mark.parametrize("feed", FEEDS)
@pytest.mark.parametrize("date", ["2020-01-01T00:00:00Z", None, "2999-01-01"])
def test_cli_exits_1_on_a_stale_undated_or_future_feed(tmp_path, feed, date):
    today = _today()
    paths = _feeds(tmp_path, **{**dict.fromkeys(FEEDS, today), feed: date})
    result = _cli(tmp_path, paths)
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["complete"] is False
    assert payload["coverage"] == "partial"
    (error,) = payload["errors"]
    expected = {None: "so its age is unknown; limit 30 days", "2999-01-01": "is in the future"}
    assert error.endswith(expected.get(date, "); limit 30"))
    assert error.startswith(STALE_ERRORS[feed].split(" is ")[0])


def test_cli_accepts_an_old_feed_under_a_larger_explicit_limit(tmp_path):
    paths = _feeds(tmp_path, osv=_today(90), kev=_today(90), epss=_today(90))
    assert _cli(tmp_path, paths).exit_code == 1
    result = _cli(tmp_path, paths, "--max-feed-age-days", "120")
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["provenance"]["max_feed_age_days"] == 120


@pytest.mark.parametrize("value", ["0", "-1", "36501", "never"])
def test_cli_rejects_a_limit_below_one_day(tmp_path, value):
    result = _cli(tmp_path, _feeds(tmp_path), "--max-feed-age-days", value)
    assert result.exit_code == 2
    assert "Invalid value for '--max-feed-age-days'" in result.output
    assert '"complete"' not in result.output


def test_cli_refuses_the_limit_without_an_offline_database(tmp_path):
    bom_path = tmp_path / "aibom.json"
    _bom().save(bom_path)
    result = CliRunner().invoke(main, ["advisories", str(bom_path), "--max-feed-age-days", "30"])
    assert result.exit_code == 1
    assert "--max-feed-age-days requires --offline-db" in result.output
