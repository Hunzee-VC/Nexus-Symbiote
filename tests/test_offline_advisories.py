"""Tests for offline OSV advisory matching, alias deduplication, and KEV/EPSS enrichment (Item 20 & X6)."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import RegistryEntryComponent
from nexus_symbiote.offline_advisories import match_offline_advisories


def _bom_with_package(
    *,
    name: str = "transformers",
    version: str = "4.35.0",
    registry_type: str = "pypi",
    purl: str | None = None,
) -> AIBOM:
    pkg_url = purl or f"pkg:{registry_type}/{name}@{version}"
    comp = RegistryEntryComponent(
        bom_ref=f"pkg:{registry_type}:{name}@{version}",
        name=name,
        version=version,
        registry_type=registry_type,
        package_url=pkg_url,
    )
    return AIBOM(components=[comp])


def _sample_osv_bundle() -> dict:
    # Planted alias pair: CVE-2024-99999 and GHSA-aaaa-bbbb-cccc refer to each other.
    return {
        "advisories": [
            {
                "id": "GHSA-aaaa-bbbb-cccc",
                "aliases": ["CVE-2024-99999"],
                "summary": "Unsafe deserialization in transformers checkpoint loader",
                "database_specific": {"severity": "MEDIUM"},
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "transformers"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "4.0.0"}, {"fixed": "4.48.0"}],
                            }
                        ],
                    }
                ],
            },
            {
                "id": "CVE-2024-99999",
                "aliases": ["GHSA-aaaa-bbbb-cccc"],
                "summary": "Unsafe deserialization in transformers checkpoint loader",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "transformers"},
                        "versions": ["4.35.0"],
                    }
                ],
            },
            {
                "id": "GHSA-npm-1111-2222",
                "summary": "Prototype pollution in mcp-helper",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "@acme/mcp-helper"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}],
                            }
                        ],
                    }
                ],
            },
        ]
    }


def test_offline_advisories_matches_transformers_and_deduplicates_alias_pair(tmp_path):
    db_file = tmp_path / "osv-bundle.json"
    db_file.write_text(json.dumps(_sample_osv_bundle()), encoding="utf-8")

    # Positive fixture: vulnerable transformers==4.35.0 matched offline; alias pair appears once.
    report, provenance = match_offline_advisories(_bom_with_package(), db_path=db_file)
    assert provenance["offline"] is True
    assert provenance["db_sha256"].startswith("sha256:")
    assert report.complete is True
    assert len(report.advisories) == 1
    adv = report.advisories[0]
    assert adv["id"] == "CVE-2024-99999"
    assert adv["aliases"] == ["GHSA-aaaa-bbbb-cccc"]
    assert adv["matched_ids"] == ["CVE-2024-99999", "GHSA-aaaa-bbbb-cccc"]
    assert adv["severity"] == "high"
    assert adv["fixed_versions"] == ["4.48.0"]
    assert adv["offline"] is True

    # Benign twin: fixed version transformers==4.48.0 produces 0 advisories.
    clean_report, _ = match_offline_advisories(_bom_with_package(version="4.48.0"), db_path=db_file)
    assert clean_report.complete is True
    assert clean_report.advisories == []


def test_offline_advisories_kev_elevates_severity_and_epss_enriches(tmp_path):
    db_dir = tmp_path / "osv-dir"
    db_dir.mkdir()
    (db_dir / "transformers.json").write_text(
        json.dumps(
            {
                "id": "GHSA-aaaa-bbbb-cccc",
                "aliases": ["CVE-2024-99999"],
                "summary": "Transformers vulnerability",
                "database_specific": {"severity": "MEDIUM"},
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "transformers"},
                        "versions": ["4.35.0"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    kev_file = tmp_path / "cisa-kev.json"
    kev_file.write_text(
        json.dumps(
            {
                "title": "CISA Catalog of Known Exploited Vulnerabilities",
                "vulnerabilities": [{"cveID": "CVE-2024-99999", "dateAdded": "2026-03-01"}],
            }
        ),
        encoding="utf-8",
    )
    epss_file = tmp_path / "epss.csv"
    epss_file.write_text(
        "#model_version:v2026.01,score_date:2026-11-01\n"
        "cve,epss,percentile\n"
        "CVE-2024-99999,0.91234,0.99450\n",
        encoding="utf-8",
    )

    report, provenance = match_offline_advisories(
        _bom_with_package(),
        db_path=db_dir,
        kev_paths=(kev_file,),
        epss_path=epss_file,
    )
    assert len(report.advisories) == 1
    adv = report.advisories[0]
    assert adv["in_kev"] is True
    assert adv["kev_sources"] == ["cisa-kev"]
    assert adv["kev_date_added"] == "2026-03-01"
    assert adv["base_severity"] == "medium"
    assert adv["severity"] == "critical"
    assert adv["severity_elevated_by"] == "cisa-kev"
    assert adv["epss_score"] == pytest.approx(0.91234)
    assert adv["epss_percentile"] == pytest.approx(0.99450)
    assert len(provenance["kev_catalogs"]) == 1
    assert provenance["epss_catalog"] is not None


def test_offline_advisories_npm_semver_and_symlink_rejection(tmp_path):
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps(_sample_osv_bundle()), encoding="utf-8")

    bom_npm = _bom_with_package(
        name="@acme/mcp-helper",
        version="1.1.5",
        registry_type="npm",
        purl="pkg:npm/%40acme/mcp-helper@1.1.5",
    )
    report, _ = match_offline_advisories(bom_npm, db_path=db_file)
    assert len(report.advisories) == 1
    assert report.advisories[0]["id"] == "GHSA-npm-1111-2222"

    # Symlink offline DB must be refused.
    link = tmp_path / "symlink-db.json"
    link.symlink_to(db_file)
    with pytest.raises(ValueError, match="symbolic link"):
        match_offline_advisories(bom_npm, db_path=link)


def test_advisories_cli_offline_mode_requires_no_live_flag(tmp_path):
    bom_path = tmp_path / "aibom.json"
    _bom_with_package().save(bom_path)
    db_file = tmp_path / "osv.json"
    db_file.write_text(json.dumps(_sample_osv_bundle()), encoding="utf-8")

    runner = CliRunner()
    res = runner.invoke(main, ["advisories", str(bom_path), "--offline-db", str(db_file)])
    assert res.exit_code == 1
    payload = json.loads(res.output)
    assert payload["sent_to_osv"] == "nothing (offline advisory bundle)"
    assert payload["provenance"]["offline"] is True
    assert len(payload["advisories"]) == 1

    # --kev without --offline-db fails cleanly.
    kev_file = tmp_path / "kev.json"
    kev_file.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
    res_bad = runner.invoke(main, ["advisories", str(bom_path), "--kev", str(kev_file)])
    assert res_bad.exit_code != 0
    assert "--offline-db" in res_bad.output
