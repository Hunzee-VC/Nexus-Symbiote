"""Registry parsers: npm packuments, PyPI JSON/Simple, OSV records, MCP Registry pages."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from symbiote.advisories.http import MalformedResponse
from symbiote.advisories.mcp_registry import SearchTruncated, lookup_server, search_term
from symbiote.advisories.npm import (
    InvalidPackageName,
    npm_package_url,
    parse_packument,
    parse_time,
    semver_key,
    validate_npm_name,
)
from symbiote.advisories.osv import MAX_PAGES, cvss3_base_score, parse_vulns, query_osv
from symbiote.advisories.pypi import (
    apply_simple_index,
    normalize_pypi_name,
    parse_pypi_json,
    pep440_key,
)

from ._support import OSV, FakeClient, Route, fixture

# --------------------------------------------------------------------------------------------- npm


def test_packument_fields() -> None:
    pkg = parse_packument("agent-cli-demo", json.loads(fixture("npm-agent-cli-demo.json")), source="x")
    r223, r230 = pkg.release("2.2.3"), pkg.release("2.3.0")
    assert r223 is not None and r230 is not None
    assert r223.has_provenance is True and r223.publisher == "GitHub Actions"
    assert r223.has_install_script is False
    assert r223.published_at == datetime(2026, 9, 1, 10, 0, tzinfo=UTC)
    assert r230.has_provenance is False and r230.has_install_script is True
    assert r230.publisher == "cline-release-bot"
    assert pkg.latest == "2.5.0"
    assert pkg.removed_versions == frozenset({"2.1.9"})  # in `time`, no longer in `versions`


def test_packument_deprecation_and_has_install_script_flag() -> None:
    data = json.loads(fixture("npm-scoped-files.json"))
    data["versions"]["1.1.0"]["hasInstallScript"] = True
    pkg = parse_packument("@demo/mcp-server-files", data, source="x")
    r100, r110 = pkg.release("1.0.0"), pkg.release("1.1.0")
    assert r100 is not None and r100.deprecated and "unsupported" in r100.deprecated
    assert r110 is not None and r110.has_install_script is True


@pytest.mark.parametrize("data", [[], "x", {"time": {}}, {"versions": []}])
def test_malformed_packument(data: object) -> None:
    with pytest.raises(MalformedResponse):
        parse_packument("p", data, source="x")


def test_unpublished_package() -> None:
    pkg = parse_packument("p", {"time": {"unpublished": {"time": "2026-01-01T00:00:00Z"}}}, source="x")
    assert pkg.unpublished and not pkg.releases


def test_scoped_name_is_encoded() -> None:
    assert npm_package_url("@demo/mcp-server-files") == "https://registry.npmjs.org/@demo%2Fmcp-server-files"
    assert npm_package_url("left-pad") == "https://registry.npmjs.org/left-pad"


@pytest.mark.parametrize(
    "name",
    [
        "../../etc/passwd",
        "..",
        "a/b/c",
        "@scope/../x",
        "pkg?x=1",
        "pkg#frag",
        "pkg name",
        "l\u0435ft-pad",  # Cyrillic e
        "パッケージ",
        "",
        "a" * 215,
        "@/x",
        "pkg%2F..",
    ],
)
def test_hostile_npm_names_are_refused(name: str) -> None:
    with pytest.raises(InvalidPackageName):
        validate_npm_name(name)


def test_semver_ordering() -> None:
    order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.10.0"]
    keys = [semver_key(v) for v in order]
    assert all(k is not None for k in keys)
    assert sorted(order, key=lambda v: semver_key(v)) == order  # type: ignore[arg-type, return-value]
    assert semver_key("not-a-version") is None


# --------------------------------------------------------------------------------------------- PyPI


def test_pypi_json_yanked_and_install_heuristic() -> None:
    project = parse_pypi_json("demo-mcp-server", json.loads(fixture("pypi-demo-mcp-server.json")), source="x")
    r = project.release("1.0.1")
    assert r is not None and r.yanked
    assert project.yank_reasons["1.0.1"].startswith("credential exfiltration")
    assert r.has_provenance is None  # unknown until the Simple API is read
    assert r.has_install_script is False  # ships a wheel
    assert project.latest == "1.1.0"


def test_pypi_simple_provenance() -> None:
    project = parse_pypi_json("demo-mcp-server", json.loads(fixture("pypi-demo-mcp-server.json")), source="x")
    apply_simple_index(project, json.loads(fixture("pypi-simple-demo-mcp-server.json")))
    r110, r100, r101 = project.release("1.1.0"), project.release("1.0.0"), project.release("1.0.1")
    assert r110 is not None and r110.has_provenance is True
    assert r100 is not None and r100.has_provenance is False
    assert r101 is not None and r101.has_provenance is None  # not listed: still unknown


@pytest.mark.parametrize("name", ["../x", "a/b", "-x", "x-", "ñame", "", "a b"])
def test_hostile_pypi_names_are_refused(name: str) -> None:
    with pytest.raises(InvalidPackageName):
        normalize_pypi_name(name)


def test_pypi_normalisation_and_pep440() -> None:
    assert normalize_pypi_name("Demo_MCP.Server") == "demo-mcp-server"
    order = ["1.0.dev1", "1.0a1", "1.0b2", "1.0rc1", "1.0", "1.0.post1", "1.1"]
    assert sorted(order, key=lambda v: pep440_key(v)) == order  # type: ignore[arg-type, return-value]
    assert pep440_key("1.0") == pep440_key("1.0.0")


# --------------------------------------------------------------------------------------------- OSV


def test_osv_mal_record_is_malicious() -> None:
    advs = parse_vulns(json.loads(fixture("osv-mal.json"))["vulns"], name="agent-cli-demo", ecosystem="npm")
    assert len(advs) == 1
    assert advs[0].malicious and advs[0].severity == "critical"
    assert advs[0].url == "https://osv.dev/vulnerability/MAL-2026-1234"


def test_osv_severity_fixed_and_pagination() -> None:
    client = FakeClient(
        osv={("@demo/mcp-server-files", "1.0.0"): "osv-vuln-page1.json"},
    )

    pages = {"page2": fixture("osv-vuln-page2.json")}

    def route(body: bytes | None) -> bytes:
        q = json.loads(body or b"{}")
        return pages[q["page_token"]] if "page_token" in q else fixture("osv-vuln-page1.json")

    client.osv[("@demo/mcp-server-files", "1.0.0")] = route
    res = query_osv(client, ecosystem="npm", name="@demo/mcp-server-files", version="1.0.0")
    assert [a.id for a in res.advisories] == [
        "GHSA-xxxx-yyyy-zzzz",
        "GHSA-cvss-only-0001",
        "GHSA-page-2222-3333",
    ]
    ghsa, cvss, page2 = res.advisories
    assert ghsa.severity == "high" and ghsa.fixed_in == ("1.1.0",) and ghsa.aliases == ("CVE-2026-0001",)
    assert cvss.severity == "critical"  # 9.8 from the CVSS v3.1 vector
    assert page2.severity == "unknown" and not page2.malicious
    assert res.pages == 2 and not res.truncated
    sent = [json.loads(b or b"{}") for m, u, b in client.calls if u == OSV]
    assert sent[0] == {"package": {"name": "@demo/mcp-server-files", "ecosystem": "npm"}, "version": "1.0.0"}
    assert sent[1]["page_token"] == "page2"


def test_osv_pagination_is_bounded() -> None:
    endless = json.dumps({"vulns": [], "next_page_token": "again"}).encode()
    client = FakeClient(osv={("p", "1.0.0"): endless})
    res = query_osv(client, ecosystem="npm", name="p", version="1.0.0")
    assert res.truncated and res.pages == MAX_PAGES
    assert len(client.calls) == MAX_PAGES


def test_osv_rejects_hostile_page_token() -> None:
    client = FakeClient(osv={("p", "1.0.0"): json.dumps({"next_page_token": "x" * 5000}).encode()})
    with pytest.raises(MalformedResponse):
        query_osv(client, ecosystem="npm", name="p", version="1.0.0")


def test_cvss3() -> None:
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss3_base_score("CVSS:2.0/AV:N") is None
    assert cvss3_base_score("CVSS:3.1/AV:N") is None


# --------------------------------------------------------------------------------------------- MCP Registry


def test_mcp_registry_exact_identifier_match() -> None:
    url = "https://registry.modelcontextprotocol.io/v0/servers?search=mcp-server-files&limit=100"
    client = FakeClient({url: "mcp-registry-files.json"})
    entry = lookup_server(client, ecosystem="npm", identifier="@demo/mcp-server-files")
    assert entry is not None
    assert entry.server_name == "io.github.demo/files"  # not the look-alike listing a different package
    assert entry.status == "deprecated" and entry.latest_version == "1.2.0"
    assert lookup_server(client, ecosystem="npm", identifier="mcp-server-files") is not None
    assert lookup_server(client, ecosystem="pypi", identifier="@demo/mcp-server-files") is None


def test_mcp_registry_search_term() -> None:
    assert search_term("@demo/mcp-server-files") == "mcp-server-files"
    assert search_term("ghcr.io/org/image") == "image"
    assert search_term("we ird&x=1") is None


@pytest.mark.parametrize(
    "value", ["0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00", "not a time", 12, "9" * 65]
)
def test_parse_time_refuses_out_of_range_and_malformed(value: object) -> None:
    assert parse_time(value) is None


def test_parse_time_normalises_to_utc() -> None:
    assert parse_time("2026-01-01T05:00:00+05:00") == datetime(2026, 1, 1, tzinfo=UTC)


def test_pypi_release_with_an_unattested_file_has_no_provenance() -> None:
    data = json.loads(fixture("pypi-demo-mcp-server.json"))
    extra = "demo_mcp_server-1.1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
    data["releases"]["1.1.0"].append({"filename": extra, "packagetype": "bdist_wheel"})
    project = parse_pypi_json("demo-mcp-server", data, source="x")
    simple = json.loads(fixture("pypi-simple-demo-mcp-server.json"))
    simple["files"].append({"filename": extra, "provenance": None})
    apply_simple_index(project, simple)
    r110 = project.release("1.1.0")
    assert r110 is not None and r110.has_provenance is False
    assert project.unattested_files == {"1.1.0": (extra,)}


_REG = "https://registry.modelcontextprotocol.io/v0/servers?search=mcp-server-files&limit=100"


def _other_page(cursor: object) -> bytes:
    server = {"name": "io.x/other", "version": "1", "packages": [{"registryType": "npm", "identifier": "o"}]}
    return json.dumps({"servers": [{"server": server}], "metadata": {"nextCursor": cursor}}).encode()


def test_mcp_registry_truncated_search_raises_instead_of_none() -> None:
    routes: dict[str, Route] = {_REG: _other_page("c1")}
    routes[_REG + "&cursor=c1"] = _other_page("c2")
    routes[_REG + "&cursor=c2"] = _other_page("c3")
    with pytest.raises(SearchTruncated):
        lookup_server(FakeClient(routes), ecosystem="npm", identifier="@demo/mcp-server-files")


def test_mcp_registry_truncated_search_with_a_match_is_marked() -> None:
    page = json.loads(fixture("mcp-registry-files.json"))
    page["metadata"] = {"nextCursor": "c1"}
    routes: dict[str, Route] = {_REG: json.dumps(page).encode()}
    routes[_REG + "&cursor=c1"] = _other_page("c2")
    routes[_REG + "&cursor=c2"] = _other_page("c3")
    entry = lookup_server(FakeClient(routes), ecosystem="npm", identifier="@demo/mcp-server-files")
    assert entry is not None and entry.truncated


@pytest.mark.parametrize("cursor", ["bad cursor with spaces", 7, {"x": 1}])
def test_mcp_registry_unfollowable_cursor_is_malformed(cursor: object) -> None:
    with pytest.raises(MalformedResponse, match="cursor"):
        lookup_server(
            FakeClient({_REG: _other_page(cursor)}), ecosystem="npm", identifier="@demo/mcp-server-files"
        )


def test_osv_git_ranges_and_withdrawn_records() -> None:
    sha = "a" * 40
    vulns = [
        {
            "id": "GHSA-aaaa-bbbb-cccc",
            "summary": "s",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "pkg"},
                    "ranges": [
                        {"type": "GIT", "repo": "https://x", "events": [{"introduced": "0"}, {"fixed": sha}]},
                        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]},
                    ],
                }
            ],
        },
        {"id": "GHSA-dddd-eeee-ffff", "summary": "retracted", "withdrawn": "2026-01-01T00:00:00Z"},
    ]
    [adv] = parse_vulns(vulns, name="pkg", ecosystem="npm")
    assert adv.id == "GHSA-aaaa-bbbb-cccc"
    assert adv.fixed_in == ("1.2.3",)  # the commit hash is not an installable version
