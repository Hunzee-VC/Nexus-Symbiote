"""advisories: gate semantics, honest coverage, batch isolation and what is sent to OSV."""

from __future__ import annotations

import hashlib
import http.client
import json
from types import SimpleNamespace
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote import advisories
from nexus_symbiote.advisories import fetch_advisories, mcp_package_identity
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import MCPServerComponent, RegistryEntryComponent
from nexus_symbiote.scanners.live_mcp import HTTPReply


def package(name: str = "requests", version: str = "2.19.0", **extra: Any):
    return RegistryEntryComponent(
        bom_ref=f"registry:pypi/{name}",
        name=name,
        version="==" + version,
        registry_type="pypi",
        package_url=f"pkg:pypi/{name}@{version}",
        **extra,
    )


def npm(name: str, version: str = "1.2.3", **extra: Any):
    return RegistryEntryComponent(
        bom_ref=f"registry:npm/{name}",
        name=name,
        version=version,
        registry_type="npm",
        package_url=f"pkg:npm/{name.replace('@', '%40')}@{version}",
        **extra,
    )


class Scripted:
    """Answer each batch from a function of the posted queries."""

    def __init__(self, answer):
        self.answer, self.calls = answer, []

    def request(self, endpoint, body, headers, *, timeout, max_bytes):
        queries = json.loads(body)["queries"]
        self.calls.append(queries)
        result = self.answer(queries, len(self.calls))
        if isinstance(result, Exception):
            raise result
        return HTTPReply(200, {"content-type": "application/json"}, json.dumps(result).encode())


def clean(queries, _):
    return {"results": [{} for _ in queries]}


def test_found_advisories_are_kept_across_pages_and_fail_the_command(tmp_path, monkeypatch):
    def paged(queries, call):
        first = {"vulns": [{"id": "GHSA-one"}], "next_page_token": "p2"}
        if call == 1:
            return {"results": [first]}
        assert queries[0]["page_token"] == "p2"  # noqa: S105 - an OSV page cursor
        return {"results": [{"vulns": [{"id": "GHSA-two"}]}]}

    transport = Scripted(paged)
    report = fetch_advisories(AIBOM(components=[package()]), transport=transport)
    assert report.complete and report.coverage == "complete"
    assert [a["advisory_id"] for a in report.advisories] == ["GHSA-one", "GHSA-two"]
    path = tmp_path / "bom.json"
    path.write_text(AIBOM(components=[package()]).to_json())
    monkeypatch.setattr(advisories, "PinnedHTTPTransport", lambda: Scripted(paged))
    failing = CliRunner().invoke(main, ["--live", "advisories", str(path)])
    assert failing.exit_code == 1
    document = json.loads(failing.stdout)
    assert document["inventory_sha256"] == "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    assert document["checked_at"] and document["tool_version"]
    tolerated = CliRunner().invoke(
        main, ["--live", "advisories", str(path), "--no-fail-on-advisory"]
    )
    assert tolerated.exit_code == 0


def test_inventory_without_queryable_packages_reports_no_coverage(tmp_path):
    bom = AIBOM(
        components=[RegistryEntryComponent(bom_ref="oci:a", name="a", registry_type="docker")]
    )
    report = fetch_advisories(bom, transport=Scripted(clean))
    assert (report.coverage, report.complete) == ("none", False)
    assert report.components_skipped == 1
    assert report.skipped == [{"component_ref": "oci:a", "reason": "ecosystem is not queried"}]
    path = tmp_path / "bom.json"
    path.write_text(bom.to_json())
    result = CliRunner().invoke(main, ["--live", "advisories", str(path)])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["coverage"] == "none"


def test_one_failed_batch_keeps_other_results(monkeypatch):
    monkeypatch.setattr(advisories, "BATCH_SIZE", 1)

    def flaky(queries, call):
        if call == 2:
            return http.client.IncompleteRead(b"partial")
        return {"results": [{"vulns": [{"id": f"GHSA-{call}"}]}]}

    bom = AIBOM(components=[package("a"), package("b"), package("c")])
    report = fetch_advisories(bom, transport=Scripted(flaky))
    assert report.components_checked == 2
    assert report.errors == ["registry:pypi/b: OSV request failed or exceeded its limits"]
    assert [a["advisory_id"] for a in report.advisories] == ["GHSA-1", "GHSA-3"]
    assert report.coverage == "partial" and not report.complete


@pytest.mark.parametrize(
    "answer,reason",
    [
        (lambda q, c: {"results": []}, "OSV reply was malformed or reported an error"),
        (lambda q, c: {"results": [{"vulns": [{"id": "bad id!"}]}]}, "malformed"),
        (lambda q, c: {"results": [{"next_page_token": "same"}]}, "repeats a page"),
        (lambda q, c: {"results": [{"next_page_token": f"t{c}"}]}, "per-package limit"),
        (lambda q, c: {"error": "quota"}, "malformed or reported an error"),
    ],
)
def test_malformed_or_endless_replies_are_recorded_per_component(answer, reason):
    report = fetch_advisories(AIBOM(components=[package()]), transport=Scripted(answer))
    assert len(report.errors) == 1 and reason in report.errors[0]
    assert not report.complete


def test_component_limit_is_reported_without_any_lookup(monkeypatch):
    monkeypatch.setattr(advisories, "MAX_COMPONENTS", 2)
    transport = Scripted(clean)
    report = fetch_advisories(
        AIBOM(components=[package("a"), package("b"), package("c")]), transport=transport
    )
    assert report.errors == ["package component limit exceeded; no lookups performed"]
    assert transport.calls == []


def test_exclusions_and_private_origins_are_never_sent():
    bom = AIBOM(
        components=[
            npm("@acme/mcp-billing", registry_uri="https://npm.acme.internal"),
            npm("left-pad", registry_uri="https://registry.npmjs.org"),
            package("Acme_Internal-Tools"),
            package("requests"),
        ]
    )
    transport = Scripted(clean)
    report = fetch_advisories(
        bom, transport=transport, exclude=["acme-internal*"], exclude_private_origins=True
    )
    sent = [query["package"]["name"] for batch in transport.calls for query in batch]
    assert sent == ["left-pad", "requests"]
    assert report.components_excluded == 2
    assert {e["reason"] for e in report.excluded} == {
        "excluded by the operator",
        "resolved from a non-public registry origin",
    }
    assert report.complete


def test_private_packages_are_sent_unless_excluded():
    transport = Scripted(clean)
    fetch_advisories(
        AIBOM(components=[npm("@acme/mcp-billing", registry_uri="https://npm.acme.internal")]),
        transport=transport,
    )
    assert transport.calls == [
        [{"package": {"name": "@acme/mcp-billing", "ecosystem": "npm"}, "version": "1.2.3"}]
    ]


def test_dry_run_lists_identities_offline_and_sends_nothing(tmp_path):
    path = tmp_path / "bom.json"
    path.write_text(AIBOM(components=[package(), npm("left-pad")]).to_json())
    result = CliRunner().invoke(main, ["advisories", str(path), "--dry-run"])
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["dry_run"] is True and document["sent_to_osv"] == "nothing (dry run)"
    assert [(q["ecosystem"], q["name"], q["version"]) for q in document["queries"]] == [
        ("PyPI", "requests", "2.19.0"),
        ("npm", "left-pad", "1.2.3"),
    ]


def test_mcp_launcher_package_identity_is_reconciled():
    server = SimpleNamespace(
        package_url="pkg:npm/mcp-remote@0.1.15", launcher_package="npm:mcp-remote", version="0.1.15"
    )
    assert mcp_package_identity(server) == ("npm", "mcp-remote", "0.1.15")  # type: ignore[arg-type]
    for mismatch in (
        {"version": "0.1.16"},
        {"launcher_package": "npm:other"},
        {"launcher_package": "pypi:mcp-remote"},
        {"package_url": "pkg:npm/mcp-remote@latest"},
    ):
        with pytest.raises(ValueError):
            mcp_package_identity(SimpleNamespace(**{**vars(server), **mismatch}))  # type: ignore[arg-type]


@pytest.mark.skipif(
    "package_url" not in MCPServerComponent.model_fields,
    reason="MCP server package URLs are recorded by the MCP collector",
)
def test_mcp_servers_with_exact_package_urls_are_queried():
    server = MCPServerComponent(
        bom_ref="mcp:remote",
        name="remote",
        launcher_package="npm:mcp-remote",
        version="0.1.15",
        package_url="pkg:npm/mcp-remote@0.1.15",  # type: ignore[call-arg]
    )
    transport = Scripted(lambda q, c: {"results": [{"vulns": [{"id": "GHSA-6xpm-ggf7-wc3p"}]}]})
    report = fetch_advisories(AIBOM(components=[server]), transport=transport)
    assert report.complete
    assert report.advisories[0]["component_ref"] == "mcp:remote"


def test_exhausted_lookup_budget_is_an_error_not_a_clean_result(monkeypatch):
    monkeypatch.setattr(advisories, "TOTAL_TIMEOUT_SECONDS", 0.0)
    transport = Scripted(clean)
    report = fetch_advisories(AIBOM(components=[package()]), transport=transport)
    assert report.errors == ["registry:pypi/requests: OSV lookup deadline exceeded"]
    assert transport.calls == [] and not report.complete
