"""advisories: gate semantics, honest coverage, batch isolation and what is sent to OSV."""

from __future__ import annotations

import hashlib
import http.client
import itertools
import json
import time
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
from nexus_symbiote.scanners.registry import RegistryScanner


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


def sent_names(transport: Scripted) -> list[str]:
    return [query["package"]["name"] for batch in transport.calls for query in batch]


def test_operator_exclusions_are_never_sent():
    transport = Scripted(clean)
    report = fetch_advisories(
        AIBOM(components=[package("Acme_Internal-Tools"), package("requests")]),
        transport=transport,
        exclude=["acme-internal*"],
    )
    assert sent_names(transport) == ["requests"]
    assert report.excluded == [
        {"component_ref": "registry:pypi/Acme_Internal-Tools", "reason": "excluded by the operator"}
    ]
    assert report.complete


@pytest.mark.parametrize("pattern", ["@Corp/*", "@CORP/billing"])
def test_npm_exclusions_withhold_a_name_written_in_another_case(pattern):
    transport = Scripted(clean)
    report = fetch_advisories(
        AIBOM(components=[npm("@corp/billing"), npm("openai")]),
        transport=transport,
        exclude=[pattern],
    )
    assert sent_names(transport) == ["openai"]
    assert report.excluded[0]["component_ref"] == "registry:npm/@corp/billing"


@pytest.mark.parametrize("pattern", ["*billing", "@corp/*-internal", "a**"])
def test_an_exclusion_with_a_star_before_its_end_is_refused(pattern):
    transport = Scripted(clean)
    with pytest.raises(ValueError, match="only as its last character"):
        fetch_advisories(
            AIBOM(components=[npm("@corp/billing")]), transport=transport, exclude=[pattern]
        )
    assert transport.calls == []


def test_component_limit_report_says_that_nothing_was_sent(monkeypatch):
    monkeypatch.setattr(advisories, "MAX_COMPONENTS", 2)
    report = fetch_advisories(
        AIBOM(components=[package("a"), package("b"), package("c")]), transport=Scripted(clean)
    )
    assert report.to_dict()["sent_to_osv"] == "nothing (package component limit exceeded)"


def test_private_origin_exclusion_sends_only_lockfile_backed_public_packages(tmp_path):
    dependencies = {"@modelcontextprotocol/sdk": "1.2.3", "mcp-billing": "1.0.0", "openai": "4.0.0"}
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": dependencies}))
    resolved = {
        "@modelcontextprotocol/sdk": "https://registry.npmjs.org/@modelcontextprotocol/sdk/-/sdk-1.2.3.tgz",
        "mcp-billing": "https://npm.acme.internal/mcp-billing/-/mcp-billing-1.0.0.tgz",
    }
    lock = {
        "lockfileVersion": 3,
        "packages": {
            f"node_modules/{name}": {"version": dependencies[name], "resolved": url}
            for name, url in resolved.items()
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    (tmp_path / "requirements.txt").write_text("mcp-acme-tools==1.0.0\n")
    bom = AIBOM(components=RegistryScanner().scan(tmp_path).components)
    transport = Scripted(clean)
    report = fetch_advisories(bom, transport=transport, exclude_private_origins=True)
    assert sent_names(transport) == ["@modelcontextprotocol/sdk"]
    withheld = {bom.get_component(e["component_ref"]).name: e["reason"] for e in report.excluded}
    unrecorded = "registry origin is not recorded by a lockfile resolution"
    assert withheld == {
        "mcp-billing": "resolved from a non-public registry origin",
        "openai": unrecorded,
        "mcp-acme-tools": unrecorded,
    }
    # Without a lockfile, a public PyPI label is assumed, so it is not evidence of the origin.
    labelled = package("acme-internal-tools", registry_uri="https://pypi.org")
    quiet = Scripted(clean)
    fetch_advisories(AIBOM(components=[labelled]), transport=quiet, exclude_private_origins=True)
    assert quiet.calls == []


def test_a_package_resolved_from_another_registry_is_sent_unless_excluded(tmp_path):
    # The registry collector names the registry a lockfile resolved a package from in
    # its package URL. That qualifier is accepted for the component's own registry, so
    # the default (private registries are sent) and both exclusions apply to it.
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"mcp-billing": "1.0.0"}}))
    resolved = "https://npm.acme.internal/mcp-billing/-/mcp-billing-1.0.0.tgz"
    record = {"version": "1.0.0", "resolved": resolved}
    lock = {"lockfileVersion": 3, "packages": {"node_modules/mcp-billing": record}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    bom = AIBOM(components=RegistryScanner().scan(tmp_path).components)
    (component,) = bom.components
    assert component.package_url == (
        "pkg:npm/mcp-billing@1.0.0?repository_url=https://npm.acme.internal"
    )
    sent = Scripted(clean)
    assert fetch_advisories(bom, transport=sent).complete
    assert sent_names(sent) == ["mcp-billing"]
    named = Scripted(clean)
    report = fetch_advisories(bom, transport=named, exclude=["mcp-billing"])
    assert named.calls == [] and report.excluded[0]["reason"] == "excluded by the operator"
    # A qualifier that names another registry than the component's is not its identity.
    forged = component.model_copy(
        update={
            "package_url": "pkg:npm/mcp-billing@1.0.0?repository_url=https://registry.npmjs.org"
        }
    )
    quiet = Scripted(clean)
    report = fetch_advisories(AIBOM(components=[forged]), transport=quiet)
    assert quiet.calls == [] and report.errors


@pytest.mark.parametrize(
    "lock_name, public_source, private_source",
    [
        (
            "uv.lock",
            'source = { registry = "https://pypi.org/simple" }',
            'source = { registry = "https://pypi.acme.internal/simple" }',
        ),
        (
            "poetry.lock",
            "",
            'source = { type = "legacy", url = "https://pypi.acme.internal/simple" }',
        ),
    ],
)
def test_private_origin_exclusion_follows_python_lockfile_resolutions(
    tmp_path, lock_name, public_source, private_source
):
    # uv.lock and poetry.lock record the index each Python package was resolved from, so
    # a package resolved from the public index is sent and one from a private index is not.
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["langgraph>=0.2.0", "mcp-acme-tools>=1.0"]\n'
    )
    (tmp_path / lock_name).write_text(
        "version = 1\n\n"
        f'[[package]]\nname = "langgraph"\nversion = "0.2.14"\n{public_source}\n\n'
        f'[[package]]\nname = "mcp-acme-tools"\nversion = "1.0.0"\n{private_source}\n'
    )
    bom = AIBOM(components=RegistryScanner().scan(tmp_path).components)
    transport = Scripted(clean)
    report = fetch_advisories(bom, transport=transport, exclude_private_origins=True)
    assert sent_names(transport) == ["langgraph"]
    withheld = {bom.get_component(e["component_ref"]).name: e["reason"] for e in report.excluded}
    assert withheld == {"mcp-acme-tools": "resolved from a non-public registry origin"}


def test_private_packages_are_sent_by_default():
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
    # Queries follow the inventory's canonical component order, not insertion order.
    assert sorted((q["ecosystem"], q["name"], q["version"]) for q in document["queries"]) == [
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
        {"package_url": "pkg:npm/mcp-remote@latest", "version": "latest"},
    ):
        with pytest.raises(ValueError, match="disagrees|exact"):
            mcp_package_identity(SimpleNamespace(**{**vars(server), **mismatch}))  # type: ignore[arg-type]


def test_mcp_servers_with_exact_package_urls_are_queried():
    server = MCPServerComponent(
        bom_ref="mcp:remote",
        name="remote",
        launcher_package="npm:mcp-remote",
        version="0.1.15",
        package_url="pkg:npm/mcp-remote@0.1.15",
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


def test_a_reply_near_the_size_limit_is_read_in_linear_time_and_bounded():
    ids = [{"id": f"G{index}"} for index in range(advisories.MAX_ADVISORIES_PER_PACKAGE)]
    transport = Scripted(lambda queries, _: {"results": [{"vulns": ids} for _ in queries]})
    bom = AIBOM(components=[package(f"pkg{index}") for index in range(24)])
    started = time.monotonic()
    report = fetch_advisories(bom, transport=transport)
    # 240,000 records in one reply of about 4 MB; checked one by one against the
    # growing list, the same reply took hours.
    assert time.monotonic() - started < 15
    assert len(report.advisories) == advisories.MAX_ADVISORIES
    assert report.components_checked == 2 and report.coverage == "partial"
    assert len(report.errors) == 22
    assert all(e.endswith(": OSV advisories exceed the report limit") for e in report.errors)


def test_report_limit_stops_later_batches_without_sending_them(monkeypatch):
    monkeypatch.setattr(advisories, "BATCH_SIZE", 1)
    monkeypatch.setattr(advisories, "MAX_ADVISORIES", 2)
    transport = Scripted(lambda q, c: {"results": [{"vulns": [{"id": "X1"}, {"id": "X2"}]}]})
    report = fetch_advisories(
        AIBOM(components=[package("a"), package("b"), package("c")]), transport=transport
    )
    assert len(transport.calls) == 1
    assert report.components_checked == 1 and len(report.advisories) == 2
    assert report.errors == [
        "registry:pypi/b: OSV advisories exceed the report limit",
        "registry:pypi/c: OSV advisories exceed the report limit",
    ]


def test_per_package_limit_spans_pages_and_stops_only_that_package(monkeypatch):
    monkeypatch.setattr(advisories, "MAX_ADVISORIES_PER_PACKAGE", 3)

    def paged(queries, _):
        results = []
        for query in queries:
            if query["package"]["name"] != "a":
                results.append({"vulns": [{"id": "B1"}]})
            elif "page_token" not in query:
                ids = ["A1", "A1", "A2"]
                results.append({"vulns": [{"id": i} for i in ids], "next_page_token": "p2"})
            else:
                results.append({"vulns": [{"id": i} for i in ("A2", "A3", "A4")]})
        return {"results": results}

    report = fetch_advisories(
        AIBOM(components=[package("a"), package("b")]), transport=Scripted(paged)
    )
    # Repeated identifiers are recorded once and do not count toward the limit.
    assert [a["advisory_id"] for a in report.advisories] == ["A1", "A2", "B1", "A3"]
    assert report.errors == [
        "registry:pypi/a: OSV advisories for this package exceed the per-package limit"
    ]
    assert report.components_checked == 1 and report.coverage == "partial"


def test_deadline_is_checked_while_a_reply_is_read(monkeypatch):
    ticks = itertools.count()
    monkeypatch.setattr(advisories, "time", SimpleNamespace(monotonic=lambda: float(next(ticks))))
    many = [{"id": f"GHSA-{index}"} for index in range(500)]

    def reply(queries, _):
        return {"results": [{"vulns": many}, {}]}

    report = fetch_advisories(
        AIBOM(components=[package("a"), package("b")]), transport=Scripted(reply)
    )
    assert 0 < len(report.advisories) < len(many)
    assert report.errors == [
        "registry:pypi/a: OSV lookup deadline exceeded",
        "registry:pypi/b: OSV lookup deadline exceeded",
    ]
    assert not report.complete
