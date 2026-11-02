"""check_dependencies on recorded fixtures (no network)."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from symbiote.advisories import (
    DependencyIntel,
    DependencyKind,
    DependencyRef,
    Ecosystem,
    HttpClient,
    NotFound,
    SignalKind,
    Unreachable,
    check_dependencies,
)
from symbiote.advisories.inventory import hosted_model_purl
from symbiote.update.types import UpdatePolicy

from ._support import NOW, OSV, FakeClient, Route, fixture

NPM_CLI = "https://registry.npmjs.org/agent-cli-demo"
NPM_FILES = "https://registry.npmjs.org/@demo%2Fmcp-server-files"
PYPI_JSON = "https://pypi.org/pypi/demo-mcp-server/json"
PYPI_SIMPLE = "https://pypi.org/simple/demo-mcp-server/"
MCPREG = "https://registry.modelcontextprotocol.io/v0/servers?search={}&limit=100"
EMPTY_REG = b'{"servers": [], "metadata": {"count": 0}}'


def _routes() -> dict[str, Route]:
    return {
        NPM_CLI: "npm-agent-cli-demo.json",
        NPM_FILES: "npm-scoped-files.json",
        PYPI_JSON: "pypi-demo-mcp-server.json",
        PYPI_SIMPLE: "pypi-simple-demo-mcp-server.json",
        MCPREG.format("agent-cli-demo"): EMPTY_REG,
        MCPREG.format("demo-mcp-server"): EMPTY_REG,
        MCPREG.format("mcp-server-files"): "mcp-registry-files.json",
    }


def _client() -> FakeClient:
    return FakeClient(_routes())


def _npm(name: str = "agent-cli-demo", version: str | None = "2.2.3") -> DependencyRef:
    return DependencyRef(
        kind=DependencyKind.MCP_SERVER_PACKAGE,
        ecosystem="npm",
        name=name,
        version=version,
        subjects=("server:cli",),
        locators=(".mcp.json#/mcpServers/cli",),
        purl=f"pkg:npm/{name}" + (f"@{version}" if version else ""),
    )


def _one(ref: DependencyRef, client: HttpClient, policy: UpdatePolicy | None = None) -> DependencyIntel:
    [intel] = check_dependencies([ref], client=client, now=NOW, policy=policy)
    return intel


def _kinds(intel: DependencyIntel) -> dict[SignalKind, list[str | None]]:
    out: dict[SignalKind, list[str | None]] = {}
    for s in intel.signals:
        out.setdefault(s.kind, []).append(s.reference)
    return out


def test_clinejection_shaped_release_is_flagged_and_skipped() -> None:
    intel = _one(_npm(), _client())
    kinds = _kinds(intel)
    assert intel.coverage == "queried", intel.errors
    assert intel.current is not None and intel.current.version == "2.2.3"
    assert intel.latest is not None and intel.latest.version == "2.5.0"
    # 2.3.0: no provenance after provenance, a new publisher, a new postinstall script.
    assert "2.3.0" in kinds[SignalKind.PROVENANCE_DOWNGRADE]
    assert "2.3.0" in kinds[SignalKind.PUBLISHER_CHANGED]
    assert "2.3.0" in kinds[SignalKind.INSTALL_SCRIPT_ADDED]
    # 2.4.0 restores provenance and the usual publisher: no history signal for it.
    assert all(s.reference != "2.4.0" for s in intel.signals if s.kind is not SignalKind.NEWER_VERSION)
    # 2.5.0 is 51 hours old: inside the 7-day cooldown.
    assert kinds[SignalKind.FRESH_RELEASE] == ["2.5.0"]
    # 3.0.0 is a different major; 2.5.0 is fresh; 2.3.0 is refused -> 2.4.0.
    assert intel.recommended is not None and intel.recommended.version == "2.4.0"
    assert kinds[SignalKind.NEWER_VERSION] == ["2.4.0"]
    assert SignalKind.VULNERABLE not in kinds and SignalKind.MALICIOUS not in kinds
    assert intel.sources[0] == NPM_CLI
    assert any(s.startswith(OSV) for s in intel.sources)


def test_recommendation_never_lands_on_the_downgraded_release() -> None:
    # Even when 2.3.0 is the newest release, it is not recommended.
    data = json.loads(fixture("npm-agent-cli-demo.json"))
    for v in ("2.4.0", "2.5.0", "3.0.0", "3.1.0-beta.1"):
        del data["versions"][v]
    data["dist-tags"]["latest"] = "2.3.0"
    client = _client()
    client.routes[NPM_CLI] = json.dumps(data).encode()
    intel = _one(_npm(), client)
    assert intel.recommended is None
    assert SignalKind.NEWER_VERSION not in _kinds(intel)
    assert "2.3.0" in _kinds(intel)[SignalKind.PROVENANCE_DOWNGRADE]


def test_allow_major_and_zero_cooldown() -> None:
    intel = _one(_npm(), _client(), UpdatePolicy(cooldown_days=0))
    assert intel.recommended is not None and intel.recommended.version == "2.5.0"
    assert SignalKind.FRESH_RELEASE not in _kinds(intel)
    intel = _one(_npm(), _client(), UpdatePolicy(cooldown_days=0, allow_major=True))
    assert intel.recommended is not None and intel.recommended.version == "3.0.0"


def test_provenance_continuity_can_be_disabled() -> None:
    policy = UpdatePolicy(require_provenance_continuity=False, block_new_install_scripts=False)
    client = _client()
    intel = _one(_npm(), client, policy)
    # 2.4.0 is still newer than 2.3.0, so the recommendation does not change, but 2.3.0 was not refused for it.
    assert intel.recommended is not None and intel.recommended.version == "2.4.0"


def test_malicious_current_version_uses_security_cooldown() -> None:
    client = FakeClient(_routes(), osv={("agent-cli-demo", "2.3.0"): "osv-mal.json"})
    intel = _one(_npm(version="2.3.0"), client)
    kinds = _kinds(intel)
    assert kinds[SignalKind.MALICIOUS] == ["MAL-2026-1234"]
    assert intel.advisories[0].malicious
    assert "2.3.0" in kinds[SignalKind.PROVENANCE_DOWNGRADE]  # the version in use
    # 2.5.0 is 51 hours old: inside the 7-day cooldown but outside the 2-day security cooldown.
    assert intel.recommended is not None and intel.recommended.version == "2.5.0"
    assert any("security cooldown" in s.detail for s in intel.signals if s.kind is SignalKind.NEWER_VERSION)
    intel = _one(_npm(version="2.3.0"), client, UpdatePolicy(security_cooldown_days=3))
    assert intel.recommended is not None and intel.recommended.version == "2.4.0"


def test_candidate_with_advisory_is_skipped() -> None:
    client = FakeClient(_routes(), osv={("agent-cli-demo", "2.4.0"): "osv-mal.json"})
    intel = _one(_npm(), client)
    assert intel.recommended is None  # 2.4.0 has an advisory, 2.3.0 is refused, 2.2.3 is current


def test_candidate_advisories_unreachable_means_no_recommendation() -> None:
    client = FakeClient(_routes(), osv={("agent-cli-demo", "2.4.0"): Unreachable("down")})
    intel = _one(_npm(), client)
    assert intel.recommended is None
    assert intel.coverage == "partial"
    assert any("could not be checked" in e for e in intel.errors)
    assert SignalKind.NEWER_VERSION not in _kinds(intel)


def test_floating_reference() -> None:
    intel = _one(_npm(version=None), _client())
    kinds = _kinds(intel)
    assert SignalKind.FLOATING in kinds
    assert intel.current is None
    assert intel.recommended is not None and intel.recommended.version == "2.4.0"
    # OSV was asked about the version the floating reference resolves to today.
    assert any(s.endswith("agent-cli-demo@2.5.0)") for s in intel.sources)


def test_scoped_floating_package_with_deprecated_registry_entry() -> None:
    intel = _one(_npm("@demo/mcp-server-files", None), _client())
    kinds = _kinds(intel)
    assert SignalKind.FLOATING in kinds
    assert "io.github.demo/files" in kinds[SignalKind.DEPRECATED]
    assert NPM_FILES in intel.sources


def test_deprecated_pin() -> None:
    intel = _one(_npm("@demo/mcp-server-files", "1.0.0"), _client())
    kinds = _kinds(intel)
    assert "1.0.0" in kinds[SignalKind.DEPRECATED]
    assert intel.recommended is not None and intel.recommended.version == "1.2.0"


def test_pypi_yanked_pin() -> None:
    ref = DependencyRef(
        kind=DependencyKind.MCP_SERVER_PACKAGE, ecosystem="pypi", name="Demo_MCP_Server", version="1.0.1"
    )
    intel = _one(ref, _client())
    kinds = _kinds(intel)
    assert intel.coverage == "queried", intel.errors
    assert kinds[SignalKind.YANKED] == ["1.0.1"]
    assert any("credential exfiltration" in s.detail for s in intel.signals)
    assert intel.recommended is not None and intel.recommended.version == "1.1.0"  # 2.0.0rc1 is a pre-release
    assert intel.recommended.has_provenance is True


def test_pypi_without_simple_api_is_partial() -> None:
    client = _client()
    del client.routes[PYPI_SIMPLE]
    ref = DependencyRef(
        kind=DependencyKind.SOFTWARE_COMPONENT, ecosystem="pypi", name="demo-mcp-server", version="1.1.0"
    )
    intel = _one(ref, client)
    assert intel.coverage == "partial"
    assert intel.current is not None and intel.current.has_provenance is None


@pytest.mark.parametrize("version", ["2.2.3", None])
def test_offline_is_unreachable_and_never_clean(version: str | None) -> None:
    intel = _one(_npm(version=version), HttpClient(offline=True))
    kinds = _kinds(intel)
    assert intel.coverage == "unreachable"
    assert intel.errors
    assert intel.recommended is None and intel.latest is None
    assert SignalKind.NEWER_VERSION not in kinds and SignalKind.FRESH_RELEASE not in kinds
    assert (SignalKind.FLOATING in kinds) == (version is None)


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[" * 200 + b"]" * 200,
        b'{"name": "agent-cli-demo"}',  # no versions
        b'["a list"]',
    ],
)
def test_malformed_registry_answer_is_not_clean(body: bytes) -> None:
    client = _client()
    client.routes[NPM_CLI] = body
    intel = _one(_npm(), client)
    assert intel.coverage in ("partial", "unreachable")
    assert any("registry lookup failed" in e for e in intel.errors)
    assert intel.recommended is None


def test_oversized_registry_answer_is_not_clean() -> None:
    client = FakeClient(_routes(), max_bytes=1024)
    intel = _one(_npm(), client)
    assert intel.coverage in ("partial", "unreachable")
    assert any("ResponseTooLarge" in e for e in intel.errors)


def test_package_missing_from_registry() -> None:
    client = _client()
    client.routes[NPM_CLI] = NotFound("HTTP 404", url=NPM_CLI, status=404)
    intel = _one(_npm(), client)
    assert SignalKind.YANKED in _kinds(intel)
    assert intel.recommended is None


@pytest.mark.parametrize(
    ("ecosystem", "name", "version"),
    [
        ("npm", "../../../etc/passwd", "1.0.0"),
        ("npm", "l\u0435ft-pad", "1.0.0"),
        ("npm", "left-pad", "1.0.0/../../x"),
        ("pypi", "../x", "1.0"),
        ("pypi", "ok", "1.0 ; rm -rf /"),
    ],
)
def test_hostile_names_are_refused_without_a_request(ecosystem: Ecosystem, name: str, version: str) -> None:
    client = _client()
    ref = DependencyRef(
        kind=DependencyKind.SOFTWARE_COMPONENT, ecosystem=ecosystem, name=name, version=version
    )
    intel = _one(ref, client)
    assert intel.coverage == "not-attempted"
    assert client.calls == []
    assert intel.errors and "refused" in intel.errors[0]


def test_hosted_model_retirement() -> None:
    ref = DependencyRef(
        kind=DependencyKind.HOSTED_MODEL,
        ecosystem="hosted-model",
        name="claude-sonnet-4-5-20250929",
        version="claude-sonnet-4-5-20250929",
        purl=hosted_model_purl("anthropic", "claude-sonnet-4-5-20250929"),
    )
    client = _client()
    intel = _one(ref, client)
    [sig] = [s for s in intel.signals if s.kind is SignalKind.RETIRING_MODEL]
    assert "2026-11-30" in sig.detail and "28 days" in sig.detail and "confidence: medium" in sig.detail
    assert sig.severity == "high"
    assert client.calls == []
    # After the date it is retired: critical.
    [late] = check_dependencies([ref], client=client, now=NOW + timedelta(days=40))
    assert [s.severity for s in late.signals if s.kind is SignalKind.RETIRING_MODEL] == ["critical"]


def test_floating_hosted_alias() -> None:
    ref = DependencyRef(
        kind=DependencyKind.HOSTED_MODEL,
        ecosystem="hosted-model",
        name="claude-sonnet-4-5",
        version=None,
        purl=hosted_model_purl("anthropic", "claude-sonnet-4-5"),
    )
    kinds = _kinds(_one(ref, _client()))
    assert SignalKind.FLOATING in kinds and SignalKind.RETIRING_MODEL in kinds


@pytest.mark.parametrize(
    ("kind", "ecosystem"),
    [
        (DependencyKind.SKILL, "skill"),
        (DependencyKind.A2A_PEER, "a2a"),
        (DependencyKind.MCP_SERVER_REMOTE, "mcp-registry"),
        (DependencyKind.LOCAL_MODEL, "huggingface"),
        (DependencyKind.SOFTWARE_COMPONENT, "oci"),
    ],
)
def test_kinds_without_an_advisor_are_not_attempted(kind: DependencyKind, ecosystem: Ecosystem) -> None:
    ref = DependencyRef(kind=kind, ecosystem=ecosystem, name="x", version="sha256:" + "0" * 64)
    intel = _one(ref, _client())
    assert intel.coverage == "not-attempted" and intel.errors
    assert intel.recommended is None and not intel.signals


def test_order_preserved_and_failures_isolated() -> None:
    refs = [_npm(), _npm("@demo/mcp-server-files", "1.2.0"), _npm("missing-pkg", "1.0.0")]
    out = check_dependencies(refs, client=_client(), now=NOW)
    assert [i.ref for i in out] == refs
    assert out[2].coverage == "partial"  # registry unreachable, OSV answered (empty)
    assert out[0].coverage == "queried"


# --------------------------------------------------------------------------------------------- review fixes


def test_out_of_range_timestamp_does_not_abort_the_run() -> None:
    """An edge-of-range offset overflows on conversion to UTC: it is a malformed time, not a crash."""
    doc = json.loads(fixture("npm-agent-cli-demo.json"))
    doc["time"]["2.4.0"] = "0001-01-01T00:00:00+05:00"
    routes = _routes()
    routes[NPM_CLI] = json.dumps(doc).encode()
    other, target = check_dependencies([_npm("other-pkg"), _npm()], client=FakeClient(routes), now=NOW)
    assert other.coverage == "partial"  # its registry is unrouted: an error, not an exception
    assert target.coverage == "queried", target.errors
    rel = next(r for r in target.releases if r.version == "2.4.0")
    assert rel.published_at is None


def test_unexpected_exception_is_isolated_per_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    import symbiote.advisories.engine as engine

    real = engine.check_dependency

    def flaky(ref: DependencyRef, **kw: object) -> DependencyIntel:
        if ref.name == "boom":
            raise OverflowError("date value out of range")
        return real(ref, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(engine, "check_dependency", flaky)
    boom, ok = check_dependencies([_npm("boom"), _npm()], client=_client(), now=NOW)
    assert boom.coverage == "unreachable"
    assert any("OverflowError" in e for e in boom.errors)
    assert ok.coverage == "queried"


def test_floating_reference_resolving_to_a_fresh_release_is_flagged() -> None:
    """``npx -y pkg`` runs dist-tag latest; when that was published hours ago, the cooldown is being skipped."""
    now = NOW - timedelta(days=2, hours=0)  # 2.5.0 (latest) published three hours before this
    [intel] = check_dependencies([_npm(version=None)], client=_client(), now=now)
    assert intel.latest is not None and intel.latest.version == "2.5.0"
    fresh = [s for s in intel.signals if s.kind is SignalKind.FRESH_RELEASE]
    assert [(s.reference, s.severity) for s in fresh] == [("2.5.0", "high")]
    assert "floating reference runs today" in fresh[0].detail
    assert intel.recommended is None or intel.recommended.version != "2.5.0"


def test_pinned_fresh_release_in_use_is_flagged() -> None:
    now = NOW - timedelta(days=2)
    [intel] = check_dependencies([_npm(version="2.5.0")], client=_client(), now=now)
    fresh = [s for s in intel.signals if s.kind is SignalKind.FRESH_RELEASE]
    assert [(s.reference, s.severity) for s in fresh] == [("2.5.0", "medium")]


def test_returning_maintainer_is_not_a_new_publisher() -> None:
    versions, times = {}, {}
    for n, who in enumerate(["bob", "alice", "alice", "alice", "alice", "alice", "bob", "mallory"]):
        v = f"1.{n}.0"
        versions[v] = {
            "name": "agent-cli-demo",
            "version": v,
            "_npmUser": {"name": who},
            "dist": {"attestations": {"url": "x", "provenance": {"predicateType": "slsa"}}},
        }
        times[v] = f"2026-0{n + 1}-01T00:00:00Z"
    doc = {"name": "agent-cli-demo", "dist-tags": {"latest": "1.7.0"}, "versions": versions, "time": times}
    routes = _routes()
    routes[NPM_CLI] = json.dumps(doc).encode()
    returning = _one(_npm(version="1.6.0"), FakeClient(routes))
    changed = [s.reference for s in returning.signals if s.kind is SignalKind.PUBLISHER_CHANGED]
    assert changed == ["1.7.0"]  # mallory is new; bob (who published 1.0.0) is not


def _pypi_with_mixed_release() -> tuple[bytes, bytes]:
    j = json.loads(fixture("pypi-demo-mcp-server.json"))
    s = json.loads(fixture("pypi-simple-demo-mcp-server.json"))
    wheel12 = "demo_mcp_server-1.2.0-py3-none-any.whl"
    j["releases"]["1.2.0"] = [
        {"filename": wheel12, "packagetype": "bdist_wheel", "upload_time_iso_8601": "2026-09-01T00:00:00Z"}
    ]
    s["files"].append({"filename": wheel12, "provenance": None})
    extra = "demo_mcp_server-1.1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
    j["releases"]["1.1.0"].append(
        {"filename": extra, "packagetype": "bdist_wheel", "upload_time_iso_8601": "2026-09-02T00:00:00Z"}
    )
    s["files"].append({"filename": extra, "provenance": None})
    return json.dumps(j).encode(), json.dumps(s).encode()


def _pypi_ref(version: str = "1.1.0") -> DependencyRef:
    return DependencyRef(
        kind=DependencyKind.MCP_SERVER_PACKAGE, ecosystem="pypi", name="demo-mcp-server", version=version
    )


def test_unattested_file_added_to_attested_pypi_release_is_a_downgrade() -> None:
    pj, ps = _pypi_with_mixed_release()
    routes = _routes()
    routes[PYPI_JSON], routes[PYPI_SIMPLE] = pj, ps
    intel = _one(_pypi_ref(), FakeClient(routes))
    assert intel.current is not None and intel.current.has_provenance is False
    downgrades = {s.reference: s.detail for s in intel.signals if s.kind is SignalKind.PROVENANCE_DOWNGRADE}
    assert "cp311" in downgrades["1.1.0"]
    assert "1.2.0" in downgrades  # an unattested release after a (partly) attested one
    assert intel.recommended is None  # 1.2.0 breaks provenance continuity


def test_unknown_provenance_is_not_recommended_under_continuity() -> None:
    pj, _ = _pypi_with_mixed_release()
    routes = _routes()
    routes[PYPI_JSON] = pj
    del routes[PYPI_SIMPLE]  # the provenance source is unreachable
    intel = _one(_pypi_ref(), FakeClient(routes))
    assert intel.coverage == "partial"
    assert intel.recommended is None
    assert not any(s.kind is SignalKind.NEWER_VERSION for s in intel.signals)
    assert any("provenance unknown for 1.2.0" in e for e in intel.errors)
    relaxed = _one(_pypi_ref(), FakeClient(routes), UpdatePolicy(require_provenance_continuity=False))
    assert relaxed.recommended is not None and relaxed.recommended.version == "1.2.0"


def test_truncated_mcp_registry_search_is_not_a_clean_answer() -> None:
    base = "https://registry.modelcontextprotocol.io/v0/servers?search=agent-cli-demo&limit=100"

    def page(i: int, cursor: str) -> bytes:
        server = {
            "name": f"io.x/o{i}",
            "version": "1",
            "packages": [{"registryType": "npm", "identifier": "o"}],
        }
        return json.dumps({"servers": [{"server": server}], "metadata": {"nextCursor": cursor}}).encode()

    routes = _routes()
    routes[base] = page(0, "c1")
    routes[base + "&cursor=c1"] = page(1, "c2")
    routes[base + "&cursor=c2"] = page(2, "c3")  # page 4 would hold the real (deleted) entry
    intel = _one(_npm(), FakeClient(routes))
    assert intel.coverage == "partial"
    assert any("truncated" in e for e in intel.errors)


def test_purl_less_launcher_package_is_not_attempted_and_floating() -> None:
    ref = DependencyRef(
        kind=DependencyKind.MCP_SERVER_PACKAGE, ecosystem="mcp-registry", name="npx:git", version=None
    )
    remote = DependencyRef(
        kind=DependencyKind.MCP_SERVER_REMOTE,
        ecosystem="mcp-registry",
        name="https://mcp.example.com/mcp",
        version=None,
    )
    a, b = check_dependencies([ref, remote], client=_client(), now=NOW)
    assert a.coverage == "not-attempted" and "no package URL" in a.errors[0]
    assert [(s.kind, s.severity) for s in a.signals] == [(SignalKind.FLOATING, "high")]
    assert b.coverage == "not-attempted" and "remote MCP endpoints" in b.errors[0]
    assert b.signals == []
