from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from symbiote.advisories.types import (
    Advisory,
    DependencyIntel,
    DependencyKind,
    DependencyRef,
    ReleaseInfo,
    Signal,
    SignalKind,
)
from symbiote.update import UpdatePolicy, plan_updates
from symbiote.update.plan import version_key

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def ago(days: float) -> datetime:
    return NOW - timedelta(days=days)


def rel(version: str, days: float | None, **kw: object) -> ReleaseInfo:
    return ReleaseInfo(version=version, published_at=None if days is None else ago(days), **kw)  # type: ignore[arg-type]


def intel(
    version: str | None,
    releases: list[ReleaseInfo],
    *,
    name: str = "server-pkg",
    kind: DependencyKind = DependencyKind.MCP_SERVER_PACKAGE,
    ecosystem: str = "npm",
    advisories: list[Advisory] | None = None,
    signals: list[Signal] | None = None,
    recommended: ReleaseInfo | None = None,
    coverage: str = "queried",
) -> DependencyIntel:
    ref = DependencyRef(
        kind=kind,
        ecosystem=ecosystem,  # type: ignore[arg-type]
        name=name,
        version=version,
        locators=(".mcp.json#/mcpServers/s",),
    )
    by = {r.version: r for r in releases}
    return DependencyIntel(
        ref=ref,
        checked_at=NOW,
        coverage=coverage,  # type: ignore[arg-type]
        current=by.get(version) if version else None,
        latest=releases[-1] if releases else None,
        recommended=recommended,
        releases=releases,
        advisories=advisories or [],
        signals=signals or [],
    )


def test_version_key_orders_semver_and_pep440() -> None:
    order = ["1.0.0-beta.1", "1.0.0rc1", "1.0.0", "1.0.0.post1", "1.0.1", "1.10.0", "2.0"]
    keys = [version_key(v) for v in order]
    assert all(k is not None for k in keys)
    assert keys == sorted(keys)  # type: ignore[type-var]
    assert version_key("latest") is None
    assert version_key("sha256:" + "a" * 64) is None


def test_security_proposes_the_confirmed_recommended_release() -> None:
    adv = Advisory(id="GHSA-aaaa-bbbb-cccc", summary="RCE", severity="high", fixed_in=("1.0.2",))
    releases = [
        rel("1.0.0", 100),
        rel("1.0.1", 50),  # not fixed
        rel("1.0.2", 1),  # fixed but inside the 2-day security cooldown
        rel("1.0.3", 5),  # passes, confirmed clean by the advisors
        rel("1.1.0", 30),
    ]
    sig = Signal(SignalKind.VULNERABLE, "high", "GHSA-aaaa-bbbb-cccc affects 1.0.0", "GHSA-aaaa-bbbb-cccc")
    i = intel("1.0.0", releases, advisories=[adv], signals=[sig], recommended=releases[3])
    [p] = plan_updates([i])
    assert p.kind == "security"
    assert p.proposed == "1.0.3"
    assert p.severity == "high"
    assert "GHSA-aaaa-bbbb-cccc" in p.rationale
    assert p.signals == [sig]
    assert any("toolset digest" in n for n in p.review_notes)
    assert any("1.0.2 as the lowest fixed version" in n for n in p.review_notes)


def test_security_never_proposes_an_unconfirmed_release() -> None:
    # Finding: the engine skipped 1.2.0 (it has advisories) and recommended 1.1.0; never propose 1.2.0.
    adv = Advisory(id="GHSA-a", summary="a", severity="high", fixed_in=("1.1.0",))
    releases = [rel("1.0.0", 300), rel("1.1.0", 60), rel("1.2.0", 30)]
    [p] = plan_updates([intel("1.0.0", releases, advisories=[adv], recommended=releases[1])])
    assert (p.kind, p.proposed) == ("security", "1.1.0")
    # OSV could not confirm any candidate (recommended None): no editable proposal.
    i = intel("1.0.0", releases, advisories=[adv], coverage="partial")
    i.errors.append("cannot recommend 1.2.0: its advisories could not be checked")
    [q] = plan_updates([i])
    assert q.kind == "replace" and q.proposed == "(verify 1.1.0 by hand)"
    assert "could not be confirmed" in q.rationale


def test_security_backported_fix_lines() -> None:
    # Finding: fixed_in (1.4.5, 1.5.2): 1.5.0 and 1.5.1 are still vulnerable; 1.5.2 is the lowest fix above 1.4.0.
    adv = Advisory(id="GHSA-b", summary="b", severity="critical", fixed_in=("1.4.5", "1.5.2"))
    releases = [rel("1.4.0", 300), rel("1.5.0", 100), rel("1.5.1", 90), rel("1.5.2", 60)]
    i = intel("1.4.0", releases, advisories=[adv])
    [p] = plan_updates([i])
    assert p.kind == "replace" and "1.5.0" not in p.proposed and p.proposed == "(verify 1.4.5 by hand)"
    [q] = plan_updates([intel("1.4.0", releases, advisories=[adv], recommended=releases[3])])
    assert (q.kind, q.proposed, q.severity) == ("security", "1.5.2", "critical")
    from symbiote.update.plan import _fixes

    assert not _fixes(adv, "1.5.0") and not _fixes(adv, "1.5.1")
    assert _fixes(adv, "1.5.2") and _fixes(adv, "1.4.6") and _fixes(adv, "1.6.0") and _fixes(adv, "2.0.0")
    assert not _fixes(adv, "1.4.4")


def test_security_without_release_metadata_is_not_editable() -> None:
    # Finding: registry unreachable, OSV answered: never an editable bump that skipped the cooldown.
    adv = Advisory(id="GHSA-c", summary="c", severity="high", fixed_in=("1.0.1",))
    i = intel("1.0.0", [], advisories=[adv], coverage="partial")
    i.errors.append("registry lookup failed: timed out")
    [p] = plan_updates([i])
    assert p.kind == "replace" and p.proposed == "(verify 1.0.1 by hand)"
    assert "no release metadata" in p.rationale
    from symbiote.update import locate_edits

    assert locate_edits(Path("/nonexistent"), p) == []


def test_security_rechecks_recommended_against_policy() -> None:
    adv = Advisory(id="GHSA-x", summary="x", severity="critical", fixed_in=("1.4.5",))
    releases = [
        rel("1.4.0", 200, has_provenance=True),
        rel("1.4.5", 10, has_provenance=False),  # provenance downgrade
        rel("1.4.6", 9, has_provenance=True),
    ]
    [p] = plan_updates([intel("1.4.0", releases, advisories=[adv], recommended=releases[1])])
    assert p.kind == "replace" and "provenance" in p.rationale
    [q] = plan_updates([intel("1.4.0", releases, advisories=[adv], recommended=releases[2])])
    assert (q.kind, q.proposed, q.severity) == ("security", "1.4.6", "critical")


def test_security_without_passing_fix_proposes_replace() -> None:
    adv = Advisory(id="GHSA-y", summary="y", severity="medium", fixed_in=("1.0.1",))
    releases = [rel("1.0.0", 100), rel("1.0.1", 0.5)]
    [p] = plan_updates([intel("1.0.0", releases, advisories=[adv])])
    assert p.kind == "replace"
    assert p.severity == "medium"
    assert "1.0.1" in p.rationale and "0 days ago" in p.rationale
    assert not p.edits


def test_malicious_release_is_critical_replace_when_no_clean_version() -> None:
    adv = Advisory(id="MAL-2026-1", summary="malware", malicious=True)
    sig = Signal(SignalKind.MALICIOUS, "critical", "known malicious release", "MAL-2026-1")
    [p] = plan_updates([intel("6.6.6", [rel("6.6.6", 3)], advisories=[adv], signals=[sig])])
    assert (p.kind, p.severity) == ("replace", "critical")
    assert "MAL-2026-1" in p.rationale
    assert any("Remove the server" in n for n in p.review_notes)


def test_malicious_with_clean_recommended_release_upgrades() -> None:
    adv = Advisory(id="MAL-2026-2", summary="malware", malicious=True)
    releases = [rel("1.0.0", 40), rel("1.0.1", 2.5), rel("1.0.2", 20)]
    rec = releases[2]
    [p] = plan_updates([intel("1.0.1", releases, advisories=[adv], recommended=rec)])
    assert (p.kind, p.proposed, p.severity) == ("security", "1.0.2", "critical")
    assert any("rotate every credential" in n for n in p.review_notes)


def test_pin_floating_reference_to_recommended() -> None:
    releases = [rel("1.4.1", 60), rel("1.4.2", 20), rel("1.5.0", 1)]
    sig = Signal(SignalKind.FLOATING, "medium", "npx -y server-pkg resolves latest at every start")
    [p] = plan_updates([intel(None, releases, signals=[sig], recommended=releases[1])])
    assert (p.kind, p.current, p.proposed, p.severity) == ("pin", "(floating)", "1.4.2", "medium")
    assert "floating" in p.rationale
    assert any("Pinning freezes" in n for n in p.review_notes)


def test_pin_without_recommended_proposes_nothing() -> None:
    releases = [rel("1.4.1", 60), rel("1.4.2", 20, has_install_script=True), rel("1.5.0", 1)]
    assert plan_updates([intel(None, releases)]) == []
    # a recommended release that fails the re-check is refused too
    assert plan_updates([intel(None, releases, recommended=releases[2])]) == []


def test_pin_oci_requires_digest() -> None:
    digest = "sha256:" + "c" * 64
    i = intel(None, [], ecosystem="oci", name="ghcr.io/acme/mcp", recommended=ReleaseInfo(version=digest))
    [p] = plan_updates([i])
    assert (p.kind, p.proposed) == ("pin", digest)
    assert plan_updates([intel(None, [], ecosystem="oci", name="ghcr.io/acme/mcp")]) == []


@pytest.mark.parametrize("ecosystem", ["oci", "huggingface"])
def test_not_attempted_floating_image_gets_pin_advice(ecosystem: str) -> None:
    sig = Signal(SignalKind.FLOATING, "medium", "not pinned to a digest")
    i = intel(None, [], ecosystem=ecosystem, name="ghcr.io/acme/mcp", signals=[sig], coverage="not-attempted")
    [p] = plan_updates([i])
    assert p.kind == "pin" and p.proposed.startswith("(pin to a reviewed") and p.severity == "medium"
    from symbiote.update import locate_edits

    assert locate_edits(Path("/nonexistent"), p) == []
    # without the floating signal, a not-attempted lookup still yields nothing
    i = intel("v1", [], ecosystem=ecosystem, name="ghcr.io/acme/mcp", coverage="not-attempted")
    assert plan_updates([i]) == []


def test_version_update_uses_recommended_and_rechecks_major() -> None:
    releases = [rel("1.0.0", 300), rel("1.2.0", 30), rel("1.3.0-beta.1", 20), rel("2.0.0", 15)]
    [p] = plan_updates([intel("1.0.0", releases, recommended=releases[1])])
    assert (p.kind, p.proposed, p.severity) == ("version", "1.2.0", "low")
    assert plan_updates([intel("1.0.0", releases, recommended=releases[3])]) == []
    [q] = plan_updates([intel("1.0.0", releases, recommended=releases[3])], UpdatePolicy(allow_major=True))
    assert q.proposed == "2.0.0"
    assert any("major-version change" in n for n in q.review_notes)


def test_version_never_proposes_a_release_the_engine_skipped() -> None:
    # Finding: the engine found advisories on 1.2.0 and recommended 1.1.0.
    releases = [rel("1.0.0", 300), rel("1.1.0", 60), rel("1.2.0", 30)]
    [p] = plan_updates([intel("1.0.0", releases, recommended=releases[1])])
    assert (p.kind, p.proposed) == ("version", "1.1.0")
    # OSV could not check 1.2.0, recommended None: nothing is proposed.
    assert plan_updates([intel("1.0.0", releases, coverage="partial")]) == []
    # MCP-registry ecosystem (no vulnerability advisor): no recommended, so no version proposal.
    i = intel("1.0.0", releases, ecosystem="mcp-registry", coverage="partial")
    assert plan_updates([i]) == []


def test_no_proposal_when_recommended_is_inside_cooldown() -> None:
    releases = [rel("1.0.0", 300), rel("1.1.0", 2)]
    sig = Signal(SignalKind.FRESH_RELEASE, "info", "1.1.0 is 2 days old", "1.1.0")
    assert plan_updates([intel("1.0.0", releases, signals=[sig], recommended=releases[1])]) == []
    assert plan_updates([intel("1.0.0", releases, recommended=releases[1])]) == []
    # a shorter cooldown admits it
    [p] = plan_updates([intel("1.0.0", releases, recommended=releases[1])], UpdatePolicy(cooldown_days=1))
    assert p.proposed == "1.1.0"


def test_no_proposal_when_recommended_downgrades_provenance() -> None:
    releases = [rel("2.2.0", 300, has_provenance=True), rel("2.3.0", 30, has_provenance=False)]
    assert plan_updates([intel("2.2.0", releases, recommended=releases[1])]) == []
    releases = [rel("2.2.0", 300), rel("2.3.0", 30)]
    sig = Signal(SignalKind.PROVENANCE_DOWNGRADE, "high", "2.3.0 has no provenance", "2.3.0")
    assert plan_updates([intel("2.2.0", releases, signals=[sig], recommended=releases[1])]) == []
    releases = [rel("2.2.0", 300, has_provenance=True), rel("2.3.0", 30, has_provenance=False)]
    policy = UpdatePolicy(require_provenance_continuity=False)
    [p] = plan_updates([intel("2.2.0", releases, recommended=releases[1])], policy)
    assert p.proposed == "2.3.0"


def test_new_install_script_and_publisher_change() -> None:
    releases = [rel("1.0.0", 300, publisher="alice"), rel("1.1.0", 30, has_install_script=True)]
    assert plan_updates([intel("1.0.0", releases, recommended=releases[1])]) == []
    releases = [rel("1.0.0", 300, publisher="alice"), rel("1.1.0", 30, publisher="mallory")]
    [p] = plan_updates([intel("1.0.0", releases, recommended=releases[1])])
    assert any("different account" in n for n in p.review_notes)


def test_retire_model_proposes_successor_as_advice() -> None:
    # the engine names the retiring model in ``reference`` and the documented successor in ``recommended``
    sig = Signal(SignalKind.RETIRING_MODEL, "high", "retires on 2027-01-05", "model-a-2025")
    i = intel(
        "model-a-2025",
        [],
        name="model-a-2025",
        kind=DependencyKind.HOSTED_MODEL,
        ecosystem="hosted-model",
        signals=[sig],
        recommended=ReleaseInfo(version="model-b-2026"),
    )
    [p] = plan_updates([i])
    assert (p.kind, p.proposed, p.severity) == ("retire-model", "model-b-2026", "high")
    assert "advice" in p.rationale
    assert any("evaluations" in n for n in p.review_notes)


def test_deprecated_without_update_proposes_replace() -> None:
    sig = Signal(SignalKind.DEPRECATED, "medium", "MCP Registry status deleted")
    [p] = plan_updates([intel("1.0.0", [rel("1.0.0", 100)], signals=[sig])])
    assert (p.kind, p.severity) == ("replace", "medium")


@pytest.mark.parametrize("coverage", ["unreachable", "not-attempted"])
def test_failed_lookups_never_produce_proposals(coverage: str) -> None:
    adv = Advisory(id="GHSA-z", summary="z", fixed_in=("1.0.1",))
    i = intel("1.0.0", [rel("1.0.0", 100), rel("1.0.1", 50)], advisories=[adv], coverage=coverage)
    assert plan_updates([i]) == []


def test_at_most_one_proposal_per_dependency_sorted_by_severity() -> None:
    adv = Advisory(id="GHSA-q", summary="q", severity="critical", fixed_in=("1.0.1",))
    vrels = [rel("1.0.0", 100), rel("1.0.1", 50), rel("1.1.0", 30)]
    vuln = intel("1.0.0", vrels, advisories=[adv], recommended=vrels[2])
    floating = intel(None, [rel("3.0.0", 30)], name="other", recommended=rel("3.0.0", 30))
    out = plan_updates([floating, vuln, vuln])
    assert [(p.dependency.name, p.kind) for p in out] == [("server-pkg", "security"), ("other", "pin")]


def test_retire_model_without_successor_never_proposes_the_same_model() -> None:
    sig = Signal(SignalKind.RETIRING_MODEL, "high", "claude-x retires on 2026-11-30 (28 days)", "claude-x")
    i = intel(
        None, [], name="claude-x", kind=DependencyKind.HOSTED_MODEL, ecosystem="hosted-model", signals=[sig]
    )
    [p] = plan_updates([i])
    assert p.kind == "retire-model"
    assert p.proposed != "claude-x" and "successor" in p.proposed
    assert "documents claude-x as its successor" not in p.rationale
    assert "No successor is documented." in p.rationale
    assert not p.edits


def test_package_missing_from_public_registry_is_not_told_to_remove_itself() -> None:
    sig = Signal(SignalKind.NOT_PUBLISHED, "medium", "internal-tools is not on the public pypi registry")
    i = intel("1.4.2", [], name="internal-tools", ecosystem="pypi", signals=[sig])
    assert plan_updates([i]) == []  # an unresolved signal for the reviewer, never a "remove or replace"
