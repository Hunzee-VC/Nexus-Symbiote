"""mcp-registry collector with an injected transport (offline)."""

from __future__ import annotations

from datetime import UTC, datetime

from symbiote.collect.base import CollectContext
from symbiote.collect.registry import McpRegistryCollector, levenshtein
from symbiote.model.enums import AliasPinning, CoverageStatus, PublisherVerification, Surface

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)

ENTRY = {
    "server": {
        "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
        "name": "io.github.acme/github-tools",
        "version": "1.4.2",
        "packages": [
            {
                "registryType": "npm",
                "identifier": "@acme/github-tools",
                "version": "1.4.2",
                "fileSha256": "a" * 64,
            }
        ],
        "remotes": [],
    },
    "_meta": {"io.modelcontextprotocol.registry/official": {"status": "active", "isLatest": True}},
}


def run(targets, responder):
    ctx = CollectContext(
        root=NOW and __import__("pathlib").Path("."),
        now=NOW,
        options={"registry": True, "registry_targets": targets, "http_get": responder},
    )
    collector = McpRegistryCollector()
    result = collector.collect(ctx)
    result.finalize_coverage(collector.surfaces)
    return result


def test_match_by_package_identifier() -> None:
    result = run(
        [
            {
                "server_id": "server:github",
                "name": "github-tools",
                "package_purl": "pkg:npm/%40acme/github-tools@1.4.2",
                "package_digest": "sha256:" + "a" * 64,
            }
        ],
        lambda url: (200, {"servers": [ENTRY]}),
    )
    res = result.entities[0]
    assert res.resolved.state == "present"
    assert res.resolved.immutable_ref == "sha256:" + "a" * 64
    assert res.registry is not None and res.registry.entry_id == "io.github.acme/github-tools"
    assert res.publisher is not None and res.publisher.verification is PublisherVerification.UNKNOWN
    assert res.alias_policy is AliasPinning.PINNED
    assert res.signer is None
    assert result.evidence and result.evidence[0].evidence_kind.value == "registry-record"
    assert any(e.type.value == "resolvedFrom" for e in result.edges)


def test_unreachable_registry_is_unknown_never_not_registered() -> None:
    def boom(url: str):
        raise OSError("connection refused")

    result = run([{"server_id": "server:github", "name": "github-tools"}], boom)
    res = result.entities[0]
    assert res.resolved.state == "unknown"
    assert result.coverage[Surface.REGISTRY].status is CoverageStatus.UNREACHABLE


def test_unmatched_entry_records_typosquat_distance() -> None:
    result = run(
        [{"server_id": "server:gthub", "name": "gthub-mcp-server"}],
        lambda url: (200, {"servers": [ENTRY]}),
    )
    res = result.entities[0]
    assert res.resolved.state == "unknown"
    assert res.typosquat_distance is not None and res.typosquat_distance.levenshtein <= 2


def test_levenshtein_bounds() -> None:
    assert levenshtein("github", "glthub") == 1
    assert levenshtein("a", "a") == 0
    assert levenshtein("short", "a-very-long-name") > 6


def test_conflicting_identity_or_incomplete_registry_never_resolves() -> None:
    target = {
        "name": "tools",
        "server_id": "server:x",
        "package_purl": "pkg:npm/%40acme/github-tools@1.4.2",
        "package_digest": "sha256:" + "a" * 64,
    }
    for changed, response in [
        ({"package_purl": "pkg:npm/%40other/unrelated@1.4.2"}, {"servers": [ENTRY]}),
        ({"remote_url": "https://unrelated.invalid"}, {"servers": [ENTRY]}),
        ({"package_purl": "pkg:pypi/github-tools@1.4.2"}, {"servers": [ENTRY]}),
        ({"package_purl": "pkg:npm/%40acme/github-tools@2.0.0"}, {"servers": [ENTRY]}),
        ({"package_digest": "sha256:" + "b" * 64}, {"servers": [ENTRY]}),
        ({}, {"servers": [ENTRY, ENTRY]}),
        ({}, {"servers": [ENTRY], "metadata": {"nextCursor": "more"}}),
    ]:
        result = run([{**target, **changed}], lambda url, payload=response: (200, payload))
        assert result.entities[0].resolved.state == "unknown"
        assert result.entities[0].alias_policy is not AliasPinning.PINNED


def test_crafted_namespace_or_short_identifier_does_not_match() -> None:
    evil = {
        "server": {
            "name": "com.evil/github",
            "version": "9.9.9",
            "packages": [{"registryType": "npm", "identifier": "git", "version": "9.9.9"}],
            "remotes": [],
        }
    }
    result = run(
        [
            {
                "server_id": "server:github",
                "name": "github",
                "package_purl": "pkg:npm/%40acme/github-tools@1.4.2",
            }
        ],
        lambda url: (200, {"servers": [evil]}),
    )
    res = result.entities[0]
    # "git" is a substring of the purl and "com.evil/github" ends with the local
    # name, but neither is an exact identity: the resolution stays unknown.
    assert res.resolved.state == "unknown"
