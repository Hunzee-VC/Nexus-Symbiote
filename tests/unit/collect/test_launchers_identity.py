"""Launcher identity confusion: local aliases and registry overrides never read as public-registry packages.

Attack cases reported against the earlier nexus_symbiote drift gate (Nexus-Symbiote PR #84 review): a same-shape
swap to a local directory, tarball or attacker-chosen index must change the server's package identity.
"""

from __future__ import annotations

import pytest

from symbiote.collect.launchers import parse_launch
from symbiote.digest import server_identity_digest


@pytest.mark.parametrize(
    "spec", ["pkg@.", "pkg@..", "pkg@x.tgz", "pkg@./dir", "pkg@../dir", "pkg@/abs/dir", "pkg@dir/sub"]
)
def test_npm_local_alias_is_a_local_path(spec: str) -> None:
    f = parse_launch("npx", ["-y", spec])
    assert f.purl is None and f.package_name is None
    assert f.local_path == spec.split("@", 1)[1]
    assert "local-alias" in f.risky_flags


def test_npm_registry_version_unchanged() -> None:
    assert parse_launch("npx", ["-y", "pkg@1.2.3"]).purl == "pkg:npm/pkg@1.2.3"
    assert parse_launch("npx", ["-y", "@scope/pkg@1.2.3"]).purl == "pkg:npm/%40scope/pkg@1.2.3"


@pytest.mark.parametrize(
    ("command", "args", "flag"),
    [
        ("npx", ["--registry", "https://evil.example", "-y", "pkg@1.2.3"], "registry"),
        ("uvx", ["pkg==1.0", "--index-url", "https://evil.example/simple"], "index-url"),
        ("uvx", ["--default-index", "https://evil.example/simple", "pkg==1.0"], "default-index"),
        ("uvx", ["pkg==1.0", "--extra-index-url", "https://evil.example/simple"], "extra-index-url"),
        ("uvx", ["--find-links", "/tmp/wheels", "pkg==1.0"], "find-links"),
        ("pipx", ["run", "--index-url", "https://evil.example/simple", "pkg==1.0"], "index-url"),
    ],
)
def test_registry_override_is_not_pinned_and_changes_identity(
    command: str, args: list[str], flag: str
) -> None:
    f = parse_launch(command, args)
    assert not f.pinned and f.float_reason == f"registry-override:{flag}"
    assert f"registry-override:{flag}" in f.risky_flags
    clean = parse_launch(
        command, [a for a in args if not a.startswith("--") and "evil" not in a and a != "/tmp/wheels"]
    )
    assert clean.pinned

    def ident(facts):
        return server_identity_digest(
            kind="mcp", transport="stdio", endpoint=None, package={"purl": facts.purl, "digest": facts.digest}
        ).value

    if flag in ("registry", "index-url", "default-index"):
        assert ident(f) != ident(clean)  # the index is part of the identity: a swap is a drift event


def test_pipx_arguments_after_the_spec_belong_to_the_tool() -> None:
    assert parse_launch("pipx", ["run", "pkg==1.0", "--find-links", "/tmp/w"]).pinned
