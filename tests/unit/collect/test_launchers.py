"""Launch-command parsing: package identity and pinning without executing anything."""

from __future__ import annotations

import pytest

from symbiote.collect.launchers import parse_launch
from symbiote.model.enums import Launcher


@pytest.mark.parametrize(
    ("command", "args", "purl", "pinned", "reason"),
    [
        (
            "npx",
            ["-y", "@modelcontextprotocol/server-github"],
            "pkg:npm/%40modelcontextprotocol/server-github",
            False,
            "no-version",
        ),
        (
            "npx",
            ["-y", "@modelcontextprotocol/server-github@2025.4.8"],
            "pkg:npm/%40modelcontextprotocol/server-github@2025.4.8",
            True,
            None,
        ),
        ("npx", ["-y", "postmark-mcp@latest"], "pkg:npm/postmark-mcp", False, "dist-tag:latest"),
        ("npx", ["mcp-remote@^0.1.16", "https://example.com/mcp"], "pkg:npm/mcp-remote", False, "range"),
        (
            "npx",
            ["--yes", "--package=@acme/tools@1.2.3", "acme-mcp"],
            "pkg:npm/%40acme/tools@1.2.3",
            True,
            None,
        ),
        ("npx", ["-p", "left-pad@1.3.0", "lp"], "pkg:npm/left-pad@1.3.0", True, None),
        ("C:\\Program Files\\nodejs\\npx.cmd", ["-y", "srv@1.0.0"], "pkg:npm/srv@1.0.0", True, None),
        ("pnpm", ["dlx", "srv@2.0.0"], "pkg:npm/srv@2.0.0", True, None),
        ("bunx", ["srv"], "pkg:npm/srv", False, "no-version"),
        ("npm", ["exec", "--", "srv@1.0.0"], "pkg:npm/srv@1.0.0", True, None),
        ("uvx", ["mcp-server-fetch"], "pkg:pypi/mcp-server-fetch", False, "no-version"),
        ("uvx", ["mcp-server-git==2025.1.14"], "pkg:pypi/mcp-server-git@2025.1.14", True, None),
        ("uvx", ["mcp-server-time@latest"], "pkg:pypi/mcp-server-time", False, "dist-tag:latest"),
        (
            "uvx",
            ["--from", "awslabs.core-mcp-server==1.0.2", "awslabs.core-mcp-server"],
            "pkg:pypi/awslabs.core-mcp-server@1.0.2",
            True,
            None,
        ),
        ("uvx", ["--python", "3.12", "Some_Pkg>=1.0"], "pkg:pypi/some-pkg", False, "range"),
        ("uv", ["tool", "run", "srv==0.4.0"], "pkg:pypi/srv@0.4.0", True, None),
        ("pipx", ["run", "--spec", "srv==1.0", "srv"], "pkg:pypi/srv@1.0", True, None),
        ("dnx", ["Contoso.Mcp@1.2.3", "--yes"], "pkg:nuget/Contoso.Mcp@1.2.3", True, None),
        ("go", ["run", "github.com/acme/mcp@v1.2.3"], "pkg:golang/github.com/acme/mcp@v1.2.3", True, None),
    ],
)
def test_registry_packages(
    command: str, args: list[str], purl: str, pinned: bool, reason: str | None
) -> None:
    facts = parse_launch(command, args)
    assert facts.purl == purl
    assert facts.pinned is pinned
    assert facts.float_reason == reason
    assert facts.floating is (not pinned)


def test_docker_digest_pins_and_tags_float() -> None:
    digest = "sha256:" + "a" * 64
    pinned = parse_launch(
        "docker", ["run", "-i", "--rm", "-e", "GITHUB_TOKEN", f"ghcr.io/github/github-mcp-server@{digest}"]
    )
    assert pinned.launcher is Launcher.DOCKER
    assert pinned.pinned
    assert pinned.digest == digest
    assert pinned.purl is not None and pinned.purl.startswith("pkg:oci/github-mcp-server@sha256")
    assert "repository_url=ghcr.io/github/github-mcp-server" in pinned.purl
    tagged = parse_launch("docker", ["run", "-i", "--rm", "mcp/fetch:1.2.3"])
    assert not tagged.pinned
    assert tagged.float_reason == "mutable-tag:1.2.3"
    implicit = parse_launch("podman", ["run", "node"])
    assert implicit.package_name == "docker.io/library/node"
    assert implicit.float_reason == "mutable-tag:latest"


def test_docker_risky_flags() -> None:
    facts = parse_launch(
        "docker",
        [
            "run", "--privileged", "--network=host", "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-v", "/:/host", "--cap-add", "SYS_ADMIN", "--user", "root", "img:1",
        ],
    )  # fmt: skip
    assert set(facts.risky_flags) >= {
        "privileged",
        "host-network",
        "docker-socket-mount",
        "host-root-mount",
        "cap-add:SYS_ADMIN",
        "runs-as-root",
    }


@pytest.mark.parametrize(
    ("command", "args", "local"),
    [
        ("node", ["/opt/servers/index.js"], "/opt/servers/index.js"),
        ("python3", ["-u", "server.py"], "server.py"),
        ("/usr/local/bin/my-mcp", [], "/usr/local/bin/my-mcp"),
        ("npx", ["./local-server"], "./local-server"),
    ],
)
def test_local_commands_have_no_package(command: str, args: list[str], local: str) -> None:
    facts = parse_launch(command, args)
    assert facts.package_name is None
    assert facts.local_path == local
    assert not facts.floating


def test_git_and_url_specs() -> None:
    pinned = parse_launch("npx", ["github:acme/srv#" + "b" * 40])
    assert pinned.pinned
    branch = parse_launch("npx", ["github:acme/srv#main"])
    assert branch.float_reason == "git-ref"
    tarball = parse_launch("npx", ["https://example.com/srv.tgz"])
    assert tarball.float_reason == "url"
    git_py = parse_launch("uvx", ["--from", "git+https://github.com/acme/srv@" + "c" * 40, "srv"])
    assert git_py.pinned


def test_deno_specifiers() -> None:
    assert parse_launch("deno", ["run", "-A", "npm:srv@1.0.0"]).pinned
    jsr = parse_launch("deno", ["run", "jsr:@acme/srv"])
    assert jsr.ecosystem == "jsr" and jsr.float_reason == "no-version"
    assert parse_launch("deno", ["run", "https://x.test/mod.ts"]).float_reason == "url"


def test_degenerate_inputs() -> None:
    assert parse_launch(None, []).launcher_detail == "none"
    assert parse_launch("npx", []).package_name is None
    assert parse_launch("docker", ["ps"]).package_name is None
    assert parse_launch("npm", ["install"]).launcher is Launcher.OTHER
