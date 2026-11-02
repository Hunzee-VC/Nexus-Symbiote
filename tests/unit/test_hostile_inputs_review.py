"""Regression tests for findings reported against src/symbiote by the Nexus-Symbiote audit session (§6)."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from symbiote.collect.base import CollectContext
from symbiote.collect.shadowscan import ShadowScanReportCollector
from symbiote.export.cdx.validate import validate_cyclonedx
from symbiote.model import enums as E
from symbiote.shadowscan.report import ReportError, read_report

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "shadowscan" / "triage-agent.report.json"


def _collect(root: Path, declaration: dict) -> object:
    ctx = CollectContext(root=root, options={"declaration": declaration}, budget_seconds=5)
    return ShadowScanReportCollector().collect(ctx)


# (8) a report path declared by the scanned repository must stay inside the root and be a bounded regular file


@pytest.mark.parametrize("declared", ["../outside.json", "/etc/hostname", "sub/../../outside.json"])
def test_repository_declared_report_cannot_leave_the_root(tmp_path: Path, declared: str) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (tmp_path / "outside.json").write_bytes(FIXTURE.read_bytes())
    result = _collect(root, {"shadowscan": {"report": declared}})
    assert result.status is E.CollectorStatus.FAILED
    assert "leaves the scan root" in (result.reason or "") or "not read" in (result.reason or "")
    assert not result.entities


def test_repository_declared_report_symlink_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (tmp_path / "outside.json").write_bytes(FIXTURE.read_bytes())
    (root / "report.json").symlink_to(tmp_path / "outside.json")
    result = _collect(root, {"shadowscan": {"report": "report.json"}})
    assert result.status is E.CollectorStatus.FAILED and not result.entities


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_repository_declared_fifo_does_not_hang(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    os.mkfifo(root / "report.json")
    started = time.monotonic()
    result = _collect(root, {"shadowscan": {"report": "report.json"}})
    assert time.monotonic() - started < 5
    assert result.status is E.CollectorStatus.FAILED


def test_repository_declared_report_inside_root_still_works(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "reports").mkdir(parents=True)
    (root / "reports" / "ss.json").write_bytes(FIXTURE.read_bytes())
    result = _collect(root, {"shadowscan": {"report": "reports/ss.json"}})
    assert result.status is E.CollectorStatus.OK and result.entities


def test_read_report_refuses_devices_fifos_and_symlinks(tmp_path: Path) -> None:
    if Path("/dev/zero").exists():
        with pytest.raises(ReportError, match="regular file"):
            read_report(Path("/dev/zero"))
    link = tmp_path / "link.json"
    link.symlink_to(FIXTURE)
    with pytest.raises(ReportError, match="symbolic link"):
        read_report(link)
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "fifo.json"
        os.mkfifo(fifo)
        with pytest.raises(ReportError, match="regular file"):
            read_report(fifo)


# (9) CycloneDX validation must stay linear in the number of entries


def test_cyclonedx_validation_is_linear() -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "services": [{"bom-ref": f"s{i}", "name": f"svc{i}"} for i in range(4000)],
    }
    started = time.monotonic()
    assert validate_cyclonedx(doc) == []
    assert time.monotonic() - started < 20  # was ~135 s with quadratic uniqueItems


def test_cyclonedx_duplicates_still_rejected() -> None:
    dup = {"bom-ref": "a", "name": "x"}
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "services": [dup, dict(dup)]}
    assert validate_cyclonedx(doc)
    # JSON Schema equality: 1 and 1.0 are equal, true and 1 are not
    from symbiote.export.cdx.validate import _canonical

    assert _canonical(1) == _canonical(1.0)
    assert _canonical(True) != _canonical(1)


# (2) no absolute scan-root disclosure when there is no agent declaration


def test_scan_root_locator_is_relative(tmp_path: Path) -> None:
    from symbiote.scan import scan

    repo = tmp_path / "secret-customer-path" / "repo"
    repo.mkdir(parents=True)
    bom = scan(repo, deterministic=True).bom
    assert str(tmp_path) not in bom.root_agent.provenance.locator


# (3) repository-supplied names cannot inject terminal markup or control sequences


def test_cli_output_neutralises_markup_and_control_characters() -> None:
    from rich.console import Console

    from symbiote.cli._render import safe_markup

    console = Console(force_terminal=False, width=200)
    with console.capture() as cap:
        console.print(
            safe_markup("[red]ok[/red] [link=https://evil]safe[/link][conceal]HIDDEN[/conceal]\x1b[2J‮")
        )
    out = cap.get()
    assert "[link=https://evil]" in out and "[conceal]HIDDEN[/conceal]" in out  # printed literally
    assert "\x1b" not in out and "‮" not in out
    assert out.startswith("ok ")  # the CLI's own style tags still render


# (4) variation selectors are hidden code points


def test_variation_selectors_are_hidden() -> None:
    from symbiote.digest.textflags import hidden_code_points

    assert (
        hidden_code_points("I \u2764\ufe0f it") == []
    )  # one selector after a visible base is ordinary emoji
    assert hidden_code_points("\u8fbb\U000e0100") == []  # ideographic variation sequence
    assert hidden_code_points("x\ufe0f\ufe0f") == ["U+FE0F"]  # a run smuggles data
    assert hidden_code_points("\U000e0101 hidden") == ["U+E0101"]  # no base
    assert hidden_code_points("a\u180b\u180b") == ["U+180B"]  # Mongolian free variation selectors


# (5) shell wrappers and repeated packages do not hide the package identity


def test_shell_wrappers_and_repeated_packages() -> None:
    from symbiote.collect.launchers import parse_launch

    wrapped = parse_launch("cmd", ["/c", "npx", "-y", "@evil/x"])
    assert wrapped.purl == "pkg:npm/%40evil/x" and "shell-wrapper:cmd" in wrapped.risky_flags
    assert parse_launch("sh", ["-c", "npx -y pkg@1.0.0"]).purl == "pkg:npm/pkg@1.0.0"
    multi = parse_launch("npx", ["-p", "a@1.0.0", "-p", "b@2.0.0", "run"])
    assert not multi.pinned and multi.float_reason == "multiple-packages"


# (6) deeply nested schemas cannot exhaust the recursion limit


def test_deep_schema_does_not_recurse() -> None:
    from symbiote.digest.textflags import tool_text_flags

    schema: dict = {"type": "object"}
    cur = schema
    for _ in range(20_000):
        cur["properties"] = {"x": {"description": "d"}}
        cur = cur["properties"]["x"]
    cur["$ref"] = "https://evil.example/x"
    assert [f.value for f in tool_text_flags({"name": "t", "inputSchema": schema})] == ["external-ref"]


# (7) a non-UTF-8 file name fails closed instead of crashing


@pytest.mark.skipif(os.name == "nt", reason="POSIX byte file names")
def test_dirmanifest_non_utf8_name_fails_closed(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from symbiote.cli.app import app
    from symbiote.digest import UndigestableError, build_dir_manifest

    target = tmp_path / "d"
    target.mkdir()
    try:
        with open(os.path.join(os.fsencode(target), b"bad\xff.txt"), "wb") as fh:
            fh.write(b"x")
    except OSError:
        pytest.skip("file system refuses non-UTF-8 names")
    with pytest.raises(UndigestableError):
        build_dir_manifest(target)
    result = CliRunner().invoke(app, ["digest", "dir", str(target)])
    assert result.exit_code == 3


# re-verification follow-ups


@pytest.mark.parametrize(
    ("command", "args", "secret"),
    [
        (
            "npx",
            ["--registry", "https://ghp_S3CR3TUSERTOKEN123@npm.pkg.github.com/", "-y", "w@2.0.0"],
            "ghp_S3CR3T",
        ),
        ("uvx", ["--index-url", "https://bob:PASSWORD-AAAA@h.example/simple?token=q#f", "p==1"], "PASSWORD"),
    ],
)
def test_index_credentials_never_reach_purl_or_identity(command: str, args: list[str], secret: str) -> None:
    from symbiote.collect.launchers import parse_launch
    from symbiote.digest import server_identity_digest

    facts = parse_launch(command, args)
    assert secret not in (facts.purl or "") and "token=" not in (facts.purl or "")
    other = parse_launch(command, [a.replace("AAAA", "BBBB").replace("S3CR3T", "OTHER1") for a in args])

    def ident(f):
        return server_identity_digest(
            kind="mcp", transport="stdio", endpoint=None, package={"purl": f.purl, "digest": None}
        ).value

    assert ident(facts) == ident(other)  # no offline credential oracle


@pytest.mark.parametrize(
    ("command", "args"),
    [("bash", ["-lc", "npx -y pkg"]), ("sh", ["-ec", "npx -y pkg"]), ("env", ["FOO=1", "npx", "-y", "pkg"])],
)
def test_more_wrappers_are_unwrapped(command: str, args: list[str]) -> None:
    from symbiote.collect.launchers import parse_launch

    facts = parse_launch(command, args)
    assert facts.purl == "pkg:npm/pkg" and not facts.pinned


def test_canonical_bytes_fails_closed_on_deep_documents() -> None:
    from symbiote.digest.jcs import UndigestableError, canonical_bytes

    doc: dict = {}
    cur = doc
    for _ in range(20_000):
        cur["a"] = {}
        cur = cur["a"]
    with pytest.raises(UndigestableError, match="too-deep"):
        canonical_bytes(doc)


def test_click_is_a_declared_dependency() -> None:
    import tomllib

    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    deps = tomllib.loads(pyproject.read_text())["project"]["dependencies"]
    assert any(d.startswith("click") for d in deps)  # cli/update_cmd.py imports click directly
