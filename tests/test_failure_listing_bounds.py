"""Failure and gap lists stay bounded however a tree multiplies them, and the inventory loads."""

from __future__ import annotations

import json
import os
import re
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner, Result

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.scanners.a2a import A2AScanner
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.prompt import PromptScanner
from nexus_symbiote.utils.confined import MAX_LISTED_FAILURE_CHARACTERS, MAX_LISTED_FAILURES

VARIANT = "is the active file on case-insensitive file systems and is not inventoried"
NOT_UTF8 = "symlink target name is not valid UTF-8; not collected"
_SUMMARY = re.compile(r" \(and (\d+) more (?:failures? )?not listed\)$")


def _spellings(name: str, count: int) -> list[str]:
    """``count`` other spellings of ``name`` that differ from it only by case."""
    letters = [index for index, character in enumerate(name) if character.isalpha()]
    spellings: list[str] = []
    for mask in range(1, 1 << len(letters)):
        characters = list(name)
        for bit, position in enumerate(letters):
            if mask >> bit & 1:
                characters[position] = characters[position].upper()
        spellings.append("".join(characters))
        if len(spellings) == count:
            break
    return spellings


def _scan(project: Path, output: Path, *options: str) -> tuple[Result, AIBOM]:
    """Scan with the gate on; the inventory is written, whatever the gate decides."""
    args = [*options, "scan", str(project), "--no-project-policy", "-o", str(output)]
    run = CliRunner().invoke(main, args)
    assert run.exit_code in (0, 1), run.output
    assert "Inventory not written" not in run.output
    return run, AIBOM.load(output)


def _failures(bom: AIBOM) -> list[str]:
    claim = bom.metadata.completeness
    assert claim is not None
    return list(claim.scan_failures)


def _listed(failures: list[str]) -> list[str]:
    return [failure for failure in failures if not _SUMMARY.search(failure)]


def _counted(failures: list[str]) -> int:
    """How many failures the lines stand for, a summary line for itself and the rest."""
    return sum(
        1 + int(match.group(1)) if (match := _SUMMARY.search(failure)) else 1
        for failure in failures
    )


def _linked_spellings(root: Path, links: int, holder: str, names: tuple[str, ...]) -> None:
    """``links`` directories ``pK/<holder> -> ../t``, where t holds 16 other spellings of
    each name and none of the names themselves."""
    target = root / "t"
    target.mkdir(parents=True)
    for name in names:
        for spelling in _spellings(name, 16):
            (target / spelling).write_text("{}")
    if len(os.listdir(target)) != 16 * len(names):
        pytest.skip("file system folds case")
    for index in range(links):
        (root / f"p{index}").mkdir()
        (root / f"p{index}" / holder).symlink_to("../t", target_is_directory=True)


@pytest.mark.parametrize(
    ("scanner", "holder", "names"),
    [
        (IDEAgentScanner, ".claude", ("settings.json", "settings.local.json")),
        (A2AScanner, ".well-known", ("agent.json", "agent-card.json")),
    ],
)
def test_a_case_variant_is_listed_once_however_many_links_lead_to_it(
    tmp_path, scanner, holder, names
):
    # Each link to one directory of 32 spellings added 32 lines with two paths each:
    # about 100 links made an inventory too large to write.
    found = {}
    for links in (150, 300):
        root = tmp_path / str(links)
        _linked_spellings(root, links, holder, names)
        failures = scanner().scan(root).scan_failures
        found[links] = sorted(failures)
        assert len(failures) == 32
        assert all(VARIANT in failure for failure in failures)
        assert {failure.split(":")[0].rsplit("/", 1)[1] for failure in failures} == {
            spelling for name in names for spelling in _spellings(name, 16)
        }
    assert found[150] == found[300]
    run, bom = _scan(tmp_path / "300", tmp_path / "out.json")
    assert run.exit_code == 1
    assert sorted(failure for failure in _failures(bom) if VARIANT in failure) == found[300]


def test_spellings_found_by_a_walk_are_listed_within_the_bounds(tmp_path):
    # One nested .claude holding thousands of names that fold to settings.json listed
    # one failure each, without bound.
    shapes = {}
    for count in (750, 1_500):
        settings = tmp_path / str(count) / "pkg" / ".claude"
        settings.mkdir(parents=True)
        for index in range(count):
            tail = format(index, "011b").replace("0", ".").replace("1", " ")
            (settings / ("Settings.json" + tail)).write_text("{}")
        failures = IDEAgentScanner().scan(tmp_path / str(count)).scan_failures
        listed = _listed(failures)
        assert len(listed) <= MAX_LISTED_FAILURES
        assert sum(map(len, listed)) <= MAX_LISTED_FAILURE_CHARACTERS
        assert len(failures) == len(listed) + 1
        assert _counted(failures) == count
        assert all(VARIANT in failure for failure in failures)
        shapes[count] = (len(failures), sum(map(len, listed)))
    assert shapes[750] == shapes[1_500]
    _, bom = _scan(tmp_path / "1500", tmp_path / "out.json")
    assert _counted([f for f in _failures(bom) if VARIANT in f]) == 1_500


def test_candidates_that_fail_to_parse_are_listed_within_the_bounds(tmp_path):
    # The mcp collector bounded failures of its source search, but not those of the
    # parse that follows it.
    count = MAX_LISTED_FAILURES + 200
    project = tmp_path / "project"
    (project / "pkg").mkdir(parents=True)
    for index in range(count):
        (project / "pkg" / f"m{index:04d}.py").write_text("import mcp\nx = (\n")
    failures = MCPScanner().scan(project).scan_failures
    assert len(failures) == MAX_LISTED_FAILURES + 1
    assert failures[-1] == (
        f"pkg/m{MAX_LISTED_FAILURES:04d}.py: invalid Python syntax (and 199 more not listed)"
    )
    _, bom = _scan(project, tmp_path / "out.json")
    assert _counted([f for f in _failures(bom) if "invalid Python syntax" in f]) == count


def test_failures_a_collector_appends_itself_are_listed_within_the_bounds(tmp_path):
    # The prompt collector appends one failure per instruction file that is not UTF-8.
    count = MAX_LISTED_FAILURES + 200
    project = tmp_path / "project"
    for index in range(count):
        (project / f"d{index:04d}").mkdir(parents=True)
        (project / f"d{index:04d}" / "CLAUDE.md").write_bytes(b"\xff\n")
    failures = PromptScanner().scan(project).scan_failures
    assert len(failures) == MAX_LISTED_FAILURES + 1
    assert failures[-1] == (
        f"d{MAX_LISTED_FAILURES:04d}/CLAUDE.md: invalid UTF-8 instruction "
        "(and 199 more failures not listed)"
    )
    _, bom = _scan(project, tmp_path / "out.json")
    assert _counted([f for f in _failures(bom) if "invalid UTF-8 instruction" in f]) == count


def _bytes_path(path: Path) -> bytes:
    return os.fsencode(path)


def test_links_to_names_that_are_not_utf8_are_refused_and_the_inventory_loads(tmp_path):
    # Followed, such a link wrote lone surrogates into the inventory, which validate,
    # risk and diff then refused, and a linked skill directory lost every prompt record.
    project = tmp_path / "project"
    (project / ".claude" / "skills" / "ok").mkdir(parents=True)
    (project / ".well-known").mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    (project / ".claude" / "skills" / "ok" / "SKILL.md").write_text("A skill.")
    raw = _bytes_path(project)
    try:
        with open(raw + b"/\xff\xfe.md", "wb") as stream:
            stream.write(b"Instructions.")
        for name in (b"/set\xff.json", b"/card\xff.json"):
            with open(raw + name, "wb") as stream:
                stream.write(b"{}")
        os.makedirs(raw + b"/\xffvendor/pdf")
    except (OSError, UnicodeEncodeError):
        pytest.skip("file system rejects names that are not UTF-8")
    with open(raw + b"/\xffvendor/pdf/SKILL.md", "wb") as stream:
        stream.write(b"A linked skill.")
    os.mkfifo(raw + b"/\xffvendor/pdf/pipe")
    os.symlink(b"\xff\xfe.md", raw + b"/CLAUDE.md")
    os.symlink(b"../set\xff.json", raw + b"/.claude/settings.json")
    os.symlink(b"../card\xff.json", raw + b"/.well-known/agent.json")
    os.symlink(b"../../\xffvendor/pdf", raw + b"/.claude/skills/pdf")
    output = tmp_path / "out.json"
    run, bom = _scan(project, output)
    assert run.exit_code == 1
    assert "Scan gate failed" in run.output
    assert "\\ud" not in output.read_text(encoding="utf-8").lower()
    failures = _failures(bom)
    for link in ("CLAUDE.md", ".claude/settings.json", ".well-known/agent.json"):
        assert f"{link}: {NOT_UTF8}" in failures
    assert f".claude/skills/pdf: {NOT_UTF8}" in failures
    assert not any("vendor/pdf/" in failure for failure in failures)
    refs = {component.bom_ref for component in bom.components}
    assert {"prompt:AGENTS.md", "skill:.claude/skills/ok/SKILL.md"} <= refs
    for command in (["validate", str(output)], ["risk", str(output)]):
        assert "not a valid native AIBOM file" not in CliRunner().invoke(main, command).output


def test_a_collection_that_also_searches_source_states_the_total_bytes_set(tmp_path):
    # Its byte limit is total-bytes plus source-scan-bytes; the failure showed the sum
    # as if it were the total-bytes value the operator set.
    config = {"mcpServers": {"s": {"command": "node", "args": ["x" * 1500]}}}
    project = tmp_path / "project"
    for name in ("a", "b"):
        (project / name).mkdir(parents=True)
        (project / name / ".mcp.json").write_text(json.dumps(config))
    stated = (
        "b/.mcp.json: total-bytes limit of 2 KiB (plus 1 KiB source-scan-bytes for source "
        "search) exceeded; raise it with --limit total-bytes=N"
    )
    configured = replace(limits.DEFAULTS, total_bytes=2 * limits.KIB, source_scan_bytes=limits.KIB)
    with limits.applied(configured):
        assert MCPScanner().scan(project).scan_failures == [stated]
    options = ("--limit", "total-bytes=2KiB", "--limit", "source-scan-bytes=1KiB")
    _, bom = _scan(project, tmp_path / "out.json", *options)
    assert stated in _failures(bom)
