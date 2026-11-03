"""Offline hygiene checks retain provenance and reject merge and documentation regressions."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "repository_hygiene", Path(__file__).parents[1] / "scripts/check_repository_hygiene.py"
)
assert SPEC and SPEC.loader
hygiene = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hygiene)


def test_committed_merge_conflicts_are_reported(tmp_path):
    path = tmp_path / "source.py"
    path.write_text("<<<<<<< HEAD\na = 1\n=======\na = 2\n>>>>>>> feature\n")
    assert "merge conflict" in hygiene.source_issues(tmp_path, [Path("source.py")])[0]


def test_local_links_resolve_from_document_and_ignore_examples_and_web(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text("# Anchor\n")
    doc = tmp_path / "docs" / "guide.md"
    doc.write_text(
        "[root](../README.md#anchor)\n[web](https://example.invalid/unfetched)\n"
        "```md\n[example](nonexistent.md)\n```\n"
    )
    assert hygiene.source_issues(tmp_path, [Path("docs/guide.md")]) == []
    doc.write_text("[broken](missing.md)\n[escape](../../outside.md)\n")
    assert len(hygiene.source_issues(tmp_path, [Path("docs/guide.md")])) == 2


def test_heading_anchors_follow_github_slugs():
    text = (
        "# Install from `source`\n## Why: offline, by default\n## FAQ\n## FAQ\n"
        "### [Linked](https://example.invalid) **bold** heading ###\n"
        '<a id="explicit"></a>\n```md\n# Not a heading\n```\n'
    )
    assert hygiene.heading_anchors(text) == {
        "install-from-source",
        "why-offline-by-default",
        "faq",
        "faq-1",
        "linked-bold-heading",
        "explicit",
    }


def test_link_fragments_must_name_an_existing_heading(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("# Guide\n## Install from source\n")
    page = tmp_path / "README.md"
    page.write_text(
        "## Usage\n[same](#usage) [other](docs/guide.md#install-from-source)\n"
        '<a href="#usage">html</a> [line](docs/guide.md#L2) [code](scripts/x.py#main)\n'
    )
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "x.py").write_text("")
    assert hygiene.source_issues(tmp_path, [Path("README.md")]) == []
    page.write_text(
        '[a](#missing) [b](docs/guide.md#install) <a href="#gone">c</a>\n```md\n[d](#x)\n```\n'
    )
    issues = hygiene.source_issues(tmp_path, [Path("README.md")])
    assert len(issues) == 3 and all("missing heading" in issue for issue in issues)


def test_absolute_links_into_this_repository_must_resolve(tmp_path):
    _project(tmp_path)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("# Guide\n## Install\n")
    (tmp_path / "docs" / "banner.jpg").write_bytes(b"\xff\xd8")
    base = "https://github.com/canonical-org/widget"
    readme = tmp_path / "README.md"
    readme.write_text(
        f"[guide]({base}/blob/main/docs/guide.md#install) [dir]({base}/tree/main/docs)\n"
        '<img src="https://raw.githubusercontent.com/Canonical-Org/Widget/main/docs/banner.jpg">\n'
        f"[issue]({base}/issues/1) [other](https://github.com/other/widget/blob/main/x.md)\n"
    )
    files = [Path("README.md")]
    assert hygiene.self_link_issues(tmp_path, files) == []
    readme.write_text(
        f"[gone]({base}/blob/main/docs/missing.md) [anchor]({base}/blob/main/docs/guide.md#nope)\n"
        "![raw](https://raw.githubusercontent.com/Canonical-Org/Widget/main/missing.png)\n"
        f"[escape]({base}/blob/main/../outside.md)\n"
    )
    issues = hygiene.self_link_issues(tmp_path, files)
    assert len(issues) == 4
    assert sum("missing heading" in issue for issue in issues) == 1


def test_source_symlink_is_not_read(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.write_text("source")
    (tmp_path / "source.py").symlink_to(outside)
    assert "unsafe" in hygiene.source_issues(tmp_path, [Path("source.py")])[0]


def test_declared_versions_match_without_importing_project_code(tmp_path):
    package = tmp_path / "src/nexus_symbiote"
    package.mkdir(parents=True)
    marker = tmp_path / "executed"
    (package / "__init__.py").write_text(
        f'__version__ = "0.1.0"\nraise RuntimeError({str(marker)!r})\n'
    )
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.1.0"\n')
    assert hygiene.version_issues(tmp_path) == [] and not marker.exists()
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.2.0"\n')
    assert hygiene.version_issues(tmp_path)


@pytest.mark.parametrize("mutation", ["modified", "unlisted", "duplicate", "traversal"])
def test_vendored_schema_provenance_cannot_silently_drift(tmp_path, mutation):
    vendor = tmp_path / hygiene.VENDOR
    vendor.mkdir(parents=True)
    schema = b'{"type":"object"}'
    (vendor / "example.json").write_bytes(schema)
    record = {"file": "example.json", "sha256": hashlib.sha256(schema).hexdigest()}
    manifest = {"files": [record]}
    source = vendor / "SOURCES.json"
    source.write_text(json.dumps(manifest))
    assert hygiene.vendor_issues(tmp_path) == []
    if mutation == "modified":
        (vendor / "example.json").write_text('{"type":"string"}')
    elif mutation == "unlisted":
        (vendor / "extra.json").write_text("{}")
    elif mutation == "duplicate":
        manifest["files"].append(record)
    else:
        record["file"] = "../outside.json"
    source.write_text(json.dumps(manifest))
    assert hygiene.vendor_issues(tmp_path)


def _project(root: Path, homepage: str = "https://github.com/Canonical-Org/Widget") -> None:
    root.joinpath("pyproject.toml").write_text(
        f'[project]\nname = "widget"\nversion = "1.0.0"\n[project.urls]\nHomepage = "{homepage}"\n'
    )


def test_stale_owner_links_to_this_repository_are_reported(tmp_path):
    _project(tmp_path)
    tmp_path.joinpath("SUPPORT.md").write_text(
        "[issues](https://github.com/old-owner/Widget/issues)\n"
    )
    issues = hygiene.owner_issues(tmp_path, [Path("SUPPORT.md")])
    assert issues == ["SUPPORT.md: links to old-owner/Widget instead of Canonical-Org/Widget"]


def test_canonical_owner_and_unrelated_repositories_are_accepted(tmp_path):
    _project(tmp_path)
    tmp_path.joinpath("README.md").write_text(
        "[canonical](https://github.com/Canonical-Org/Widget/blob/main/X.md)\n"
        "[case](https://github.com/canonical-org/widget)\n"
        "[sibling](https://github.com/old-owner/OtherProject)\n"
        "[profile](https://github.com/old-owner)\n"
        "[pypi](https://pypi.org/p/Widget)\n"
    )
    assert hygiene.owner_issues(tmp_path, [Path("README.md")]) == []


def test_stale_owner_slug_outside_a_url_is_reported(tmp_path):
    _project(tmp_path)
    tmp_path.joinpath("docs.md").write_text("    gh attestation verify x --repo old-owner/widget\n")
    assert len(hygiene.owner_issues(tmp_path, [Path("docs.md")])) == 1


def test_dated_audits_keep_the_owner_recorded_at_the_time(tmp_path):
    _project(tmp_path)
    audit = tmp_path / "docs" / "audits"
    audit.mkdir(parents=True)
    audit.joinpath("a.md").write_text("[run](https://github.com/old-owner/Widget/actions/runs/1)\n")
    assert hygiene.owner_issues(tmp_path, [Path("docs/audits/a.md")]) == []


def test_unparseable_homepage_fails_closed(tmp_path):
    _project(tmp_path, homepage="https://example.invalid/widget")
    assert hygiene.owner_issues(tmp_path, [Path("README.md")]) == [
        "canonical repository owner could not be determined"
    ]


def test_tracked_repository_passes_its_own_owner_check():
    root = Path(__file__).parents[1]
    listing = subprocess.run(  # noqa: S603 - fixed read-only Git operation
        [shutil.which("git") or "git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        check=True,
        timeout=10,
    )
    files = [Path(value) for value in listing.stdout.decode().split("\0") if value]
    assert hygiene.owner_issues(root, files) == []
