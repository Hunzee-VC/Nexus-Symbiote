"""Every Markdown link, image and anchor in the repository resolves."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_docs", ROOT / "scripts" / "check_docs.py")
assert SPEC is not None and SPEC.loader is not None
check_docs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_docs)


def test_slugify_matches_github_anchors() -> None:
    assert check_docs.slugify("Install from reviewed source") == "install-from-reviewed-source"
    assert check_docs.slugify("The `--offline` flag") == "the---offline-flag"
    assert check_docs.slugify("Commands and exit codes") == "commands-and-exit-codes"
    assert check_docs.slugify("Why: what problem it solves?") == "why-what-problem-it-solves"


def test_duplicate_headings_get_numbered_anchors(tmp_path: Path) -> None:
    page = tmp_path / "page.md"
    page.write_text("# Same\n\n## Same\n\n```\n# not a heading\n```\n", encoding="utf-8")
    assert check_docs.anchors(page) == {"same", "same-1"}


def test_broken_relative_link_and_anchor_are_reported(tmp_path: Path) -> None:
    (tmp_path / "a.md").write_text(
        "[ok](b.md#there) [bad](missing.md) [frag](b.md#nope)\n", encoding="utf-8"
    )
    (tmp_path / "b.md").write_text("## There\n", encoding="utf-8")
    errors = check_docs.check_all(tmp_path)
    assert len(errors) == 2
    assert any("missing.md: file does not exist" in error for error in errors)
    assert any("#nope" in error for error in errors)


def test_repository_markdown_links_resolve() -> None:
    assert check_docs.check_all() == []
