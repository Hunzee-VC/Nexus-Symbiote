"""Check that Markdown links and images in the repository resolve.

Relative links must point at existing files, fragments must name a heading in
the target Markdown file, and absolute links into this repository on GitHub must
point at files that exist in the checkout. External URLs are never fetched.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_URLS = (
    "https://github.com/aisecnomad/Nexus-symbiote/",
    "https://github.com/aisecnomad/nexus-symbiote/",
)
SKIP_PARTS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "dist",
        "build",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "fixtures",
    }
)
FENCE = re.compile(r"```.*?```", re.DOTALL)
INLINE_CODE = re.compile(r"`[^`\n]*`")
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REFERENCE_DEFINITION = re.compile(
    r"^\s*\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+\"[^\"]*\")?\s*$", re.MULTILINE
)
HTML_LINK = re.compile(r"<(?:a|img)\b[^>]*?\b(?:href|src)=\"([^\"]+)\"", re.IGNORECASE)
HEADING = re.compile(r"^#{1,6}[ \t]+(.*?)[ \t]*#*[ \t]*$", re.MULTILINE)
HTML_ID = re.compile(r"\bid=\"([^\"]+)\"")


def markdown_files(root: Path = ROOT) -> list[Path]:
    return sorted(
        path for path in root.rglob("*.md") if not (set(path.relative_to(root).parts) & SKIP_PARTS)
    )


def slugify(heading: str) -> str:
    """Approximate GitHub's heading anchors: lower case, punctuation removed, spaces to hyphens."""
    text = re.sub(r"`([^`]*)`", r"\1", heading)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[^\w\- ]", "", text.strip().lower())
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    text = FENCE.sub("", path.read_text(encoding="utf-8"))
    seen: dict[str, int] = {}
    result: set[str] = set()
    for match in HEADING.finditer(text):
        slug = slugify(match.group(1))
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        result.add(slug if count == 0 else f"{slug}-{count}")
    result.update(HTML_ID.findall(text))
    return result


def check_fragment(path: Path, fragment: str) -> str | None:
    if unquote(fragment).lower() not in anchors(path):
        return f"no heading or id matches #{fragment}"
    return None


def check_path(base: Path, target: str) -> str | None:
    path_part, _, fragment = target.partition("#")
    path_part = unquote(path_part)
    resolved = (base / path_part) if path_part else base
    if not resolved.exists():
        return "file does not exist"
    if fragment and resolved.is_file() and resolved.suffix == ".md":
        return check_fragment(resolved, fragment)
    return None


def check_target(source: Path, target: str) -> str | None:
    if target.startswith(("mailto:", "tel:")):
        return None
    for prefix in REPOSITORY_URLS:
        if target.startswith(prefix):
            rest = target[len(prefix) :]
            for kind in ("blob/main/", "tree/main/"):
                if rest.startswith(kind):
                    return check_path(ROOT, rest[len(kind) :])
            return None
    if "://" in target:
        return None
    if target.startswith("#"):
        return check_fragment(source, target[1:])
    return check_path(source.parent, target)


def check_file(path: Path, root: Path = ROOT) -> list[str]:
    raw = path.read_text(encoding="utf-8")
    text = FENCE.sub(lambda match: "\n" * match.group(0).count("\n"), raw)
    text = INLINE_CODE.sub("", text)
    errors: list[str] = []
    for pattern in (MARKDOWN_LINK, REFERENCE_DEFINITION, HTML_LINK):
        for match in pattern.finditer(text):
            target = match.group(1)
            problem = check_target(path, target)
            if problem:
                line = text.count("\n", 0, match.start()) + 1
                errors.append(f"{path.relative_to(root)}:{line}: {target}: {problem}")
    return errors


def check_all(root: Path = ROOT) -> list[str]:
    return [error for path in markdown_files(root) for error in check_file(path, root)]


def main() -> int:
    errors = check_all()
    for error in errors:
        print(error)
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
