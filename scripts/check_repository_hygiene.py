"""Check tracked source conflicts, inline local doc links, versions and vendor digests offline."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
import subprocess
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlsplit

VENDOR = Path("src/nexus_symbiote/generators/schemas/vendor")
MAX_FILE_BYTES = 2 * 1024 * 1024
LINK = re.compile(r'!?\[[^\]\n]*\]\((<[^>\n]+>|[^)\s]+)(?:\s+"[^"\n]*")?\)')
MARKER = re.compile(r"^(?:<{7}|>{7}|\|{7})(?: .*)?$", re.M)


def read_file(root: Path, relative: Path) -> bytes:
    path = root / relative
    if relative.is_absolute() or ".." in relative.parts or path.is_symlink():
        raise ValueError("unsafe tracked path")
    if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("tracked file is missing or outside the repository")
    with path.open("rb") as stream:
        value = stream.read(MAX_FILE_BYTES + 1)
    if len(value) > MAX_FILE_BYTES:
        raise ValueError("file exceeds the hygiene check byte limit")
    return value


def source_issues(root: Path, files: list[Path]) -> list[str]:
    errors = []
    for relative in files:
        if relative.suffix not in {".py", ".md", ".toml", ".yml", ".yaml"}:
            continue
        if "fixtures" in relative.parts or VENDOR in relative.parents:
            continue
        try:
            text = read_file(root, relative).decode("utf-8")
        except (OSError, ValueError, UnicodeError):
            errors.append(f"{relative}: source is unavailable or unsafe")
            continue
        if MARKER.search(text):
            errors.append(f"{relative}: unresolved merge conflict marker")
        if relative.suffix != ".md":
            continue
        fence = ""
        for line in text.splitlines():
            stripped = line.lstrip()
            if stripped.startswith(("```", "~~~")):
                marker = stripped[:3]
                fence = "" if fence == marker else fence if fence else marker
                continue
            if fence:
                continue
            for match in LINK.finditer(line):
                link = match[1].strip("<>")
                parsed = urlsplit(link)
                if parsed.scheme or parsed.netloc or not parsed.path:
                    continue
                local = unquote(parsed.path)
                target = (
                    root / local.lstrip("/")
                    if local.startswith("/")
                    else root / relative.parent / local
                )
                if not target.resolve().is_relative_to(root.resolve()) or not target.exists():
                    errors.append(f"{relative}: missing or escaping inline local link: {link}")
    return errors


def version_issues(root: Path) -> list[str]:
    try:
        project = tomllib.loads(read_file(root, Path("pyproject.toml")).decode())["project"][
            "version"
        ]
        module = ast.parse(read_file(root, Path("src/nexus_symbiote/__init__.py")).decode())
        versions = [
            ast.literal_eval(node.value)
            for node in module.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__version__"
                for target in node.targets
            )
        ]
        if not isinstance(project, str) or versions != [project]:
            return ["distribution and package versions disagree"]
    except (OSError, ValueError, KeyError, SyntaxError, UnicodeError):
        return ["distribution or package version could not be checked"]
    return []


def vendor_issues(root: Path) -> list[str]:
    errors = []
    try:
        records = json.loads(read_file(root, VENDOR / "SOURCES.json"))["files"]
        if not isinstance(records, list) or not records:
            raise ValueError("missing schema provenance")
        seen = set()
        for record in records:
            name, expected = record["file"], record["sha256"]
            relative = Path(name)
            if name in seen or relative.is_absolute() or ".." in relative.parts:
                raise ValueError("invalid or duplicate vendor path")
            seen.add(name)
            if not isinstance(expected, str) or not re.fullmatch("[0-9a-f]{64}", expected):
                raise ValueError("invalid digest")
            if hashlib.sha256(read_file(root, VENDOR / relative)).hexdigest() != expected:
                errors.append(f"{VENDOR / relative}: differs from its reviewed provenance digest")
        actual = {
            p.relative_to(root / VENDOR).as_posix()
            for p in (root / VENDOR).rglob("*.json*")
            if p.name != "SOURCES.json"
        }
        if actual != seen:
            errors.append("vendored schema files and provenance entries disagree")
    except (OSError, ValueError, KeyError, TypeError):
        errors.append("vendored schema provenance is unavailable or invalid")
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        git = shutil.which("git")
        if git is None:
            raise OSError("Git is unavailable")
        result = subprocess.run(  # noqa: S603 - fixed read-only Git operation
            [git, "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=True,
            timeout=10,
        )
        files = [Path(value) for value in result.stdout.decode().split("\0") if value]
        errors = [*source_issues(root, files), *version_issues(root), *vendor_issues(root)]
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Repository hygiene could not inspect the tracked source.")
        return 1
    for error in errors:
        print(error)
    if not errors:
        print(f"Repository hygiene passed for {len(files)} tracked paths.")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
