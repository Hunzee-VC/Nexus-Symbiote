"""Minimal textual edits for update proposals (``spec/monitoring.md`` §4).

A proposal is applied by replacing one string token (``"pkg@latest"`` → ``"pkg@1.4.2"``) in the configuration
file that declares the dependency, located by ``DependencyRef.locators`` (``<path>#<json pointer>``). Nothing
else in the file changes: no re-serialisation, so formatting, comments, key order and line endings survive
byte for byte.

Safety rules:

* The edit is verified, not guessed: each literal occurrence of the old token is tried in turn, the file is
  re-parsed, and the edit is accepted only when exactly one occurrence yields *exactly* the original document
  with the value at the locator replaced. Occurrences in comments, in other servers or in other keys therefore
  never match; two indistinguishable occurrences make the edit ambiguous and it is refused.
* Paths must stay under ``root``; absolute paths, ``~``, ``..`` and symbolic links anywhere on the path are
  refused. Files are read with a byte cap and written atomically (temporary file + ``os.replace``).
* Tokens are restricted to a conservative character set (no quotes, backslashes, whitespace or ``$``), so a
  replacement can never change the file's structure. A proposal whose edit cannot be made safely gets a
  review note instead of an edit.

Package contents are never fetched, installed or imported.
"""

from __future__ import annotations

import copy
import difflib
import os
import re
import stat
import tempfile
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any, Final, Literal

from symbiote.collect._common import parse_structured
from symbiote.update.types import FileEdit, UpdateProposal

__all__ = ["PatchError", "apply_proposals", "locate_edits", "render_diff", "rewrite_token"]

Fmt = Literal["json", "jsonc", "toml", "yaml"]

MAX_CONFIG_BYTES: Final = 1024 * 1024
_MAX_OCCURRENCES: Final = 64
_SAFE_TOKEN: Final = re.compile(r"^[A-Za-z0-9@/._:+=~^<>!,*\[\]-]{1,512}$")
_TOKEN_CHAR: Final = re.compile(r"[A-Za-z0-9@/._:+=~^<>!*-]")  # brackets and commas delimit YAML flow items
_OCI_DIGEST: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_OCI_DIGEST_SUFFIX: Final = re.compile(r"@sha256:[0-9a-f]{64}$")
_PYPI_SPEC: Final = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]{0,200})(?P<extras>\[[A-Za-z0-9._,-]{0,200}\])?(?P<rest>.{0,200})$"
)
_EDITABLE_KINDS: Final = frozenset({"pin", "security", "version"})
_PREFIXES: Final[dict[str, tuple[str, ...]]] = {
    "npm": ("--package=", "-p=", "npm:"),
    "pypi": ("--from=", "--spec=", "--with="),
    "oci": (),
}


class PatchError(ValueError):
    """An edit that cannot be made safely; the message is a reason fit for a review note."""


# --------------------------------------------------------------------------------------------- tokens


def _norm_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _split_npm(spec: str) -> tuple[str, str | None]:
    if spec.startswith("@"):
        slash = spec.find("/")
        at = spec.find("@", slash if slash != -1 else 1)
        return (spec, None) if at == -1 else (spec[:at], spec[at + 1 :])
    name, sep, version = spec.partition("@")
    return name, version if sep else None


def _oci_name(image: str) -> tuple[str, str]:
    """``(image without tag/digest, normalised registry/repository)`` for an image reference."""
    ref = _OCI_DIGEST_SUFFIX.sub("", image)
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref = ref[: len(ref) - len(last)] + last.split(":", 1)[0]
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        normal = ref
    else:
        normal = "docker.io/" + ("library/" + ref if len(parts) == 1 else ref)
    return ref, normal.lower()


def _oci_matches(dep_name: str, image: str) -> bool:
    _, normal = _oci_name(image)
    _, dep_normal = _oci_name(dep_name)
    return normal == dep_normal


def rewrite_token(ecosystem: str, name: str, token: str, proposed: str) -> str | None:
    """The replacement for ``token`` if it references package ``name``; ``None`` when it does not.

    ``npx`` specs become ``pkg@<version>``, ``uvx``/``pipx`` specs ``pkg==<version>`` and OCI images
    ``image@sha256:<digest>`` (only when ``proposed`` is a digest). Option prefixes such as ``--package=`` or
    ``--from=`` are kept.
    """
    prefix = next((p for p in _PREFIXES.get(ecosystem, ()) if token.startswith(p)), "")
    spec = token[len(prefix) :]
    if not spec:
        return None
    if ecosystem == "npm":
        pkg, _ = _split_npm(spec)
        if pkg != name or not pkg:
            return None
        return f"{prefix}{pkg}@{proposed}"
    if ecosystem == "pypi":
        if spec.startswith(("git+", "http://", "https://", "file:", ".", "/")):
            return None
        match = _PYPI_SPEC.match(spec)
        if not match or _norm_pypi(match.group("name")) != _norm_pypi(name):
            return None
        rest = match.group("rest").strip()
        if rest and not rest.startswith(("==", "@", ">", "<", "~=", "!=", "===")):
            return None
        return f"{prefix}{match.group('name')}{match.group('extras') or ''}=={proposed}"
    if ecosystem == "oci":
        if spec.startswith("-") or not _oci_matches(name, spec):
            return None
        if not _OCI_DIGEST.match(proposed):
            raise PatchError("the image digest is not known, so the tag cannot be pinned")
        bare, _ = _oci_name(spec)
        return f"{prefix}{bare}@{proposed}"
    return None


# --------------------------------------------------------------------------------------------- locators & paths


def _split_locator(locator: str) -> tuple[str, list[str]]:
    path, sep, pointer = locator.partition("#")
    if not sep:
        raise PatchError(f"locator {locator!r} has no JSON pointer")
    if pointer and not pointer.startswith("/"):
        raise PatchError(f"locator {locator!r} has an invalid JSON pointer")
    tokens = [t.replace("~1", "/").replace("~0", "~") for t in pointer.split("/")[1:]] if pointer else []
    return path, tokens


def _pointer(tokens: Sequence[str]) -> str:
    return "".join("/" + t.replace("~", "~0").replace("/", "~1") for t in tokens)


def _safe_path(root: Path, rel: str) -> Path:
    """Resolve ``rel`` under ``root`` refusing absolute paths, ``..`` and any symbolic link on the way."""
    if not rel or rel.startswith(("~", "/", "\\")) or "\\" in rel or "\x00" in rel:
        raise PatchError(f"{rel!r} is not a path relative to the agent root")
    parts = PurePosixPath(rel).parts
    if any(p in ("..", "") for p in parts) or PurePosixPath(rel).is_absolute():
        raise PatchError(f"{rel!r} escapes the agent root")
    base = Path(root)
    if base.is_symlink():
        raise PatchError("the agent root is a symbolic link")
    current = base
    for part in parts:
        if part == ".":
            continue
        current = current / part
        try:
            st = current.lstat()
        except FileNotFoundError:
            raise PatchError(f"{rel} does not exist") from None
        except OSError as exc:
            raise PatchError(f"{rel}: {exc.strerror or type(exc).__name__}") from None
        if stat.S_ISLNK(st.st_mode):
            raise PatchError(f"{rel} is or passes through a symbolic link")
    try:
        current.resolve(strict=True).relative_to(base.resolve(strict=True))
    except (ValueError, OSError):
        raise PatchError(f"{rel} is outside the agent root") from None
    if not current.is_file():
        raise PatchError(f"{rel} is not a regular file")
    return current


def _fmt_for(path: str) -> Fmt:
    lowered = path.lower()
    if lowered.endswith(".toml"):
        return "toml"
    if lowered.endswith((".yaml", ".yml")):
        return "yaml"
    if lowered.endswith((".json", ".jsonc")):
        return "jsonc"  # a superset of JSON: VS Code style comments and trailing commas are tolerated
    raise PatchError(f"{path}: unsupported configuration format")


def _read_text(path: Path, rel: str) -> str:
    try:
        with path.open("rb") as fh:
            data = fh.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise PatchError(f"{rel}: {exc.strerror or type(exc).__name__}") from None
    if len(data) > MAX_CONFIG_BYTES:
        raise PatchError(f"{rel} exceeds {MAX_CONFIG_BYTES} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise PatchError(f"{rel} is not UTF-8") from None


def _parse(text: str, fmt: Fmt, rel: str) -> Any:
    try:
        return parse_structured(text.encode("utf-8"), fmt)
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise PatchError(f"{rel} cannot be parsed ({type(exc).__name__})") from None
    except Exception as exc:  # yaml.YAMLError and friends: any parser failure means "cannot edit safely"
        raise PatchError(f"{rel} cannot be parsed ({type(exc).__name__})") from None


def _child(node: Any, token: str) -> Any:
    if isinstance(node, dict):
        if token not in node:
            raise KeyError(token)
        return node[token]
    if isinstance(node, list):
        if not token.isdigit() or int(token) >= len(node):
            raise KeyError(token)
        return node[int(token)]
    raise KeyError(token)


def _get(data: Any, tokens: Sequence[str]) -> Any:
    node = data
    for token in tokens:
        node = _child(node, token)
    return node


def _with_value(data: Any, tokens: Sequence[str], value: str) -> Any:
    out = copy.deepcopy(data)
    parent = _get(out, tokens[:-1])
    if isinstance(parent, list):
        parent[int(tokens[-1])] = value
    else:
        parent[tokens[-1]] = value
    return out


# --------------------------------------------------------------------------------------------- core edit


def _target(
    data: Any, tokens: list[str], ecosystem: str, name: str, proposed: str
) -> tuple[list[str], str, str]:
    """``(pointer tokens, old token, new token)`` of the one string that references the package."""
    try:
        node = _get(data, tokens)
    except KeyError:
        raise PatchError("the locator no longer resolves in the file") from None
    if isinstance(node, str):
        new = rewrite_token(ecosystem, name, node, proposed)
        if new is None:
            raise PatchError(f"the value at the locator does not reference {name}")
        return tokens, node, new
    lists: list[tuple[list[str], list[Any]]] = []
    if isinstance(node, list):
        lists.append((tokens, node))
    elif isinstance(node, dict):
        for key in ("args", "command"):
            value = node.get(key)
            if isinstance(value, list):
                lists.append(([*tokens, key], value))
    found: list[tuple[list[str], str, str]] = []
    for base, items in lists:
        for index, item in enumerate(items):
            if isinstance(item, str):
                new = rewrite_token(ecosystem, name, item, proposed)
                if new is not None:
                    found.append(([*base, str(index)], item, new))
    if not found:
        raise PatchError(f"no argument referencing {name} was found at the locator")
    if len(found) > 1:
        raise PatchError(f"{len(found)} arguments reference {name}; the token is ambiguous")
    return found[0]


def _replace_unique(text: str, fmt: Fmt, rel: str, tokens: list[str], old: str, new: str) -> str:  # noqa: PLR0917
    """Replace the single literal occurrence of ``old`` whose replacement changes exactly ``tokens``."""
    if old == new:
        raise PatchError("the reference is already at the proposed version")
    for token in (old, new):
        if not _SAFE_TOKEN.match(token):
            raise PatchError(f"{token[:60]!r} contains characters that cannot be replaced textually")
    original = _parse(text, fmt, rel)
    try:
        if _get(original, tokens) != old:
            raise PatchError("the file changed since the edit was planned")
    except KeyError:
        raise PatchError("the locator no longer resolves in the file") from None
    expected = _with_value(original, tokens, new)
    matches: list[str] = []
    start, seen = 0, 0
    while True:
        index = text.find(old, start)
        if index == -1:
            break
        start = index + 1
        before = text[index - 1] if index > 0 else ""
        after = text[index + len(old)] if index + len(old) < len(text) else ""
        if (before and _TOKEN_CHAR.match(before)) or (after and _TOKEN_CHAR.match(after)):
            continue
        seen += 1
        if seen > _MAX_OCCURRENCES:
            raise PatchError(f"more than {_MAX_OCCURRENCES} occurrences of {old!r}")
        candidate = text[:index] + new + text[index + len(old) :]
        try:
            reparsed = _parse(candidate, fmt, rel)
        except PatchError:
            continue
        if reparsed == expected:
            matches.append(candidate)
    if not matches:
        raise PatchError(f"the token {old!r} could not be located safely in {rel}")
    if len(matches) > 1:
        raise PatchError(f"the token {old!r} occurs {len(matches)} times in {rel}; the edit is ambiguous")
    return matches[0]


def _add_note(proposal: UpdateProposal, note: str) -> None:
    if note not in proposal.review_notes:
        proposal.review_notes.append(note)


def locate_edits(root: Path, proposal: UpdateProposal) -> list[FileEdit]:
    """Minimal edits that carry out ``proposal``; when an edit cannot be made safely, a review note instead."""
    dep = proposal.dependency
    if proposal.kind not in _EDITABLE_KINDS:
        _add_note(
            proposal,
            "No automatic edit: this proposal is advice; change the configuration by hand after review.",
        )
        return []
    if not dep.locators:
        _add_note(proposal, f"No declaring configuration file is recorded for {dep.name}; update it by hand.")
        return []
    edits: list[FileEdit] = []
    for loc in dep.locators:
        try:
            rel, tokens = _split_locator(loc)
            fmt = _fmt_for(rel)
            path = _safe_path(Path(root), rel)
            text = _read_text(path, rel)
            data = _parse(text, fmt, rel)
            ptr, old, new = _target(data, tokens, dep.ecosystem, dep.name, proposal.proposed)
            _replace_unique(text, fmt, rel, ptr, old, new)
        except PatchError as exc:
            _add_note(proposal, f"Could not edit {loc} automatically ({exc}); update it by hand.")
            continue
        edit = FileEdit(path=rel, locator=f"{rel}#{_pointer(ptr)}", before=old, after=new)
        if edit not in edits:
            edits.append(edit)
    return edits


def _changes(root: Path, proposals: Sequence[UpdateProposal]) -> dict[str, tuple[Path, str, str]]:
    """``{relpath: (path, original text, edited text)}``; any unsafe edit raises :class:`PatchError`."""
    files: dict[str, tuple[Path, str, str]] = {}
    for proposal in proposals:
        edits = proposal.edits if proposal.edits else locate_edits(root, proposal)
        for edit in edits:
            rel, tokens = _split_locator(edit.locator)
            if rel != edit.path:
                raise PatchError(f"edit path {edit.path!r} does not match its locator {edit.locator!r}")
            fmt = _fmt_for(rel)
            if rel not in files:
                path = _safe_path(Path(root), rel)
                text = _read_text(path, rel)
                files[rel] = (path, text, text)
            path, original, current = files[rel]
            files[rel] = (path, original, _replace_unique(current, fmt, rel, tokens, edit.before, edit.after))
    return {rel: v for rel, v in files.items() if v[1] != v[2]}


def render_diff(root: Path, proposals: Sequence[UpdateProposal]) -> str:
    """A unified diff (``a/``/``b/`` prefixes) of every edit the proposals make, files in sorted order."""
    out: list[str] = []
    for rel, (_, before, after) in sorted(_changes(root, proposals).items()):
        lines = difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        )
        for line in lines:
            out.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
    return "".join(out)


def _atomic_write(root: Path, rel: str, data: bytes) -> None:
    path = _safe_path(root, rel)  # re-checked immediately before writing
    mode = stat.S_IMODE(path.stat().st_mode)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".symbiote-tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def apply_proposals(root: Path, proposals: Sequence[UpdateProposal]) -> list[str]:
    """Write every edit atomically and return the changed files (relative to ``root``).

    All edits are computed and verified before the first write, so an unsafe edit changes nothing.
    """
    root = Path(root)
    changes = _changes(root, proposals)
    for rel, (_, _, after) in sorted(changes.items()):
        _atomic_write(root, rel, after.encode("utf-8"))
    return sorted(changes)
