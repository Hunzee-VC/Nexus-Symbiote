"""MCP SDK references in Python, TypeScript and JavaScript source, found without running it.

Only files that contain an MCP SDK marker are parsed. Finding them is a bounded
substring search under its own byte budget, so unrelated source files count
toward no limit and appear nowhere in the inventory. A file is listed as a
scanned surface only when it produced a component, a gap or a failure. Every
limit that stops collection is a scan failure naming the limit and the path.
"""

from __future__ import annotations

import ast
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from nexus_symbiote import limits
from nexus_symbiote.core.enums import TrustTier
from nexus_symbiote.core.models import MCPClientComponent
from nexus_symbiote.scanners.base import ScanResult, parse_python
from nexus_symbiote.scanners.python_tools import collect_python_tools
from nexus_symbiote.scanners.ts_tools import (
    collect_typescript_source,
    has_server_markers,
    is_server_source,
)
from nexus_symbiote.utils.confined import ConfinedCollection

_PYTHON_SKIPPED = frozenset({"tests", "test", "dist", "build"})
_CLIENT_MARKER = b"@modelcontextprotocol/sdk"
_SDK_IMPORT = re.compile(
    r"(?:\bfrom\s*[\"']@modelcontextprotocol/sdk(?:/[^\"']*)?[\"']|"
    r"\brequire\s*\(\s*[\"']@modelcontextprotocol/sdk(?:/[^\"']*)?[\"'])"
)
_NEXT = re.compile(r"/\*|\n")
_SPACE = re.compile(r"\s*")


def _python_marker(content: bytes) -> bool | None:
    """Whether Python source can name the MCP SDK; ``None`` when it is not UTF-8.

    Python folds identifiers to NFKC, so fullwidth or other compatibility letters
    can spell ``mcp`` in an import; a non-ASCII file is compared in that form too.
    """
    if b"mcp" in content or b"MCPClient" in content:
        return True
    if content.isascii():
        return False
    try:
        text = unicodedata.normalize("NFKC", content.decode("utf-8"))
    except UnicodeDecodeError:
        return None
    return "mcp" in text or "MCPClient" in text


def strip_js_comments(text: str) -> str:
    """Remove ``/* */`` blocks and lines that start with ``//``, in linear time.

    Same result as ``re.sub(r"/\\*.*?\\*/|(?m:^\\s*//[^\\n]*$)", "", text, flags=re.S)``,
    whose lazy block and newline-spanning ``\\s*`` backtrack quadratically on an
    unterminated ``/*`` or a run of blank lines.
    """
    parts: list[str] = []
    position = 0
    length = len(text)
    blocks_may_close = True
    line_start = True
    while position < length:
        if line_start:
            line_start = False
            space = _SPACE.match(text, position)
            end = position if space is None else space.end()
            if text.startswith("//", end):
                newline = text.find("\n", end)
                position = length if newline < 0 else newline
            else:
                parts.append(text[position:end])
                position = end
            continue
        found = _NEXT.search(text, position)
        if found is None:
            parts.append(text[position:])
            break
        start = found.start()
        if found.group() == "\n":
            parts.append(text[position : start + 1])
            position = start + 1
            line_start = True
            continue
        parts.append(text[position:start])
        close = text.find("*/", start + 2) if blocks_may_close else -1
        if close >= 0:
            position = close + 2
            continue
        # Without a later "*/" no block can close, so every "/*" from here on is text.
        blocks_may_close = False
        parts.append("/*")
        position = start + 2
    return "".join(parts)


def _client_reference(text: str) -> bool:
    # A bounded syntax hint, never a claim that an SDK is installed or deployed.
    return bool(_SDK_IMPORT.search(strip_js_comments(text)))


def _python_client(tree: ast.Module) -> bool:
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module is not None
        and node.module.split(".")[0] == "mcp"
        and any("Client" in alias.name for alias in node.names)
        for node in ast.walk(tree)
    ) or any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "MCPClient"
        for node in ast.walk(tree)
    )


@dataclass
class _Kind:
    """One kind of source reference: which files qualify and which are candidates."""

    label: str
    eligible: Callable[[Path], bool]
    marker: Callable[[bytes], bool | None]
    selected: list[tuple[Path, bytes]] = field(default_factory=list)
    unparsed: list[Path] = field(default_factory=list)


def _python_source(path: Path) -> bool:
    return path.suffix == ".py" and not _PYTHON_SKIPPED.intersection(path.parts)


def _root_source(suffix: str) -> Callable[[Path], bool]:
    return lambda path: len(path.parts) == 1 and path.suffix == suffix


def _client_marker(content: bytes) -> bool:
    return _CLIENT_MARKER in content


def _outcome(result: ScanResult) -> tuple[int, int, int]:
    return len(result.components), len(result.surfaces_excluded), len(result.scan_failures)


def collect_source_references(files: ConfinedCollection, result: ScanResult) -> None:
    """Inventory MCP servers and clients declared in source beneath the collection root."""
    settings = limits.current()
    servers = _Kind("TypeScript MCP server", is_server_source, has_server_markers)
    python = _Kind("Python MCP", _python_source, _python_marker)
    typescript = _Kind("root TypeScript MCP client", _root_source(".ts"), _client_marker)
    javascript = _Kind("root JavaScript MCP client", _root_source(".js"), _client_marker)
    kinds = (servers, python, typescript, javascript)
    sources = [path for path in files.iter_files() if any(k.eligible(path) for k in kinds)]
    # Root files first, as before, so the files parsed under a limit stay predictable.
    sources.sort(key=lambda path: len(path.parts) > 1)
    failed: set[Path] = set()

    def fail(path: Path, reason: str) -> None:
        if path not in failed:
            failed.add(path)
            result.scan_failures.append(f"{path.as_posix()}: {reason}")

    with files.separate_budget(limits.bound("source-scan-bytes")) as budget:
        for position, path in enumerate(sources):
            content = files.read_bytes(path)
            if content is None:
                unread = sources[position + 1 :]
                if budget.exhausted and unread:
                    result.scan_failures.append(
                        f"{unread[0].as_posix()}: not searched for MCP SDK references "
                        f"({len(unread)} files in all); " + budget.bound.exceeded()
                    )
                if budget.exhausted:
                    break
                continue
            for kind in kinds:
                if not kind.eligible(path):
                    continue
                verdict = kind.marker(content)
                if verdict is None:
                    fail(path, "invalid UTF-8")
                elif not verdict:
                    continue
                elif len(content) > settings.syntax_bytes:
                    fail(path, limits.bound("syntax-bytes").exceeded())
                elif len(kind.selected) < settings.source_files:
                    kind.selected.append((path, content))
                else:
                    kind.unparsed.append(path)
    for kind in kinds:
        if kind.unparsed:
            result.scan_failures.append(
                f"{kind.unparsed[0].as_posix()}: {kind.label} source not parsed "
                f"({len(kind.unparsed)} files in all); " + limits.bound("source-files").exceeded()
            )

    surfaces: list[str] = []
    detected: list[str] = []
    for path, content in servers.selected:
        before = _outcome(result)
        collect_typescript_source(path, content, result)
        if _outcome(result) != before:
            surfaces.append(path.as_posix())
    for path, content in python.selected:
        before = _outcome(result)
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            fail(path, "invalid UTF-8")
            continue
        try:
            tree = parse_python(text)
        except (SyntaxError, ValueError, RecursionError):
            fail(path, "invalid Python syntax")
        else:
            collect_python_tools(tree, text, path, result)
            if _python_client(tree):
                detected.append(path.as_posix())
        if _outcome(result) != before or path.as_posix() in detected:
            surfaces.append(path.as_posix())
    for path, content in (*typescript.selected, *javascript.selected):
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            fail(path, "invalid UTF-8")
            continue
        if _client_reference(text):
            detected.append(path.as_posix())
            surfaces.append(path.as_posix())
    result.surfaces_scanned.extend(dict.fromkeys(surfaces))
    if detected:
        result.components.append(
            MCPClientComponent(
                bom_ref="mcp-client:sdk",
                name="MCP SDK client (code-detected)",
                host_application="sdk",
                source_path=detected[0],
                trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                properties={
                    "collection_mode": "static-source-reference",
                    "source_paths": detected,
                },
            )
        )
