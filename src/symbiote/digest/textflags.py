"""Lint facts over model-visible text (``spec/digests.md §7``; checks SYM-TOOL-005/006/009/010)."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Any

from symbiote.model.common import looks_like_secret
from symbiote.model.enums import TextFlag

_HIDDEN_CATEGORIES = {"Cf", "Co", "Cn"}
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_TAGS = set(range(0xE0000, 0xE0080))
_ALLOWED_FORMAT = {0x00AD}  # soft hyphen is common in real text; still reported when combined with bidi/tag

_CROSS_TOOL_PATTERNS = [
    re.compile(r"\bbefore (?:using|calling|invoking) (?:the )?[\w.-]+\b", re.I),
    re.compile(
        r"\bignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions|messages|rules)", re.I
    ),
    re.compile(r"\bdo not (?:tell|inform|mention|reveal|show)(?: this)?(?: to)? (?:the )?user\b", re.I),
    re.compile(r"\binstead of (?:using|calling) [\w.-]+\b", re.I),
    re.compile(
        r"\b(?:send|forward|post|upload) (?:the )?(?:contents?|data|file|conversation|context)[^.]{0,60}\bto\b",
        re.I,
    ),
    re.compile(r"\b(?:read|cat|open) (?:~/|/etc/|\.ssh/|\.env|id_rsa)", re.I),
    re.compile(r"<\s*(?:IMPORTANT|SYSTEM|INSTRUCTIONS?)\s*>", re.I),
]

MAX_DESCRIPTION_BYTES = 4096


def hidden_code_points(text: str) -> list[str]:
    """Code points in ``text`` that are invisible or direction-altering (Cf/Co/Cn, bidi controls, tag characters)."""
    found: list[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in _BIDI or cp in _TAGS or 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
            # variation selectors (Mn) are invisible and can smuggle data through otherwise plain text
            found.append(f"U+{cp:04X}")
            continue
        if cp in _ALLOWED_FORMAT:
            continue
        cat = unicodedata.category(ch)
        if (cat in _HIDDEN_CATEGORIES and cp not in (0x200C, 0x200D)) or cp in (0x200B, 0x2060, 0xFEFF):
            found.append(f"U+{cp:04X}")
    return found


def _nodes(obj: Any) -> Iterable[Any]:
    """Every value in a JSON tree, depth first, without recursion (hostile schemas nest thousands deep)."""
    stack = [obj]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, Mapping):
            stack.extend(reversed(list(node.values())))
        elif isinstance(node, list):
            stack.extend(reversed(node))


def iter_strings(obj: Any) -> Iterable[str]:
    return (n for n in _nodes(obj) if isinstance(n, str))


def external_refs(schema: Any) -> list[str]:
    """``$ref`` values that are not fragment-local."""
    out: list[str] = []
    for node in _nodes(schema):
        if isinstance(node, Mapping):
            ref = node.get("$ref")
            if isinstance(ref, str) and not ref.startswith("#"):
                out.append(ref)
    return out


def cross_tool_directives(text: str) -> list[str]:
    return [m.group(0) for p in _CROSS_TOOL_PATTERNS for m in p.finditer(text)]


def schema_descriptions(schema: Any) -> Iterable[str]:
    for node in _nodes(schema):
        if isinstance(node, Mapping):
            for key in ("description", "title"):
                value = node.get(key)
                if isinstance(value, str):
                    yield value


def tool_text_flags(raw_tool: Mapping[str, Any]) -> list[TextFlag]:
    """Flags over the model-visible text of a raw tool definition."""
    flags: set[TextFlag] = set()
    texts = [str(raw_tool.get(k, "")) for k in ("name", "title", "description")]
    texts += list(schema_descriptions(raw_tool.get("inputSchema"))) + list(
        schema_descriptions(raw_tool.get("outputSchema"))
    )
    ann = raw_tool.get("annotations")
    if isinstance(ann, Mapping) and isinstance(ann.get("title"), str):
        texts.append(ann["title"])
    for t in texts:
        if hidden_code_points(t):
            flags.add(TextFlag.HIDDEN_UNICODE)
        if cross_tool_directives(t):
            flags.add(TextFlag.CROSS_TOOL_DIRECTIVE)
        if looks_like_secret(t):
            flags.add(TextFlag.SECRET_SHAPED_TOKEN)
    if external_refs(raw_tool.get("inputSchema")) or external_refs(raw_tool.get("outputSchema")):
        flags.add(TextFlag.EXTERNAL_REF)
    return sorted(flags, key=lambda f: f.value)


def oversized_description(raw_tool: Mapping[str, Any]) -> bool:
    d = raw_tool.get("description")
    return isinstance(d, str) and len(d.encode("utf-8")) > MAX_DESCRIPTION_BYTES


__all__ = [
    "MAX_DESCRIPTION_BYTES",
    "cross_tool_directives",
    "external_refs",
    "hidden_code_points",
    "iter_strings",
    "oversized_description",
    "schema_descriptions",
    "tool_text_flags",
]
