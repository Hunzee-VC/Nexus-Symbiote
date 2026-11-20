"""Deterministic linear-time text-poisoning and prompt-injection rules.

Runs offline over the text of collected components: tool descriptions and schemas,
agent cards, and the instruction, skill, tool and configuration files that the
selected collectors recorded as component sources. It reads no other file. Every
rule is a bounded lexical scan, so the pass is O(N) in the scanned text. Default-
ignorable code points are removed and the rest is NFKC-normalized before matching,
with a map back to UTF-8 byte offsets. Findings are appended to the owning existing
components; matched payload text and secret values are never written into them.
"""

from __future__ import annotations

import itertools
import re
import sys
import unicodedata
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.hashing import parse_json_strict
from nexus_symbiote.core.models import (
    A2AServerComponent,
    AgentComponent,
    IDEAgentComponent,
    MCPServerComponent,
    PromptComponent,
    RiskAssessment,
    SkillPackageComponent,
    ToolComponent,
)
from nexus_symbiote.scanners.prompt import _HIDDEN
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.terminal import neutralize

RULE_PACK_VERSION = "1.0.0"

CATEGORY_TOOL_POISONING = "tool_description_poisoning"
CATEGORY_INSTRUCTION_INJECTION = "instruction_injection"

_RULE_REFERENCE_PREFIX = "rule:"

_MAX_TAG_BODY_CHARS = 800
_MAX_COMMENT_BODY_CHARS = 1_200
_MAX_JSON_DEPTH = 32
_MAX_JSON_STRINGS = 4_096
_MAX_WHERE_CHARS = 160

_CREDENTIAL_NAME_HINTS = (".env", "secret", "credential", "id_rsa", "id_ed25519", ".netrc")
_CREDENTIAL_SUFFIXES = frozenset({".key", ".pem", ".p12", ".pfx", ".kdbx"})

_TEXT_DECLARATION_SUFFIXES = frozenset(
    {".md", ".mdc", ".markdown", ".txt", ".json", ".yaml", ".yml", ".toml", ".prompt"}
)
_COMPONENT_SOURCE_SUFFIXES = frozenset(
    {
        *_TEXT_DECLARATION_SUFFIXES,
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".py",
    }
)
_SIDE_CHANNEL_PARAM_NAMES = frozenset(
    {
        "note",
        "notes",
        "debug",
        "telemetry",
        "meta",
        "metadata",
        "audit",
        "query",
        "context",
        "extra",
        "extras",
        "callback",
        "webhook",
        "reason",
        "comment",
    }
)
# Typographic apostrophes fold to ASCII so that "Don’t tell" reads as "Don't tell".
_APOSTROPHES = {"‘": "'", "’": "'"}

_DIRECTIVE_TAG_OPEN_RE = re.compile(
    r"<((?:important|system|instructions?|hidden|secret|override)[\w-]{0,40})\b[^>]{0,120}>",
    re.IGNORECASE,
)
_CLOSE_TAG_RE = re.compile(r"</\s*([\w-]{1,60})\s*>")

_TAG_EXFIL_ACTION_RE = re.compile(
    r"(?:"
    r"never\s+tell|do\s+not\s+tell|don't\s+tell|"
    r"do\s+not\s+mention|don't\s+mention|without\s+telling|"
    r"hide\s+(?:this|it)\s+from|"
    r"ignore\s+(?:read[- ]only|all|previous|prior|above|safety)|"
    r"disregard\s+(?:all|previous|prior|above)|"
    r"\b(?:drop\s+table|delete\s+from|truncate\s+table|alter\s+table|rm\s+-rf)\b|"
    r"--export-tokens|"
    r"\b(?:read|include|pass|send|forward|upload|post|exfiltrate|export)\b.{0,80}"
    r"(?:\.ssh\b|~/\.aws|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|credentials|\.netrc|\.npmrc|\.pypirc|"
    r"\.env|https?://)"
    r")",
    re.IGNORECASE | re.DOTALL,
)

_COMMENT_ATTACK_RE = re.compile(
    r"(?:"
    r"\b(?:ignore|disregard)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|system)\s+"
    r"(?:instructions?|directives?|rules?|constraints?|prompts?)\b|"
    r"\bapprove\s+every\b|"
    r"\bbypass\s+(?:all\s+|any\s+)?(?:approval|check|validation|review|safety)\b|"
    r"\b(?:forward|send|exfiltrate|export|upload)\b.{0,80}https?://|"
    r"--export-tokens|"
    r"\b(?:read|copy|include|pass)\b.{0,60}(?:\.ssh\b|~/\.aws|\bid_rsa\b|credentials)|"
    r"\b(?:drop\s+table|delete\s+from)\b|"
    r"\b(?:never\s+tell|do\s+not\s+mention(?:\s+this)?)\b.{0,40}\busers?\b"
    r")",
    re.IGNORECASE | re.DOTALL,
)

_CONCEAL_RE = re.compile(
    r"\b(?:"
    r"never\s+tell|"
    r"do\s+not\s+tell|don't\s+tell|"
    r"do\s+not\s+mention(?:\s+this|\s+that|\s+it)?|don't\s+mention(?:\s+this|\s+that|\s+it)?|"
    r"do\s+not\s+inform|don't\s+inform|"
    r"without\s+telling|without\s+informing|"
    r"hide\s+(?:this|it)\s+from"
    r")\s+(?:to\s+)?(?:the\s+)?(?:end[- ]?)?users?\b"
    # "Never tell the user to ..." gives the user advice; it hides nothing from them.
    r"(?!\s+to\b|\s+(?:any\s+|their\s+|our\s+|your\s+)?"
    r"(?:private|secret|sensitive|confidential|credential|credentials|key|keys|token|tokens|password|passwords|secrets)\b)",
    re.IGNORECASE,
)

_CRED_PATH_RE = re.compile(
    r"(?:(?:~|\$HOME|/home/[\w.-]+|/Users/[\w.-]+|/root)/\.ssh(?:/[a-z0-9._-]+)?|"
    r"~/\.aws/credentials|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\.aws/credentials\b|\.netrc\b|"
    r"\.git-credentials\b|\.pypirc\b|\.npmrc\b)",
    re.IGNORECASE,
)

# The credential path must be the object of a read or relay verb, as in "read ~/.ssh/id_rsa"
# or "include the contents of ~/.aws/credentials"; a negation counts only when it governs
# that verb ("do not read ~/.ssh/id_rsa"), not anywhere near the path.
_CRED_VERB_BEFORE_RE = re.compile(
    r"\b(?P<neg>(?:never|not|don't|avoid|cannot)\s+)?"
    r"(?:read|cat|open|load|copy|include|pass|send|forward|upload|post|append|exfiltrate|"
    r"export|embed|attach|dump|print)\s+"
    r"(?:(?:the|its|your|their|all|any|every|contents?|of|from|file|files|data|keys?|private|"
    r"secret|at|in|out)\s+){0,4}[`'\"(\[]?$",
    re.IGNORECASE,
)

_CRED_RELAY_WINDOW_RE = re.compile(
    r"(?:"
    r"\b(?:pass|include|send|forward|upload|post|append|exfiltrate|export|embed)\b"
    r".{0,90}\b(?:parameter|param|field|query|note|body|header|payload|contents?|arguments?|args|https?://)\b|"
    r"\bbefore\s+calling\b.{0,80}\bread\b"
    r")",
    re.IGNORECASE | re.DOTALL,
)

_EXFIL_URL_RE = re.compile(
    r"(?:"
    r"--export-tokens\b.{0,120}(?:https?://|--to\b)|"
    r"\b(?:forward|send|exfiltrate|post|upload|relay)\s+"
    r"(?:every|all|any|each|user|session|incoming|prompt|query)\s+"
    r"(?:[a-z_-]{1,24}\s+){0,3}to\s+https?://"
    r")",
    re.IGNORECASE,
)

_OVERRIDE_RE = re.compile(
    r"\b(?:"
    r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|preceding|system)\s+"
    r"(?:(?:safety|security|guardrail)\s+)?(?:instructions?|directives?|rules?|constraints?|prompts?)|"
    r"disregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|preceding|system)\s+"
    r"(?:(?:safety|security|guardrail)\s+)?(?:instructions?|directives?|rules?|constraints?|prompts?)|"
    r"forget\s+(?:all\s+|everything\s+)?(?:you\s+were\s+told|previous\s+instructions?|prior\s+instructions?)|"
    r"override\s+(?:all\s+|the\s+)?(?:system\s+prompt|safety\s+rules?|approval\s+checks?)"
    r")\b",
    re.IGNORECASE,
)

_READONLY_OVERRIDE_RE = re.compile(
    r"\bignore\s+read[- ]only\b.{0,120}\b"
    r"(?:drop\s+table|delete\s+from|truncate\s+table|alter\s+table|insert\s+into|update\s+|rm\s+-rf)\b",
    re.IGNORECASE | re.DOTALL,
)

_SUBJECT = r"(?:this\s+|the\s+)?(?:repository|repo|codebase|project|agent|it)"
_VERDICT = r"(?:compliant|clean|safe|benign|low[- ]risk|passing)"
_AUDITOR_DECEIT_RE = re.compile(
    r"\b(?:"
    r"note\s+to\s+(?:any\s+)?(?:automated\s+)?(?:auditor|auditors|reviewer|reviewers|ai\s+reviewer|scanner|scanners|security\s+tool)|"
    rf"(?:report|classify|declare)\s+{_SUBJECT}\s+as\s+{_VERDICT}|"
    r"this\s+(?:repository|repo|project|codebase)\s+contains\s+no\s+"
    r"(?:mcp\s+servers?|models?|secrets?|vulnerabilities|risks)\b.{0,120}\b(?:report|compliant|safe|clean)"
    r")\b",
    re.IGNORECASE | re.DOTALL,
)
# Directives that ordinary build instructions also use ("suppress warnings in CI logs")
# count only when an auditor or scanner is addressed near them.
_AUDITOR_DIRECTIVE_RE = re.compile(
    rf"\b(?:(?:mark|treat)\s+{_SUBJECT}\s+as\s+{_VERDICT}|"
    r"(?:suppress|hide|omit|skip)\s+(?:all\s+|any\s+)?(?:security\s+)?"
    r"(?:findings|warnings|risks|alerts|vulnerabilities|mcp\s+servers?))\b",
    re.IGNORECASE,
)
_AUDITOR_ADDRESSEE_RE = re.compile(
    r"\b(?:auditors?|reviewers?|scanners?|security\s+tools?)\b", re.IGNORECASE
)
_ADDRESSEE_WINDOW = 120

_NEGATED_PREFIX_RE = re.compile(
    r"\b(?:never|do\s+not|don't|not\s+to|prohibit|forbid)\s*[\"']?\s*$",
    re.IGNORECASE,
)

_TOOL_NAME_CALL_TEMPLATES = (
    '.tool("{name}"',
    ".tool('{name}'",
    "def {name}(",
    'name": "{name}"',
    "name': '{name}'",
    '"{name}"',
    "'{name}'",
)

_RULE_DESCRIPTIONS: dict[str, str] = {
    "TP-TAG-001": "coercive directive XML-style tag containing override, secret-read, or exfiltration action",
    "TP-CMT-001": "hidden HTML comment containing override, secret-read, or exfiltration directive",
    "TP-CRED-002": "credential/sensitive file read or exfiltration URL directive",
    "TP-CONCEAL-003": "user-concealment directive instructing agent not to inform user",
    "II-OVR-001": "prompt-injection instruction override directive",
    "II-AUD-002": "automated-auditor or scanner deception directive",
    "TP-SIDENOTE-004": "side-channel parameter targeting or read-only annotation contradiction",
}


@dataclass(frozen=True)
class TextPoisoningHit:
    """Single deterministic finding produced by the text-poisoning rule pack.

    ``byte_offset`` counts UTF-8 bytes from the start of the scanned text: the file,
    or, when ``where`` names a JSON pointer or component field, that string.
    """

    rule_id: str
    category: str
    severity: RiskSeverity
    byte_offset: int
    surface: str
    summary: str
    where: str = ""


ComponentWithRisks = (
    AgentComponent
    | MCPServerComponent
    | ToolComponent
    | PromptComponent
    | SkillPackageComponent
    | A2AServerComponent
    | IDEAgentComponent
)
_COMPONENT_KINDS = (
    AgentComponent,
    MCPServerComponent,
    ToolComponent,
    PromptComponent,
    SkillPackageComponent,
    A2AServerComponent,
    IDEAgentComponent,
)
_ATTRIBUTION_PRIORITY = (
    ToolComponent,
    PromptComponent,
    SkillPackageComponent,
    A2AServerComponent,
    MCPServerComponent,
    IDEAgentComponent,
)


def _utf8_width(ch: str) -> int:
    # A JSON value can hold a lone surrogate ("\ud800"), which str.encode refuses.
    code = ord(ch)
    if code < 0x80:
        return 1
    if code < 0x800:
        return 2
    if code < 0x10000:
        return 3
    return 4


def normalize_for_lexical_scan(text: str) -> tuple[str, list[int]]:
    """Remove default-ignorable code points and NFKC-fold the rest in one O(N) pass.

    Each character is folded on its own, so fullwidth or compatibility forms of
    markup (``＜IMPORTANT＞``) read as ASCII. Returns the folded string plus a list
    mapping each of its characters back to the UTF-8 byte offset in ``text`` of the
    character it came from.
    """
    folded: list[str] = []
    byte_offsets: list[int] = []
    byte_pos = 0
    for ch in text:
        if ch < "\x80":
            folded.append(ch)
            byte_offsets.append(byte_pos)
        elif unicodedata.category(ch) != "Cf" and _HIDDEN.match(ch) is None:
            for part in _APOSTROPHES.get(ch) or unicodedata.normalize("NFKC", ch):
                folded.append(part)
                byte_offsets.append(byte_pos)
        byte_pos += _utf8_width(ch)
    return "".join(folded), byte_offsets


def _byte_offset_at(byte_offsets: list[int], char_index: int) -> int:
    if not byte_offsets or char_index <= 0:
        return 0
    return byte_offsets[min(char_index, len(byte_offsets) - 1)]


def _has_negated_prefix(text: str, pos: int) -> bool:
    window = text[max(0, pos - 40) : pos]
    return _NEGATED_PREFIX_RE.search(window) is not None


def _default_category(is_tool_surface: bool) -> str:
    return CATEGORY_TOOL_POISONING if is_tool_surface else CATEGORY_INSTRUCTION_INJECTION


def _directive_tag_bodies(normalized: str) -> Iterator[tuple[int, str]]:
    """Yield ``(tag start, body)`` for each directive tag, in O(N) overall.

    A body ends at its matching close tag, at the next directive tag, or after
    ``_MAX_TAG_BODY_CHARS``, so bodies never overlap and each character is read by at
    most one close-tag search. Tag names are compared case-insensitively on the short
    names alone, never by lowercasing the text, which can change its length.
    """
    pending: re.Match[str] | None = None
    opens = _DIRECTIVE_TAG_OPEN_RE.finditer(normalized)
    for following in itertools.chain(opens, (None,)):
        if pending is not None:
            start = pending.end()
            limit = min(len(normalized), start + _MAX_TAG_BODY_CHARS)
            if following is not None:
                limit = min(limit, following.start())
            end = limit
            tag = pending.group(1).lower()
            for close in _CLOSE_TAG_RE.finditer(normalized, start, limit):
                if close.group(1).lower() == tag:
                    end = close.start()
                    break
            yield pending.start(), normalized[start:end]
        pending = following


def scan_text_block(
    text: str,
    *,
    surface: str,
    is_tool_surface: bool = False,
    max_hits: int = 64,
    where: str = "",
) -> list[TextPoisoningHit]:
    """Scan a single text string using deterministic O(N) lexical rules."""
    if not text:
        return []

    normalized, byte_offsets = normalize_for_lexical_scan(text)
    if not normalized:
        return []

    hits: list[TextPoisoningHit] = []
    base_category = _default_category(is_tool_surface)

    def record(rule_id: str, category: str, char_index: int) -> None:
        if len(hits) < max_hits:
            hits.append(
                TextPoisoningHit(
                    rule_id=rule_id,
                    category=category,
                    severity=RiskSeverity.HIGH,
                    byte_offset=_byte_offset_at(byte_offsets, char_index),
                    surface=surface,
                    summary=_RULE_DESCRIPTIONS[rule_id],
                    where=where,
                )
            )

    # 1. TP-TAG-001: Directive tags containing coercive/exfiltration/override payload
    for tag_start, body in _directive_tag_bodies(normalized):
        if _TAG_EXFIL_ACTION_RE.search(body) is not None and not _has_negated_prefix(
            normalized, tag_start
        ):
            record("TP-TAG-001", base_category, tag_start)

    # 2. TP-CMT-001: HTML comments carrying override, exfil, or secret-read directives
    search_pos = 0
    while (cmt_start := normalized.find("<!--", search_pos)) != -1:
        cmt_end = normalized.find("-->", cmt_start + 4, cmt_start + 4 + _MAX_COMMENT_BODY_CHARS)
        stop = (
            cmt_end + 3
            if cmt_end != -1
            else min(len(normalized), cmt_start + 4 + _MAX_COMMENT_BODY_CHARS)
        )
        if _COMMENT_ATTACK_RE.search(normalized[cmt_start + 4 : stop]) is not None:
            record("TP-CMT-001", base_category, cmt_start)
        search_pos = stop

    # 3. TP-CRED-002: Sensitive credential path relay or exfiltration URL directive
    for cred_match in _CRED_PATH_RE.finditer(normalized):
        verb = _CRED_VERB_BEFORE_RE.search(
            normalized, max(0, cred_match.start() - 80), cred_match.start()
        )
        if verb is None or verb.group("neg"):
            continue
        win_start = max(0, cred_match.start() - 120)
        win_end = min(len(normalized), cred_match.end() + 120)
        if _CRED_RELAY_WINDOW_RE.search(normalized, win_start, win_end) is not None:
            record("TP-CRED-002", base_category, cred_match.start())

    for exfil_match in _EXFIL_URL_RE.finditer(normalized):
        if not _has_negated_prefix(normalized, exfil_match.start()):
            record("TP-CRED-002", base_category, exfil_match.start())

    # 4. TP-CONCEAL-003: Concealment instructions ("never tell the user", "do not mention this to the user")
    for conceal_match in _CONCEAL_RE.finditer(normalized):
        if not _has_negated_prefix(normalized, conceal_match.start()):
            record("TP-CONCEAL-003", base_category, conceal_match.start())

    # 5. II-OVR-001: Instruction override or ignore read-only + destructive command
    for ovr_re in (_OVERRIDE_RE, _READONLY_OVERRIDE_RE):
        for ovr_match in ovr_re.finditer(normalized):
            if not _has_negated_prefix(normalized, ovr_match.start()):
                record("II-OVR-001", base_category, ovr_match.start())

    # 6. II-AUD-002: Auditor/scanner deception directives
    for aud_match in _AUDITOR_DECEIT_RE.finditer(normalized):
        if not _has_negated_prefix(normalized, aud_match.start()):
            record("II-AUD-002", CATEGORY_INSTRUCTION_INJECTION, aud_match.start())
    for aud_match in _AUDITOR_DIRECTIVE_RE.finditer(normalized):
        addressed = _AUDITOR_ADDRESSEE_RE.search(
            normalized,
            max(0, aud_match.start() - _ADDRESSEE_WINDOW),
            aud_match.end() + _ADDRESSEE_WINDOW,
        )
        if addressed is not None and not _has_negated_prefix(normalized, aud_match.start()):
            record("II-AUD-002", CATEGORY_INSTRUCTION_INJECTION, aud_match.start())

    return hits


def extract_json_text_entries(
    data: object,
    *,
    max_depth: int = _MAX_JSON_DEPTH,
    max_entries: int = _MAX_JSON_STRINGS,
) -> list[tuple[str, str]]:
    """Iteratively extract ``(dotted_field_path, string_value)`` pairs from parsed JSON."""
    results: list[tuple[str, str]] = []
    queue: deque[tuple[str, object, int]] = deque([("", data, 0)])
    while queue and len(results) < max_entries:
        prefix, node, depth = queue.popleft()
        if depth > max_depth:
            continue
        if isinstance(node, str):
            if node.strip():
                results.append((prefix or "$", node))
        elif isinstance(node, dict):
            for key, val in node.items():
                if not isinstance(key, str):
                    continue
                child = f"{prefix}.{key}" if prefix else key
                queue.append((child, val, depth + 1))
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                child = f"{prefix}[{idx}]"
                queue.append((child, item, depth + 1))
    return results


_Scopes = tuple[tuple[str, dict[str, Any]], ...]


def _json_strings_with_scopes(data: object) -> list[tuple[str, str, _Scopes]]:
    """``(JSON pointer, string, enclosing scopes)`` for each nonblank string, bounded.

    A scope is an enclosing object with a label that can name a component: its own
    ``name`` string, or the key it is stored under (``mcpServers.<name>``). Scopes are
    listed innermost first.
    """
    results: list[tuple[str, str, _Scopes]] = []
    queue: deque[tuple[str, object, int, _Scopes]] = deque([("", data, 0, ())])
    while queue and len(results) < _MAX_JSON_STRINGS:
        pointer, node, depth, scopes = queue.popleft()
        if depth > _MAX_JSON_DEPTH:
            continue
        if isinstance(node, str):
            if node.strip():
                results.append((pointer, node, scopes))
        elif isinstance(node, dict):
            label = node.get("name")
            inner = ((label, node), *scopes) if isinstance(label, str) else scopes
            for key, val in node.items():
                child = f"{pointer}/{key.replace('~', '~0').replace('/', '~1')}"
                outer = ((key, val), *inner) if isinstance(val, dict) else inner
                queue.append((child, val, depth + 1, outer))
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                queue.append((f"{pointer}/{idx}", item, depth + 1, scopes))
    return results


def _collect_schema_property_names(schema: dict[str, Any] | None) -> set[str]:
    if not isinstance(schema, dict):
        return set()
    names: set[str] = set()
    queue: deque[tuple[dict[str, Any], int]] = deque([(schema, 0)])
    while queue and len(names) < 256:
        node, depth = queue.popleft()
        if depth > _MAX_JSON_DEPTH:
            continue
        props = node.get("properties")
        if isinstance(props, dict):
            for k, v in props.items():
                if isinstance(k, str):
                    names.add(k)
                if isinstance(v, dict):
                    queue.append((v, depth + 1))
        for combiner in ("items", "additionalProperties"):
            sub = node.get(combiner)
            if isinstance(sub, dict):
                queue.append((sub, depth + 1))
        for list_key in ("anyOf", "oneOf", "allOf"):
            items = node.get(list_key)
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        queue.append((item, depth + 1))
    return names


def check_sidenote_tool_schema(
    schema: dict[str, Any] | None,
    combined_text: str,
    annotations: dict[str, Any] | None,
    *,
    surface: str,
    existing_hits: list[TextPoisoningHit],
) -> list[TextPoisoningHit]:
    """Detect Sidenote cross-property escalation on tool schemas and annotations.

    Both checks need a tool-poisoning hit in the tool's own text; destructive keywords
    alone are not one, since a read-only tool may list the statements it rejects.
    Flags:
    1) A tool declaring ``readOnlyHint=True`` or ``destructiveHint=False`` whose text
       carries a poisoning directive.
    2) A declared side-channel parameter (``note``, ``debug``, ``query``, ``context``,
       ``metadata`` ...) that the tool's text names beside such a directive.
    The finding is located at the poisoning hit that triggered it.
    """
    poison = next((h for h in existing_hits if h.category == CATEGORY_TOOL_POISONING), None)
    if poison is None:
        return []
    ann = annotations or {}
    flagged = ann.get("readOnlyHint") is True or ann.get("destructiveHint") is False
    if not flagged:
        normalized, _ = normalize_for_lexical_scan(combined_text)
        flagged = any(
            re.search(rf"\b{re.escape(prop)}\b", normalized, re.IGNORECASE) is not None
            for prop in sorted(_collect_schema_property_names(schema))
            if prop.lower() in _SIDE_CHANNEL_PARAM_NAMES
        )
    if not flagged:
        return []
    return [
        TextPoisoningHit(
            rule_id="TP-SIDENOTE-004",
            category=CATEGORY_TOOL_POISONING,
            severity=RiskSeverity.HIGH,
            byte_offset=poison.byte_offset,
            surface=surface,
            summary=_RULE_DESCRIPTIONS["TP-SIDENOTE-004"],
            where=poison.where,
        )
    ]


def _is_credential_path(rel_path: str) -> bool:
    posix = PurePosixPath(rel_path)
    lower = posix.as_posix().lower()
    if any(part.startswith(".env") for part in posix.parts):
        return True
    if posix.suffix.lower() in _CREDENTIAL_SUFFIXES:
        return True
    name_lower = posix.name.lower()
    return any(hint in name_lower or f"/{hint}" in lower for hint in _CREDENTIAL_NAME_HINTS)


def _priority_key(component: ComponentWithRisks) -> tuple[int, str]:
    rank = next(
        (i for i, kind in enumerate(_ATTRIBUTION_PRIORITY) if isinstance(component, kind)),
        len(_ATTRIBUTION_PRIORITY),
    )
    return rank, component.bom_ref


def _fallback_component(
    candidates: list[ComponentWithRisks], root_agent: ComponentWithRisks | None
) -> ComponentWithRisks | None:
    """The owner of text that no single tool in a shared source can be shown to own.

    Such text never goes to one of several tools, which would blame a sibling.
    """
    if len(candidates) == 1:
        return candidates[0]
    others = [c for c in candidates if not isinstance(c, ToolComponent)]
    return min(others, key=_priority_key) if others else root_agent


def _attribute_source_component(
    content: str,
    raw_bytes: bytes,
    byte_offset: int,
    candidates: list[ComponentWithRisks],
    fallback: ComponentWithRisks | None,
) -> ComponentWithRisks | None:
    """Pick the most specific component owning ``byte_offset`` inside a multi-entity source."""
    if not candidates:
        return fallback
    if len(candidates) == 1:
        return candidates[0]

    tool_candidates = [c for c in candidates if isinstance(c, ToolComponent)]
    if tool_candidates:
        char_pos = len(raw_bytes[:byte_offset].decode("utf-8", errors="ignore"))
        prefix = content[max(0, char_pos - 600) : char_pos]
        best_tool: ToolComponent | None = None
        best_idx = -1
        for tool in tool_candidates:
            for tmpl in _TOOL_NAME_CALL_TEMPLATES:
                marker = tmpl.format(name=tool.name)
                found = prefix.rfind(marker)
                if found > best_idx:
                    best_idx = found
                    best_tool = tool
        if best_tool is not None:
            return best_tool
    return _fallback_component(candidates, fallback)


_MD_COMMENT_LINE_RE = re.compile(
    r"^[ \t]{0,3}\[[^\]\n]{1,120}\]:[ \t]*(?:#|<>).*$",
    re.MULTILINE,
)


def _mask_hidden_markdown_markup(text: str) -> str:
    """Blank hidden HTML/PI/reference comments, keeping every UTF-8 byte offset.

    Each masked character becomes as many spaces as it has UTF-8 bytes, so offsets
    measured in the masked text are offsets in the file.
    """
    masked = bytearray(len(text))
    for open_tok, close_tok in (("<!--", "-->"), ("<?", "?>")):
        pos = 0
        while (start := text.find(open_tok, pos)) != -1:
            end = text.find(close_tok, start + len(open_tok), start + 4096)
            stop = end + len(close_tok) if end != -1 else min(len(text), start + 4096)
            masked[start:stop] = b"\x01" * (stop - start)
            pos = stop
    for match in _MD_COMMENT_LINE_RE.finditer(text):
        masked[match.start() : match.end()] = b"\x01" * (match.end() - match.start())
    return "".join(
        " " * _utf8_width(ch) if flag else ch for ch, flag in zip(text, masked, strict=True)
    )


def _append_consolidated_risks(
    component: ComponentWithRisks,
    hits: list[TextPoisoningHit],
    *,
    seen_keys: set[tuple[str, str, str]],
) -> int:
    """Group hits by ``(category, surface)`` and append sanitized ``RiskAssessment`` entries."""
    grouped: dict[tuple[str, str], list[TextPoisoningHit]] = {}
    for hit in hits:
        grouped.setdefault((hit.category, hit.surface), []).append(hit)

    added = 0
    for (category, surface), group in sorted(grouped.items()):
        dedup_key = (component.bom_ref, category, surface)
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)
        # The first location of each rule, so each offset is that of the rule printed beside
        # it; TP-SIDENOTE-004 shares its trigger's location and is listed after it.
        firsts: dict[str, TextPoisoningHit] = {}
        order = sorted(
            group,
            key=lambda h: (h.where, h.byte_offset, h.rule_id == "TP-SIDENOTE-004", h.rule_id),
        )
        for h in order:
            firsts.setdefault(h.rule_id, h)
        located = [
            f"{h.rule_id} at byte_offset={h.byte_offset}"
            + (f" of {neutralize(h.where)[:_MAX_WHERE_CHARS]}" if h.where else "")
            for h in firsts.values()
        ]
        first = next(iter(firsts.values()))
        detail = (
            f"Surface '{neutralize(surface)}' ({neutralize(component.name)}) matched "
            f"{'; '.join(located)} (pack={RULE_PACK_VERSION}): {first.summary}. "
            "Matched payload text is withheld."
        )
        recommendation = (
            "Remove coercive tags, override directives, hidden instructions, or credential-relay "
            "guidance from untrusted tool metadata, agent cards, or prompt files before loading into LLM context."
        )
        component.risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category=category,
                detail=detail,
                recommendation=recommendation,
                references=[f"{_RULE_REFERENCE_PREFIX}{rid}" for rid in firsts],
            )
        )
        added += 1
    return added


def _scan_component_fields(comp: ComponentWithRisks) -> list[TextPoisoningHit]:
    if isinstance(comp, ToolComponent):
        surface = comp.source_path or comp.name
        hits: list[TextPoisoningHit] = []
        parts: list[str] = []
        fields = [("description", comp.description_text), ("description", comp.description)]
        fields += [
            (f"input_schema.{path}", val)
            for path, val in extract_json_text_entries(comp.input_schema)
        ]
        for field, text in fields:
            if text:
                parts.append(text)
                hits.extend(
                    scan_text_block(text, surface=surface, is_tool_surface=True, where=field)
                )
        return hits + check_sidenote_tool_schema(
            comp.input_schema,
            "\n".join(parts),
            comp.annotations,
            surface=surface,
            existing_hits=hits,
        )
    if isinstance(comp, A2AServerComponent):
        surface = comp.source_path or comp.agent_card_path or comp.name
        texts = [("description", comp.description)]
        texts += [(f"skills_declared[{i}]", s) for i, s in enumerate(comp.skills_declared)]
        return [
            hit
            for field, text in texts
            if text
            for hit in scan_text_block(text, surface=surface, is_tool_surface=True, where=field)
        ]
    if comp.description:
        return scan_text_block(
            comp.description,
            surface=comp.source_path or comp.name,
            is_tool_surface=isinstance(comp, MCPServerComponent),
            where="description",
        )
    return []


def _scan_json_source(
    rel_path: str,
    parsed: object,
    comps: list[ComponentWithRisks],
    root_agent: AgentComponent | None,
) -> list[tuple[ComponentWithRisks, list[TextPoisoningHit]]]:
    """Scan each string of a JSON source and give its hits to the component that holds it.

    A string belongs to the innermost enclosing object whose ``name`` (or key) names a
    component recorded for this file, so a poisoned tool's text is never charged to a
    sibling tool declared beside it.
    """
    by_name: dict[str, ComponentWithRisks] = {}
    for comp in sorted(comps, key=_priority_key):
        by_name.setdefault(comp.name, comp)
    fallback = _fallback_component(comps, root_agent) if comps else root_agent
    groups: dict[str, tuple[ComponentWithRisks, dict[str, Any] | None, list[TextPoisoningHit]]]
    groups = {}
    texts: dict[str, list[str]] = {}
    for pointer, value, scopes in _json_strings_with_scopes(parsed):
        owner = next(((by_name[label], node) for label, node in scopes if label in by_name), None)
        target, node = owner if owner is not None else (fallback, None)
        if target is None:
            continue
        is_tool = isinstance(target, (ToolComponent, A2AServerComponent, MCPServerComponent))
        group = groups.setdefault(target.bom_ref, (target, node, []))
        if group[1] is None and node is not None:
            group = groups[target.bom_ref] = (target, node, group[2])
        group[2].extend(
            scan_text_block(value, surface=rel_path, is_tool_surface=is_tool, where=pointer)
        )
        texts.setdefault(target.bom_ref, []).append(value)
    results: list[tuple[ComponentWithRisks, list[TextPoisoningHit]]] = []
    for ref, (target, node, hits) in groups.items():
        if isinstance(target, ToolComponent) and node is not None:
            schema = next(
                (node[k] for k in ("inputSchema", "input_schema", "parameters") if k in node),
                None,
            )
            ann = node.get("annotations")
            hits = hits + check_sidenote_tool_schema(
                schema if isinstance(schema, dict) else None,
                "\n".join(texts[ref]),
                ann if isinstance(ann, dict) else None,
                surface=rel_path,
                existing_hits=hits,
            )
        results.append((target, hits))
    return results


def _scan_text_source(
    rel_path: str,
    raw_text: str,
    comps: list[ComponentWithRisks],
    root_agent: AgentComponent | None,
) -> list[tuple[ComponentWithRisks, list[TextPoisoningHit]]]:
    suffix = PurePosixPath(rel_path).suffix.lower()
    is_tool_ctx = any(
        isinstance(c, (ToolComponent, A2AServerComponent, MCPServerComponent)) for c in comps
    )
    scan_input = raw_text
    if (
        not is_tool_ctx
        and suffix in {".md", ".mdc", ".markdown"}
        and any(
            r.category == "hidden_markup" and r.severity == RiskSeverity.HIGH
            for comp in comps
            for r in comp.risks
        )
    ):
        scan_input = _mask_hidden_markdown_markup(raw_text)
    hits = scan_text_block(scan_input, surface=rel_path, is_tool_surface=is_tool_ctx)
    raw_bytes = raw_text.encode("utf-8") if hits else b""
    by_target: dict[str, tuple[ComponentWithRisks, list[TextPoisoningHit]]] = {}
    for h in hits:
        chosen = _attribute_source_component(raw_text, raw_bytes, h.byte_offset, comps, root_agent)
        if chosen is not None:
            by_target.setdefault(chosen.bom_ref, (chosen, []))[1].append(h)
    return list(by_target.values())


def _source_candidates(
    components_by_path: dict[str, list[ComponentWithRisks]],
) -> Iterator[str]:
    for rel_path, comps in sorted(components_by_path.items()):
        suffix = PurePosixPath(rel_path).suffix.lower()
        if suffix not in _COMPONENT_SOURCE_SUFFIXES or _is_credential_path(rel_path):
            continue
        if suffix not in _TEXT_DECLARATION_SUFFIXES and any(
            isinstance(c, SkillPackageComponent) and c.skill_type == "skill-resource" for c in comps
        ):
            continue
        yield rel_path


def apply_text_poisoning_rules(
    aibom: AIBOM,
    root: Path | None = None,
    *,
    exclude_paths: Iterable[str | Path] = (),
    failures: list[str] | None = None,
    exclusions: list[str] | None = None,
    surfaces: list[str] | None = None,
) -> int:
    """Run deterministic text-poisoning & injection rules across an assembled AIBOM.

    Inspects in-memory component descriptions and schemas and, when ``root`` is given,
    the repository files that collected components name as their source or agent card,
    read through confined descriptor-relative opens. No other file is read, so a
    collector that was not selected adds no surface. Findings are appended to existing
    components; no component is created and no hash changes. A surface the rules cannot
    process is recorded in ``failures``, never raised.
    """
    components: list[ComponentWithRisks] = [
        c for c in aibom.components if isinstance(c, _COMPONENT_KINDS)
    ]
    components_by_path: dict[str, list[ComponentWithRisks]] = {}
    for comp in components:
        paths = [comp.source_path]
        if isinstance(comp, A2AServerComponent):
            paths.append(comp.agent_card_path)
        for path in dict.fromkeys(paths):
            if path and "://" not in path:
                components_by_path.setdefault(path, []).append(comp)
    agents = [c for c in components if isinstance(c, AgentComponent)]
    root_agent = min(agents, key=lambda a: a.bom_ref) if agents else None
    seen_keys: set[tuple[str, str, str]] = set()
    own_failures: list[str] = []
    own_exclusions: list[str] = []
    scanned_rel_paths: set[str] = set()
    added = 0

    def failed(subject: str, exc: Exception) -> None:
        own_failures.append(
            f"{neutralize(subject)}: text-poisoning rules could not be applied "
            f"({type(exc).__name__})"
        )

    # Source files first: their findings carry file byte offsets or JSON pointers, which
    # the in-memory fields scanned after them cannot give for the same component.
    if root is not None and root.is_dir():
        with ConfinedCollection(
            root, own_failures, own_exclusions, exclude_paths=exclude_paths
        ) as files:
            for rel_path in _source_candidates(components_by_path):
                if files.excluded(rel_path):
                    continue
                raw_text = files.read_text(rel_path, missing_ok=True)
                if raw_text is None:
                    continue
                scanned_rel_paths.add(rel_path)
                comps = components_by_path[rel_path]
                try:
                    parsed: object = None
                    if rel_path.lower().endswith(".json"):
                        try:
                            parsed = parse_json_strict(raw_text, max_bytes=sys.maxsize)
                        except (ValueError, RecursionError, TypeError):
                            # Includes duplicate keys: the raw text holds every value.
                            parsed = None
                    owned = (
                        _scan_json_source(rel_path, parsed, comps, root_agent)
                        if isinstance(parsed, (dict, list))
                        else _scan_text_source(rel_path, raw_text, comps, root_agent)
                    )
                    for target, hits in owned:
                        added += _append_consolidated_risks(target, hits, seen_keys=seen_keys)
                except (ValueError, RecursionError) as exc:
                    failed(rel_path, exc)

    for comp in components:
        try:
            added += _append_consolidated_risks(
                comp, _scan_component_fields(comp), seen_keys=seen_keys
            )
        except (ValueError, RecursionError) as exc:
            failed(comp.bom_ref, exc)

    if surfaces is not None:
        surfaces.extend(sorted(scanned_rel_paths))
    for target_list, own in ((failures, own_failures), (exclusions, own_exclusions)):
        if target_list is not None:
            known = set(target_list)
            for msg in own:
                if msg not in known:
                    target_list.append(msg)
                    known.add(msg)
    return added
