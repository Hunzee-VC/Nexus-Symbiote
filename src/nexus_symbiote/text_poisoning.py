"""Deterministic linear-time text-poisoning and prompt-injection rules.

Runs offline across discovered tool schemas, prompt/instruction files, A2A
cards, and assistant configurations using confined descriptor-relative reads.
Every rule uses bounded lexical scans (worst-case O(N)), normalizes away
invisible format characters (Unicode category Cf) before matching, preserves
all existing inventory components and digests, and never emits raw matched
payload text or secret values into findings.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
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

_TEST_TOP_DIRS = frozenset({"test", "tests", "__tests__"})
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
_INSTRUCTION_ROOT_FILES = frozenset(
    {
        "claude.md",
        "claude.local.md",
        "agents.md",
        "agents.override.md",
        "gemini.md",
        "codex.md",
        ".cursorrules",
        ".clinerules",
        ".windsurfrules",
        "system_prompt.txt",
        "system_prompt.md",
    }
)
_INSTRUCTION_DIRS = frozenset(
    {
        ".claude",
        ".cursor",
        ".windsurf",
        ".clinerules",
        ".roo",
        ".kiro",
        ".codex",
        ".agents",
        ".gemini",
        "skills",
        "prompts",
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

_DIRECTIVE_TAG_OPEN_RE = re.compile(
    r"<(important|system|instructions|instruction|hidden|secret|override)\b[^>]{0,120}>",
    re.IGNORECASE,
)

_TAG_EXFIL_ACTION_RE = re.compile(
    r"(?:"
    r"before\s+calling|"
    r"never\s+tell|do\s+not\s+tell|don't\s+tell|"
    r"do\s+not\s+mention|don't\s+mention|without\s+telling|"
    r"hide\s+(?:this|it)\s+from|"
    r"ignore\s+(?:read[- ]only|all|previous|prior|above|safety)|"
    r"disregard\s+(?:all|previous|prior|above)|"
    r"\boverride\b|"
    r"\b(?:drop\s+table|delete\s+from|truncate\s+table|alter\s+table|rm\s+-rf)\b|"
    r"--export-tokens|"
    r"\b(?:read|include|pass|send|forward|upload|post|exfiltrate|export)\b.{0,80}"
    r"(?:~/\.ssh|~/\.aws|\bid_rsa\b|\bid_ed25519\b|credentials|\.netrc|\.npmrc|\.pypirc|\.env|parameter|field|https?://)"
    r")",
    re.IGNORECASE | re.DOTALL,
)

_COMMENT_ATTACK_RE = re.compile(
    r"(?:"
    r"\b(?:ignore|disregard)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|system)\s+"
    r"(?:instructions?|directives?|rules?|constraints?|prompts?)\b|"
    r"\bapprove\s+every\b|"
    r"\bbypass\s+(?:all\s+|any\s+)?(?:approval|check|validation|review|safety)\b|"
    r"\b(?:forward|send|exfiltrate|export|post|upload)\b.{0,80}https?://|"
    r"--export-tokens|"
    r"\b(?:read|copy|include|pass)\b.{0,60}(?:~/\.ssh|~/\.aws|\bid_rsa\b|credentials)|"
    r"\b(?:drop\s+table|delete\s+from|rm\s+-rf)\b|"
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
    r"(?!\s+(?:any\s+|their\s+|our\s+|your\s+)?"
    r"(?:private|secret|sensitive|confidential|credential|credentials|key|keys|token|tokens|password|passwords|secrets)\b)",
    re.IGNORECASE,
)

_CRED_PATH_RE = re.compile(
    r"(?:~/\.ssh(?:/[a-z0-9._-]+)?|~/\.aws/credentials|"
    r"\bid_rsa\b|\bid_ed25519\b|\.aws/credentials\b|\.netrc\b|"
    r"\.git-credentials\b|\.pypirc\b|\.npmrc\b)",
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

_CRED_BENIGN_GUARD_RE = re.compile(
    r"(?:"
    r"\blists?\s+ssh\s+keys\b|"
    r"\b(?:never|do\s+not|don't|avoid|must\s+not|cannot)\s+"
    r"(?:read|pass|include|send|forward|print|expose|show|display|upload|export|commit|log)\b"
    r")",
    re.IGNORECASE,
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
    r"override\s+(?:all\s+|the\s+)?(?:system\s+prompt|previous\s+instructions?|prior\s+instructions?|safety\s+rules?|approval\s+checks?)"
    r")\b",
    re.IGNORECASE,
)

_READONLY_OVERRIDE_RE = re.compile(
    r"\bignore\s+read[- ]only\b.{0,120}\b"
    r"(?:drop\s+table|delete\s+from|truncate\s+table|alter\s+table|insert\s+into|update\s+|rm\s+-rf)\b",
    re.IGNORECASE | re.DOTALL,
)

_DESTRUCTIVE_SQL_OR_SHELL_RE = re.compile(
    r"\b(?:drop\s+table|delete\s+from|truncate\s+table|alter\s+table|rm\s+-rf)\b",
    re.IGNORECASE,
)

_AUDITOR_DECEIT_RE = re.compile(
    r"\b(?:"
    r"note\s+to\s+(?:any\s+)?(?:automated\s+)?(?:auditor|auditors|reviewer|reviewers|ai\s+reviewer|scanner|scanners|security\s+tool)|"
    r"(?:report|mark|treat|classify|declare)\s+(?:this\s+|the\s+)?(?:repository|repo|codebase|project|agent|it)\s+as\s+"
    r"(?:compliant|clean|safe|benign|low[- ]risk|passing)|"
    r"(?:suppress|hide|omit|skip)\s+(?:all\s+|any\s+)?(?:security\s+)?(?:findings|warnings|risks|alerts|vulnerabilities|mcp\s+servers?)|"
    r"this\s+(?:repository|repo|project|codebase)\s+contains\s+no\s+"
    r"(?:mcp\s+servers?|models?|secrets?|vulnerabilities|risks)\b.{0,120}\b(?:report|compliant|safe|clean)"
    r")\b",
    re.IGNORECASE | re.DOTALL,
)

_NEGATED_PREFIX_RE = re.compile(
    r"\b(?:never|do\s+not|don't|not\s+to|prohibit|forbid|example:|rejected:|fixture:)\s*[\"']?\s*$",
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
    """Single deterministic finding produced by the text-poisoning rule pack."""

    rule_id: str
    category: str
    severity: RiskSeverity
    byte_offset: int
    surface: str
    summary: str


ComponentWithRisks = (
    AgentComponent
    | MCPServerComponent
    | ToolComponent
    | PromptComponent
    | SkillPackageComponent
    | A2AServerComponent
    | IDEAgentComponent
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
    """Strip invisible Unicode format (Cf) characters in one O(N) pass.

    Returns the stripped string plus a list mapping each stripped-string character
    index back to the original UTF-8 byte offset in ``text``.
    """
    stripped_chars: list[str] = []
    byte_offsets: list[int] = []
    byte_pos = 0
    for ch in text:
        ch_bytes = _utf8_width(ch)
        if unicodedata.category(ch) != "Cf":
            stripped_chars.append(ch)
            byte_offsets.append(byte_pos)
        byte_pos += ch_bytes
    return "".join(stripped_chars), byte_offsets


def _byte_offset_at(byte_offsets: list[int], char_index: int) -> int:
    if not byte_offsets or char_index <= 0:
        return 0
    return byte_offsets[min(char_index, len(byte_offsets) - 1)]


def _has_negated_prefix(text: str, pos: int) -> bool:
    window = text[max(0, pos - 40) : pos]
    return _NEGATED_PREFIX_RE.search(window) is not None


def _default_category(is_tool_surface: bool) -> str:
    return CATEGORY_TOOL_POISONING if is_tool_surface else CATEGORY_INSTRUCTION_INJECTION


def _record_hit(
    hits: list[TextPoisoningHit],
    max_hits: int,
    *,
    rule_id: str,
    category: str,
    byte_offset: int,
    surface: str,
) -> None:
    if len(hits) < max_hits:
        hits.append(
            TextPoisoningHit(
                rule_id=rule_id,
                category=category,
                severity=RiskSeverity.HIGH,
                byte_offset=byte_offset,
                surface=surface,
                summary=_RULE_DESCRIPTIONS[rule_id],
            )
        )


def scan_text_block(
    text: str,
    *,
    surface: str,
    is_tool_surface: bool = False,
    max_hits: int = 64,
) -> list[TextPoisoningHit]:
    """Scan a single text string using deterministic O(N) lexical rules."""
    if not text:
        return []

    normalized, byte_offsets = normalize_for_lexical_scan(text)
    if not normalized:
        return []

    hits: list[TextPoisoningHit] = []
    base_category = _default_category(is_tool_surface)

    # 1. TP-TAG-001: Directive tags containing coercive/exfiltration/override payload
    for tag_match in _DIRECTIVE_TAG_OPEN_RE.finditer(normalized):
        tag_name = tag_match.group(1).lower()
        body_start = tag_match.end()
        close_marker = f"</{tag_name}>"
        close_idx = normalized.lower().find(
            close_marker, body_start, body_start + _MAX_TAG_BODY_CHARS
        )
        body_end = (
            close_idx if close_idx != -1 else min(len(normalized), body_start + _MAX_TAG_BODY_CHARS)
        )
        body = normalized[body_start:body_end]
        if _TAG_EXFIL_ACTION_RE.search(body) is not None and not _has_negated_prefix(
            normalized, tag_match.start()
        ):
            _record_hit(
                hits,
                max_hits,
                rule_id="TP-TAG-001",
                category=base_category,
                byte_offset=_byte_offset_at(byte_offsets, tag_match.start()),
                surface=surface,
            )

    # 2. TP-CMT-001: HTML comments carrying override, exfil, or secret-read directives
    search_pos = 0
    while (cmt_start := normalized.find("<!--", search_pos)) != -1:
        cmt_end = normalized.find("-->", cmt_start + 4, cmt_start + 4 + _MAX_COMMENT_BODY_CHARS)
        stop = (
            cmt_end + 3
            if cmt_end != -1
            else min(len(normalized), cmt_start + 4 + _MAX_COMMENT_BODY_CHARS)
        )
        comment_body = normalized[cmt_start + 4 : stop]
        if _COMMENT_ATTACK_RE.search(comment_body) is not None:
            _record_hit(
                hits,
                max_hits,
                rule_id="TP-CMT-001",
                category=base_category,
                byte_offset=_byte_offset_at(byte_offsets, cmt_start),
                surface=surface,
            )
        search_pos = stop

    # 3. TP-CRED-002: Sensitive credential path relay or exfiltration URL directive
    for cred_match in _CRED_PATH_RE.finditer(normalized):
        win_start = max(0, cred_match.start() - 120)
        win_end = min(len(normalized), cred_match.end() + 120)
        window = normalized[win_start:win_end]
        if _CRED_BENIGN_GUARD_RE.search(window) is not None:
            continue
        if _CRED_RELAY_WINDOW_RE.search(window) is not None:
            _record_hit(
                hits,
                max_hits,
                rule_id="TP-CRED-002",
                category=base_category,
                byte_offset=_byte_offset_at(byte_offsets, cred_match.start()),
                surface=surface,
            )

    for exfil_match in _EXFIL_URL_RE.finditer(normalized):
        if not _has_negated_prefix(normalized, exfil_match.start()):
            _record_hit(
                hits,
                max_hits,
                rule_id="TP-CRED-002",
                category=base_category,
                byte_offset=_byte_offset_at(byte_offsets, exfil_match.start()),
                surface=surface,
            )

    # 4. TP-CONCEAL-003: Concealment instructions ("never tell the user", "do not mention this to the user")
    for conceal_match in _CONCEAL_RE.finditer(normalized):
        if not _has_negated_prefix(normalized, conceal_match.start()):
            _record_hit(
                hits,
                max_hits,
                rule_id="TP-CONCEAL-003",
                category=base_category,
                byte_offset=_byte_offset_at(byte_offsets, conceal_match.start()),
                surface=surface,
            )

    # 5. II-OVR-001: Instruction override or ignore read-only + destructive command
    override_cat = base_category if is_tool_surface else CATEGORY_INSTRUCTION_INJECTION
    for ovr_match in _OVERRIDE_RE.finditer(normalized):
        if not _has_negated_prefix(normalized, ovr_match.start()):
            _record_hit(
                hits,
                max_hits,
                rule_id="II-OVR-001",
                category=override_cat,
                byte_offset=_byte_offset_at(byte_offsets, ovr_match.start()),
                surface=surface,
            )
    for ro_match in _READONLY_OVERRIDE_RE.finditer(normalized):
        if not _has_negated_prefix(normalized, ro_match.start()):
            _record_hit(
                hits,
                max_hits,
                rule_id="II-OVR-001",
                category=override_cat,
                byte_offset=_byte_offset_at(byte_offsets, ro_match.start()),
                surface=surface,
            )

    # 6. II-AUD-002: Auditor/scanner deception directives
    for aud_match in _AUDITOR_DECEIT_RE.finditer(normalized):
        if not _has_negated_prefix(normalized, aud_match.start()):
            _record_hit(
                hits,
                max_hits,
                rule_id="II-AUD-002",
                category=CATEGORY_INSTRUCTION_INJECTION,
                byte_offset=_byte_offset_at(byte_offsets, aud_match.start()),
                surface=surface,
            )

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

    Flags:
    1) A tool declaring ``readOnlyHint=True`` or ``destructiveHint=False`` while its
       text carries destructive SQL/shell or coercive exfiltration directives.
    2) A declared parameter (especially side-channel fields like ``note``, ``debug``,
       ``query``, ``telemetry``, ``context``, ``metadata``) targeted by a credential/exfil
       directive in the tool description or schema text.
    """
    normalized, byte_offsets = normalize_for_lexical_scan(combined_text)
    if not normalized:
        return []

    ann = annotations or {}
    claims_benign = ann.get("readOnlyHint") is True or ann.get("destructiveHint") is False
    has_destructive = _DESTRUCTIVE_SQL_OR_SHELL_RE.search(normalized) is not None
    has_poison_hit = any(h.category == CATEGORY_TOOL_POISONING for h in existing_hits)

    if claims_benign and (has_destructive or has_poison_hit):
        match = _DESTRUCTIVE_SQL_OR_SHELL_RE.search(normalized)
        offset = (
            _byte_offset_at(byte_offsets, match.start())
            if match
            else (existing_hits[0].byte_offset if existing_hits else 0)
        )
        return [
            TextPoisoningHit(
                rule_id="TP-SIDENOTE-004",
                category=CATEGORY_TOOL_POISONING,
                severity=RiskSeverity.HIGH,
                byte_offset=offset,
                surface=surface,
                summary=_RULE_DESCRIPTIONS["TP-SIDENOTE-004"],
            )
        ]

    prop_names = _collect_schema_property_names(schema)
    suspicious_props = {p for p in prop_names if p.lower() in _SIDE_CHANNEL_PARAM_NAMES}
    if suspicious_props and has_poison_hit:
        for prop in sorted(suspicious_props):
            prop_re = re.compile(rf"\b{re.escape(prop)}\b", re.IGNORECASE)
            if (m := prop_re.search(normalized)) is not None:
                return [
                    TextPoisoningHit(
                        rule_id="TP-SIDENOTE-004",
                        category=CATEGORY_TOOL_POISONING,
                        severity=RiskSeverity.HIGH,
                        byte_offset=_byte_offset_at(byte_offsets, m.start()),
                        surface=surface,
                        summary=_RULE_DESCRIPTIONS["TP-SIDENOTE-004"],
                    )
                ]
    return []


def _is_credential_path(rel_path: str) -> bool:
    posix = PurePosixPath(rel_path)
    lower = posix.as_posix().lower()
    if any(part.startswith(".env") for part in posix.parts):
        return True
    if posix.suffix.lower() in _CREDENTIAL_SUFFIXES:
        return True
    name_lower = posix.name.lower()
    return any(hint in name_lower or f"/{hint}" in lower for hint in _CREDENTIAL_NAME_HINTS)


def _is_test_path(rel_path: str) -> bool:
    parts = PurePosixPath(rel_path).parts
    return bool(parts) and parts[0].lower() in _TEST_TOP_DIRS


def _is_supplemental_surface(rel_path: str) -> bool:
    posix = PurePosixPath(rel_path)
    lower = posix.as_posix().lower()
    name_lower = posix.name.lower()
    suffix = posix.suffix.lower()

    if name_lower in _INSTRUCTION_ROOT_FILES:
        return True
    if suffix == ".json":
        if "tool" in lower or "schema" in lower or "assistant" in lower:
            return True
        if ".well-known/" in lower or name_lower in {"agent-card.json", "agent.json"}:
            return True
    if (
        posix.parts
        and posix.parts[0].lower() in _INSTRUCTION_DIRS
        and suffix in _TEXT_DECLARATION_SUFFIXES
    ):
        return True
    if suffix == ".md" and name_lower in {
        "skill.md",
        "claude.md",
        "agents.md",
        "gemini.md",
        "codex.md",
    }:
        return True
    return bool(name_lower.endswith(".prompt.md") or name_lower.endswith(".tool.json"))


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

    _priority = (
        ToolComponent,
        PromptComponent,
        SkillPackageComponent,
        A2AServerComponent,
        MCPServerComponent,
        IDEAgentComponent,
    )
    return min(
        candidates,
        key=lambda cand: next(
            (idx for idx, kind in enumerate(_priority) if isinstance(cand, kind)),
            len(_priority),
        ),
    )


_MD_COMMENT_LINE_RE = re.compile(
    r"^[ \t]{0,3}\[[^\]\n]{1,120}\]:[ \t]*(?:#|<>).*$",
    re.MULTILINE,
)


def _mask_hidden_markdown_markup(text: str) -> str:
    """Replace hidden HTML/PI/reference comments with spaces while keeping length."""
    chars = list(text)
    for open_tok, close_tok in (("<!--", "-->"), ("<?", "?>")):
        pos = 0
        while (start := text.find(open_tok, pos)) != -1:
            end = text.find(close_tok, start + len(open_tok), start + 4096)
            stop = end + len(close_tok) if end != -1 else min(len(text), start + 4096)
            for idx in range(start, stop):
                chars[idx] = " "
            pos = stop
    for match in _MD_COMMENT_LINE_RE.finditer(text):
        for idx in range(match.start(), match.end()):
            chars[idx] = " "
    return "".join(chars)


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
        ordered_rules: list[str] = []
        seen_rules: set[str] = set()
        for h in group:
            if h.rule_id not in seen_rules:
                seen_rules.add(h.rule_id)
                ordered_rules.append(h.rule_id)
        primary_rule = ordered_rules[0]
        earliest_offset = min(h.byte_offset for h in group)
        dedup_key = (component.bom_ref, category, surface)
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        safe_surface = neutralize(surface)
        safe_name = neutralize(component.name)
        severity = max(
            (h.severity for h in group),
            key=lambda s: ("info", "low", "medium", "high", "critical").index(s.value),
        )
        rules_label = ", ".join(ordered_rules)
        summary_desc = group[0].summary
        detail = (
            f"Surface '{safe_surface}' ({safe_name}) matched rule {primary_rule} "
            f"[{rules_label}] at byte_offset={earliest_offset} (pack={RULE_PACK_VERSION}): "
            f"{summary_desc}. Matched payload text is withheld."
        )
        recommendation = (
            "Remove coercive tags, override directives, hidden instructions, or credential-relay "
            "guidance from untrusted tool metadata, agent cards, or prompt files before loading into LLM context."
        )
        component.risks.append(
            RiskAssessment(
                severity=severity,
                category=category,
                detail=detail,
                recommendation=recommendation,
                references=[f"{_RULE_REFERENCE_PREFIX}{rid}" for rid in ordered_rules],
            )
        )
        added += 1
    return added


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

    Inspects in-memory component descriptions and schemas, plus safely opened
    repository component sources and declared schema/prompt/assistant files when
    ``root`` is provided. Appends ``RiskAssessment`` findings directly to owning
    existing components without creating synthetic components or altering component
    hashes.
    """
    components_by_path: dict[str, list[ComponentWithRisks]] = {}
    tools_by_name: dict[str, list[ToolComponent]] = {}
    root_agent: AgentComponent | None = None
    seen_keys: set[tuple[str, str, str]] = set()
    added = 0

    for comp in aibom.components:
        if not isinstance(
            comp,
            (
                AgentComponent,
                MCPServerComponent,
                ToolComponent,
                PromptComponent,
                SkillPackageComponent,
                A2AServerComponent,
                IDEAgentComponent,
            ),
        ):
            continue
        if isinstance(comp, AgentComponent) and root_agent is None:
            root_agent = comp
        if isinstance(comp, ToolComponent):
            tools_by_name.setdefault(comp.name, []).append(comp)
        if comp.source_path and "://" not in comp.source_path:
            components_by_path.setdefault(comp.source_path, []).append(comp)
        if (
            isinstance(comp, A2AServerComponent)
            and comp.agent_card_path
            and "://" not in comp.agent_card_path
        ):
            components_by_path.setdefault(comp.agent_card_path, []).append(comp)

    # Phase 1: In-memory component text & JSON-schema inspection
    for comp in aibom.components:
        if isinstance(comp, ToolComponent):
            surface = comp.source_path or comp.name
            hits: list[TextPoisoningHit] = []
            parts: list[str] = []
            for text in (comp.description_text, comp.description):
                if text:
                    parts.append(text)
                    hits.extend(scan_text_block(text, surface=surface, is_tool_surface=True))
            for _field_path, val in extract_json_text_entries(comp.input_schema):
                parts.append(val)
                hits.extend(scan_text_block(val, surface=surface, is_tool_surface=True))
            sidenote_hits = check_sidenote_tool_schema(
                comp.input_schema,
                "\n".join(parts),
                comp.annotations,
                surface=surface,
                existing_hits=hits,
            )
            added += _append_consolidated_risks(comp, [*hits, *sidenote_hits], seen_keys=seen_keys)
        elif isinstance(comp, A2AServerComponent):
            surface = comp.source_path or comp.agent_card_path or comp.name
            hits = []
            for text in (comp.description, *comp.skills_declared):
                if text:
                    hits.extend(scan_text_block(text, surface=surface, is_tool_surface=True))
            added += _append_consolidated_risks(comp, hits, seen_keys=seen_keys)
        elif isinstance(
            comp,
            (
                PromptComponent,
                SkillPackageComponent,
                MCPServerComponent,
                IDEAgentComponent,
                AgentComponent,
            ),
        ):
            if comp.description:
                surface = comp.source_path or comp.name
                is_tool = isinstance(comp, MCPServerComponent)
                hits = scan_text_block(comp.description, surface=surface, is_tool_surface=is_tool)
                added += _append_consolidated_risks(comp, hits, seen_keys=seen_keys)

    if root is None or not root.is_dir():
        return added

    # Phase 2: Confined repository file inspection (component sources + supplemental schemas/prompts)
    own_failures: list[str] = []
    own_exclusions: list[str] = []
    scanned_rel_paths: set[str] = set()

    with ConfinedCollection(
        root, own_failures, own_exclusions, exclude_paths=exclude_paths
    ) as files:
        candidate_paths: list[tuple[str, bool]] = []
        seen_candidates: set[str] = set()

        for rel_path, comps in sorted(components_by_path.items()):
            posix = PurePosixPath(rel_path)
            if posix.suffix.lower() not in _COMPONENT_SOURCE_SUFFIXES:
                continue
            if any(
                isinstance(c, SkillPackageComponent) and c.skill_type == "skill-resource"
                for c in comps
            ):
                if posix.suffix.lower() not in _TEXT_DECLARATION_SUFFIXES:
                    continue
            if rel_path not in seen_candidates:
                seen_candidates.add(rel_path)
                candidate_paths.append((rel_path, True))

        for path_obj in files.iter_files():
            rel_path = path_obj.as_posix()
            if (
                rel_path in seen_candidates
                or _is_test_path(rel_path)
                or _is_credential_path(rel_path)
            ):
                continue
            if _is_supplemental_surface(rel_path):
                seen_candidates.add(rel_path)
                candidate_paths.append((rel_path, False))

        for rel_path, from_component in candidate_paths:
            if _is_credential_path(rel_path) or files.excluded(rel_path):
                continue
            if files.regular_file(rel_path) is None:
                continue
            suffix = PurePosixPath(rel_path).suffix.lower()
            comps = components_by_path.get(rel_path, [])
            is_tool_ctx = any(
                isinstance(c, (ToolComponent, A2AServerComponent, MCPServerComponent))
                for c in comps
            )

            raw_text = files.read_text(rel_path, missing_ok=True)
            if raw_text is None:
                continue
            scanned_rel_paths.add(rel_path)
            if not from_component and _is_test_path(rel_path):
                continue

            raw_bytes = raw_text.encode("utf-8")

            if suffix == ".json":
                parsed: Any = None
                try:
                    from nexus_symbiote.core.hashing import MAX_JSON_NESTING, json_nesting_exceeds

                    if not json_nesting_exceeds(raw_text, MAX_JSON_NESTING):
                        parsed = json.loads(raw_text)
                except (ValueError, RecursionError):
                    parsed = None

                is_json_tool = is_tool_ctx or any(
                    tok in rel_path.lower()
                    for tok in ("tool", "schema", "agent-card", "agent.json", ".well-known")
                )
                json_hits: list[TextPoisoningHit] = []
                if isinstance(parsed, dict):
                    entries = extract_json_text_entries(parsed)
                    for _, val in entries:
                        json_hits.extend(
                            scan_text_block(val, surface=rel_path, is_tool_surface=is_json_tool)
                        )
                    maybe_fn = parsed.get("function")
                    fn_obj: dict[str, Any] = maybe_fn if isinstance(maybe_fn, dict) else parsed
                    schema_node = (
                        fn_obj.get("inputSchema")
                        or fn_obj.get("parameters")
                        or parsed.get("inputSchema")
                        or parsed.get("parameters")
                    )
                    fn_ann = fn_obj.get("annotations")
                    parsed_ann = parsed.get("annotations")
                    ann_node: dict[str, Any] | None = (
                        fn_ann
                        if isinstance(fn_ann, dict)
                        else (parsed_ann if isinstance(parsed_ann, dict) else None)
                    )
                    if isinstance(schema_node, dict) or ann_node is not None:
                        json_hits.extend(
                            check_sidenote_tool_schema(
                                schema_node if isinstance(schema_node, dict) else None,
                                "\n".join(val for _, val in entries),
                                ann_node,
                                surface=rel_path,
                                existing_hits=json_hits,
                            )
                        )
                    target_comp: ComponentWithRisks | None = None
                    if comps:
                        target_comp = _attribute_source_component(
                            raw_text,
                            raw_bytes,
                            json_hits[0].byte_offset if json_hits else 0,
                            comps,
                            root_agent,
                        )
                    else:
                        named = (
                            fn_obj.get("name")
                            if isinstance(fn_obj.get("name"), str)
                            else parsed.get("name")
                        )
                        if isinstance(named, str) and named in tools_by_name:
                            target_comp = tools_by_name[named][0]
                        elif root_agent is not None:
                            target_comp = root_agent
                    if target_comp is not None and json_hits:
                        added += _append_consolidated_risks(
                            target_comp, json_hits, seen_keys=seen_keys
                        )
                else:
                    hits = scan_text_block(raw_text, surface=rel_path, is_tool_surface=is_json_tool)
                    target_comp = _attribute_source_component(
                        raw_text, raw_bytes, hits[0].byte_offset if hits else 0, comps, root_agent
                    )
                    if target_comp is not None and hits:
                        added += _append_consolidated_risks(target_comp, hits, seen_keys=seen_keys)
                continue

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
            if not hits:
                continue
            hits_by_target: dict[str, tuple[ComponentWithRisks, list[TextPoisoningHit]]] = {}
            for h in hits:
                chosen = _attribute_source_component(
                    raw_text, raw_bytes, h.byte_offset, comps, root_agent
                )
                if chosen is None:
                    continue
                bucket = hits_by_target.setdefault(chosen.bom_ref, (chosen, []))
                bucket[1].append(h)
            for chosen, target_hits in hits_by_target.values():
                added += _append_consolidated_risks(chosen, target_hits, seen_keys=seen_keys)

    if surfaces is not None:
        surfaces.extend(sorted(scanned_rel_paths))
    if failures is not None:
        existing_failures = set(failures)
        for msg in own_failures:
            if msg not in existing_failures:
                failures.append(msg)
                existing_failures.add(msg)
    if exclusions is not None:
        existing_exclusions = set(exclusions)
        for msg in own_exclusions:
            if msg not in existing_exclusions:
                exclusions.append(msg)
                existing_exclusions.add(msg)
    return added
