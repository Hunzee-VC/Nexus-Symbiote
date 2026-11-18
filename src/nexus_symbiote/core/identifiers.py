"""Neutralize collected identifiers and report the characters that disguised them.

A name, description or supplier that a collector read from a checkout can hold a
terminal control sequence, a bidirectional override or letters of two scripts that
look alike. Printed text goes through ``reporting.safe_line``, but an export is read
by other tools, and one unescape in a consumer makes a ``\\u001b`` in a CycloneDX
name a live terminal sequence again. Every collected component therefore has these
fields neutralized once, at collection, and a finding records what was replaced:
the character classes, their counts and a digest of the raw value, never the text.
"""

from __future__ import annotations

import hashlib
import unicodedata
from collections import Counter

from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.hashing import hash_tool_definition, tool_definition_extensions
from nexus_symbiote.core.models import (
    AnyComponent,
    MCPServerComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.utils.terminal import LOG_COMMAND, UNSAFE_TEXT, neutralize

CATEGORY = "identifier_characters"
RECOMMENDATION = (
    "Rename the component in its configuration with plain letters of one script, "
    "and look for who added the characters."
)

ESC_SEQUENCE = "ESC sequence"
TAB = "tab"
C0_CONTROL = "C0 control"
C1_CONTROL = "C1 control"
BIDI_FORMAT = "bidirectional format character"
OTHER_FORMAT = "other format or invisible character"
LOG_INTRODUCER = "CI log-command introducer"
CLASSES = (ESC_SEQUENCE, TAB, C0_CONTROL, C1_CONTROL, BIDI_FORMAT, OTHER_FORMAT, LOG_INTRODUCER)

_BIDI = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")

# Scripts as the first script word of a letter's Unicode name, so FULLWIDTH LATIN and
# HALFWIDTH KATAKANA letters count for their script. A letter whose name holds none,
# such as a modifier or mathematical letter, belongs to no script here.
_SCRIPTS = frozenset(
    (
        "LATIN",
        "GREEK",
        "CYRILLIC",
        "ARMENIAN",
        "HEBREW",
        "ARABIC",
        "SYRIAC",
        "THAANA",
        "NKO",
        "SAMARITAN",
        "MANDAIC",
        "DEVANAGARI",
        "BENGALI",
        "GURMUKHI",
        "GUJARATI",
        "ORIYA",
        "TAMIL",
        "TELUGU",
        "KANNADA",
        "MALAYALAM",
        "SINHALA",
        "THAI",
        "LAO",
        "TIBETAN",
        "MYANMAR",
        "GEORGIAN",
        "HANGUL",
        "ETHIOPIC",
        "CHEROKEE",
        "CANADIAN",
        "OGHAM",
        "RUNIC",
        "TAGALOG",
        "HANUNOO",
        "BUHID",
        "TAGBANWA",
        "KHMER",
        "MONGOLIAN",
        "LIMBU",
        "TAI",
        "BUGINESE",
        "BALINESE",
        "SUNDANESE",
        "BATAK",
        "LEPCHA",
        "OL",
        "GLAGOLITIC",
        "COPTIC",
        "TIFINAGH",
        "HIRAGANA",
        "KATAKANA",
        "BOPOMOFO",
        "CJK",
        "YI",
        "LISU",
        "VAI",
        "BAMUM",
        "JAVANESE",
        "CHAM",
        "GOTHIC",
        "DESERET",
        "SHAVIAN",
        "OSMANYA",
        "ADLAM",
        "KAITHI",
        "BRAHMI",
        "CUNEIFORM",
        "PHOENICIAN",
        "LYDIAN",
        "LYCIAN",
        "CARIAN",
        "UGARITIC",
        "OSAGE",
    )
)
_SHOWN_SCRIPT = {"CJK": "Han", "NKO": "N'Ko", "OL": "Ol Chiki", "CANADIAN": "Canadian Syllabics"}
# UTS #39's Highly Restrictive level: Han with the kana, with Bopomofo or with Hangul
# is one writing system, and Latin beside it is ordinary.
_EAST_ASIAN = (
    frozenset({"CJK", "HIRAGANA", "KATAKANA"}),
    frozenset({"CJK", "BOPOMOFO"}),
    frozenset({"CJK", "HANGUL"}),
)
_SHOWN_CHARS = 80
_LISTED_VALUES = 10


def character_classes(value: str) -> dict[str, int]:
    """How many characters of each class ``neutralize`` would replace in ``value``.

    The classes together are exactly what ``neutralize`` changes: a value with no
    class has the same text after neutralization, and one with any class differs.
    """
    counts: Counter[str] = Counter()
    for char in value:
        if char == "\x1b":
            counts[ESC_SEQUENCE] += 1
        elif char == "\t":
            counts[TAB] += 1
        elif char <= "\x1f" or char == "\x7f":
            counts[C0_CONTROL] += 1
        elif "\x80" <= char <= "\x9f":
            counts[C1_CONTROL] += 1
        elif char in _BIDI:
            counts[BIDI_FORMAT] += 1
        elif UNSAFE_TEXT.match(char):
            counts[OTHER_FORMAT] += 1
    introducers = len(LOG_COMMAND.findall(value))
    if introducers:
        counts[LOG_INTRODUCER] = introducers
    return {name: counts[name] for name in CLASSES if counts[name]}


def letter_scripts(value: str) -> frozenset[str]:
    """The scripts of the letters in ``value``, by their Unicode names."""
    found: set[str] = set()
    for char in value:
        if not unicodedata.category(char).startswith("L"):
            continue
        for word in unicodedata.name(char, "").split():
            if word in _SCRIPTS:
                found.add(word)
                break
    return frozenset(found)


def mixed_scripts(value: str) -> tuple[str, ...]:
    """The scripts of ``value``, shown by name, when its letters mix them; else empty.

    Digits, punctuation, emoji and letters of no listed script never make a mix, and
    Latin beside one East Asian writing system is ordinary.
    """
    found = letter_scripts(value)
    if len(found) < 2:
        return ()
    rest = found - {"LATIN"}
    if any(rest <= family for family in _EAST_ASIAN):
        return ()
    return tuple(sorted(_SHOWN_SCRIPT.get(script, script.capitalize()) for script in found))


def raw_digest(value: str) -> str:
    """SHA-256 of the raw value's UTF-8 bytes, which the finding records instead of it."""
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def _shown(value: str) -> str:
    return value if len(value) <= _SHOWN_CHARS else value[:_SHOWN_CHARS] + "..."


def _describe(label: str, raw: str, *, scripts: bool) -> str | None:
    classes = character_classes(raw)
    mixed = mixed_scripts(raw) if scripts else ()
    if not classes and not mixed:
        return None
    parts = []
    if classes:
        parts.append("holds " + ", ".join(_plural(count, name) for name, count in classes.items()))
    if mixed:
        parts.append("mixes the " + ", ".join(mixed) + " scripts")
    return f"{label} {' and '.join(parts)} (raw value sha256:{raw_digest(raw)})"


def _nested_tool_names(component: AnyComponent) -> list[tuple[str, list[str], int]]:
    """Each tool-name list under the server's client settings, by field, with its index.

    The MCP collector exports the names of auto-approved and filtered tools under
    ``properties.client_settings.auto_approved_tools`` and ``tool_filter_names``, one
    list per configuration field. A tool's own component is neutralized as every other
    component is; these lists are the other place a tool name is recorded.
    """
    if not isinstance(component, MCPServerComponent):
        return []
    settings = component.properties.get("client_settings")
    if not isinstance(settings, dict):
        return []
    found: list[tuple[str, list[str], int]] = []
    for group in ("auto_approved_tools", "tool_filter_names"):
        lists = settings.get(group)
        if not isinstance(lists, dict):
            continue
        for field, names in lists.items():
            if not isinstance(names, list):
                continue
            for index, name in enumerate(names):
                if isinstance(name, str):
                    found.append((field, names, index))
    return found


def _displayed_tool_hash(tool: ToolComponent, name: str) -> str | None:
    """The digest ``validators.integrity`` recomputes over the displayed descriptor."""
    if tool.description_text is None:
        return None
    properties = tool.properties
    try:
        extensions = tool_definition_extensions(
            {
                "title": properties.get("mcp_title", properties.get("title")),
                "outputSchema": properties.get(
                    "mcp_output_schema", properties.get("output_schema")
                ),
                "_meta": properties.get("mcp_meta", properties.get("meta")),
            }
        )
        return hash_tool_definition(
            name, tool.description_text, tool.input_schema, tool.annotations, **extensions
        )
    except (TypeError, ValueError):
        return None


def _rebind_tool_name(tool: ToolComponent, raw_name: str) -> None:
    """Bind the displayed descriptor digest to the neutralized name.

    The collector hashed the descriptor it displays over the raw name. Only a digest
    that matched that descriptor is replaced, so a tool that did not verify before
    still does not.
    """
    if tool.name == raw_name:
        return
    before = _displayed_tool_hash(tool, raw_name)
    if before is None or before not in {tool.definition_hash, tool.redacted_definition_hash}:
        return
    after = _displayed_tool_hash(tool, tool.name)
    tool.redacted_definition_hash = after if after != tool.definition_hash else None


def neutralize_identifiers(component: AnyComponent) -> RiskAssessment | None:
    """Neutralize the component's name, description, supplier and nested tool names.

    Returns the one ``identifier_characters`` finding this adds to the component when
    a value changed or an MCP server or tool name mixes scripts; None when nothing did.
    Applying it again to the same component changes nothing and adds no finding.

    A tool whose name changed has its displayed descriptor digest bound to the new name,
    so integrity validation still verifies it; ``definition_hash`` keeps the original.
    The details and recommendations of the component's earlier findings are neutralized
    too, without a finding of their own: a collector composes them around the quoted
    name, so a control sequence there is the name's, already reported.
    """
    reported = any(risk.category == CATEGORY for risk in component.risks)
    raw_name = component.name
    named = isinstance(component, (MCPServerComponent, ToolComponent))
    values: list[tuple[str, str, bool]] = [("name", component.name, named)]
    if component.description is not None:
        values.append(("description", component.description, False))
    if component.supplier is not None:
        values.append(("supplier", component.supplier, False))
    nested = _nested_tool_names(component)
    values.extend(
        (f"tool name '{_shown(neutralize(names[index]))}' in {field}", names[index], True)
        for field, names, index in nested
    )
    descriptions = [
        described
        for label, raw, scripts in values
        if (described := _describe(label, raw, scripts=scripts)) is not None
    ]

    component.name = neutralize(component.name)
    if isinstance(component, ToolComponent):
        _rebind_tool_name(component, raw_name)
    if component.description is not None:
        component.description = neutralize(component.description)
    if component.supplier is not None:
        component.supplier = neutralize(component.supplier)
    for _, names, index in nested:
        names[index] = neutralize(names[index])
    for risk in component.risks:
        risk.detail = neutralize(risk.detail)
        if risk.recommendation is not None:
            risk.recommendation = neutralize(risk.recommendation)
    if not descriptions or reported:
        return None

    listed = descriptions[:_LISTED_VALUES]
    if len(descriptions) > _LISTED_VALUES:
        listed.append(f"and {len(descriptions) - _LISTED_VALUES} more values")
    finding = RiskAssessment(
        severity=RiskSeverity.HIGH,
        category=CATEGORY,
        detail=(
            f"The {component.component_type.value} component '{_shown(component.name)}' was "
            "collected with characters that can rewrite or disguise its identity (in the "
            "inventory a tab is a space and other control and format characters are "
            "U+FFFD): " + "; ".join(listed) + "."
        ),
        recommendation=RECOMMENDATION,
    )
    component.risks.append(finding)
    return finding
