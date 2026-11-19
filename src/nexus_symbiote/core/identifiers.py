"""Neutralize collected identifiers and report the characters that disguised them.

A name, description or supplier that a collector read from a checkout can hold a
terminal control sequence, a bidirectional override or letters of two scripts that
look alike. Printed text goes through ``reporting.safe_line``, but an export is read
by other tools, and one unescape in a consumer makes a ``\\u001b`` in a CycloneDX
name a live terminal sequence again. Every collected component therefore has these
fields neutralized once, at collection, and a finding records what was replaced:
the character classes, their counts and a digest of the raw value, never the text.

Ordinary text is left alone: a variation selector after an emoji, a joiner inside an
emoji sequence or where IDNA's CONTEXTJ rules allow it, and a word in one script beside
a word in another are kept as written and reported nowhere, unless every letter of a
non-Latin word beside Latin text reads as a Latin letter.
"""

from __future__ import annotations

import bisect
import hashlib
import re
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
from nexus_symbiote.utils.terminal import LOG_COMMAND, UNSAFE_TEXT

CATEGORY = "identifier_characters"
RECOMMENDATION = (
    "Rename the component in its configuration with plain letters of one script, "
    "and look for who added the characters."
)
# The SHA-256 of each field's raw text, by field name, for every field neutralization
# changed; trace-diff matches on it and export-inventory refuses what it names.
RAW_DIGESTS = "neutralized_raw_sha256"
# Under RAW_DIGESTS, the SHA-256 of a rewritten name's raw text without the spaces, tabs
# and line breaks around it, when it had any: trace-diff compares names trimmed.
TRIMMED_NAME = "trimmed_name"
_TRIM = " \t\r\n"

ESC_SEQUENCE = "ESC sequence"
TAB = "tab"
LINE_BREAK = "line break"
C0_CONTROL = "C0 control"
C1_CONTROL = "C1 control"
BIDI_FORMAT = "bidirectional format character"
OTHER_FORMAT = "other format or invisible character"
LOG_INTRODUCER = "CI log-command introducer"
CLASSES = (
    ESC_SEQUENCE,
    TAB,
    LINE_BREAK,
    C0_CONTROL,
    C1_CONTROL,
    BIDI_FORMAT,
    OTHER_FORMAT,
    LOG_INTRODUCER,
)
# A description, supplier or finding text may wrap or indent; only a name may not.
SPACING = frozenset({TAB, LINE_BREAK})


def _code_ranges(text: str) -> tuple[tuple[int, int], ...]:
    """Code point ranges written as hex ``start-end`` or single points."""
    found = []
    for item in text.split():
        start, _, end = item.partition("-")
        found.append((int(start, 16), int(end or start, 16)))
    return tuple(found)


_BIDI = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_REPLACED = re.compile(UNSAFE_TEXT.pattern[:-1] + r"\t]")
# JSON writes these in fewer bytes than U+FFFD's escape, so they become a space and an
# introducer loses its second "#" to one: neutralized text is never longer in an export
# than the raw text was, and an inventory that fitted the native size limit still does.
_SPACED = frozenset("\t\n\x0b\x0c\r\x08\x7f")
_VARIATION = frozenset("\ufe0e\ufe0f")
_KEYCAP_BASES = frozenset("#*0123456789")
_KEYCAP = "\u20e3"
# Emoji (in emoji-variation-sequences.txt or Extended_Pictographic) whose general
# category is not So; every So symbol counts as an emoji too.
_EMOJI_NOT_SO = frozenset(
    "\u203c\u2049\u2139\u2194\u25fb\u25fc\u25fd\u25fe\u2934\u2935\u3030\u303d"
)
_ZWJ = "\u200d"
_ZWNJ = "\u200c"
_JOINERS = frozenset({_ZWNJ, _ZWJ})
_VIRAMA = 9
# Joining_Type L or D, and R or D, from Unicode 16.0's ArabicShaping.txt: the letters a ZWNJ may follow
# and precede under CONTEXTJ. Unlisted marks and format characters are transparent.
_JOINS_FORWARD = _code_ranges(
    "0620 0626 0628 062A-062E 0633-063F 0641-0647 0649-064A 066E-066F 0678-0687 "
    "069A-06BF 06C1-06C2 06CC 06CE 06D0-06D1 06FA-06FC 06FF 0712-0714 071A-071D "
    "071F-0727 0729 072B 072D-072E 074E-0758 075C-076A 076D-0770 0772 0775-0777 "
    "077A-077F 07CA-07EA 0841-0845 0848 084A-0853 0855 0860 0862-0865 0868 0886 "
    "0889-088D 088F 08A0-08A9 08AF-08B0 08B3-08B8 08BA-08C8 1807 1820-1878 1887-18A8 "
    "18AA A840-A872 10AC0-10AC4 10ACD 10AD3-10ADC 10ADE-10AE0 10AEB-10AEE 10B80 10B82 "
    "10B86-10B88 10B8A-10B8B 10B8D 10B90 10BAD-10BAE 10D00-10D21 10D23 10EC3-10EC4 "
    "10EC6-10EC7 10ED9-10EEE 10F30-10F32 10F34-10F44 10F51-10F53 10F70-10F73 10F76-10F81 "
    "10FB0 10FB2-10FB3 10FB8 10FBB-10FBC 10FBE-10FBF 10FC1 10FC4 10FCA-10FCB 1E900-1E943"
)
_JOINS_BACKWARD = _code_ranges(
    "0620 0622-063F 0641-064A 066E-066F 0671-0673 0675-06D3 06D5 06EE-06EF 06FA-06FC "
    "06FF 0710 0712-072F 074D-077F 07CA-07EA 0840-0858 0860 0862-0865 0867-086A "
    "0870-0882 0886 0889-088F 08A0-08AC 08AE-08C8 1807 1820-1878 1887-18A8 18AA "
    "A840-A871 10AC0-10AC5 10AC7 10AC9-10ACA 10ACE-10AD6 10AD8-10AE1 10AE4 10AEB-10AEF "
    "10B80-10B91 10BA9-10BAE 10D01-10D23 10EC2-10EC4 10EC6-10EC7 10F30-10F44 10F51-10F54 "
    "10F70-10F81 10FB0 10FB2-10FB6 10FB8-10FBF 10FC1-10FC4 10FC9-10FCA 1E900-1E943"
)
_TRANSPARENT = frozenset({"Mn", "Me", "Cf"})
_MARKS = frozenset({"Mn", "Mc", "Me"})
# Cyrillic, Greek and Armenian letters that read as Latin ones (after UTS #39
# confusables.txt): a word of only these beside Latin text is a lookalike.
_LATIN_LOOKALIKES = frozenset("асеорхуіјѕԁһӏԛԝмАВЕКМНОРСТХІЈЅӀοανικρτυϲϳΑΒΕΖΗΙΚΜΝΟΡΤΥΧօոսհ")

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
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_PERCENT_TRIPLET = re.compile(r"%[0-9A-Fa-f]{2}")
_LISTED_VALUES = 10


def _in(char: str, ranges: tuple[tuple[int, int], ...]) -> bool:
    point = ord(char)
    index = bisect.bisect_right(ranges, (point, 0x10FFFF)) - 1
    return index >= 0 and ranges[index][0] <= point <= ranges[index][1]


def _script_word(char: str) -> str:
    name = unicodedata.name(char, "")
    return name.split()[0] if name else ""


def _emoji(char: str) -> bool:
    return bool(char) and (unicodedata.category(char) == "So" or char in _EMOJI_NOT_SO)


def _emoji_before(value: str, index: int) -> bool:
    """Whether an emoji ends just before ``index``, after its selector or skin tone."""
    while index > 0 and (
        value[index - 1] in _VARIATION
        or unicodedata.name(value[index - 1], "").startswith("EMOJI MODIFIER")
    ):
        index -= 1
    return index > 0 and _emoji(value[index - 1])


def _virama_on_its_letter(value: str, index: int, base: int | None = None) -> bool:
    """Whether ``value[index]`` is a virama on a letter of its own script.

    The letter is sought from ``base`` back, by default the character before the virama,
    so a ZWJ between the two can be stepped over without copying ``value``.
    """
    if not 0 < index < len(value) or unicodedata.combining(value[index]) != _VIRAMA:
        return False
    script = _script_word(value[index])
    base = index - 1 if base is None else base
    while base >= 0 and _stepped_over(value[base], _MARKS):
        base -= 1
    return (
        base >= 0
        and unicodedata.category(value[base])[0] == "L"
        and _script_word(value[base]) == script
    )


def _stepped_over(char: str, categories: frozenset[str]) -> bool:
    """Whether a context rule steps over ``char``, one of ``categories`` that is kept.

    A character neutralization replaces is not stepped over: a second pass would meet
    its U+FFFD instead and replace a joiner the first pass kept.
    """
    return unicodedata.category(char) in categories and not _REPLACED.match(char)


def _joining_neighbour(value: str, index: int, step: int) -> str:
    """The first character from ``index`` in direction ``step`` that is not transparent."""
    while 0 <= index < len(value) and _stepped_over(value[index], _TRANSPARENT):
        index += step
    return value[index] if 0 <= index < len(value) else ""


def _kept(value: str, index: int) -> bool:
    """Whether the selector or joiner at ``index`` is part of ordinary spelling.

    A variation selector chooses the presentation of the emoji before it, or of a
    keycap's ``#``, ``*`` or digit when U+20E3 follows. A zero-width joiner joins two
    emoji. Otherwise a joiner is kept only as IDNA's CONTEXTJ rules (RFC 5892, Appendix
    A.1 and A.2) allow: either one after a virama, here on a letter of the virama's own
    script, and a ZWNJ between a letter that joins forward and one that joins backward.
    A ZWJ between a letter and a virama of its script, Bengali's ra with ya-phala, is
    kept too, as the Unicode Standard spells it.
    """
    char = value[index]
    before = value[index - 1] if index else ""
    after = value[index + 1] if index + 1 < len(value) else ""
    if char in _VARIATION:
        if before in _KEYCAP_BASES:
            return after == _KEYCAP
        return _emoji(before)
    if char not in _JOINERS:
        return False
    if char == _ZWJ and _emoji_before(value, index) and _emoji(after):
        return True
    if _virama_on_its_letter(value, index - 1):
        return True
    if char == _ZWJ:
        return _virama_on_its_letter(value, index + 1, index - 1)
    previous = _joining_neighbour(value, index - 1, -1)
    following = _joining_neighbour(value, index + 1, 1)
    return (
        bool(previous)
        and bool(following)
        and _in(previous, _JOINS_FORWARD)
        and _in(following, _JOINS_BACKWARD)
    )


def _class(char: str) -> str:
    if char == "\x1b":
        return ESC_SEQUENCE
    if char == "\t":
        return TAB
    if char in "\n\r":
        return LINE_BREAK
    if char <= "\x1f" or char == "\x7f":
        return C0_CONTROL
    if "\x80" <= char <= "\x9f":
        return C1_CONTROL
    if char in _BIDI:
        return BIDI_FORMAT
    return OTHER_FORMAT


def _rewrites(value: str) -> dict[int, tuple[str, str]]:
    """Each position neutralization changes in ``value``, with its class and replacement.

    Every replacement is one character, so positions in the raw and neutralized text
    agree.
    """
    found: dict[int, tuple[str, str]] = {}
    for match in _REPLACED.finditer(value):
        char, index = match.group(), match.start()
        if (char in _VARIATION or char in _JOINERS) and _kept(value, index):
            continue
        found[index] = (_class(char), " " if char in _SPACED else "\ufffd")
    text = _apply(value, found)
    for match in LOG_COMMAND.finditer(text):
        found[match.start() + 1] = (LOG_INTRODUCER, " ")
    return found


def _apply(value: str, rewrites: dict[int, tuple[str, str]]) -> str:
    if not rewrites:
        return value
    chars = list(value)
    for index, (_, replacement) in rewrites.items():
        chars[index] = replacement
    return "".join(chars)


def neutral_text(value: str) -> str:
    """``value`` with every character that can rewrite or disguise output replaced.

    A tab, line break, form feed, backspace or delete becomes a space, a CI log-command
    introducer's second ``#`` a space, and every other control, bidirectional, format
    or invisible character U+FFFD, except selectors and joiners in ordinary spelling.
    Applying it again changes nothing.
    """
    return _apply(value, _rewrites(value))


def character_classes(value: str) -> dict[str, int]:
    """How many characters of each class ``neutral_text`` replaces in ``value``.

    The classes together are exactly what ``neutral_text`` changes: a value with no
    class has the same text after neutralization, and one with any class differs.
    """
    counts = Counter(name for name, _ in _rewrites(value).values())
    return {name: counts[name] for name in CLASSES if counts[name]}


def reference_text(value: str) -> str:
    """``value`` for use inside a ``bom_ref``.

    Each character ``neutral_text`` would replace is percent-encoded as its UTF-8 bytes
    instead, so no reference holds a control or format character. When anything is
    encoded, or the name already holds a ``%`` and two hex digits, every ``%`` becomes
    ``%25`` too, so an encoded reference decodes to exactly one name and different raw
    names get different references. A name with neither, ``%`` alone included, is its
    own reference.
    """
    rewrites = _rewrites(value)
    if not rewrites and not _PERCENT_TRIPLET.search(value):
        return value
    chars = list(value)
    for index, char in enumerate(chars):
        if index in rewrites:
            chars[index] = "".join(f"%{byte:02X}" for byte in char.encode("utf-8", "surrogatepass"))
        elif char == "%":
            chars[index] = "%25"
    return "".join(chars)


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


def _words(value: str) -> list[str]:
    """Runs of letters, marks, digits and joiners: the words a name is written in."""
    words: list[str] = []
    current: list[str] = []
    for char in value:
        if unicodedata.category(char)[0] in "LMN" or char in _JOINERS:
            current.append(char)
        elif current:
            words.append("".join(current))
            current = []
    if current:
        words.append("".join(current))
    return words


def _mix(found: frozenset[str]) -> bool:
    if len(found) < 2:
        return False
    rest = found - {"LATIN"}
    return not any(rest <= family for family in _EAST_ASIAN)


def _reads_as_latin(word: str) -> bool:
    letters = [char for char in word if unicodedata.category(char)[0] == "L"]
    return bool(letters) and all(char in _LATIN_LOOKALIKES for char in letters)


def mixed_scripts(value: str) -> tuple[str, ...]:
    """The scripts mixed within a word of ``value``, shown by name; else empty.

    A word is a run of letters, marks, digits and joiners, so a Cyrillic word beside a
    Latin one is ordinary, and Latin and Cyrillic letters inside one word, the lookalike
    case, are not. A Cyrillic, Greek or Armenian word whose every letter reads as a
    Latin one, such as ``ехес`` in ``shell_ехес``, mixes with the Latin text beside it.
    Digits, punctuation, emoji and letters of no listed script never make a mix, and
    Latin beside one East Asian writing system is ordinary.
    """
    mixed: set[str] = set()
    latin = "LATIN" in letter_scripts(value)
    for word in _words(value):
        found = letter_scripts(word)
        if _mix(found):
            mixed |= found
        elif latin and found and "LATIN" not in found and _reads_as_latin(word):
            mixed |= found | {"LATIN"}
    return tuple(sorted(_SHOWN_SCRIPT.get(script, script.capitalize()) for script in mixed))


def raw_digest(value: str) -> str:
    """SHA-256 of the raw value's UTF-8 bytes, which the finding records instead of it."""
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def _shown(value: str) -> str:
    return value if len(value) <= _SHOWN_CHARS else value[:_SHOWN_CHARS] + "..."


def _describe(label: str, raw: str, *, name: bool, scripts: bool) -> str | None:
    """The finding's account of one value, or None when it holds nothing to report.

    A description or supplier may wrap or indent, so its tabs and line breaks become
    spaces unreported; a name's are reported. Only MCP server and tool names are
    checked for a mix of scripts.
    """
    classes = {
        key: count for key, count in character_classes(raw).items() if name or key not in SPACING
    }
    mixed = mixed_scripts(raw) if scripts else ()
    if not classes and not mixed:
        return None
    parts = []
    if classes:
        parts.append("holds " + ", ".join(_plural(count, key) for key, count in classes.items()))
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
    a value holds a reported character or an MCP server or tool name mixes scripts
    within a word; None when nothing does. Applying it again to the same component
    changes nothing and adds no finding. Each field whose text changed has the SHA-256
    of its raw text recorded under ``properties["neutralized_raw_sha256"]``, so a
    rewritten value is never taken for a plain one that reads the same; a rewritten name
    with spaces, tabs or line breaks around it also has the digest of its trimmed raw
    text recorded there, under ``trimmed_name``.

    A tool whose name changed has its displayed descriptor digest bound to the new name,
    so integrity validation still verifies it; ``definition_hash`` keeps the original.
    The details and recommendations of the component's earlier findings are neutralized
    too, without a finding of their own: a collector composes them around the quoted
    name, so a control sequence there is the name's, already reported.
    """
    reported = any(risk.category == CATEGORY for risk in component.risks)
    raw_name = component.name
    named = isinstance(component, (MCPServerComponent, ToolComponent))
    fields: list[tuple[str, str]] = [("name", component.name)]
    if component.description is not None:
        fields.append(("description", component.description))
    if component.supplier is not None:
        fields.append(("supplier", component.supplier))
    accounts = [
        _describe(field, raw, name=field == "name", scripts=field == "name" and named)
        for field, raw in fields
    ]
    nested = _nested_tool_names(component)
    accounts.extend(
        _describe(
            f"tool name '{_shown(neutral_text(names[index]))}' in {field}",
            names[index],
            name=True,
            scripts=True,
        )
        for field, names, index in nested
    )
    descriptions = [account for account in accounts if account is not None]

    rewritten = {
        field: f"sha256:{raw_digest(raw)}" for field, raw in fields if neutral_text(raw) != raw
    }
    if "name" in rewritten and raw_name.strip(_TRIM) != raw_name:
        rewritten[TRIMMED_NAME] = f"sha256:{raw_digest(raw_name.strip(_TRIM))}"
    component.name = neutral_text(component.name)
    if isinstance(component, ToolComponent):
        _rebind_tool_name(component, raw_name)
    if component.description is not None:
        component.description = neutral_text(component.description)
    if component.supplier is not None:
        component.supplier = neutral_text(component.supplier)
    for _, names, index in nested:
        names[index] = neutral_text(names[index])
    for risk in component.risks:
        risk.detail = neutral_text(risk.detail)
        if risk.recommendation is not None:
            risk.recommendation = neutral_text(risk.recommendation)
    if rewritten:
        recorded = component.properties.get(RAW_DIGESTS)
        merged = dict(recorded) if isinstance(recorded, dict) else {}
        merged.update(rewritten)
        component.properties[RAW_DIGESTS] = dict(sorted(merged.items()))
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
            "inventory a tab, line break, form feed, backspace or delete is a space, so is "
            "the second # of a CI log-command introducer, and other control and format "
            "characters are U+FFFD): " + "; ".join(listed) + "."
        ),
        recommendation=RECOMMENDATION,
    )
    component.risks.append(finding)
    return finding


def name_key(value: str) -> tuple[str, str]:
    """A key that two names share only when their raw text is the same.

    A name neutralization leaves alone is its own key; any other is keyed by the
    SHA-256 of its raw text, which is what an inventory records for a rewritten name.
    """
    if neutral_text(value) == value:
        return ("text", value)
    return ("raw", f"sha256:{raw_digest(value)}")


def recorded_name_key(component: AnyComponent, name: str) -> tuple[str, str]:
    """``name_key`` of the raw name the component was collected with, trimmed.

    ``name`` is the recorded name with the spaces, tabs and line breaks around it
    trimmed, as trace-diff reads it, and the key is that of the raw name trimmed the
    same way. A component whose name neutralization rewrote is keyed by the digest it
    recorded, so ``run job`` collected from ``run<TAB>job`` matches neither a plain
    ``run job`` nor anything else, while ``job`` collected from ``job<TAB>`` is keyed as
    ``job``; an inventory written before neutralization keeps the raw name, which is
    keyed as it is.
    """
    recorded = component.properties.get(RAW_DIGESTS)
    if not isinstance(recorded, dict):
        return name_key(name)
    digest = recorded.get(TRIMMED_NAME, recorded.get("name"))
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        return name_key(name)
    if digest == f"sha256:{raw_digest(name)}":
        return name_key(name)
    return ("raw", digest)
