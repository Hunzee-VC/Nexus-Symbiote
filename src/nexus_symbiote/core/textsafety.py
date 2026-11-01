"""Detection of characters that can hide, reorder, or smuggle text.

Used on prompt files and on tool names and descriptions. The rules are deliberately
narrow: legitimate emoji sequences and scripts use zero-width joiners and variation
selectors, and those are not reported.
"""

from __future__ import annotations

from dataclasses import dataclass

# Bidirectional embedding, override, and isolate controls (the "Trojan Source" class).
# LRM, RLM, and ALM are legitimate in right-to-left text and are not reported.
_BIDI_CONTROLS: frozenset[int] = frozenset(range(0x202A, 0x202F)) | frozenset(
    range(0x2066, 0x206A)
)

# Language tag characters. They are invisible and can carry an ASCII payload.
_TAG_CHARACTERS: range = range(0xE0000, 0xE0080)

# Zero-width and invisible format characters. ZWJ, ZWNJ, and variation selectors are
# omitted on purpose because emoji and several scripts depend on them.
_INVISIBLE: frozenset[int] = frozenset({0x180E, 0x200B, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064})


@dataclass(frozen=True)
class HiddenCharacter:
    index: int
    codepoint: str
    kind: str  # "bidi-control" | "tag-character" | "invisible"


def find_hidden_characters(text: str) -> list[HiddenCharacter]:
    """Return every character that can hide or reorder text.

    A byte-order mark at index 0 is accepted, because some editors write one.
    """
    hits: list[HiddenCharacter] = []
    for index, char in enumerate(text):
        code = ord(char)
        if code in _BIDI_CONTROLS:
            kind = "bidi-control"
        elif code in _TAG_CHARACTERS:
            kind = "tag-character"
        elif code == 0xFEFF:
            if index == 0:
                continue
            kind = "invisible"
        elif code in _INVISIBLE:
            kind = "invisible"
        else:
            continue
        hits.append(HiddenCharacter(index=index, codepoint=f"U+{code:04X}", kind=kind))
    return hits
