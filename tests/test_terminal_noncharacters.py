"""Every Unicode noncharacter is neutralized, not only U+FFFE and U+FFFF.

Audit 2026-11-14 L10 found that noncharacters passed terminal neutralization; the fix
covered U+FFFE and U+FFFF. The other 64 (U+FDD0 to U+FDEF and the last two code points
of planes 1 to 16) are equally unassigned for ever.
"""

from __future__ import annotations

from nexus_symbiote.utils.terminal import UNSAFE_TEXT, neutralize

NONCHARACTERS = [
    *range(0xFDD0, 0xFDF0),
    *(plane << 16 | low for plane in range(17) for low in (0xFFFE, 0xFFFF)),
]


def test_there_are_66_noncharacters():
    assert len(set(NONCHARACTERS)) == 66


def test_every_noncharacter_is_replaced():
    assert [hex(point) for point in NONCHARACTERS if neutralize(chr(point)) != "�"] == []


def test_neighbours_of_the_noncharacter_ranges_are_left_alone():
    for point in (0xFDCF, 0xFDF0, 0x1FFFD, 0x20000, 0x10FFFD):
        assert not UNSAFE_TEXT.search(chr(point)), hex(point)
