"""SPDX projection 3 neutralizes relationship comments with a frozen mapping, and
projection 2 exports still recover with their original comments."""

import json
import re
from copy import deepcopy
from pathlib import Path

import pytest

from nexus_symbiote.generators import spdx
from nexus_symbiote.generators.recovery import recover_export
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.generators.validation import validate_spdx
from nexus_symbiote.utils import terminal
from nexus_symbiote.utils.terminal import neutralize

# Every code point that projection 3 shows as U+FFFD, as inclusive ranges. Recovery
# renders each comment again and compares it with the stored one, so this set never
# changes once released: a different set needs a new projection.
PROJECTION_THREE_REPLACED = [
    (0x0000, 0x0008),
    (0x000A, 0x001F),
    (0x007F, 0x009F),
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFFB),
    (0xFFFE, 0xFFFF),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
]


def legacy_document():
    path = Path(__file__).parent / "fixtures/export-projection-2/conditional.spdx.json"
    return json.loads(path.read_text(encoding="utf-8"))


def marker(document):
    node = next(node for node in document["@graph"] if node["type"] == "SpdxDocument")
    return next(
        prop
        for extension in node["extension"]
        for prop in extension["extension_cdxProperty"]
        if prop["extension_cdxPropName"] == "nexus-symbiote:projection"
    )


def conditional(document):
    return next(node for node in document["@graph"] if "conditions:" in node.get("comment", ""))


def with_conditions(conditions):
    bom = SPDXGenerator.recover(legacy_document())
    bom.dependencies[0].conditions = conditions
    return bom


def test_frozen_projection_two_recovers_with_its_original_comment():
    document = legacy_document()
    assert validate_spdx(document) == []
    original_comment = conditional(document)["comment"]
    assert "\n" in original_comment and "\t" in original_comment and "\u202e" in original_comment
    bom = SPDXGenerator.recover(document)
    assert recover_export(json.dumps(document)) == bom
    assert "\n" in bom.dependencies[0].conditions

    current = SPDXGenerator().generate(bom)
    assert marker(current)["extension_cdxPropValue"] == "spdx-3.0.1/3"
    assert conditional(current)["comment"] == (
        "Conditional native relationship 'invokes' (conditions: Only when approved\ufffdand "
        "read-only \ufffdapproval). Not an unconditional usesTool assertion."
    )
    assert SPDXGenerator.recover(current) == bom
    assert document == legacy_document()


@pytest.mark.parametrize(
    "conditions",
    [
        "when approved\nby the owner",
        "approved\tby owner",
        "approved \u202eby owner",
        "served\x1b[2J ##vso[task.setvariable]\ufffe",
        "x" * 1030,
    ],
)
def test_projection_two_comments_keep_the_original_text(conditions):
    # What the projection 2 generator wrote: the text as it is, cut at 1,024 characters.
    document = SPDXGenerator()._projection(with_conditions(conditions), legacy_v2=True)
    assert marker(document)["extension_cdxPropValue"] == "spdx-3.0.1/2"
    shown = conditions if len(conditions) <= 1024 else conditions[:1024] + " [truncated]"
    assert conditional(document)["comment"] == (
        f"Conditional native relationship 'invokes' (conditions: {shown}). "
        "Not an unconditional usesTool assertion."
    )
    assert SPDXGenerator.recover(document).dependencies[0].conditions == conditions


@pytest.mark.parametrize("edit", ["comment", "marker"])
def test_projection_two_rejects_a_changed_comment_or_marker(edit):
    document = legacy_document()
    if edit == "comment":
        conditional(document)["comment"] = neutralize(conditional(document)["comment"])
    else:
        marker(document)["extension_cdxPropValue"] = "spdx-3.0.1/3"
    with pytest.raises(ValueError, match="projection conflicts"):
        SPDXGenerator.recover(document)


def test_projection_three_cannot_be_relabelled_as_two():
    bom = SPDXGenerator.recover(legacy_document())
    document = deepcopy(SPDXGenerator().generate(bom))
    marker(document)["extension_cdxPropValue"] = "spdx-3.0.1/2"
    with pytest.raises(ValueError, match="projection conflicts"):
        SPDXGenerator.recover(document)


def test_projection_three_replaces_exactly_its_frozen_character_set():
    every = "".join(map(chr, range(0x110000)))
    shown = spdx._comment_text(every)
    assert len(shown) == len(every)
    changed = [
        point for point, (old, new) in enumerate(zip(every, shown, strict=True)) if old != new
    ]
    assert shown[0x09] == " "
    replaced = [point for point in changed if point != 0x09]
    assert {shown[point] for point in replaced} == {"\ufffd"}
    ranges: list[tuple[int, int]] = []
    for point in replaced:
        if ranges and ranges[-1][1] == point - 1:
            ranges[-1] = (ranges[-1][0], point)
        else:
            ranges.append((point, point))
    assert ranges == PROJECTION_THREE_REPLACED


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ("name\tvalue", "name value"),
        ("a\u202eb\ufffec\x85d\u2028e", "a\ufffdb\ufffdc\ufffdd\ufffde"),
        ("x##vso[task.setvariable]", "x##\ufffdvso[task.setvariable]"),
        ("##[error]y", "##\ufffd[error]y"),
        ("##teamcity[z", "##\ufffdteamcity[z"),
        ("## [not a command] #[ #", "## [not a command] #[ #"),
    ],
)
def test_projection_three_known_answers(text, shown):
    assert spdx._comment_text(text) == shown


def test_projection_three_does_not_follow_terminal_neutralization(monkeypatch):
    bom = with_conditions("approved\u00a0by\u2066 the owner")
    document = SPDXGenerator().generate(bom)
    comment = conditional(document)["comment"]
    recovered = SPDXGenerator.recover(deepcopy(document))
    # A later release whose terminal output also neutralizes U+00A0 must neither
    # change projection 3 comments nor reject projection 3 exports written before it.
    widened = re.compile(terminal.UNSAFE_TEXT.pattern[:-1] + "\u00a0]")
    monkeypatch.setattr(terminal, "UNSAFE_TEXT", widened)
    assert neutralize("\u00a0") == "\ufffd"
    assert SPDXGenerator.recover(deepcopy(document)) == recovered
    assert conditional(SPDXGenerator().generate(bom))["comment"] == comment
    assert "\u00a0" in comment and "\u2066" not in comment
