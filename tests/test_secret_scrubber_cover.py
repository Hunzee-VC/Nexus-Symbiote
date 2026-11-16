"""The known-value cover is exactly the union of every occurrence of every value."""

from __future__ import annotations

import random

import pytest

from nexus_symbiote.utils.secrets import SecretScrubber


def _occurrences(text: str, values: list[str]) -> list[tuple[int, int]]:
    """Every occurrence of every value, overlapping ones included, as joined spans."""
    covered = bytearray(len(text))
    for value in values:
        if not value:
            continue
        start = text.find(value)
        while start >= 0:
            covered[start : start + len(value)] = b"\x01" * len(value)
            start = text.find(value, start + 1)
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(text):
        if covered[index]:
            end = index
            while end < len(text) and covered[end]:
                end += 1
            spans.append((index, end))
            index = end
        else:
            index += 1
    return spans


@pytest.mark.parametrize("seed", range(400))
def test_cover_matches_every_occurrence_on_small_alphabets(seed: int) -> None:
    # A two- or three-letter alphabet makes periodic values, overlapping and nested
    # occurrences, and values absent from the text all common.
    rng = random.Random(seed)  # noqa: S311 - fixed test data, not a secret
    alphabet = "ab" if seed % 2 else "abc"
    values = [
        "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 6)))
        for _ in range(rng.randint(1, 8))
    ]
    text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
    scrubber = SecretScrubber(values)
    assert scrubber.spans(text) == _occurrences(text, values)


def test_values_absent_from_the_text_do_not_change_the_cover() -> None:
    present = ["abab", "bab", "credential-0001"]
    absent = [f"credential-{i:04d}" for i in range(2, 300)]
    text = "x ababab y credential-0001 z babab"
    assert SecretScrubber([*present, *absent]).spans(text) == SecretScrubber(present).spans(text)
    assert SecretScrubber(absent).spans(text) == []


def test_a_fully_covered_text_ends_the_walk_with_later_values_absent() -> None:
    # The longest value covers the whole text; every shorter value is absent or
    # inside it, so the cover is the whole text whichever values are skipped.
    text = "secret-value-0001"
    values = [text, "zzzz", "value", "yyy", "0001"]
    assert SecretScrubber(values).spans(text) == [(0, len(text))]
