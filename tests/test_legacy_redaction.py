"""The floor under the union engine: main's rules replayed with every character tracked.

``redact_text`` hides whatever the replay says main hid, so the replay must produce main's
output exactly and trace each character it keeps to its source.
"""

from __future__ import annotations

import random

import pytest

from nexus_symbiote.utils import _legacy_redaction as legacy
from nexus_symbiote.utils.secrets import SecretScrubber, redact_text

# Main's own outputs, recorded from its redact_text: (text, values, text mode, identifier mode).
RECORDED = [
    ("see https://h.example/p?token=abc12345 and more", (), "see https://h.example and more", None),
    ("ssh://git@github.com/org/repo.git", (), "ssh://github.com", None),
    ("password = hunter2hunter2, user = bob", (), "password = ***, user = bob", None),
    ("Authorization: Bearer abcdef123456", (), "Authorization: Bearer ***", None),
    (
        "Cookie: sid=abcdefgh12345; theme=dark",
        (),
        "Cookie: sid=***; theme=dark",
        "Cookie: sid=abcdefgh12345; theme=dark",
    ),
    ("token= api_key= hunter2hunter2_secret=x", (), "token= *** hunter2hunter2_secret=***", None),
    (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\nafter",
        (),
        "***\nafter",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\nafter",
    ),
    ("value hunter2hunter2 and hunter2hunter2!", ("hunter2hunter2",), "value *** and ***!", None),
    (
        "a*b*c*d secret*value*1 tail secret*value*1",
        ("secret*value*1", "a*b*c*d"),
        "*** *** tail ***",
        None,
    ),
    (
        "https://user:pw@HOST.example:0443/x ghp_" + "a" * 36,
        (),
        "https://host.example:443 ***",
        None,
    ),
    ("x=Bearer y=Bearer abc123def456", (), "x=Bearer *** abc123def456", None),
    ("sig_v=abc PRIMARY_KEY=sig_v: v", (), "sig_v=*** PRIMARY_KEY=sig_v: ***", None),
]


@pytest.mark.parametrize(("text", "values", "shown", "named"), RECORDED)
def test_the_replay_gives_mains_recorded_output(
    text: str, values: tuple[str, ...], shown: str, named: str | None
) -> None:
    ordered = SecretScrubber(values).values
    assert legacy.redaction(text, ordered) == shown
    assert legacy.tracked_redaction(text, ordered, identifier=False) == shown
    expected = shown if named is None else named
    assert legacy.tracked_redaction(text, ordered, identifier=True) == expected


_PIECES = [
    "https://u:pw@h.example/p?q=1",
    "HTTPS://Host.Example:0443/x",
    "ssh://git@github.com/o/r.git",
    "token=",
    "password: ",
    "api_key=",
    "Authorization: Bearer ",
    "Cookie: sid=",
    "; theme=dark",
    "ghp_" + "b" * 36,
    "-----BEGIN PRIVATE KEY-----\n",
    "-----END PRIVATE KEY-----",
    '"',
    "'",
    "\\",
    " ",
    "\n",
    ",",
    "*",
    "***",
    "@",
    "#",
    "?",
]


def _text(rng: random.Random, values: list[str]) -> str:
    parts = []
    for _ in range(rng.randrange(1, 14)):
        roll = rng.random()
        if roll < 0.3 and values:
            parts.append(rng.choice(values))
        elif roll < 0.75:
            parts.append(rng.choice(_PIECES))
        else:
            parts.append(
                "".join(rng.choice("abcXYZ019_-./:=") for _ in range(rng.randrange(1, 12)))
            )
    return "".join(parts)


@pytest.mark.parametrize("seed", range(4))
def test_the_tracked_replay_equals_mains_sequential_rules(seed: int) -> None:
    # Values with and without "*", overlapping one another, and the text they occur in:
    # the batched known-value pass must give what replacing each value in turn gives.
    rng = random.Random(seed)  # noqa: S311 - reproducible test inputs
    for _ in range(400):
        pool = ["secret*value*1", "a*b*c*d", "hunter2hunter2", "hunter2", "**x*", "2hunter"]
        values = SecretScrubber(rng.sample(pool, rng.randrange(0, len(pool)))).values
        text = _text(rng, list(values))
        for identifier in (False, True):
            assert legacy.tracked_redaction(
                text, values, identifier=identifier
            ) == legacy.redaction(text, values, identifier=identifier), (text, values)


@pytest.mark.parametrize(
    ("url", "shown", "sources"),
    [
        ("https://GitHub.com/org", "https://github.com", [*range(18)]),
        ("ssh://git@h.example/x", "ssh://h.example", [*range(6), *range(10, 19)]),
        ("https://h.example:0443/x", "https://h.example:443", [*range(18), 19, 20, 21]),
        ("http://[FE80::1]:8080/x", "http://[fe80::1]:8080", [*range(21)]),
        ("https://h.example:/x", "https://h.example", [*range(17)]),
    ],
)
def test_an_origin_is_traced_to_the_characters_it_shows(
    url: str, shown: str, sources: list[int]
) -> None:
    assert legacy.origin_sources(url, shown) == sources


def test_an_origin_that_does_not_align_is_not_traced() -> None:
    assert legacy.origin_sources("https://h.example/x", "[redacted-url]") is None
    assert legacy.origin_sources("https://a[b]c/x", "https://b") is None


def test_hidden_spans_report_what_main_removed_apart_from_the_rewrites_own() -> None:
    text = "token=abc123def tail"
    assert legacy.hidden_spans(text, (), identifier=False, removed=[]) == [(6, 15)]
    url = "see https://u:pw@h.example/p tail"
    hidden = legacy.hidden_spans(url, (), identifier=False, removed=[])
    assert [url[start:end] for start, end in hidden] == ["u:pw@", "/p"]
    assert legacy.hidden_spans(url, (), identifier=False, removed=[(12, 17), (26, 28)]) == []


def test_values_holding_stars_beyond_the_replay_budget_hide_the_whole_text() -> None:
    values = tuple(SecretScrubber([f"s{index:03d}*value" for index in range(64)]).values)
    text = " ".join(values) + " tail"
    assert legacy.hidden_spans(text, values, identifier=False, removed=[]) == [(0, len(text))]
    assert redact_text(text, values) == "***"


def test_known_values_without_a_star_are_replayed_in_one_rebuild(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rebuilds = 0
    replace_spans = legacy._Tracked.replace_spans

    def counted(self: legacy._Tracked, edits: object) -> None:
        nonlocal rebuilds
        rebuilds += 1
        replace_spans(self, edits)  # type: ignore[arg-type]

    monkeypatch.setattr(legacy._Tracked, "replace_spans", counted)
    values = tuple(SecretScrubber([f"credential-{index:04d}" for index in range(512)]).values)
    text = " ".join(values)
    assert legacy.tracked_redaction(text, values, identifier=True) == " ".join(["***"] * 512)
    assert rebuilds == 1


@pytest.mark.parametrize(
    ("text", "values"),
    [
        ("Ix.y://'X//", ("/'X/", "'X//", "X//")),
        ('pwdtokenQFB0T8Ox.y://a.btoken"UNJR', ("//a.btok", 'token"U', '.btoken"')),
    ],
)
def test_a_letter_main_showed_only_lower_cased_is_not_shown_as_written(
    text: str, values: tuple[str, ...]
) -> None:
    # Main read these letters as part of a URL's host or scheme and showed them
    # lower-cased; where the union reads the URL differently it must not show them as
    # written.
    shown = redact_text(text, values)
    for letter in {char for char in text if char.isupper() and text.count(char) == 1}:
        assert letter not in shown, (letter, shown)
