"""A URL keeps the origin main showed, and a credential key shows only a whole-URL locator."""

from __future__ import annotations

import pytest

from nexus_symbiote.utils.secrets import (
    SecretScrubber,
    redact_keyed_text,
    redact_metadata,
    redact_text,
)
from tests.support import scaling_ratio

SECRET = "Hunter2Secret"  # noqa: S105 - synthetic sentinel


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("ssh://git@github.com/org/repo.git", "ssh://github.com"),
        ("postgres://app:pw@db.example.com:5432/app", "postgres://db.example.com:5432"),
        ("https://GitHub.com/org/repo", "https://github.com"),
        ("HTTPS://example.com/x", "https://example.com"),
        ("https://h.example:0443/x", "https://h.example:443"),
        ("https://user@host.example/x", "https://host.example"),
        ("http://[FE80::1]:8080/x", "http://[fe80::1]:8080"),
    ],
)
def test_a_url_keeps_the_origin_main_showed(url: str, origin: str) -> None:
    # The origin is lower-cased, drops user info and a port's leading zeros; none of that
    # is a match reaching into it, so it is shown, as main showed it.
    assert redact_text(f"clone {url} now") == f"clone {origin} now"
    assert redact_text(url, identifier=True) == origin
    assert redact_metadata({"repository": url}) == {"repository": origin}
    assert redact_keyed_text("url", url) == origin


def test_a_known_value_in_the_host_still_redacts_the_whole_url() -> None:
    url = "ssh://git@Hunter2Secret.example/org/repo.git"
    assert redact_text(url, [SECRET]) == "***"


@pytest.mark.parametrize(
    ("key", "value", "values"),
    [
        ("password", f"https://h'{SECRET}&signing_key=a@b", ()),
        ("X-Api-Key", f"https://h<{SECRET}>signing_key=x#y", ()),
        ("password", f"https://h'{SECRET},XXXXXXXXXA@BBBBBB", ("XXXXXXXXXA", "A@BBBBBB")),
        ("password", f"https://h'{SECRET}", ()),
        ("password", f'https://h"{SECRET}', ()),
        ("password", f"https://h/x\\'{SECRET}", ()),
    ],
)
def test_a_credential_value_glued_to_a_url_is_no_locator(
    key: str, value: str, values: tuple[str, ...]
) -> None:
    assert redact_keyed_text(key, value, values) == "***"
    assert redact_metadata({key: value}, values) == {key: "***"}
    assert redact_keyed_text(key, value, redacted=redact_text(value, values)) == "***"


@pytest.mark.parametrize(
    ("key", "value", "shown"),
    [
        ("token_url", "https://auth.example.com/token", "https://auth.example.com"),
        ("password", "https://admin:hunter2pass@db.example.com/x", "https://db.example.com"),
        (
            "DATABASE_URL",
            "postgres://app@db.example.com:5432/app",
            "postgres://db.example.com:5432",
        ),
        ("api_key", "${API_KEY}", "${API_KEY}"),
    ],
)
def test_a_locator_or_reference_under_a_credential_key_is_shown(
    key: str, value: str, shown: str
) -> None:
    assert redact_keyed_text(key, value) == shown


def test_short_strings_cost_nothing_per_known_value() -> None:
    # A string shorter than every known value holds none, so main's known-value pass is
    # not replayed for it: the cost per string must not grow with the number of values.
    values = [f"{index:016x}" for index in range(4096)]
    scrubbers = {1: SecretScrubber(values[:256]), 16: SecretScrubber(values)}
    texts = {f"k{index}": "abc" for index in range(2000)}
    assert scaling_ratio(lambda scale: redact_metadata(texts, scrubbers[scale]), factor=16) < 4
