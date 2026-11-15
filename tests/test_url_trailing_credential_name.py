"""A credential name that ends a URL match keeps redacting the value after it.

The URL rule stops at whitespace, so in ``https://h/?a=b,password: value`` it takes the
name with the URL. Showing the URL as its origin then dropped the name, and the
assignment rule never saw the value.
"""

from __future__ import annotations

import time

import pytest

from nexus_symbiote.utils.secrets import redact_text

VALUE = "hunter2hunter2"


@pytest.mark.parametrize(
    "text",
    [
        f"https://h.example/?a=b,password: {VALUE}",
        f"https://h.example/?a=b;password: {VALUE}",
        f"https://h.example/?a=b&password: {VALUE}",
        f"https://h.example/?a=b|password: {VALUE}",
        f"https://h.example/?a=b`password: {VALUE}",
        f"https://h.example/?a=b]password: {VALUE}",
        f"https://h.example/?a=b}}password: {VALUE}",
        f"https://h.example/?a=b\\password: {VALUE}",
        f"https://h.example/a.password: {VALUE}",
        f"(https://h.example/?a=b)secret: {VALUE}",
        f"(https://h.example/path)secret: {VALUE}",
        f"(https://h.example/?token=abc)password: {VALUE}",
        f"https://h.example/?sig=x&token=abc&password: {VALUE}",
        f"https://h.example/?token=abc)password= {VALUE}",
        f"[docs](https://h.example/?a=b)password: {VALUE}",
        f"x https://h.example/?q=1#password: {VALUE}",
        f"https://h.example/?a=b,password= {VALUE}",
        f"https://h.example/?a=b,password : {VALUE}",
        f"https://h.example/?a=b,password\t=\t{VALUE}",
        f"https://h.example/?a=b,password:\n{VALUE}",
        f"https://h.example/?a=b,password: '{VALUE}'",
        f"https://h.example/?a=b,DB_PASSWORD_PROD: {VALUE}",
        f"https://h.example/?a=b,API_KEY: {VALUE}",
        f"https://user:pw@h.example/?a=b,token: {VALUE}",
        f"https://a.example/?x=1 https://b.example/?y=2,secret: {VALUE}",
    ],
)
def test_value_after_a_name_that_ends_a_url_is_redacted(text: str) -> None:
    for identifier in (False, True):
        shown = redact_text(text, identifier=identifier)
        assert VALUE not in shown
        assert "***" in shown


def test_the_url_keeps_its_origin_and_the_value_is_redacted() -> None:
    shown = redact_text(f"https://h.example/cb?a=b,password: {VALUE}")
    assert shown.startswith("https://h.example ")
    assert shown.endswith("***")
    assert VALUE not in shown


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # No text follows the URL, so there is no value to lose: the origin alone.
        ("https://h.example/cb?token=", "https://h.example"),
        ("https://h.example/cb?a=b,password:", "https://h.example"),
        # The name is not written as an assignment.
        ("https://h.example/reset-password and more", "https://h.example and more"),
        ("https://h.example/api/token then call it", "https://h.example then call it"),
        # No credential name ends the URL.
        ("https://h.example/a?b=c next: word", "https://h.example next: word"),
        ("see https://h.example/docs: the guide", "see https://h.example the guide"),
    ],
)
def test_other_urls_are_shown_as_before(text: str, expected: str) -> None:
    assert redact_text(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        f"<https://h.example/cb?password=>token: {VALUE}",
        f"<https://h.example/cb?password=<b>token: {VALUE}",
        f"<https://h.example/cb?a=b,password:>secret= {VALUE}",
        f'<a href="https://h.example/cb?token=abc123">password: {VALUE}</a>',
        f"<a href='https://h.example/cb?password='>token: {VALUE}</a>",
    ],
)
def test_a_name_glued_to_the_end_of_a_url_does_not_hide_the_next_name(text: str) -> None:
    assert VALUE not in redact_text(text)


def test_a_value_inside_the_url_is_still_dropped_with_it() -> None:
    assert redact_text(f"https://h.example/cb?password={VALUE} next") == "https://h.example next"


def test_long_urls_stay_linear() -> None:
    def cost(count: int) -> float:
        text = " ".join(f"https://h.example/{'token.' * 40}{n}: x" for n in range(count))
        started = time.perf_counter()
        redact_text(text)
        return time.perf_counter() - started

    cost(200)
    small, large = min(cost(500) for _ in range(3)), min(cost(4000) for _ in range(3))
    assert large < small * 40
