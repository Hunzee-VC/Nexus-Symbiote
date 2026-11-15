"""Assignment and cookie rules read the text with each URL masked (#208 merge review)."""

from __future__ import annotations

import pytest

from nexus_symbiote.utils.secrets import redact_text
from tests.support import scaling_ratio

SECRET = "hunter2hunter2"  # noqa: S105 - synthetic sentinel


@pytest.mark.parametrize(
    "text",
    [
        f"sort_key = token = '{SECRET}'",
        f"signing_key:\n  password: {SECRET}",
        f"ssh_key:\n  passphrase: {SECRET}",
        f"cache_key = \npassword = {SECRET}",
        f"env:\n  PRIMARY_KEY:\n  DB_PASSWORD : {SECRET}",
    ],
)
def test_a_name_whose_value_is_the_next_assignment_does_not_hide_it(text: str) -> None:
    assert SECRET not in redact_text(text)


def test_a_value_glued_to_its_separator_is_a_value_whatever_it_spells() -> None:
    assert redact_text(f"sort_key={SECRET}sort_key:x") == "sort_key=***"


@pytest.mark.parametrize(
    "text",
    [
        f"see <https://h.example/cb?cookie=x> Cookie: sid={SECRET}; tok=abc12345defg",
        f"https://h.example/?cookie=a Cookie: sid={SECRET}",
    ],
)
def test_a_cookie_header_after_a_url_holding_cookie_is_redacted(text: str) -> None:
    shown = redact_text(text)
    assert SECRET not in shown and "abc12345defg" not in shown


@pytest.mark.parametrize("closer", ["", ")", "]", ";", "&", "#", "/p"])
def test_a_credential_name_that_ends_a_url_takes_the_value_after_it(closer: str) -> None:
    assert SECRET not in redact_text(f"https://h.example/?a=b{closer},password: {SECRET}")


def test_a_scheme_word_after_a_url_ending_in_a_name_stays_for_the_scheme_rule() -> None:
    assert redact_text("https://h.example/?a,password: Bearer abc.def.ghi") == (
        "https://h.example Bearer ***"
    )


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        (
            f'<a href="https://h.example/cb?token=abc123">password: {SECRET}</a>',
            '<a href="https://h.example">password: ***',
        ),
        ("x https://h/p?token=abc then words", "x https://h then words"),
        ("token=abc123 next", "token=*** next"),
    ],
)
def test_ordinary_forms_redact_as_before(text: str, shown: str) -> None:
    assert redact_text(text) == shown


def test_urls_holding_assignments_are_read_in_linear_time() -> None:
    assert scaling_ratio(lambda scale: redact_text('https://h/?sig=x"' * (2000 * scale))) < 10
