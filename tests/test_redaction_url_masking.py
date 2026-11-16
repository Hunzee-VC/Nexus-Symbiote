"""Assignment and cookie rules read the text with each URL masked (#208 merge review)."""

from __future__ import annotations

import pytest

from nexus_symbiote.utils.secrets import redact_keyed_text, redact_text
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


@pytest.mark.parametrize(
    "text",
    [
        f"wss://h.example/?sig=abc#ApiKey {SECRET})",
        f"git+ssh://h/zqbb/ApiKey {SECRET}\n",
        f"wss://h/p#zz s3://h/?sig=a/Authorization: Token {SECRET}\\redis://h/?a=b",
    ],
)
def test_a_scheme_word_inside_a_url_still_marks_the_credential_after_it(text: str) -> None:
    # The scheme and header rules read the text as it is, as well as with URLs masked.
    assert SECRET not in redact_text(text)


@pytest.mark.parametrize(
    "text",
    [
        f's3://h/p?Authorization":"{SECRET}  next',
        f"redis://h/db\tproxy-authorization:\twss://h/p?Authorization=\n{SECRET})",
    ],
)
def test_a_header_name_inside_a_url_still_marks_the_value_after_it(text: str) -> None:
    assert SECRET not in redact_text(text)


def test_a_cookie_key_hides_what_main_hid() -> None:
    # Main read a `Cookie` key's value as pairs after redacting it, so the run after a
    # closing quote was a pair's value; the union keeps that.
    shown = redact_keyed_text("Cookie", f'sig_v="abc\\"def"{SECRET}%PRIMARY_KEY')
    assert SECRET not in shown


@pytest.mark.parametrize(
    "text",
    [
        f'token = "https://h/p\\"{SECRET}"',
        f'{{"password": "https://h\\"{SECRET}"}}',
        f"password='https://h/p\\'{SECRET}'",
        f"api_key:///x>{SECRET}",
    ],
)
def test_a_quoted_value_or_a_name_masked_with_a_url_still_hides_its_value(text: str) -> None:
    # The URL's mask covers the backslash before an escaped quote, or the end of a name
    # that reads as the URL's scheme; the value is read in the original text as well.
    assert SECRET not in redact_text(text)
    assert SECRET not in redact_text(text, identifier=True)


@pytest.mark.parametrize(
    "text",
    [
        f"token= api_key= {SECRET}_secret=x",
        f"X-Api-Key=\napi_key=\n{SECRET}_secret'=%",
        f"PRIMARY_KEY=sig_v: {SECRET}",
        f"token: password: {SECRET}_secret=x",
    ],
)
def test_every_name_start_is_read_as_an_assignment(text: str) -> None:
    assert SECRET not in redact_text(text)


@pytest.mark.parametrize(
    "text",
    [
        f"password=Cookie: a={SECRET}",
        f"token: Cookie: sid={SECRET}; theme=dark",
        f"see https://h.example/x then password=Cookie: a={SECRET}",
    ],
)
def test_a_cookie_header_inside_an_assignment_value_is_read(text: str) -> None:
    assert SECRET not in redact_text(text)


@pytest.mark.parametrize("unit", ["https://h/?password=>", "https://h/?token:>"])
def test_a_url_ending_in_a_credential_name_is_read_in_linear_time(unit: str) -> None:
    assert scaling_ratio(lambda scale: redact_text(unit * (2000 * scale))) < 10
