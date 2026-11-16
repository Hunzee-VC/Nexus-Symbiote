"""Values after two-character marks, chained names and credential-named options.

The assignment rule read one ``:`` or ``=`` as the mark, so in ``password := value``
the ``=`` became the value and the real one stayed in clear. A first name's unquoted
value could also take a second name with it, and a long option such as
``--password value`` has no mark at all.
"""

from __future__ import annotations

import pytest

from nexus_symbiote.utils.secrets import redact_text
from tests.support import scaling_ratio

VALUE = "hunter2hunter2"


@pytest.mark.parametrize("mark", [":=", "=>", "::", "=:", "==", ":>"])
@pytest.mark.parametrize("name", ["password", "API_KEY", "'token'", '"client_secret"'])
@pytest.mark.parametrize("layout", ["{n}{m}{v}", "{n} {m} {v}", "{n}{m} {v}", '{n} {m} "{v}"'])
def test_value_after_a_two_character_mark_is_redacted(mark: str, name: str, layout: str) -> None:
    text = "set " + layout.format(n=name, m=mark, v=VALUE) + " next"
    for identifier in (False, True):
        shown = redact_text(text, identifier=identifier)
        assert VALUE not in shown
        assert shown.endswith(" next")


@pytest.mark.parametrize(
    "text",
    [
        f"token=abcpassword : {VALUE}",
        f"token=abcaccess-key = {VALUE}",
        f"password: secret = {VALUE}",
        f"token=abc)password: {VALUE}",
        f"api_key=x;y token=abc/secret:\t{VALUE}",
        f"https://h.example/x?password=: {VALUE}",
        f"https://h.example/?a,password:: {VALUE}",
        f'https://h.example/?a=b,password" : {VALUE}',
        f"https://h.example/?a=bAPI_KEY=>{VALUE},x",
        f"https://h.example/?a=b/API_KEY:>{VALUE}}}",
        f"https://h.example/?a=b(token => {VALUE}]",
        f"https://h.example/&client_secret:\n{VALUE};y",
        f"https://h.example/sig='{VALUE}'",
        f'https://h.example/?a=b--#@api_key="{VALUE}"',
        f"https://h.example/?token=abcpassword : {VALUE}",
        f"<a href='https://h.example/cb?password='>token: {VALUE}</a>",
    ],
)
def test_a_name_inside_an_earlier_value_or_url_still_redacts_its_value(text: str) -> None:
    assert VALUE not in redact_text(text)


def test_a_name_glued_to_a_url_stays_readable() -> None:
    shown = redact_text(f"<https://h.example/cb?password=>token: {VALUE}")
    assert shown == "<https://h.example>token: ***"


@pytest.mark.parametrize(
    "text",
    [
        f"mysql --password {VALUE} db",
        f'tool --api-key "{VALUE}"',
        f"curl --db-password {VALUE}",
        f"run --client_secret\t'{VALUE}'",
        f"x --access-token {VALUE} --verbose",
    ],
)
def test_value_after_a_credential_named_option_is_redacted(text: str) -> None:
    for identifier in (False, True):
        assert VALUE not in redact_text(text, identifier=identifier)


@pytest.mark.parametrize(
    "text",
    [
        "run --max-tokens 4096",
        "--tokenizer bert-base",
        "x --password --verbose-mode",
        "a -- password value",
        "grep -password value",
        "the password is long",
        "ratio 3:=4 and a => b",
        "see key==value pairs",
    ],
)
def test_text_without_a_credential_assignment_is_unchanged(text: str) -> None:
    assert redact_text(text) == text


@pytest.mark.parametrize(
    "unit",
    [
        "password := x ",
        "token=abcpassword : x ",
        "--password x ",
        "secret=> ",
        "--api-key --api-key ",
    ],
)
def test_marks_chained_names_and_options_stay_linear(unit: str) -> None:
    assert scaling_ratio(lambda scale: redact_text(unit * (2000 * scale))) < 10
