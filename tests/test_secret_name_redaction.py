"""Free-text redaction must cover environment-style credential names."""

from __future__ import annotations

import time

import pytest

from nexus_symbiote.utils.secrets import REDACTED, redact_text

SECRET = "s3cr3tValue9"  # noqa: S105 - synthetic fixture


@pytest.mark.parametrize(
    "name",
    [
        "token",
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "x-api-key",
        "client_secret",
        "AWS_SECRET_ACCESS_KEY",
        "SECRET_KEY",
        "private_key",
        "DB_PASSWORD",
        "mytoken",
    ],
)
@pytest.mark.parametrize("operator", ["=", ": "])
def test_credential_assignment_value_is_redacted(name, operator):
    text = f"--env {name}{operator}{SECRET} --other"
    redacted = redact_text(text)
    assert SECRET not in redacted
    assert f"{name}{operator}{REDACTED}" in redacted


@pytest.mark.parametrize(
    "text", ["max_tokens=4096", "tokenizer=bert", "keyword=value", "monkey=banana", "mode=fast"]
)
def test_unrelated_assignments_are_unchanged(text):
    assert redact_text(text) == text


def test_long_adversarial_input_stays_fast():
    text = "token " * 100_000 + "a" * 1_000_000
    started = time.monotonic()
    redact_text(text)
    assert time.monotonic() - started < 5
