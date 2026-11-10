"""Free-text redaction must cover credential names, schemes and token formats."""

from __future__ import annotations

import time

import pytest

from nexus_symbiote.utils.secrets import (
    REDACTED,
    SecretScrubber,
    redact_descriptor,
    redact_metadata,
    redact_text,
    secret_like,
)

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


# Spelled in parts so the source never holds a token-shaped literal, which secret scanners
# rightly refuse; the value is the public example token from Discord's documentation.
DISCORD_SHAPED_TOKEN = ".".join(
    ("MTk4NjIyNDgzNDcxOTI1MjQ4", "Cl2FMQ", "ZnCjm1XVW7vRze4b7Cq4se7kKWs")
)


@pytest.mark.parametrize(
    "text,kept",
    [
        ("Authorization: Bearer abc.DEF-123", "Authorization: Bearer"),
        ("authorization: bearer eyJhbGciOi.payload_x", "authorization: bearer"),
        ("basic dXNlcjpwYXNz", "basic"),
        ("Basic dXNlcjpwYXNzd29yZA==", "Basic"),
        ("Authorization: token ghp_0123456789abcdefABCDEF0123456789abcd", "Authorization: token"),
        (f"Bot {DISCORD_SHAPED_TOKEN}", "Bot"),
    ],
)
def test_authorization_scheme_credentials_are_redacted(text, kept):
    credential = text.split()[-1]
    redacted = redact_text(text)
    assert credential not in redacted
    assert redacted == f"{kept} {REDACTED}"


@pytest.mark.parametrize(
    "text",
    [
        "Provides basic arithmetic",
        "Basic Auth is supported",
        "Uses a Bearer token for auth",
        "Bearer authentication",
        "a token for the session",
    ],
)
def test_authorization_scheme_words_in_prose_survive(text):
    assert redact_text(text) == text


@pytest.mark.parametrize(
    "name",
    [
        "DB_PASSWORD_PROD",
        "SECRET_KEY_BASE",
        "API_KEY_OPENAI",
        "AWS_ACCESS_KEY_ID",
        "token2",
        "AccountKey",
        "Pwd",
        "client_credentials",
        "x_sig",
        '"password"',
    ],
)
def test_credential_names_with_suffixes_and_quotes_are_redacted(name):
    text = f"{name}={SECRET} rest" if not name.startswith('"') else f'{name}: "{SECRET}" rest'
    redacted = redact_text(text)
    assert SECRET not in redacted and redacted.endswith(" rest")


def test_quoted_value_is_redacted_whole():
    assert redact_text('password="two words" next') == f"password={REDACTED} next"


@pytest.mark.parametrize(
    "token",
    [
        "ghp_" + "a1" * 18,
        "github_pat_" + "B2" * 20,
        "glpat-" + "c3" * 10,
        "xoxb-" + "1234567890-abcdef",
        "sk-proj-" + "d4" * 12,
        "sk_live_" + "e5" * 10,
        "AKIA" + "ABCDEFGHIJKLMNOP",
        "AIza" + "f6" * 17 + "g",
        "npm_" + "h7" * 18,
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl",
    ],
)
def test_known_token_formats_in_free_text_are_redacted(token):
    redacted = redact_text(f"example call with {token} inside")
    assert token not in redacted and redacted == f"example call with {REDACTED} inside"


def test_private_key_blocks_are_redacted_and_certificates_kept():
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----"
    assert redact_text(f"key: {key} done") == f"key: {REDACTED} done"
    assert redact_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE truncated") == REDACTED
    certificate = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    assert redact_text(certificate) == certificate


def test_identifiers_keep_names_that_resemble_token_formats():
    name = "sk-learn-classifier-tool-v2"
    assert redact_text(name, identifier=True) == name
    descriptor = redact_descriptor({"name": name, "description": f"Runs {name}"})
    assert descriptor["name"] == name and descriptor["description"] == f"Runs {REDACTED}"


@pytest.mark.parametrize(
    "name,value,expected",
    [
        ("DEBUG", "1", False),
        ("LANG", "en", False),
        ("PORT", "8443", False),
        ("NODE_ENV", "production", False),
        ("MCP_HOST", "mcp.vendor.example", False),
        ("AUTH_ISSUER", "https://auth.example.test", False),
        ("API_TOKEN", "short", False),
        ("API_TOKEN", "mcp.vendor.example", True),
        ("GITHUB_PAT", "0123456789", True),
        ("UNRELATED", "ghp_" + "a" * 36, True),
        ("DATABASE_URL", "postgres://user:pw@db.example/app", True),
    ],
)
def test_secret_like_values_need_a_credential_name_or_shape(name, value, expected):
    assert secret_like(name, value) is expected


def test_scrubber_replaces_longest_values_first_and_skips_short_texts():
    scrubber = SecretScrubber(["abcdefgh", "abcdefgh-ijkl", ""])
    assert scrubber.scrub("x abcdefgh-ijkl y abcdefgh") == f"x {REDACTED} y {REDACTED}"
    assert scrubber.contains("..abcdefgh..") and not scrubber.contains("abc")
    assert scrubber.scrub("short") == "short"
    assert not SecretScrubber() and SecretScrubber().scrub("anything") == "anything"


@pytest.mark.parametrize(
    "text",
    [
        "eyJ" * 400_000,
        "-----BEGIN" * 200_000,
        "Bearer " * 300_000,
        "password=" * 300_000,
        "DB_PASSWORD" + "_X" * 400_000,
        "ghp_" * 300_000,
    ],
)
def test_new_patterns_stay_linear_on_adversarial_input(text):
    started = time.monotonic()
    redact_text(text)
    assert time.monotonic() - started < 5


def test_prepared_scrubber_is_linear_in_values_and_strings():
    scrubber = SecretScrubber(f"credential-{i:05d}" for i in range(256))
    metadata = {"examples": [f"value {i} credential-00007" for i in range(20_000)]}
    started = time.monotonic()
    redacted = redact_metadata(metadata, scrubber)
    assert time.monotonic() - started < 10
    assert "credential-00007" not in str(redacted)


@pytest.mark.parametrize(
    "text,kept",
    [
        ("Authorization: Bearer abcdefghijklmnopqrstuv", "Authorization: Bearer"),
        ("Token ABCDEFGHIJKLMNOPQRST", "Token"),
        ("ApiKey qwertyuiopasdfghjk", "ApiKey"),
        ("Bearer abc123", "Bearer"),
        ("Bot aBcDeFgH", "Bot"),
    ],
)
def test_long_or_shaped_scheme_values_are_redacted_whatever_their_letters(text, kept):
    assert redact_text(text) == f"{kept} {REDACTED}"


@pytest.mark.parametrize(
    "text", ["Send a Bearer Tokens header", "Token Validation failed", "Bearer scheme"]
)
def test_capitalised_prose_after_a_scheme_word_survives(text):
    assert redact_text(text) == text
