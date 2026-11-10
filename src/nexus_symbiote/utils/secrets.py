"""Conservative redaction for collector output, never credential retrieval."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

REDACTED = "***"
# Shorter environment values are flags such as "1", "en" or "info", not credentials;
# scrubbing them out of free text would corrupt ordinary names and descriptions.
MIN_SECRET_LENGTH = 8
_URL = re.compile(r"(?<![a-zA-Z0-9+.-])[a-zA-Z0-9+.-]+://[^\s\"'<>]+")
# No leading word boundary: "_" is a word character, so a boundary would skip
# GITHUB_TOKEN= and client_secret=. Delimited suffixes (DB_PASSWORD_PROD=) and
# digits (token2=) may follow the keyword; "max_tokens" and "tokenizer" may not.
# Possessive and bounded quantifiers keep every attempt linear.
_ASSIGNMENT = re.compile(
    r"(?i)((?:api[-_]?key|access[-_]?key|secret[-_]?key|private[-_]?key|account[-_]?key"
    r"|token|password|passwd|passphrase|pwd|secret|credentials?|sig)"
    r"(?:\d{1,4})?(?:[-_.][a-z0-9]{1,32}){0,4}[\"']?\s*+[:=]\s*+)"
    r"(\"[^\"\n]{0,256}\"|'[^'\n]{0,256}'|[^\s,;]++)"
)
_AUTH = re.compile(r"(?i)\b(Bearer|Basic|Token|Bot|ApiKey|Api-Key)(\s++)([A-Za-z0-9_+/=.~-]{6,}+)")
# A prose word after a scheme ("Bearer authentication") is shorter than this; a value
# this long after Bearer, Token, Bot or ApiKey is redacted whatever its shape.
LONG_CREDENTIAL_LENGTH = 16
# Credential formats with a fixed prefix. The leading lookbehind starts a match
# only at a word boundary, so a long run is scanned once, not once per position.
TOKEN_SHAPE = re.compile(
    r"(?<![\w-])(?:eyJ[\w-]{8,}+\.[\w-]{8,}+(?:\.[\w-]++)?"
    r"|gh[oprsu]_[A-Za-z0-9]{36,}+|github_pat_\w{22,}+|glpat-[\w-]{20,}+"
    r"|xox[abeoprs]-[\w-]{10,}+|sk-[\w-]{20,}+|[rs]k_(?:live|test)_[A-Za-z0-9]{16,}+"
    r"|(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[\w-]{35}|ya29\.[\w-]{20,}+|npm_[A-Za-z0-9]{36}"
    r"|pypi-[\w-]{50,}+)"
)
_CREDENTIAL_NAME = re.compile(
    r"(?i)key|token|secret|pass|pwd|credential|auth|cookie|session|private|signature|cert"
    r"|dsn|connection_?str|conn_?str|jwt|bearer|header|(?:^|_)pat(?:_|$)"
)
_URL_USERINFO = re.compile(r"://[^/\s@?#]*@")
_PLAIN_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s@?#]+")


def redact_url(value: str) -> str:
    """Keep URL origin only; paths, userinfo, queries and fragments may hold secrets.

    These are locators with credentials omitted, not round-trippable connection
    strings. No URL is fetched or resolved by this helper.
    """
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.hostname:
            return "[redacted-url]"
        host = parts.hostname
        if ":" in host:
            host = f"[{host}]"
        if parts.port is not None:
            host = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme, host, "", "", ""))
    except ValueError:
        return "[redacted-url]"


def secret_like(name: str, value: str) -> bool:
    """Whether a variable's value must be kept out of free text and identity fields.

    The variable name marks a credential (KEY, TOKEN, SECRET, PASS, AUTH, ...), or
    the value has a known token format or carries URL user information. Values
    shorter than MIN_SECRET_LENGTH never qualify, and a plain URL without user
    information, query or fragment is a locator, not a secret.
    """
    if len(value) < MIN_SECRET_LENGTH:
        return False
    if TOKEN_SHAPE.search(value) or _URL_USERINFO.search(value):
        return True
    if _PLAIN_URL.fullmatch(value):
        return False
    return bool(_CREDENTIAL_NAME.search(name))


def secret_values(variables: Mapping[str, Any]) -> list[str]:
    """The string values of ``variables`` that ``secret_like`` selects."""
    return [
        value
        for name, value in variables.items()
        if isinstance(name, str) and isinstance(value, str) and secret_like(name, value)
    ]


class SecretScrubber:
    """Known secret values, prepared once per source and applied linearly per text.

    Each value is located with one substring search, longest first, so scrubbing a
    text costs its length times the number of values, never values times every
    string of a document. Texts shorter than the shortest value are skipped.
    """

    __slots__ = ("_shortest", "_values")

    def __init__(self, values: Iterable[str] = ()) -> None:
        unique = {value for value in values if value}
        self._values = tuple(sorted(unique, key=lambda value: (-len(value), value)))
        self._shortest = min((len(value) for value in self._values), default=0)

    def __bool__(self) -> bool:
        return bool(self._values)

    def contains(self, text: str) -> bool:
        if not self._values or len(text) < self._shortest:
            return False
        return any(value in text for value in self._values)

    def scrub(self, text: str) -> str:
        if not self._values or len(text) < self._shortest:
            return text
        for value in self._values:
            if value in text:
                text = text.replace(value, REDACTED)
        return text


def _scrubber(secrets: Iterable[str] | SecretScrubber) -> SecretScrubber:
    return secrets if isinstance(secrets, SecretScrubber) else SecretScrubber(secrets)


def _credential_like(token: str, scheme: str) -> bool:
    if scheme.lower() == "basic":
        # Basic credentials are base64 of "user:password"; prose such as
        # "basic arithmetic" does not decode to a pair.
        padded = token + "=" * (-len(token) % 4)
        try:
            return b":" in base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            return False
    return (
        len(token) >= LONG_CREDENTIAL_LENGTH
        or any(char.isdigit() for char in token)
        or (any(char.isupper() for char in token[1:]) and any(char.islower() for char in token))
        or any(char in "._~+/=-" for char in token)
    )


def _auth_replacement(match: re.Match[str]) -> str:
    scheme, space, token = match.groups()
    if _credential_like(token, scheme):
        return scheme + space + REDACTED
    return match.group()


def _redact_private_keys(value: str) -> str:
    """Replace PEM private key blocks, including unterminated ones, in one pass."""
    if "-----BEGIN" not in value:
        return value
    parts: list[str] = []
    copied = search = 0
    while (start := value.find("-----BEGIN", search)) >= 0:
        label_end = value.find("-----", start + 10)
        if label_end < 0:
            break
        if "PRIVATE KEY" not in value[start + 10 : label_end]:
            search = label_end + 5
            continue
        end = value.find("-----END", label_end + 5)
        close = -1 if end < 0 else value.find("-----", end + 8)
        stop = len(value) if close < 0 else close + 5
        parts.extend((value[copied:start], REDACTED))
        copied = search = stop
    parts.append(value[copied:])
    return "".join(parts)


def redact_text(
    value: str,
    secrets: Iterable[str] | SecretScrubber = (),
    *,
    identifier: bool = False,
) -> str:
    """Remove known secret values and common URL/auth/assignment/token encodings.

    ``identifier`` keeps names that are matched against other evidence, such as tool
    names, free of the token-format and private key rules: an innocuous name like
    ``sk-learn-classifier`` must keep matching the name a live server reports.
    """
    value = _scrubber(secrets).scrub(value)
    value = _URL.sub(lambda match: redact_url(match.group()), value)
    if not identifier:
        value = _redact_private_keys(value)
    value = _ASSIGNMENT.sub(lambda match: match.group(1) + REDACTED, value)
    value = _AUTH.sub(_auth_replacement, value)
    if not identifier:
        value = TOKEN_SHAPE.sub(REDACTED, value)
    return value


def redact_metadata(value: Any, secrets: Iterable[str] | SecretScrubber = ()) -> Any:
    """Redact textual metadata while retaining its JSON structure."""
    return _redact_metadata(value, _scrubber(secrets))


def _redact_metadata(value: Any, scrubber: SecretScrubber) -> Any:
    if isinstance(value, str):
        return redact_text(value, scrubber)
    if isinstance(value, dict):
        return {
            redact_text(str(key), scrubber): _redact_metadata(item, scrubber)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_metadata(item, scrubber) for item in value]
    return value


_SCHEMA_LITERALS = frozenset({"default", "const", "enum", "example", "examples"})
_SCHEMA_MAPS = frozenset(
    {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas", "dependencies"}
)


def _schema_projection(value: Any, *, named_schemas: bool = False) -> Any:
    """Drop embedded instance data. Property and definition names are not keywords."""
    if isinstance(value, list):
        return [_schema_projection(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _schema_projection(item, named_schemas=not named_schemas and key in _SCHEMA_MAPS)
            for key, item in value.items()
            if named_schemas or key not in _SCHEMA_LITERALS
        }
    return value


def redact_descriptor(
    descriptor: dict[str, Any], secrets: Iterable[str] | SecretScrubber = ()
) -> dict[str, Any]:
    """Project an MCP descriptor for display; its original digest binds omitted literals.

    The tool name is an identifier compared with live observations, so only the
    identifier rules of ``redact_text`` apply to it.
    """
    scrubber = _scrubber(secrets)
    safe = {}
    for key, value in descriptor.items():
        if key in {"inputSchema", "outputSchema"}:
            value = _schema_projection(value)
        elif key not in {"name", "title", "description", "annotations", "_meta"}:
            key = redact_text(key, scrubber)
        if key == "name" and isinstance(value, str):
            safe[key] = redact_text(value, scrubber, identifier=True)
        else:
            safe[key] = _redact_metadata(value, scrubber)
    return safe
