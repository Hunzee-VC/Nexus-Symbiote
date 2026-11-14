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
# A backslash escapes the next character of a quoted value, as JSON reads it.
# Possessive and bounded quantifiers keep every attempt linear.
_CREDENTIAL_KEYWORD = (
    r"(?:api[-_]?key|access[-_]?key|secret[-_]?key|private[-_]?key|account[-_]?key"
    r"|[a-z0-9]{2,24}[-_]key"
    r"|token|password|passwd|passphrase|pwd|secret|credentials?|sig)"
    r"(?:\d{1,4})?(?:[-_.][a-z0-9]{1,32}){0,4}"
)
_ASSIGNMENT = re.compile(
    rf"(?i)({_CREDENTIAL_KEYWORD}[\"']?\s*+[:=]\s*+)"
    r"(\"(?:[^\"\\\n]|\\.){0,256}\"|'(?:[^'\\\n]|\\.){0,256}'|[^\s,;]++)"
)
# A mapping key that _ASSIGNMENT would read as the name in `name: value`.
_CREDENTIAL_KEY = re.compile(rf"(?i){_CREDENTIAL_KEYWORD}\Z")
_AUTHORIZATION_KEY = re.compile(r"(?i)(?:proxy-)?authorization")
_COOKIE_KEY = re.compile(r"(?i)(?:set-)?cookie")
_SCHEME_AND_VALUE = re.compile(r"([A-Za-z0-9-]{1,32})(\s++)(\S.*+)", re.DOTALL)
# A reference names where a credential comes from and holds none. Only the braced and
# the upper-case forms count: a password may itself begin with "$".
_REFERENCE = re.compile(r"\$\{[^{}\s]{1,128}\}|\$[A-Z][A-Z0-9_]{1,127}")
_AUTH = re.compile(r"(?i)\b(Bearer|Basic|Token|Bot|ApiKey|Api-Key)(\s++)([A-Za-z0-9_+/=.~-]{6,}+)")
# After an Authorization or Proxy-Authorization header name the scheme's value is a
# credential whatever its shape; the shape checks only tell prose from credentials.
# Searched in a bounded window before each scheme, so the cost per match is constant.
_AUTHORIZATION_HEADER = re.compile(r"(?i)authorization[\"']?\s{0,8}[:=]\s{0,8}[\"']?$")
_AUTHORIZATION_LOOKBACK = 40
# A prose word after a scheme ("Bearer authentication") is shorter than this; a value
# this long after Bearer, Token, Bot, ApiKey or Api-Key is redacted whatever its shape.
LONG_CREDENTIAL_LENGTH = 16
# Formats distinctive enough to stand out inside a name (AWS_AKIA..., X_glpat-...).
# Each stops at the end of its own run or matches the rest, so starting one after
# every "_" or "-" keeps the scan linear. An AWS key id must end there, or
# REGION_ASIAPACIFICSOUTHEAST1 would read as one. The AI-vendor prefixes also open
# ordinary names (pplx-7b-online, fw_config_loader), so each needs a body of at
# least 20 characters in the vendor's own alphabet.
_DISTINCT_SHAPES = (
    r"gh[oprsu]_[A-Za-z0-9]{36,}+|github_pat_\w{22,}+|glpat-[\w-]{20,}+"
    r"|xox[abeoprs]-[\w-]{10,}+|[rs]k_(?:live|test)_[A-Za-z0-9]{16,}+"
    r"|(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])|AIza[\w-]{35}|ya29\.[\w-]{20,}+"
    r"|npm_[A-Za-z0-9]{36}|pypi-[\w-]{50,}+|hf_[A-Za-z0-9]{30,}+"
    r"|SG\.[\w-]{16,}+\.[\w-]{16,}+|dckr_pat_[\w-]{20,}+|shp(?:at|ss|ca|pa)_[0-9a-fA-F]{32}"
    r"|SK[0-9a-f]{32}(?![A-Za-z0-9])|dapi[0-9a-f]{32}|xapp-[\w-]{20,}+"
    r"|PMAK-[0-9a-f]{24}-[0-9a-f]{34}|dp\.pt\.\w{40,}+"
    r"|pcsk_[A-Za-z0-9_]{20,}+|gsk_[A-Za-z0-9]{20,}+|r8_[A-Za-z0-9]{20,}+"
    r"|pplx-[A-Za-z0-9]{20,}+|xai-[A-Za-z0-9]{20,}+|lsv2_(?:pt|sk)_[A-Za-z0-9_]{20,}+"
    r"|tvly-[A-Za-z0-9-]{20,}+|fw_[A-Za-z0-9]{20,}+"
)
# A JWT can fail only at its first dot, so it starts only at a word boundary: started
# after every "_" its first segment would be rescanned once per position.
_JWT = r"eyJ[\w-]{8,}+\.[\w-]{8,}+(?:\.[\w-]++)?"
# Credential formats with a fixed prefix. sk- also names ordinary things
# (sk-learn-classifier), so it counts only at a word boundary.
TOKEN_SHAPE = re.compile(
    rf"(?<![\w-])(?:{_JWT}|sk-[\w-]{{20,}}+|(?:AKIA|ASIA)[A-Z0-9]{{16}})"
    rf"|(?<![A-Za-z0-9])(?:{_DISTINCT_SHAPES})"
)
# Names matched against other evidence keep sk-... forms; a distinct token is redacted.
_NAMED_TOKEN = re.compile(rf"(?<![\w-]){_JWT}|(?<![A-Za-z0-9])(?:{_DISTINCT_SHAPES})")
# A header value with no scheme is redacted when it looks like a credential; after
# Negotiate or NTLM, which the scheme rule above does not know, whatever its shape.
_RAW_AUTH_HEADER = re.compile(
    r"(?i)(\b(?:proxy-)?authorization[\"']?\s{0,8}[:=]\s{0,8}[\"']?)"
    r"(?:(negotiate|ntlm)([ \t]++)([A-Za-z0-9_+/=.~-]++)|([A-Za-z0-9_+/=.~:-]{8,}+))"
)
_AUTH_SCHEMES = frozenset(
    {
        "bearer",
        "basic",
        "token",
        "bot",
        "apikey",
        "api-key",
        "digest",
        "negotiate",
        "aws4-hmac-sha256",
    }
)
_COOKIE_HEADER = re.compile(r"(?i)(\b(?:set-)?cookie[\"']?\s{0,8}[:=]\s{0,8}[\"']?)([^\r\n\"']++)")
_COOKIE_PAIR = re.compile(r"([A-Za-z0-9_.-]{1,64}=)([^\s;,\"']++)")
_COOKIE_ATTRS = frozenset(
    {"path", "domain", "samesite", "max-age", "expires", "priority", "version"}
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
        # WHATWG parsers, as browsers use, end the host at a backslash; urlsplit does not.
        if not parts.scheme or not parts.hostname or "\\" in parts.netloc:
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
    start = match.start()
    header = _AUTHORIZATION_HEADER.search(
        match.string, max(0, start - _AUTHORIZATION_LOOKBACK), start
    )
    if header is not None or _credential_like(token, scheme):
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
            # The closing dashes may open the next BEGIN line.
            search = label_end
            continue
        end = value.find("-----END", label_end + 5)
        close = -1 if end < 0 else value.find("-----", end + 8)
        stop = len(value) if close < 0 else close + 5
        parts.extend((value[copied:start], REDACTED))
        copied = search = stop
    parts.append(value[copied:])
    return "".join(parts)


def _raw_auth_replacement(match: re.Match[str]) -> str:
    prefix, scheme, space, _credential, token = match.groups()
    if scheme is not None:
        return prefix + scheme + space + REDACTED
    if token.lower() in _AUTH_SCHEMES or not _credential_like(token, "token"):
        return match.group()
    return prefix + REDACTED


def _cookie_pair_replacement(match: re.Match[str]) -> str:
    name_eq, val = match.groups()
    if name_eq[:-1].lower() in _COOKIE_ATTRS:
        return match.group()
    if len(val) >= MIN_SECRET_LENGTH or _credential_like(val, "token"):
        return name_eq + REDACTED
    return match.group()


def _cookie_header_replacement(match: re.Match[str]) -> str:
    prefix, raw_cookies = match.groups()
    return prefix + _COOKIE_PAIR.sub(_cookie_pair_replacement, raw_cookies)


def redact_text(
    value: str,
    secrets: Iterable[str] | SecretScrubber = (),
    *,
    identifier: bool = False,
) -> str:
    """Remove known secret values and common URL/auth/assignment/token encodings.

    ``identifier`` keeps names that are matched against other evidence, such as tool
    names, free of the private key rule and of the token formats that ordinary names
    take: an innocuous name like ``sk-learn-classifier`` must keep matching the name a
    live server reports. A name holding a distinctive token such as ``ghp_...`` is
    still redacted.
    """
    value = _scrubber(secrets).scrub(value)
    value = _URL.sub(lambda match: redact_url(match.group()), value)
    if not identifier:
        value = _redact_private_keys(value)
    value = _ASSIGNMENT.sub(lambda match: match.group(1) + REDACTED, value)
    value = _AUTH.sub(_auth_replacement, value)
    if identifier:
        return _NAMED_TOKEN.sub(REDACTED, value)
    value = _RAW_AUTH_HEADER.sub(_raw_auth_replacement, value)
    value = _COOKIE_HEADER.sub(_cookie_header_replacement, value)
    return TOKEN_SHAPE.sub(REDACTED, value)


def redact_keyed_text(
    key: str,
    value: str,
    secrets: Iterable[str] | SecretScrubber = (),
    *,
    redacted: str | None = None,
) -> str:
    """Redact a mapping's text value as ``redact_text`` redacts ``key: value``.

    Parsed JSON or TOML hands a header or an assignment over as a key and a value, so
    the rules of ``redact_text`` that read both in one string never see them. The value
    of an ``Authorization`` or ``Proxy-Authorization`` key is a credential after any
    scheme word, the pairs of a ``Cookie`` or ``Set-Cookie`` key are cookies, and the
    value of a key that names a credential, such as ``password`` or ``X-Api-Key``, is
    one whatever its shape. A reference to a variable and a plain URL stay, as
    locators. ``redacted`` is the value as the caller already redacted it, when that
    is not ``redact_text(value, secrets)``.
    """
    safe = redact_text(value, secrets) if redacted is None else redacted
    if not value:
        return safe
    if _AUTHORIZATION_KEY.fullmatch(key):
        parts = _SCHEME_AND_VALUE.fullmatch(value)
        if parts is not None and parts.group(1).lower() in _AUTH_SCHEMES:
            scheme, space, credential = parts.groups()
            return safe if _REFERENCE.fullmatch(credential) else scheme + space + REDACTED
        return safe if _REFERENCE.fullmatch(value) else REDACTED
    if _COOKIE_KEY.fullmatch(key):
        return _COOKIE_PAIR.sub(_cookie_pair_replacement, safe)
    if _CREDENTIAL_KEY.search(key):
        return safe if _REFERENCE.fullmatch(value) or _PLAIN_URL.fullmatch(safe) else REDACTED
    return safe


def redact_metadata(value: Any, secrets: Iterable[str] | SecretScrubber = ()) -> Any:
    """Redact textual metadata while retaining its JSON structure."""
    return _redact_metadata(value, _scrubber(secrets))


def _redact_metadata(value: Any, scrubber: SecretScrubber) -> Any:
    if isinstance(value, str):
        return redact_text(value, scrubber)
    if isinstance(value, dict):
        return {
            redact_text(str(key), scrubber): (
                redact_keyed_text(str(key), item, scrubber)
                if isinstance(item, str)
                else _redact_metadata(item, scrubber)
            )
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
