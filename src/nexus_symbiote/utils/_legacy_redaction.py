"""The redaction rules of release 0.x before the union engine, as a floor under it.

``secrets.redact_text`` matches every rule in the original text and replaces each union
of matches at once. That finds what rule-after-rule redaction missed, but it reads some
texts differently: one rule's match can take the name another rule needed. Main applied
its rules one after another, each on the previous one's output, and hid values the
union engine shows. ``hidden_spans`` runs those rules, unchanged, with the position of
every character tracked through each substitution, and returns the characters of the
original text they removed. The union engine hides those too, so it never shows what
the earlier rules hid.

The constants and replacements below are copied from ``secrets.py`` as it stood before
the union engine, and must not be changed to follow it: this module is the reference.
"""

from __future__ import annotations

import base64
import binascii
import re
from array import array
from collections.abc import Callable, Iterable
from urllib.parse import urlsplit, urlunsplit

_REDACTED = "***"
_MIN_SECRET_LENGTH = 8
_URL = re.compile(r"(?<![a-zA-Z0-9+.-])[a-zA-Z0-9+.-]+://[^\s\"'<>]+")
_CREDENTIAL_KEYWORD = (
    r"(?:api[-_]?key|access[-_]?key|secret[-_]?key|private[-_]?key|account[-_]?key"
    r"|token|password|passwd|passphrase|pwd|secret|credentials?|sig)"
    r"(?:\d{1,4})?(?:[-_.][a-z0-9]{1,32}){0,4}"
)
_ASSIGNMENT = re.compile(
    rf"(?i)({_CREDENTIAL_KEYWORD}[\"']?\s*+[:=]\s*+)"
    r"(\"(?:[^\"\\\n]|\\.){0,256}\"|'(?:[^'\\\n]|\\.){0,256}'|[^\s,;]++)"
)
_AUTH = re.compile(r"(?i)\b(Bearer|Basic|Token|Bot|ApiKey|Api-Key)(\s++)([A-Za-z0-9_+/=.~-]{6,}+)")
_AUTHORIZATION_HEADER = re.compile(r"(?i)authorization[\"']?\s{0,8}[:=]\s{0,8}[\"']?$")
_AUTHORIZATION_LOOKBACK = 40
_LONG_CREDENTIAL_LENGTH = 16
_DISTINCT_SHAPES = (
    r"gh[oprsu]_[A-Za-z0-9]{36,}+|github_pat_\w{22,}+|glpat-[\w-]{20,}+"
    r"|xox[abeoprs]-[\w-]{10,}+|[rs]k_(?:live|test)_[A-Za-z0-9]{16,}+"
    r"|(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])|AIza[\w-]{35}|ya29\.[\w-]{20,}+"
    r"|npm_[A-Za-z0-9]{36}|pypi-[\w-]{50,}+|hf_[A-Za-z0-9]{30,}+"
    r"|pcsk_[A-Za-z0-9_]{20,}+|gsk_[A-Za-z0-9]{20,}+|r8_[A-Za-z0-9]{20,}+"
    r"|pplx-[A-Za-z0-9]{20,}+|xai-[A-Za-z0-9]{20,}+|lsv2_(?:pt|sk)_[A-Za-z0-9_]{20,}+"
    r"|tvly-[A-Za-z0-9-]{20,}+|fw_[A-Za-z0-9]{20,}+"
)
_JWT = r"eyJ[\w-]{8,}+\.[\w-]{8,}+(?:\.[\w-]++)?"
_TOKEN_SHAPE = re.compile(
    rf"(?<![\w-])(?:{_JWT}|sk-[\w-]{{20,}}+|(?:AKIA|ASIA)[A-Z0-9]{{16}})"
    rf"|(?<![A-Za-z0-9])(?:{_DISTINCT_SHAPES})"
)
_NAMED_TOKEN = re.compile(rf"(?<![\w-]){_JWT}|(?<![A-Za-z0-9])(?:{_DISTINCT_SHAPES})")
_RAW_AUTH_HEADER = re.compile(
    r"(?i)(\b(?:proxy-)?authorization[\"']?\s{0,8}[:=]\s{0,8}[\"']?)"
    r"(?:(negotiate|ntlm)([ \t]++)([A-Za-z0-9_+/=.~-]++)|([A-Za-z0-9_+/=.~:-]{8,}+))"
)
_AUTH_SCHEMES = frozenset(
    {"bearer", "basic", "token", "bot", "apikey", "api-key", "digest", "negotiate"}
    | {"aws4-hmac-sha256"}
)
_COOKIE_HEADER = re.compile(r"(?i)(\b(?:set-)?cookie[\"']?\s{0,8}[:=]\s{0,8}[\"']?)([^\r\n\"']++)")
_COOKIE_PAIR = re.compile(r"([A-Za-z0-9_.-]{1,64}=)([^\s;,\"']++)")
_COOKIE_ATTRS = frozenset(
    {"path", "domain", "samesite", "max-age", "expires", "priority", "version"}
)

Span = tuple[int, int]


def _redact_url(value: str) -> str:
    try:
        parts = urlsplit(value)
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


def _credential_like(token: str, scheme: str) -> bool:
    if scheme.lower() == "basic":
        padded = token + "=" * (-len(token) % 4)
        try:
            return b":" in base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            return False
    return (
        len(token) >= _LONG_CREDENTIAL_LENGTH
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
        return scheme + space + _REDACTED
    return match.group()


def _raw_auth_replacement(match: re.Match[str]) -> str:
    prefix, scheme, space, _credential, token = match.groups()
    if scheme is not None:
        return prefix + scheme + space + _REDACTED
    if token.lower() in _AUTH_SCHEMES or not _credential_like(token, "token"):
        return match.group()
    return prefix + _REDACTED


def _cookie_pair_replacement(match: re.Match[str]) -> str:
    name_eq, val = match.groups()
    if name_eq[:-1].lower() in _COOKIE_ATTRS:
        return match.group()
    if len(val) >= _MIN_SECRET_LENGTH or _credential_like(val, "token"):
        return name_eq + _REDACTED
    return match.group()


def _cookie_header_replacement(match: re.Match[str]) -> str:
    prefix, raw_cookies = match.groups()
    return prefix + _COOKIE_PAIR.sub(_cookie_pair_replacement, raw_cookies)


def _private_key_blocks(value: str) -> list[Span]:
    blocks: list[Span] = []
    if "-----BEGIN" not in value:
        return blocks
    search = 0
    while (start := value.find("-----BEGIN", search)) >= 0:
        label_end = value.find("-----", start + 10)
        if label_end < 0:
            break
        if "PRIVATE KEY" not in value[start + 10 : label_end]:
            search = label_end
            continue
        end = value.find("-----END", label_end + 5)
        close = -1 if end < 0 else value.find("-----", end + 8)
        stop = len(value) if close < 0 else close + 5
        blocks.append((start, stop))
        search = stop
    return blocks


def _plain(value: str, values: tuple[str, ...], *, identifier: bool) -> str:
    """Main's redaction of ``value``, untracked: only to tell whether it changes anything."""
    for known in values:
        if known in value:
            value = value.replace(known, _REDACTED)
    value = _URL.sub(lambda match: _redact_url(match.group()), value)
    if not identifier:
        parts: list[str] = []
        copied = 0
        for start, stop in _private_key_blocks(value):
            parts.extend((value[copied:start], _REDACTED))
            copied = stop
        parts.append(value[copied:])
        value = "".join(parts)
    value = _ASSIGNMENT.sub(lambda match: match.group(1) + _REDACTED, value)
    value = _AUTH.sub(_auth_replacement, value)
    if identifier:
        return _NAMED_TOKEN.sub(_REDACTED, value)
    value = _RAW_AUTH_HEADER.sub(_raw_auth_replacement, value)
    value = _COOKIE_HEADER.sub(_cookie_header_replacement, value)
    return _TOKEN_SHAPE.sub(_REDACTED, value)


class _Tracked:
    """A text and, for each of its characters, the original index it came from or -1."""

    __slots__ = ("source", "text")

    def __init__(self, text: str) -> None:
        self.text = text
        self.source = array("q", range(len(text)))

    def replace_spans(self, edits: Iterable[tuple[int, int, str, array[int]]]) -> None:
        """Apply sorted, disjoint ``(start, end, replacement, replacement_source)`` edits."""
        parts: list[str] = []
        source = array("q")
        copied = 0
        for start, end, replacement, replacement_source in edits:
            parts.append(self.text[copied:start])
            source.extend(self.source[copied:start])
            parts.append(replacement)
            source.extend(replacement_source)
            copied = end
        parts.append(self.text[copied:])
        source.extend(self.source[copied:])
        self.text = "".join(parts)
        self.source = source

    def kept(self, start: int, end: int, replacement: str) -> array[int]:
        """The source of ``replacement`` for ``text[start:end]``: what it keeps of either end.

        Every replacement here keeps a leading part (a name, a scheme, an origin) and
        replaces what follows, so the common prefix keeps its sources, and so does a
        common suffix; what lies between is synthetic.
        """
        original = self.text[start:end]
        limit = min(len(original), len(replacement))
        prefix = 0
        while prefix < limit and original[prefix] == replacement[prefix]:
            prefix += 1
        suffix = 0
        while (
            suffix < limit - prefix
            and original[len(original) - 1 - suffix] == replacement[len(replacement) - 1 - suffix]
        ):
            suffix += 1
        middle = len(replacement) - prefix - suffix
        result = array("q", self.source[start : start + prefix])
        result.extend(array("q", [-1]) * middle)
        result.extend(self.source[end - suffix : end])
        return result

    def sub(self, pattern: re.Pattern[str], replace: Callable[[re.Match[str]], str]) -> None:
        edits = []
        for match in pattern.finditer(self.text):
            replacement = replace(match)
            if replacement != match.group():
                start, end = match.span()
                edits.append((start, end, replacement, self.kept(start, end, replacement)))
        if edits:
            self.replace_spans(edits)


def _cookie_headers(tracked: _Tracked) -> None:
    """Main's cookie rule, tracked pair by pair, so the text between pairs keeps its source."""
    edits = []
    for header in _COOKIE_HEADER.finditer(tracked.text):
        base = header.start(2)
        cookies = header.group(2)
        for pair in _COOKIE_PAIR.finditer(cookies):
            replacement = _cookie_pair_replacement(pair)
            if replacement != pair.group():
                start, end = base + pair.start(), base + pair.end()
                edits.append((start, end, replacement, tracked.kept(start, end, replacement)))
    if edits:
        tracked.replace_spans(edits)


def hidden_spans(
    value: str,
    values: tuple[str, ...],
    *,
    identifier: bool,
    removed: Iterable[Span],
    cookie: bool = False,
) -> list[Span]:
    """Spans of ``value`` that main's rules hid, apart from the ``removed`` ones.

    ``values`` are the known values, longest first; ``removed`` are what the caller's
    own URL rewrites already take away, which main's rewrites took too. ``cookie`` adds
    main's reading of a ``Cookie`` key's value: every pair of the redacted text.
    """
    plain = _plain(value, values, identifier=identifier)
    if cookie:
        plain = _COOKIE_PAIR.sub(_cookie_pair_replacement, plain)
    if plain == value:
        return []
    return _absent(value, _run(value, values, identifier=identifier, cookie=cookie), removed)


def _run(
    value: str, values: tuple[str, ...], *, identifier: bool, cookie: bool = False
) -> _Tracked:
    tracked = _Tracked(value)
    for known in values:
        if known not in tracked.text:
            continue
        edits = []
        position = 0
        while (start := tracked.text.find(known, position)) >= 0:
            end = start + len(known)
            edits.append((start, end, _REDACTED, array("q", [-1, -1, -1])))
            position = end
        tracked.replace_spans(edits)
    tracked.sub(_URL, lambda match: _redact_url(match.group()))
    if not identifier:
        tracked.replace_spans(
            (start, stop, _REDACTED, array("q", [-1, -1, -1]))
            for start, stop in _private_key_blocks(tracked.text)
        )
    tracked.sub(_ASSIGNMENT, lambda match: match.group(1) + _REDACTED)
    tracked.sub(_AUTH, _auth_replacement)
    if identifier:
        tracked.sub(_NAMED_TOKEN, lambda _match: _REDACTED)
    else:
        tracked.sub(_RAW_AUTH_HEADER, _raw_auth_replacement)
        _cookie_headers(tracked)
        tracked.sub(_TOKEN_SHAPE, lambda _match: _REDACTED)
    if cookie:
        tracked.sub(_COOKIE_PAIR, _cookie_pair_replacement)
    return tracked


def tracked_redaction(
    value: str, values: tuple[str, ...], *, identifier: bool, cookie: bool = False
) -> str:
    """Main's output for ``value``, from the tracked run: for tests of the tracking."""
    return _run(value, values, identifier=identifier, cookie=cookie).text


def _absent(value: str, tracked: _Tracked, removed: Iterable[Span]) -> list[Span]:
    present = bytearray(len(value))
    for index in tracked.source:
        if index >= 0:
            present[index] = 1
    for start, end in removed:
        present[start:end] = b"\x01" * (end - start)
    return [match.span() for match in re.finditer(rb"\x00+", present)]
