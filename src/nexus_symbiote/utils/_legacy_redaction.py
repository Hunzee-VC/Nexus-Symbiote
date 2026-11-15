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
Only the tracking around them is new: how each output character is traced to its source.
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
# The authority a URL's origin is taken from, as urlsplit delimits it.
_NETLOC = re.compile(r"[^/?#]*")
# What the known-value replay may copy of the text for values holding "*", in characters
# per character of the text, plus a constant: past it the replay is abandoned and the
# whole text counts as hidden. Each such value is replayed alone, rebuilding the text.
_STAR_REPLAY_FACTOR = 16
_STAR_REPLAY_BASE = 1024


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


def origin_sources(url: str, shown: str) -> list[int] | None:
    """For each character of ``shown``, the origin a URL rewrite gives ``url``, its index
    in ``url``; ``None`` when the two do not align.

    The origin repeats the URL's scheme, host and port, lower-cased and without a port's
    leading zeros, and leaves out the user info before the host. Every other character
    of the URL is removed by the rewrite, even where the origin still reads like it, and
    so is one the origin shows only lower-cased: ``shown_unchanged`` keeps the rest.
    """
    head = url.find("://") + 3
    if head < 3 or shown[:head] != url[:head].lower():
        return None
    netloc = _NETLOC.match(url, head)
    netloc_end = head if netloc is None else netloc.end()
    host_start = url.rfind("@", head, netloc_end) + 1 or head
    rest = shown[head:]
    width = rest.find("]") + 1 if rest.startswith("[") else len(rest.partition(":")[0])
    if width == 0 or host_start + width > netloc_end:
        return None
    if url[host_start : host_start + width].lower() != rest[:width]:
        return None
    sources = [*range(head), *range(host_start, host_start + width)]
    port = rest[width:]
    if port:
        colon = host_start + width
        written = url[colon + 1 : netloc_end]
        digits = port[1:]
        if url[colon : colon + 1] != ":" or not written.endswith(digits):
            return None
        if written[: len(written) - len(digits)].strip("0"):
            return None
        sources.append(colon)
        sources.extend(range(netloc_end - len(digits), netloc_end))
    return sources


def shown_unchanged(url: str, shown: str, sources: list[int]) -> list[int | None]:
    """For each character of ``shown``, its source in ``url`` if it shows that character as
    written, else ``None``: an upper-case letter shown lower-cased is not shown."""
    return [index if shown[offset] == url[index] else None for offset, index in enumerate(sources)]


def redaction(value: str, values: tuple[str, ...], *, identifier: bool = False) -> str:
    """Main's redaction of ``value`` with the known ``values``, longest first."""
    return _plain(value, values, identifier=identifier)


def _plain(value: str, values: tuple[str, ...], *, identifier: bool) -> str:
    """Main's redaction of ``value``, untracked."""
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

    def sub_urls(self) -> None:
        """Main's URL rewrite, each origin character traced to the URL character it shows."""
        edits = []
        for match in _URL.finditer(self.text):
            url = match.group()
            replacement = _redact_url(url)
            if replacement == url:
                continue
            start, end = match.span()
            sources = origin_sources(url, replacement)
            source = (
                self.kept(start, end, replacement)
                if sources is None
                else array(
                    "q",
                    [
                        -1 if index is None else self.source[start + index]
                        for index in shown_unchanged(url, replacement, sources)
                    ],
                )
            )
            edits.append((start, end, replacement, source))
        if edits:
            self.replace_spans(edits)

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

    ``values`` are the known values, longest first, which a caller passes only when one
    occurs in ``value``: main's known-value pass changes nothing otherwise. ``removed``
    are what the caller's own URL rewrites already take away, which main's took too. ``cookie`` adds
    main's reading of a ``Cookie`` key's value: every pair of the redacted text.
    """
    if not values:
        # Without a known value the rules alone decide whether main changed the text,
        # and they cost much less untracked; a known value main always replaces.
        plain = _plain(value, values, identifier=identifier)
        if cookie:
            plain = _COOKIE_PAIR.sub(_cookie_pair_replacement, plain)
        if plain == value:
            return []
    tracked = _run(value, values, identifier=identifier, cookie=cookie)
    if tracked is None:
        return [(0, len(value))] if value else []
    return _absent(value, tracked, removed)


def _stars(edits: list[Span]) -> list[tuple[int, int, str, array[int]]]:
    return [(start, end, _REDACTED, array("q", [-1, -1, -1])) for start, end in sorted(edits)]


def _replace_known(tracked: _Tracked, values: tuple[str, ...]) -> bool:
    """Main's known-value pass, ``text.replace(known, "***")`` for each value in turn.

    A value without "*" can only match text no earlier value replaced, as a replaced
    run reads as "*" to it, and it matches there as it would in main's text. So such
    values are found in a copy of the text where each replaced occurrence keeps its
    length, filled with a character no value holds, and all of them are applied in one
    rebuild. A value with "*" can match across a replaced run, so the text is rebuilt
    and the value replayed alone; each rebuild is charged to a budget of
    ``_STAR_REPLAY_FACTOR`` texts, and ``False`` is returned once it is spent. Such a
    value whose parts between its "*"s are not all in the text cannot occur in main's
    text either, as each part would lie in text no value replaced, so it costs nothing.
    """
    star = _REDACTED[0]
    held = set("".join(values))
    filler = next(chr(code) for code in range(len(held) + 1) if chr(code) not in held)
    budget = _STAR_REPLAY_FACTOR * len(tracked.text) + _STAR_REPLAY_BASE
    pending: list[Span] = []
    masked = tracked.text
    for known in values:
        if star not in known:
            if known not in masked:
                continue
            position = 0
            while (start := masked.find(known, position)) >= 0:
                position = start + len(known)
                pending.append((start, position))
            masked = masked.replace(known, filler * len(known))
            continue
        if not all(part in masked for part in known.split(star)):
            continue
        if pending:
            budget -= len(tracked.text)
            if budget < 0:
                return False
            tracked.replace_spans(_stars(pending))
            pending = []
            masked = tracked.text
        if known not in tracked.text:
            continue
        budget -= len(tracked.text)
        if budget < 0:
            return False
        edits = []
        position = 0
        while (start := tracked.text.find(known, position)) >= 0:
            position = start + len(known)
            edits.append((start, position))
        tracked.replace_spans(_stars(edits))
        masked = tracked.text
    if pending:
        tracked.replace_spans(_stars(pending))
    return True


def _run(
    value: str, values: tuple[str, ...], *, identifier: bool, cookie: bool = False
) -> _Tracked | None:
    """Main's rules, tracked; ``None`` when the known-value replay is beyond its bound."""
    tracked = _Tracked(value)
    if not _replace_known(tracked, values):
        return None
    tracked.sub_urls()
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
) -> str | None:
    """Main's output for ``value``, from the tracked run: for tests of the tracking."""
    tracked = _run(value, values, identifier=identifier, cookie=cookie)
    return None if tracked is None else tracked.text


def _absent(value: str, tracked: _Tracked, removed: Iterable[Span]) -> list[Span]:
    present = bytearray(len(value))
    for index in tracked.source:
        if index >= 0:
            present[index] = 1
    for start, end in removed:
        present[start:end] = b"\x01" * (end - start)
    return [match.span() for match in re.finditer(rb"\x00+", present)]
