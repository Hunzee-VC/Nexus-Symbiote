"""Conservative redaction for collector output, never credential retrieval."""

from __future__ import annotations

import base64
import binascii
import bisect
import heapq
import re
from collections.abc import Iterable, Iterator, Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

REDACTED = "***"
# What a known value reads as to the rules on the masked pass: a separator, as its
# redaction was, that no token, scheme value or header value contains.
_MASK = REDACTED[0]
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
    r"|pcsk_[A-Za-z0-9_]{20,}+|gsk_[A-Za-z0-9]{20,}+|r8_[A-Za-z0-9]{20,}+"
    r"|pplx-[A-Za-z0-9]{20,}+|xai-[A-Za-z0-9]{20,}+|lsv2_(?:pt|sk)_[A-Za-z0-9_]{20,}+"
    r"|tvly-[A-Za-z0-9-]{20,}+|fw_[A-Za-z0-9]{20,}+"
    r"|SG\.[\w-]{16,}+\.[\w-]{16,}+|dckr_pat_[\w-]{20,}+|shp(?:at|ss|ca)_[0-9a-fA-F]{32}"
    r"|SK[0-9a-f]{32}(?![A-Za-z0-9])"
    r"|shppa_[0-9a-fA-F]{32}|dapi[0-9a-f]{32}|xapp-[\w-]{20,}+|PMAK-[0-9a-f]{24}-[0-9a-f]{34}"
    # A Doppler service token may name its config first: dp.st.<config>.<token>.
    r"|dp\.(?:pt|ct|sa|scim|audit|st(?:\.[a-z0-9_-]{2,35}+)?)\.[A-Za-z0-9]{40,}+"
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
# The authority a URL's shown origin is taken from, as urlsplit delimits it.
_NETLOC = re.compile(r"[^/?#]*")


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


def _longest_first(value: str) -> tuple[int, str]:
    return (-len(value), value)


def _smallest_period(value: str) -> int:
    """The smallest shift at which ``value`` overlaps itself, its length when none does."""
    border = 0
    borders = [0] * len(value)
    for index in range(1, len(value)):
        while border and value[index] != value[border]:
            border = borders[border - 1]
        if value[index] == value[border]:
            border += 1
        borders[index] = border
    return len(value) - (borders[-1] if value else 0)


Span = tuple[int, int]


def _periodic_end(text: str, end: int, period: int) -> int:
    """Extend ``end`` while ``text`` repeats itself ``period`` characters back.

    Galloping, then halving, compares slices in C, so a run costs its length and only
    the logarithm of it in interpreted steps. Steps are powers of two, so halving the
    first one that fails tries every length below it.
    """
    step = 1
    while text.startswith(text[end - period : end - period + step], end):
        end += step
        step *= 2
    while step > 1:
        step //= 2
        if text.startswith(text[end - period : end - period + step], end):
            end += step
    return end


_COVERED = re.compile(rb"\x01+")


class SecretScrubber:
    """Known secret values, prepared once per source and applied linearly per text.

    Every occurrence of every value is located in the original text, overlapping ones
    included, so one value can never hide part of another. Each value costs a search
    of the text in C. Values go longest first and mark what they cover: a run of a
    value overlapping itself is measured along its smallest period, an occurrence
    wholly inside covered text is passed over to the next uncovered character, and
    every occurrence found otherwise covers a new one, so the interpreted steps grow
    with the text, not with the number of values times their occurrences. Values
    that are parts of one another, repeated between uncovered gaps, could still make
    each value pass over every repetition; past ``len(text) // 8`` passes and a few
    per value, the cover is every value's greedy replacement widened by the longest
    value on each side, which holds every overlapping occurrence. Texts shorter than
    the shortest value are skipped.
    """

    __slots__ = ("_periods", "_shortest", "_values")

    def __init__(self, values: Iterable[str] = ()) -> None:
        unique = {value for value in values if value}
        self._values = tuple(sorted(unique, key=_longest_first))
        self._periods = {value: _smallest_period(value) for value in self._values}
        self._shortest = len(self._values[-1]) if self._values else 0

    def __bool__(self) -> bool:
        return bool(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def extended(self, values: Iterable[str]) -> SecretScrubber:
        """This scrubber with ``values`` added, merged without sorting its own again.

        A file's values are prepared once and each server adds its own few, so the
        cost per server grows with the file's values, not with their sort.
        """
        known = self._periods
        extra = sorted(
            {value for value in values if value and value not in known}, key=_longest_first
        )
        if not extra:
            return self
        merged = SecretScrubber()
        merged._values = tuple(heapq.merge(self._values, extra, key=_longest_first))
        merged._periods = {**known, **{value: _smallest_period(value) for value in extra}}
        merged._shortest = len(merged._values[-1])
        return merged

    def contains(self, text: str) -> bool:
        if not self._values or len(text) < self._shortest:
            return False
        return any(value in text for value in self._values)

    def spans(self, text: str) -> list[Span]:
        """Where known values occur in ``text``: sorted, disjoint, touching runs joined."""
        if not self._values or len(text) < self._shortest:
            return []
        covered = self._covered(text)
        return [] if covered is None else [run.span() for run in _COVERED.finditer(covered)]

    def _covered(self, text: str) -> bytearray | None:
        covered: bytearray | None = None
        passes = len(text) // 8 + 4 * len(self._values) + 1024
        # Only an occurrence reaching an uncovered character, between the first and
        # the last, can add to the cover.
        first, last_free = 0, len(text) - 1
        for value in self._values:
            size = len(value)
            period = self._periods[value]
            # An occurrence overlapping a run at a shift that is not a multiple of the
            # period starts past both the period and size - period (Fine and Wilf).
            resume = min(size, max(period, size - period) + 1)
            if covered is not None:
                first = covered.find(0, first)
                if first < 0:
                    break
                last_free = covered.rfind(0, 0, last_free + 1)
            bound = last_free + size
            start = text.find(value, max(0, first - size + 1), bound)
            while start >= 0:
                if covered is None:
                    covered = bytearray(len(text))
                elif covered.find(0, start, start + size) < 0:
                    # Every occurrence starting before the next uncovered character
                    # lies wholly in covered text.
                    passes -= 1
                    if passes < 0:
                        return self._widened_greedy(text)
                    free = covered.find(0, start + size)
                    if free < 0:
                        break
                    start = text.find(value, max(start + 1, free - size + 1), bound)
                    continue
                end = _periodic_end(text, start + size, period)
                last = start + (end - size - start) // period * period
                covered[start : last + size] = b"\x01" * (last + size - start)
                start = text.find(value, last + resume, bound)
        return covered

    def _widened_greedy(self, text: str) -> bytearray:
        """Every value replaced in turn, each run then widened by the longest value.

        An occurrence the replacements skip overlaps a replaced one, so it lies within
        the longest value's length of a run. A marker no value holds keeps a replaced
        run from matching a shorter value; one the text holds only widens the cover.
        """
        covered = bytearray(len(text))
        held = set("".join(self._values))
        marker = next((chr(code) for code in range(0x110000) if chr(code) not in held), None)
        if marker is None:
            covered[:] = b"\x01" * len(text)
            return covered
        replaced = text
        for value in self._values:
            replaced = replaced.replace(value, marker * len(value))
        reach = len(self._values[0]) - 1
        for run in re.finditer(re.escape(marker) + "+", replaced):
            start, end = max(0, run.start() - reach), min(len(text), run.end() + reach)
            covered[start:end] = b"\x01" * (end - start)
        return covered

    def scrub(self, text: str) -> str:
        spans = self.spans(text)
        return _apply(text, spans, []) if spans else text


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


def _authorization_scheme_credential(match: re.Match[str]) -> bool:
    scheme, _space, token = match.groups()
    start = match.start()
    header = _AUTHORIZATION_HEADER.search(
        match.string, max(0, start - _AUTHORIZATION_LOOKBACK), start
    )
    return header is not None or _credential_like(token, scheme)


def _scheme_matches(value: str) -> Iterator[re.Match[str]]:
    """Scheme matches, each search resuming where the previous credential starts.

    A scheme word can end a credential and start the next (``x=Bearer``, then the
    value after it). Applied one after another, the rules used to find it once an
    earlier rule had redacted the first scheme. A credential holds no whitespace and
    a scheme is followed by some, so a resumed search reads each credential twice at
    most.
    """
    position = 0
    while (match := _AUTH.search(value, position)) is not None:
        yield match
        position = match.start(3)


def _private_key_spans(value: str) -> Iterable[Span]:
    """PEM private key blocks, including unterminated ones, in one pass."""
    if "-----BEGIN" not in value:
        return
    search = 0
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
        search = len(value) if close < 0 else close + 5
        yield start, search


def _raw_auth_span(match: re.Match[str]) -> Span | None:
    _prefix, scheme, _space, _credential, token = match.groups()
    if scheme is not None:
        return match.span(4)
    if token.lower() in _AUTH_SCHEMES or not _credential_like(token, "token"):
        return None
    return match.span(5)


def _cookie_pair_secret(match: re.Match[str]) -> bool:
    name_eq, val = match.groups()
    if name_eq[:-1].lower() in _COOKIE_ATTRS:
        return False
    return len(val) >= MIN_SECRET_LENGTH or _credential_like(val, "token")


def _cookie_pair_replacement(match: re.Match[str]) -> str:
    return match.group(1) + REDACTED if _cookie_pair_secret(match) else match.group()


def _cookie_spans(value: str, start: int = 0, end: int | None = None) -> Iterable[Span]:
    stop = len(value) if end is None else end
    for pair in _COOKIE_PAIR.finditer(value, start, stop):
        if _cookie_pair_secret(pair):
            yield pair.span(2)


class _Rewrite:
    """A URL shown as its origin; ``revealed`` ends the source text the origin repeats."""

    __slots__ = ("end", "replacement", "revealed", "start")

    def __init__(self, start: int, end: int, replacement: str, revealed: int) -> None:
        self.start, self.end = start, end
        self.replacement, self.revealed = replacement, revealed


def _url_rewrite(match: re.Match[str]) -> _Rewrite | None:
    url = match.group()
    shown = redact_url(url)
    if shown == url:
        return None
    start = match.start()
    revealed = start
    if shown != "[redacted-url]":
        scheme_end = url.index("://") + 3
        netloc = _NETLOC.match(url, scheme_end)
        revealed = start + (netloc.end() if netloc else scheme_end)
    return _Rewrite(start, match.end(), shown, revealed)


def _merged(spans: list[Span]) -> list[Span]:
    """Sorted, disjoint spans; touching spans become one."""
    spans.sort()
    merged: list[Span] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged


def _apply(value: str, spans: list[Span], rewrites: list[_Rewrite]) -> str:
    """Replace each maximal union of ``spans`` and ``rewrites`` in one pass.

    ``spans`` are disjoint and sorted. A rewrite whose revealed origin no span touches,
    and which no span extends past, is shown as rewritten; any other union of a
    rewrite and spans is redacted as a whole, so a rewrite never shows a known value.
    """
    items: list[tuple[int, int, _Rewrite | None]] = [(start, end, None) for start, end in spans]
    for rewrite in rewrites:
        # The last span starting inside the revealed origin is the only one that can
        # reach into it: the spans are disjoint and sorted.
        index = bisect.bisect_left(spans, (rewrite.revealed, -1))
        touched = (
            rewrite.revealed > rewrite.start and index > 0 and spans[index - 1][1] > rewrite.start
        )
        items.append((rewrite.start, rewrite.end, None if touched else rewrite))
    items.sort(key=lambda item: (item[0], -item[1]))
    parts: list[str] = []
    copied = 0
    group_start = group_end = -1
    shown: list[_Rewrite] = []

    def flush() -> None:
        if len(shown) == 1 and (group_start, group_end) == (shown[0].start, shown[0].end):
            parts.append(shown[0].replacement)
        else:
            parts.append(REDACTED)

    for start, end, shape in items:
        if group_end >= 0 and (
            start < group_end or (start == group_end and shape is None and not shown)
        ):
            group_end = max(group_end, end)
        else:
            if group_end >= 0:
                flush()
                copied = group_end
            parts.append(value[copied:start])
            group_start, group_end = start, end
            shown = []
        if shape is not None:
            shown.append(shape)
    if group_end < 0:
        return value
    flush()
    parts.append(value[group_end:])
    return "".join(parts)


def _rule_matches(
    value: str, *, identifier: bool, cookie: bool
) -> tuple[list[Span], list[_Rewrite]]:
    rewrites = [
        rewrite for match in _URL.finditer(value) if (rewrite := _url_rewrite(match)) is not None
    ]
    spans: list[Span] = []
    if not identifier:
        spans.extend(_private_key_spans(value))
    spans.extend(match.span(2) for match in _ASSIGNMENT.finditer(value))
    spans.extend(
        match.span(3) for match in _scheme_matches(value) if _authorization_scheme_credential(match)
    )
    if identifier:
        spans.extend(match.span() for match in _NAMED_TOKEN.finditer(value))
        return spans, rewrites
    for match in _RAW_AUTH_HEADER.finditer(value):
        if (span := _raw_auth_span(match)) is not None:
            spans.append(span)
    for match in _COOKIE_HEADER.finditer(value):
        spans.extend(_cookie_spans(value, *match.span(2)))
    spans.extend(match.span() for match in TOKEN_SHAPE.finditer(value))
    if cookie:
        spans.extend(_cookie_spans(value))
    return spans, rewrites


def _masked(value: str, spans: list[Span]) -> str:
    """``value`` with each span replaced by as many marker characters, offsets kept."""
    parts: list[str] = []
    copied = 0
    for start, end in spans:
        parts.append(value[copied:start])
        parts.append(_MASK * (end - start))
        copied = end
    parts.append(value[copied:])
    return "".join(parts)


def _redaction(
    value: str, scrubber: SecretScrubber, *, identifier: bool, cookie: bool = False
) -> tuple[list[Span], list[_Rewrite]]:
    """Every rule's and every known value's match in ``value``.

    The rules read the original text, where a known value cannot erase the context
    they need, and again the text with each known value masked, where a value's edge
    separates words as its redaction did: a token, header or URL right next to a known
    value still matches. ``cookie`` reads the whole value as cookie pairs.
    """
    known = scrubber.spans(value)
    spans, rewrites = _rule_matches(value, identifier=identifier, cookie=cookie)
    if known:
        masked_spans, masked_rewrites = _rule_matches(
            _masked(value, known), identifier=identifier, cookie=cookie
        )
        spans.extend(masked_spans)
        spans.extend(known)
        # A masked URL runs on through a known value holding a space or quote, so it
        # replaces the shorter URL read at the same place.
        starts = {rewrite.start: rewrite for rewrite in rewrites}
        starts.update((rewrite.start, rewrite) for rewrite in masked_rewrites)
        rewrites = list(starts.values())
    return spans, rewrites


def _redact(value: str, spans: list[Span], rewrites: list[_Rewrite]) -> str:
    return _apply(value, _merged(spans), rewrites) if spans or rewrites else value


def redact_text(
    value: str,
    secrets: Iterable[str] | SecretScrubber = (),
    *,
    identifier: bool = False,
) -> str:
    """Remove known secret values and common URL/auth/assignment/token encodings.

    Every rule and every known value is matched in the original text, and each union
    of their matches is replaced at once: a known value cannot erase the context a
    rule needs, such as the name before ``=`` or an ``Authorization`` header, nor can
    a rule's rewrite hide part of a known value from the scrubber.

    ``identifier`` keeps names that are matched against other evidence, such as tool
    names, free of the private key rule and of the token formats that ordinary names
    take: an innocuous name like ``sk-learn-classifier`` must keep matching the name a
    live server reports. A name holding a distinctive token such as ``ghp_...`` is
    still redacted.
    """
    spans, rewrites = _redaction(value, _scrubber(secrets), identifier=identifier)
    return _redact(value, spans, rewrites)


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
    if not value:
        return redact_text(value, secrets) if redacted is None else redacted
    cookie = _COOKIE_KEY.fullmatch(key) is not None
    if redacted is not None:
        safe = redacted
    else:
        # The pairs are read in the original value too: a known value redacted first
        # could hide the name that marks the pair after it.
        spans, rewrites = _redaction(value, _scrubber(secrets), identifier=False, cookie=cookie)
        safe = _redact(value, spans, rewrites)
    if _AUTHORIZATION_KEY.fullmatch(key):
        parts = _SCHEME_AND_VALUE.fullmatch(value)
        if parts is not None and parts.group(1).lower() in _AUTH_SCHEMES:
            scheme, space, credential = parts.groups()
            return safe if _REFERENCE.fullmatch(credential) else scheme + space + REDACTED
        return safe if _REFERENCE.fullmatch(value) else REDACTED
    if cookie:
        return safe if redacted is None else _COOKIE_PAIR.sub(_cookie_pair_replacement, safe)
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
