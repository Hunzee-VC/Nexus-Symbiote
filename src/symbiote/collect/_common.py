"""Shared helpers for static collectors: bounded reads, JSONC, locators, placeholders, redaction, trust zones.

Every helper is defensive: hostile or malformed input produces an error class that becomes a coverage fact,
and secret material is dropped before it can reach an entity (``spec/collectors.md`` rules).
"""

from __future__ import annotations

import ipaddress
import json
import re
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import yaml

from symbiote.model.common import looks_like_secret
from symbiote.model.enums import TrustZone

__all__ = [
    "REDACTED",
    "ReadOutcome",
    "UrlFacts",
    "classify_env_value",
    "json_pointer",
    "locator",
    "parse_jsonc",
    "parse_structured",
    "placeholders_in",
    "read_bounded",
    "redact_args",
    "secretish_name",
    "url_facts",
]

REDACTED: Final = "<redacted>"

ErrorClass = Literal["permission-denied", "not-found", "too-large", "unreadable", "parse-error", "not-utf8"]


@dataclass(frozen=True, slots=True)
class ReadOutcome:
    data: bytes | None
    error_class: ErrorClass | None = None
    detail: str | None = None

    @property
    def ok(self) -> bool:
        return self.data is not None


def read_bounded(path: Path, limit: int) -> ReadOutcome:
    """Read a whole file if it is at most ``limit`` bytes; failures are classified, never raised."""
    try:
        size = path.stat().st_size
        if size > limit:
            return ReadOutcome(None, "too-large", f"{size} > {limit} bytes")
        with path.open("rb") as fh:
            return ReadOutcome(fh.read(limit + 1)[:limit])
    except PermissionError as exc:
        return ReadOutcome(None, "permission-denied", str(exc))
    except FileNotFoundError as exc:
        return ReadOutcome(None, "not-found", str(exc))
    except OSError as exc:
        return ReadOutcome(None, "unreadable", f"{type(exc).__name__}: {exc}")


# --------------------------------------------------------------------------------------------- parsing


def _strip_jsonc(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments outside strings, then trailing commas before ``}``/``]``."""
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        out.append(ch)
        i += 1
    stripped = "".join(out)
    # trailing commas: a comma followed only by whitespace before a closing bracket (outside strings)
    result: list[str] = []
    in_string = False
    j = 0
    while j < len(stripped):
        ch = stripped[j]
        if in_string:
            result.append(ch)
            if ch == "\\" and j + 1 < len(stripped):
                result.append(stripped[j + 1])
                j += 2
                continue
            if ch == '"':
                in_string = False
            j += 1
            continue
        if ch == '"':
            in_string = True
        elif ch == ",":
            k = j + 1
            while k < len(stripped) and stripped[k] in " \t\r\n":
                k += 1
            if k < len(stripped) and stripped[k] in "}]":
                j += 1
                continue
        result.append(ch)
        j += 1
    return "".join(result)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def parse_jsonc(text: str) -> Any:
    """Parse JSON-with-comments (VS Code style), rejecting duplicate keys (parser-disagreement attacks)."""
    return json.loads(_strip_jsonc(text), object_pairs_hook=_no_duplicate_keys)


def parse_structured(data: bytes, fmt: Literal["json", "jsonc", "toml", "yaml"]) -> Any:
    """Decode UTF-8 (BOM tolerated) and parse with the format's safe parser."""
    text = data.decode("utf-8-sig")
    if fmt == "toml":
        return tomllib.loads(text)
    if fmt == "yaml":
        return yaml.safe_load(text)
    if fmt == "jsonc":
        return parse_jsonc(text)
    return json.loads(text, object_pairs_hook=_no_duplicate_keys)


# --------------------------------------------------------------------------------------------- locators


def _escape_pointer_token(token: str | int) -> str:
    return str(token).replace("~", "~0").replace("/", "~1")


def json_pointer(*tokens: str | int) -> str:
    """RFC 6901 JSON Pointer for the given path tokens (``json_pointer("a/b", 0) == "/a~1b/0"``)."""
    return "".join("/" + _escape_pointer_token(t) for t in tokens)


def locator(display_path: str, *tokens: str | int) -> str:
    """``<path>#<json-pointer>`` (``spec/agentbom-profile.md`` §1.3 locator form)."""
    return f"{display_path}#{json_pointer(*tokens)}" if tokens else display_path


# --------------------------------------------------------------------------------------------- placeholders & secrets

#: ``${VAR}``, ``${VAR:-default}``, ``${env:VAR}``, ``${input:id}``, ``${workspaceFolder}``, ``$VAR``.
_PLACEHOLDER = re.compile(
    r"\$\{(?:(?P<ns>env|input|config|command|workspaceFolder|userHome|pathSeparator):)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.-]*)(?::-[^}]*)?\}"
    r"|\$(?P<bare>[A-Z_][A-Z0-9_]{1,})"
)
_SECRET_NAME = re.compile(
    r"(?i)(token|secret|passw(or)?d|passwd|api[_-]?key|apikey|credential|private[_-]?key|auth|bearer|cookie|session|pat\b|_key$|^key$)"
)


def placeholders_in(value: str) -> list[str]:
    """Placeholder references in ``value`` rendered canonically (``env:X``, ``input:y``, ``X``)."""
    found: list[str] = []
    for m in _PLACEHOLDER.finditer(value):
        if m.group("bare"):
            found.append(m.group("bare"))
        else:
            ns = m.group("ns")
            found.append(f"{ns}:{m.group('name')}" if ns else m.group("name"))
    return found


def secretish_name(name: str) -> bool:
    """True when a variable/header name suggests it carries a credential."""
    return bool(_SECRET_NAME.search(name))


EnvValueKind = Literal["placeholder", "literal-secret", "literal", "empty"]

#: Authentication scheme words that may precede a placeholder (``Bearer ${TOKEN}``) without being a secret.
_AUTH_SCHEME = re.compile(r"(?i)\b(?:bearer|basic|token|apikey|api-key|digest)\b")


def classify_env_value(name: str, value: object) -> EnvValueKind:
    """Classify a configured env/header value without retaining it.

    ``literal-secret``: an inline value under a credential-like name or with a credential shape — a static
    long-lived credential stored in a configuration file (``SYM-AUTHZ-003`` input).
    """
    if value is None or value == "":
        return "empty"
    text = str(value)
    if placeholders_in(text) and _AUTH_SCHEME.sub("", _PLACEHOLDER.sub("", text)).strip(" -_:/") == "":
        return "placeholder"
    if looks_like_secret(text) or secretish_name(name):
        return "literal-secret"
    return "literal"


_SECRET_FLAGS: Final = re.compile(
    r"^--?(?:api[-_]?key|token|access[-_]?token|auth[-_]?token|password|passwd|secret|client[-_]?secret|"
    r"bearer|key|pat|github[-_]?token|private[-_]?key)$",
    re.I,
)
_URL_USERINFO = re.compile(r"^(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<user>[^:/@\s]+):(?P<pw>[^@/\s]+)@", re.I)


def redact_args(args: Sequence[object]) -> tuple[list[str], int]:
    """Return ``args`` with credential material replaced by :data:`REDACTED`, and the number of redactions.

    Covers credential-shaped tokens, values following ``--token``-style flags (``--token X`` and
    ``--token=X``), ``KEY=value`` pairs with credential-like keys, and passwords in URL userinfo.
    """
    out: list[str] = []
    redactions = 0
    redact_next = False
    for raw in args:
        arg = str(raw)
        if redact_next:
            out.append(REDACTED)
            redactions += 1
            redact_next = False
            continue
        if "=" in arg and arg.startswith("-"):
            flag, _, val = arg.partition("=")
            if _SECRET_FLAGS.match(flag) and val and not placeholders_in(val):
                out.append(f"{flag}={REDACTED}")
                redactions += 1
                continue
        if _SECRET_FLAGS.match(arg):
            out.append(arg)
            redact_next = True
            continue
        if "=" in arg and not arg.startswith("-"):
            key, _, val = arg.partition("=")
            if secretish_name(key) and val and not placeholders_in(val):
                out.append(f"{key}={REDACTED}")
                redactions += 1
                continue
        m = _URL_USERINFO.match(arg)
        if m:
            out.append(
                _URL_USERINFO.sub(lambda mm: f"{mm.group('scheme')}{mm.group('user')}:{REDACTED}@", arg)
            )
            redactions += 1
            continue
        if looks_like_secret(arg):
            out.append(REDACTED)
            redactions += 1
            continue
        out.append(arg)
    if redact_next:
        # a trailing secret flag with no value: nothing to redact
        pass
    return out, redactions


# --------------------------------------------------------------------------------------------- endpoints

_INTERNAL_SUFFIXES: Final = (
    ".local",
    ".internal",
    ".corp",
    ".lan",
    ".intranet",
    ".home.arpa",
    ".cluster.local",
    ".svc",
)


@dataclass(frozen=True, slots=True)
class UrlFacts:
    """Privacy-preserving facts about a configured URL."""

    display: str
    scheme: str
    host: str | None
    trust_zone: TrustZone
    crosses_trust_boundary: bool
    query_param_names: tuple[str, ...]
    had_userinfo: bool
    secret_in_query: bool


def url_facts(url: str) -> UrlFacts:
    """Classify ``url`` without retaining credentials: userinfo and query values are dropped from ``display``."""
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower() or None
    query = parse_qsl(parts.query, keep_blank_values=True)
    names = tuple(sorted({k for k, _ in query}))
    secret_q = any(secretish_name(k) or looks_like_secret(v) for k, v in query)
    netloc = parts.netloc.rsplit("@", 1)[-1]
    display = urlunsplit((scheme, netloc.lower(), parts.path, "", ""))
    zone = _zone_for_host(host)
    crosses = zone not in (TrustZone.LOCAL_PROCESS, TrustZone.LOOPBACK)
    return UrlFacts(
        display=display,
        scheme=scheme,
        host=host,
        trust_zone=zone,
        crosses_trust_boundary=crosses,
        query_param_names=names,
        had_userinfo="@" in parts.netloc,
        secret_in_query=secret_q,
    )


def _zone_for_host(host: str | None) -> TrustZone:
    if not host:
        return TrustZone.UNKNOWN
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        return TrustZone.LOOPBACK
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        internal = "." not in host or host.endswith(_INTERNAL_SUFFIXES)
        return TrustZone.INTERNAL if internal else TrustZone.EXTERNAL
    if ip.is_loopback:
        return TrustZone.LOOPBACK
    return TrustZone.INTERNAL if (ip.is_private or ip.is_link_local) else TrustZone.EXTERNAL


def names_from_mapping(mapping: object) -> list[str]:
    """Sorted string keys of a mapping (env/header tables); non-mappings yield no names."""
    if not isinstance(mapping, Mapping):
        return []
    return sorted(str(k) for k in mapping if isinstance(k, str) and "=" not in k and not looks_like_secret(k))


def as_str_list(value: object) -> list[str]:
    """Coerce a JSON/TOML/YAML value to a list of strings (scalars become one-element lists)."""
    if value is None:
        return []
    if isinstance(value, (str, int, float, bool)):
        return [str(value)]
    if isinstance(value, Iterable) and not isinstance(value, (bytes, Mapping)):
        return [str(v) for v in value if isinstance(v, (str, int, float, bool))]
    return []
