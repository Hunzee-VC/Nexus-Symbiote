"""Literal credentials in agent configuration: what counts as one, and of which type.

A collector passes each value it already redacts, with the header, variable or option
name that holds it, and gets the types of the credentials written there, from a fixed
vocabulary. A reference (``${NAME}``, ``$NAME``, ``%NAME%``, a command substitution)
and a placeholder (``<token>``, ``your-api-key``, ``CHANGE_ME``, ``xxxx``) hold none.
The finding names the file, the position and the type: never the value, a part of it,
its length or a digest of it. docs/finding-catalog.md states the rule, and
docs/known-limitations.md what it misses and what it reports wrongly.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import RiskAssessment
from nexus_symbiote.scanners.mcp_launch import expands
from nexus_symbiote.utils.secrets import MIN_SECRET_LENGTH, TOKEN_SHAPE

CATEGORY = "literal_credential"
URL_PASSWORD = "URL password"  # noqa: S105 - a type name, not a credential
_GITHUB = "GitHub token"
_AWS = "AWS access key ID"
_ANTHROPIC = "Anthropic key"
_OPENAI = "OpenAI key"
_PRIVATE_KEY = "private key"
_KNOWN_FORMAT = "token in a known format"
_BEARER = "bearer token"
_BASIC = "basic credentials"
_HIGH_ENTROPY = "generic high-entropy value"
_UNKNOWN = "unknown"
# Every type a finding can name, most specific first: the order a finding lists them in.
KINDS = (
    _GITHUB,
    _AWS,
    _ANTHROPIC,
    _OPENAI,
    _PRIVATE_KEY,
    _KNOWN_FORMAT,
    _BEARER,
    _BASIC,
    URL_PASSWORD,
    _HIGH_ENTROPY,
    _UNKNOWN,
)
# The type names the format, not the issuer: another provider's key that starts with
# "sk-" reads as an OpenAI key. A format the redaction knows and this table does not
# is a token in a known format.
_FORMATS = (
    (("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"), _GITHUB),
    (("AKIA", "ASIA"), _AWS),
    (("sk-ant-",), _ANTHROPIC),
    (("sk-",), _OPENAI),
)
# "sk-" also starts ordinary names and the stand-in keys of local model servers
# (sk-local-development-key), so such a token needs a run of letters and digits that
# holds both, as generated keys do.
_KEY_RUN = re.compile(r"[A-Za-z0-9]{12,}")
_PEM_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----")
# A line of key material, which a template that keeps only the BEGIN and END lines lacks.
_KEY_MATERIAL = re.compile(r"[A-Za-z0-9+/=]{32,}")
_BRACED_REFERENCE = re.compile(r"\$\{[^{}]{0,256}\}")
# What says that a value stands in for a credential: text in angle, square or doubled
# curly brackets, a value wholly in curly brackets, a run of "x", "*" or ".", the
# sequences that documentation counts out, and the words that templates use. A
# credential that holds one of these by chance is not reported.
_PLACEHOLDER = re.compile(
    r"(?i)<[^<>]++>|\[[^\[\]]++\]|\{\{[^{}]*+\}\}|\A\{.*\}\Z|x{4,}|\*{3,}|\.{3,}"
    r"|123456|abcdef|your|example|sample|placeholder|change[-_ ]?me|replace|insert|dummy"
    r"|redacted",
    re.DOTALL,
)
# Written as a variable is named, such as MY_API_KEY: the name of a value, not one.
_VARIABLE_NAME = re.compile(r"[A-Z][A-Z0-9]*+(?:_[A-Z0-9]++)++")
_MIN_DISTINCT = 5
_RANDOM_LENGTH = 20
_RANDOM_DISTINCT = 10
# Names whose value is a credential whatever it looks like. The word ends the name, but
# for a number, so TOKEN_FILE, MAX_TOKENS and SECRET_NAME are not among them, and
# neither is a bare KEY, which also names sort, cache and public keys.
_CREDENTIAL_NAME = re.compile(
    r"(?i)(?:token|secret|password|passwd|passphrase|bearer"
    r"|(?:api|access|secret|private|account)[-_.]?key"
    r"|(?:\A|[^a-z0-9])(?:pass|pwd|pat))(?:[-_.]?[0-9]{1,4})?\Z"
)
_AUTHORIZATION = re.compile(r"(?i)-{0,2}(?:proxy-)?authorization")
# The word after Bearer, in the characters RFC 6750 gives a token. One that an
# expansion follows is only part of a value.
_BEARER_WORD = re.compile(r"(?i)\bbearer[ \t]++([A-Za-z0-9._~+/=-]++)(?![$%{`])")
_SCHEME_FORM = re.compile(r"([A-Za-z-]{3,7})[ \t]++(\S++)")
_SCHEMES = {
    "bearer": _BEARER,
    "basic": _BASIC,
    "token": None,
    "bot": None,
    "apikey": None,
    "api-key": None,
}
# A URL, a path or a file name locates a credential and holds none.
_PATH = re.compile(r"(?:[A-Za-z]:)?[\\/]|\.{1,2}[\\/]|~[\\/]")
_FILE_SUFFIXES = (
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".txt",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".crt",
    ".cer",
    ".env",
    ".ini",
    ".conf",
)
ADVICE = (
    "Rotate the credential, which everyone who can read the file or its history holds, "
    "and take the value out of the file: write a reference that the client expands, such "
    "as ${NAME}, or supply the value from the environment or a secret store."
)


def credential_name(name: str) -> bool:
    """Whether a header, variable, option or query parameter is named for a credential."""
    return _CREDENTIAL_NAME.search(name) is not None


def _formats(text: str) -> list[str]:
    """The types of the tokens and private keys in a text that are not placeholders.

    A reference is taken out first, so that the name it holds cannot read as a token.
    """
    literal = _BRACED_REFERENCE.sub(" ", text) if "${" in text else text
    kinds = []
    for match in TOKEN_SHAPE.finditer(literal):
        token = match.group()
        if _PLACEHOLDER.search(token) is not None or (
            token.startswith("sk-")
            and all(run.isalpha() or run.isdigit() for run in _KEY_RUN.findall(token))
        ):
            continue
        kinds.append(
            next((kind for prefixes, kind in _FORMATS if token.startswith(prefixes)), _KNOWN_FORMAT)
        )
    header = _PEM_PRIVATE_KEY.search(literal)
    if header is not None and any(
        len(set(line)) >= _RANDOM_DISTINCT for line in _KEY_MATERIAL.findall(literal, header.end())
    ):
        kinds.append(_PRIVATE_KEY)
    return kinds


def _reads_generated(text: str) -> bool:
    """Whether a value holds a digit, or is long and mixes cases.

    Words in one case, and a short capitalized or camel-case name, read as a default or
    a placeholder: ``postgres``, ``not-needed``, ``MyApiKey``.
    """
    return any(map(str.isdigit, text)) or (
        len(text) >= _RANDOM_LENGTH and any(map(str.isupper, text)) and any(map(str.islower, text))
    )


def candidate_kinds(candidate: str, kind: str | None = None) -> list[str]:
    """The types of a value written where a credential belongs.

    A token format in it names the type; otherwise ``kind`` does, or how random the
    value reads. A reference, a placeholder and a value that reads as words have none.
    """
    formats = _formats(candidate)
    if formats:
        return formats
    if (
        len(candidate) < MIN_SECRET_LENGTH
        or len(set(candidate)) < _MIN_DISTINCT
        or expands(candidate)
        or _PLACEHOLDER.search(candidate) is not None
        or _VARIABLE_NAME.fullmatch(candidate) is not None
        or not _reads_generated(candidate)
    ):
        return []
    if kind is not None:
        return [kind]
    random = (
        len(candidate) >= _RANDOM_LENGTH
        and len(set(candidate)) >= _RANDOM_DISTINCT
        and any(map(str.isalpha, candidate))
        and any(map(str.isdigit, candidate))
        and not any(map(str.isspace, candidate))
    )
    return [_HIGH_ENTROPY if random else _UNKNOWN]


def value_kinds(value: str, name: str = "") -> list[str]:
    """The types of the literal credentials in one value held under ``name``.

    A token format, a private key and the word after ``Bearer`` count anywhere in the
    value, whatever holds it. Otherwise the whole value counts when ``name`` is an
    ``Authorization`` header or ends in a credential word: after its authentication
    scheme word if it starts with one, and not when it is a URL, a path or a file name,
    which locate a credential.
    """
    kinds = _formats(value)
    bearer = [
        kind for word in _BEARER_WORD.findall(value) for kind in candidate_kinds(word, _BEARER)
    ]
    if bearer or not (_AUTHORIZATION.fullmatch(name) or credential_name(name)):
        return kinds + bearer
    text = value.strip()
    form = _SCHEME_FORM.fullmatch(text)
    if form is not None and form.group(1).lower() in _SCHEMES:
        kinds += candidate_kinds(form.group(2), _SCHEMES[form.group(1).lower()])
    elif (
        "://" not in text
        and _PATH.match(text) is None
        and not text[-5:].lower().endswith(_FILE_SUFFIXES)
    ):
        kinds += candidate_kinds(text)
    return kinds


def ordered_kinds(kinds: Iterable[str]) -> list[str]:
    """Each type once, in the order of ``KINDS``."""
    return sorted(set(kinds), key=KINDS.index)


def literal_credential(
    subject: str, path: str, position: str, kinds: Sequence[str]
) -> RiskAssessment:
    """The finding for one position of ``path`` that holds a literal credential.

    ``subject`` names the component as its other findings do, and ``position`` the
    place by field and name only, as the caller exports names.
    """
    label = "type" if len(kinds) == 1 else "types"
    return RiskAssessment(
        severity=RiskSeverity.HIGH,
        category=CATEGORY,
        detail=(
            f"{subject} holds a literal credential in {path} at {position} "
            f"(credential {label}: {', '.join(kinds)})."
        ),
        recommendation=ADVICE,
    )
