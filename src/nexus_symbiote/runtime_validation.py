"""Bound offline JSON Schema work outside the authorization process.

Approved descriptors can still contain expensive regular expressions or schema
combinations. Only a short fixed result crosses this worker boundary; schemas
never select executable code, network retrieval or worker limits.
"""

from __future__ import annotations

import json
import math
import os
import re
import selectors
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.parse import unquote

MAX_SCHEMA_BYTES = 256 * 1024
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 20_000
MAX_SAFE_INTEGER = 2**53 - 1
# Interpreter start-up and imports get their own budget, so a slow or throttled
# host does not spend the evaluation budget before the untrusted input arrives.
WORKER_STARTUP_SECONDS = 10.0
WORKER_STARTUP_CPU_SECONDS = 10
WORKER_TIMEOUT_SECONDS = 2.0
WORKER_CPU_SECONDS = 1
WORKER_MEMORY_BYTES = 256 * 1024 * 1024
WORKER_SLOTS = 4
_WORKER_SLOTS = threading.BoundedSemaphore(WORKER_SLOTS)
_WORKER_COMMAND = (sys.executable, "-I", "-m", "nexus_symbiote.runtime_validation")
_READY = b"ready\n"
_VALID = b"valid\n"
_INVALID = b"invalid\n"
_SCHEMA = b"schema\n"
# Optional checkers jsonschema imports whenever they are installed, for example
# through cyclonedx-python-lib's jsonschema[format-nongpl] requirement.
_UNUSED_FORMAT_MODULES = (
    "fqdn",
    "idna",
    "isoduration",
    "jsonpointer",
    "rfc3339_validator",
    "rfc3986_validator",
    "rfc3987",
    "rfc3987_syntax",
    "uri_template",
    "webcolors",
)
# A schema without "$schema" is read as 2020-12, the MCP default. Draft 3 and
# unknown dialects are refused rather than read under another dialect's keywords.
DIALECTS = (
    "http://json-schema.org/draft-04/schema",
    "http://json-schema.org/draft-06/schema",
    "http://json-schema.org/draft-07/schema",
    "https://json-schema.org/draft/2019-09/schema",
    "https://json-schema.org/draft/2020-12/schema",
)


class ValidationBudgetError(ValueError):
    """Validation was invalid, incomplete, or outside the supported budget.

    ``reason`` is a stable code from ``nexus_symbiote.runtime.REASONS``.
    """

    def __init__(self, message: str, *, reason: str = "validation-failed") -> None:
        super().__init__(message)
        self.reason = reason


def check_json_budget(
    value: Any,
    *,
    maximum: int,
    max_depth: int = MAX_JSON_DEPTH,
    max_nodes: int = MAX_JSON_NODES,
) -> None:
    """Check size and complexity iteratively before recursive serialization.

    Count escaped JSON string sizes as well as values. A cyclic or repeatedly
    aliased container exhausts the same depth/node budget as expanded JSON.
    Integers must lie in the I-JSON range of +/-(2**53 - 1); floats must be finite.
    """
    pending = [(value, 0)]
    nodes = 0
    size = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > max_depth or nodes > max_nodes:
            raise ValidationBudgetError(
                "JSON complexity exceeds validation budget", reason="json-budget-exceeded"
            )
        if isinstance(item, dict):
            if len(item) > max_nodes:
                raise ValidationBudgetError(
                    "JSON complexity exceeds validation budget", reason="json-budget-exceeded"
                )
            size += 2 + 2 * len(item)
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValidationBudgetError("invalid JSON object key", reason="json-invalid")
                if len(key) > maximum:
                    raise ValidationBudgetError(
                        "oversized JSON object key", reason="json-budget-exceeded"
                    )
                size += len(json.dumps(key, ensure_ascii=True))
                pending.append((child, depth + 1))
        elif isinstance(item, (list, tuple)):
            if len(item) > max_nodes:
                raise ValidationBudgetError(
                    "JSON complexity exceeds validation budget", reason="json-budget-exceeded"
                )
            size += 2 + len(item)
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item) > maximum:
                raise ValidationBudgetError(
                    "JSON exceeds validation byte budget", reason="json-budget-exceeded"
                )
            size += len(json.dumps(item, ensure_ascii=True))
        elif item is None or isinstance(item, bool):
            size += 5
        elif isinstance(item, int):
            if not -MAX_SAFE_INTEGER <= item <= MAX_SAFE_INTEGER:
                raise ValidationBudgetError(
                    "integer outside the I-JSON range", reason="json-number-out-of-range"
                )
            size += 24
        elif isinstance(item, float) and math.isfinite(item):
            size += 24
        else:
            raise ValidationBudgetError("value is outside the JSON domain", reason="json-invalid")
        if size > maximum or len(pending) + nodes > max_nodes:
            raise ValidationBudgetError(
                "JSON exceeds validation budget", reason="json-budget-exceeded"
            )


def validate_arguments(schema: Any, arguments: dict[str, Any]) -> None:
    """Validate in a disposable, CPU/memory/wall-time-bounded Python process.

    Isolated Python ignores the working directory and PYTHONPATH. The worker
    uses the installed trusted package and an empty reference retrieval registry.
    Start-up has its own deadline; the evaluation budget starts when the worker
    reports that it is ready. Capacity exhaustion, unavailable POSIX limits,
    crashes, malformed replies and timeouts deny the operation, each with its
    own reason. No approval nonce is consumed here.
    """
    if not isinstance(schema, dict):
        raise ValidationBudgetError(
            "served tool requires an object input schema", reason="schema-invalid"
        )
    check_json_budget(schema, maximum=MAX_SCHEMA_BYTES)
    check_json_budget(arguments, maximum=MAX_ARGUMENT_BYTES)
    wire = json.dumps(
        {"schema": schema, "arguments": arguments},
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    if len(wire) > MAX_SCHEMA_BYTES + MAX_ARGUMENT_BYTES + 64:
        raise ValidationBudgetError(
            "validation request exceeds byte budget", reason="json-budget-exceeded"
        )
    if not _WORKER_SLOTS.acquire(blocking=False):
        raise ValidationBudgetError(
            "validation worker capacity unavailable", reason="validation-capacity"
        )
    try:
        result = _run_worker(wire)
    finally:
        _WORKER_SLOTS.release()
    if result == _VALID:
        return
    if result == _INVALID:
        raise ValidationBudgetError(
            "tool arguments do not satisfy the offline input schema", reason="arguments-invalid"
        )
    if result == _SCHEMA:
        raise ValidationBudgetError(
            "offline input schema is invalid, unsupported or not resolvable offline",
            reason="schema-invalid",
        )
    raise ValidationBudgetError(
        "offline input schema validation failed or exceeded budget", reason="validation-failed"
    )


def check_worker() -> None:
    """Validate a trivial schema once; call at start-up or from a readiness probe."""
    validate_arguments({"type": "object"}, {})


def _run_worker(wire: bytes) -> bytes:
    try:
        process = subprocess.Popen(  # noqa: S603
            list(_WORKER_COMMAND),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": os.defpath},
        )
    except OSError as exc:
        raise ValidationBudgetError(
            "offline input schema worker could not start", reason="validation-unavailable"
        ) from exc
    try:
        try:
            ready = process.stdout is not None and _read_ready(process.stdout.fileno()) == _READY
        except OSError:
            ready = False
        if not ready:
            raise ValidationBudgetError(
                "offline input schema worker did not start within its budget",
                reason="validation-unavailable",
            )
        try:
            stdout, _ = process.communicate(wire, timeout=WORKER_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise ValidationBudgetError(
                "offline input schema worker timed out", reason="validation-timeout"
            ) from exc
        except OSError as exc:
            raise ValidationBudgetError(
                "offline input schema worker stopped before reading the request",
                reason="validation-failed",
            ) from exc
        return stdout if process.returncode == 0 else b""
    finally:
        if process.returncode is None:
            process.kill()
            try:
                process.communicate()
            except (OSError, ValueError):
                process.wait()


def _read_ready(fd: int) -> bytes:
    deadline = time.monotonic() + WORKER_STARTUP_SECONDS
    data = b""
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while len(data) < len(_READY):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                break
            chunk = os.read(fd, len(_READY) - len(data))
            if not chunk:
                break
            data += chunk
    return data


def _disable_unused_format_checkers() -> None:
    """Keep optional format checkers out of the worker before jsonschema loads.

    The worker never asserts "format" (no FormatChecker), so these modules cannot
    change a result. Some do expensive import-time work (rfc3987-syntax compiles a
    grammar), which would spend the CPU budget meant for the untrusted input.
    """
    for name in _UNUSED_FORMAT_MODULES:
        sys.modules[name] = None  # type: ignore[assignment]


# ECMA-262 WhiteSpace and LineTerminator code points, which "\s" matches there.
_ECMA_SPACE = r"\t\n\x0b\x0c\r \xa0  -     　﻿"
_CLASS_ESCAPES = {"d": "0-9", "w": "A-Za-z0-9_", "s": _ECMA_SPACE}
_ESCAPES = {
    "d": "[0-9]",
    "D": "[^0-9]",
    "w": "[A-Za-z0-9_]",
    "W": "[^A-Za-z0-9_]",
    "s": f"[{_ECMA_SPACE}]",
    "S": f"[^{_ECMA_SPACE}]",
}
_ANY = r"[^\n\r  ]"
_GROUPS = ("(?:", "(?=", "(?!", "(?<=", "(?<!")
_LOOKAROUNDS = frozenset(_GROUPS[1:])
_COMPLEMENTS = {"D": "0-9", "W": "A-Za-z0-9_", "S": _ECMA_SPACE}
_QUANTIFIER = re.compile(r"\{[0-9]+(?:,[0-9]*)?\}")
# Python reads "{,n}" and "{,}" as quantifiers; ECMA-262 reads the braces literally
# or, with the u flag, rejects them.
_PYTHON_QUANTIFIER = re.compile(r"\{,[0-9]*\}")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
# The characters that ECMA-262 lets an escape quote with the u flag.
_IDENTITY_ESCAPES = frozenset("^$\\.*+?()[]{}|/")
_ESCAPE_TOKEN = re.compile(r"\\(?:u([0-9a-fA-F]{4})|.)", re.S)


def ecma_pattern(pattern: str) -> str:
    """Translate an ECMA-262 pattern into a Python pattern with the same meaning.

    JSON Schema patterns are ECMA-262 expressions, read here as with the ``u`` flag
    that JSON Schema recommends. Python's ``$`` also matches before a final newline,
    and its ``\\d``, ``\\w`` and ``.`` differ for non-ASCII input, so a value the
    author excluded could pass. Syntax that ECMA-262 rejects or reads differently
    and that has no translation, such as inline flags, possessive quantifiers or a
    class escape as a range bound, raises ``re.error`` and makes the schema invalid.
    """
    # Without the u flag, ECMA-262 Annex B accepts more syntax and counts UTF-16 code
    # units, which Python cannot. A pattern that names a character outside the BMP
    # or a surrogate must therefore be valid with the u flag.
    strict = _names_astral(pattern)
    out: list[str] = []
    lookarounds: list[bool] = []
    # The last token: "atom", "assertion", "quantifier", "lazy", or "" at the start
    # of the pattern, a group or an alternative. Only an atom can be repeated.
    previous = ""
    index = 0
    while index < len(pattern):
        char = pattern[index]
        quantifier = _QUANTIFIER.match(pattern, index) if char == "{" else None
        if char in "*+?" or quantifier is not None:
            if char == "?" and previous == "quantifier":
                out.append("?")
                index += 1
                previous = "lazy"
                continue
            if previous != "atom":
                raise re.error("quantifier does not follow a repeatable atom")
            text = char if quantifier is None else quantifier.group()
            out.append(text)
            index += len(text)
            previous = "quantifier"
            continue
        if char == "{" and _PYTHON_QUANTIFIER.match(pattern, index):
            raise re.error("quantifier without a minimum has no ECMA-262 meaning")
        if char == "[":
            text, index = _character_class(pattern, index, strict)
            out.append(text)
            previous = "atom"
            continue
        if char == "\\":
            text, index, previous = _escape_outside_class(pattern, index, strict)
            out.append(text)
            continue
        if char == "(":
            prefix = _group_prefix(pattern, index)
            out.append("(?P<" if prefix == "(?<" else prefix)
            index += len(prefix)
            lookarounds.append(prefix in _LOOKAROUNDS)
            previous = ""
            continue
        if strict and char in "]{}":
            raise re.error("a lone bracket or brace is not valid with the u flag")
        if char == ")":
            previous = "assertion" if lookarounds and lookarounds.pop() else "atom"
        elif char in "^$":
            previous = "assertion"
        else:
            previous = "" if char == "|" else "atom"
        out.append(_ANY if char == "." else r"\Z" if char == "$" else char)
        index += 1
    return "".join(out)


def _group_prefix(pattern: str, index: int) -> str:
    if not pattern.startswith("(?", index):
        return "("
    for prefix in (*_GROUPS, "(?<"):
        if pattern.startswith(prefix, index):
            return prefix
    raise re.error("group syntax is not ECMA-262")


def _names_astral(pattern: str) -> bool:
    """Whether a pattern names a character outside the BMP or a UTF-16 surrogate."""
    if any(ord(char) > 0xFFFF or 0xD800 <= ord(char) <= 0xDFFF for char in pattern):
        return True
    codes = (escape.group(1) for escape in _ESCAPE_TOKEN.finditer(pattern))
    return any(code is not None and 0xD800 <= int(code, 16) <= 0xDFFF for code in codes)


def _escape(pattern: str, index: int, *, in_class: bool, strict: bool) -> tuple[str, int]:
    """Return the character escape at ``index`` unchanged and the index after it."""
    if index + 1 >= len(pattern):
        raise re.error("pattern ends with a backslash")
    escaped = pattern[index + 1]
    end = index + 2
    if escaped in "xu":
        width = 2 if escaped == "x" else 4
        if end + width > len(pattern) or not _HEX_DIGITS.issuperset(pattern[end : end + width]):
            raise re.error("incomplete hexadecimal escape")
        end += width
        point = _surrogate_pair(pattern, index, end)
        if point is not None:
            return f"\\U{point:08x}", end + 6
    elif escaped in "0123456789":
        octal = escaped != "0" or (end < len(pattern) and pattern[end] in "0123456789")
        if strict and octal and (in_class or escaped == "0"):
            raise re.error("an octal escape is not valid with the u flag")
        if in_class and escaped in "01234567":
            # Up to three octal digits, as Python and Annex B read them. Emit a fixed-width
            # escape so the digits of a following \d expansion cannot join it.
            while end < min(len(pattern), index + 4) and pattern[end] in "01234567":
                end += 1
            value = int(pattern[index + 1 : end], 8)
            if value > 0xFF:
                raise re.error("octal escape is out of range")
            return f"\\x{value:02x}", end
    elif escaped.isascii() and escaped.isalpha():
        if escaped not in "bfnrtv":
            raise re.error("escape is not an ECMA-262 escape")
    elif strict and escaped not in _IDENTITY_ESCAPES and not (in_class and escaped == "-"):
        raise re.error("an identity escape is not valid with the u flag")
    return pattern[index:end], end


def _surrogate_pair(pattern: str, index: int, end: int) -> int | None:
    """Return the code point of an escaped surrogate pair starting at ``index``.

    With the u flag, ``\\uD83D\\uDE00`` is one code point; Python would read two lone
    surrogates that no argument contains.
    """
    high = int(pattern[index + 2 : end], 16)
    low = pattern[end : end + 6]
    if not 0xD800 <= high <= 0xDBFF or len(low) != 6 or not low.startswith("\\u"):
        return None
    if not _HEX_DIGITS.issuperset(low[2:]) or not 0xDC00 <= int(low[2:], 16) <= 0xDFFF:
        return None
    return 0x10000 + (high - 0xD800) * 0x400 + int(low[2:], 16) - 0xDC00


def _escape_outside_class(pattern: str, index: int, strict: bool) -> tuple[str, int, str]:
    """Translate the escape at ``index``; return it, the index after it and its token."""
    escaped = pattern[index + 1 : index + 2]
    if escaped in _ESCAPES:
        return _ESCAPES[escaped], index + 2, "atom"
    if escaped == "b":
        return "\\b", index + 2, "assertion"
    if escaped == "B":
        # Python's \B never matches an empty string; ECMA-262's does.
        return r"(?:\B|^\Z)", index + 2, "assertion"
    if escaped == "k":
        end = pattern.find(">", index + 3)
        if not pattern.startswith("<", index + 2) or end < 0:
            raise re.error("invalid named backreference")
        return f"(?P={pattern[index + 3 : end]})", end + 1, "atom"
    text, end = _escape(pattern, index, in_class=False, strict=strict)
    return text, end, "atom"


def _class_atom(pattern: str, index: int, strict: bool) -> tuple[str, str, int]:
    """Return one class atom as Python class text, its kind and the index after it.

    The kind is "char" for one character, "set" for ``\\d``, ``\\w`` and ``\\s``,
    and "complement" for ``\\D``, ``\\W`` and ``\\S``, whose text is the set they
    exclude.
    """
    if pattern[index] != "\\":
        return pattern[index], "char", index + 1
    escaped = pattern[index + 1 : index + 2]
    if escaped in _CLASS_ESCAPES:
        return _CLASS_ESCAPES[escaped], "set", index + 2
    if escaped in _COMPLEMENTS:
        return _COMPLEMENTS[escaped], "complement", index + 2
    if escaped == "B":
        raise re.error("\\B has no meaning inside a character class")
    text, end = _escape(pattern, index, in_class=True, strict=strict)
    return text, "char", end


def _character_class(pattern: str, index: int, strict: bool) -> tuple[str, int]:
    """Translate the class that starts at ``index``; return it and the index after it."""
    index += 1
    negated = pattern.startswith("^", index)
    if negated:
        index += 1
    if pattern.startswith("]", index):
        raise re.error("empty or ambiguous character class")
    members: list[str] = []
    complements: list[str] = []
    while not pattern.startswith("]", index):
        if index >= len(pattern):
            raise re.error("unterminated character class")
        low, kind, index = _class_atom(pattern, index, strict)
        if pattern.startswith("-", index) and pattern[index + 1 : index + 2] not in ("", "]"):
            high, high_kind, index = _class_atom(pattern, index + 1, strict)
            if kind != "char" or high_kind != "char":
                # Annex B reads [%-\w] as a union and the u flag rejects it; Python
                # would read the expansion as a wider range, so refuse it.
                raise re.error("a class escape cannot bound a character range")
            members.append(f"{low}-{high}")
        elif kind == "complement":
            complements.append(low)
        else:
            members.append(low)
    index += 1
    positive = "".join(members)
    if not complements:
        return ("[^" if negated else "[") + positive + "]", index
    # Python classes cannot hold a complement, so express the class with
    # alternatives and lookaheads that each test the same single character.
    positive = "\\" + positive if positive.startswith("^") else positive
    if not negated:
        options = [f"[{positive}]"] if positive else []
        options.extend(f"[^{excluded}]" for excluded in complements)
        return "(?:" + "|".join(options) + ")", index
    guard = f"(?![{positive}])" if positive else ""
    guard += "".join(f"(?=[{excluded}])" for excluded in complements[:-1])
    return f"(?:{guard}[{complements[-1]}])", index


class _EcmaRegex:
    """The part of the ``re`` module jsonschema uses, with ECMA-262 pattern meaning."""

    error = re.error

    def __init__(self) -> None:
        self._compiled: dict[str, re.Pattern[str]] = {}

    def compile(self, pattern: str, flags: int = 0) -> re.Pattern[str]:
        if flags:
            raise re.error("pattern flags are not supported")
        compiled = self._compiled.get(pattern)
        if compiled is None:
            compiled = re.compile(ecma_pattern(pattern), re.ASCII)
            self._compiled[pattern] = compiled
        return compiled

    def search(self, pattern: str, string: str, flags: int = 0) -> re.Match[str] | None:
        return self.compile(pattern, flags).search(string)

    def __getattr__(self, name: str) -> Any:
        return getattr(re, name)


def _load_dialects() -> dict[str, Any]:
    import jsonschema._format
    import jsonschema._keywords
    import jsonschema._legacy_keywords
    import jsonschema._utils
    from jsonschema import (
        Draft4Validator,
        Draft6Validator,
        Draft7Validator,
        Draft201909Validator,
        Draft202012Validator,
    )

    # jsonschema evaluates "pattern", "patternProperties" and the keywords that
    # consult them with re.search; route every such call through ECMA semantics.
    regex = _EcmaRegex()
    for module in (
        jsonschema._format,
        jsonschema._keywords,
        jsonschema._legacy_keywords,
        jsonschema._utils,
    ):
        module.re = regex  # type: ignore[attr-defined]
    validators = (
        Draft4Validator,
        Draft6Validator,
        Draft7Validator,
        Draft201909Validator,
        Draft202012Validator,
    )
    return dict(zip(DIALECTS, validators, strict=True))


# Each schema rejects its instance only when patterns have ECMA-262 meaning, through
# each place jsonschema evaluates one: pattern, patternProperties, and the
# additionalProperties and unevaluatedProperties checks that consult it.
_SELF_CHECKS: tuple[tuple[dict[str, Any], Any], ...] = (
    ({"pattern": "^a$"}, "a\n"),
    ({"pattern": "^\\d$"}, "\u0663"),
    ({"patternProperties": {"^\\s$": {"type": "string"}}}, {"\ufeff": 0}),
    ({"patternProperties": {"^a$": {}}, "additionalProperties": False}, {"a\n": 0}),
    ({"patternProperties": {"^a$": {}}, "unevaluatedProperties": False}, {"a\n": 0}),
)


def _ecma_semantics_hold(dialects: dict[str, Any]) -> bool:
    """Confirm that every dialect evaluates patterns through the ECMA-262 translation.

    The translation is installed on private jsonschema modules. A release that moved
    a regex call would silently bring back Python semantics, so the worker then
    refuses to start and every call fails closed.
    """
    from jsonschema.exceptions import SchemaError
    from referencing import Registry

    for validator in dialects.values():
        try:
            validator.check_schema({"pattern": "(?i)a"})
        except SchemaError:
            pass
        else:
            return False
        for schema, instance in _SELF_CHECKS:
            if not set(schema) <= set(validator.VALIDATORS):
                continue
            if validator(schema, registry=Registry()).is_valid(instance):
                return False
    return True


# Keywords whose values hold subschemas in some supported dialect, by shape.
_SUBSCHEMA = frozenset(
    {
        "additionalItems",
        "additionalProperties",
        "contains",
        "contentSchema",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    }
)
_SUBSCHEMA_LISTS = frozenset({"allOf", "anyOf", "items", "oneOf", "prefixItems"})
_SUBSCHEMA_MAPS = frozenset(
    {"$defs", "definitions", "dependencies", "dependentSchemas", "patternProperties", "properties"}
)


def _ignores_a_keyword(
    schema: dict[str, Any], known: frozenset[str], every: frozenset[str], legacy_ref: bool
) -> bool:
    """Whether the schema holds a constraint that its declared dialect does not apply.

    A keyword of another supported dialect, or one next to "$ref" in draft-04 to
    draft-07, which ignore the siblings of "$ref", reads as a constraint to whoever
    approves the schema but is not enforced. "format" is never asserted here.
    """
    pending: list[Any] = [schema]
    seen: set[int] = set()
    while pending:
        node = pending.pop()
        if not isinstance(node, dict) or id(node) in seen:
            continue
        seen.add(id(node))
        used = every.intersection(node)
        if used - known or (legacy_ref and "$ref" in node and used - {"$ref", "format"}):
            return True
        for keyword, value in node.items():
            if keyword in _SUBSCHEMA_MAPS and isinstance(value, dict):
                pending.extend(value.values())
            elif keyword in _SUBSCHEMA_LISTS and isinstance(value, list):
                pending.extend(value)
            elif keyword in _SUBSCHEMA:
                pending.append(value)
        reference = node.get("$ref")
        if isinstance(reference, str) and reference.startswith("#/"):
            pending.append(_pointer(schema, reference))
    return False


def _pointer(document: Any, reference: str) -> Any:
    """Resolve a same-document JSON Pointer reference such as "#/$defs/a", else None."""
    node = document
    for token in unquote(reference[1:]).split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and token in node:
            node = node[token]
        elif isinstance(node, list) and token.isascii() and token.isdigit():
            if int(token) >= len(node):
                return None
            node = node[int(token)]
        else:
            return None
    return node


def _evaluate(dialects: dict[str, Any], schema: dict[str, Any], arguments: Any) -> bytes:
    from jsonschema.exceptions import SchemaError
    from jsonschema.exceptions import ValidationError as SchemaValidationError
    from referencing import Registry
    from referencing.exceptions import Unresolvable

    declared = schema.get("$schema", DIALECTS[-1])
    if not isinstance(declared, str):
        return _SCHEMA
    dialect = declared.removesuffix("#")
    validator = dialects.get(dialect)
    if validator is None:
        return _SCHEMA
    every = frozenset().union(*(other.VALIDATORS for other in dialects.values()))
    try:
        validator.check_schema(schema)
        if _ignores_a_keyword(
            schema, frozenset(validator.VALIDATORS), every, dialect in DIALECTS[:3]
        ):
            return _SCHEMA
        validator(schema, registry=Registry()).validate(arguments)
    except SchemaValidationError:
        return _INVALID
    except (SchemaError, Unresolvable, re.error):
        return _SCHEMA
    return _VALID


def _worker() -> int:
    """Internal fixed-protocol worker; failure details never echo input values."""
    try:
        if os.name != "posix":
            return 1
        import resource

        resource.setrlimit(
            resource.RLIMIT_CPU, (WORKER_STARTUP_CPU_SECONDS, WORKER_STARTUP_CPU_SECONDS)
        )
        resource.setrlimit(resource.RLIMIT_AS, (WORKER_MEMORY_BYTES, WORKER_MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        _disable_unused_format_checkers()
        dialects = _load_dialects()
        if not _ecma_semantics_hold(dialects):
            return 1
        # RLIMIT_CPU counts the whole process, so measure start-up and grant the
        # evaluation at least WORKER_CPU_SECONDS on top of what was already used.
        usage = resource.getrusage(resource.RUSAGE_SELF)
        budget = math.ceil(usage.ru_utime + usage.ru_stime) + WORKER_CPU_SECONDS
        resource.setrlimit(resource.RLIMIT_CPU, (budget, budget))
        sys.stdout.buffer.write(_READY)
        sys.stdout.buffer.flush()
        maximum = MAX_SCHEMA_BYTES + MAX_ARGUMENT_BYTES + 64
        wire = sys.stdin.buffer.read(maximum + 1)
        if len(wire) > maximum:
            return 1
        request = json.loads(wire)
        if not isinstance(request, dict) or set(request) != {"schema", "arguments"}:
            return 1
        schema, arguments = request["schema"], request["arguments"]
        if not isinstance(schema, dict) or not isinstance(arguments, dict):
            return 1
        check_json_budget(schema, maximum=MAX_SCHEMA_BYTES)
        check_json_budget(arguments, maximum=MAX_ARGUMENT_BYTES)
        sys.stdout.buffer.write(_evaluate(dialects, schema, arguments))
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(_worker())
