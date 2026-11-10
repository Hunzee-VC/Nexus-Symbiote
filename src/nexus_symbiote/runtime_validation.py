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


def ecma_pattern(pattern: str) -> str:
    """Translate an ECMA-262 pattern into a Python pattern with the same meaning.

    JSON Schema patterns are ECMA-262 expressions. Python's ``$`` also matches
    before a final newline, and its ``\\d``, ``\\w`` and ``.`` differ for
    non-ASCII input, so a value the author excluded could pass. Syntax whose
    meaning differs and cannot be translated, such as inline flags or Python-only
    escapes, raises ``re.error`` and makes the schema invalid.
    """
    out: list[str] = []
    index = 0
    in_class = False
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            if index + 1 >= len(pattern):
                raise re.error("pattern ends with a backslash")
            escaped = pattern[index + 1]
            index += 2
            if escaped.isascii() and escaped.isalpha():
                if in_class and escaped in _CLASS_ESCAPES:
                    out.append(_CLASS_ESCAPES[escaped])
                    continue
                if in_class and escaped in "DSW":
                    raise re.error("negated class escape inside a character class")
                if not in_class and escaped in _ESCAPES:
                    out.append(_ESCAPES[escaped])
                    continue
                if not in_class and escaped == "k":
                    end = pattern.find(">", index)
                    if not pattern.startswith("<", index) or end < 0:
                        raise re.error("invalid named backreference")
                    out.append(f"(?P={pattern[index + 1 : end]})")
                    index = end + 1
                    continue
                if escaped not in "bBfnrtvxu":
                    raise re.error("escape is not an ECMA-262 escape")
            out.append("\\" + escaped)
            continue
        if in_class:
            in_class = char != "]"
            out.append(char)
            index += 1
            continue
        if char == "[":
            in_class = True
            out.append(char)
            index += 1
            if pattern.startswith("^", index):
                out.append("^")
                index += 1
            if pattern.startswith("]", index):
                raise re.error("empty or ambiguous character class")
            continue
        if char == "(" and pattern.startswith("(?", index):
            prefix = next((group for group in _GROUPS if pattern.startswith(group, index)), None)
            if prefix is not None:
                out.append(prefix)
                index += len(prefix)
                continue
            if pattern.startswith("(?<", index):
                out.append("(?P<")
                index += 3
                continue
            raise re.error("group syntax is not ECMA-262")
        out.append(_ANY if char == "." else r"\Z" if char == "$" else char)
        index += 1
    if in_class:
        raise re.error("unterminated character class")
    return "".join(out)


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


def _evaluate(dialects: dict[str, Any], schema: dict[str, Any], arguments: Any) -> bytes:
    from jsonschema.exceptions import SchemaError
    from jsonschema.exceptions import ValidationError as SchemaValidationError
    from referencing import Registry
    from referencing.exceptions import Unresolvable

    declared = schema.get("$schema", DIALECTS[-1])
    if not isinstance(declared, str):
        return _SCHEMA
    validator = dialects.get(declared.removesuffix("#"))
    if validator is None:
        return _SCHEMA
    try:
        validator.check_schema(schema)
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
