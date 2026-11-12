"""A canonical gateway resolves, validates and executes one form of the arguments.

With ``canonical_arguments=True`` the executor receives the RFC 8785 form that the
approval binds. RFC 8785 writes 1.0 as 1, orders keys, and writes a float of 2**53
or more below 1e21 as an integer whose value can differ from the float's, so the
scope resolver and the schema check must judge that form, not the one sent.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

import nexus_symbiote.runtime as runtime
from nexus_symbiote.live.session import invoke_pinned_stdio
from nexus_symbiote.runtime import (
    AuthorizationError,
    ServedTool,
    canonical_bytes,
    digest,
    request_digest,
    sign_contract,
    tool_definition_digest,
)
from tests.test_runtime_authorization import fixture

DRAFT_04 = "http://json-schema.org/draft-04/schema#"
ROUTES = ("invoke", "pinned-stdio")
VALIDATE = runtime.validate_arguments
TWO_TO_THE_60 = 2.0**60


def draft_04(value_schema: dict[str, Any]) -> dict[str, Any]:
    return {"$schema": DRAFT_04, "type": "object", "properties": {"n": value_schema}}


NOT_INTEGER = draft_04({"type": "number", "not": {"type": "integer"}})
INTEGERS_UP_TO_10 = draft_04(
    {"anyOf": [{"type": "integer", "maximum": 10}, {"type": "number", "not": {"type": "integer"}}]}
)
INTEGER_OR_NUMBER = draft_04({"oneOf": [{"type": "integer"}, {"type": "number"}]})
NON_INTEGRAL_ITEMS = draft_04(
    {"type": "array", "items": {"type": "number", "not": {"type": "integer"}}}
)
EXACTLY_2_TO_THE_60 = {
    "type": "object",
    "properties": {
        "n": {"type": "integer", "const": 1.152921504606847e18, "maximum": 1.152921504606847e18}
    },
}
ANY_OBJECT = {"type": "object"}


@dataclass
class Outcome:
    """The decision and the argument forms each party saw, as ``json.dumps`` text."""

    reason: str
    resolved: list[str] = field(default_factory=list)
    validated: list[str] = field(default_factory=list)
    executed: list[str] = field(default_factory=list)


def launcher(directory: Path, definition: dict[str, Any]) -> tuple[Path, str, Path]:
    """A pinned stdio server that serves ``definition`` and logs the arguments it parsed."""
    log = directory / "calls.jsonl"
    path = directory / "launcher"
    path.write_text(
        f"""#!{sys.executable}
import json, sys
definition = {definition!r}
for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    if method == "notifications/initialized":
        continue
    if method == "initialize":
        result = {{"protocolVersion": "2025-06-18", "capabilities": {{"tools": {{}}}},
                  "serverInfo": {{"name": "test", "version": "1"}}}}
    elif method == "tools/list":
        result = {{"tools": [definition]}}
    elif method == "tools/call":
        with open({str(log)!r}, "a") as f:
            f.write(json.dumps(msg["params"]["arguments"]) + "\\n")
        result = {{"content": [{{"type": "text", "text": "ok"}}]}}
    else:
        raise SystemExit(1)
    print(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": result}}), flush=True)
"""
    )
    path.chmod(0o700)
    return path, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(), log


def through(
    route: str,
    directory: Path,
    monkeypatch: pytest.MonkeyPatch,
    schema: dict[str, Any],
    arguments: dict[str, Any],
    *,
    canonical: bool,
    resolve: Any = None,
    action: str = "send",
    resource: str = "mailbox:team",
) -> Outcome:
    """Send one approved call through ``invoke`` or ``invoke_pinned_stdio``."""
    values = list(fixture(directory))
    gateway, call, bom, snapshot, statuses, approval, release, human, status, executed = values
    definition = {"name": "send", "description": "Send a message", "inputSchema": schema}
    if route == "pinned-stdio":
        path, pin, log = launcher(directory, definition)
        endpoint = "stdio+launcher:" + pin
    else:
        endpoint = snapshot.tools[0].endpoint_identity
        gateway.describe = lambda *_: ServedTool(endpoint_identity=endpoint, definition=definition)
    grant = snapshot.tools[0].model_copy(
        update={
            "endpoint_identity": endpoint,
            "definition_digest": tool_definition_digest(definition),
            "actions": (action,),
            "resources": (resource,),
        }
    )
    snapshot = snapshot.model_copy(update={"tools": (grant,)})
    call = call.model_copy(update={"action": action, "resource": resource, "arguments": arguments})
    outcome = Outcome(reason="executed")
    try:
        req_digest = request_digest(call)
    except AuthorizationError as exc:
        outcome.reason = exc.reason
        return outcome
    approval = approval.model_copy(
        update={
            "snapshot_digest": digest(snapshot.model_dump(mode="json")),
            "request_digest": req_digest,
        }
    )
    scope = resolve or (lambda _: (action, resource))

    def resolve_and_record(seen: runtime.ToolCall) -> tuple[str, str]:
        outcome.resolved.append(json.dumps(seen.arguments))
        return scope(seen)

    def validate_and_record(schema: Any, checked: dict[str, Any]) -> None:
        outcome.validated.append(json.dumps(checked))
        VALIDATE(schema, checked)

    gateway.resolve_scope = resolve_and_record
    gateway.canonical_arguments = canonical
    monkeypatch.setattr(runtime, "validate_arguments", validate_and_record)
    evidence = {
        "snapshot": sign_contract(snapshot, "snapshot", (release,)),
        "trust": sign_contract(statuses, "trust", (status,)),
        "bom": bom,
        "approval": sign_contract(approval, "approval", (human,)),
    }
    try:
        if route == "pinned-stdio":
            invoke_pinned_stdio(gateway, call, command=str(path), sha256=pin, **evidence)
        else:
            gateway.invoke(call, **evidence)
    except AuthorizationError as exc:
        outcome.reason = exc.reason
    if route == "pinned-stdio":
        outcome.executed = log.read_text().splitlines() if log.exists() else []
    else:
        outcome.executed = [json.dumps(admitted.arguments) for admitted in executed]
    return outcome


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize(
    ("schema", "arguments", "reason"),
    [
        pytest.param(NOT_INTEGER, {"n": 1.0}, "arguments-invalid", id="draft-04-not-integer"),
        pytest.param(NOT_INTEGER, {"n": -0.0}, "arguments-invalid", id="draft-04-negative-zero"),
        pytest.param(
            INTEGERS_UP_TO_10, {"n": 1000.0}, "arguments-invalid", id="draft-04-integers-up-to-10"
        ),
        pytest.param(INTEGER_OR_NUMBER, {"n": 5.0}, "arguments-invalid", id="draft-04-one-of"),
        pytest.param(
            NON_INTEGRAL_ITEMS, {"n": [0.5, 2.0]}, "arguments-invalid", id="draft-04-nested"
        ),
        pytest.param(
            EXACTLY_2_TO_THE_60,
            {"n": TWO_TO_THE_60},
            "arguments-number-out-of-range",
            id="2020-12-const-and-maximum",
        ),
        pytest.param(
            ANY_OBJECT, {"n": 2.0**53}, "arguments-number-out-of-range", id="float-2-to-the-53"
        ),
        pytest.param(ANY_OBJECT, {"n": -1e20}, "arguments-number-out-of-range", id="float-1e20"),
        pytest.param(
            ANY_OBJECT,
            {"n": {"ids": [TWO_TO_THE_60]}},
            "arguments-number-out-of-range",
            id="nested-float-2-to-the-60",
        ),
        pytest.param(
            ANY_OBJECT,
            {"n": 2.0**70},
            "arguments-number-out-of-range",
            id="float-2-to-the-70-exponential",
        ),
    ],
)
def test_canonical_gateway_refuses_arguments_whose_executed_form_fails(
    tmp_path, monkeypatch, route, schema, arguments, reason
):
    sent = through(route, tmp_path / "default", monkeypatch, schema, arguments, canonical=False)
    if reason == "arguments-number-out-of-range":
        assert sent.reason == reason
        assert sent.executed == []
    else:
        assert sent.reason == "executed"
        assert len(sent.executed) == 1
    canonical = through(
        route, tmp_path / "canonical", monkeypatch, schema, arguments, canonical=True
    )
    assert canonical.reason == reason
    assert canonical.executed == []


@pytest.mark.parametrize("route", ROUTES)
def test_canonical_gateway_executes_numbers_whose_canonical_form_stays_in_range(
    tmp_path, monkeypatch, route
):
    arguments = {"max": 2.0**53 - 1, "min": -(2.0**53 - 1), "frac": 0.5, "tiny": 5e-324}
    outcome = through(route, tmp_path, monkeypatch, ANY_OBJECT, arguments, canonical=True)
    assert outcome.reason == "executed"
    executed = json.loads(outcome.executed[0])
    assert executed == {"frac": 0.5, "max": 2**53 - 1, "min": -(2**53 - 1), "tiny": 5e-324}
    assert [type(executed[key]) for key in ("frac", "max", "min", "tiny")] == [
        float,
        int,
        int,
        float,
    ]


@pytest.mark.parametrize(
    ("route", "canonical"),
    [("invoke", False), ("invoke", True), ("pinned-stdio", True)],
)
def test_resolver_schema_check_and_executor_see_the_same_arguments(
    tmp_path, monkeypatch, route, canonical
):
    arguments = {
        "zeta": 1.0,
        "alpha": -0.0,
        "to": "team@example.test",
        "list": [2.0, 0.5, {"b": 1, "a": 2.5}],
    }
    outcome = through(route, tmp_path, monkeypatch, ANY_OBJECT, arguments, canonical=canonical)
    assert outcome.reason == "executed"
    form = json.loads(canonical_bytes(arguments)) if canonical else arguments
    assert outcome.resolved == outcome.validated == outcome.executed == [json.dumps(form)]


def first_key_command(call: runtime.ToolCall) -> tuple[str, str]:
    # A backend that runs the command named by the first key, as the docs describe.
    command = next(iter(call.arguments))
    return command, "collection:" + str(call.arguments[command])


@pytest.mark.parametrize("route", ROUTES)
def test_canonical_gateway_resolves_scope_on_the_key_order_it_executes(
    tmp_path, monkeypatch, route
):
    arguments = {"find": "users", "delete": "users"}
    labels = {"action": "find", "resource": "collection:users", "resolve": first_key_command}
    sent = through(
        route, tmp_path / "default", monkeypatch, ANY_OBJECT, arguments, canonical=False, **labels
    )
    assert sent.reason == "executed"
    assert sent.resolved == [json.dumps(arguments)]
    canonical = through(
        route, tmp_path / "canonical", monkeypatch, ANY_OBJECT, arguments, canonical=True, **labels
    )
    assert canonical.reason == "scope-mismatch"
    assert canonical.resolved == [json.dumps({"delete": "users", "find": "users"})]
    assert canonical.validated == canonical.executed == []
