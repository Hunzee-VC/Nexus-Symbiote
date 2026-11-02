"""Availability regressions for approved schemas and caller-controlled arguments."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

import nexus_symbiote.runtime as runtime
import nexus_symbiote.runtime_validation as validation
from tests.test_runtime_authorization import fixture, invoke


def test_valid_schema_and_arguments_execute_through_gateway(tmp_path):
    values = fixture(tmp_path)
    assert invoke(values) == "executed"
    assert len(values[-1]) == 1


def test_worker_ignores_project_module_and_pythonpath(tmp_path, monkeypatch):
    marker = tmp_path / "executed"
    (tmp_path / "nexus_symbiote.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    validation.validate_arguments({"type": "object"}, {})
    assert not marker.exists()


def test_pathological_approved_regex_is_terminated_outside_gateway_process():
    # The outer deadline also protects the test runner if worker isolation is
    # accidentally removed and the gateway returns to inline regex validation.
    source = """
from nexus_symbiote.runtime import AuthorizationError, _validate_arguments
schema = {"type": "object", "properties": {
    "payload": {"type": "string", "pattern": "^(a+)+$"}
}}
try:
    _validate_arguments(schema, {"payload": "a" * 30 + "!"})
except AuthorizationError:
    print("denied")
else:
    raise SystemExit("unsafe schema input accepted")
"""
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", source],
        capture_output=True,
        env={"PATH": os.defpath},
        timeout=5,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.stdout == b"denied\n"


def test_missing_approval_is_denied_before_schema_evaluation(tmp_path, monkeypatch):
    def unexpected(*_):
        pytest.fail("schema evaluation must not run without required approval")

    monkeypatch.setattr(runtime, "_validate_arguments", unexpected)
    values = fixture(tmp_path)
    with pytest.raises(runtime.AuthorizationError, match="operation-bound approval required"):
        invoke(values, approval=None)
    assert values[-1] == []


def test_revoked_tool_is_denied_before_schema_evaluation(tmp_path, monkeypatch):
    def unexpected(*_):
        pytest.fail("schema evaluation must not run for a revoked tool")

    monkeypatch.setattr(runtime, "_validate_arguments", unexpected)
    values = list(fixture(tmp_path))
    values[4] = values[4].model_copy(
        update={"revoked_tools": (values[3].tools[0].definition_digest,)}
    )
    with pytest.raises(runtime.AuthorizationError, match="revoked"):
        invoke(values)
    assert values[-1] == []


def test_validation_failure_preserves_approval_for_retry(tmp_path, monkeypatch):
    values = fixture(tmp_path)

    def unavailable(*_):
        raise validation.ValidationBudgetError("worker unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(runtime, "validate_arguments", unavailable)
        with pytest.raises(runtime.AuthorizationError, match="offline input schema"):
            invoke(values)
    assert values[-1] == []
    assert invoke(values) == "executed"


@pytest.mark.parametrize("kind", ["arguments", "schema", "depth", "nodes", "cycle"])
def test_oversized_or_overcomplex_json_is_denied_before_worker_start(kind, monkeypatch):
    def unexpected(*_, **__):
        pytest.fail("budget violation must not start a worker")

    monkeypatch.setattr(validation.subprocess, "run", unexpected)
    schema = {"type": "object"}
    arguments = {}
    if kind == "arguments":
        arguments["payload"] = "a" * validation.MAX_ARGUMENT_BYTES
    elif kind == "schema":
        schema["description"] = "a" * validation.MAX_SCHEMA_BYTES
    elif kind == "depth":
        nested = {}
        arguments["payload"] = nested
        for _ in range(validation.MAX_JSON_DEPTH + 1):
            child = {}
            nested["child"] = child
            nested = child
    elif kind == "nodes":
        arguments["payload"] = [0] * validation.MAX_JSON_NODES
    else:
        arguments["payload"] = arguments
    with pytest.raises(validation.ValidationBudgetError):
        validation.validate_arguments(schema, arguments)


@pytest.mark.parametrize(
    ("returncode", "stdout"), [(-9, b""), (1, b"valid\n"), (0, b""), (0, b"valid\nextra")]
)
def test_worker_crash_or_invalid_protocol_fails_closed(returncode, stdout, monkeypatch):
    monkeypatch.setattr(
        validation.subprocess,
        "run",
        lambda *_, **__: subprocess.CompletedProcess([], returncode, stdout=stdout),
    )
    with pytest.raises(validation.ValidationBudgetError):
        validation.validate_arguments({"type": "object"}, {})


def test_worker_timeout_fails_closed_and_releases_capacity(monkeypatch):
    def timed_out(*_, **__):
        raise subprocess.TimeoutExpired("worker", validation.WORKER_TIMEOUT_SECONDS)

    with monkeypatch.context() as patch:
        patch.setattr(validation.subprocess, "run", timed_out)
        with pytest.raises(validation.ValidationBudgetError, match="timed out"):
            validation.validate_arguments({"type": "object"}, {})
    validation.validate_arguments({"type": "object"}, {})


def test_concurrent_worker_capacity_exhaustion_denies_without_waiting():
    acquired = 0
    try:
        while validation._WORKER_SLOTS.acquire(blocking=False):
            acquired += 1
        with pytest.raises(validation.ValidationBudgetError, match="capacity unavailable"):
            validation.validate_arguments({"type": "object"}, {})
    finally:
        for _ in range(acquired):
            validation._WORKER_SLOTS.release()
