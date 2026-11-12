"""After tools/call is sent, a failure is an unknown or server-reported outcome, never a denial."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest

from nexus_symbiote.live.session import ExecutionOutcomeUnknown, ToolCallError, invoke_pinned_stdio
from nexus_symbiote.runtime import AuthorizationError
from tests.test_runtime_authorization import DEFINITION, fixture
from tests.test_runtime_stdio_session import signed_inputs

NOTE = {"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info"}}


def launcher(tmp_path: Path, mode: str) -> tuple[Path, str, Path]:
    log = tmp_path / "calls.jsonl"
    path = tmp_path / "launcher"
    path.write_text(
        f"""#!/usr/bin/python3
import json, os, sys, time
definition = {DEFINITION!r}
note = {NOTE!r}
mode = {mode!r}
for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    if method == "notifications/initialized":
        continue
    reply = {{"jsonrpc": "2.0", "id": msg["id"]}}
    if method == "initialize":
        reply["result"] = {{"protocolVersion": "2025-11-25", "capabilities": {{"tools": {{}}}}, "serverInfo": {{"name": "t", "version": "1"}}}}
    elif method == "tools/list":
        if mode == "notify":
            print(json.dumps(note), flush=True)
        reply["result"] = {{"tools": [definition]}}
    elif method == "tools/call":
        with open({str(log)!r}, "a") as f:
            f.write(json.dumps([method, msg["params"]]) + "\\n")
        if mode == "notify":
            print(json.dumps(note), flush=True)
            print(json.dumps({{**note, "method": "notifications/progress"}}), flush=True)
        if mode == "error":
            reply["error"] = {{"code": -32602, "message": "secret detail"}}
        elif mode == "stall":
            time.sleep(30)
        elif mode == "slow":
            time.sleep(1.5)
            reply["result"] = {{"content": [{{"type": "text", "text": "ok"}}]}}
        elif mode == "garbage":
            print("not json", flush=True)
            continue
        else:
            reply["result"] = {{"content": [{{"type": "text", "text": "ok"}}]}}
    print(json.dumps(reply), flush=True)
"""
    )
    path.chmod(0o700)
    return path, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(), log


def call(tmp_path: Path, mode: str, **kwargs):
    values = fixture(tmp_path)
    path, pin, log = launcher(tmp_path, mode)
    outcome = invoke_pinned_stdio(
        values[0], values[1], command=str(path), sha256=pin, **signed_inputs(values, pin), **kwargs
    )
    return outcome, log


def test_notifications_before_list_and_call_replies_are_skipped(tmp_path):
    outcome, log = call(tmp_path, "notify")
    assert outcome["content"][0]["text"] == "ok"
    assert len(log.read_text().splitlines()) == 1


def test_json_rpc_error_reply_is_a_tool_call_error_not_a_denial(tmp_path):
    with pytest.raises(ToolCallError) as caught:
        call(tmp_path, "error")
    assert not isinstance(caught.value, AuthorizationError)
    assert caught.value.code == -32602
    assert "secret detail" not in str(caught.value)


@pytest.mark.parametrize("mode", ["stall", "garbage"])
def test_failure_after_dispatch_is_an_unknown_outcome(tmp_path, mode):
    started = time.monotonic()
    with pytest.raises(ExecutionOutcomeUnknown) as caught:
        call(tmp_path, mode, call_deadline_seconds=0.5)
    assert not isinstance(caught.value, AuthorizationError)
    assert time.monotonic() - started < 10
    # The call reached the server: the approval is spent and the tool may have run.
    assert [
        json.loads(line)[0] for line in (tmp_path / "calls.jsonl").read_text().splitlines()
    ] == ["tools/call"]


def test_call_deadline_is_separate_from_the_handshake_deadline(tmp_path, monkeypatch):
    # A tool that runs longer than the whole handshake budget still completes,
    # because tools/call gets its own deadline instead of the handshake's remainder.
    monkeypatch.setattr("nexus_symbiote.live.session.DEADLINE_SECONDS", 1.0)
    outcome, _ = call(tmp_path, "slow", call_deadline_seconds=5)
    assert outcome["content"][0]["text"] == "ok"
