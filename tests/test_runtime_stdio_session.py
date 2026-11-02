from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from nexus_symbiote.live.session import PinnedStdioSession, invoke_pinned_stdio
from nexus_symbiote.runtime import AuthorizationError, digest, sign_contract
from tests.test_runtime_authorization import DEFINITION, fixture


def launcher(
    tmp_path: Path, *, altered: bool = False, missing: bool = False, mode: str = "normal"
) -> tuple[Path, str, Path]:
    log = tmp_path / "calls.jsonl"
    path = tmp_path / "launcher"
    definition = dict(DEFINITION)
    if altered:
        definition["description"] = "changed after approval"
    script = f"""#!/usr/bin/python3
import json, os, sys, time
definition = {definition!r}
log = {str(log)!r}
mode = {mode!r}
for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    if method == "notifications/initialized":
        continue
    if method == "initialize":
        result = {{"protocolVersion": "2025-06-18", "capabilities": {{"tools": {{}}}}, "serverInfo": {{"name": "test", "version": "1"}}}}
    elif method == "tools/list":
        with open(log, "a") as f:
            f.write(json.dumps([method, os.getpid()]) + "\\n")
        if mode == "exit":
            raise SystemExit(1)
        if mode == "stall":
            time.sleep(30)
        result = {{"tools": [] if {missing!r} else [definition]}}
    elif method == "tools/call":
        with open(log, "a") as f:
            f.write(json.dumps([method, os.getpid(), msg["params"]]) + "\\n")
        result = {{"content": [{{"type": "text", "text": "ok"}}]}}
    else:
        raise SystemExit(1)
    reply_id = msg["id"] + 1 if method == "tools/list" and mode == "wrong-id" else msg["id"]
    print(json.dumps({{"jsonrpc": "2.0", "id": reply_id, "result": result}}), flush=True)
"""
    path.write_text(script)
    path.chmod(0o700)
    return path, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(), log


def signed_inputs(values, pin):
    gateway, call, bom, snapshot, status, approval, release, human, trust, executed = values
    grant = snapshot.tools[0].model_copy(update={"endpoint_identity": "stdio+launcher:" + pin})
    snapshot = snapshot.model_copy(update={"tools": (grant,)})
    approval = approval.model_copy(
        update={"snapshot_digest": digest(snapshot.model_dump(mode="json"))}
    )
    return {
        "snapshot": sign_contract(snapshot, "snapshot", (release,)),
        "trust": sign_contract(status, "trust", (trust,)),
        "bom": bom,
        "approval": sign_contract(approval, "approval", (human,)),
    }


def test_authorized_call_uses_same_pinned_process_and_consumes_nonce(tmp_path):
    values = fixture(tmp_path)
    path, pin, log = launcher(tmp_path)
    kwargs = signed_inputs(values, pin)
    result = invoke_pinned_stdio(values[0], values[1], command=str(path), sha256=pin, **kwargs)
    assert result["content"][0]["text"] == "ok"
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r[0] for r in records] == ["tools/list", "tools/call"]
    assert records[0][1] == records[1][1]
    assert records[1][2] == {"name": "send", "arguments": {"to": "team@example.test"}}
    assert values[-1] == []  # The gateway's separate executor was never called.
    with pytest.raises(AuthorizationError, match="already been used"):
        invoke_pinned_stdio(values[0], values[1], command=str(path), sha256=pin, **kwargs)
    assert len(log.read_text().splitlines()) == 3  # Second process listed but did not call.


def test_changed_descriptor_denied_before_call(tmp_path):
    values = fixture(tmp_path)
    path, pin, log = launcher(tmp_path, altered=True)
    with pytest.raises(AuthorizationError, match="descriptor changed"):
        invoke_pinned_stdio(
            values[0], values[1], command=str(path), sha256=pin, **signed_inputs(values, pin)
        )
    assert [json.loads(line)[0] for line in log.read_text().splitlines()] == ["tools/list"]


def test_wrong_launcher_pin_never_starts_process(tmp_path):
    values = fixture(tmp_path)
    path, _, log = launcher(tmp_path)
    pin = "sha256:" + "0" * 64
    with pytest.raises(AuthorizationError, match="differs"):
        invoke_pinned_stdio(
            values[0], values[1], command=str(path), sha256=pin, **signed_inputs(values, pin)
        )
    assert not log.exists()


def test_session_is_single_use_and_rejects_wrong_server(tmp_path):
    path, pin, _ = launcher(tmp_path)
    session = PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail")
    with session, pytest.raises(AuthorizationError, match="server mismatch"):
        session.describe("server:other", "send")
    with pytest.raises(AuthorizationError, match="reused"), session:
        pass


def test_concurrent_replay_allows_only_one_call(tmp_path):
    values = fixture(tmp_path)
    path, pin, log = launcher(tmp_path)
    kwargs = signed_inputs(values, pin)

    def request():
        try:
            invoke_pinned_stdio(values[0], values[1], command=str(path), sha256=pin, **kwargs)
            return "executed"
        except AuthorizationError as exc:
            assert "already been used" in str(exc)
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: request(), range(2)))
    assert sorted(results) == ["denied", "executed"]
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert sum(row[0] == "tools/call" for row in records) == 1


def test_session_rejects_call_for_different_tool_and_repeat(tmp_path):
    values = fixture(tmp_path)
    path, pin, log = launcher(tmp_path)
    with PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail") as session:
        session.describe("server:mail", "send")
        with pytest.raises(AuthorizationError, match="described session"):
            session.execute(values[1].model_copy(update={"tool_name": "other"}))
        session.execute(values[1])
        with pytest.raises(AuthorizationError, match="described session"):
            session.execute(values[1])
    assert [json.loads(line)[0] for line in log.read_text().splitlines()] == [
        "tools/list",
        "tools/call",
    ]


def test_failed_descriptor_lookup_cannot_enable_execution(tmp_path):
    values = fixture(tmp_path)
    path, pin, log = launcher(tmp_path, missing=True)
    with PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail") as session:
        with pytest.raises(AuthorizationError, match="missing"):
            session.describe("server:mail", "send")
        with pytest.raises(AuthorizationError, match="described session"):
            session.execute(values[1])
        with pytest.raises(AuthorizationError, match="repeated"):
            session.describe("server:mail", "send")
    assert [json.loads(line)[0] for line in log.read_text().splitlines()] == ["tools/list"]


def test_symlink_launcher_is_rejected(tmp_path):
    path, pin, log = launcher(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with (
        pytest.raises((OSError, ValueError)),
        PinnedStdioSession(command=str(alias), sha256=pin, server_id="server:mail"),
    ):
        pass
    assert not log.exists()


@pytest.mark.parametrize("mode", ["wrong-id", "exit", "stall"])
def test_protocol_failure_kills_and_reaps_process(tmp_path, monkeypatch, mode):
    values = fixture(tmp_path)
    path, pin, log = launcher(tmp_path, mode=mode)
    monkeypatch.setattr("nexus_symbiote.live.session.DEADLINE_SECONDS", 0.5)
    with pytest.raises((AuthorizationError, OSError, ValueError)):
        invoke_pinned_stdio(
            values[0], values[1], command=str(path), sha256=pin, **signed_inputs(values, pin)
        )
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r[0] for r in records] == ["tools/list"]
    with pytest.raises(ProcessLookupError):
        os.kill(records[0][1], 0)


@pytest.mark.parametrize(
    "failure", ["workload", "changed-workload", "scope", "endpoint", "revocation", "approval"]
)
def test_gateway_gates_prevent_real_process_tool_calls(tmp_path, failure):
    values = list(fixture(tmp_path))
    gateway, call, _, snapshot, status, approval, _, human, trust_key, _ = values
    path, pin, log = launcher(tmp_path)
    kwargs = signed_inputs(values, pin)
    if failure == "workload":
        context = gateway.authenticate()
        gateway.authenticate = lambda: context.model_copy(update={"tenant": "other"})
    elif failure == "changed-workload":
        context = gateway.authenticate()
        calls = iter([context, context.model_copy(update={"tenant": "other"})])
        gateway.authenticate = lambda: next(calls)
    elif failure == "scope":
        gateway.resolve_scope = lambda _: ("send", "mailbox:admin")
    elif failure == "endpoint":
        kwargs = signed_inputs(values, "sha256:" + "f" * 64)
    elif failure == "revocation":
        status = status.model_copy(update={"revoked_tools": (snapshot.tools[0].definition_digest,)})
        kwargs["trust"] = sign_contract(status, "trust", (trust_key,))
    elif failure == "approval":
        approval = approval.model_copy(update={"request_digest": "sha256:" + "0" * 64})
        kwargs["approval"] = sign_contract(approval, "approval", (human,))
    with pytest.raises(AuthorizationError):
        invoke_pinned_stdio(gateway, call, command=str(path), sha256=pin, **kwargs)
    records = [json.loads(line)[0] for line in log.read_text().splitlines()] if log.exists() else []
    assert "tools/call" not in records
