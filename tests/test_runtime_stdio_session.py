from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from nexus_symbiote.live.session import PinnedStdioSession, invoke_pinned_stdio
from nexus_symbiote.runtime import AuthorizationError, digest, sign_contract
from tests.test_runtime_authorization import DEFINITION, fixture


def launcher(tmp_path: Path, *, altered: bool = False) -> tuple[Path, str, Path]:
    log = tmp_path / "calls.jsonl"
    path = tmp_path / "launcher"
    definition = dict(DEFINITION)
    if altered:
        definition["description"] = "changed after approval"
    script = f"""#!/usr/bin/python3
import json, os, sys
definition = {definition!r}
log = {str(log)!r}
for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    if method == "notifications/initialized":
        continue
    if method == "initialize":
        result = {{"protocolVersion": "2025-06-18", "capabilities": {{"tools": {{}}}}}}
    elif method == "tools/list":
        with open(log, "a") as f:
            f.write(json.dumps([method, os.getpid()]) + "\\n")
        result = {{"tools": [definition]}}
    elif method == "tools/call":
        with open(log, "a") as f:
            f.write(json.dumps([method, os.getpid(), msg["params"]]) + "\\n")
        result = {{"content": [{{"type": "text", "text": "ok"}}]}}
    else:
        raise SystemExit(1)
    print(json.dumps({{"jsonrpc": "2.0", "id": msg["id"], "result": result}}), flush=True)
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
