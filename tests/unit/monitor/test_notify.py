"""Webhook notifications, captured by a local http.server (spec/monitoring.md §2 step 6)."""

from __future__ import annotations

import importlib
import json
import logging
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from symbiote.model.enums import Severity
from symbiote.monitor import CycleRecord, MonitorConfig, NotifyTarget, StateStore, notify, run_cycle

from .conftest import NOW

# ``symbiote.monitor.notify`` (the function) shadows the submodule on the package; fetch the module itself.
notify_mod = importlib.import_module("symbiote.monitor.notify")


class _Capture:
    def __init__(self) -> None:
        self.bodies: list[dict[str, Any]] = []
        self.statuses: list[int] = []


@pytest.fixture
def server() -> Iterator[tuple[str, _Capture]]:
    capture = _Capture()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            capture.bodies.append(json.loads(self.rfile.read(length)))
            status = capture.statuses.pop(0) if capture.statuses else 204
            self.send_response(status)
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/hook/s3cr3t-token", capture
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_cycle_notification_payload(
    make_config: Callable[..., MonitorConfig],
    server: tuple[str, _Capture],
    caplog: pytest.LogCaptureFixture,
) -> None:
    url, capture = server
    cfg = make_config("notify:\n  - {type: webhook, url_env: TEST_SYMBIOTE_HOOK, min_severity: high}\n")
    with caplog.at_level(logging.DEBUG):
        rec = run_cycle(
            cfg.agents[0],
            config=cfg,
            state=StateStore(cfg.state_dir),
            now=NOW,
            notify_env={"TEST_SYMBIOTE_HOOK": url},
        )
    assert rec.notifications == [
        {
            "urlEnv": "TEST_SYMBIOTE_HOOK",
            "status": "sent",
            "events": len(capture.bodies[0]["events"]),
            "detail": "HTTP 204",
        }
    ]
    body = capture.bodies[0]
    assert (
        body["source"] == "symbiote-monitor"
        and body["agent"] == "triage-agent"
        and body["status"] == "findings"
    )
    assert body["events"] and all(e["severity"] in ("critical", "high") for e in body["events"])
    assert any(e["type"] == "new-finding" and e["check"] == "SYM-MCP-002" for e in body["events"])
    assert "s3cr3t" not in caplog.text
    assert "s3cr3t" not in json.dumps(rec.to_json())


def _record() -> CycleRecord:
    rec = CycleRecord(agent="a", started_at=NOW.isoformat(), status="findings")
    rec.new_findings = [
        {"check": "SYM-A", "severity": "critical", "subjects": ["x"], "message": "m", "fingerprint": "f1"},
        {"check": "SYM-B", "severity": "medium", "subjects": ["y"], "message": "m", "fingerprint": "f2"},
    ]
    return rec


def test_min_severity_filter(server: tuple[str, _Capture]) -> None:
    url, capture = server
    targets = [
        NotifyTarget(type="webhook", url_env="HOOK_A", min_severity=Severity.CRITICAL),
        NotifyTarget(type="webhook", url_env="HOOK_B", min_severity=Severity.MEDIUM),
    ]
    out = notify(_record(), targets, env={"HOOK_A": url, "HOOK_B": url})
    assert [d.status for d in out] == ["sent", "sent"]
    assert [len(b["events"]) for b in capture.bodies] == [1, 2]
    quiet = CycleRecord(agent="a", started_at=NOW.isoformat())
    assert notify(quiet, targets[:1], env={"HOOK_A": url})[0].status == "skipped"


def test_delivery_failures_are_warnings(
    server: tuple[str, _Capture], caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(notify_mod, "_RETRY_DELAY", 0.0)
    url, capture = server
    target = NotifyTarget(type="webhook", url_env="HOOK", min_severity=Severity.HIGH, timeout=2.0)
    # 503 then success: one retry.
    capture.statuses = [503]
    assert notify(_record(), [target], env={"HOOK": url})[0].status == "sent"
    assert len(capture.bodies) == 2
    # Two server errors: failed, logged without the URL.
    capture.statuses = [500, 500]
    with caplog.at_level(logging.WARNING, logger="symbiote.monitor"):
        out = notify(_record(), [target], env={"HOOK": url})
    assert out[0].status == "failed" and out[0].detail == "HTTP 500"
    assert "HOOK" in caplog.text and "s3cr3t" not in caplog.text and "127.0.0.1" not in caplog.text
    # Not set, plain http to a remote host, unreachable port: never raises.
    assert notify(_record(), [target], env={})[0].status == "not-configured"
    assert notify(_record(), [target], env={"HOOK": "http://hooks.example.com/x"})[0].status == "failed"
    dead = NotifyTarget(type="webhook", url_env="HOOK", min_severity=Severity.HIGH, timeout=0.5)
    assert notify(_record(), [dead], env={"HOOK": "http://127.0.0.1:9/x"})[0].status == "failed"
