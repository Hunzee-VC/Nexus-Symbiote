"""Cycle notifications (``spec/monitoring.md`` §2 step 6).

Events at or above a target's ``min_severity`` are POSTed as JSON to a webhook whose URL is read from the
environment variable the configuration names. Delivery is best effort: a timeout, one retry, a warning on
failure, never an exception. The URL is a secret (it often embeds a token): it is never logged or returned.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from symbiote import __version__
from symbiote.monitor.risk import at_least

if TYPE_CHECKING:
    from symbiote.monitor.config import NotifyTarget
    from symbiote.monitor.runner import CycleRecord

__all__ = ["Delivery", "build_payload", "cycle_events", "deliver", "notify"]

log = logging.getLogger("symbiote.monitor")

MAX_EVENTS = 200
MAX_PAYLOAD_BYTES = 256 * 1024
_RETRY_DELAY = 0.5


@dataclass(frozen=True, slots=True)
class Delivery:
    url_env: str
    status: Literal["sent", "skipped", "failed", "not-configured"]
    events: int
    detail: str = ""

    def to_json(self) -> dict[str, Any]:
        return {"urlEnv": self.url_env, "status": self.status, "events": self.events, "detail": self.detail}


def cycle_events(record: CycleRecord) -> list[dict[str, Any]]:
    """Every notifiable event of a cycle, each with a ``severity``."""
    events: list[dict[str, Any]] = []
    if record.status == "error":
        events.append(
            {
                "type": "cycle-error",
                "severity": "high",
                "detail": "; ".join(record.errors)[:500] or "cycle failed",
            }
        )
    if record.incomplete:
        events.append(
            {
                "type": "cycle-incomplete",
                "severity": "medium",
                "detail": "; ".join(record.incomplete)[:500],
            }
        )
    for f in record.new_findings:
        events.append(
            {
                "type": "new-finding",
                "severity": f["severity"],
                "check": f["check"],
                "subjects": f["subjects"],
                "detail": f["message"],
            }
        )
    for d in record.drift:
        events.append(
            {
                "type": "drift",
                "severity": d["severity"],
                "event": d["type"],
                "against": d["against"],
                "subjects": [d["subject"]],
                "detail": d.get("detail") or "",
            }
        )
    for dep in record.dependencies:
        for s in dep.get("signals", []):
            events.append(
                {
                    "type": "dependency-signal",
                    "severity": s["severity"],
                    "signal": s["kind"],
                    "dependency": dep["name"],
                    "version": dep.get("version"),
                    "detail": s["detail"],
                }
            )
    for v in record.verification:
        if v["status"] == "fail":
            events.append(
                {
                    "type": "verification-failure",
                    "severity": v["severity"],
                    "check": v["check"],
                    "detail": v["message"],
                }
            )
    if record.escalation == "escalated":
        events.append(
            {"type": "escalated", "severity": "high", "detail": "; ".join(record.escalation_reasons)[:500]}
        )
    return events


def build_payload(record: CycleRecord, events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "source": "symbiote-monitor",
        "version": __version__,
        "agent": record.agent,
        "status": record.status,
        "tier": record.tier,
        "escalated": record.escalated,
        "cycleAt": record.started_at,
        "nextDueAt": record.next_due_at,
        "snapshot": record.snapshot,
        "events": list(events)[:MAX_EVENTS],
        "truncated": len(events) > MAX_EVENTS,
    }


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # a redirect is a failed delivery: never re-send the payload elsewhere


def _post(url: str, body: bytes, timeout: float) -> int:
    parts = urllib.parse.urlsplit(url)
    handlers: list[urllib.request.BaseHandler] = [_NoRedirect()]
    if _is_loopback(parts.hostname or ""):
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(  # noqa: S310 - scheme checked by the caller
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": f"symbiote/{__version__}"},
    )
    with opener.open(req, timeout=timeout) as resp:
        resp.read(64 * 1024)
        status: int = resp.status
        return status


def deliver(
    target: NotifyTarget,
    payload: Mapping[str, Any],
    *,
    env: Mapping[str, str] | None = None,
) -> Delivery:
    environ = os.environ if env is None else env
    n = len(payload.get("events", []))
    url = environ.get(target.url_env, "").strip()
    if not url:
        log.warning("notification skipped: environment variable %s is not set", target.url_env)
        return Delivery(target.url_env, "not-configured", n, f"${target.url_env} is not set")
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme != "https" and not (parts.scheme == "http" and _is_loopback(host)):
        log.warning("notification skipped: ${%s} must be an https URL", target.url_env)
        return Delivery(target.url_env, "failed", n, "webhook URL must use https")
    body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    if len(body) > MAX_PAYLOAD_BYTES:
        body = json.dumps({**payload, "events": [], "truncated": True}, sort_keys=True, default=str).encode()
    last = ""
    for attempt in range(2):
        try:
            status = _post(url, body, target.timeout)
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
            if exc.code < 500 and exc.code != 429:
                break
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = type(exc).__name__
        else:
            if 200 <= status < 300:
                return Delivery(target.url_env, "sent", n, f"HTTP {status}")
            last = f"HTTP {status}"
        if attempt == 0:
            time.sleep(_RETRY_DELAY)
    log.warning("notification via ${%s} failed: %s", target.url_env, last)
    return Delivery(target.url_env, "failed", n, last)


def notify(
    record: CycleRecord,
    targets: Sequence[NotifyTarget],
    *,
    env: Mapping[str, str] | None = None,
) -> list[Delivery]:
    """Send the cycle's events to every target whose threshold they meet. Never raises."""
    if not targets:
        return []
    events = cycle_events(record)
    out: list[Delivery] = []
    for target in targets:
        selected = [e for e in events if at_least(e["severity"], target.min_severity)]
        if not selected:
            out.append(Delivery(target.url_env, "skipped", 0, "no events at or above the threshold"))
            continue
        try:
            out.append(deliver(target, build_payload(record, selected), env=env))
        except Exception as exc:  # notification must never fail a cycle
            log.warning("notification via ${%s} failed: %s", target.url_env, type(exc).__name__)
            out.append(Delivery(target.url_env, "failed", len(selected), type(exc).__name__))
    return out
