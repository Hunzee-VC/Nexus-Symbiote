"""Development benchmark for the reference gateway. Run as python -m tests.bench_admission."""

from __future__ import annotations

import argparse
import json
import math
import platform
import sqlite3
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from symbiote.attest.dsse import Envelope, generate_signing_key
from symbiote.digest.jcs import canonical_bytes
from symbiote.enforce.admission import (
    DEFAULT_MAX_TRUST_AGE,
    CallIntent,
    approve_call,
    dispatch_call,
    sign_gateway_bundle,
    verify_receipt,
)
from tests.unit.test_admission import BINDING, NOW, RAW2, fixture_bom, intent, ring


def measure(samples: int) -> dict[str, Any]:
    if not 1 <= samples <= 10_000:
        raise ValueError("samples must be between 1 and 10,000")
    policy_key, gateway_key, user_key = [generate_signing_key("ed25519") for _ in range(3)]
    policies, receipts, approvals = ring(policy_key), ring(gateway_key), ring(user_key)
    initial = sign_gateway_bundle(fixture_bom(), BINDING, policy_key)
    revoked = sign_gateway_bundle(fixture_bom(serial=2, trust_serial=2, revoke=True), BINDING, policy_key)
    timings: dict[str, list[int]] = {}
    outcomes: dict[str, dict[str, Any]] = {}
    with TemporaryDirectory(prefix="symbiote-bench-") as directory:

        def check(
            case: str,
            policy: Envelope,
            call: CallIntent,
            expected: str,
            *,
            gateway: str = "connected",
            ticket: Envelope | None = None,
            clock: datetime = NOW,
            max_trust_age: timedelta = DEFAULT_MAX_TRUST_AGE,
            reason: str | None = None,
        ) -> None:
            effects = []
            args = {"repo": call.resource}
            db = Path(directory) / (gateway + ".sqlite")
            started = time.perf_counter_ns()
            envelope, _ = dispatch_call(
                policy,
                call,
                RAW2,
                args,
                resolve_resource=lambda a: a["repo"],
                invoke=effects.append,
                bundle_keys=policies,
                receipt_key=gateway_key,
                state_db=db,
                approval=ticket,
                approval_keys=approvals,
                now=clock,
                max_trust_age=max_trust_age,
            )
            elapsed = time.perf_counter_ns() - started
            receipt = verify_receipt(envelope, receipts)
            if (
                receipt.intent != call
                or receipt.decision != expected
                or (reason is not None and reason != receipt.reason)
                or effects != ([args] if expected == "allow" else [])
            ):
                raise RuntimeError(f"{case} failed its decision, signed receipt or side-effect check")
            timings.setdefault(case, []).append(elapsed)
            outcomes[case] = {"expected": expected, "reason": receipt.reason, "gateway": gateway}

        check("cold_allow", initial, intent("dev", "first"), "allow")
        for i in range(samples):
            check("warm_allow", initial, intent("dev", f"allow-{i}"), "allow")
            check("warm_approval_required", initial, intent("prod", f"unapproved-{i}"), "approval-required")
        authorized = intent("prod", "one-use")
        ticket = approve_call(initial, authorized, user_key, now=NOW, expires=NOW + timedelta(minutes=1))
        check("approved_once", initial, authorized, "allow", ticket=ticket)
        check(
            "approval_replay", initial, authorized, "deny", ticket=ticket, reason="request-already-consumed"
        )
        check("disconnected_before_update", initial, intent("dev", "old-1"), "allow", gateway="disconnected")
        check(
            "first_decision_after_revocation_delivery",
            revoked,
            intent("dev", "revoked"),
            "deny",
            reason="publisher-revoked-or-quarantined",
        )
        check(
            "connected_rollback",
            initial,
            intent("dev", "rollback"),
            "deny",
            reason="rollback-or-equivocation",
        )
        check(
            "disconnected_with_unexpired_cache",
            initial,
            intent("dev", "old-2"),
            "allow",
            gateway="disconnected",
            clock=NOW + timedelta(minutes=1),
        )
        for seconds, expected in [(29, "allow"), (30, "deny")]:
            check(
                f"disconnected_30s_budget_at_{seconds}s",
                initial,
                intent("dev", f"short-{seconds}"),
                expected,
                gateway="disconnected",
                clock=NOW + timedelta(seconds=seconds),
                max_trust_age=timedelta(seconds=30),
                reason="stale-or-invalid-policy" if expected == "deny" else "scoped-grant",
            )
        check(
            "disconnected_after_expiry",
            initial,
            intent("dev", "old-3"),
            "deny",
            gateway="disconnected",
            clock=NOW + timedelta(hours=2),
        )

    for case, values in timings.items():
        ranked = sorted(values)
        outcomes[case].update(samples=len(values), raw_ns=values)
        if len(values) > 1:
            outcomes[case]["nearest_rank_ms"] = {
                f"p{n}": ranked[math.ceil(len(ranked) * n / 100) - 1] / 1e6 for n in (50, 95, 99)
            }
    return {
        "schema_version": 1,
        "scope": "local reference adapter with two independent SQLite state files",
        "python": sys.version.split()[0],
        "machine": platform.machine(),
        "system": platform.system(),
        "kernel": platform.release(),
        "processor": platform.processor() or None,
        "sqlite": sqlite3.sqlite_version,
        "concurrency": 1,
        "clock": "perf_counter_ns",
        "policy_time": NOW.isoformat(),
        "warm_iterations_per_case": samples,
        "argument_bytes": {r: len(canonical_bytes({"repo": r})) for r in ("dev", "prod")},
        "outcomes": outcomes,
    }


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--samples", type=int, default=200)
    cli.add_argument("--output", type=Path, help="Create a new JSON file containing all raw observations.")
    args = cli.parse_args()
    result = measure(args.samples)
    out = json.dumps(result, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(out)
    else:
        print(out, end="")
