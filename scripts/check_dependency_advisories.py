"""Fail CI on known OSV advisories or incomplete checks of exact PyPI versions.

With ``--lock`` the inventory is every pin of the named lock files, whatever its environment
marker, so pins installed only on another Python or platform are audited too. Distributions
installed in the running environment but pinned by no lock (the runner's own pip, for example)
are listed in the report and not audited. Without ``--lock`` the installed environment is the
inventory.

A reviewed waiver (``--waivers``) can accept one advisory for one exact package version until
an expiry date at most 90 days ahead; it is printed and recorded. An expired or malformed
waiver fails the check, and so does one that matches no advisory of a version this run audits.

Batch ordering and per-query pagination: https://google.github.io/osv.dev/post-v1-querybatch/
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.metadata
import json
import os
import re
import time
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from check_locks import locked_packages

from nexus_symbiote.core.hashing import parse_json_strict
from nexus_symbiote.scanners.live_mcp import DiscoveryTransport, PinnedHTTPTransport

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_PACKAGES = 500
BATCH_SIZE = 100
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_PAGES = 10
TOTAL_TIMEOUT_SECONDS = 120
MAX_WAIVER_DAYS = 90
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WAIVERS = ROOT / "config" / "dependency-advisory-waivers.json"


def installed_packages() -> list[dict[str, str]]:
    """Include the actual environment, excluding only this source-built project."""
    packages: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        name = (distribution.metadata.get_all("Name") or [""])[0]
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", name) is None:
            raise ValueError("installed distribution has no valid PyPI identity")
        name = re.sub(r"[-_.]+", "-", name).lower()
        if name == "nexus-symbiote":
            continue
        version = distribution.version
        if not version or len(version) > 200 or any(c.isspace() for c in version):
            raise ValueError("installed distribution has no exact version")
        if name in packages and packages[name] != version:
            raise ValueError("conflicting installed versions for one package")
        packages[name] = version
    if not packages or len(packages) > MAX_PACKAGES:
        raise ValueError("installed dependency inventory is empty or exceeds the limit")
    return [{"name": name, "version": version} for name, version in sorted(packages.items())]


def lock_inventory(locks: list[Path]) -> list[dict[str, str]]:
    packages = [
        package for path in locks for package in locked_packages(path.resolve().parent, [path.name])
    ]
    unique = {(p["name"], p["version"]): p for p in packages}
    if not unique or len(unique) > MAX_PACKAGES:
        raise ValueError("locked dependency inventory is empty or exceeds the limit")
    return [unique[key] for key in sorted(unique)]


def unlocked_installed(locked: list[dict[str, str]]) -> list[dict[str, str]]:
    """Installed distributions that no lock pins: the runner's tools, never the reviewed set."""
    pinned = {(p["name"], p["version"]) for p in locked}
    return [p for p in installed_packages() if (p["name"], p["version"]) not in pinned]


def load_waivers(path: Path, today: date) -> list[dict[str, str]]:
    """Reviewed, expiring acceptances of one advisory for one exact package version."""
    if not path.exists():
        return []
    document = parse_json_strict(path.read_bytes(), max_bytes=1024 * 1024)
    waivers = document.get("waivers") if isinstance(document, dict) else None
    if not isinstance(waivers, list) or set(document) != {"waivers"}:
        raise ValueError("advisory waivers must be an object with one waivers list")
    accepted = []
    for waiver in waivers:
        if not isinstance(waiver, dict) or set(waiver) != {
            "advisory_id",
            "package",
            "version",
            "reason",
            "expires",
        }:
            raise ValueError(
                "each advisory waiver needs exactly advisory_id, package, version, reason"
                " and expires"
            )
        if any(not isinstance(value, str) for value in waiver.values()):
            raise ValueError("advisory waiver fields must be strings")
        expires = date.fromisoformat(waiver["expires"])
        if expires < today:
            raise ValueError(f"advisory waiver for {waiver['advisory_id']} has expired")
        if expires > today + timedelta(days=MAX_WAIVER_DAYS):
            raise ValueError(
                f"advisory waiver for {waiver['advisory_id']} lasts over {MAX_WAIVER_DAYS} days"
            )
        if len(waiver["reason"].strip()) < 20:
            raise ValueError(f"advisory waiver for {waiver['advisory_id']} gives no reason")
        accepted.append(waiver)
    return accepted


def apply_waivers(report: dict[str, Any], waivers: list[dict[str, str]]) -> None:
    """Move waived advisories aside; a waiver for an audited version that matches nothing
    denies approval, so an exception does not outlive its advisory."""
    keys = {(w["advisory_id"], w["package"], w["version"]): w for w in waivers}
    audited = {(p.get("name"), p.get("version")) for p in report.get("packages", [])}
    blocking, waived, used = [], [], set()
    for advisory in report["advisories"]:
        key = (advisory["advisory_id"], advisory["name"], advisory["version"])
        if key in keys:
            used.add(key)
            waived.append(
                {**advisory, "reason": keys[key]["reason"], "expires": keys[key]["expires"]}
            )
        else:
            blocking.append(advisory)
    report["advisories"] = blocking
    report["waived"] = waived
    if report["complete"]:
        for key in sorted(set(keys) - used):
            if (key[1], key[2]) in audited:
                report["errors"].append(
                    f"advisory waiver {key[0]} for {key[1]}=={key[2]} is unused"
                )
    report["passed"] = report["complete"] and not blocking and not report["errors"]


def audit(
    packages: list[dict[str, str]], *, transport: DiscoveryTransport | None = None
) -> dict[str, Any]:
    """Follow bounded batch pages; errors and unknown responses never mean clean."""
    if not packages or len(packages) > MAX_PACKAGES:
        raise ValueError("dependency inventory is empty or exceeds the limit")
    queries = []
    identities: set[tuple[str, str]] = set()
    for package in packages:
        name, version = package.get("name", ""), package.get("version", "")
        if (
            re.fullmatch(r"[a-z0-9][a-z0-9-]{0,199}", name) is None
            or not version
            or len(version) > 200
            or any(c.isspace() for c in version)
            or (name, version) in identities
        ):
            raise ValueError("invalid or duplicate exact dependency identity")
        identities.add((name, version))
        queries.append({"package": {"ecosystem": "PyPI", "name": name}, "version": version})
    report: dict[str, Any] = {
        "schema_version": 1,
        "source_sha": os.environ.get("GITHUB_SHA"),
        "checked_at": datetime.now(UTC).isoformat(),
        "scope": "installed exact PyPI versions; source project excluded; OSV knowledge is incomplete",
        "packages": packages,
        "inventory_sha256": hashlib.sha256(
            json.dumps(packages, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "complete": False,
        "advisories": [],
        "errors": [],
    }
    client = transport or PinnedHTTPTransport()
    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    try:
        for start in range(0, len(queries), BATCH_SIZE):
            pending: list[tuple[int, dict[str, Any], set[str]]] = [
                (i, queries[i], set()) for i in range(start, min(start + BATCH_SIZE, len(queries)))
            ]
            for _ in range(MAX_PAGES):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("OSV audit deadline exceeded")
                reply = client.request(
                    OSV_BATCH_URL,
                    json.dumps({"queries": [query for _, query, _ in pending]}).encode(),
                    {"Content-Type": "application/json", "Accept": "application/json"},
                    timeout=min(20, remaining),
                    max_bytes=MAX_RESPONSE_BYTES,
                )
                if reply.status != 200 or len(reply.body) > MAX_RESPONSE_BYTES:
                    raise ValueError("OSV batch did not return bounded success")
                body = parse_json_strict(reply.body, max_bytes=MAX_RESPONSE_BYTES)
                if not isinstance(body, dict) or set(body) != {"results"}:
                    raise ValueError("OSV batch is malformed or reports an error")
                results = body["results"]
                if not isinstance(results, list) or len(results) != len(pending):
                    raise ValueError("OSV batch result count differs from dependency queries")
                following = []
                for (index, query, seen), result in zip(pending, results, strict=True):
                    if not isinstance(result, dict) or result.keys() - {"vulns", "next_page_token"}:
                        raise ValueError("OSV batch result is malformed or reports an error")
                    vulns = result.get("vulns", [])
                    if not isinstance(vulns, list) or len(vulns) > 10_000:
                        raise ValueError("OSV vulnerability list is malformed or excessive")
                    for vuln in vulns:
                        advisory = vuln.get("id") if isinstance(vuln, dict) else None
                        if (
                            not isinstance(advisory, str)
                            or re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", advisory) is None
                        ):
                            raise ValueError("OSV vulnerability record has no valid identifier")
                        record = {**packages[index], "advisory_id": advisory}
                        if record not in report["advisories"]:
                            report["advisories"].append(record)
                    token = result.get("next_page_token", "")
                    if not isinstance(token, str) or len(token) > 2048 or token in seen:
                        raise ValueError("OSV pagination is malformed or repeats a page")
                    if token:
                        following.append((index, {**query, "page_token": token}, seen | {token}))
                pending = following
                if not pending:
                    break
            if pending:
                raise ValueError("OSV pagination limit exceeded")
        if time.monotonic() > deadline:
            raise ValueError("OSV audit deadline exceeded")
        report["complete"] = True
    except (OSError, ValueError, TypeError, RecursionError, http.client.HTTPException):
        report["errors"].append("OSV dependency lookup is incomplete; approval denied")
    report["passed"] = report["complete"] and not report["advisories"]
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--lock", type=Path, action="append", default=[])
    parser.add_argument("--waivers", type=Path, default=DEFAULT_WAIVERS)
    args = parser.parse_args(argv)
    waiver_error: str | None = None
    try:
        waivers = load_waivers(args.waivers, datetime.now(UTC).date())
    except (OSError, ValueError, TypeError) as exc:
        # The waiver file is reviewed repository configuration; its problems name themselves.
        message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        waivers, waiver_error = [], f"advisory waivers rejected: {message}"
    locked: list[dict[str, str]] | None = None
    try:
        if args.lock:
            packages = locked = lock_inventory(args.lock)
            report = audit(packages)
            report["scope"] = (
                "every exact PyPI version pinned by the named locks, whatever its marker;"
                " OSV knowledge is incomplete"
            )
            report["locks"] = [path.name for path in args.lock]
        else:
            report = audit(installed_packages())
        apply_waivers(report, waivers)
    except (OSError, ValueError, TypeError):
        report = {
            "complete": False,
            "passed": False,
            "errors": ["dependency identities unavailable"],
        }
    if locked is not None and "advisories" in report:
        # Listing the runner's own tools is informational: its failure keeps the audit.
        try:
            report["unlocked_installed"] = unlocked_installed(locked)
        except (OSError, ValueError, TypeError):
            report["errors"].append("installed distributions outside the locks unavailable")
            report["passed"] = False
    if waiver_error is not None:
        report["errors"].append(waiver_error)
        report["passed"] = False
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for advisory in report.get("advisories", []):
        print(f"Advisory {advisory['advisory_id']} for {advisory['name']}=={advisory['version']}")
    for advisory in report.get("waived", []):
        print(
            f"Waived until {advisory['expires']}: {advisory['advisory_id']} for"
            f" {advisory['name']}=={advisory['version']}"
        )
    for error in report.get("errors", []):
        print(error)
    print("Dependency advisory acceptance: " + ("passed" if report["passed"] else "failed"))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
