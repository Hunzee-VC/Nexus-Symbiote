"""Explicit, bounded OSV queries for exact declared PyPI/npm package identities."""

from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import unquote

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import parse_json_strict
from nexus_symbiote.core.models import RegistryEntryComponent
from nexus_symbiote.scanners.live_mcp import DiscoveryTransport, PinnedHTTPTransport

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_COMPONENTS = 500
TOTAL_TIMEOUT_SECONDS = 60.0
_VERSION = re.compile(r"[0-9][A-Za-z0-9.+!_-]{0,199}")


@dataclass
class AdvisoryReport:
    components_checked: int = 0
    components_skipped: int = 0
    errors: list[str] = field(default_factory=list)
    advisories: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "complete": not self.errors,
            "scope": "exact declared PyPI/npm package URLs; installed artifacts unverified",
        }


def package_identity(component: RegistryEntryComponent) -> tuple[str, str, str]:
    """Accept a narrow purl subset and reconcile it with the inventory declaration."""
    purl = component.package_url
    if not isinstance(purl, str) or len(purl) > 2048 or "?" in purl or "#" in purl:
        raise ValueError("exact package_url is required, without qualifiers or subpath")
    match = re.fullmatch(r"pkg:(pypi|npm)/(.+)@([^@/]+)", purl)
    if match is None:
        raise ValueError("only exact PyPI/npm package URLs are supported")
    kind, encoded_name, encoded_version = match.groups()
    name, version = (
        unquote(encoded_name, errors="strict"),
        unquote(encoded_version, errors="strict"),
    )
    valid_name = (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", name)
        if kind == "pypi"
        else re.fullmatch(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*", name)
    )
    if valid_name is None or _VERSION.fullmatch(version) is None:
        raise ValueError("package URL name or exact version is invalid")
    normalize = (
        (lambda value: re.sub(r"[-_.]+", "-", value).lower())
        if kind == "pypi"
        else (lambda value: value)
    )
    declared_version = (component.version or "").removeprefix("==")
    if (
        component.registry_type != kind
        or normalize(component.name) != normalize(name)
        or declared_version != version
    ):
        raise ValueError("package URL disagrees with registry, name or version")
    return ("PyPI" if kind == "pypi" else "npm"), normalize(name), version


def fetch_advisories(
    bom: AIBOM, timeout: float = 15.0, *, transport: DiscoveryTransport | None = None
) -> AdvisoryReport:
    """Query only OSV over pinned HTTPS; report missing identity and lookup failures."""
    import json

    if not 0 < timeout <= 30:
        raise ValueError("timeout must be in (0, 30] seconds")
    report = AdvisoryReport()
    client = transport or PinnedHTTPTransport()
    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    components = [c for c in bom.components if isinstance(c, RegistryEntryComponent)]
    if len(components) > MAX_COMPONENTS:
        report.errors.append("registry component limit exceeded; no lookups performed")
        return report
    for comp in components:
        if comp.registry_type not in {"pypi", "npm"}:
            report.components_skipped += 1
            continue
        try:
            ecosystem, name, version = package_identity(comp)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("total OSV lookup deadline exceeded")
            report.components_checked += 1
            reply = client.request(
                OSV_QUERY_URL,
                json.dumps(
                    {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                ).encode(),
                {"Content-Type": "application/json", "Accept": "application/json"},
                timeout=min(timeout, remaining),
                max_bytes=MAX_RESPONSE_BYTES,
            )
            if reply.status != 200 or len(reply.body) > MAX_RESPONSE_BYTES:
                raise ValueError("OSV returned a non-success or oversized response")
            body = parse_json_strict(reply.body, max_bytes=MAX_RESPONSE_BYTES)
            if not isinstance(body, dict) or body.get("next_page_token"):
                raise ValueError("invalid or incomplete OSV response")
            vulns = body.get("vulns", [])
            if not isinstance(vulns, list) or len(vulns) > 10_000:
                raise ValueError("invalid or over-limit OSV vulnerability list")
            pending: list[dict[str, Any]] = []
            for vuln in vulns:
                if (
                    not isinstance(vuln, dict)
                    or not isinstance(vuln.get("id"), str)
                    or re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", vuln["id"]) is None
                ):
                    raise ValueError("invalid OSV vulnerability record")
                # No uncontrolled nested API data is propagated as verified local evidence.
                pending.append(
                    {
                        "component_ref": comp.bom_ref,
                        "package_url": comp.package_url,
                        "advisory_id": vuln["id"],
                        "ecosystem": ecosystem,
                        "version": version,
                        "url": "https://osv.dev/vulnerability/" + vuln["id"],
                    }
                )
            report.advisories.extend(pending)
        except (OSError, ValueError, TypeError, RecursionError):
            # Transport exception text can contain server data; keep it out of reports.
            report.errors.append(f"{comp.bom_ref}: OSV lookup incomplete or identity unverified")
    return report
