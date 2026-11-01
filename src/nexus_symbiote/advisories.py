"""OSV.dev advisory lookups for discovered registry dependencies.

Static discovery finds packages; OSV answers whether those exact versions
have known vulnerabilities. This module queries the public OSV.dev API
(https://api.osv.dev) and maps results back to AIBOM components.

Network use is explicit: this runs only under the `symbiote advisories`
command, never during `scan`, so static BOM generation remains offline.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import ComponentType
from nexus_symbiote.core.models import RegistryEntryComponent

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT_SECONDS = 15.0

REGISTRY_TO_OSV_ECOSYSTEM: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "go": "Go",
    "crates-io": "crates.io",
    "rubygems": "RubyGems",
    "packagist": "Packagist",
    "nuget": "NuGet",
    "huggingface": "PyPI",
    "docker-hub": "Docker",
    "mcp-registry": "npm",
    "skill-marketplace": "npm",
}


@dataclass
class Advisory:
    component_ref: str
    component_name: str
    package_name: str
    ecosystem: str
    version: str | None
    advisory_id: str
    aliases: list[str] = field(default_factory=list)
    summary: str | None = None
    fixed_versions: list[str] = field(default_factory=list)
    url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class AdvisoryReport:
    components_checked: int = 0
    lookups_failed: int = 0
    errors: list[str] = field(default_factory=list)
    advisories: list[Advisory] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "components_checked": self.components_checked,
            "lookups_failed": self.lookups_failed,
            "errors": self.errors,
            "advisories": [a.to_dict() for a in self.advisories],
        }


def _query_osv(package_name: str, ecosystem: str, version: str | None) -> list[dict[str, Any]]:
    """Query OSV for one package. Raises OSError on network failure."""
    payload: dict[str, Any] = {"package": {"name": package_name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version

    request = urllib.request.Request(
        OSV_QUERY_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    # OSV_QUERY_URL is a pinned https:// constant; no untrusted scheme reaches here.
    with urllib.request.urlopen(request, timeout=OSV_TIMEOUT_SECONDS) as response:  # noqa: S310
        body = json.loads(response.read().decode("utf-8"))
    vulns = body.get("vulns", [])
    return [v for v in vulns if isinstance(v, dict)] if isinstance(vulns, list) else []


def fetch_advisories(bom: AIBOM, timeout: float = OSV_TIMEOUT_SECONDS) -> AdvisoryReport:
    """Look up OSV advisories for every registry component in the BOM."""
    report = AdvisoryReport()

    registry_components = [
        c
        for c in bom.components
        if c.component_type == ComponentType.REGISTRY_ENTRY
        and isinstance(c, RegistryEntryComponent)
    ]

    for comp in registry_components:
        if not comp.name:
            continue
        ecosystem = REGISTRY_TO_OSV_ECOSYSTEM.get(comp.registry_type or "")
        if ecosystem is None:
            continue

        report.components_checked += 1
        try:
            vulns = _query_osv(comp.name, ecosystem, comp.version)
        except (OSError, ValueError) as exc:
            report.lookups_failed += 1
            report.errors.append(f"{comp.bom_ref}: OSV lookup failed ({exc})")
            continue

        for vuln in vulns:
            aliases = list(vuln.get("aliases", []))
            fixed: list[str] = []
            for affected in vuln.get("affected", []):
                for rg in affected.get("ranges", []):
                    for event in rg.get("events", []):
                        if "fixed" in event:
                            fixed.append(str(event["fixed"]))
            report.advisories.append(
                Advisory(
                    component_ref=comp.bom_ref,
                    component_name=comp.name,
                    package_name=comp.name,
                    ecosystem=ecosystem,
                    version=comp.version,
                    advisory_id=str(vuln.get("id", "unknown")),
                    aliases=aliases,
                    summary=vuln.get("summary"),
                    fixed_versions=sorted(set(fixed)),
                    url=f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
                )
            )

    return report


def lookup_for_component(component: RegistryEntryComponent) -> str | None:
    """Return the OSV ecosystem for a registry component, or None if unsupported."""
    return REGISTRY_TO_OSV_ECOSYSTEM.get(component.registry_type or "")
