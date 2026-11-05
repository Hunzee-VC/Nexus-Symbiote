"""Write a CycloneDX 1.7 SBOM of an installed environment from ``pip inspect`` output.

The release evidence already records the locked runtime as raw ``pip inspect`` JSON.
This script projects that record into a standard SBOM for consumers that read
CycloneDX, validated against the vendored official schema. It describes what pip
reports as installed, with dependency edges from the declared requirements that
apply to the inspected interpreter; it does not authenticate the files or prove the
lock was used.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from nexus_symbiote.generators.validation import require_valid

MAX_INPUT_BYTES = 64 * 1024 * 1024
NAMESPACE = uuid.UUID("5a1d4c3e-9b7f-4e2a-8c6d-0f1e2d3c4b5a")
MARKER_KEYS = (
    "implementation_name",
    "implementation_version",
    "os_name",
    "platform_machine",
    "platform_python_implementation",
    "platform_release",
    "platform_system",
    "platform_version",
    "python_full_version",
    "python_version",
    "sys_platform",
)


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _component(record: dict[str, Any]) -> dict[str, Any] | None:
    metadata = record.get("metadata")
    if not isinstance(metadata, dict):
        return None
    name, version = metadata.get("name"), metadata.get("version")
    if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
        return None
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", name) is None or len(version) > 200:
        return None
    canonical = normalize(name)
    purl = f"pkg:pypi/{canonical}@{version}"
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": purl,
        "name": canonical,
        "version": version,
        "purl": purl,
    }
    summary = metadata.get("summary")
    if isinstance(summary, str) and summary.strip():
        component["description"] = summary.strip()[:512]
    licenses = [
        value[len("License :: ") :]
        for value in metadata.get("classifier", [])
        if isinstance(value, str) and value.startswith("License :: ")
    ]
    expression = metadata.get("license_expression")
    if isinstance(expression, str) and expression.strip():
        component["licenses"] = [{"expression": expression.strip()}]
    elif licenses:
        component["licenses"] = [{"license": {"name": value}} for value in licenses[:8]]
    return component


def _marker_environment(inspect: dict[str, Any]) -> dict[str, str]:
    # Markers are evaluated for the inspected interpreter, never the one running this
    # script, so the graph does not depend on where the evidence is assembled.
    environment = inspect.get("environment")
    if not isinstance(environment, dict) or not all(
        isinstance(environment.get(key), str) for key in MARKER_KEYS
    ):
        raise ValueError("pip inspect output must contain the marker environment")
    return {key: environment[key] for key in MARKER_KEYS}


def _requirements(record: dict[str, Any]) -> list[Requirement]:
    metadata = record.get("metadata", {})
    parsed: list[Requirement] = []
    for raw in metadata.get("requires_dist", []) or []:
        if not isinstance(raw, str):
            continue
        try:
            parsed.append(Requirement(raw))
        except InvalidRequirement:
            continue
    return parsed


def _applies(requirement: Requirement, environment: dict[str, str], extras: set[str]) -> bool:
    if requirement.marker is None:
        return True
    return any(
        requirement.marker.evaluate({**environment, "extra": extra})
        for extra in ("", *sorted(extras))
    )


def _active_extras(
    named: dict[str, tuple[dict[str, Any], list[Requirement]]], environment: dict[str, str]
) -> dict[str, set[str]]:
    """Extras in effect for each distribution, as a fixed point.

    An extra is active when pip reports it as requested at install time, or when an
    applicable requirement of an installed distribution asks for it. Older pip does not
    report requested extras; those then count as inactive, which omits an edge rather
    than inventing one.
    """
    active = {
        name: {normalize(e) for e in record.get("requested_extras") or [] if isinstance(e, str)}
        for name, (record, _) in named.items()
    }
    changed = True
    while changed:
        changed = False
        for name, (_, requirements) in named.items():
            for requirement in requirements:
                target = normalize(requirement.name)
                wanted = {normalize(extra) for extra in requirement.extras}
                if (
                    target in active
                    and not wanted <= active[target]
                    and _applies(requirement, environment, active[name])
                ):
                    active[target] |= wanted
                    changed = True
    return active


def _requires(
    name: str,
    requirements: list[Requirement],
    installed: dict[str, str],
    environment: dict[str, str],
    extras: set[str],
) -> list[str]:
    # An edge needs a requirement that applies here (its marker holds for this
    # interpreter and an active extra) and a dependency that is installed. A
    # requirement on the distribution itself only selects extras.
    refs: set[str] = set()
    for requirement in requirements:
        target = normalize(requirement.name)
        ref = installed.get(target)
        if ref is not None and target != name and _applies(requirement, environment, extras):
            refs.add(ref)
    return sorted(refs)


def build_sbom(inspect: dict[str, Any], *, timestamp: datetime) -> dict[str, Any]:
    records = inspect.get("installed")
    if not isinstance(records, list):
        raise ValueError("pip inspect output must contain an installed list")
    marker_environment = _marker_environment(inspect)
    pairs = sorted(
        (
            (component, record)
            for record in records
            if isinstance(record, dict)
            for component in [_component(record)]
            if component
        ),
        key=lambda pair: (pair[0]["name"], pair[0]["version"]),
    )
    components = [component for component, _ in pairs]
    installed = {c["name"]: c["bom-ref"] for c in components}
    if len(installed) != len(components):
        raise ValueError("an installed distribution appears more than once")
    named = {c["name"]: (record, _requirements(record)) for c, record in pairs}
    extras = _active_extras(named, marker_environment)
    dependencies = [
        {
            "ref": c["bom-ref"],
            "dependsOn": _requires(
                c["name"], named[c["name"]][1], installed, marker_environment, extras[c["name"]]
            ),
        }
        for c in components
    ]
    identity = uuid.uuid5(NAMESPACE, json.dumps([c["purl"] for c in components]))
    python = marker_environment["python_full_version"]
    root = {
        "type": "application",
        "bom-ref": "environment",
        "name": "nexus-symbiote-runtime-environment",
        "description": "Installed Python distributions of the locked release runtime",
    }
    if python:
        root["version"] = "python-" + python
    document: dict[str, Any] = {
        "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{identity}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "nexus-symbiote-release"}]},
            "component": root,
        },
        "components": components,
        "dependencies": dependencies,
    }
    require_valid(document, "cyclonedx")
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inspect_json", type=Path, help="output of `python -m pip inspect`")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    with args.inspect_json.open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise SystemExit("pip inspect output exceeds the size limit")
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    timestamp = (
        datetime.fromtimestamp(int(epoch), tz=UTC)
        if epoch and epoch.isdigit()
        else datetime.now(UTC)
    )
    document = build_sbom(json.loads(raw), timestamp=timestamp)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Environment SBOM: {len(document['components'])} distributions -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
