"""Write a CycloneDX 1.7 SBOM of an installed environment from ``pip inspect`` output.

The release evidence already records the locked runtime as raw ``pip inspect`` JSON.
This script projects that record into a standard SBOM for consumers that read
CycloneDX, validated against the vendored official schema. It describes what pip
reports as installed, with dependency edges from the declared requirements that
apply to the inspected interpreter. With ``--lock`` every installed distribution
except this project and the virtual environment's own pip must be pinned by that
lock at the installed version, and the SBOM records the lock's SHA-256. It does not
authenticate the installed files: pip does not record which of a lock entry's
hashed files it installed from an index, so components carry no file hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from packageurl import PackageURL
from packaging.requirements import InvalidRequirement, Requirement

from nexus_symbiote.generators.validation import require_valid

MAX_INPUT_BYTES = 64 * 1024 * 1024
PROJECT = "nexus-symbiote"
# Installed by `python -m venv` before any lock is read, so no lock pins it.
BOOTSTRAP = frozenset({"pip"})
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


def _component(record: dict[str, Any]) -> dict[str, Any]:
    """A record pip reports must become a component; one that cannot is an error, not a gap."""
    metadata = record.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("an installed distribution has no metadata")
    name, version = metadata.get("name"), metadata.get("version")
    if not isinstance(name, str) or not isinstance(version, str) or not name or not version:
        raise ValueError("an installed distribution has no name or version")
    if (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", name) is None
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+!-]{0,199}", version) is None
    ):
        raise ValueError("an installed distribution's name or version cannot be represented")
    canonical = normalize(name)
    purl = PackageURL(type="pypi", name=canonical, version=version).to_string()
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
    legacy = metadata.get("license")
    if isinstance(expression, str) and expression.strip():
        component["licenses"] = [{"expression": expression.strip()}]
    elif licenses:
        component["licenses"] = [{"license": {"name": value}} for value in licenses[:8]]
    elif isinstance(legacy, str) and legacy.strip() and "\n" not in legacy.strip():
        # The legacy License field, when it is a name rather than a pasted licence text.
        component["licenses"] = [{"license": {"name": legacy.strip()[:200]}}]
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

    An extra is active when an applicable requirement of an installed distribution
    asks for it. ``pip inspect`` does not record the extras named on the pip command
    line, so edges gated only on such an extra are omitted rather than invented.
    """
    active: dict[str, set[str]] = {name: set() for name in named}
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


def locked_versions(text: str) -> dict[str, set[str]]:
    """Every exact name and version a hash lock pins, whatever its marker."""
    pinned: dict[str, set[str]] = {}
    for line in text.splitlines():
        if not line.strip() or line[0].isspace() or line.lstrip().startswith("#"):
            continue
        requirement = Requirement(line.removesuffix("\\").strip())
        clauses = list(requirement.specifier)
        if len(clauses) != 1 or clauses[0].operator != "==":
            raise ValueError("lock entry is not one exact pin")
        pinned.setdefault(normalize(requirement.name), set()).add(clauses[0].version)
    if not pinned:
        raise ValueError("lock pins nothing")
    return pinned


def build_sbom(
    inspect: dict[str, Any],
    *,
    timestamp: datetime,
    lock: tuple[dict[str, set[str]], str] | None = None,
) -> dict[str, Any]:
    records = inspect.get("installed")
    if not isinstance(records, list):
        raise ValueError("pip inspect output must contain an installed list")
    marker_environment = _marker_environment(inspect)
    if not all(isinstance(record, dict) for record in records):
        raise ValueError("pip inspect output lists a malformed installed record")
    pairs = sorted(
        ((_component(record), record) for record in records),
        key=lambda pair: (pair[0]["name"], pair[0]["version"]),
    )
    components = [component for component, _ in pairs]
    if lock is not None:
        pinned, _ = lock
        for component in components:
            name = component["name"]
            if (
                name != PROJECT
                and name not in BOOTSTRAP
                and component["version"] not in pinned.get(name, set())
            ):
                raise ValueError(
                    f"{component['name']}=={component['version']} is installed but not locked"
                )
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
        "description": "Installed Python distributions of the "
        + ("locked release runtime" if lock is not None else "inspected environment"),
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
            **(
                {
                    "properties": [
                        {"name": "nexus-symbiote:lock-sha256", "value": lock[1]},
                    ]
                }
                if lock is not None
                else {}
            ),
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
    parser.add_argument("--lock", type=Path, help="require every installed pin to be in it")
    args = parser.parse_args()
    lock = None
    if args.lock is not None:
        text = args.lock.read_bytes()
        lock = (locked_versions(text.decode("utf-8")), hashlib.sha256(text).hexdigest())
    with args.inspect_json.open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise SystemExit("pip inspect output exceeds the size limit")
    # The CLI's rule: unset means now, and any value that is not an epoch is refused.
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is None:
        timestamp = datetime.now(UTC)
    else:
        try:
            if re.fullmatch(r"[0-9]{1,12}", epoch) is None:
                raise ValueError
            timestamp = datetime.fromtimestamp(int(epoch), tz=UTC)
        except (OverflowError, OSError, ValueError):
            raise SystemExit("SOURCE_DATE_EPOCH must be a whole number of seconds") from None
    document = build_sbom(json.loads(raw), timestamp=timestamp, lock=lock)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Environment SBOM: {len(document['components'])} distributions -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
