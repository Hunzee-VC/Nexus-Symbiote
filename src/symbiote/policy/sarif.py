"""SARIF 2.1.0 output for GitHub code scanning (``spec/checks.md`` §4).

``ruleId`` is the check id, ``level`` follows the severity (critical/high → error, medium → warning,
low/info → note) and ``properties.security-severity`` gives code scanning its numeric severity. Locations come
from evidence locators: ``path#/json/pointer`` (the pointer is kept as a logical location) or ``path:line``.
Indeterminate findings are reported at ``note`` level with ``kind = "review"``, never silently dropped.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from typing import Any, Final

from symbiote import __version__
from symbiote.model.entities import Finding
from symbiote.model.enums import FindingState, Severity
from symbiote.policy.spec import CHECKS

__all__ = ["SARIF_SCHEMA", "to_sarif"]

SARIF_SCHEMA: Final = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL: Final = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY: Final = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}
_LINE: Final = re.compile(r"^(?P<path>.+?):(?P<line>\d+)$")


def _location(locator: str | None, subjects: list[str]) -> dict[str, Any]:
    logical = [{"fullyQualifiedName": s, "kind": "object"} for s in subjects[:5]]
    if not locator:
        return {"logicalLocations": logical} if logical else {}
    path, _, pointer = locator.partition("#")
    physical: dict[str, Any] = {"artifactLocation": {"uri": path.removeprefix("~/")}}
    match = _LINE.match(path)
    if match:
        physical = {
            "artifactLocation": {"uri": match.group("path")},
            "region": {"startLine": int(match.group("line"))},
        }
    if pointer:
        logical.insert(0, {"fullyQualifiedName": pointer, "kind": "member"})
    location: dict[str, Any] = {"physicalLocation": physical}
    if logical:
        location["logicalLocations"] = logical
    return location


def _fingerprint(finding: Finding) -> str:
    material = json.dumps([finding.check_id, finding.subject_refs, finding.inputs], separators=(",", ":"))
    return hashlib.sha256(material.encode()).hexdigest()


def _rule(check_id: str) -> dict[str, Any]:
    spec = CHECKS.get(check_id)
    if spec is None:
        return {"id": check_id, "name": check_id}
    tags = ["security", "agentbom", *(f"{m.framework}:{m.id}" for m in spec.mappings)]
    return {
        "id": spec.id,
        "name": "".join(part.capitalize() for part in re.split(r"[^A-Za-z0-9]+", spec.title) if part),
        "shortDescription": {"text": spec.title},
        "fullDescription": {"text": spec.description or spec.title},
        "help": {"text": spec.remediation, "markdown": f"**Remediation.** {spec.remediation}"},
        "helpUri": f"https://aisecnomad.github.io/symbiote/policy/checks/#{spec.id.lower()}",
        "defaultConfiguration": {"level": _LEVEL[spec.severity]},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[spec.severity],
            "tags": tags,
            "precision": "high",
        },
    }


def to_sarif(findings: Iterable[Finding], *, artifact_root: str | None = None) -> dict[str, Any]:
    """Render findings as one SARIF run."""
    items = list(findings)
    rule_ids = sorted({f.check_id for f in items})
    index = {rid: i for i, rid in enumerate(rule_ids)}
    results: list[dict[str, Any]] = []
    for finding in items:
        indeterminate = finding.state is FindingState.INDETERMINATE
        location = _location(finding.locator, finding.subject_refs)
        result: dict[str, Any] = {
            "ruleId": finding.check_id,
            "ruleIndex": index[finding.check_id],
            "level": "note" if indeterminate else _LEVEL[finding.severity],
            "kind": "review" if indeterminate else "fail",
            "message": {"text": finding.message},
            "partialFingerprints": {"symbiote/v1": _fingerprint(finding)},
            "properties": {
                "state": finding.state.value,
                "severity": finding.severity.value,
                "security-severity": _SECURITY_SEVERITY[finding.severity],
                "subjects": finding.subject_refs,
                "inputs": finding.inputs,
                "mappings": [f"{m.framework}:{m.id}" for m in finding.mappings],
            },
        }
        if location:
            result["locations"] = [location]
        results.append(result)
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "symbiote",
                "semanticVersion": __version__,
                "informationUri": "https://github.com/aisecnomad/symbiote",
                "rules": [_rule(r) for r in rule_ids],
            }
        },
        "results": results,
        "columnKind": "unicodeCodePoints",
    }
    if artifact_root:
        run["originalUriBaseIds"] = {"SRCROOT": {"uri": artifact_root.rstrip("/") + "/"}}
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
