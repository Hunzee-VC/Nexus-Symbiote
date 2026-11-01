"""Rego export: module shape, severities, input paths, enum literals and (when ``opa`` is installed) parity.

The parity test is the contract from ``spec/checks.md``: for every exported check, OPA over the companion
document yields exactly the built-in engine's failing findings. Without ``opa`` the structural tests still pin
every field path and enum literal the rules read to the published companion schema, so a renamed field or enum
value fails here instead of silently disabling a rule.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime
from enum import StrEnum
from functools import reduce
from pathlib import Path
from typing import Any

import pytest

from symbiote.export.companion import companion_bytes, load_companion
from symbiote.export.companion.emit import load_companion_schema
from symbiote.model.document import AgentBOM
from symbiote.model.enums import (
    CoverageStatus,
    CredentialStorageKind,
    DigestStatus,
    EdgeType,
    FindingState,
    IdentityKind,
    InstructionKind,
    ModelKind,
    SerializationRisk,
    Severity,
    SignatureStatus,
    ToolSource,
    Transport,
    TriState,
    ValueState,
)
from symbiote.policy import CHECKS, REGO_RULES, explain, export_rego, render_module, run_policy
from symbiote.policy.checks.models import _WEIGHTS_KINDS
from symbiote.policy.checks.tools import _DECLARED_ONLY
from symbiote.policy.rego import EXTRA_SEVERITIES, QUERY

#: Every document path the exported rules read ("[]" = array item, "{}" = map value).
INPUT_PATHS = (
    "subject",
    "snapshot.validity.notAfter",
    "coverage.surfaces{}.status",
    "edges[].type",
    "edges[].from",
    "edges[].to",
    "toolServers[].id",
    "toolServers[].name",
    "toolServers[].tags[]",
    "toolServers[].package.state",
    "toolServers[].package.value.floating",
    "toolServers[].package.value.purl",
    "toolServers[].transport.value",
    "toolServers[].endpoint.value",
    "toolServers[].crossesTrustBoundary.value",
    "toolServers[].clientTrustFlags{}",
    "credentialBindings[].id",
    "credentialBindings[].tags[]",
    "credentialBindings[].storage.kind",
    "credentialBindings[].storage.locator",
    "credentialBindings[].subjectRef",
    "credentialBindings[].identityRef",
    "tools[].id",
    "tools[].toolName",
    "tools[].source",
    "tools[].serverRef",
    "tools[].inputSchema",
    "tools[].outputSchema",
    "tools[].digest.status",
    "tools[].digest.reason",
    "tools[].digest.value",
    "models[].id",
    "models[].name",
    "models[].kind",
    "models[].weights",
    "models[].signature.status",
    "models[].tags[]",
    "models[].serialization.state",
    "models[].serialization.value.riskClass",
    "models[].serialization.value.trustRemoteCode",
    "models[].serialization.value.chatTemplateExecutable",
    "models[].hosted.value.endpointOrigin",
    "instructions[].id",
    "instructions[].path",
    "instructions[].kind",
    "instructions[].precedence",
    "instructions[].tags[]",
    "instructions[].loadsRemote.state",
    "instructions[].loadsRemote.value[]",
    "skills[].id",
    "skills[].path",
    "skills[].tags[]",
    "identities[].id",
    "identities[].kind",
    "identities[].ref",
    "identities[].tags[]",
)

#: Enum values the rules compare against, by the enum that defines them.
ENUM_LITERALS: dict[type[StrEnum], set[str]] = {
    ValueState: {"present"},
    Transport: {"stdio"},
    CredentialStorageKind: {"file"},
    ToolSource: {"declared-config"},
    DigestStatus: {"ok"},
    SerializationRisk: {"code-exec-on-load", "template-execution"},
    TriState: {"true"},
    ModelKind: {"weights", "adapter", "embedding"},
    SignatureStatus: {"verified", "unsigned"},
    InstructionKind: {"hook"},
    IdentityKind: {"github-app"},
    EdgeType: {"holdsCredential"},
    CoverageStatus: {"queried"},
}


def _deref(node: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    while "$ref" in node:
        ref = node["$ref"]
        assert ref.startswith("#/"), ref
        node = reduce(lambda n, k: n[k], ref[2:].split("/"), root)
    return node


def _branches(node: dict[str, Any], root: dict[str, Any]) -> list[dict[str, Any]]:
    node = _deref(node, root)
    subs = [s for key in ("anyOf", "oneOf", "allOf") for s in node.get(key, [])]
    return [b for s in subs for b in _branches(s, root)] if subs else [node]


def _step(node: dict[str, Any], root: dict[str, Any], token: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for branch in _branches(node, root):
        if token == "[]" and isinstance(branch.get("items"), dict):
            out.append(branch["items"])
        elif token == "{}":
            if isinstance(branch.get("additionalProperties"), dict):
                out.append(branch["additionalProperties"])
            out.extend(branch.get("patternProperties", {}).values())
        elif token in branch.get("properties", {}):
            out.append(branch["properties"][token])
    return out


def _resolve(path: str, schema: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = [schema]
    for token in re.findall(r"\[\]|\{\}|[A-Za-z0-9_$]+", path):
        nodes = [child for n in nodes for child in _step(n, schema, token)]
        if not nodes:
            return []
    return nodes


def _delimiters_balanced(text: str) -> bool:
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "([{":
            stack.append(ch)
        elif ch in pairs and (not stack or stack.pop() != pairs[ch]):
            return False
    return not stack and not in_string


def test_module_header_and_sections() -> None:
    module = render_module()
    assert "\npackage agentbom\n" in module
    assert "\nimport rego.v1\n" in module
    assert "\ndeny contains msg if {" in module  # Conftest entry point
    for check_id in REGO_RULES:
        assert f"\n# {check_id}: {CHECKS[check_id].title}\n" in module
    assert _delimiters_balanced(module)
    for check_id, body in REGO_RULES.items():
        assert _delimiters_balanced(body), check_id
        assert "\t" in body and "    " not in body, f"{check_id}: Rego bodies are tab-indented"


def test_rule_ids_and_severities_match_the_specs() -> None:
    module = render_module()
    pairs = set(re.findall(r'finding\("(SYM-[A-Z0-9]+-\d{3})", "(\w+)"', module))
    assert {cid for cid, _ in pairs} == set(REGO_RULES)
    assert set(REGO_RULES) <= set(CHECKS)
    for cid, severity in pairs:
        assert severity == CHECKS[cid].severity.value or severity in EXTRA_SEVERITIES.get(cid, ()), (
            cid,
            severity,
        )


def test_manifest_partitions_the_checks(tmp_path: Path) -> None:
    manifest = export_rego(tmp_path / "out")
    assert (tmp_path / "out" / "agentbom.rego").read_text(encoding="utf-8") == render_module()
    on_disk = json.loads((tmp_path / "out" / "manifest.json").read_text(encoding="utf-8"))
    assert on_disk == manifest
    rego, builtin = set(on_disk["rego"]), set(on_disk["builtinOnly"])
    assert rego.isdisjoint(builtin)
    assert rego | builtin == set(CHECKS)
    assert on_disk["query"] == QUERY == "data.agentbom.findings"
    # Reachability, ordered decision tables and baselines stay built-in, so they must never appear as Rego.
    assert {"SYM-AUTHZ-001", "SYM-HITL-001", "SYM-TOOL-002", "SYM-INSTR-003", "SYM-SNAP-001"} <= builtin
    assert explain("SYM-MCP-002")["rego"] is True
    assert explain("SYM-AUTHZ-001")["rego"] is False


@pytest.mark.parametrize("path", INPUT_PATHS)
def test_input_paths_exist_in_the_companion_schema(path: str) -> None:
    assert _resolve(path, load_companion_schema()), f"{path} is not in the companion schema"


def test_enum_literals_exist_and_are_used() -> None:
    module = render_module()
    for enum, literals in ENUM_LITERALS.items():
        values = {member.value for member in enum}
        for literal in literals:
            assert literal in values, f"{literal!r} is not a {enum.__name__} value"
            assert f'"{literal}"' in module, f"{literal!r} is no longer used; drop it from ENUM_LITERALS"
    assert {k.value for k in _WEIGHTS_KINDS} == ENUM_LITERALS[ModelKind]
    assert f'"{_DECLARED_ONLY}"' in module
    for severity in re.findall(r'finding\("SYM-[A-Z0-9]+-\d{3}", "(\w+)"', module):
        assert severity in {s.value for s in Severity}


def _opa() -> str:
    """The ``opa`` binary; skips locally when absent, fails in the CI parity job (``SYMBIOTE_REQUIRE_OPA=1``)."""
    opa = shutil.which("opa")
    if opa is None:
        if os.environ.get("SYMBIOTE_REQUIRE_OPA") == "1":
            pytest.fail("SYMBIOTE_REQUIRE_OPA=1 but `opa` is not on PATH")
        pytest.skip("opa is not installed (the CI rego-parity job installs it)")
    return opa


def _opa_findings(opa: str, bom: AgentBOM, tmp_path: Path) -> set[tuple[str, str, tuple[str, ...]]]:
    export_rego(tmp_path / "rego")
    document = tmp_path / "agentbom.json"
    document.write_bytes(companion_bytes(bom, validate=False))
    proc = subprocess.run(
        [opa, "eval", "--format", "json", "--data", str(tmp_path / "rego"), "--input", str(document), QUERY],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    value = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    return {(f["checkId"], f["severity"], tuple(sorted(f["subjectRefs"]))) for f in value}


def _builtin_findings(bom: AgentBOM) -> set[tuple[str, str, tuple[str, ...]]]:
    result = run_policy(bom, select=sorted(REGO_RULES), now=datetime.now(UTC))
    return {
        (f.check_id, f.severity.value, tuple(sorted(f.subject_refs)))
        for f in result.findings
        if f.state is FindingState.FAIL
    }


def test_opa_parity_on_the_risky_agent(risky_bom: AgentBOM, tmp_path: Path) -> None:
    opa = _opa()
    builtin = _builtin_findings(risky_bom)
    assert len({cid for cid, _, _ in builtin}) >= 8, "the fixture should exercise most exported checks"
    assert _opa_findings(opa, risky_bom, tmp_path) == builtin


def test_opa_parity_on_a_minimal_document(tmp_path: Path) -> None:
    opa = _opa()
    golden = Path(__file__).parents[2] / "golden" / "companion" / "minimal.agentbom.json"
    bom = load_companion(golden)
    assert _opa_findings(opa, bom, tmp_path) == _builtin_findings(bom)


def test_opa_check_accepts_the_module(tmp_path: Path) -> None:
    opa = _opa()
    export_rego(tmp_path)
    subprocess.run([opa, "check", str(tmp_path / "agentbom.rego")], check=True, timeout=60)
