"""SARIF rules for every category: earlier tags unchanged, framework tags added, still valid."""

from __future__ import annotations

from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import MCPServerComponent, RiskAssessment
from nexus_symbiote.crosswalk import CROSSWALK, sarif_tag
from nexus_symbiote.generators._rules import RULES
from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.generators.validation import validate_sarif

CRITICAL, HIGH = RiskSeverity.CRITICAL, RiskSeverity.HIGH
# The catalog before the crosswalk, as SARIF consumers saw it: CWE numbers, OWASP
# identifiers and per-severity CWE numbers.
EARLIER: dict[str, tuple[tuple[int, ...], tuple[str, ...], dict[RiskSeverity, tuple[int, ...]]]] = {
    "version_pinning": ((829,), ("LLM03", "ASI04"), {}),
    "mutable_image_tag": ((829,), ("LLM03", "ASI04"), {}),
    "transport_security": ((), ("ASI07",), {HIGH: (319,), CRITICAL: (319,)}),
    "local_process": ((), ("ASI07",), {}),
    "authentication": ((306,), ("ASI03", "ASI07"), {}),
    "serialization_format": ((), ("LLM03", "ASI04", "ASI05"), {CRITICAL: (502,), HIGH: (1336,)}),
    "serialization_format_unknown": ((502,), ("LLM03", "ASI04"), {}),
    "signing_status": ((345,), ("LLM03", "ASI04"), {}),
    "code_execution": ((494, 829), ("LLM03", "ASI04", "ASI05"), {}),
    "invisible_characters": ((451, 1427), ("LLM01", "ASI01"), {}),
    "bidi_override": ((451, 1427), ("LLM01", "ASI01"), {}),
    "tag_characters": ((451, 1427), ("LLM01", "ASI01"), {}),
    "prompt_size": ((), ("LLM01", "ASI01"), {}),
    "instruction_layering": ((), ("LLM01", "ASI01"), {}),
    "permission_scope": ((250,), ("LLM06", "ASI02", "ASI03"), {}),
    "capability_scope": ((), ("LLM06", "ASI02"), {}),
    "data_integrity": ((), ("LLM04", "LLM08", "ASI06"), {HIGH: (319,), CRITICAL: (319,)}),
    "rag_discovery": ((), ("LLM08", "ASI06"), {}),
    "attestation": ((345,), ("LLM03", "ASI04"), {}),
    "completeness": ((), (), {}),
    "detection_method": ((), (), {}),
    "shadowscan-heuristic": ((), (), {}),
    "shadowscan-inventory-unmatched": ((), (), {}),
}
NEW_PREFIXES = (
    "external/owasp-llm-top-10-2026/",
    "external/mitre-atlas/",
    "external/nist-ai-rmf/",
)


def _earlier_tags(category: str, severity: RiskSeverity) -> list[str]:
    cwe, owasp, by_severity = EARLIER[category]
    owasp_tags = [
        f"external/owasp-llm-top-10-2025/{item.lower()}"
        if item.startswith("LLM")
        else f"external/owasp-agentic-top-10/{item.lower()}"
        for item in owasp
    ]
    numbers = by_severity.get(severity, cwe)
    return ["security", *(f"external/cwe/cwe-{number:03d}" for number in numbers), *owasp_tags]


def _rules() -> dict[str, dict[str, Any]]:
    """The SARIF rules for every catalogued category at every severity, by rule id."""
    risks = [
        RiskAssessment(severity=severity, category=category, detail=f"{category} {severity}")
        for category in sorted(RULES)
        for severity in RiskSeverity
    ]
    bom = AIBOM(components=[MCPServerComponent(bom_ref="server", name="s", risks=risks)])
    document = SARIFGenerator().generate(bom)
    assert validate_sarif(document) == []
    rules: list[dict[str, Any]] = document["runs"][0]["tool"]["driver"]["rules"]
    return {rule["id"]: rule for rule in rules}


def test_every_category_has_its_own_rule_with_valid_bounded_tags():
    rules = _rules()
    assert len(rules) == len(RULES) * len(RiskSeverity)
    for category, info in RULES.items():
        for severity in RiskSeverity:
            rule = rules[f"nexus_symbiote/{category}/{severity.value}"]
            assert rule["shortDescription"]["text"] == f"{info.title} ({severity.value})"
            assert rule["fullDescription"]["text"] == info.description
            tags = rule["properties"]["tags"]
            assert tags[0] == "security" and len(tags) == len(set(tags)) <= 10
            assert all(tag == tag.lower() for tag in tags)
            assert not any("eu-ai-act" in tag or "42001" in tag for tag in tags)
    assert set(CROSSWALK) == set(RULES)


def test_earlier_tags_are_unchanged_and_new_tags_only_follow_them():
    rules = _rules()
    for category in EARLIER:
        for severity in RiskSeverity:
            tags = rules[f"nexus_symbiote/{category}/{severity.value}"]["properties"]["tags"]
            earlier = _earlier_tags(category, severity)
            assert tags[: len(earlier)] == earlier, (category, severity)
            added = tags[len(earlier) :]
            assert all(tag.startswith(NEW_PREFIXES) for tag in added), (category, added)


def test_references_said_to_come_from_the_earlier_rules_are_earlier_tags():
    kept = [
        (category, reference)
        for category, references in CROSSWALK.items()
        for reference in references
        if "earlier SARIF rules" in reference.rationale
    ]
    assert len(kept) == 5
    for category, reference in kept:
        tag = sarif_tag(reference.framework, reference.entry)
        severities = [severity for severity in RiskSeverity if reference.applies(severity)]
        assert severities and tag
        for severity in severities:
            assert tag in _earlier_tags(category, severity), (category, reference.entry, severity)


def test_new_framework_tags_are_present():
    rules = _rules()

    def tags(category: str, severity: str) -> list[str]:
        return list(rules[f"nexus_symbiote/{category}/{severity}"]["properties"]["tags"])

    assert tags("version_pinning", "high") == [
        "security",
        "external/cwe/cwe-829",
        "external/owasp-llm-top-10-2025/llm03",
        "external/owasp-agentic-top-10/asi04",
        "external/owasp-llm-top-10-2026/llm04",
        "external/mitre-atlas/aml.t0109",
        "external/nist-ai-rmf/manage-3.1",
    ]
    assert "external/owasp-llm-top-10-2026/llm03" in tags("permission_scope", "medium")
    assert "external/mitre-atlas/aml.t0010.005" in tags("launcher_identity", "high")
    assert "external/mitre-atlas/aml.t0105" in tags("permission_scope", "high")
    assert tags("shadowscan-heuristic", "high") == ["security"]


def test_tags_hold_for_every_kind_of_finding_of_the_rule():
    rules = _rules()

    def tags(category: str, severity: str) -> list[str]:
        return list(rules[f"nexus_symbiote/{category}/{severity}"]["properties"]["tags"])

    model = [
        "external/owasp-llm-top-10-2025/llm03",
        "external/owasp-agentic-top-10/asi04",
        "external/owasp-agentic-top-10/asi05",
        "external/owasp-llm-top-10-2026/llm04",
        "external/mitre-atlas/aml.t0011.000",
        "external/nist-ai-rmf/manage-3.2",
    ]
    assert tags("serialization_format", "critical") == ["security", "external/cwe/cwe-502", *model]
    assert tags("serialization_format", "high") == ["security", "external/cwe/cwe-1336", *model]
    assert tags("serialization_format", "medium") == ["security", *model]
    assert tags("authentication", "medium") == [
        "security",
        "external/cwe/cwe-306",
        "external/owasp-agentic-top-10/asi03",
        "external/owasp-agentic-top-10/asi07",
        "external/nist-ai-rmf/measure-2.7",
    ]
    assert tags("nonregistry_source", "medium") == ["security"]
    assert "external/owasp-llm-top-10-2025/llm03" in tags("nonregistry_source", "high")
    assert tags("lockfile_unread", "low") == ["security", "external/nist-ai-rmf/govern-1.6"]


def test_a_category_outside_the_catalog_keeps_the_generic_rule():
    bom = AIBOM(
        components=[
            MCPServerComponent(
                bom_ref="server",
                name="s",
                risks=[RiskAssessment(severity=HIGH, category="made_up_category", detail="x")],
            )
        ]
    )
    (rule,) = SARIFGenerator().generate(bom)["runs"][0]["tool"]["driver"]["rules"]
    assert rule["properties"]["tags"] == ["security"]
    assert rule["shortDescription"]["text"] == "Made up category (high)"
