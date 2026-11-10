"""Rule catalog for SARIF: application-owned titles, help and taxonomy tags.

Rule text never comes from the inventory. CWE tags use GitHub's
``external/cwe/cwe-NNN`` form; OWASP tags name the OWASP Top 10 for LLM Applications
2025 (``LLM01``-``LLM10``) and the OWASP Top 10 for Agentic Applications (``ASI01``-
``ASI10``). docs/standard-exports.md lists the same table.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from nexus_symbiote.core.enums import RiskSeverity


@dataclass(frozen=True)
class RuleInfo:
    title: str
    description: str
    cwe: tuple[int, ...] = ()
    owasp: tuple[str, ...] = ()
    # Categories whose findings differ in kind by severity carry their own CWE set.
    cwe_by_severity: dict[RiskSeverity, tuple[int, ...]] = field(default_factory=dict)

    def tags(self, severity: RiskSeverity) -> list[str]:
        cwe = self.cwe_by_severity.get(severity, self.cwe)
        owasp = [
            f"external/owasp-llm-top-10-2025/{item.lower()}"
            if item.startswith("LLM")
            else f"external/owasp-agentic-top-10/{item.lower()}"
            for item in self.owasp
        ]
        return ["security", *(f"external/cwe/cwe-{number:03d}" for number in cwe), *owasp]


_SUPPLY_CHAIN = ("LLM03", "ASI04")
_INSTRUCTION = ("LLM01", "ASI01")

RULES: dict[str, RuleInfo] = {
    "version_pinning": RuleInfo(
        "Unpinned version",
        "A dependency, MCP server package or container image is declared without an exact "
        "version or digest, so what runs can change without a change to the repository.",
        cwe=(829,),
        owasp=_SUPPLY_CHAIN,
    ),
    "mutable_image_tag": RuleInfo(
        "Mutable image tag",
        "A container image is referenced by a tag rather than a digest; the tag can be "
        "moved to different image content.",
        cwe=(829,),
        owasp=_SUPPLY_CHAIN,
    ),
    "transport_security": RuleInfo(
        "Transport security",
        "An endpoint is declared without TLS, or an MCP server runs as a local process "
        "whose executable the inventory does not verify.",
        owasp=("ASI07",),
        cwe_by_severity={RiskSeverity.HIGH: (319,), RiskSeverity.CRITICAL: (319,)},
    ),
    "authentication": RuleInfo(
        "Missing authentication requirement",
        "An agent endpoint declares no authentication requirement for itself or a skill.",
        cwe=(306,),
        owasp=("ASI03", "ASI07"),
    ),
    "serialization_format": RuleInfo(
        "Unsafe model serialization",
        "A model artifact uses a format or loader that can execute code or evaluate "
        "templates when the model is loaded.",
        owasp=(*_SUPPLY_CHAIN, "ASI05"),
        cwe_by_severity={RiskSeverity.CRITICAL: (502,), RiskSeverity.HIGH: (1336,)},
    ),
    "serialization_format_unknown": RuleInfo(
        "Unknown model serialization safety",
        "The safety of a model artifact's format or loader could not be established.",
        cwe=(502,),
        owasp=_SUPPLY_CHAIN,
    ),
    "signing_status": RuleInfo(
        "Unsigned model artifact",
        "A model artifact has no verified signature bound to its bytes.",
        cwe=(345,),
        owasp=_SUPPLY_CHAIN,
    ),
    "code_execution": RuleInfo(
        "Remote code execution enabled",
        "A model configuration lets the loader run code from the model repository.",
        cwe=(494, 829),
        owasp=(*_SUPPLY_CHAIN, "ASI05"),
    ),
    "invisible_characters": RuleInfo(
        "Invisible characters in instructions",
        "An instruction file contains invisible Unicode characters that can carry hidden "
        "instructions.",
        cwe=(451, 1427),
        owasp=_INSTRUCTION,
    ),
    "bidi_override": RuleInfo(
        "Bidirectional override in instructions",
        "An instruction file contains bidirectional control characters that can make text "
        "read differently from how it is processed.",
        cwe=(451, 1427),
        owasp=_INSTRUCTION,
    ),
    "tag_characters": RuleInfo(
        "Unicode tag characters in instructions",
        "An instruction file contains invisible Unicode tag characters, a known way to hide "
        "prompt text.",
        cwe=(451, 1427),
        owasp=_INSTRUCTION,
    ),
    "prompt_size": RuleInfo(
        "Large instruction file",
        "An instruction file is large enough to make review for injected text difficult.",
        owasp=_INSTRUCTION,
    ),
    "instruction_layering": RuleInfo(
        "Layered instruction files",
        "An IDE agent reads instructions from more than one location.",
        owasp=_INSTRUCTION,
    ),
    "permission_scope": RuleInfo(
        "Unscoped agent permissions",
        "An IDE agent configuration grants tool permissions without scoping them to resources.",
        cwe=(250,),
        owasp=("LLM06", "ASI02", "ASI03"),
    ),
    "capability_scope": RuleInfo(
        "Destructive tool capability",
        "A tool declares destructive or financial side effects.",
        owasp=("LLM06", "ASI02"),
    ),
    "data_integrity": RuleInfo(
        "Retrieval source integrity",
        "A retrieval source is reached without encryption or declares no content control.",
        owasp=("LLM04", "LLM08", "ASI06"),
        cwe_by_severity={RiskSeverity.HIGH: (319,), RiskSeverity.CRITICAL: (319,)},
    ),
    "rag_discovery": RuleInfo(
        "Undeclared retrieval source",
        "A vector store or retrieval source is referenced without a declared configuration.",
        owasp=("LLM08", "ASI06"),
    ),
    "attestation": RuleInfo(
        "Unattested extension",
        "An agent extension has no verified attestation of its identity or publisher.",
        cwe=(345,),
        owasp=_SUPPLY_CHAIN,
    ),
    "completeness": RuleInfo(
        "Incomplete declaration",
        "A declaration lacks information the inventory needs to detect changes.",
    ),
    "detection_method": RuleInfo(
        "Code-detected reference",
        "A component was inferred from source code rather than declared configuration.",
    ),
    "shadowscan-heuristic": RuleInfo(
        "Imported discovery risk",
        "An imported ShadowScan report rated this component; the rating is heuristic.",
    ),
    "shadowscan-inventory-unmatched": RuleInfo(
        "Imported unmatched discovery",
        "An imported ShadowScan report found no matching inventory entry.",
    ),
}

GENERIC_HELP = (
    "The finding comes from the Nexus SymBiote inventory. Review the component named in "
    "the result and its recommendation, which the result's properties carry. Findings "
    "describe declarations in the repository; they do not establish exploitability."
)
