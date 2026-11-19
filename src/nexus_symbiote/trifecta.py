"""Lethal-trifecta, toxic-flow chain, and tool-shadowing analysis.

Evaluates an AgentBOM offline for three structural agentic risks:

1. **Lethal trifecta (Item 15):** an agent scope combining untrusted input, private
   data access, and external egress or state mutation without an explicit approval gate
   is rated ``critical``. An identical agent with an explicit approval gate on the
   egress/mutating surface stays clean.
2. **Chained toxic flows (Item 24):** a leak or state-mutation chain possible only by
   combining two distinct components (source + sink) produces one ``toxic_flow`` finding
   naming both components rather than treating each in isolation as clean.
3. **Tool shadowing (Item 24):** two distinct tool definitions that collide on a
   normalized, confusable-folded tool name across servers or sources produce one
   ``tool_shadowing`` finding, escalated to ``high`` when a lower-trust source shadows
   a higher-trust one.

All rules operate strictly on recorded inventory evidence without executing code or
contacting the network. Untrusted ad-hoc inventory properties (such as
``properties.requires_approval``) and unverified IDE starting modes cannot clear a gate.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import (
    AssuranceLevel,
    CapabilityClass,
    HumanInTheLoop,
    RiskSeverity,
    SideEffectProfile,
    TrustTier,
)
from nexus_symbiote.core.models import (
    A2AClientComponent,
    A2AServerComponent,
    AgentComponent,
    AnyComponent,
    AuthorizationRecord,
    CapabilityDeclaration,
    DataSourceComponent,
    IDEAgentComponent,
    MCPClientComponent,
    MCPServerComponent,
    MemoryStoreComponent,
    RAGSourceComponent,
    ToolComponent,
)
from nexus_symbiote.risk_classes import RiskClass, RiskClassification, classify

# Case-preserving confusable skeleton table covering Cyrillic, Greek, and common
# Latin homoglyphs so evasion via look-alike letters normalizes identically.
_CONFUSABLES = str.maketrans(
    {
        # Cyrillic uppercase
        "\u0410": "A",
        "\u0412": "B",
        "\u0421": "C",
        "\u0415": "E",
        "\u0401": "E",
        "\u041d": "H",
        "\u0406": "I",
        "\u0407": "I",
        "\u0408": "J",
        "\u041a": "K",
        "\u041c": "M",
        "\u041e": "O",
        "\u0420": "P",
        "\u0405": "S",
        "\u0422": "T",
        "\u0425": "X",
        "\u04ae": "Y",
        # Cyrillic lowercase
        "\u0430": "a",
        "\u0432": "b",
        "\u0441": "c",
        "\u0501": "d",
        "\u0435": "e",
        "\u0451": "e",
        "\u04bb": "h",
        "\u043d": "h",
        "\u0456": "i",
        "\u0457": "i",
        "\u0458": "j",
        "\u043a": "k",
        "\u04cf": "l",
        "\u043c": "m",
        "\u043e": "o",
        "\u0440": "p",
        "\u0455": "s",
        "\u0442": "t",
        "\u0443": "y",
        "\u0475": "v",
        "\u0445": "x",
        # Greek uppercase
        "\u0391": "A",
        "\u0392": "B",
        "\u0395": "E",
        "\u0396": "Z",
        "\u0397": "H",
        "\u0399": "I",
        "\u039a": "K",
        "\u039c": "M",
        "\u039d": "N",
        "\u039f": "O",
        "\u03a1": "P",
        "\u03a4": "T",
        "\u03a5": "Y",
        "\u03a7": "X",
        # Greek lowercase
        "\u03b1": "a",
        "\u03b2": "b",
        "\u03b5": "e",
        "\u03b9": "i",
        "\u03ba": "k",
        "\u03bc": "m",
        "\u03bd": "v",
        "\u03bf": "o",
        "\u03c1": "p",
        "\u03c4": "t",
        "\u03c5": "u",
        "\u03c7": "x",
        # Latin/Armenian look-alikes
        "\u0261": "g",
        "\u0578": "n",
        "\u0131": "i",
    }
)
_CAMEL_ACRONYM_RE = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL_BOUNDARY_RE = re.compile(r"([a-z0-9])([A-Z])")
_SEPARATOR_RE = re.compile(r"[\s\-_.]+")
_IDENT_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_WITHHELD_ENV_NAME_RE = re.compile(r"\[redacted-[1-9][0-9]{0,5}\]")

# Environment variable names that plausibly carry credentials, tokens, or private DSNs.
# Benign runtime knobs (TZ, LANG, NODE_ENV, PORT, DEBUG, LOG_LEVEL) do not match.
_SECRET_ENV_KEY_RE = re.compile(
    r"(?:^|_)(?:"
    r"secret|secrets|token|tokens|password|passwd|pass|pwd|"
    r"cred|creds|credential|credentials|auth|bearer|cookie|cookies|session|"
    r"private|private_key|api_key|apikey|access_key|signing_key|encryption_key|"
    r"master_key|ssh_key|gpg_key|cert_key|client_secret|jwt|oauth|pat|pem|"
    r"dsn|conn_str|connection_string|database_url|db_url|redis_url|mongo_uri|"
    r"kubeconfig|vault"
    r")(?:$|_)|^(?:aws_access|aws_secret|aws_session|openai_|anthropic_|"
    r"gh_token|github_token|slack_token|stripe_|gcp_|azure_client_secret)",
    re.IGNORECASE,
)

# Tool name patterns (applied to canonical_tool_name(), which splits camelCase and
# folds Unicode confusables). Outbound sinks (send_webhook, post_slack) are excluded
# from external-reader patterns so they do not satisfy untrusted_input on their own.
_UNTRUSTED_TOOL_RE = re.compile(
    r"(?:^|_)(?:"
    r"fetch|fetch_url|web_fetch|get_url|load_url|read_url|open_url|fetch_page|get_page|"
    r"scrape|scrape_url|crawl|browse|browser|web_browse|web_search|search_web|"
    r"http_get|curl|download|download_url|read_web|external_read|"
    r"read_email|fetch_email|get_email|list_emails|read_issue|read_pr|"
    r"read_comment|read_message|read_slack|read_webhook|receive_webhook"
    r")(?:$|_)"
)
_UNTRUSTED_DESC_RE = re.compile(
    r"(?:^|_)(?:fetch_external|web_page|web_pages|scrape|crawl|browse_web|"
    r"read_email|search_web|download_url|http_get|external_web)(?:$|_)"
)
_PRIVATE_TOOL_RE = re.compile(
    r"(?:^|_)(?:"
    r"read_file|file_read|read_files|cat_file|open_file|view_file|load_file|get_file|"
    r"list_files|read_dir|search_files|grep_files|"
    r"read_secret|read_secrets|get_secret|get_secrets|list_secret|list_secrets|"
    r"fetch_secret|secret|secrets|vault|keychain|credential|credentials|"
    r"env_read|read_env|get_env|dump_env|"
    r"db_query|query_db|sql_query|run_sql|execute_sql|read_db|"
    r"customer_data|private_data|internal_doc|internal_docs|"
    r"read_email|list_emails|get_email|read_drive|read_s3|get_object|"
    r"read_config|read_ssh|read_key|private_key"
    r")(?:$|_)"
)
_EGRESS_TOOL_RE = re.compile(
    r"(?:^|_)(?:"
    r"send_webhook|post_webhook|webhook_send|send_email|send_mail|email_send|"
    r"send_message|post_message|post_slack|slack_post|send_report|send_data|"
    r"http_post|http_put|http_patch|http_delete|http_request|post_data|upload|publish|"
    r"notify|write_file|delete_file|exec|execute|shell|bash|run_command|eval|run_code|"
    r"git_push|create_pr|create_issue"
    r")(?:$|_)"
)

# Token sets for static MCP server launcher packages and declared server names.
_MCP_UNTRUSTED_TOKENS = frozenset(
    [
        "fetch",
        "web",
        "browser",
        "playwright",
        "puppeteer",
        "brave",
        "tavily",
        "exa",
        "firecrawl",
        "crawl",
        "scrape",
        "http",
        "curl",
        "rss",
        "slack",
        "discord",
        "email",
        "gmail",
        "outlook",
        "imap",
        "github",
        "gitlab",
        "jira",
        "linear",
        "notion",
        "confluence",
        "zendesk",
        "intercom",
        "reddit",
        "twitter",
        "youtube",
        "wikipedia",
        "docs",
        "search",
        "news",
        "feed",
    ]
)
_MCP_PRIVATE_TOKENS = frozenset(
    [
        "filesystem",
        "fs",
        "files",
        "postgres",
        "postgresql",
        "sqlite",
        "mysql",
        "mariadb",
        "mssql",
        "mongodb",
        "mongo",
        "redis",
        "dynamodb",
        "bigquery",
        "snowflake",
        "duckdb",
        "database",
        "db",
        "sql",
        "vault",
        "secrets",
        "secret",
        "keychain",
        "onepassword",
        "1password",
        "bitwarden",
        "aws",
        "gcp",
        "azure",
        "s3",
        "gcs",
        "gdrive",
        "drive",
        "dropbox",
        "onedrive",
        "email",
        "gmail",
        "outlook",
        "imap",
        "crm",
        "salesforce",
        "hubspot",
        "zendesk",
        "stripe",
        "plaid",
        "git",
    ]
)
_MCP_EGRESS_TOKENS = frozenset(
    [
        "slack",
        "discord",
        "email",
        "gmail",
        "outlook",
        "smtp",
        "webhook",
        "github",
        "gitlab",
        "jira",
        "linear",
        "shell",
        "bash",
        "terminal",
        "exec",
        "playwright",
        "puppeteer",
        "browser",
        "twilio",
        "sendgrid",
        "pagerduty",
        "stripe",
    ]
)

_MUTATING_CAPABILITIES = frozenset(
    {
        CapabilityClass.WRITE,
        CapabilityClass.EXECUTE,
        CapabilityClass.DESTRUCTIVE,
        CapabilityClass.PAYMENT,
    }
)
_PRIVATE_CAPABILITIES = frozenset({CapabilityClass.CREDENTIALS, CapabilityClass.FILESYSTEM})
_MUTATING_SIDE_EFFECTS = frozenset(
    {
        SideEffectProfile.STATE_MODIFYING,
        SideEffectProfile.DESTRUCTIVE,
        SideEffectProfile.FINANCIAL_TRANSACTION,
    }
)

_SEVERITY_RANK: dict[RiskSeverity, int] = {
    RiskSeverity.CRITICAL: 0,
    RiskSeverity.HIGH: 1,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.LOW: 3,
    RiskSeverity.INFO: 4,
}
_TRUST_RANK: dict[TrustTier, int] = {
    TrustTier.INTERNAL_VERIFIED: 5,
    TrustTier.INTERNAL_UNVERIFIED: 4,
    TrustTier.THIRD_PARTY_SIGNED: 3,
    TrustTier.THIRD_PARTY_UNSIGNED: 2,
    TrustTier.UNTRUSTED_PUBLIC: 1,
    TrustTier.UNKNOWN: 0,
}
_GATED_CLAUDE_MODES = frozenset({"default", "ask", "plan"})
_UNGATED_CLAUDE_MODES = frozenset({"bypassPermissions", "acceptEdits"})
_GATED_CODEX_POLICIES = frozenset({"on-request", "untrusted"})
_UNGATED_CODEX_POLICIES = frozenset({"never"})
_SHADOW_HIGH_TIERS = frozenset(
    {TrustTier.THIRD_PARTY_UNSIGNED, TrustTier.UNTRUSTED_PUBLIC, TrustTier.UNKNOWN}
)
_WORKSPACE_SURFACE_TYPES = (
    MCPServerComponent,
    ToolComponent,
    DataSourceComponent,
    MemoryStoreComponent,
    RAGSourceComponent,
    A2AServerComponent,
    A2AClientComponent,
)
_CHAINABLE_TYPES = (ToolComponent, MCPServerComponent)


@dataclass(frozen=True)
class LegEvidence:
    """Evidence tying one component to a trifecta leg."""

    component_ref: str
    component_name: str
    basis: tuple[str, ...]
    locator: str | None
    assurance: AssuranceLevel
    gated: bool


@dataclass(frozen=True)
class FlowFinding:
    """A deterministic, evidence-backed trifecta, toxic-flow, or shadowing finding."""

    kind: str
    severity: RiskSeverity
    scope_ref: str
    summary: str
    component_refs: tuple[str, ...]
    evidence: tuple[dict[str, Any], ...]
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity.value,
            "scope_ref": self.scope_ref,
            "summary": self.summary,
            "component_refs": list(self.component_refs),
            "evidence": list(self.evidence),
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class TrifectaReport:
    """Result of lethal-trifecta, toxic-flow, and tool-shadowing analysis."""

    scopes_evaluated: int
    findings: tuple[FlowFinding, ...]
    shadowed_refs: tuple[str, ...]

    @property
    def has_critical(self) -> bool:
        return any(f.severity is RiskSeverity.CRITICAL for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return {
            "scopes_evaluated": self.scopes_evaluated,
            "finding_count": len(self.findings),
            "severity_counts": dict(sorted(counts.items())),
            "shadowed_refs": list(self.shadowed_refs),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass(frozen=True)
class _ComponentSignals:
    """Precomputed classification and leg bases for a single component."""

    component: AnyComponent
    risk_classification: RiskClassification
    locator: str | None
    untrusted_basis: tuple[str, ...]
    private_basis: tuple[str, ...]
    egress_basis: tuple[str, ...]
    explicitly_gated: bool
    explicitly_ungated: bool


def _normalize_identifier(text: str) -> str:
    """NFKC-normalize, strip invisible/combining chars, fold confusables, split camelCase."""
    normalized = unicodedata.normalize("NFKC", text)
    cleaned = "".join(
        ch
        for ch in normalized
        if unicodedata.category(ch) not in {"Cf", "Cc", "Cs", "Co", "Cn", "Mn"}
    )
    folded = cleaned.translate(_CONFUSABLES)
    split = _CAMEL_ACRONYM_RE.sub(r"\1_\2", folded)
    split = _CAMEL_BOUNDARY_RE.sub(r"\1_\2", split)
    return split.strip().lower()


def canonical_tool_name(name: str) -> str:
    """Normalize a tool name for shadowing and naming-rule detection."""
    return _SEPARATOR_RE.sub("_", _normalize_identifier(name)).strip("_")


def _identifier_tokens(text: str) -> set[str]:
    norm = _normalize_identifier(text)
    return {tok for tok in _IDENT_SPLIT_RE.split(norm) if tok}


def _component_locator(component: AnyComponent) -> str | None:
    if component.source_path:
        return component.source_path
    for claim in component.claims.values():
        if claim.locator:
            return claim.locator
    return None


def _mcp_package_identities(server: MCPServerComponent) -> list[str]:
    identities: list[str] = []
    if server.launcher_package:
        identities.append(server.launcher_package)
    raw_packages = server.properties.get("packages")
    if isinstance(raw_packages, list):
        for entry in raw_packages:
            if isinstance(entry, dict):
                ident = entry.get("identity")
                if isinstance(ident, str) and ident:
                    identities.append(ident)
    return identities


def _ide_has_allow_rules_or_risks(agent: IDEAgentComponent) -> bool:
    counts = agent.properties.get("declared_permission_rule_counts")
    if isinstance(counts, dict):
        allow_count = counts.get("allow")
        if isinstance(allow_count, int) and not isinstance(allow_count, bool) and allow_count > 0:
            return True
    return any(risk.category == "permission_scope" for risk in agent.risks)


def _is_explicitly_ungated(component: AnyComponent) -> bool:
    """True when the component explicitly opts out of approval gates."""
    decl = getattr(component, "capabilities", None)
    if isinstance(decl, CapabilityDeclaration) and decl.human_in_the_loop is HumanInTheLoop.NONE:
        return True
    if isinstance(component, IDEAgentComponent):
        if (
            component.ide_type == "claude-code"
            and component.permission_mode in _UNGATED_CLAUDE_MODES
        ):
            return True
        if component.ide_type == "codex":
            policy = component.properties.get("approval_policy")
            if isinstance(policy, str) and policy in _UNGATED_CODEX_POLICIES:
                return True
    return False


def _has_explicit_approval_gate(component: AnyComponent) -> bool:
    """Fail-closed check: True only when typed, verified approval evidence is recorded.

    Untrusted ad-hoc properties (such as ``properties.requires_approval``) are ignored.
    Static IDE starting modes (such as ``default`` in ``.claude/settings.json``) do not
    gate a scope unless effective authorization was verified without allow-rule bypasses
    or ``permission_scope`` risks.
    """
    if _is_explicitly_ungated(component):
        return False

    decl = getattr(component, "capabilities", None)
    if (
        isinstance(decl, CapabilityDeclaration)
        and decl.human_in_the_loop is HumanInTheLoop.REQUIRED
    ):
        return True

    auths = getattr(component, "authorizations", None)
    if isinstance(auths, list) and auths:
        records = [a for a in auths if isinstance(a, AuthorizationRecord)]
        if records and all(r.approval_required is True for r in records):
            return True

    if isinstance(component, IDEAgentComponent):
        verified = (
            component.properties.get("effective_authorization_verified") is True
            and component.assurance_level in {AssuranceLevel.VERIFIED, AssuranceLevel.OBSERVED}
            and not _ide_has_allow_rules_or_risks(component)
        )
        if not verified:
            return False
        if component.ide_type == "claude-code" and component.permission_mode in _GATED_CLAUDE_MODES:
            return True
        if component.ide_type == "codex":
            policy = component.properties.get("approval_policy")
            if isinstance(policy, str) and policy in _GATED_CODEX_POLICIES:
                return True

    return False


def _is_pure_readonly_network_reader(component: ToolComponent) -> bool:
    """True for a read-only network search/fetch tool with no mutating or exfil capabilities."""
    decl = component.capabilities
    if not isinstance(decl, CapabilityDeclaration):
        return False
    caps = set(decl.capabilities)
    if caps & _MUTATING_CAPABILITIES or caps & _PRIVATE_CAPABILITIES:
        return False
    if decl.egress_domains:
        return False
    if decl.side_effect_profile in _MUTATING_SIDE_EFFECTS:
        return False
    canon = canonical_tool_name(component.name)
    if _EGRESS_TOOL_RE.search(canon):
        return False
    return CapabilityClass.NETWORK in caps and CapabilityClass.READ in caps


def _untrusted_input_basis(component: AnyComponent, rc: RiskClassification) -> tuple[str, ...]:
    basis: set[str] = set()
    props = component.properties
    if props.get("untrusted_input") is True or props.get("reads_untrusted_input") is True:
        basis.add("property:untrusted_input")
    if isinstance(component, (A2AServerComponent, A2AClientComponent)):
        basis.add(f"component_type:{component.component_type.value}")
    if isinstance(component, MCPServerComponent):
        if component.endpoint_url and RiskClass.NETWORK_EGRESS in rc.classes:
            basis.add("mcp_server:remote_endpoint")
        for ident in _mcp_package_identities(component):
            if _identifier_tokens(ident) & _MCP_UNTRUSTED_TOKENS:
                basis.add("mcp_server:untrusted_input_package")
                break
        if _identifier_tokens(component.name) & _MCP_UNTRUSTED_TOKENS:
            basis.add("mcp_server:untrusted_input_name")
    if isinstance(component, IDEAgentComponent):
        for risk in component.risks:
            if risk.category == "permission_scope" and "web fetch" in risk.detail.lower():
                basis.add("ide_agent:unscoped_web_fetch")
                break
    decl = getattr(component, "capabilities", None)
    if isinstance(decl, CapabilityDeclaration):
        caps = set(decl.capabilities)
        if CapabilityClass.NETWORK in caps and CapabilityClass.READ in caps:
            basis.add("capabilities:network+read")
    if isinstance(component, ToolComponent):
        canon = canonical_tool_name(component.name)
        if _UNTRUSTED_TOOL_RE.search(canon):
            basis.add("tool_name:external_reader")
        elif component.description:
            desc_canon = canonical_tool_name(component.description)
            if _UNTRUSTED_DESC_RE.search(desc_canon):
                basis.add("tool_description:external_reader")
    return tuple(sorted(basis))


def _private_data_basis(component: AnyComponent, rc: RiskClassification) -> tuple[str, ...]:
    basis: set[str] = set()
    if RiskClass.SECRET_ACCESS in rc.classes:
        basis.add("risk_class:secret-access")
    if isinstance(component, (DataSourceComponent, MemoryStoreComponent, RAGSourceComponent)):
        basis.add(f"component_type:{component.component_type.value}")
    if isinstance(component, MCPServerComponent):
        if any(
            _WITHHELD_ENV_NAME_RE.fullmatch(key) or _SECRET_ENV_KEY_RE.search(key)
            for key in component.env
        ):
            basis.add("mcp_server:secret_env")
        for ident in _mcp_package_identities(component):
            if _identifier_tokens(ident) & _MCP_PRIVATE_TOKENS:
                basis.add("mcp_server:private_data_package")
                break
        if _identifier_tokens(component.name) & _MCP_PRIVATE_TOKENS:
            basis.add("mcp_server:private_data_name")
    decl = getattr(component, "capabilities", None)
    if isinstance(decl, CapabilityDeclaration):
        caps = set(decl.capabilities)
        for cap in (CapabilityClass.CREDENTIALS, CapabilityClass.FILESYSTEM, CapabilityClass.READ):
            if cap in caps and (
                cap is not CapabilityClass.READ
                or component.properties.get("private_data") is True
                or bool(decl.filesystem_paths)
                or bool(decl.oauth_scopes)
            ):
                basis.add(f"capabilities:{cap.value}")
        if decl.filesystem_paths:
            basis.add("filesystem_paths:declared")
        if decl.oauth_scopes:
            basis.add("oauth_scopes:declared")
    if component.properties.get("private_data") is True:
        basis.add("property:private_data")
    if isinstance(component, ToolComponent):
        canon = canonical_tool_name(component.name)
        if _PRIVATE_TOOL_RE.search(canon):
            basis.add("tool_name:private_reader")
    return tuple(sorted(basis))


def _egress_basis(component: AnyComponent, rc: RiskClassification) -> tuple[str, ...]:
    basis: set[str] = set()
    skip_readonly_net = isinstance(component, ToolComponent) and _is_pure_readonly_network_reader(
        component
    )
    for cls in (
        RiskClass.NETWORK_EGRESS,
        RiskClass.EXFIL_CAPABLE,
        RiskClass.WRITE_CAPABLE,
        RiskClass.CODE_EXEC,
    ):
        if skip_readonly_net and cls in {RiskClass.NETWORK_EGRESS, RiskClass.EXFIL_CAPABLE}:
            continue
        if cls in rc.classes:
            basis.add(f"risk_class:{cls.value}")
    if component.properties.get("external_egress") is True:
        basis.add("property:external_egress")
    if isinstance(component, MCPServerComponent):
        for ident in _mcp_package_identities(component):
            if _identifier_tokens(ident) & _MCP_EGRESS_TOKENS:
                basis.add("mcp_server:egress_package")
                break
        if _identifier_tokens(component.name) & _MCP_EGRESS_TOKENS:
            basis.add("mcp_server:egress_name")
    if isinstance(component, IDEAgentComponent):
        for risk in component.risks:
            if risk.category == "permission_scope" and "shell command" in risk.detail.lower():
                basis.add("ide_agent:unscoped_shell")
                break
    if isinstance(component, ToolComponent) and not skip_readonly_net:
        canon = canonical_tool_name(component.name)
        if _EGRESS_TOOL_RE.search(canon):
            basis.add("tool_name:egress_or_mutation")
    return tuple(sorted(basis))


def _tarjan_scc(nodes: list[str], adj: dict[str, list[str]]) -> list[list[str]]:
    """Iterative Tarjan's strongly connected components in O(V + E) time."""
    index_counter = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    sccs: list[list[str]] = []

    for start in nodes:
        if start in indices:
            continue
        call_stack: list[tuple[str, int]] = [(start, 0)]
        indices[start] = lowlinks[start] = index_counter
        index_counter += 1
        stack.append(start)
        on_stack.add(start)

        while call_stack:
            v, edge_idx = call_stack[-1]
            neighbors = adj.get(v, ())
            if edge_idx < len(neighbors):
                call_stack[-1] = (v, edge_idx + 1)
                w = neighbors[edge_idx]
                if w not in indices:
                    indices[w] = lowlinks[w] = index_counter
                    index_counter += 1
                    stack.append(w)
                    on_stack.add(w)
                    call_stack.append((w, 0))
                elif w in on_stack:
                    if indices[w] < lowlinks[v]:
                        lowlinks[v] = indices[w]
            else:
                call_stack.pop()
                if call_stack:
                    parent = call_stack[-1][0]
                    if lowlinks[v] < lowlinks[parent]:
                        lowlinks[parent] = lowlinks[v]
                if lowlinks[v] == indices[v]:
                    comp_scc: list[str] = []
                    while True:
                        member = stack.pop()
                        on_stack.remove(member)
                        comp_scc.append(member)
                        if member == v:
                            break
                    sccs.append(comp_scc)
    return sccs


def _scopes(
    bom: AIBOM,
    signals: dict[str, _ComponentSignals],
) -> list[tuple[str, bool, list[AnyComponent]]]:
    """Compute evaluation scopes in O(V + E) time using SCC condensation.

    Returns tuples of ``(scope_ref, scope_owner_gated, members)``.
    - Cyclic agent graphs collapse into a single SCC so traversal is linear.
    - IDE agents without explicit MCP/tool bindings inherit the workspace MCP/tool
      surface even when they carry edges to prompt components.
    - Any component left uncovered by all agent scopes is evaluated in an
      ``inventory:unscoped`` scope so empty agents cannot hide unlinked tools.
    """
    by_ref = {comp.bom_ref: comp for comp in bom.components}
    if not by_ref:
        return []

    agents = sorted(
        (c for c in bom.components if isinstance(c, (AgentComponent, IDEAgentComponent))),
        key=lambda c: c.bom_ref,
    )
    if not agents:
        ordered = sorted(bom.components, key=lambda c: c.bom_ref)
        return [("inventory:root", False, ordered)]

    adj: dict[str, list[str]] = {ref: [] for ref in by_ref}
    for dep in bom.dependencies:
        if dep.source_ref in by_ref and dep.target_ref in by_ref:
            adj[dep.source_ref].append(dep.target_ref)

    clients_by_host: dict[str, list[MCPClientComponent]] = {}
    for comp in bom.components:
        if isinstance(comp, AgentComponent):
            for ref in (
                *comp.tool_refs,
                *comp.data_refs,
                *comp.memory_refs,
                *comp.skill_refs,
                *comp.sub_agent_refs,
            ):
                if ref in by_ref:
                    adj[comp.bom_ref].append(ref)
        elif isinstance(comp, IDEAgentComponent):
            for ref in (*comp.mcp_server_refs, *comp.prompt_refs):
                if ref in by_ref:
                    adj[comp.bom_ref].append(ref)
        elif isinstance(comp, MCPClientComponent):
            if comp.host_application:
                clients_by_host.setdefault(comp.host_application, []).append(comp)
            for ref in comp.server_refs:
                if ref in by_ref:
                    adj[comp.bom_ref].append(ref)
        elif isinstance(comp, ToolComponent) and comp.mcp_server_ref in by_ref:
            adj[comp.mcp_server_ref].append(comp.bom_ref)

    for comp in agents:
        if isinstance(comp, IDEAgentComponent) and not comp.mcp_server_refs and comp.ide_type:
            for client in clients_by_host.get(comp.ide_type, ()):
                adj[comp.bom_ref].append(client.bom_ref)

    nodes_sorted = sorted(by_ref)
    sccs = _tarjan_scc(nodes_sorted, adj)
    scc_of: dict[str, int] = {}
    for scc_id, scc_members in enumerate(sccs):
        for ref in scc_members:
            scc_of[ref] = scc_id

    agent_refs = {a.bom_ref for a in agents}
    scc_agents: dict[int, list[AnyComponent]] = {}
    for scc_id, scc_members in enumerate(sccs):
        a_list = sorted(
            (by_ref[r] for r in scc_members if r in agent_refs), key=lambda c: c.bom_ref
        )
        if a_list:
            scc_agents[scc_id] = a_list

    # Condensed DAG edges between SCCs, plus agent-to-agent parent tracking.
    dag_adj: dict[int, list[int]] = {i: [] for i in range(len(sccs))}
    agent_parents: dict[int, set[int]] = {scc_id: set() for scc_id in scc_agents}
    for u, targets in adj.items():
        su = scc_of[u]
        seen_t: set[int] = set()
        for v in targets:
            sv = scc_of[v]
            if sv != su and sv not in seen_t:
                seen_t.add(sv)
                dag_adj[su].append(sv)
                if su in scc_agents and sv in scc_agents:
                    agent_parents[sv].add(su)

    # An agent SCC is gated only if EVERY agent in that SCC has an explicit approval gate
    # and NONE is explicitly ungated.
    scc_gated: dict[int, bool] = {}
    for scc_id, a_list in scc_agents.items():
        scc_gated[scc_id] = all(signals[a.bom_ref].explicitly_gated for a in a_list) and not any(
            signals[a.bom_ref].explicitly_ungated for a in a_list
        )

    # Tarjan emits SCCs in reverse topological order, so reversed(range(len(sccs))) is
    # topological order. Track whether an SCC already has an ungated agent ancestor so
    # alternating-gate chains stay O(V + E) without missing any ungated scope.
    has_ungated_ancestor: dict[int, bool] = dict.fromkeys(range(len(sccs)), False)
    for su in reversed(range(len(sccs))):
        propagates_ungated = has_ungated_ancestor[su] or (su in scc_agents and not scc_gated[su])
        if propagates_ungated:
            for sv in dag_adj[su]:
                has_ungated_ancestor[sv] = True

    selected_sccs: list[int] = []
    for scc_id in sorted(scc_agents, key=lambda sid: scc_agents[sid][0].bom_ref):
        parents = agent_parents[scc_id]
        if not parents or (not scc_gated[scc_id] and not has_ungated_ancestor[scc_id]):
            selected_sccs.append(scc_id)

    workspace_surface = sorted(
        (c for c in bom.components if isinstance(c, _WORKSPACE_SURFACE_TYPES)),
        key=lambda c: c.bom_ref,
    )

    covered_refs: set[str] = set()
    result: list[tuple[str, bool, list[AnyComponent]]] = []

    for scc_id in selected_sccs:
        # BFS over condensed SCCs from scc_id.
        visited_sccs: set[int] = {scc_id}
        queue: list[int] = [scc_id]
        q_idx = 0
        while q_idx < len(queue):
            cur = queue[q_idx]
            q_idx += 1
            for nxt in dag_adj[cur]:
                if nxt not in visited_sccs:
                    visited_sccs.add(nxt)
                    queue.append(nxt)

        member_refs: set[str] = set()
        for sid in visited_sccs:
            member_refs.update(sccs[sid])

        # An IDE agent without explicit MCP/tool bindings governs the repository's
        # workspace MCP/tool surface regardless of prompt edges.
        owners = scc_agents[scc_id]
        has_ide_owner = any(isinstance(a, IDEAgentComponent) for a in owners)
        has_surface = any(
            isinstance(by_ref[r], (MCPServerComponent, ToolComponent)) for r in member_refs
        )
        if has_ide_owner and not has_surface:
            for comp in workspace_surface:
                member_refs.add(comp.bom_ref)

        covered_refs.update(member_refs)
        scope_members = sorted((by_ref[r] for r in member_refs), key=lambda c: c.bom_ref)
        scope_ref = owners[0].bom_ref
        result.append((scope_ref, scc_gated[scc_id], scope_members))

    uncovered = sorted(
        (c for c in bom.components if c.bom_ref not in covered_refs),
        key=lambda c: c.bom_ref,
    )
    if uncovered:
        result.append(("inventory:unscoped", False, uncovered))

    return result


def _evidence_entry(leg: str, item: LegEvidence) -> dict[str, Any]:
    return {
        "leg": leg,
        "component_ref": item.component_ref,
        "component_name": item.component_name,
        "basis": list(item.basis),
        "locator": item.locator,
        "assurance": item.assurance.value,
        "gated": item.gated,
    }


def _detect_shadowing(bom: AIBOM) -> tuple[list[FlowFinding], set[str]]:
    tools = [c for c in bom.components if isinstance(c, ToolComponent)]
    groups: dict[str, list[ToolComponent]] = {}
    for tool in sorted(tools, key=lambda t: t.bom_ref):
        key = canonical_tool_name(tool.name)
        if key:
            groups.setdefault(key, []).append(tool)

    findings: list[FlowFinding] = []
    shadowed_refs: set[str] = set()
    for canon_name, group in sorted(groups.items()):
        if len(group) < 2:
            continue
        distinct_origins = {(t.mcp_server_ref, t.source_path) for t in group}
        if len(distinct_origins) < 2 and len({t.bom_ref for t in group}) < 2:
            continue
        tiers = [t.trust_tier for t in group]
        has_trusted = any(
            _TRUST_RANK[t] >= _TRUST_RANK[TrustTier.THIRD_PARTY_SIGNED] for t in tiers
        )
        has_untrusted = any(t in _SHADOW_HIGH_TIERS for t in tiers)
        severity = RiskSeverity.HIGH if (has_trusted and has_untrusted) else RiskSeverity.MEDIUM
        refs = tuple(t.bom_ref for t in group)
        shadowed_refs.update(refs)
        evidence = tuple(
            {
                "leg": "shadowed_tool",
                "component_ref": t.bom_ref,
                "component_name": t.name,
                "canonical_name": canon_name,
                "server_ref": t.mcp_server_ref,
                "trust_tier": t.trust_tier.value,
                "locator": _component_locator(t),
                "assurance": t.assurance_level.value,
            }
            for t in group
        )
        findings.append(
            FlowFinding(
                kind="tool_shadowing",
                severity=severity,
                scope_ref="inventory:root",
                summary=(
                    f"Tool name '{canon_name}' is defined by {len(group)} distinct components "
                    f"({', '.join(refs)}), creating a tool-shadowing conflict."
                ),
                component_refs=refs,
                evidence=evidence,
                recommendation=(
                    "Namespace tools per server, pin tool definition digests, and remove "
                    "duplicate or lower-trust tool definitions that shadow trusted tools."
                ),
            )
        )
    return findings, shadowed_refs


def analyze_trifecta(bom: AIBOM) -> TrifectaReport:
    """Analyze an inventory for lethal trifectas, chained toxic flows, and tool shadowing."""
    signals: dict[str, _ComponentSignals] = {}
    for comp in bom.components:
        rc = classify(comp)
        signals[comp.bom_ref] = _ComponentSignals(
            component=comp,
            risk_classification=rc,
            locator=_component_locator(comp),
            untrusted_basis=_untrusted_input_basis(comp, rc),
            private_basis=_private_data_basis(comp, rc),
            egress_basis=_egress_basis(comp, rc),
            explicitly_gated=_has_explicit_approval_gate(comp),
            explicitly_ungated=_is_explicitly_ungated(comp),
        )

    scopes = _scopes(bom, signals)
    findings: list[FlowFinding] = []

    for scope_ref, owner_gated, members in scopes:
        effective_owner_gated = owner_gated and not any(
            isinstance(comp, IDEAgentComponent) and signals[comp.bom_ref].explicitly_ungated
            for comp in members
        )
        untrusted: list[LegEvidence] = []
        private: list[LegEvidence] = []
        egress: list[LegEvidence] = []

        for comp in members:
            sig = signals[comp.bom_ref]
            # Fail closed: an explicit opt-out on a component overrides an owner gate.
            gated = (effective_owner_gated or sig.explicitly_gated) and not sig.explicitly_ungated
            if sig.untrusted_basis:
                untrusted.append(
                    LegEvidence(
                        comp.bom_ref,
                        comp.name,
                        sig.untrusted_basis,
                        sig.locator,
                        comp.assurance_level,
                        gated,
                    )
                )
            if sig.private_basis:
                private.append(
                    LegEvidence(
                        comp.bom_ref,
                        comp.name,
                        sig.private_basis,
                        sig.locator,
                        comp.assurance_level,
                        gated,
                    )
                )
            if sig.egress_basis:
                egress.append(
                    LegEvidence(
                        comp.bom_ref,
                        comp.name,
                        sig.egress_basis,
                        sig.locator,
                        comp.assurance_level,
                        gated,
                    )
                )

        ungated_egress = [item for item in egress if not item.gated]

        if untrusted and private and ungated_egress:
            involved = sorted(
                {
                    *(i.component_ref for i in untrusted),
                    *(i.component_ref for i in private),
                    *(i.component_ref for i in ungated_egress),
                }
            )
            evidence = (
                *(_evidence_entry("untrusted_input", i) for i in untrusted),
                *(_evidence_entry("private_data", i) for i in private),
                *(_evidence_entry("egress", i) for i in ungated_egress),
            )
            findings.append(
                FlowFinding(
                    kind="lethal_trifecta",
                    severity=RiskSeverity.CRITICAL,
                    scope_ref=scope_ref,
                    summary=(
                        f"Scope '{scope_ref}' combines untrusted input, private data access, "
                        f"and ungated external egress/state mutation across {len(involved)} "
                        "component(s) without an approval gate."
                    ),
                    component_refs=tuple(involved),
                    evidence=evidence,
                    recommendation=(
                        "Break at least one leg of the trifecta or enforce an explicit "
                        "human-in-the-loop approval gate (human_in_the_loop: required) on "
                        "every egress and state-modifying tool."
                    ),
                )
            )

        # Item 24: Chained toxic flow across two distinct components where neither alone
        # is EXFIL_CAPABLE (linear time without materializing Cartesian pairs).
        chained_sources = [
            item
            for item in private
            if isinstance(signals[item.component_ref].component, _CHAINABLE_TYPES)
            and RiskClass.EXFIL_CAPABLE
            not in signals[item.component_ref].risk_classification.classes
        ]
        chained_sinks = [
            item
            for item in ungated_egress
            if isinstance(signals[item.component_ref].component, _CHAINABLE_TYPES)
            and RiskClass.EXFIL_CAPABLE
            not in signals[item.component_ref].risk_classification.classes
        ]
        if chained_sources and chained_sinks:
            source_refs = {src.component_ref for src in chained_sources}
            sink_refs = {snk.component_ref for snk in chained_sinks}
            active_sources = [
                src
                for src in chained_sources
                if len(sink_refs) > 1 or src.component_ref not in sink_refs
            ]
            active_sinks = [
                snk
                for snk in chained_sinks
                if len(source_refs) > 1 or snk.component_ref not in source_refs
            ]
            if active_sources and active_sinks:
                pair_refs = tuple(
                    sorted(
                        {
                            *(src.component_ref for src in active_sources),
                            *(snk.component_ref for snk in active_sinks),
                        }
                    )
                )
                pair_evidence = (
                    *(_evidence_entry("toxic_source", src) for src in active_sources),
                    *(_evidence_entry("toxic_sink", snk) for snk in active_sinks),
                )
                findings.append(
                    FlowFinding(
                        kind="toxic_flow",
                        severity=RiskSeverity.HIGH,
                        scope_ref=scope_ref,
                        summary=(
                            f"Scope '{scope_ref}' enables a chained toxic flow across "
                            f"{len(pair_refs)} distinct components ({', '.join(pair_refs)}) where "
                            "private data from one component can leave through an ungated sink."
                        ),
                        component_refs=pair_refs,
                        evidence=pair_evidence,
                        recommendation=(
                            "Require explicit approval on egress/state-modifying sink tools or "
                            "isolate private-data tools from network-capable tools."
                        ),
                    )
                )

    shadow_findings, shadowed_refs = _detect_shadowing(bom)
    findings.extend(shadow_findings)
    findings.sort(key=lambda f: (_SEVERITY_RANK[f.severity], f.kind, f.scope_ref, f.component_refs))
    return TrifectaReport(
        scopes_evaluated=len(scopes),
        findings=tuple(findings),
        shadowed_refs=tuple(sorted(shadowed_refs)),
    )
