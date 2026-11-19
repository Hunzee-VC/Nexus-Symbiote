"""Settings-as-security-events precedence and oversight evaluation (`R0.3.0-2`).

Evaluates repository-resident host settings (``permissions.allow``, ``permissions.ask``,
``permissions.deny``, ``alwaysAllow`` / ``autoApprove``, subagent/command/skill front
matter, and Codex ``approval_policy``) to resolve per-tool ``HumanInTheLoop`` state,
detect ``oversight_gap`` on auto-approved destructive tools, extract ``activation`` scope
and ``sandbox.network.allowedDomains``, and flag ``subagent_inline_mcp_server``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from nexus_symbiote.core.enums import HumanInTheLoop, RiskSeverity
from nexus_symbiote.core.models import RiskAssessment
from nexus_symbiote.utils.terminal import neutralize

_DESTRUCTIVE_VERBS_RE = re.compile(
    r"(?:^|[_:/-])(?:delete|destroy|drop|rm|remove|purge|truncate|wipe|reset|"
    r"force[_-]?push|exec|shell|bash|run[_-]?command|kill|terminate)(?:$|[_:/-])",
    re.IGNORECASE,
)
_EXACT_DESTRUCTIVE_TOOLS = frozenset({"bash", "shell", "exec", "sh", "zsh", "powershell", "cmd"})

_AUTO_POLICIES = frozenset({"never", "auto", "bypasspermissions"})
_CONDITIONAL_POLICIES = frozenset({"on-failure"})
_REQUIRED_POLICIES = frozenset({"on-request", "untrusted", "default", "plan", "dontask"})


def _normalize_patterns(raw: Any) -> tuple[str, ...]:
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        return tuple(parts)
    if isinstance(raw, Iterable) and not isinstance(raw, (bytes, Mapping)):
        out: list[str] = []
        for item in raw:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
        return tuple(out)
    return ()


def _tool_pattern_matches(pattern: str, tool_name: str) -> bool:
    """Match a permission rule pattern against a tool name."""
    pat = pattern.strip()
    if not pat:
        return False
    if pat == "*":
        return True
    base = pat.split("(", 1)[0].strip()
    if not base:
        return False
    if base.endswith("*"):
        prefix = base[:-1]
        return tool_name.startswith(prefix)
    return base == tool_name


def is_destructive_tool(tool_name: str, annotations: Mapping[str, Any] | None = None) -> bool:
    """Return True when annotations or tool name indicate destructive or shell capability."""
    if annotations is not None and annotations.get("destructiveHint") is True:
        return True
    lowered = tool_name.strip().lower()
    if lowered in _EXACT_DESTRUCTIVE_TOOLS:
        return True
    return bool(_DESTRUCTIVE_VERBS_RE.search(lowered))


def resolve_tool_approval(
    tool_name: str,
    *,
    permissions: Mapping[str, Any] | None = None,
    always_allow: Iterable[str] = (),
    frontmatter_tools: Mapping[str, Any] | None = None,
    approval_policy: str | None = None,
    host_modelled: bool = True,
) -> HumanInTheLoop | None:
    """Resolve per-tool ``HumanInTheLoop`` from documented precedence, or ``None`` if unknown.

    Precedence:
    1. ``deny`` (always blocks / requires approval, never auto)
    2. ``ask`` (``HumanInTheLoop.REQUIRED``)
    3. ``allow`` / ``alwaysAllow`` (``HumanInTheLoop.NONE``)
    4. Host ``approval_policy`` / ``permissionMode`` when modelled
    5. ``None`` (unknown) for unmodelled hosts or absent rules
    """
    if not host_modelled:
        return None

    perms = permissions if isinstance(permissions, Mapping) else {}
    fm = frontmatter_tools if isinstance(frontmatter_tools, Mapping) else {}

    deny_rules = _normalize_patterns(perms.get("deny")) + _normalize_patterns(fm.get("deny"))
    if any(_tool_pattern_matches(pat, tool_name) for pat in deny_rules):
        return HumanInTheLoop.REQUIRED

    ask_rules = _normalize_patterns(perms.get("ask")) + _normalize_patterns(fm.get("ask"))
    if any(_tool_pattern_matches(pat, tool_name) for pat in ask_rules):
        return HumanInTheLoop.REQUIRED

    allow_rules = (
        _normalize_patterns(perms.get("allow"))
        + _normalize_patterns(fm.get("allow"))
        + _normalize_patterns(always_allow)
    )
    if any(_tool_pattern_matches(pat, tool_name) for pat in allow_rules):
        return HumanInTheLoop.NONE

    if approval_policy is not None:
        norm = approval_policy.strip().lower()
        if norm in _AUTO_POLICIES:
            return HumanInTheLoop.NONE
        if norm in _CONDITIONAL_POLICIES:
            return HumanInTheLoop.CONDITIONAL
        if norm in _REQUIRED_POLICIES:
            return HumanInTheLoop.REQUIRED

    return None


def _candidate_tool_names(
    permissions: Mapping[str, Any],
    always_allow: Iterable[str],
    frontmatter_tools: Mapping[str, Any] | None,
) -> list[str]:
    fm = frontmatter_tools if isinstance(frontmatter_tools, Mapping) else {}
    raw = (
        _normalize_patterns(permissions.get("allow"))
        + _normalize_patterns(permissions.get("ask"))
        + _normalize_patterns(permissions.get("deny"))
        + _normalize_patterns(fm.get("allow"))
        + _normalize_patterns(fm.get("ask"))
        + _normalize_patterns(fm.get("deny"))
        + _normalize_patterns(always_allow)
    )
    seen: set[str] = set()
    names: list[str] = []
    for pat in raw:
        base = pat.split("(", 1)[0].strip()
        if base and base != "*" and not base.endswith("*") and base not in seen:
            seen.add(base)
            names.append(base)
    return names


def oversight_gap_assessments(
    permissions: Mapping[str, Any] | None,
    *,
    always_allow: Iterable[str] = (),
    frontmatter_tools: Mapping[str, Any] | None = None,
    approval_policy: str | None = None,
    host_modelled: bool = True,
    source_name: str = "settings",
) -> tuple[dict[str, str], list[RiskAssessment]]:
    """Compute per-tool ``human_in_the_loop`` map and ``oversight_gap`` findings."""
    perms = permissions if isinstance(permissions, Mapping) else {}
    tool_states: dict[str, str] = {}
    assessments: list[RiskAssessment] = []
    safe_source = neutralize(source_name)
    for tool_name in _candidate_tool_names(perms, always_allow, frontmatter_tools):
        resolved = resolve_tool_approval(
            tool_name,
            permissions=perms,
            always_allow=always_allow,
            frontmatter_tools=frontmatter_tools,
            approval_policy=approval_policy,
            host_modelled=host_modelled,
        )
        tool_states[tool_name] = resolved.value if resolved is not None else "unknown"
        if resolved == HumanInTheLoop.NONE and is_destructive_tool(tool_name):
            safe_tool = neutralize(tool_name)
            assessments.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="oversight_gap",
                    detail=(
                        f"Destructive or shell tool '{safe_tool}' resolves to auto-approval "
                        f"without human-in-the-loop in '{safe_source}'."
                    ),
                    recommendation=(
                        f"Move '{safe_tool}' from allow/alwaysAllow to ask or deny rules."
                    ),
                )
            )
    return tool_states, assessments


def extract_deny_rules(merged_settings: Mapping[str, Any]) -> list[str]:
    """Return sorted ``permissions.deny`` patterns from merged host settings."""
    perms = merged_settings.get("permissions")
    if not isinstance(perms, Mapping):
        return []
    return sorted(set(_normalize_patterns(perms.get("deny"))))


def extract_sandbox_allowed_domains(merged_settings: Mapping[str, Any]) -> list[str]:
    """Return sorted ``sandbox.network.allowedDomains`` entries from merged settings."""
    sandbox = merged_settings.get("sandbox")
    if not isinstance(sandbox, Mapping):
        return []
    network = sandbox.get("network")
    if not isinstance(network, Mapping):
        return []
    return sorted(set(_normalize_patterns(network.get("allowedDomains"))))


def extract_activation_scope(frontmatter: Mapping[str, Any]) -> dict[str, Any] | None:
    """Extract normalized ``activation`` scope (``always_apply`` and ``globs``)."""
    globs: set[str] = set()
    for key in ("globs", "applyTo", "paths"):
        globs.update(_normalize_patterns(frontmatter.get(key)))
    always_apply = frontmatter.get("alwaysApply") is True
    if not globs and not always_apply:
        return None
    return {"always_apply": always_apply, "globs": sorted(globs)}


def extract_subagent_inline_mcp_servers(
    frontmatter: Mapping[str, Any], source_name: str
) -> list[RiskAssessment]:
    """Flag inline ``mcpServers`` declarations inside subagent front matter."""
    raw = frontmatter.get("mcpServers")
    if not raw:
        return []
    server_names: list[str] = []
    if isinstance(raw, Mapping):
        server_names = [neutralize(str(k)) for k in sorted(raw.keys())]
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, str) and item.strip():
                server_names.append(neutralize(item.strip()))
            elif isinstance(item, Mapping) and item.get("name"):
                server_names.append(neutralize(str(item["name"])))
    if not server_names and not isinstance(raw, (Mapping, list)):
        return []
    safe_source = neutralize(source_name)
    listed = ", ".join(server_names) if server_names else "inline declaration"
    return [
        RiskAssessment(
            severity=RiskSeverity.MEDIUM,
            category="subagent_inline_mcp_server",
            detail=(
                f"Subagent '{safe_source}' declares inline mcpServers ({listed}), "
                "granting MCP tool access outside the top-level .mcp.json inventory."
            ),
            recommendation="Move MCP server definitions into a reviewed .mcp.json and pin versions.",
        )
    ]


_FM_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---(?:\r?\n|\Z)", re.DOTALL)


def scan_subagent_and_rule_frontmatter(
    files: Any,
    base: str,
    risks: list[RiskAssessment],
    properties: dict[str, Any],
) -> None:
    """Inspect .claude/agents/*.md and .cursor/rules/*.mdc front matter via ConfinedCollection."""
    import yaml

    prefix = f"{base}/" if base else ""
    activation_scopes: dict[str, dict[str, Any]] = {}
    for rel_path in sorted(files.iter_files()):
        rel = rel_path.as_posix()
        if prefix and not rel.startswith(prefix):
            continue
        sub_rel = rel[len(prefix) :]
        is_agent = sub_rel.startswith(".claude/agents/") and sub_rel.endswith(".md")
        is_rule = sub_rel.startswith((".cursor/rules/", ".claude/rules/")) and sub_rel.endswith(
            (".mdc", ".md")
        )
        if not (is_agent or is_rule):
            continue
        text = files.read_text(rel, missing_ok=True)
        if not text:
            continue
        match = _FM_RE.match(text)
        if match is None:
            continue
        try:
            meta = yaml.safe_load(match.group(1))
        except yaml.YAMLError:
            continue
        if not isinstance(meta, Mapping):
            continue
        if is_agent:
            risks.extend(extract_subagent_inline_mcp_servers(meta, rel))
        scope = extract_activation_scope(meta)
        if scope is not None:
            activation_scopes[neutralize(rel)] = scope
    if activation_scopes:
        properties["activation"] = activation_scopes
