"""Tool-definition checks ``SYM-TOOL-*`` (``spec/checks.md`` §2)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from symbiote.authz.flags import destructive_open_world_ungated
from symbiote.digest.textflags import cross_tool_directives, external_refs, hidden_code_points
from symbiote.model.common import looks_like_secret
from symbiote.model.entities import Finding, ToolDefinition
from symbiote.model.enums import FindingState, Severity, TextFlag, ToolSource, TriState, ValueState
from symbiote.policy.spec import CheckSpec, PolicyContext, asi, atlas, check

_DECLARED_ONLY = "declared-without-definition"


def _declared_only(tool: ToolDefinition) -> bool:
    return tool.source is ToolSource.DECLARED_CONFIG and (tool.digest.reason or "").startswith(_DECLARED_ONLY)


def _model_visible_text(tool: ToolDefinition) -> list[str]:
    texts = [tool.tool_name, tool.title or "", tool.description or ""]

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in {"description", "title"} and isinstance(value, str):
                    texts.append(value)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(tool.input_schema)
    walk(tool.output_schema)
    return texts


@check(
    "SYM-TOOL-001",
    "Unpinned tool",
    Severity.HIGH,
    mappings=(asi(4), atlas("AML.T0109"), atlas("AML.T0110")),
    inputs=("tools[].digest", "tools[].source", "tool_servers[].toolset_digest"),
    remediation=(
        "Observe the server live (`symbiote scan --live`), review the served tool definitions and approve the "
        "toolset digest; enforce it at the gateway so any change to a name, description, schema or annotation "
        "is blocked until re-approved."
    ),
)
def unpinned_tool(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A tool has no usable digest, or exists only as a declared name with no served definition."""
    for tool in ctx.bom.tools:
        if _declared_only(tool) or not tool.digest.ok:
            why = (
                "only its name is configured"
                if _declared_only(tool)
                else f"digest {tool.digest.status.value}: {tool.digest.reason}"
            )
            yield spec.finding(
                ctx,
                subjects=[tool.id],
                inputs=[tool.server_ref],
                message=f"Tool {tool.tool_name!r} is not pinned ({why}).",
            )
    for server in ctx.bom.tool_servers:
        if ctx.index.tools_of_server(server.id):
            continue
        toolset = server.toolset_digest
        if toolset is None or toolset.state is not ValueState.PRESENT:
            yield spec.finding(
                ctx,
                subjects=[server.id],
                message=f"Server {server.name or server.id!r}: no tool definition is pinned (tools were never observed or approved).",
            )


@check(
    "SYM-TOOL-002",
    "Served tools differ from the approved set",
    Severity.CRITICAL,
    mappings=(asi(4), atlas("AML.T0109")),
    inputs=("tools[].digest", "baseline.tools[].digest"),
    remediation=(
        "Treat this as a rug-pull until proven otherwise: block the changed tools at the gateway, diff the served "
        "definition against the approved one (`symbiote diff`), and re-approve only after review."
    ),
)
def served_not_approved(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A served tool digest is not in the approved toolset, or an approved tool is missing."""
    if ctx.baseline is None:
        return
    approved = {t.digest.value: t for t in ctx.baseline.tools if t.digest.value}
    served = [t for t in ctx.bom.tools if t.source is ToolSource.SERVED_LIVE]
    served_digests = {t.digest.value for t in served if t.digest.value}
    for tool in served:
        if tool.digest.value not in approved:
            yield spec.finding(
                ctx,
                subjects=[tool.id],
                message=f"Served tool {tool.tool_name!r} ({tool.digest.value or 'undigestable'}) is not in the approved set.",
            )
    for digest, tool in approved.items():
        if served and digest not in served_digests:
            yield spec.finding(
                ctx,
                subjects=[ctx.bom.subject],
                inputs=[tool.id],
                message=f"Approved tool {tool.tool_name!r} is no longer served with its approved definition.",
            )


@check(
    "SYM-TOOL-003",
    "Destructive, open-world tool without a human gate",
    Severity.HIGH,
    mappings=(asi(2), atlas("AML.T0086")),
    inputs=("tools[].annotations", "tools[].side_effects", "tool_servers[].client_trust_flags"),
    remediation=(
        "Require human approval for this tool in the client (remove it from auto-approve lists) or enforce an "
        "approval gate at the gateway; scope its credentials to the minimum resources."
    ),
)
def destructive_ungated(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """(destructive_hint ≠ false or observed destructive) ∧ open_world_hint ≠ false ∧ no required approval."""
    for tool in ctx.bom.tools:
        value, inputs = destructive_open_world_ungated(ctx.index, tool)
        if value is TriState.TRUE:
            yield spec.finding(
                ctx,
                subjects=[tool.id],
                inputs=inputs,
                message=f"Tool {tool.tool_name!r} is destructive and open-world and runs without approval.",
            )
        elif value is TriState.UNKNOWN and not _declared_only(tool):
            yield spec.finding(
                ctx,
                subjects=[tool.id],
                inputs=inputs,
                state=FindingState.INDETERMINATE,
                message=f"Tool {tool.tool_name!r} may be destructive and open-world (annotations or approval unknown).",
            )


@check(
    "SYM-TOOL-004",
    "Non-canonicalizable tool definition",
    Severity.CRITICAL,
    mappings=(asi(4),),
    inputs=("tools[].digest",),
    remediation="Fix the server so its tool definition is valid JSON without duplicate keys, NaN or integers beyond ±2^53; until then the tool cannot be pinned and must be blocked.",
)
def undigestable_definition(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A served definition could not be canonicalised (fail-closed digest)."""
    for tool in ctx.bom.tools:
        if not tool.digest.ok and not _declared_only(tool):
            yield spec.finding(
                ctx,
                subjects=[tool.id],
                message=f"Tool {tool.tool_name!r} cannot be canonicalised: {tool.digest.reason}.",
            )


@check(
    "SYM-TOOL-005",
    "External $ref in a tool schema",
    Severity.HIGH,
    mappings=(asi(4), atlas("AML.T0110")),
    inputs=("tools[].input_schema", "tools[].output_schema"),
    remediation="Inline the referenced schema; a remote $ref lets the tool contract change behind a URL without any digest change.",
)
def external_ref(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Any ``$ref`` that is not fragment-local."""
    for tool in ctx.bom.tools:
        refs = external_refs(tool.input_schema) + external_refs(tool.output_schema or {})
        if refs:
            yield spec.finding(
                ctx,
                subjects=[tool.id],
                message=f"Tool {tool.tool_name!r} schema references external definitions: {', '.join(sorted(set(refs))[:5])}.",
            )


@check(
    "SYM-TOOL-006",
    "Hidden Unicode in model-visible tool text",
    Severity.HIGH,
    mappings=(asi(1), atlas("AML.T0051")),
    inputs=("tools[].description", "tools[].input_schema", "tools[].text_flags"),
    remediation="Reject the definition: invisible, bidi or tag characters in a tool description are a tool-poisoning technique.",
)
def hidden_unicode(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Cf/Co/Cn, bidi-control or tag code points in name, title, description or schema descriptions."""
    for tool in ctx.bom.tools:
        found = TextFlag.HIDDEN_UNICODE in tool.text_flags or any(
            hidden_code_points(t) for t in _model_visible_text(tool)
        )
        if found:
            yield spec.finding(
                ctx,
                subjects=[tool.id],
                message=f"Tool {tool.tool_name!r} contains invisible or direction-altering characters in model-visible text.",
            )


@check(
    "SYM-TOOL-007",
    "Tool annotations absent",
    Severity.MEDIUM,
    mappings=(asi(2),),
    inputs=("tools[].annotations",),
    remediation="Ask the server author to declare readOnlyHint/destructiveHint/openWorldHint; meanwhile policy assumes the MCP defaults (destructive, open-world).",
)
def annotations_absent(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """No annotations, or every hint absent (MCP defaults then apply: destructive and open-world)."""
    for tool in ctx.bom.tools:
        if _declared_only(tool):
            continue
        ann = tool.annotations
        if (
            ann is None
            or ann.state is not ValueState.PRESENT
            or ann.value is None
            or not ann.value.any_present
        ):
            yield spec.finding(
                ctx,
                subjects=[tool.id],
                message=f"Tool {tool.tool_name!r} declares no behaviour hints; it is treated as destructive and open-world.",
            )


@check(
    "SYM-TOOL-008",
    "Tool-name shadowing across servers",
    Severity.MEDIUM,
    mappings=(asi(4), atlas("AML.T0110")),
    inputs=("tools[].tool_name", "tools[].digest", "tools[].server_ref"),
    remediation="Rename or remove one of the tools, or namespace tool names per server in the client, so a malicious server cannot shadow a trusted tool.",
)
def shadowing(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """The same tool name on two or more servers with different digests."""
    by_name: dict[str, list[ToolDefinition]] = defaultdict(list)
    for tool in ctx.bom.tools:
        by_name[tool.tool_name].append(tool)
    for name, tools in sorted(by_name.items()):
        servers = {t.server_ref for t in tools}
        digests = {t.digest.value for t in tools}
        if len(servers) > 1 and len(digests) > 1:
            yield spec.finding(
                ctx,
                subjects=[t.id for t in tools],
                message=f"Tool name {name!r} is provided by {len(servers)} servers with different definitions.",
            )


@check(
    "SYM-TOOL-009",
    "Cross-tool directive in a description (heuristic)",
    Severity.INFO,
    mappings=(asi(1), atlas("AML.T0051")),
    inputs=("tools[].description",),
    remediation="Read the description: instructions such as 'before using X, call Y' or 'do not tell the user' are classic tool-poisoning payloads.",
)
def cross_tool_directive(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Description matches patterns such as 'before using <tool>', 'ignore previous', 'do not tell the user'."""
    for tool in ctx.bom.tools:
        hits = TextFlag.CROSS_TOOL_DIRECTIVE in tool.text_flags or any(
            cross_tool_directives(t) for t in _model_visible_text(tool)
        )
        if hits:
            yield spec.finding(
                ctx,
                subjects=[tool.id],
                message=f"Tool {tool.tool_name!r} description contains cross-tool or concealment directives.",
            )


@check(
    "SYM-TOOL-010",
    "Oversized or secret-shaped model-visible text",
    Severity.MEDIUM,
    mappings=(asi(4),),
    inputs=("tools[].description", "tools[].text_flags"),
    remediation="Remove credentials from tool text and keep descriptions short; long descriptions hide injected instructions from reviewers.",
)
def oversized_or_secret(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Credential-shaped tokens in model-visible text, or a description over 4 KiB."""
    for tool in ctx.bom.tools:
        texts = _model_visible_text(tool)
        secret = TextFlag.SECRET_SHAPED_TOKEN in tool.text_flags or any(looks_like_secret(t) for t in texts)
        oversized = len((tool.description or "").encode("utf-8")) > 4096
        if secret or oversized:
            why = " and ".join(
                x
                for x, ok in (
                    ("contains a credential-shaped token", secret),
                    ("has a description over 4 KiB", oversized),
                )
                if ok
            )
            yield spec.finding(ctx, subjects=[tool.id], message=f"Tool {tool.tool_name!r} {why}.")
