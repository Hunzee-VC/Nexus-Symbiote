"""Instruction, skill, data-source and memory checks (``SYM-INSTR-*``, ``SYM-SKILL-*``, ``SYM-DATA-*``, ``SYM-MEM-*``)."""

from __future__ import annotations

from collections.abc import Iterator

from symbiote.authz.classify import capabilities
from symbiote.authz.trifecta import assess_agent
from symbiote.model.entities import Finding
from symbiote.model.enums import (
    CapabilityClass,
    DataSourceKind,
    FindingState,
    InstructionKind,
    Severity,
    TriState,
    TrustTier,
    ValueState,
)
from symbiote.policy.spec import CheckSpec, PolicyContext, asi, atlas, check

_PROMPT_KINDS = (InstructionKind.SYSTEM_PROMPT, InstructionKind.DEVELOPER_PROMPT)


@check(
    "SYM-INSTR-001",
    "Instruction editable by an untrusted principal",
    Severity.HIGH,
    mappings=(asi(6),),
    inputs=("instructions[].editors",),
    remediation="Restrict who can change system prompts (CODEOWNERS, protected branches) and never let an agent that reads untrusted input write its own instructions.",
)
def untrusted_editor(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """An editor is an agent fed by untrusted inputs, or a system prompt's editors are unknown."""
    for instr in ctx.bom.instructions:
        editors = instr.editors
        if editors is None or editors.state is not ValueState.PRESENT or editors.value is None:
            if instr.instruction_kind in _PROMPT_KINDS:
                yield spec.finding(
                    ctx,
                    subjects=[instr.id],
                    state=FindingState.INDETERMINATE,
                    message=f"Who can edit system prompt {instr.path or instr.id!r} is unknown.",
                )
            continue
        for editor in editors.value:
            if (
                editor in {a.id for a in ctx.bom.agents}
                and assess_agent(ctx.index, editor).untrusted_input.value is TriState.TRUE
            ):
                yield spec.finding(
                    ctx,
                    subjects=[instr.id],
                    inputs=[editor],
                    message=f"Agent {editor} reads untrusted input and can edit {instr.path or instr.id!r}.",
                )


@check(
    "SYM-INSTR-002",
    "Instruction loads remote content",
    Severity.HIGH,
    mappings=(asi(1), atlas("AML.T0051")),
    inputs=("instructions[].loads_remote",),
    remediation="Vendor the referenced content into the repository and pin it by digest; a remote include changes the agent's instructions without a commit.",
)
def loads_remote(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """loads_remote is non-empty."""
    for instr in ctx.bom.instructions:
        claim = instr.loads_remote
        if claim is not None and claim.state is ValueState.PRESENT and claim.value:
            yield spec.finding(
                ctx,
                subjects=[instr.id],
                message=f"{instr.path or instr.id!r} pulls instructions from {', '.join(claim.value[:3])}.",
            )


@check(
    "SYM-INSTR-003",
    "Instruction changed since approval",
    Severity.CRITICAL,
    mappings=(asi(6),),
    inputs=("instructions[].digest", "baseline.instructions[].digest"),
    remediation="Review the diff of the instruction file and re-approve the snapshot; unexpected prompt changes are a persistence technique.",
)
def changed_since_approval(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Instruction digest not in the approved snapshot."""
    if ctx.baseline is None:
        return
    approved = {i.digest for i in ctx.baseline.instructions}
    for instr in ctx.bom.instructions:
        if instr.digest not in approved:
            yield spec.finding(
                ctx,
                subjects=[instr.id],
                message=f"{instr.path or instr.id!r} differs from every approved instruction.",
            )


@check(
    "SYM-INSTR-004",
    "Hidden Unicode in an instruction or rules file",
    Severity.HIGH,
    mappings=(asi(1), asi(6), atlas("AML.T0051")),
    inputs=("instructions[].tags", "skills[].tags"),
    remediation="Strip invisible and bidi characters and review the file in a hex-aware diff; this is the 'Rules File Backdoor' technique.",
    extension=True,
)
def hidden_unicode_instructions(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Invisible, bidi or tag characters in agent instruction, rules or skill files."""
    for entity in (*ctx.bom.instructions, *ctx.bom.skills):
        if "hidden-unicode" in entity.tags:
            yield spec.finding(
                ctx,
                subjects=[entity.id],
                message=f"{getattr(entity, 'path', None) or entity.id!r} contains invisible or direction-altering characters.",
            )


@check(
    "SYM-INSTR-005",
    "Repository-supplied executable hook",
    Severity.MEDIUM,
    mappings=(asi(5), asi(4)),
    inputs=("instructions[kind=hook]",),
    remediation="Review hooks like code (CODEOWNERS), keep them out of shared project settings where possible, and require trust confirmation before a checkout's hooks run.",
    extension=True,
)
def repo_hooks(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Hooks in project settings execute shell commands on agent events for anyone who opens the repository."""
    hooks = [
        i for i in ctx.bom.instructions if i.instruction_kind is InstructionKind.HOOK and i.precedence <= 2
    ]
    if hooks:
        yield spec.finding(
            ctx,
            subjects=[h.id for h in hooks],
            message=f"{len(hooks)} hook command(s) ship with the repository and run automatically.",
        )


@check(
    "SYM-SKILL-001",
    "Skill metadata invalid",
    Severity.LOW,
    mappings=(asi(4),),
    inputs=("skills[].frontmatter", "skills[].name_matches_directory", "skills[].tags"),
    remediation="Fix SKILL.md frontmatter (name equals the directory, lowercase, ≤64 chars; description present and ≤1024 chars) so the skill cannot masquerade as another.",
    extension=True,
)
def skill_metadata(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """Skill name differs from its directory or violates the Agent Skills naming rules."""
    for skill in ctx.bom.skills:
        problems = [
            t for t in skill.tags if t in {"invalid-name", "description-too-long", "missing-description"}
        ]
        if not skill.name_matches_directory:
            problems.append("name-differs-from-directory")
        if problems:
            yield spec.finding(
                ctx, subjects=[skill.id], message=f"Skill {skill.name or skill.id!r}: {', '.join(problems)}."
            )


@check(
    "SYM-SKILL-002",
    "Skill ships executable scripts with shell access",
    Severity.MEDIUM,
    mappings=(asi(5), asi(4)),
    inputs=("skills[].scripts", "skills[].frontmatter.allowed_tools"),
    remediation="Review the scripts like any dependency, pin the skill by its directory digest, and restrict allowed-tools to what the skill needs.",
    extension=True,
)
def skill_scripts(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A skill bundles scripts and is allowed to execute shell commands."""
    for skill in ctx.bom.skills:
        if skill.has_scripts and "capability:execute" in skill.tags:
            yield spec.finding(
                ctx,
                subjects=[skill.id],
                message=f"Skill {skill.name or skill.id!r} bundles {len(skill.scripts)} script(s) and may run shell commands.",
            )


@check(
    "SYM-DATA-001",
    "Untrusted input feeding a privileged agent",
    Severity.HIGH,
    mappings=(asi(1), asi(6), atlas("AML.T0070")),
    inputs=("edges[readsContextFrom]", "data_sources[].trust_tier", "tools[].capabilities"),
    remediation="Quarantine untrusted sources behind a separate, unprivileged agent and pass only structured, validated results to the privileged one.",
)
def untrusted_feeds_privileged(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """readsContextFrom a trust tier ≥ 3 source ∧ any write/egress capability."""
    for agent in ctx.index.agents():
        untrusted = [
            s for s, _ in ctx.index.data_sources_of(agent.id) if s.trust_tier is TrustTier.UNTRUSTED_PUBLIC
        ]
        if not untrusted:
            continue
        caps = {c for t in ctx.index.tools_of(agent.id) for c in capabilities(t)}
        risky = caps & {
            CapabilityClass.WRITE,
            CapabilityClass.NETWORK_EGRESS,
            CapabilityClass.COMMUNICATE,
            CapabilityClass.PAYMENT,
            CapabilityClass.EXECUTE,
        }
        if risky:
            yield spec.finding(
                ctx,
                subjects=[agent.id],
                inputs=[s.id for s in untrusted],
                message=f"Agent reads untrusted sources and holds {sorted(c.value for c in risky)}.",
            )


@check(
    "SYM-MEM-001",
    "Memory writers unknown",
    Severity.HIGH,
    mappings=(asi(6), atlas("AML.T0080")),
    inputs=("data_sources[kind=memory-store].writers",),
    remediation="Record which identities and agents can write each memory store and enforce it; unknown writers make memory poisoning undetectable.",
)
def memory_writers_unknown(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A memory store whose writers are unknown."""
    for source in ctx.bom.data_sources:
        if source.data_kind is DataSourceKind.MEMORY_STORE and (
            source.writers is None or source.writers.state is not ValueState.PRESENT
        ):
            yield spec.finding(
                ctx,
                subjects=[source.id],
                message=f"Writers of memory store {source.name or source.id!r} are unknown.",
            )


@check(
    "SYM-MEM-002",
    "Untrusted memory writer",
    Severity.CRITICAL,
    mappings=(asi(6), atlas("AML.T0080")),
    inputs=("data_sources[kind=memory-store].writers", "edges[writesMemoryTo]"),
    remediation="Route memory writes from agents that read untrusted input through a quarantine and review step, or make the store read-only for them.",
)
def untrusted_memory_writer(spec: CheckSpec, ctx: PolicyContext) -> Iterator[Finding]:
    """A writer fed by untrusted inputs writes persistent memory without quarantine."""
    for agent in ctx.index.agents():
        stores = [s for s in ctx.index.memory_writes_of(agent.id) if s.quarantine is None]
        if stores and assess_agent(ctx.index, agent.id).untrusted_input.value is TriState.TRUE:
            yield spec.finding(
                ctx,
                subjects=[agent.id, *(s.id for s in stores)],
                message=f"Agent reads untrusted input and writes {len(stores)} memory store(s) without quarantine.",
            )
