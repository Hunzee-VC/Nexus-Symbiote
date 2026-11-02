"""instructions collector: instruction files, prompt templates and hooks across clients and scopes."""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from symbiote.collect import instructions as mod
from symbiote.collect._common import ReadOutcome
from symbiote.collect.base import CollectContext, CollectionResult, load_collectors, run_collectors
from symbiote.collect.instructions import (
    MAX_APPLIES_TO_TAGS,
    MAX_FRONTMATTER_CHARS,
    MAX_FRONTMATTER_STRING,
    PROJECT_RULES,
    FrontmatterSanitizer,
    HookDecl,
    IdRegistry,
    InstructionsCollector,
    RunState,
    applies_to_tags,
    capability_tags,
    classify,
    has_hidden_unicode,
    is_jinja_template,
    list_tree,
    media_type_for,
    os_error_class,
    parse_frontmatter,
    parse_hooks,
    prompt_rule,
    read_file_facts,
    record_walk,
    remote_display,
    resolve_within,
    scan_imports,
    split_tools,
    streamed_line_endings,
    symlink_tag,
)
from symbiote.digest import canonical_bytes, line_endings, prompt_digest, triage_digest
from symbiote.model import AgentBOM, Producer, Snapshot
from symbiote.model.entities import Agent, Instruction, PromptTemplate
from symbiote.model.enums import (
    AgentRole,
    CollectorStatus,
    CoverageStatus,
    DigestStatus,
    EdgeType,
    InstructionKind,
    LineEndings,
    SnapshotKind,
    Surface,
    TemplateEngine,
    TemplateRiskClass,
    UnknownReason,
    ValueState,
)

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
D = "sha256:" + "ab" * 32
# Obviously fake credential shapes: they must be flagged and must never appear in any emitted entity.
GH_PAT = "ghp_" + "Z" * 36
AWS_KEY = "AKIA" + "Q" * 16
OPENAI_KEY = "sk-" + "x" * 24
ZWSP, RLO, BOM = "\u200b", "\u202e", "\ufeff"

AGENT_J2 = "Hello {{ user }}, you are {% if admin %}admin{% endif %}.\n"
AGENT_SCHEMA = (
    '{"type": "object", "properties": {"user": {"type": "string", "minLength": 1}}, "required": ["user"]}'
)
CLAUDE_MD = (
    "# Project\n"
    "See @docs/guide.md and @README for context.\n"
    "Remote rules: @https://rules.example.com/team.md\n"
    "Mail ops@example.com for access.\n"
    "```python\n@decorator\n```\n"
    "Inline `@not-an-import` stays code.\n"
)
SETTINGS: dict[str, Any] = {
    "permissions": {"allow": ["Bash(ls:*)"]},
    "hooks": {
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "./scripts/check.sh", "timeout": 30}],
            },
            {
                "matcher": "Write|Edit",
                "hooks": [{"type": "command", "command": f"GITHUB_TOKEN={GH_PAT} ./notify.sh"}],
            },
        ],
        "SessionStart": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": "curl -s https://hooks.example.com/services/T000/B000/XYZ?token=abc",
                    }
                ]
            }
        ],
        "Stop": [{"hooks": [{"type": "prompt", "prompt": "Check the task is complete."}]}],
        "PostToolUse": [{"matcher": "*", "hooks": [{"type": "mystery", "command": "x"}]}],
    },
}
LOCAL_SETTINGS: dict[str, Any] = {
    "disableAllHooks": True,
    "hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": "echo hi"}]}]},
}

PROJECT_FILES: dict[str, str] = {
    "CLAUDE.md": CLAUDE_MD,
    "CLAUDE.local.md": f"local notes, key {OPENAI_KEY}\n",
    ".claude/CLAUDE.md": "project memory\n",
    "AGENTS.md": "Agents guide\r\nSecond line\r\n",
    "services/api/AGENTS.md": f"Nested{ZWSP} rules{RLO}\n",
    "GEMINI.md": f"{BOM}Gemini context\n",
    "docs/GEMINI.md": "nested gemini\n",
    ".cursorrules": "legacy cursor rules\n",
    ".cursor/rules/typescript.mdc": (
        "---\ndescription: TypeScript rules\nglobs: *.ts,*.tsx\nalwaysApply: false\n---\nUse strict mode.\n"
    ),
    ".cursor/rules/always.mdc": "---\nalwaysApply: true\n---\nBe concise.\n",
    "web/.cursor/rules/react.mdc": '---\nglobs: ["*.jsx"]\n---\nPrefer hooks.\n',
    ".github/copilot-instructions.md": "Copilot rules\n",
    ".github/instructions/python.instructions.md": '---\napplyTo: "**/*.py"\n---\nType hints.\n',
    ".github/prompts/review.prompt.md": "---\nmode: agent\ntools: ['codebase']\ndescription: Review code\n---\nReview.\n",
    ".github/chatmodes/plan.chatmode.md": "---\ndescription: Plan\n---\nPlan.\n",
    ".windsurfrules": "windsurf legacy\n",
    ".windsurf/rules/style.md": "---\ntrigger: always_on\n---\nStyle.\n",
    ".clinerules/01-style.md": "Cline style\n",
    ".roo/rules/general.md": "Roo general\n",
    ".roo/rules-code/code.txt": "Roo code mode\n",
    ".kiro/steering/components.md": (
        '---\ninclusion: fileMatch\nfileMatchPattern: "components/**/*.tsx"\n---\nComponents.\n'
    ),
    ".claude/rules/security.md": '---\npaths:\n  - "src/**"\n---\nNo secrets.\n',
    ".claude/agents/reviewer.md": (
        f"---\nname: reviewer\ndescription: Reviews code\ntools: Read, Grep, Bash\napi_key: {AWS_KEY}\n"
        "created: 2025-01-02\n---\nYou review.\n"
    ),
    ".claude/agents/CLAUDE.md": "---\nname: odd\n---\nA sub-agent file named CLAUDE.md.\n",
    ".claude/commands/git/commit.md": (
        "---\nallowed-tools: Bash(git add:*), Bash(git commit:*), Write\ndescription: Commit\n---\n"
        "Commit @src/changes.md now.\n"
    ),
    ".claude/settings.json": json.dumps(SETTINGS),
    ".claude/settings.local.json": json.dumps(LOCAL_SETTINGS),
    "prompts/system.md": "You are a helpful assistant.\n",
    "prompts/agent.j2": AGENT_J2,
    "prompts/agent.schema.json": AGENT_SCHEMA,
    "prompts/support/escalate.txt": "{% if urgent %}Escalate{% endif %}\n",
    "prompts/config.yaml": 'template: "{{ not_a_template }}"\n',
    "prompts/notes.json": "{}",
    "node_modules/pkg/AGENTS.md": "vendored, pruned\n",
    "README.md": "not an instruction\n",
}
HOME_FILES: dict[str, str] = {
    ".claude/CLAUDE.md": "user memory\n",
    ".claude/agents/helper.md": "---\nname: helper\n---\nHelp.\n",
    ".claude/commands/standup.md": "Standup.\n",
    ".claude/projects/session.jsonl": "{}\n",
    ".codex/AGENTS.md": "codex global\n",
    ".gemini/GEMINI.md": "gemini global\n",
    ".claude/settings.json": json.dumps(
        {"hooks": {"Notification": [{"hooks": [{"type": "command", "command": "notify-send done"}]}]}}
    ),
}

EXPECTED_PROJECT: dict[str, tuple[InstructionKind, int]] = {
    "CLAUDE.md": (InstructionKind.CLAUDE_MD, 2),
    "CLAUDE.local.md": (InstructionKind.CLAUDE_MD, 2),
    ".claude/CLAUDE.md": (InstructionKind.CLAUDE_MD, 2),
    "AGENTS.md": (InstructionKind.AGENTS_MD, 2),
    "services/api/AGENTS.md": (InstructionKind.AGENTS_MD, 1),
    "GEMINI.md": (InstructionKind.GEMINI_MD, 2),
    "docs/GEMINI.md": (InstructionKind.GEMINI_MD, 1),
    ".cursorrules": (InstructionKind.CURSOR_RULES, 2),
    ".cursor/rules/typescript.mdc": (InstructionKind.CURSOR_RULES, 2),
    ".cursor/rules/always.mdc": (InstructionKind.CURSOR_RULES, 2),
    "web/.cursor/rules/react.mdc": (InstructionKind.CURSOR_RULES, 1),
    ".github/copilot-instructions.md": (InstructionKind.COPILOT_INSTRUCTIONS, 2),
    ".github/instructions/python.instructions.md": (InstructionKind.COPILOT_INSTRUCTIONS, 2),
    ".github/prompts/review.prompt.md": (InstructionKind.OTHER, 2),
    ".github/chatmodes/plan.chatmode.md": (InstructionKind.OTHER, 2),
    ".windsurfrules": (InstructionKind.WINDSURF_RULES, 2),
    ".windsurf/rules/style.md": (InstructionKind.WINDSURF_RULES, 2),
    ".clinerules/01-style.md": (InstructionKind.RULES_FILE, 2),
    ".roo/rules/general.md": (InstructionKind.RULES_FILE, 2),
    ".roo/rules-code/code.txt": (InstructionKind.RULES_FILE, 2),
    ".kiro/steering/components.md": (InstructionKind.RULES_FILE, 2),
    ".claude/rules/security.md": (InstructionKind.RULES_FILE, 2),
    ".claude/agents/reviewer.md": (InstructionKind.OTHER, 2),
    ".claude/agents/CLAUDE.md": (InstructionKind.OTHER, 2),
    ".claude/commands/git/commit.md": (InstructionKind.OTHER, 2),
    "prompts/system.md": (InstructionKind.SYSTEM_PROMPT, 2),
    "prompts/config.yaml": (InstructionKind.SYSTEM_PROMPT, 2),
}


def _write(path: Path, content: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    return path


def _populate(base: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        _write(base / rel, content)


@pytest.fixture
def scene(tmp_path: Path) -> tuple[Path, Path]:
    repo, home = tmp_path / "repo", tmp_path / "home"
    _populate(repo, PROJECT_FILES)
    _populate(home, HOME_FILES)
    return repo, home


def _run(
    root: Path, home: Path | None = None, collector: InstructionsCollector | None = None, **kw: Any
) -> CollectionResult:
    ctx = CollectContext(root=root, home=home, platform="linux", agent_id="agent:triage", now=NOW, **kw)
    result = run_collectors(ctx, [collector or InstructionsCollector()])[0]
    assert result.status is CollectorStatus.OK, result.reason
    return result


def _files(result: CollectionResult) -> dict[str, Instruction]:
    return {
        e.path: e
        for e in result.entities
        if isinstance(e, Instruction)
        and e.path is not None
        and e.instruction_kind is not InstructionKind.HOOK
    }


def _hooks(result: CollectionResult) -> dict[str, Instruction]:
    return {
        e.provenance.locator or "": e
        for e in result.entities
        if isinstance(e, Instruction) and e.instruction_kind is InstructionKind.HOOK
    }


def _prompts(result: CollectionResult) -> dict[str, PromptTemplate]:
    return {e.path or "": e for e in result.entities if isinstance(e, PromptTemplate)}


def _dump(result: CollectionResult) -> str:
    return json.dumps(
        [e.to_json_dict() for e in result.entities]
        + [e.to_json_dict() for e in result.edges]
        + [r.model_dump(mode="json") for r in result.redactions]
        + [result.coverage[Surface.INSTRUCTIONS].model_dump(mode="json")]
        + result.warnings
    )


def _failed(result: CollectionResult) -> dict[str, str | None]:
    return {
        s.locator or s.source: s.error_class
        for s in result.coverage[Surface.INSTRUCTIONS].sources
        if not s.ok
    }


# --------------------------------------------------------------------------------------------- inventory


def test_project_inventory_kinds_precedence_and_ids(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    result = _run(repo)
    files = _files(result)
    assert {p: (i.instruction_kind, i.precedence) for p, i in files.items()} == EXPECTED_PROJECT
    assert files["CLAUDE.md"].id == "instr:claude.md"
    assert files["services/api/AGENTS.md"].id == "instr:services-api-agents.md"
    assert "scope:directory" in files["services/api/AGENTS.md"].tags
    assert "scope:project" in files["AGENTS.md"].tags
    assert files[".cursorrules"].media_type == "text/plain"
    assert files[".cursor/rules/typescript.mdc"].media_type == "text/markdown"
    assert files["prompts/config.yaml"].media_type == "application/yaml"  # YAML prompts are never templates
    assert files["CLAUDE.md"].name == "CLAUDE.md"
    assert files["CLAUDE.md"].provenance.locator == "CLAUDE.md"
    assert files["CLAUDE.md"].provenance.collector == "collector:instructions@0.1.0"
    ids = [e.id for e in result.entities]
    assert len(ids) == len(set(ids))
    assert not any("node_modules" in (e.path or "") for e in files.values())  # pruned by the walk


def test_exact_bytes_digests_and_line_endings(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    files = _files(_run(repo))
    for rel, instruction in files.items():
        data = (repo / rel).read_bytes()
        assert instruction.digest == "sha256:" + hashlib.sha256(data).hexdigest()
        assert instruction.size == len(data)
        assert instruction.normalized_digest == triage_digest(data)
        assert instruction.line_endings is line_endings(data)
    assert files["AGENTS.md"].line_endings is LineEndings.CRLF
    assert files["CLAUDE.md"].line_endings is LineEndings.LF


def test_imports_remote_and_local(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    claude = _files(_run(repo))["CLAUDE.md"]
    assert claude.loads_remote is not None
    assert claude.loads_remote.value == ["https://rules.example.com/team.md"]
    assert claude.loads_remote.locator == "CLAUDE.md:3"
    assert "local-import:docs/guide.md" in claude.tags
    assert "local-import:README" in claude.tags
    imports = [t for t in claude.tags if t.startswith("local-import:")]
    assert len(imports) == 2  # e-mail addresses, fenced code and inline code are not imports
    files = _files(_run(repo))
    assert files[".claude/commands/git/commit.md"].tags.count("local-import:src/changes.md") == 1
    empty = files["AGENTS.md"].loads_remote
    assert empty is not None and empty.state is ValueState.PRESENT and empty.value == []


def test_hidden_unicode_and_secret_like_are_flagged_never_echoed(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    result = _run(repo)
    files = _files(result)
    assert "hidden-unicode" in files["services/api/AGENTS.md"].tags
    assert "hidden-unicode" not in files["GEMINI.md"].tags  # a leading BOM is not a hidden payload
    local = files["CLAUDE.local.md"]
    assert local.contains_secret_like and "secret-like" in local.tags
    assert not files["CLAUDE.md"].contains_secret_like
    dump = _dump(result)
    for secret in (OPENAI_KEY, AWS_KEY, GH_PAT):
        assert secret not in dump
    for body in ("Use strict mode.", "You review.", "Second line", "Gemini context"):
        assert body not in dump  # instruction content is never stored


def test_frontmatter_lenient_cursor_and_applies_to(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    files = _files(_run(repo))
    ts = files[".cursor/rules/typescript.mdc"]
    assert ts.frontmatter == {"description": "TypeScript rules", "globs": "*.ts,*.tsx", "alwaysApply": False}
    assert {"lenient-frontmatter", "applies-to:*.ts", "applies-to:*.tsx"} <= set(ts.tags)
    assert "applies-to:**" in files[".cursor/rules/always.mdc"].tags
    react = files["web/.cursor/rules/react.mdc"]
    assert "applies-to:*.jsx" in react.tags and "lenient-frontmatter" not in react.tags
    assert "applies-to:**/*.py" in files[".github/instructions/python.instructions.md"].tags
    assert "applies-to:**" in files[".windsurf/rules/style.md"].tags
    assert "applies-to:components/**/*.tsx" in files[".kiro/steering/components.md"].tags
    assert "applies-to:src/**" in files[".claude/rules/security.md"].tags
    assert files["CLAUDE.md"].frontmatter is None  # memory files carry no frontmatter
    assert files[".github/prompts/review.prompt.md"].frontmatter == {
        "mode": "agent",
        "tools": ["codebase"],
        "description": "Review code",
    }


def test_frontmatter_secret_dropped_and_redaction_recorded(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    result = _run(repo)
    reviewer = _files(result)[".claude/agents/reviewer.md"]
    assert reviewer.frontmatter == {
        "name": "reviewer",
        "description": "Reviews code",
        "tools": "Read, Grep, Bash",
        "created": "2025-01-02",
    }
    assert reviewer.contains_secret_like
    (redaction,) = result.redactions
    assert redaction.redaction_class == "credential-shaped-token"
    assert redaction.applied_by == "collector:instructions@0.1.0"
    assert reviewer.id in redaction.ids
    assert redaction.count == len(redaction.ids) == 2  # the reviewer key and the hook URL query token


def test_capability_tags_from_tool_frontmatter(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    files = _files(_run(repo))
    assert "capability:execute" in files[".claude/agents/reviewer.md"].tags
    commit = files[".claude/commands/git/commit.md"]
    assert {"capability:execute", "capability:write"} <= set(commit.tags)
    assert not any(t.startswith("capability:") for t in files[".github/prompts/review.prompt.md"].tags)


# --------------------------------------------------------------------------------------------- prompt templates


def test_prompt_templates_with_and_without_schema(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    result = _run(repo)
    prompts = _prompts(result)
    assert set(prompts) == {"prompts/agent.j2", "prompts/support/escalate.txt"}
    agent = prompts["prompts/agent.j2"]
    schema = json.loads(AGENT_SCHEMA)
    assert agent.id == "prompt:prompts-agent.j2"
    assert agent.engine is TemplateEngine.JINJA2
    assert agent.risk_class is TemplateRiskClass.TEMPLATE_EXECUTION
    assert agent.digest == prompt_digest(
        engine="jinja2", role="system", template=AGENT_J2, variables_schema=schema
    )
    assert agent.template_digest == "sha256:" + hashlib.sha256(AGENT_J2.encode()).hexdigest()
    assert agent.variables_schema == schema
    assert agent.variables_schema_digest == "sha256:" + hashlib.sha256(AGENT_SCHEMA.encode()).hexdigest()
    escalate = prompts["prompts/support/escalate.txt"]
    assert escalate.variables_schema is None and escalate.variables_schema_digest is None
    assert escalate.digest.ok
    assert "prompts/agent.j2" not in _files(result)
    sources = {s.locator: s for s in result.coverage[Surface.INSTRUCTIONS].sources}
    assert sources["prompts/agent.schema.json"].ok


def test_prompt_schema_problems(tmp_path: Path) -> None:
    _populate(
        tmp_path,
        {
            "prompts/dup.j2": "{{ a }}",
            "prompts/dup.schema.json": '{"a": 1, "a": 2}',
            "prompts/list.j2": "{{ a }}",
            "prompts/list.schema.json": "[1, 2]",
            "prompts/secret.j2": "{{ a }}",
            "prompts/secret.schema.json": json.dumps({"default": AWS_KEY}),
            "prompts/hidden.j2": "{{ a }}",
            "prompts/hidden.schema.json": json.dumps({"title": f"x{ZWSP}"}),
            "prompts/large.j2": "{{ a }}",
            "prompts/large.schema.json": json.dumps({"description": "y" * (70 * 1024)}),
            "prompts/deep.j2": "{{ a }}",
            "prompts/deep.schema.json": "[" * 100_000 + "]" * 100_000,
        },
    )
    outside = _write(tmp_path.parent / f"{tmp_path.name}-outside.schema.json", "{}")
    _write(tmp_path / "prompts/escape.j2", "{{ a }}")
    os.symlink(outside, tmp_path / "prompts/escape.schema.json")
    result = _run(tmp_path)
    prompts = _prompts(result)
    for name in ("dup", "list", "deep", "escape"):
        tmpl = prompts[f"prompts/{name}.j2"]
        assert "variables-schema-invalid" in tmpl.tags and tmpl.variables_schema is None
    failed = _failed(result)
    assert failed["prompts/dup.schema.json"] == "parse-error"
    assert failed["prompts/escape.schema.json"] == "symlink-escape"
    secret = prompts["prompts/secret.j2"]
    assert secret.variables_schema is None and secret.variables_schema_digest is not None
    assert {"secret-like", "variables-schema-not-embedded"} <= set(secret.tags)
    assert secret.digest.ok  # the digest still commits to the real schema
    assert AWS_KEY not in _dump(result)
    assert result.redactions[0].ids == [secret.id]
    hidden = prompts["prompts/hidden.j2"]
    assert hidden.variables_schema is None and "hidden-unicode" in hidden.tags
    large = prompts["prompts/large.j2"]
    assert large.variables_schema is None and "variables-schema-not-embedded" in large.tags


def test_prompt_digest_recursion_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write(tmp_path / "prompts/agent.j2", "{{ a }}")

    def explode(**_: Any) -> Any:
        raise RecursionError

    monkeypatch.setattr(mod, "prompt_digest", explode)
    (tmpl,) = _prompts(_run(tmp_path)).values()
    assert tmpl.digest.status is DigestStatus.UNDIGESTABLE and tmpl.digest.reason == "nesting-too-deep"


def test_prompt_dirs_are_configurable(tmp_path: Path) -> None:
    _populate(tmp_path, {"src/agent/prompts/system.md": "sys\n", "prompts/other.md": "other\n"})
    custom = _files(_run(tmp_path, collector=InstructionsCollector(prompt_dirs=("src/agent/prompts/",))))
    assert set(custom) == {"src/agent/prompts/system.md"}
    assert not _files(_run(tmp_path, collector=InstructionsCollector(prompt_dirs=())))


# --------------------------------------------------------------------------------------------- hooks


def test_hooks_digest_tags_and_privacy(scene: tuple[Path, Path]) -> None:
    repo, _ = scene
    result = _run(repo)
    hooks = _hooks(result)
    assert set(hooks) == {
        ".claude/settings.json#/hooks/PreToolUse/0/hooks/0",
        ".claude/settings.json#/hooks/PreToolUse/1/hooks/0",
        ".claude/settings.json#/hooks/SessionStart/0/hooks/0",
        ".claude/settings.json#/hooks/Stop/0/hooks/0",
        ".claude/settings.local.json#/hooks/UserPromptSubmit/0/hooks/0",
    }
    bash = hooks[".claude/settings.json#/hooks/PreToolUse/0/hooks/0"]
    payload = {"event": "PreToolUse", "matcher": "Bash", "type": "command", "command": "./scripts/check.sh"}
    assert bash.digest == "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()
    assert bash.id == "instr:claude-settings.json/hook/pretooluse/0/0"
    assert bash.name == "PreToolUse:Bash"
    assert bash.size == len(b"./scripts/check.sh")
    assert bash.path == ".claude/settings.json"
    assert bash.media_type == "application/json"
    assert bash.precedence == 2
    assert set(bash.tags) == {"event:PreToolUse", "hook-type:command", "scope:project"}
    assert bash.loads_remote is not None and bash.loads_remote.value == []
    leaky = hooks[".claude/settings.json#/hooks/PreToolUse/1/hooks/0"]
    assert leaky.contains_secret_like and "secret-like" in leaky.tags
    session = hooks[".claude/settings.json#/hooks/SessionStart/0/hooks/0"]
    assert session.name == "SessionStart:*"
    assert session.loads_remote is not None and session.loads_remote.value == ["https://hooks.example.com"]
    stop = hooks[".claude/settings.json#/hooks/Stop/0/hooks/0"]
    prompt_payload = {
        "event": "Stop",
        "matcher": None,
        "type": "prompt",
        "prompt": "Check the task is complete.",
    }
    assert stop.digest == "sha256:" + hashlib.sha256(canonical_bytes(prompt_payload)).hexdigest()
    assert "hook-type:prompt" in stop.tags
    local = hooks[".claude/settings.local.json#/hooks/UserPromptSubmit/0/hooks/0"]
    assert "disabled" in local.tags
    dump = _dump(result)
    for text in ("./scripts/check.sh", "notify.sh", "T000/B000/XYZ", "Check the task is complete"):
        assert text not in dump  # hook bodies are digested, never stored
    assert _failed(result)[".claude/settings.json#/hooks/PostToolUse/0/hooks/0"] == "unsupported-hook"
    sources = {s.locator: s for s in result.coverage[Surface.INSTRUCTIONS].sources}
    assert sources[".claude/settings.json"].ok and sources[".claude/settings.json"].items == 4


def test_hook_settings_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write(tmp_path / ".claude/settings.json", "{ not json")
    _write(tmp_path / ".claude/settings.local.json", json.dumps({"hooks": []}))
    result = _run(tmp_path)
    failed = _failed(result)
    assert failed[".claude/settings.json"] == "parse-error"
    assert failed[".claude/settings.local.json#/hooks"] == "invalid-hooks"
    assert result.coverage[Surface.INSTRUCTIONS].status is CoverageStatus.PARTIAL
    assert not any("not json" in w for w in result.warnings)

    _write(
        tmp_path / ".claude/settings.json",
        json.dumps({"hooks": {"Stop": [{"matcher": 2**60, "hooks": [{"type": "command", "command": "x"}]}]}}),
    )
    assert _failed(_run(tmp_path))[".claude/settings.json#/hooks/Stop/0/hooks/0"] == "undigestable"

    real = mod.read_bounded

    def denied(path: Path, limit: int) -> ReadOutcome:
        return ReadOutcome(None, "permission-denied") if path.name == "settings.json" else real(path, limit)

    monkeypatch.setattr(mod, "read_bounded", denied)
    assert _failed(_run(tmp_path))[".claude/settings.json"] == "permission-denied"


def test_hook_settings_symlink_escape(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    outside = _write(tmp_path / "elsewhere/settings.json", json.dumps(SETTINGS))
    (repo / ".claude").mkdir(parents=True)
    os.symlink(outside, repo / ".claude/settings.json")
    result = _run(repo)
    assert _failed(result)[".claude/settings.json"] == "symlink-escape"
    assert not _hooks(result)


# --------------------------------------------------------------------------------------------- scopes


def test_user_scope_files_hooks_and_id_collisions(scene: tuple[Path, Path]) -> None:
    repo, home = scene
    result = _run(repo, home)
    files = _files(result)
    user = {p: (i.instruction_kind, i.precedence) for p, i in files.items() if p.startswith("~/")}
    assert user == {
        "~/.claude/CLAUDE.md": (InstructionKind.CLAUDE_MD, 3),
        "~/.claude/agents/helper.md": (InstructionKind.OTHER, 3),
        "~/.claude/commands/standup.md": (InstructionKind.OTHER, 3),
        "~/.codex/AGENTS.md": (InstructionKind.AGENTS_MD, 3),
        "~/.gemini/GEMINI.md": (InstructionKind.GEMINI_MD, 3),
    }
    assert all("scope:user" in files[p].tags for p in user)
    # ``.claude/CLAUDE.md`` and ``~/.claude/CLAUDE.md`` slug alike: the project file keeps the plain id
    assert files[".claude/CLAUDE.md"].id == "instr:claude-claude.md"
    assert files["~/.claude/CLAUDE.md"].id.startswith("instr:claude-claude.md-")
    (notify,) = (h for h in _hooks(result).values() if h.path == "~/.claude/settings.json")
    assert notify.precedence == 3 and "scope:user" in notify.tags and "event:Notification" in notify.tags
    assert not any("projects" in (s.locator or "") for s in result.coverage[Surface.INSTRUCTIONS].sources)
    ids = [e.id for e in result.entities]
    assert len(ids) == len(set(ids))


def test_repo_only_scan_marks_user_scope_not_attempted(tmp_path: Path) -> None:
    _write(tmp_path / "CLAUDE.md", "memory\n")
    result = _run(tmp_path)
    cov = result.coverage[Surface.INSTRUCTIONS]
    assert any(s.source == "user-scope" and s.error_class == "not-attempted" for s in cov.sources)
    assert cov.status is CoverageStatus.PARTIAL
    assert cov.items_seen == 1


def test_empty_repo_is_queried_with_zero_items(tmp_path: Path) -> None:
    result = _run(tmp_path / "repo", tmp_path / "home")
    cov = result.coverage[Surface.INSTRUCTIONS]
    assert cov.status is CoverageStatus.QUERIED
    assert cov.items_seen == 0
    assert not result.entities and not result.edges and not result.redactions


def test_home_equal_to_root_is_not_double_counted(tmp_path: Path) -> None:
    _populate(tmp_path, {".claude/CLAUDE.md": "memory\n", ".claude/settings.json": json.dumps(SETTINGS)})
    result = _run(tmp_path, tmp_path)
    claude = [
        e
        for e in result.entities
        if isinstance(e, Instruction) and e.instruction_kind is InstructionKind.CLAUDE_MD
    ]
    assert len(claude) == 1 and claude[0].precedence == 2
    assert len(_hooks(result)) == 4


def test_load_instruction_edges_carry_precedence(scene: tuple[Path, Path]) -> None:
    repo, home = scene
    result = _run(repo, home)
    edges = {e.to_ref: e for e in result.edges}
    assert all(e.type is EdgeType.LOADS_INSTRUCTION and e.from_ref == "agent:triage" for e in result.edges)
    for entity in result.entities:
        edge = edges[entity.id]
        precedence = entity.precedence if isinstance(entity, Instruction) else 2
        assert edge.qualifiers == {"precedence": precedence}
        assert edge.declared_by == entity.provenance.locator
    assert len(result.edges) == len(result.entities)


# --------------------------------------------------------------------------------------------- limits and hostile input


def test_too_large_file_is_streamed_not_analysed(tmp_path: Path) -> None:
    body = (f"@https://x.example/y {OPENAI_KEY}\r\n" * 4).encode()
    _write(tmp_path / "AGENTS.md", body)
    _write(tmp_path / "prompts/agent.j2", b"{{ x }}" * 20)
    result = _run(tmp_path, max_file_bytes=64)
    files = _files(result)
    agents = files["AGENTS.md"]
    assert agents.digest == "sha256:" + hashlib.sha256(body).hexdigest()
    assert agents.size == len(body) and agents.line_endings is LineEndings.CRLF
    assert agents.normalized_digest is None and not agents.contains_secret_like
    assert "too-large-for-analysis" in agents.tags
    assert agents.loads_remote is not None and agents.loads_remote.state is ValueState.UNKNOWN
    assert agents.loads_remote.unknown_reason is UnknownReason.TRUNCATED
    assert (
        files["prompts/agent.j2"].instruction_kind is InstructionKind.SYSTEM_PROMPT
    )  # unanalysed: no template
    assert _failed(result)["AGENTS.md"] == "too-large"
    assert result.coverage[Surface.INSTRUCTIONS].status is CoverageStatus.PARTIAL
    assert any("digested, not analysed" in w for w in result.warnings)


def test_streaming_failure_is_a_coverage_fact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write(tmp_path / "AGENTS.md", "x" * 200)

    def denied(path: Path) -> tuple[str, int]:
        raise PermissionError(path)

    monkeypatch.setattr(mod, "file_digest", denied)
    result = _run(tmp_path, max_file_bytes=64)
    assert _failed(result)["AGENTS.md"] == "permission-denied"
    assert not result.entities


def test_symlinks_followed_inside_root_and_refused_outside(tmp_path: Path) -> None:
    repo, home = tmp_path / "repo", tmp_path / "home"
    _write(repo / "AGENTS.md", "shared rules\n")
    os.symlink("AGENTS.md", repo / "CLAUDE.md")
    _write(tmp_path / "outside/GEMINI.md", "outside\n")
    os.symlink(tmp_path / "outside/GEMINI.md", repo / "GEMINI.md")
    os.symlink("missing.md", repo / ".cursorrules")
    _write(repo / "shared/CLAUDE.md", "via a linked directory\n")
    os.symlink("shared", repo / ".claude")
    _write(home / "dotfiles/CLAUDE.md", "dotfiles memory\n")
    (home / ".claude").mkdir(parents=True)
    os.symlink(home / "dotfiles/CLAUDE.md", home / ".claude/CLAUDE.md")
    result = _run(repo, home)
    files = _files(result)
    claude = files["CLAUDE.md"]
    assert claude.digest == files["AGENTS.md"].digest
    assert "symlink-to:AGENTS.md" in claude.tags and "symlink-to:AGENTS.md" not in files["AGENTS.md"].tags
    assert "symlink-to:shared/CLAUDE.md" in files[".claude/CLAUDE.md"].tags
    assert "symlink-to:~/dotfiles/CLAUDE.md" in files["~/.claude/CLAUDE.md"].tags
    failed = _failed(result)
    assert failed["GEMINI.md"] == "symlink-escape" and "GEMINI.md" not in files
    assert failed[".cursorrules"] == "broken-symlink"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_non_regular_files_are_never_opened(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "AGENTS.md")  # opening a FIFO would block the scan forever
    (tmp_path / "pkg").mkdir()
    os.mkfifo(tmp_path / "pkg/GEMINI.md")
    result = _run(tmp_path)
    failed = _failed(result)
    assert failed["AGENTS.md"] == failed["pkg/GEMINI.md"] == "not-a-regular-file"
    assert not result.entities


def test_unlistable_user_directory_is_a_coverage_fact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    _write(home / ".claude/agents/helper.md", "help\n")

    def denied(base: Path, *, exclude: Any, limit: int) -> tuple[list[Path], list[tuple[Path, str]]]:
        return [], [(base, "permission-denied")]

    monkeypatch.setattr(mod, "list_tree", denied)
    failed = _failed(_run(tmp_path / "repo", home))
    assert failed["~/.claude/agents"] == "permission-denied"


def test_unreadable_file_is_a_coverage_fact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _populate(tmp_path, {"GEMINI.md": "x\n", "AGENTS.md": "y\n"})
    real = mod.read_bounded

    def denied(path: Path, limit: int) -> ReadOutcome:
        return ReadOutcome(None, "permission-denied") if path.name == "GEMINI.md" else real(path, limit)

    monkeypatch.setattr(mod, "read_bounded", denied)
    result = _run(tmp_path, tmp_path / "home")
    assert _failed(result) == {"GEMINI.md": "permission-denied"}
    assert set(_files(result)) == {"AGENTS.md"}
    assert result.coverage[Surface.INSTRUCTIONS].status is CoverageStatus.PARTIAL


def test_non_utf8_files(tmp_path: Path) -> None:
    _write(tmp_path / "AGENTS.md", b"\xff\xfe bad @https://x.example/y " + AWS_KEY.encode())
    _write(tmp_path / ".claude/agents/broken.md", b"---\nname: \xff\n---\nbody")
    _write(tmp_path / "prompts/bad.j2", b"{{ \xff }}")
    files = _files(_run(tmp_path))
    agents = files["AGENTS.md"]
    assert "not-utf8" in agents.tags and agents.normalized_digest is None
    assert agents.contains_secret_like  # still scanned for credential shapes
    assert (
        agents.loads_remote is not None
        and agents.loads_remote.unknown_reason is UnknownReason.UNSUPPORTED_SOURCE
    )
    assert files[".claude/agents/broken.md"].frontmatter is None
    bad = files["prompts/bad.j2"]
    assert bad.instruction_kind is InstructionKind.SYSTEM_PROMPT and "not-utf8" in bad.tags
    assert bad.loads_remote is not None and bad.loads_remote.value == []


def test_walk_truncation_marks_surface_truncated(tmp_path: Path) -> None:
    _populate(tmp_path, {"a/AGENTS.md": "a", "b/AGENTS.md": "b", "c/AGENTS.md": "c"})
    result = _run(tmp_path, max_files=2)
    cov = result.coverage[Surface.INSTRUCTIONS]
    assert cov.status is CoverageStatus.TRUNCATED and cov.truncated_at == 2
    assert any("walk stopped" in w for w in result.warnings)


def test_colliding_slugs_get_suffixes(tmp_path: Path) -> None:
    _populate(tmp_path, {"a/b-c/AGENTS.md": "one", "a-b/c/AGENTS.md": "two"})
    files = _files(_run(tmp_path))
    assert files["a-b/c/AGENTS.md"].id == "instr:a-b-c-agents.md"
    assert files["a/b-c/AGENTS.md"].id.startswith("instr:a-b-c-agents.md-")


def test_deterministic_output(scene: tuple[Path, Path]) -> None:
    repo, home = scene
    assert _dump(_run(repo, home)) == _dump(_run(repo, home))


def test_registered_and_assembles_into_a_valid_document(scene: tuple[Path, Path]) -> None:
    (collector,) = load_collectors(["instructions"], include_plugins=False)
    assert isinstance(collector, InstructionsCollector)
    assert collector.detect(CollectContext(root=Path("/nonexistent")))
    repo, home = scene
    result = _run(repo, home)
    bom = AgentBOM(
        snapshot=Snapshot(
            id=f"snap:1:{D[7:19]}",
            kind=SnapshotKind.DECLARED,
            digest=D,
            serial=1,
            agent_ref="agent:triage",
            produced_at=NOW,
        ),
        subject="agent:triage",
        producer=Producer(version="0.1.0"),
        agents=[Agent(id="agent:triage", name="triage", version="1.0.0", role=AgentRole.ROOT)],
        instructions=[e for e in result.entities if isinstance(e, Instruction)],
        prompts=[e for e in result.entities if isinstance(e, PromptTemplate)],
        edges=result.edges,
        redactions=result.redactions,
    )
    assert len(bom.edges_from("agent:triage", "loadsInstruction")) == len(result.entities)
    assert bom.instructions and bom.prompts


# --------------------------------------------------------------------------------------------- helpers


def test_rule_table_order_and_prompt_rule() -> None:
    hit = classify(".claude/agents/CLAUDE.md", PROJECT_RULES)
    assert hit is not None and hit[0].label == "claude-agents"
    nested = classify("pkg/.claude/CLAUDE.md", PROJECT_RULES)
    assert nested is not None and nested[1].group("dir") == "pkg/.claude"
    assert classify("docs/agents.md", PROJECT_RULES) is None  # memory file names are case-sensitive
    assert classify(".clinerules", PROJECT_RULES) is not None
    assert classify(".roorules-code", PROJECT_RULES) is not None
    assert prompt_rule(()) is None and prompt_rule(["/"]) is None
    rule = prompt_rule(["prompts", "lib/prompts"])
    assert rule is not None and rule.pattern.fullmatch("lib/prompts/a/b.prompt")
    assert media_type_for("x.JINJA2") == "text/x-jinja2" and media_type_for(".windsurfrules") == "text/plain"


def test_is_jinja_template() -> None:
    assert is_jinja_template("a.j2", b"{{ x }}")
    assert is_jinja_template("a.md", b"{% if x %}y{% endif %}")
    assert not is_jinja_template("a.yaml", b"{{ x }}")
    assert not is_jinja_template("a.j2", b"plain")
    assert not is_jinja_template("a.txt", b"{{ \xff }}")


def test_split_tools_and_capabilities() -> None:
    assert split_tools("Read Bash(git add:*), Bash(git commit -m:*)  WebFetch") == [
        "Read",
        "Bash(git add:*)",
        "Bash(git commit -m:*)",
        "WebFetch",
    ]
    assert split_tools(["Read, Grep", "Bash(ls -la)", 3, None]) == ["Read", "Grep", "Bash(ls -la)"]
    assert split_tools("Bash(unbalanced)) Edit") == ["Bash(unbalanced))", "Edit"]
    assert split_tools(None) == [] and split_tools({"a": 1}) == []
    assert split_tools("Read, ") == ["Read"]
    assert capability_tags(["Read", "Bash(rm:*)", "MultiEdit", "WebSearch", "mcp__gh__x"]) == [
        "capability:execute",
        "capability:network-egress",
        "capability:write",
    ]
    assert capability_tags(["Bashful", "codebase"]) == []


def test_scan_imports_edge_cases() -> None:
    text = (
        "@./local.md first\n"
        "~~~\n@fenced.md\n~~~\n"
        "(@paren.md) and @trailing.md, @{{var}} @... @~/x\n"
        f"@sk-{'a' * 30}\n"
        "@HTTPS://Example.com/Path?q=1#frag\n"
        "@https://example.com/Path?q=1\n"
    )
    scan = scan_imports(text)
    assert scan.local == ("./local.md", "trailing.md", "~/x")
    assert scan.remote == ("https://example.com/Path",)
    assert scan.remote_line == 7
    assert scan.redacted == 1  # the secret-shaped target, dropped and never echoed


def test_remote_display() -> None:
    assert remote_display("https://user:pw@Example.com:8443/a/b?token=1#x") == (
        "https://example.com:8443/a/b",
        True,
    )
    assert remote_display("https://example.com/a/b", origin_only=True) == ("https://example.com", False)
    assert remote_display(f"https://example.com/{GH_PAT}") == ("https://example.com/<redacted>", True)
    assert remote_display("https://example.com/" + "a" * 3000)[0] == "https://example.com/<redacted>"
    assert remote_display(f"https://example.com/a{ZWSP}b")[0] == "https://example.com/<redacted>"
    assert remote_display(f"https://exa{ZWSP}mple.com/a")[0] == "https://<invalid-host>"
    assert remote_display("https://[::1/x") == ("https://<unparseable>", False)


def test_parse_frontmatter_modes() -> None:
    assert parse_frontmatter("---\na: 1\n---\n", "none") == (None, None)
    assert parse_frontmatter("no frontmatter", "lenient") == (None, None)
    assert parse_frontmatter("---\n---\nbody", "lenient") == ({}, None)
    assert parse_frontmatter("---  \r\na: 1\r\n---", "lenient") == ({"a": 1}, None)
    assert parse_frontmatter("---\n- a\n---\n", "lenient") == (None, "invalid-frontmatter")
    assert parse_frontmatter("---\nglobs: *.ts\n---\n", "strict") == (None, "invalid-frontmatter")
    assert parse_frontmatter("---\na: 1\n---", "strict") == (
        None,
        None,
    )  # the spec split needs a final newline
    big = "---\n" + "a: b\n" * (MAX_FRONTMATTER_CHARS // 4) + "---\n"
    assert parse_frontmatter(big, "lenient") == (None, "oversized-frontmatter")
    lenient, problem = parse_frontmatter(
        "---\n  - orphan\nglobs: *.ts\n# comment\nalwaysApply: TRUE\nempty:\nquoted: 'x: y'\nlist:\n  - *.a\n  - \"*.b\"\n---\n",
        "lenient",
    )
    assert problem == "lenient-frontmatter"
    assert lenient == {
        "globs": "*.ts",
        "alwaysApply": True,
        "empty": None,
        "quoted": "x: y",
        "list": ["*.a", "*.b"],
    }
    deep, problem = parse_frontmatter("---\na: " + "[" * 5000 + "\n---\n", "strict")
    assert deep is None and problem == "invalid-frontmatter"


def test_lenient_frontmatter_is_linear_time() -> None:
    # a lazy capture followed by optional blanks backtracks quadratically; hostile rules files must not stall
    run = " " * 30_000
    block = f"---\n{{bad: [yaml\na: x{run}y\n  -   {run}z\n---\n"
    started = time.perf_counter()
    parsed, problem = parse_frontmatter(block, "lenient")
    assert time.perf_counter() - started < 1.0
    assert problem == "lenient-frontmatter" and parsed == {"a": ["z"]}


def test_frontmatter_sanitizer() -> None:
    sanitizer = FrontmatterSanitizer()
    cleaned = sanitizer.mapping(
        {
            "ok": "fine",
            "n": 3,
            "f": 1.5,
            "big": 2**60,
            "nan": float("nan"),
            "flag": True,
            "none": None,
            "day": datetime(2025, 1, 2, tzinfo=UTC),
            "secret": OPENAI_KEY,
            AWS_KEY: "key is secret-shaped",
            "hidden": f"a{ZWSP}b",
            "long": "x" * (MAX_FRONTMATTER_STRING + 1),
            "list": ["a", OPENAI_KEY, {"nested": 1}, 2],
            "map": {"nested": "dropped"},
            "bytes": b"raw",
            7: "non-string key",
        }
    )
    assert cleaned == {
        "ok": "fine",
        "n": 3,
        "f": 1.5,
        "flag": True,
        "none": None,
        "day": "2025-01-02T00:00:00+00:00",
        "list": ["a", 2],
    }
    assert sanitizer.redacted == 3


def test_applies_to_tags() -> None:
    assert applies_to_tags({"alwaysApply": True, "globs": "**/*.ts"}) == [
        "applies-to:**",
        "applies-to:**/*.ts",
    ]
    assert applies_to_tags({"inclusion": "always"}) == ["applies-to:**"]
    # keys are read in a fixed order (globs, applyTo, fileMatchPattern, paths); duplicates and blanks collapse
    assert applies_to_tags({"paths": ["src/**", "src/**", 3], "applyTo": f" a , ,{AWS_KEY}"}) == [
        "applies-to:a",
        "applies-to:src/**",
    ]
    assert applies_to_tags({"globs": "x" * 300}) == []
    many = applies_to_tags({"globs": ",".join(f"g{i}" for i in range(50))})
    assert len(many) == MAX_APPLIES_TO_TAGS


def test_parse_hooks_shapes() -> None:
    assert parse_hooks([]) == ([], [])
    assert parse_hooks({"hooks": None}) == ([], [])
    assert parse_hooks({"hooks": "x"}) == ([], [(("hooks",), "invalid-hooks")])
    decls, problems = parse_hooks(
        {
            "hooks": {
                "A": "not-a-list",
                "B": [
                    "not-a-group",
                    {"hooks": "x"},
                    {"matcher": "m", "hooks": ["x", {"type": 1}, {"type": "command"}]},
                ],
                "C": [{"hooks": [{"type": "command", "command": "ok"}, {"type": "prompt", "prompt": "p"}]}],
            }
        }
    )
    assert problems == [
        (("hooks", "A"), "invalid-hooks"),
        (("hooks", "B", 0), "invalid-hooks"),
        (("hooks", "B", 1), "invalid-hooks"),
        (("hooks", "B", 2, "hooks", 0), "unsupported-hook"),
        (("hooks", "B", 2, "hooks", 1), "unsupported-hook"),
        (("hooks", "B", 2, "hooks", 2), "unsupported-hook"),
    ]
    assert [d.payload() for d in decls] == [
        {"event": "C", "matcher": None, "type": "command", "command": "ok"},
        {"event": "C", "matcher": None, "type": "prompt", "prompt": "p"},
    ]
    assert decls[1].pointer == ("hooks", "C", 0, "hooks", 1)


def test_hook_labels_are_sanitized(tmp_path: Path) -> None:
    settings = {
        "hooks": {AWS_KEY: [{"matcher": f"Bash{ZWSP}", "hooks": [{"type": "command", "command": "x"}]}]}
    }
    _write(tmp_path / ".claude/settings.json", json.dumps(settings))
    (hook,) = _hooks(_run(tmp_path)).values()
    assert hook.name == "hook:*" and hook.id == "instr:claude-settings.json/hook/event/0/0"
    assert not any(t.startswith("event:") for t in hook.tags)
    decl = HookDecl("E", 0, 0, None, "command", "command", "x")
    assert decl.pointer == ("hooks", "E", 0, "hooks", 0)


def test_streamed_line_endings_match_in_memory(tmp_path: Path) -> None:
    samples = [
        b"",
        b"no newline",
        b"a\nb\n",
        b"a\r\nb\r\n",
        b"a\r\nb\n",
        b"a" * ((1 << 20) - 1) + b"\r\n" + b"tail\r\n",  # CRLF split across the 1 MiB chunk boundary
        b"a" * ((1 << 20) - 1) + b"\r\n" + b"x\n",
    ]
    for i, data in enumerate(samples):
        path = _write(tmp_path / f"s{i}", data)
        assert streamed_line_endings(path) is line_endings(data), i


def test_read_file_facts(tmp_path: Path) -> None:
    small = _write(tmp_path / "small", b"abc\n")
    facts, error = read_file_facts(small, 100)
    assert error is None and facts is not None and facts.data == b"abc\n"
    big = _write(tmp_path / "big", b"x" * 200)
    facts, error = read_file_facts(big, 100)
    assert facts is not None and facts.data is None and facts.size == 200 and error is None
    assert facts.digest == "sha256:" + hashlib.sha256(b"x" * 200).hexdigest()
    assert read_file_facts(tmp_path / "missing", 100) == (None, "not-found")


def test_filesystem_helpers(tmp_path: Path) -> None:
    bounds = tmp_path.resolve()
    target = _write(tmp_path / "dir/file.md", "x")
    assert resolve_within(target, bounds) == (target.resolve(), None)
    assert resolve_within(tmp_path / "dir", bounds) == (None, "not-a-regular-file")
    assert resolve_within(target, bounds, directory=True) == (None, "not-a-directory")
    assert resolve_within(tmp_path / "nope", bounds) == (None, "not-found")
    os.symlink("loop-b", tmp_path / "loop-a")
    os.symlink("loop-a", tmp_path / "loop-b")
    assert resolve_within(tmp_path / "loop-a", bounds)[1] in {"symlink-loop", "unreadable"}
    assert os_error_class(PermissionError()) == "permission-denied"
    assert os_error_class(IsADirectoryError()) == "unreadable"
    os.symlink("dir/file.md", tmp_path / "link.md")
    assert symlink_tag(tmp_path / "link.md", base=tmp_path, bounds=bounds) == "symlink-to:dir/file.md"
    assert symlink_tag(target, base=tmp_path, bounds=bounds) is None
    assert symlink_tag(target, base=tmp_path / "other", bounds=bounds) is None
    assert symlink_tag(tmp_path / "loop-a", base=tmp_path, bounds=bounds) is None
    assert (
        has_hidden_unicode(f"a{RLO}")
        and not has_hidden_unicode("plain ascii")
        and not has_hidden_unicode("café")
    )


def test_list_tree(tmp_path: Path) -> None:
    _populate(tmp_path, {"b/x.md": "1", "a.md": "2", "skip/y.md": "3", "c/d/e.md": "4"})
    os.symlink("b", tmp_path / "linked-dir")
    files, problems = list_tree(tmp_path, exclude=("skip",), limit=100)
    assert [p.relative_to(tmp_path).as_posix() for p in files] == ["a.md", "b/x.md", "c/d/e.md", "linked-dir"]
    assert problems == []
    files, problems = list_tree(tmp_path / "a.md", exclude=(), limit=100)
    assert files == [] and problems == [(tmp_path / "a.md", "unreadable")]
    assert len(list_tree(tmp_path, exclude=(), limit=1)[0]) == 1


def test_run_state_and_id_registry(tmp_path: Path) -> None:
    registry = IdRegistry()
    first = registry.claim("instr", "a/b")
    assert first == "instr:a-b"
    second, third = registry.claim("instr", "a-b"), registry.claim("instr", "a b")
    assert (
        len({first, second, third}) == 3
        and second.startswith("instr:a-b-")
        and third.startswith("instr:a-b-")
    )
    collector = InstructionsCollector()
    state = RunState(CollectContext(root=tmp_path, now=NOW), collector.new_result())
    assert state.first_visit(tmp_path / "x") and not state.first_visit(tmp_path / "x")
    state.redact("instr:a", 0)
    state.fail("src", "where", "boom")
    assert state.result.warnings == ["where: boom"]
    assert state.finish(collector.ref).redactions == []
    state.redact("instr:a", 2)
    assert state.finish(collector.ref).redactions[0].count == 2


def test_record_walk(tmp_path: Path) -> None:
    result = InstructionsCollector().new_result()
    record_walk(result, 3, 10)
    record_walk(result, 10, 10)
    sources = result.coverage[Surface.INSTRUCTIONS].sources
    assert [(s.ok, s.error_class) for s in sources] == [(True, None), (False, "truncated")]
    assert result.coverage[Surface.INSTRUCTIONS].status is CoverageStatus.TRUNCATED
