"""System prompt, instruction file, and skill definition scanner."""

from __future__ import annotations

import re
from pathlib import Path

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import PromptComponent, RiskAssessment, SkillPackageComponent
from nexus_symbiote.scanners.base import Scanner, ScanResult

INVISIBLE_CHARS: dict[str, str] = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "­": "SOFT HYPHEN",
}

BIDI_OVERRIDES: dict[str, str] = {
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
}

TAG_CHAR_RANGE = re.compile(r"[\U000e0001-\U000e007f]")


def detect_invisible_characters(content: str, source_name: str) -> list[RiskAssessment]:
    """Detect invisible Unicode characters that could be used for prompt trojans.

    Checks for zero-width characters, bidirectional overrides, and deprecated
    tag characters — all of which are invisible in most editors and can alter
    LLM interpretation of prompts.
    """
    risks: list[RiskAssessment] = []

    found_invisible = []
    for char, name in INVISIBLE_CHARS.items():
        count = content.count(char)
        if count > 0:
            found_invisible.append(f"{name} (U+{ord(char):04X}) x{count}")

    if found_invisible:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="invisible_characters",
                detail=(
                    f"'{source_name}' contains invisible Unicode characters: "
                    f"{', '.join(found_invisible)}. "
                    "These are invisible in most editors and may alter LLM behavior."
                ),
                recommendation="Remove all zero-width characters or document their purpose.",
            )
        )

    found_bidi = []
    for char, name in BIDI_OVERRIDES.items():
        count = content.count(char)
        if count > 0:
            found_bidi.append(f"{name} (U+{ord(char):04X}) x{count}")

    if found_bidi:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="bidi_override",
                detail=(
                    f"'{source_name}' contains bidirectional override characters: "
                    f"{', '.join(found_bidi)}. "
                    "Bidi overrides can make malicious instructions appear as benign text."
                ),
                recommendation="Remove all bidirectional override characters immediately.",
            )
        )

    tag_matches = TAG_CHAR_RANGE.findall(content)
    if tag_matches:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="tag_characters",
                detail=(
                    f"'{source_name}' contains {len(tag_matches)} deprecated Unicode tag "
                    "characters (U+E0001–U+E007F). These are invisible and have no "
                    "legitimate use in prompt files."
                ),
                recommendation="Remove all tag characters — likely a prompt trojan.",
            )
        )

    return risks


INSTRUCTION_FILES: dict[str, str] = {
    "CLAUDE.md": "system-prompt",
    ".claude/CLAUDE.md": "system-prompt",
    "AGENTS.md": "system-prompt",
    "CODEX.md": "system-prompt",
    "codex.md": "system-prompt",
    ".cursorrules": "rules-file",
    ".clinerules": "rules-file",
    ".windsurfrules": "rules-file",
    ".github/copilot-instructions.md": "instruction",
    ".github/AGENTS.md": "instruction",
    ".codex/instructions.md": "instruction",
    "system_prompt.txt": "system-prompt",
    "system_prompt.md": "system-prompt",
}

SKILL_DIRECTORIES = [".claude/skills", ".claude/commands", "skills"]

# Instruction files a host loads from below the root: per-directory memory files,
# subagent definitions and rule or prompt directories.
NESTED_INSTRUCTION_NAMES = {"CLAUDE.md": "system-prompt", "AGENTS.md": "system-prompt"}
INSTRUCTION_DIRECTORIES: dict[str, str] = {
    ".claude/agents": "subagent",
    ".cursor/rules": "rules-file",
    ".github/instructions": "instruction",
    ".github/prompts": "instruction",
}
_INSTRUCTION_SUFFIXES = (".md", ".mdc", ".txt")
_DECLARATION_SUFFIXES = (".md", ".txt", ".yaml", ".yml", ".json")


class PromptScanner(Scanner):
    name = "prompt"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        with self._collection(project_root, result) as files:
            for rel_path, prompt_type in INSTRUCTION_FILES.items():
                content = files.read_bytes(rel_path, missing_ok=True)
                if content is None:
                    continue
                full_path = files.root / rel_path
                result.surfaces_scanned.append(str(full_path))
                try:
                    text = content.decode("utf-8")
                except UnicodeDecodeError:
                    result.scan_failures.append(f"{rel_path}: invalid UTF-8 instruction")
                    continue
                comp = self._scan_instruction_file(full_path, rel_path, prompt_type, content, text)
                result.components.append(comp)

            for path in sorted(files.iter_files()):
                nested_path = path.as_posix()
                if nested_path in INSTRUCTION_FILES:
                    continue
                nested_type: str | None = (
                    NESTED_INSTRUCTION_NAMES.get(path.name) if len(path.parts) > 1 else None
                )
                if nested_type is None and path.suffix.lower() in _INSTRUCTION_SUFFIXES:
                    nested_type = next(
                        (
                            kind
                            for directory, kind in INSTRUCTION_DIRECTORIES.items()
                            if nested_path.startswith(directory + "/")
                        ),
                        None,
                    )
                if nested_type is None:
                    continue
                content = files.read_bytes(path)
                if content is None:
                    continue
                result.surfaces_scanned.append(nested_path)
                try:
                    text = content.decode("utf-8")
                except UnicodeDecodeError:
                    result.scan_failures.append(f"{nested_path}: invalid UTF-8 instruction")
                    continue
                result.components.append(
                    self._scan_instruction_file(
                        files.root / path, nested_path, nested_type, content, text
                    )
                )

            for skill_dir in SKILL_DIRECTORIES:
                found = False
                paths = list(files.iter_files(skill_dir))
                packages = {path.parent for path in paths if path.name == "SKILL.md"}
                for path in paths:
                    declaration = path.suffix.lower() in _DECLARATION_SUFFIXES
                    # A skill package's scripts run with the agent's authority, so they
                    # are bound by digest like its declarations.
                    if path.name.startswith(".") or not (
                        declaration or packages.intersection(path.parents)
                    ):
                        continue
                    content = files.read_bytes(path)
                    if content is None:
                        continue
                    if declaration:
                        try:
                            content.decode("utf-8")
                        except UnicodeDecodeError:
                            result.scan_failures.append(f"{path}: invalid UTF-8 skill declaration")
                            continue
                    found = True
                    relative = path.as_posix()
                    result.surfaces_scanned.append(str(files.root / path))
                    result.components.append(
                        SkillPackageComponent(
                            bom_ref=f"skill:{relative}",
                            name=relative,
                            skill_type="skill" if declaration else "skill-resource",
                            hashes={"sha256": hash_bytes(content)},
                            source_path=str(files.root / path),
                            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                        )
                    )
                if not found and not result.scan_failures and not result.surfaces_excluded:
                    result.surfaces_scanned.append(f"skills ({skill_dir} no skill files found)")

        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("prompts (no instruction files found)")

        return result

    def _scan_instruction_file(
        self, path: Path, rel_path: str, prompt_type: str, raw: bytes, text: str
    ) -> PromptComponent:
        content_hash = hash_bytes(raw)
        file_size = len(raw)
        risks: list[RiskAssessment] = []

        if file_size > 50_000:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="prompt_size",
                    detail=f"'{rel_path}' is {file_size:,} bytes — large prompts increase injection surface.",
                    recommendation="Review for unnecessary content.",
                )
            )

        risks.extend(detect_invisible_characters(text, rel_path))

        return PromptComponent(
            bom_ref=f"prompt:{rel_path}",
            name=rel_path,
            prompt_type=prompt_type,
            content_hash=content_hash,
            source_path=str(path),
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
        )
