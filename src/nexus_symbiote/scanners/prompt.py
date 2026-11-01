"""System prompt, instruction file, and skill definition scanner."""

from __future__ import annotations

import re
from pathlib import Path

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import PromptComponent, RiskAssessment, SkillPackageComponent
from nexus_symbiote.scanners.base import Scanner, ScanResult, read_regular_text, safe_rglob

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
    ".cursorrules": "rules-file",
    ".clinerules": "rules-file",
    ".windsurfrules": "rules-file",
    ".github/copilot-instructions.md": "instruction",
    ".github/AGENTS.md": "instruction",
    "system_prompt.txt": "system-prompt",
    "system_prompt.md": "system-prompt",
}

SKILL_DIRECTORIES = [".claude/skills", ".claude/commands", "skills"]


class PromptScanner(Scanner):
    name = "prompt"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        for rel_path, prompt_type in INSTRUCTION_FILES.items():
            full_path = project_root / rel_path
            if full_path.is_symlink() or full_path.exists():
                result.surfaces_scanned.append(str(full_path))
                try:
                    comp = self._scan_instruction_file(full_path, rel_path, prompt_type)
                    result.components.append(comp)
                except (OSError, UnicodeError):
                    result.scan_failures.append(f"Failed to read {full_path}")

        for skill_dir in SKILL_DIRECTORIES:
            full_dir = project_root / skill_dir
            if full_dir.is_symlink():
                result.scan_failures.append(f"Refusing symlinked skill directory {full_dir}")
            elif full_dir.is_dir():
                result.surfaces_scanned.append(str(full_dir))
                skills = self._scan_skill_directory(full_dir, result)
                result.components.extend(skills)
            else:
                result.surfaces_excluded.append(f"skills ({skill_dir} not found)")

        if not result.components and not result.scan_failures:
            result.surfaces_excluded.append("prompts (no instruction files found)")

        return result

    def _scan_instruction_file(
        self, path: Path, rel_path: str, prompt_type: str
    ) -> PromptComponent:
        content = read_regular_text(path)
        encoded = content.encode("utf-8")
        content_hash = hash_bytes(encoded)
        file_size = len(encoded)
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

        risks.extend(detect_invisible_characters(content, rel_path))

        return PromptComponent(
            bom_ref=f"prompt:{rel_path}",
            name=rel_path,
            prompt_type=prompt_type,
            content_hash=content_hash,
            source_path=str(path),
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
        )

    def _scan_skill_directory(
        self, skill_dir: Path, result: ScanResult
    ) -> list[SkillPackageComponent]:
        skills: list[SkillPackageComponent] = []
        for path in sorted(safe_rglob(skill_dir, "*")):
            if path.name.startswith("."):
                continue
            if path.suffix.lower() not in (".md", ".txt", ".yaml", ".yml", ".json"):
                continue
            if not path.is_file() and not path.is_symlink():
                result.scan_failures.append(f"Not a regular skill file: {path}")
                continue

            rel_path = str(path.relative_to(skill_dir.parent.parent))
            try:
                content_hash = hash_bytes(read_regular_text(path).encode("utf-8"))
            except (OSError, UnicodeError):
                result.scan_failures.append(f"Failed to read {path}")
                continue

            skills.append(
                SkillPackageComponent(
                    bom_ref=f"skill:{rel_path}",
                    name=rel_path,
                    skill_type="skill",
                    hashes={"sha256": content_hash},
                    source_path=str(path),
                    trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                )
            )
        return skills
