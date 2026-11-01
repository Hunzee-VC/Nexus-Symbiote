"""System prompt, instruction file, and skill definition scanner."""

from __future__ import annotations

from pathlib import Path

from symbote.core.enums import RiskSeverity, TrustTier
from symbote.core.hashing import hash_file
from symbote.core.models import PromptComponent, RiskAssessment, SkillPackageComponent
from symbote.scanners.base import Scanner, ScanResult

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
            if full_path.exists() and full_path.is_file():
                result.surfaces_scanned.append(str(full_path))
                comp = self._scan_instruction_file(full_path, rel_path, prompt_type)
                result.components.append(comp)

        for skill_dir in SKILL_DIRECTORIES:
            full_dir = project_root / skill_dir
            if full_dir.is_dir():
                result.surfaces_scanned.append(str(full_dir))
                skills = self._scan_skill_directory(full_dir)
                result.components.extend(skills)
            else:
                result.surfaces_excluded.append(f"skills ({skill_dir} not found)")

        if not result.components:
            result.surfaces_excluded.append("prompts (no instruction files found)")

        return result

    def _scan_instruction_file(
        self, path: Path, rel_path: str, prompt_type: str
    ) -> PromptComponent:
        content_hash = hash_file(path)
        file_size = path.stat().st_size
        risks: list[RiskAssessment] = []

        if file_size > 50_000:
            risks.append(RiskAssessment(
                severity=RiskSeverity.MEDIUM,
                category="prompt_size",
                detail=f"'{rel_path}' is {file_size:,} bytes — large prompts increase injection surface.",
                recommendation="Review for unnecessary content.",
            ))

        return PromptComponent(
            bom_ref=f"prompt:{rel_path}",
            name=rel_path,
            prompt_type=prompt_type,
            content_hash=content_hash,
            source_path=str(path),
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
        )

    def _scan_skill_directory(self, skill_dir: Path) -> list[SkillPackageComponent]:
        skills: list[SkillPackageComponent] = []
        for path in sorted(skill_dir.rglob("*")):
            if not path.is_file() or path.name.startswith("."):
                continue
            if path.suffix.lower() not in (".md", ".txt", ".yaml", ".yml", ".json"):
                continue

            rel_path = str(path.relative_to(skill_dir.parent.parent))
            content_hash = hash_file(path)

            skills.append(SkillPackageComponent(
                bom_ref=f"skill:{rel_path}",
                name=rel_path,
                skill_type="skill",
                hashes={"sha256": content_hash},
                source_path=str(path),
                trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            ))
        return skills
