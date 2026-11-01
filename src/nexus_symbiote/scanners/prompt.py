"""System prompt, instruction file, and skill definition scanner."""

from __future__ import annotations

import unicodedata
from collections import Counter
from pathlib import Path

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import PromptComponent, RiskAssessment, SkillPackageComponent
from nexus_symbiote.core.textsafety import HiddenCharacter, find_hidden_characters
from nexus_symbiote.scanners.base import (
    Scanner,
    ScanResult,
    matched_exclusion,
    read_regular_text,
    relative_posix,
)

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


def detect_invisible_characters(content: str, source_name: str) -> list[RiskAssessment]:
    """Report characters that can hide or reorder text in a prompt file.

    Bidirectional controls and tag characters can make instructions read differently from
    how a model receives them, so they are HIGH. Other invisible format characters are
    MEDIUM. Joiners and variation selectors are not reported, because emoji and several
    scripts depend on them.
    """
    hits = find_hidden_characters(content)
    reordering = [hit for hit in hits if hit.kind != "invisible"]
    invisible = [hit for hit in hits if hit.kind == "invisible"]

    risks: list[RiskAssessment] = []
    if reordering:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="hidden-characters",
                detail=_describe(content, source_name, reordering, "can reorder or hide text"),
                recommendation="Remove bidirectional and tag characters. Treat any instance as a possible prompt trojan.",
            )
        )
    if invisible:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.MEDIUM,
                category="hidden-characters",
                detail=_describe(content, source_name, invisible, "are invisible in most editors"),
                recommendation="Remove invisible characters, or document their purpose.",
            )
        )
    return risks


def _describe(
    content: str, source_name: str, hits: list[HiddenCharacter], reason: str
) -> str:
    counts = Counter(hit.codepoint for hit in hits)
    names: dict[str, str] = {}
    for hit in hits:
        names.setdefault(hit.codepoint, unicodedata.name(content[hit.index], "UNNAMED"))
    listed = ", ".join(f"{cp} {names[cp]} x{count}" for cp, count in sorted(counts.items()))
    return f"'{source_name}' contains {len(hits)} hidden character(s) that {reason}: {listed}."


class PromptScanner(Scanner):
    name = "prompt"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        missing_files: list[str] = []
        for rel_path, prompt_type in INSTRUCTION_FILES.items():
            full_path = project_root / rel_path
            if matched_exclusion(full_path, project_root, self.exclude_paths):
                result.record_excluded(rel_path, "excluded by policy")
                continue
            if not (full_path.is_symlink() or full_path.exists()):
                missing_files.append(rel_path)
                continue
            result.surfaces_scanned.append(rel_path)
            try:
                comp = self._scan_instruction_file(full_path, rel_path, prompt_type)
            except (OSError, UnicodeError):
                result.record_failure(f"Failed to read {rel_path}")
                continue
            result.components.append(comp)
        if missing_files:
            result.record_absent("instruction-file", missing_files)

        missing_dirs: list[str] = []
        for skill_dir in SKILL_DIRECTORIES:
            full_dir = project_root / skill_dir
            if matched_exclusion(full_dir, project_root, self.exclude_paths):
                result.record_excluded(skill_dir, "excluded by policy")
            elif full_dir.is_symlink():
                result.record_failure(f"Refusing symlinked skill directory {skill_dir}")
            elif full_dir.is_dir():
                result.surfaces_scanned.append(skill_dir)
                skills = self._scan_skill_directory(full_dir, project_root, result)
                result.components.extend(skills)
            else:
                missing_dirs.append(skill_dir)
        if missing_dirs:
            result.record_absent("skill-directory", missing_dirs)

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
                    detail=f"'{rel_path}' is {file_size:,} bytes; large prompts increase injection surface.",
                    recommendation="Review for unnecessary content.",
                )
            )

        risks.extend(detect_invisible_characters(content, rel_path))

        return PromptComponent(
            bom_ref=f"prompt:{rel_path}",
            name=rel_path,
            prompt_type=prompt_type,
            content_hash=content_hash,
            source_path=rel_path,
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
        )

    def _scan_skill_directory(
        self, skill_dir: Path, project_root: Path, result: ScanResult
    ) -> list[SkillPackageComponent]:
        skills: list[SkillPackageComponent] = []
        for path in sorted(skill_dir.rglob("*")):
            if path.name.startswith("."):
                continue
            if path.suffix.lower() not in (".md", ".txt", ".yaml", ".yml", ".json"):
                continue

            rel_path = relative_posix(path, project_root)
            if matched_exclusion(path, project_root, self.exclude_paths):
                result.record_excluded(rel_path, "excluded by policy")
                continue
            if path.is_symlink():
                result.record_failure(f"Refusing symlinked skill file {rel_path}")
                continue
            try:
                content_hash = hash_bytes(read_regular_text(path).encode("utf-8"))
            except (OSError, UnicodeError):
                result.record_failure(f"Failed to read {rel_path}")
                continue

            skills.append(
                SkillPackageComponent(
                    bom_ref=f"skill:{rel_path}",
                    name=rel_path,
                    skill_type="skill",
                    hashes={"sha256": content_hash},
                    source_path=rel_path,
                    trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                )
            )
        return skills
