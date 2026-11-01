"""Registry trust scanner.

Analyzes dependency manifests and container files to identify AI/agent-related
dependencies and assess registry trust:
  - package.json for npm MCP and agent packages
  - requirements*.txt and pyproject.toml for Python ML and agent packages
  - Dockerfiles and compose files for model-serving images
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.models import RegistryEntryComponent, RiskAssessment
from nexus_symbiote.scanners.base import Scanner, ScanResult, read_regular_text
from nexus_symbiote.scanners.mcp import (
    excluded_before_read,
    make_components_unique,
    parse_json_object,
    pinned_version,
)

REQUIREMENT_FILES = ("requirements.txt", "requirements-dev.txt", "requirements-ml.txt")
CONTAINER_FILES = ("Dockerfile", "Dockerfile.agent", "docker-compose.yml", "docker-compose.yaml")
MANIFEST_FILES = ("package.json", *REQUIREMENT_FILES, "pyproject.toml", *CONTAINER_FILES)

# Exact package names, after PEP 503 normalization, that are AI or agent libraries.
AI_PACKAGE_NAMES = frozenset(
    {
        "openai",
        "anthropic",
        "langchain",
        "langchain-core",
        "langgraph",
        "llama-index",
        "crewai",
        "autogen",
        "pyautogen",
        "mcp",
        "fastmcp",
        "litellm",
        "transformers",
        "torch",
        "tensorflow",
        "safetensors",
        "tokenizers",
        "sentence-transformers",
        "chromadb",
        "pinecone",
        "pinecone-client",
        "weaviate-client",
        "qdrant-client",
        "faiss-cpu",
        "ollama",
        "mistralai",
        "cohere",
        "google-generativeai",
        "vllm",
        "llama-cpp-python",
        "huggingface-hub",
        "semantic-kernel",
        "dspy-ai",
    }
)

# Name families that match by prefix, such as langchain-openai or torchvision.
AI_PACKAGE_PATTERNS = [
    re.compile(r"(?:^|/)@modelcontextprotocol/", re.I),
    re.compile(r"(?:^|/)mcp[-_]", re.I),
    re.compile(r"(?:^|/)(?:langchain|llama[-_]index|crewai|autogen|openai|anthropic|cohere)", re.I),
    re.compile(r"(?:^|/)(?:transformers|torch|tensorflow|safetensors|tokenizers)", re.I),
    re.compile(r"(?:^|/)(?:chromadb|pinecone|qdrant|weaviate|pgvector|faiss)", re.I),
    re.compile(r"(?:^|/)(?:guardrails|nemo[-_]guardrails|rebuff)", re.I),
]

DOCKER_AI_KEYWORDS = ("vllm", "ollama", "triton", "tgi", "llama", "model")

# None of these patterns has a nested quantifier, so each runs in linear time on untrusted input.
# The Dockerfile and compose patterns are also anchored to line starts.
_NAME_SEPARATORS = re.compile(r"[-_.]+")
_REQUIREMENT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_DOCKER_FROM = re.compile(r"^[ \t]*FROM[ \t]+(?:--\S+[ \t]+)*(\S+)", re.IGNORECASE | re.MULTILINE)
_COMPOSE_IMAGE = re.compile(r"^[ \t]*(?:-[ \t]+)?image:[ \t]*[\"']?([^\s\"'#]+)", re.MULTILINE)


class RegistryScanner(Scanner):
    name = "registry"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        present: list[str] = []
        present.extend(self._scan_npm(project_root, result))
        present.extend(self._scan_pip(project_root, result))
        present.extend(self._scan_docker(project_root, result))
        make_components_unique(result)

        if not present:
            result.record_absent("registry-trust", MANIFEST_FILES)
        elif not result.components and not result.scan_failures:
            result.record_absent("registry-trust AI dependencies", present)
        return result

    def _scan_npm(self, root: Path, result: ScanResult) -> list[str]:
        path = root / "package.json"
        if not (path.exists() or path.is_symlink()):
            return []
        surface = "registry-trust package.json"
        text = self._read_manifest(root, path, surface, result)
        if text is None:
            return ["package.json"]
        data = parse_json_object(text, surface, result)
        if data is None:
            return ["package.json"]

        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(section)
            if deps is None:
                continue
            if not isinstance(deps, dict):
                result.record_failure(f"{surface}: {section} is not an object; ignored")
                continue
            for pkg_name, version_spec in deps.items():
                if not self._is_ai_package(pkg_name):
                    continue
                if not isinstance(version_spec, str):
                    result.record_failure(
                        f"{surface}: {section} entry for an AI package is not a string; ignored"
                    )
                    continue
                shown = _display_spec(version_spec)
                risks: list[RiskAssessment] = []
                if pinned_version(version_spec) is None:
                    risks.append(
                        RiskAssessment(
                            severity=RiskSeverity.MEDIUM,
                            category="version_pinning",
                            detail=(
                                f"npm package '{pkg_name}' uses range '{shown}' instead of "
                                "exact pin."
                            ),
                            recommendation=(
                                "Pin to exact version in package.json and verify integrity via "
                                "lockfile."
                            ),
                        )
                    )
                result.components.append(
                    RegistryEntryComponent(
                        bom_ref=f"registry:npm/{pkg_name}",
                        name=pkg_name,
                        version=shown,
                        registry_type="npm",
                        registry_uri="https://registry.npmjs.org",
                        trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                        risks=risks,
                    )
                )
        return ["package.json"]

    def _scan_pip(self, root: Path, result: ScanResult) -> list[str]:
        present: list[str] = []
        for req_file in REQUIREMENT_FILES:
            path = root / req_file
            if not (path.exists() or path.is_symlink()):
                continue
            present.append(req_file)
            surface = f"registry-trust {req_file}"
            text = self._read_manifest(root, path, surface, result)
            if text is None:
                continue
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line or line.startswith(("#", "-")):
                    continue
                requirement = _split_requirement(line)
                if requirement is None:
                    continue
                name, spec = requirement
                if self._is_ai_package(name):
                    self._add_pip_entry(name, spec, False, result)

        pyproject = root / "pyproject.toml"
        if pyproject.exists() or pyproject.is_symlink():
            present.append("pyproject.toml")
            surface = "registry-trust pyproject.toml"
            text = self._read_manifest(root, pyproject, surface, result)
            if text is not None:
                self._scan_pyproject(text, surface, result)
        return present

    def _scan_pyproject(self, text: str, surface: str, result: ScanResult) -> None:
        try:
            document = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, RecursionError):
            result.record_failure(f"{surface}: malformed TOML")
            return
        for name, spec in _pyproject_requirements(document):
            if self._is_ai_package(name):
                self._add_pip_entry(name, spec, True, result)

    def _add_pip_entry(self, name: str, spec: str, from_pyproject: bool, result: ScanResult) -> None:
        shown = _display_spec(spec)
        risks: list[RiskAssessment] = []
        if pinned_version(spec) is None:
            if from_pyproject:
                risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.MEDIUM,
                        category="unpinned-ai-dependency",
                        detail=(
                            f"AI package '{name}' is declared in pyproject.toml without an "
                            f"exact == pin: '{shown}'"
                        ),
                        recommendation="Pin with == in pyproject.toml and verify hashes in the lock file.",
                    )
                )
            else:
                risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.MEDIUM,
                        category="version_pinning",
                        detail=f"PyPI package '{name}' not pinned to exact version: '{shown}'",
                        recommendation="Pin to exact version with hash checking (pip --require-hashes).",
                    )
                )
        result.components.append(
            RegistryEntryComponent(
                bom_ref=f"registry:pypi/{name}",
                name=name,
                version=shown or None,
                registry_type="pypi",
                registry_uri="https://pypi.org",
                trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                risks=risks,
            )
        )

    def _scan_docker(self, root: Path, result: ScanResult) -> list[str]:
        present: list[str] = []
        for file_name in CONTAINER_FILES:
            path = root / file_name
            if not (path.exists() or path.is_symlink()):
                continue
            present.append(file_name)
            surface = f"registry-trust {file_name}"
            text = self._read_manifest(root, path, surface, result)
            if text is None:
                continue
            pattern = _COMPOSE_IMAGE if file_name.startswith("docker-compose") else _DOCKER_FROM
            for match in pattern.finditer(text):
                image = match.group(1)
                if not any(keyword in image.lower() for keyword in DOCKER_AI_KEYWORDS):
                    continue
                risks: list[RiskAssessment] = []
                if not _docker_pinned(image):
                    risks.append(
                        RiskAssessment(
                            severity=RiskSeverity.HIGH,
                            category="version_pinning",
                            detail=f"Docker image '{image}' is not pinned to a specific tag/digest.",
                            recommendation="Pin to a SHA256 digest for reproducible builds.",
                        )
                    )
                result.components.append(
                    RegistryEntryComponent(
                        bom_ref=f"registry:docker/{image}",
                        name=image,
                        registry_type="docker-hub",
                        trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                        risks=risks,
                    )
                )
        return present

    def _read_manifest(
        self, root: Path, path: Path, surface: str, result: ScanResult
    ) -> str | None:
        """Read a manifest. A symbolic link or an unreadable manifest also fails the scan."""
        if path.is_symlink():
            result.record_failure(
                f"{surface}: symbolic link refused; its dependencies are not analyzed"
            )
        if excluded_before_read(path, root, self.exclude_paths, surface, result):
            return None
        try:
            text = read_regular_text(path)
        except OSError:
            result.record_excluded(surface, "unreadable or not a regular file; not followed")
            result.record_failure(f"{surface}: could not be read; its dependencies are not analyzed")
            return None
        except UnicodeError:
            result.record_failure(f"{surface}: not valid UTF-8 text")
            return None
        result.surfaces_scanned.append(surface)
        return text

    def _is_ai_package(self, name: str) -> bool:
        normalized = _NAME_SEPARATORS.sub("-", name.strip()).lower()
        return normalized in AI_PACKAGE_NAMES or any(
            p.search(normalized) for p in AI_PACKAGE_PATTERNS
        )


def _split_requirement(text: str) -> tuple[str, str] | None:
    """The PEP 508 name and version specifier. Extras, environment markers, and options are dropped."""
    stripped = text.strip()
    match = _REQUIREMENT_NAME.match(stripped)
    if match is None:
        return None
    rest = stripped[match.end() :].lstrip()
    if rest.startswith("["):
        close = rest.find("]")
        rest = rest[close + 1 :] if close != -1 else ""
    for separator in (";", " #", " --"):
        cut = rest.find(separator)
        if cut != -1:
            rest = rest[:cut]
    return match.group(0), rest.strip()


def _pep508_entries(value: object) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    entries: list[tuple[str, str]] = []
    for item in value:
        if isinstance(item, str):
            parsed = _split_requirement(item)
            if parsed is not None:
                entries.append(parsed)
    return entries


def _poetry_entries(value: object) -> list[tuple[str, str]]:
    if not isinstance(value, dict):
        return []
    entries: list[tuple[str, str]] = []
    for name, spec in value.items():
        if not isinstance(name, str) or name.lower() == "python":
            continue
        if isinstance(spec, dict):
            spec = spec.get("version")
        entries.append((name, spec if isinstance(spec, str) else ""))
    return entries


def _pyproject_requirements(document: dict[str, Any]) -> list[tuple[str, str]]:
    """Name and specifier for every declared dependency: PEP 621, PEP 735, and Poetry."""
    entries: list[tuple[str, str]] = []
    project = document.get("project")
    if isinstance(project, dict):
        entries.extend(_pep508_entries(project.get("dependencies")))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in optional.values():
                entries.extend(_pep508_entries(group))
    groups = document.get("dependency-groups")
    if isinstance(groups, dict):
        for group in groups.values():
            entries.extend(_pep508_entries(group))
    tool = document.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        entries.extend(_poetry_entries(poetry.get("dependencies")))
        entries.extend(_poetry_entries(poetry.get("dev-dependencies")))
        poetry_groups = poetry.get("group")
        if isinstance(poetry_groups, dict):
            for group in poetry_groups.values():
                if isinstance(group, dict):
                    entries.extend(_poetry_entries(group.get("dependencies")))
    return entries


def _display_spec(spec: str) -> str:
    """A specifier that is safe to store. A URL can carry credentials, so it is replaced."""
    return "[redacted-url]" if "://" in spec else spec


def _docker_pinned(image: str) -> bool:
    """A digest, or a tag that pins an exact version. A missing or floating tag is not pinned."""
    if "@sha256:" in image:
        return True
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return False
    tag = last.rsplit(":", 1)[1]
    if tag.startswith("v"):
        tag = tag[1:]
    return pinned_version(tag) is not None
