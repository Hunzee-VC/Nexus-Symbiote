"""Registry trust scanner.

Analyzes package manager lock files and dependency manifests to identify
AI/agent-related dependencies and assess registry trust:
  - npm/yarn/pnpm lock files for MCP packages
  - pip/poetry/uv lock files for ML dependencies
  - Docker images for model serving
"""

from __future__ import annotations

import re
from pathlib import Path

from symbote.core.enums import RiskSeverity, TrustTier
from symbote.core.models import RegistryEntryComponent, RiskAssessment
from symbote.scanners.base import Scanner, ScanResult

AI_PACKAGE_PATTERNS = [
    re.compile(r"(?:^|/)@modelcontextprotocol/", re.I),
    re.compile(r"(?:^|/)mcp[-_]", re.I),
    re.compile(r"(?:^|/)(?:langchain|llama[-_]index|crewai|autogen|openai|anthropic|cohere)", re.I),
    re.compile(r"(?:^|/)(?:transformers|torch|tensorflow|safetensors|tokenizers)", re.I),
    re.compile(r"(?:^|/)(?:chromadb|pinecone|qdrant|weaviate|pgvector|faiss)", re.I),
    re.compile(r"(?:^|/)(?:guardrails|nemo[-_]guardrails|rebuff)", re.I),
]


class RegistryScanner(Scanner):
    name = "registry"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        npm_comps = self._scan_npm(project_root, result)
        result.components.extend(npm_comps)

        pip_comps = self._scan_pip(project_root, result)
        result.components.extend(pip_comps)

        docker_comps = self._scan_docker(project_root, result)
        result.components.extend(docker_comps)

        if not result.components:
            result.surfaces_excluded.append("registry (no AI-related dependencies found)")

        return result

    def _scan_npm(self, root: Path, result: ScanResult) -> list[RegistryEntryComponent]:
        components: list[RegistryEntryComponent] = []
        pkg_path = root / "package.json"
        if not pkg_path.exists():
            return components

        result.surfaces_scanned.append(str(pkg_path))
        data = self._safe_read_json(pkg_path)
        if not isinstance(data, dict):
            return components

        all_deps: dict[str, str] = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(key, {})
            if isinstance(deps, dict):
                all_deps.update(deps)

        for pkg_name, version_spec in all_deps.items():
            if not self._is_ai_package(pkg_name):
                continue

            pinned = bool(re.match(r"^\d+\.\d+\.\d+$", version_spec))
            risks: list[RiskAssessment] = []

            if not pinned:
                risks.append(RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="version_pinning",
                    detail=f"npm package '{pkg_name}' uses range '{version_spec}' instead of exact pin.",
                    recommendation="Pin to exact version in package.json and verify integrity via lockfile.",
                ))

            components.append(RegistryEntryComponent(
                bom_ref=f"registry:npm/{pkg_name}",
                name=pkg_name,
                version=version_spec,
                registry_type="npm",
                registry_uri="https://registry.npmjs.org",
                trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                risks=risks,
            ))

        return components

    def _scan_pip(self, root: Path, result: ScanResult) -> list[RegistryEntryComponent]:
        components: list[RegistryEntryComponent] = []

        for req_file in ["requirements.txt", "requirements-dev.txt", "requirements-ml.txt"]:
            req_path = root / req_file
            if not req_path.exists():
                continue
            result.surfaces_scanned.append(str(req_path))
            try:
                lines = req_path.read_text(encoding="utf-8").splitlines()
            except OSError:
                result.scan_failures.append(f"Failed to read {req_path}")
                continue

            for line in lines:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([><=!~]+\s*[\d.]+(?:\s*,\s*[><=!~]+\s*[\d.]+)*)?", line)
                if not match:
                    continue
                pkg_name = match.group(1)
                version_spec = match.group(2) or ""
                if not self._is_ai_package(pkg_name):
                    continue

                pinned = bool(re.match(r"==\d+\.\d+", version_spec.strip()))
                risks: list[RiskAssessment] = []
                if not pinned:
                    risks.append(RiskAssessment(
                        severity=RiskSeverity.MEDIUM,
                        category="version_pinning",
                        detail=f"PyPI package '{pkg_name}' not pinned to exact version: '{version_spec}'",
                        recommendation="Pin to exact version with hash checking (pip --require-hashes).",
                    ))

                components.append(RegistryEntryComponent(
                    bom_ref=f"registry:pypi/{pkg_name}",
                    name=pkg_name,
                    version=version_spec.strip() if version_spec else None,
                    registry_type="pypi",
                    registry_uri="https://pypi.org",
                    trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                    risks=risks,
                ))

        pyproject = root / "pyproject.toml"
        if pyproject.exists():
            result.surfaces_scanned.append(str(pyproject))
            try:
                content = pyproject.read_text(encoding="utf-8")
                deps_section = re.findall(r'^\s*"?([a-zA-Z0-9_.-]+)"?\s*[><=!~]', content, re.M)
                for pkg_name in deps_section:
                    if self._is_ai_package(pkg_name):
                        if not any(c.name == pkg_name for c in components):
                            components.append(RegistryEntryComponent(
                                bom_ref=f"registry:pypi/{pkg_name}",
                                name=pkg_name,
                                registry_type="pypi",
                                registry_uri="https://pypi.org",
                                trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                            ))
            except OSError:
                pass

        return components

    def _scan_docker(self, root: Path, result: ScanResult) -> list[RegistryEntryComponent]:
        components: list[RegistryEntryComponent] = []

        for dockerfile_name in ["Dockerfile", "Dockerfile.agent", "docker-compose.yml", "docker-compose.yaml"]:
            path = root / dockerfile_name
            if not path.exists():
                continue
            result.surfaces_scanned.append(str(path))
            try:
                content = path.read_text(encoding="utf-8")
            except OSError:
                continue

            from_images = re.findall(r"(?:FROM|image:\s*)\s*([^\s]+)", content)
            for image in from_images:
                if any(kw in image.lower() for kw in ("vllm", "ollama", "triton", "tgi", "llama", "model")):
                    has_tag = ":" in image and not image.endswith(":latest")
                    risks: list[RiskAssessment] = []
                    if not has_tag:
                        risks.append(RiskAssessment(
                            severity=RiskSeverity.HIGH,
                            category="version_pinning",
                            detail=f"Docker image '{image}' is not pinned to a specific tag/digest.",
                            recommendation="Pin to a SHA256 digest for reproducible builds.",
                        ))

                    components.append(RegistryEntryComponent(
                        bom_ref=f"registry:docker/{image}",
                        name=image,
                        registry_type="docker-hub",
                        trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                        risks=risks,
                    ))

        return components

    def _is_ai_package(self, name: str) -> bool:
        return any(p.search(name) for p in AI_PACKAGE_PATTERNS)
