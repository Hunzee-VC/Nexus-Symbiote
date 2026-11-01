"""Offline registry references collected from bounded local manifests.

These declarations do not establish registry authenticity, resolved artifacts,
installed versions, or cryptographic verification.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.models import RegistryEntryComponent, RiskAssessment
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.utils.secrets import redact_text

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
        with self._collection(project_root, result) as files:
            result.components.extend(self._scan_npm(files.root, result))
            result.components.extend(self._scan_pip(files.root, result))
            result.components.extend(self._scan_docker(files.root, result))
        if not result.components and not result.scan_failures:
            result.surfaces_excluded.append("registry (no AI-related dependencies found)")
        return result

    def _read(self, path: Path, result: ScanResult) -> str | None:
        assert self._files is not None
        content = self._files.read_text(path, missing_ok=True)
        if content is not None:
            result.surfaces_scanned.append(str(path))
        return content

    def _scan_npm(self, root: Path, result: ScanResult) -> list[RegistryEntryComponent]:
        assert self._files is not None
        path = root / "package.json"
        data = self._files.read_json(path, missing_ok=True)
        if data is None:
            return []
        result.surfaces_scanned.append(str(path))
        if not isinstance(data, dict):
            result.scan_failures.append("package.json: expected an object")
            return []
        all_deps: dict[str, str] = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(key, {})
            if not isinstance(deps, dict) or not all(
                isinstance(value, str) for value in deps.values()
            ):
                result.scan_failures.append(f"package.json: invalid {key} map")
                continue
            all_deps.update(deps)
        components: list[RegistryEntryComponent] = []
        for raw_name, raw_spec in sorted(all_deps.items()):
            if not self._is_ai_package(raw_name):
                continue
            name, spec = redact_text(raw_name), redact_text(raw_spec)
            risks: list[RiskAssessment] = []
            if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?", raw_spec):
                risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.MEDIUM,
                        category="version_pinning",
                        detail=f"npm package '{name}' has a nonexact declared reference: {spec}",
                        recommendation="Resolve and verify an immutable artifact with lockfile integrity evidence.",
                    )
                )
            components.append(
                RegistryEntryComponent(
                    bom_ref=f"registry:npm/{name}",
                    name=name,
                    version=spec,
                    registry_type="npm",
                    registry_uri="https://registry.npmjs.org",
                    source_path=str(path),
                    trust_tier=TrustTier.UNKNOWN,
                    risks=risks,
                    properties={
                        "collection_mode": "manifest-reference",
                        "registry_origin_verified": False,
                    },
                )
            )
        return components

    def _pip_component(self, line: str, path: Path) -> RegistryEntryComponent | None:
        match = re.match(r"^([a-zA-Z0-9_.-]+)(?:\[[^\]]*\])?\s*(.*)$", line.strip())
        if not match or not self._is_ai_package(match.group(1)):
            return None
        name = match.group(1)
        raw_spec = match.group(2).split(";", 1)[0].split(" #", 1)[0].strip()
        spec = redact_text(raw_spec)
        pinned = bool(re.fullmatch(r"==\d+(?:\.\d+)+(?:[a-zA-Z0-9.+-]*)", raw_spec))
        risks = (
            []
            if pinned
            else [
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="version_pinning",
                    detail=f"PyPI package '{name}' has a nonexact declared reference: {spec}",
                    recommendation="Pin the version and verify artifact hashes (pip --require-hashes).",
                )
            ]
        )
        return RegistryEntryComponent(
            bom_ref=f"registry:pypi/{name}",
            name=name,
            version=spec or None,
            registry_type="pypi",
            registry_uri="https://pypi.org",
            source_path=str(path),
            trust_tier=TrustTier.UNKNOWN,
            risks=risks,
            properties={"collection_mode": "manifest-reference", "registry_origin_verified": False},
        )

    def _scan_pip(self, root: Path, result: ScanResult) -> list[RegistryEntryComponent]:
        components: list[RegistryEntryComponent] = []
        for filename in ("requirements.txt", "requirements-dev.txt", "requirements-ml.txt"):
            path = root / filename
            content = self._read(path, result)
            if content is None:
                continue
            for line in content.splitlines():
                if not line.strip() or line.lstrip().startswith(("#", "-")):
                    continue
                component = self._pip_component(line, path)
                if component:
                    components.append(component)
        path = root / "pyproject.toml"
        content = self._read(path, result)
        if content is None:
            return components
        try:
            data = tomllib.loads(content)
        except (tomllib.TOMLDecodeError, RecursionError):
            result.scan_failures.append("pyproject.toml: invalid TOML")
            return components
        declarations: list[str] = []
        project = data.get("project", {})
        if not isinstance(project, dict):
            result.scan_failures.append("pyproject.toml: invalid project table")
            return components
        deps = project.get("dependencies", [])
        if isinstance(deps, list) and all(isinstance(value, str) for value in deps):
            declarations.extend(deps)
        else:
            result.scan_failures.append("pyproject.toml: invalid project dependencies")
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for values in optional.values():
                if isinstance(values, list) and all(isinstance(value, str) for value in values):
                    declarations.extend(values)
                else:
                    result.scan_failures.append("pyproject.toml: invalid optional dependencies")
        tool = data.get("tool", {})
        poetry: Any = tool.get("poetry", {}) if isinstance(tool, dict) else {}
        poetry_deps = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
        if isinstance(poetry_deps, dict):
            for name, value in poetry_deps.items():
                if isinstance(value, str):
                    declarations.append(f"{name}{value}")
                elif isinstance(value, dict) and isinstance(value.get("version"), str):
                    declarations.append(f"{name}{value['version']}")
        for declaration in declarations:
            component = self._pip_component(declaration, path)
            if component and not any(item.name == component.name for item in components):
                components.append(component)
        return components

    def _scan_docker(self, root: Path, result: ScanResult) -> list[RegistryEntryComponent]:
        components: list[RegistryEntryComponent] = []
        for filename in (
            "Dockerfile",
            "Dockerfile.agent",
            "docker-compose.yml",
            "docker-compose.yaml",
        ):
            path = root / filename
            content = self._read(path, result)
            if content is None:
                continue
            for raw_image in re.findall(r"(?:FROM|image:\s*)\s*([^\s]+)", content):
                if not any(
                    word in raw_image.lower()
                    for word in ("vllm", "ollama", "triton", "tgi", "llama", "model")
                ):
                    continue
                image = redact_text(raw_image)
                has_digest = bool(re.search(r"@sha256:[0-9a-fA-F]{64}$", raw_image))
                has_tag = ":" in raw_image.rsplit("/", 1)[-1] and not raw_image.endswith(":latest")
                risks: list[RiskAssessment] = []
                if not has_digest:
                    risks.append(
                        RiskAssessment(
                            severity=RiskSeverity.MEDIUM if has_tag else RiskSeverity.HIGH,
                            category="mutable_image_tag" if has_tag else "version_pinning",
                            detail=f"Docker image '{image}' lacks an immutable digest pin.",
                            recommendation="Pin to a SHA256 artifact digest and verify its provenance.",
                        )
                    )
                components.append(
                    RegistryEntryComponent(
                        bom_ref=f"registry:docker/{image}",
                        name=image,
                        registry_type="docker-hub",
                        source_path=str(path),
                        trust_tier=TrustTier.UNKNOWN,
                        risks=risks,
                        properties={
                            "collection_mode": "manifest-reference",
                            "registry_origin_verified": False,
                        },
                    )
                )
        return components

    def _is_ai_package(self, name: str) -> bool:
        return any(pattern.search(name) for pattern in AI_PACKAGE_PATTERNS)
