"""RAG / vector store / knowledge base scanner.

Discovers RAG pipeline configurations from common frameworks:
  - LangChain/LangGraph config files
  - LlamaIndex settings
  - Custom RAG configuration files
  - Vector store connection strings in environment/config
"""

from __future__ import annotations

import os
import re
from importlib import import_module
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.models import RAGSourceComponent, RiskAssessment
from nexus_symbiote.scanners.base import (
    Scanner,
    ScanResult,
    matched_exclusion,
    read_regular_text,
    relative_posix,
    sanitized_origin,
)

RAG_CONFIG_PATTERNS = [
    "rag_config.json",
    "rag_config.yaml",
    "rag_config.yml",
    "retrieval_config.json",
    "vector_store_config.json",
    "knowledge_base.json",
    "kb_config.json",
]

VECTOR_STORE_PATTERNS = [
    re.compile(
        r"(?:PINECONE|WEAVIATE|QDRANT|CHROMA|MILVUS|PGVECTOR)_(?:URL|HOST|API_KEY|INDEX)", re.I
    ),
    re.compile(r"VECTOR_(?:STORE|DB)_", re.I),
    re.compile(r"EMBEDDING_(?:MODEL|API)", re.I),
]


class RAGScanner(Scanner):
    name = "rag"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        configs, sources = self._walk(project_root, result)

        components: list[RAGSourceComponent] = []
        for config_path in configs:
            result.surfaces_scanned.append(relative_posix(config_path, project_root))
            components.extend(self._scan_rag_config(config_path, project_root, result))
        if not configs and not result.surfaces_excluded:
            result.record_absent("rag-config", RAG_CONFIG_PATTERNS)

        components.extend(self._scan_env_files(project_root, result))
        components.extend(self._scan_python_imports(sources, project_root, result))
        _make_refs_unique(components)
        result.components.extend(components)
        return result

    def _walk(self, root: Path, result: ScanResult) -> tuple[list[Path], list[Path]]:
        """Collect RAG config files and Python sources in sorted order.

        Excluded content is never read. Each excluded root that holds relevant content is
        recorded once, so a large excluded tree does not flood the coverage record.
        """
        configs: list[Path] = []
        sources: list[Path] = []
        excluded_roots: set[str] = set()

        def on_error(error: OSError) -> None:
            location = relative_posix(Path(error.filename), root) if error.filename else "."
            result.record_failure(f"Failed to read directory {location}")

        for folder, dirnames, filenames in os.walk(root, onerror=on_error):
            dirnames.sort()
            for name in sorted(filenames):
                if name not in RAG_CONFIG_PATTERNS and not name.endswith(".py"):
                    continue
                path = Path(folder) / name
                blocked = _excluded_root(path, root, self.exclude_paths)
                if blocked is not None:
                    excluded_roots.add(relative_posix(blocked, root))
                elif name in RAG_CONFIG_PATTERNS:
                    configs.append(path)
                else:
                    sources.append(path)

        for rel in sorted(excluded_roots):
            result.record_excluded(rel, "excluded by policy")
        return configs, sources

    def _scan_rag_config(
        self, config_path: Path, root: Path, result: ScanResult
    ) -> list[RAGSourceComponent]:
        rel = relative_posix(config_path, root)
        if config_path.suffix.lower() in (".yaml", ".yml"):
            try:
                yaml = import_module("yaml")
            except ImportError:
                result.record_failure(f"YAML support unavailable for {rel}")
                return []
            try:
                data = yaml.safe_load(read_regular_text(config_path))
            except (yaml.YAMLError, OSError, UnicodeError):
                result.record_failure(f"Failed to parse {rel}")
                return []
        else:
            data = self._safe_read_json(config_path)
        if not isinstance(data, dict):
            result.record_failure(f"Failed to parse object from {rel}")
            return []

        raw_sources: Any = data.get("sources", data.get("knowledge_bases", [data]))
        if isinstance(raw_sources, dict):
            raw_sources = [raw_sources]
        if not isinstance(raw_sources, list):
            result.record_failure(f"'sources' in {rel} is not a list or object")
            return []

        components: list[RAGSourceComponent] = []
        for index, source in enumerate(raw_sources):
            if not isinstance(source, dict):
                result.record_failure(f"RAG source {index} in {rel} is not an object")
                continue
            components.append(self._source_component(source, index, rel, result))
        return components

    def _source_component(
        self, source: dict[str, Any], index: int, rel: str, result: ScanResult
    ) -> RAGSourceComponent:
        name = _as_text(source.get("name"), "name", rel, result) or f"rag-source-{index}"
        corpus_type = (
            _as_text(source.get("type", source.get("store_type")), "type", rel, result)
            or "unknown"
        )
        embeddings = source.get("embeddings")
        nested_model: object = None
        if isinstance(embeddings, dict):
            nested_model = embeddings.get("model")
        elif embeddings is not None:
            result.record_failure(f"'embeddings' in {rel} is not an object")
        embedding = _as_text(
            source.get("embedding_model", nested_model), "embedding_model", rel, result
        )
        chunking = source.get("chunking_strategy", source.get("chunk_size"))

        raw_uris: object = source.get("source_uris", source.get("documents", []))
        uris: list[Any]
        if isinstance(raw_uris, str):
            uris = [raw_uris]
        elif isinstance(raw_uris, list):
            uris = raw_uris
        else:
            uris = []
            if raw_uris is not None:
                result.record_failure(f"'source_uris' in {rel} is not a string or list")

        risks: list[RiskAssessment] = []
        for uri in uris:
            if isinstance(uri, str) and any(
                scheme in uri.lower() for scheme in ("http://", "ftp://")
            ):
                risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.HIGH,
                        category="data_integrity",
                        detail=f"RAG source '{name}' ingests from unencrypted URI: {sanitized_origin(uri)}",
                        recommendation="Use HTTPS for all data source connections.",
                    )
                )

        if not source.get("sanitization") and not source.get("content_filter"):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="data_integrity",
                    detail=f"RAG source '{name}' has no configured content sanitization.",
                    recommendation="Add input sanitization to prevent indirect prompt injection via ingested documents.",
                )
            )

        return RAGSourceComponent(
            bom_ref=f"rag:{name}",
            name=name,
            corpus_type=corpus_type,
            embedding_model_name=embedding,
            chunking_strategy=str(chunking) if chunking else None,
            source_uris=[sanitized_origin(str(u)) for u in uris if u],
            trust_tier=TrustTier.UNKNOWN,
            risks=risks,
        )

    def _scan_env_files(self, project_root: Path, result: ScanResult) -> list[RAGSourceComponent]:
        components: list[RAGSourceComponent] = []
        env_files = [".env", ".env.example", ".env.local"]

        for env_name in env_files:
            env_path = project_root / env_name
            if not (env_path.exists() or env_path.is_symlink()):
                continue

            try:
                content = read_regular_text(env_path)
            except (OSError, UnicodeError):
                result.record_failure(f"Failed to read {env_name}")
                continue

            detected_stores: set[str] = set()
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for pattern in VECTOR_STORE_PATTERNS:
                    if pattern.search(line):
                        key = line.split("=", 1)[0].strip()
                        store_name = key.split("_")[0].lower()
                        detected_stores.add(store_name)

            for store in sorted(detected_stores):
                components.append(
                    RAGSourceComponent(
                        bom_ref=f"rag:env-{store}:{env_name}",
                        name=f"{store} (from env)",
                        corpus_type="vector-store",
                        trust_tier=TrustTier.UNKNOWN,
                        source_path=env_name,
                        risks=[
                            RiskAssessment(
                                severity=RiskSeverity.INFO,
                                category="rag_discovery",
                                detail=f"Vector store '{store}' detected from environment variables.",
                                recommendation="Document this data source in your AIBOM with explicit provenance.",
                            )
                        ],
                    )
                )

        return components

    def _scan_python_imports(
        self, sources: list[Path], project_root: Path, result: ScanResult
    ) -> list[RAGSourceComponent]:
        store_imports = {
            "chromadb": "chroma",
            "pinecone": "pinecone",
            "qdrant_client": "qdrant",
            "weaviate": "weaviate",
            "pymilvus": "milvus",
            "pgvector": "pgvector",
            "faiss": "faiss",
            "lancedb": "lancedb",
        }
        detected: set[str] = set()

        for py_file in sources:
            try:
                content = read_regular_text(py_file)
            except (OSError, UnicodeError):
                result.record_failure(f"Failed to read {relative_posix(py_file, project_root)}")
                continue

            for import_name, store_name in store_imports.items():
                if f"import {import_name}" in content or f"from {import_name}" in content:
                    detected.add(store_name)

        components: list[RAGSourceComponent] = []
        for store in sorted(detected):
            components.append(
                RAGSourceComponent(
                    bom_ref=f"rag:import-{store}",
                    name=f"{store} (from imports)",
                    corpus_type="vector-store",
                    trust_tier=TrustTier.UNKNOWN,
                    risks=[
                        RiskAssessment(
                            severity=RiskSeverity.INFO,
                            category="rag_discovery",
                            detail=f"Vector store library '{store}' imported in Python code.",
                            recommendation="Add explicit RAG source configuration to your AIBOM.",
                        )
                    ],
                )
            )

        return components


def _as_text(value: object, label: str, rel: str, result: ScanResult) -> str | None:
    if value is None or isinstance(value, str):
        return value
    result.record_failure(f"'{label}' in {rel} is not a string; ignored")
    return None


def _excluded_root(path: Path, root: Path, patterns: tuple[str, ...]) -> Path | None:
    """Return the shallowest directory, or the file itself, that a policy pattern excludes."""
    parts = path.relative_to(root).parts
    for depth in range(1, len(parts) + 1):
        candidate = root.joinpath(*parts[:depth])
        if matched_exclusion(candidate, root, patterns):
            return candidate
    return None


def _make_refs_unique(components: list[RAGSourceComponent]) -> None:
    """Suffix repeated references so one scan never emits duplicate bom_refs."""
    seen: set[str] = set()
    for component in components:
        base = component.bom_ref
        ref = base
        suffix = 2
        while ref in seen:
            ref = f"{base}#{suffix}"
            suffix += 1
        seen.add(ref)
        component.bom_ref = ref
