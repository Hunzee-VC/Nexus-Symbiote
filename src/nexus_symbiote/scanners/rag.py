"""RAG / vector store / knowledge base scanner.

Discovers RAG pipeline configurations from common frameworks:
  - LangChain/LangGraph config files
  - LlamaIndex settings
  - Custom RAG configuration files
  - Vector store connection strings in environment/config
"""

from __future__ import annotations

import re
from importlib import import_module
from pathlib import Path

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.models import RAGSourceComponent, RiskAssessment
from nexus_symbiote.scanners.base import Scanner, ScanResult, read_regular_text, sanitized_origin

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

        for pattern in RAG_CONFIG_PATTERNS:
            for config_path in project_root.rglob(pattern):
                if ".git" in config_path.parts or "node_modules" in config_path.parts:
                    continue
                result.surfaces_scanned.append(str(config_path))
                comps = self._scan_rag_config(config_path, result)
                result.components.extend(comps)

        env_comps = self._scan_env_files(project_root, result)
        if env_comps:
            result.components.extend(env_comps)

        py_comps = self._scan_python_imports(project_root, result)
        if py_comps:
            result.components.extend(py_comps)

        if not result.components and not result.scan_failures:
            result.surfaces_excluded.append("rag (no RAG configuration found)")

        return result

    def _scan_rag_config(self, config_path: Path, result: ScanResult) -> list[RAGSourceComponent]:
        if config_path.suffix.lower() in (".yaml", ".yml"):
            try:
                yaml = import_module("yaml")
            except ImportError:
                result.scan_failures.append(f"YAML support unavailable for {config_path}")
                return []
            try:
                data = yaml.safe_load(read_regular_text(config_path))
            except (yaml.YAMLError, OSError, UnicodeError):
                result.scan_failures.append(f"Failed to parse {config_path}")
                return []
        else:
            data = self._safe_read_json(config_path)
        if not isinstance(data, dict):
            result.scan_failures.append(f"Failed to parse object from {config_path}")
            return []

        components: list[RAGSourceComponent] = []
        sources = data.get("sources", data.get("knowledge_bases", [data]))

        if isinstance(sources, dict):
            sources = [sources]
        if not isinstance(sources, list):
            return []

        for i, source in enumerate(sources):
            if not isinstance(source, dict):
                continue

            name = source.get("name", f"rag-source-{i}")
            corpus_type = source.get("type", source.get("store_type", "unknown"))
            embedding = source.get("embedding_model", source.get("embeddings", {}).get("model"))
            chunking = source.get("chunking_strategy", source.get("chunk_size"))

            risks: list[RiskAssessment] = []
            source_uris_raw = source.get("source_uris", source.get("documents", []))
            if isinstance(source_uris_raw, str):
                source_uris_list = [source_uris_raw]
            elif isinstance(source_uris_raw, list):
                source_uris_list = source_uris_raw
            else:
                source_uris_list = []

            for uri in source_uris_list:
                if isinstance(uri, str) and ("http://" in uri or "ftp://" in uri):
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

            components.append(
                RAGSourceComponent(
                    bom_ref=f"rag:{name}",
                    name=name,
                    corpus_type=corpus_type,
                    embedding_model_name=embedding,
                    chunking_strategy=str(chunking) if chunking else None,
                    source_uris=[sanitized_origin(str(u)) for u in source_uris_list if u],
                    trust_tier=TrustTier.UNKNOWN,
                    risks=risks,
                )
            )

        return components

    def _scan_env_files(self, project_root: Path, result: ScanResult) -> list[RAGSourceComponent]:
        components: list[RAGSourceComponent] = []
        env_files = [".env", ".env.example", ".env.local"]

        for env_name in env_files:
            env_path = project_root / env_name
            if not env_path.exists():
                continue

            try:
                content = read_regular_text(env_path)
            except (OSError, UnicodeError):
                result.scan_failures.append(f"Failed to read {env_path}")
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

            for store in detected_stores:
                components.append(
                    RAGSourceComponent(
                        bom_ref=f"rag:env-{store}",
                        name=f"{store} (from env)",
                        corpus_type="vector-store",
                        trust_tier=TrustTier.UNKNOWN,
                        source_path=str(env_path),
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
        self, project_root: Path, result: ScanResult
    ) -> list[RAGSourceComponent]:
        components: list[RAGSourceComponent] = []
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

        for py_file in project_root.rglob("*.py"):
            if (
                ".git" in py_file.parts
                or "node_modules" in py_file.parts
                or "__pycache__" in py_file.parts
            ):
                continue
            try:
                content = read_regular_text(py_file)
            except (OSError, UnicodeError):
                result.scan_failures.append(f"Failed to read {py_file}")
                continue

            for import_name, store_name in store_imports.items():
                if f"import {import_name}" in content or f"from {import_name}" in content:
                    detected.add(store_name)

        for store in detected:
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
