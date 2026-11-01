"""Offline, bounded collection of declared RAG configuration and imports.

Configuration and import references are discovery evidence. They do not establish
that a store is deployed, reachable, authorized, or resistant to poisoning.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.models import RAGSourceComponent, RiskAssessment
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import redact_text

RAG_CONFIG_PATTERNS = {
    "rag_config.json",
    "rag_config.yaml",
    "rag_config.yml",
    "retrieval_config.json",
    "vector_store_config.json",
    "knowledge_base.json",
    "kb_config.json",
}
STORE_IMPORTS = {
    "chromadb": "chroma",
    "pinecone": "pinecone",
    "qdrant_client": "qdrant",
    "weaviate": "weaviate",
    "pymilvus": "milvus",
    "pgvector": "pgvector",
    "faiss": "faiss",
    "lancedb": "lancedb",
}
ENV_FILES = {".env", ".env.example", ".env.local"}


class RAGScanner(Scanner):
    name = "rag"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        detected_imports: set[str] = set()
        with self._collection(project_root, result) as files:
            for path in files.iter_files():
                if path.name in RAG_CONFIG_PATTERNS:
                    result.surfaces_scanned.append(str(files.root / path))
                    result.components.extend(self._scan_rag_config(path, files, result))
                elif path.name in ENV_FILES and len(path.parts) == 1:
                    content = files.read_text(path)
                    if content is not None:
                        result.surfaces_scanned.append(str(files.root / path))
                        result.components.extend(self._scan_env(content, files.root / path))
                elif path.suffix == ".py":
                    content = files.read_text(path)
                    if content is None:
                        continue
                    result.surfaces_scanned.append(str(files.root / path))
                    if len(content) > 262_144:
                        result.scan_failures.append(f"{path}: Python syntax collection size limit")
                        continue
                    try:
                        tree = ast.parse(content)
                    except (SyntaxError, ValueError, RecursionError):
                        result.scan_failures.append(f"{path}: invalid Python syntax")
                        continue
                    for node in ast.walk(tree):
                        names = []
                        if isinstance(node, ast.Import):
                            names = [alias.name for alias in node.names]
                        elif isinstance(node, ast.ImportFrom) and node.module:
                            names = [node.module]
                        for name in names:
                            top_level = name.split(".", 1)[0]
                            if top_level in STORE_IMPORTS:
                                detected_imports.add(STORE_IMPORTS[top_level])
            for store in sorted(detected_imports):
                result.components.append(
                    RAGSourceComponent(
                        bom_ref=f"rag:import-{store}",
                        name=f"{store} (from imports)",
                        corpus_type="vector-store",
                        trust_tier=TrustTier.UNKNOWN,
                        properties={"collection_mode": "static-import-reference"},
                        risks=[
                            RiskAssessment(
                                severity=RiskSeverity.INFO,
                                category="rag_discovery",
                                detail=f"Vector store library '{store}' imported in Python code.",
                                recommendation="Document whether this reference is used by the deployment.",
                            )
                        ],
                    )
                )
        if not result.components and not result.scan_failures:
            result.surfaces_excluded.append("rag (no RAG configuration found)")
        return result

    def _read_config(self, path: Path, files: ConfinedCollection, result: ScanResult) -> Any:
        if path.suffix == ".json":
            return files.read_json(path)
        content = files.read_text(path)
        if content is None:
            return None
        try:
            import yaml
        except ImportError:
            result.scan_failures.append(f"{path}: YAML parser unavailable (install yaml extra)")
            return None
        try:
            # Anchors/aliases and tags are unnecessary for this static profile;
            # rejecting them avoids recursive or amplified configuration graphs.
            for index, token in enumerate(yaml.scan(content)):
                if index >= 20_000 or isinstance(
                    token, (yaml.AliasToken, yaml.AnchorToken, yaml.TagToken)
                ):
                    result.scan_failures.append(
                        f"{path}: YAML aliases, tags or token limit unsupported"
                    )
                    return None

            class UniqueSafeLoader(yaml.SafeLoader):
                pass

            def unique_mapping(loader: Any, node: Any) -> dict[Any, Any]:
                loader.flatten_mapping(node)
                mapping: dict[Any, Any] = {}
                for key, value in loader.construct_pairs(node, deep=True):
                    if key in mapping:
                        raise ValueError("duplicate YAML key")
                    mapping[key] = value
                return mapping

            UniqueSafeLoader.add_constructor(
                yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping
            )
            loader = UniqueSafeLoader(content)
            try:
                value = loader.get_single_data()
            finally:
                loader.dispose()
            if value is None:
                raise ValueError("empty YAML configuration")
            return value
        except (yaml.YAMLError, TypeError, ValueError, RecursionError):
            result.scan_failures.append(f"{path}: invalid YAML")
            return None

    def _scan_rag_config(
        self, path: Path, files: ConfinedCollection, result: ScanResult
    ) -> list[RAGSourceComponent]:
        data = self._read_config(path, files, result)
        if data is None:
            return []
        if not isinstance(data, dict):
            result.scan_failures.append(f"{path}: expected a RAG configuration object")
            return []
        sources = data.get("sources", data.get("knowledge_bases", [data]))
        if isinstance(sources, dict):
            sources = [sources]
        if not isinstance(sources, list) or len(sources) > 1000:
            result.scan_failures.append(f"{path}: invalid or oversized RAG source list")
            return []
        components: list[RAGSourceComponent] = []
        for index, source in enumerate(sources):
            if not isinstance(source, dict):
                result.scan_failures.append(f"{path}: RAG source must be an object")
                continue
            name = source.get("name", f"rag-source-{index}")
            corpus_type = source.get("type", source.get("store_type", "unknown"))
            embeddings = source.get("embeddings", {})
            embedding = source.get("embedding_model")
            if embedding is None and isinstance(embeddings, dict):
                embedding = embeddings.get("model")
            source_uris = source.get("source_uris", source.get("documents", []))
            if isinstance(source_uris, str):
                source_uris = [source_uris]
            if (
                not isinstance(name, str)
                or not isinstance(corpus_type, str)
                or (embedding is not None and not isinstance(embedding, str))
                or not isinstance(source_uris, list)
                or not all(isinstance(uri, str) for uri in source_uris)
            ):
                result.scan_failures.append(f"{path}: invalid RAG source field types")
                continue
            name = redact_text(name)
            uris = [redact_text(uri) for uri in source_uris]
            risks: list[RiskAssessment] = []
            for uri in uris:
                if uri.startswith(("http://", "ftp://")):
                    risks.append(
                        RiskAssessment(
                            severity=RiskSeverity.HIGH,
                            category="data_integrity",
                            detail=f"RAG source '{name}' declares an unencrypted URI: {uri}",
                            recommendation="Use authenticated encrypted transport for data connections.",
                        )
                    )
            if not source.get("sanitization") and not source.get("content_filter"):
                risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.MEDIUM,
                        category="data_integrity",
                        detail=f"RAG source '{name}' has no declared content filtering control.",
                        recommendation=(
                            "Review ingestion controls, retrieval ACLs and tool authority. "
                            "Content filtering does not establish prompt-injection immunity."
                        ),
                    )
                )
            chunking = source.get("chunking_strategy", source.get("chunk_size"))
            if chunking is not None and not isinstance(chunking, (str, int)):
                result.scan_failures.append(f"{path}: unsupported chunking declaration")
                continue
            components.append(
                RAGSourceComponent(
                    bom_ref=f"rag:{name}",
                    name=name,
                    corpus_type=corpus_type,
                    embedding_model_name=redact_text(embedding) if embedding else None,
                    chunking_strategy=redact_text(str(chunking)) if chunking else None,
                    source_uris=uris,
                    source_path=str(files.root / path),
                    trust_tier=TrustTier.UNKNOWN,
                    risks=risks,
                    properties={
                        "collection_mode": "static-config",
                        "source_credentials_omitted": True,
                    },
                )
            )
        return components

    def _scan_env(self, content: str, path: Path) -> list[RAGSourceComponent]:
        detected: set[str] = set()
        for line in content.splitlines():
            key, separator, _ = line.strip().partition("=")
            key = key.removeprefix("export ").strip()
            if not separator or not key.replace("_", "").isalnum():
                continue
            first = key.split("_", 1)[0].lower()
            if first in {
                "pinecone",
                "weaviate",
                "qdrant",
                "chroma",
                "milvus",
                "pgvector",
                "vector",
                "embedding",
            }:
                detected.add(first)
        return [
            RAGSourceComponent(
                bom_ref=f"rag:env-{store}",
                name=f"{store} (from env)",
                corpus_type="vector-store",
                trust_tier=TrustTier.UNKNOWN,
                source_path=str(path),
                properties={"collection_mode": "environment-key-reference"},
                risks=[
                    RiskAssessment(
                        severity=RiskSeverity.INFO,
                        category="rag_discovery",
                        detail=f"Vector store '{store}' referenced by environment variable names.",
                        recommendation="Document this reference and its deployment-specific provenance.",
                    )
                ],
            )
            for store in sorted(detected)
        ]
