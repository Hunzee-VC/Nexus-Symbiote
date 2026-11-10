"""Offline, bounded collection of declared RAG configuration and imports.

Configuration and import references are discovery evidence. They do not establish
that a store is deployed, reachable, authorized, or resistant to poisoning.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import hash_canonical
from nexus_symbiote.core.models import RAGSourceComponent, RiskAssessment
from nexus_symbiote.scanners.base import Scanner, ScanResult, parse_python
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV
from nexus_symbiote.scanners.source_binding import (
    ORIGIN_PATHS,
    BindingError,
    beyond_origin,
    url_shape,
    value_binding,
)
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import redact_text, redact_url
from nexus_symbiote.utils.terminal import neutralize

RAG_CONFIG_PATTERNS = {
    "rag_config.json",
    "rag_config.yaml",
    "rag_config.yml",
    "retrieval_config.json",
    "vector_store_config.json",
    "knowledge_base.json",
    "kb_config.json",
}
# This name also suits a knowledge base's data, so such a file is a configuration only
# when it declares sources or a recognised source field.
_DATA_NAMES = frozenset({"knowledge_base.json"})
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
_IMPORT_MARKERS = tuple(name.encode() for name in STORE_IMPORTS)
ENV_FILES = {".env", ".env.example", ".env.local"}
SOURCE_STRUCTURE_PROFILE = "nexus-symbiote/rag-source-structure/v1"
SOURCE_VALUE_BINDING_PROFILE = "nexus-symbiote/rag-source-values/v1"
_SOURCE_FIELDS = frozenset(
    {
        "source_uris",
        "documents",
        "embedding_model",
        "embeddings",
        "chunking_strategy",
        "chunk_size",
        "store_type",
        "vector_store",
        "index_name",
        "collection",
        "collection_name",
        "namespace",
        "sanitization",
        "content_filter",
    }
)
# Fields whose values the record exports or digests; others are bound only by the key.
_EXPORTED_FIELDS = _SOURCE_FIELDS | {"name", "type"}
_IDENTITY_FIELDS = ("index_name", "collection", "collection_name", "namespace")
_CONTROLS = ("sanitization", "content_filter")
_MAX_ENTRIES = 1000
_MAX_NAME = 256
_MAX_URI = 4096
_MAX_PYTHON_CHARACTERS = 262_144
# Identifiers such as store types, embedding models and collection names; anything
# else may be a locator with credentials and is exported only as a redaction marker.
_IDENTIFIER = re.compile(r"[A-Za-z0-9_@][A-Za-z0-9_.:/+ ()-]{0,255}")
_PLAIN_PATH = re.compile(r"[A-Za-z0-9_.~/-]{1,4096}")
_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.-]{0,31}):")
_TOKEN_SHAPE = re.compile(
    r"(?<![\w-])(?:eyJ[\w-]{8,}\.[\w-]{8,}"
    r"|(?:gh[oprsu]_|github_pat_|glpat-|xox[abeoprs]-|sk-|[rs]k_live_|AKIA|ASIA|AIza)"
    r"[\w-]{12,})"
)
# Transports that show encryption or never leave the host.
_PROTECTED_SCHEMES = frozenset(
    {
        "https",
        "wss",
        "s3",
        "s3a",
        "gs",
        "gcs",
        "az",
        "azure",
        "abfss",
        "wasbs",
        "hf",
        "rediss",
        "sftp",
        "ssh",
        "git+ssh",
        "git+https",
        "file",
    }
)
_CLEAR_TEXT_SCHEMES = frozenset(
    {"http", "ftp", "ws", "redis", "git", "git+http", "telnet", "ldap", "mqtt", "amqp"}
)
_REDACTED = "[redacted]"
_CONNECTION_STRING = "[redacted-connection-string]"


class _SourceError(ValueError):
    """A RAG source declaration this collector cannot record; the text names the field."""


def _identifier(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise _SourceError(f"invalid RAG source {field}")
    text = str(value).strip()
    if "://" in text or _TOKEN_SHAPE.search(text) or not _IDENTIFIER.fullmatch(text):
        return _REDACTED
    return text


def _exported_uri(raw: str) -> tuple[str, bool]:
    """Export a source locator without credentials; say whether part of it is unbound.

    A URL keeps only its scheme, host and port; a plain path is exported as written;
    anything else, such as a key=value connection string or user:secret@host, is
    replaced by a redaction marker.
    """
    value = raw.strip()
    if _SCHEME.match(value) and "://" in value:
        try:
            # WHATWG parsers end the host at a backslash; urlsplit does not.
            odd = "\\" in urlsplit(value).netloc
        except ValueError:
            odd = True
        exported = "[redacted-url]" if odd else redact_url(value)
        return exported, exported == "[redacted-url]" or beyond_origin(value, ORIGIN_PATHS)
    if "=" in value and (";" in value or value.split("=", 1)[0].strip().isidentifier()):
        return _CONNECTION_STRING, True
    if _PLAIN_PATH.fullmatch(value) and not _TOKEN_SHAPE.search(value):
        return value, False
    return _REDACTED, True


def _scheme(raw: str) -> str | None:
    match = _SCHEME.match(raw.strip())
    return match.group(1).lower() if match and "://" in raw else None


def _control(value: Any) -> str:
    """Only a boolean, or an object whose ``enabled`` is a boolean, states a control."""
    if value is None:
        return "absent"
    if isinstance(value, dict) and isinstance(value.get("enabled"), bool):
        value = value["enabled"]
    if isinstance(value, bool):
        return "enabled" if value else "disabled"
    return "unrecognized"


def _named_list(data: dict[str, Any], key: str) -> list[Any]:
    value = data.get(key)
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if not isinstance(value, list):
        raise _SourceError(f"invalid RAG {key} list")
    return value


class RAGScanner(Scanner):
    name = "rag"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        python_sources: list[Path] = []
        with self._collection(project_root, result) as files:
            for path in files.iter_files():
                if path.name in RAG_CONFIG_PATTERNS:
                    result.components.extend(self._scan_rag_config(path, files, result))
                elif path.name in ENV_FILES and len(path.parts) == 1:
                    raw = files.read_bytes(path)
                    if raw is not None:
                        # Only ASCII key names are read; values are never decoded or kept.
                        content = raw.decode("utf-8", errors="replace")
                        result.surfaces_scanned.append(path.as_posix())
                        result.components.extend(self._scan_env(content, path))
                elif path.suffix == ".py":
                    python_sources.append(path)
            result.components.extend(self._scan_imports(files.root, python_sources))
        result.surfaces_scanned.append("rag: Python vector-store imports (heuristic)")
        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("rag (no RAG configuration found)")
        return result

    def _scan_imports(self, root: Path, sources: list[Path]) -> list[RAGSourceComponent]:
        """Name vector stores imported by Python source; nothing here is a coverage gap.

        Source is read under its own byte budget and its failures are not kept: a file
        that is too large, not UTF-8 or not parsable by this interpreter declares no RAG
        configuration, so it never fails the collector or the default gates.
        """
        detected: dict[str, str] = {}
        with ConfinedCollection(root, [], exclude_paths=self._exclude_paths) as heuristic:
            for path in sources:
                raw = heuristic.read_bytes(path)
                if raw is None or not any(marker in raw for marker in _IMPORT_MARKERS):
                    continue
                try:
                    content = raw.decode("utf-8")
                    if len(content) > _MAX_PYTHON_CHARACTERS:
                        continue
                    tree = parse_python(content)
                except (SyntaxError, ValueError):
                    continue
                for node in ast.walk(tree):
                    names = []
                    if isinstance(node, ast.Import):
                        names = [alias.name for alias in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                        names = [node.module]
                    for name in names:
                        store = STORE_IMPORTS.get(name.split(".", 1)[0])
                        if store is not None:
                            detected.setdefault(store, path.as_posix())
        return [
            RAGSourceComponent(
                bom_ref=f"rag:import-{store}",
                name=f"{store} (from imports)",
                corpus_type="vector-store",
                source_path=detected[store],
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
            for store in sorted(detected)
        ]

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
        except (yaml.YAMLError, TypeError, ValueError, RecursionError, OverflowError, IndexError):
            result.scan_failures.append(f"{path}: invalid YAML")
            return None

    def _scan_rag_config(
        self, path: Path, files: ConfinedCollection, result: ScanResult
    ) -> list[RAGSourceComponent]:
        relative = path.as_posix()
        data = self._read_config(path, files, result)
        if data is None:
            return []
        declared = isinstance(data, dict) and bool(
            ({"sources", "knowledge_bases"} | _SOURCE_FIELDS | {"type"}) & set(data)
        )
        if path.name in _DATA_NAMES and not declared:
            return []
        result.surfaces_scanned.append(relative)
        if not isinstance(data, dict):
            result.scan_failures.append(f"{relative}: expected a RAG configuration object")
            return []
        try:
            # Both list names are read, so neither can hide entries behind the other.
            if {"sources", "knowledge_bases"} & set(data):
                sources = _named_list(data, "sources") + _named_list(data, "knowledge_bases")
            else:
                sources = [data]
        except _SourceError as exc:
            result.scan_failures.append(f"{relative}: {exc}")
            return []
        if len(sources) > _MAX_ENTRIES:
            result.scan_failures.append(f"{relative}: invalid or oversized RAG source list")
            return []
        components: list[RAGSourceComponent] = []
        for index, source in enumerate(sources):
            if not isinstance(source, dict):
                result.scan_failures.append(f"{relative}: RAG source must be an object")
                continue
            try:
                components.append(self._source(relative, index, source))
            except BindingError as exc:
                result.scan_failures.append(f"{relative}: {exc}")
            except _SourceError as exc:
                result.scan_failures.append(f"{relative}: {exc}")
            except (TypeError, ValueError, RecursionError):
                result.scan_failures.append(f"{relative}: invalid RAG source field types")
        return components

    def _source(self, relative: str, index: int, source: dict[str, Any]) -> RAGSourceComponent:
        declared_name = source.get("name")
        if declared_name is None:
            name, bom_ref = f"rag-source-{index}", f"rag:{relative}#{index}"
        elif not isinstance(declared_name, str):
            raise _SourceError("invalid RAG source name")
        elif len(declared_name) > _MAX_NAME:
            raise _SourceError(f"RAG source name exceeds {_MAX_NAME} characters")
        else:
            name = redact_text(declared_name)
            bom_ref = f"rag:{name}"
        shown = neutralize(name)
        corpus_type = _identifier(source.get("type"), "type")
        store_type = _identifier(source.get("store_type"), "store_type")
        embeddings = source.get("embeddings")
        if embeddings is not None and not isinstance(embeddings, dict):
            raise _SourceError("invalid RAG source embeddings")
        embedding = _identifier(source.get("embedding_model"), "embedding_model")
        nested = _identifier((embeddings or {}).get("model"), "embeddings.model")
        if embedding is not None and nested is not None and embedding != nested:
            raise _SourceError("conflicting RAG embedding model declarations")
        embedding = embedding or nested
        strategy = _identifier(source.get("chunking_strategy"), "chunking_strategy")
        chunk_size = _identifier(source.get("chunk_size"), "chunk_size")
        identities = {
            field: value
            for field in _IDENTITY_FIELDS
            if (value := _identifier(source.get(field), field)) is not None
        }
        locators = source.get("source_uris")
        locators = [] if locators is None else locators
        if isinstance(locators, str):
            locators = [locators]
        if (
            not isinstance(locators, list)
            or len(locators) > _MAX_ENTRIES
            or not all(isinstance(uri, str) for uri in locators)
        ):
            raise _SourceError("invalid RAG source_uris")
        if any(len(uri) > _MAX_URI for uri in locators):
            raise _SourceError(f"RAG source URI exceeds {_MAX_URI} characters")
        exported = [_exported_uri(uri) for uri in locators]
        documents = source.get("documents")
        if isinstance(documents, str):
            documents = [documents]
        if documents is not None and not isinstance(documents, list):
            raise _SourceError("invalid RAG source documents")
        documents_hash = hash_canonical({"documents": documents}) if documents is not None else None
        controls = {control: _control(source.get(control)) for control in _CONTROLS}
        structure_hash = hash_canonical(
            {
                "profile": SOURCE_STRUCTURE_PROFILE,
                "structure": {
                    "fields": sorted(redact_text(str(key)) for key in source),
                    "name": name,
                    "type": corpus_type,
                    "store_type": store_type,
                    "embedding_model": embedding,
                    "chunking": [strategy, chunk_size],
                    "identities": identities,
                    "source_uris": [
                        {"export": value, "shape": url_shape(uri.strip(), ORIGIN_PATHS)}
                        for uri, (value, _) in zip(locators, exported, strict=True)
                    ],
                    "documents": documents_hash,
                    "controls": controls,
                },
            }
        )
        binding = value_binding(SOURCE_VALUE_BINDING_PROFILE, source)
        risks: list[RiskAssessment] = []
        # One finding per locator, as each one is a separate connection.
        for uri, (value, _) in zip(locators, exported, strict=True):
            scheme = _scheme(uri)
            if scheme in _CLEAR_TEXT_SCHEMES:
                risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.HIGH,
                        category="data_integrity",
                        detail=f"RAG source '{shown}' declares an unencrypted URI: {value}",
                        recommendation="Use authenticated encrypted transport for data connections.",
                    )
                )
            elif scheme is not None and scheme not in _PROTECTED_SCHEMES:
                risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.LOW,
                        category="transport_security",
                        detail=(
                            f"RAG source '{shown}' declares a URI whose transport is not shown "
                            f"to be encrypted: {value}"
                        ),
                        recommendation="Confirm that the connection is encrypted and authenticated.",
                    )
                )
        if "enabled" not in controls.values():
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="data_integrity",
                    detail=f"RAG source '{shown}' has no declared content filtering control.",
                    recommendation=(
                        "Declare sanitization or content_filter as true. Review ingestion "
                        "controls, retrieval ACLs and tool authority. Content filtering "
                        "does not establish prompt-injection immunity."
                    ),
                )
            )
        unbound = [
            label
            for label, gap in (
                ("source URIs beyond their exported origins", any(gap for _, gap in exported)),
                ("values of fields that are not exported", bool(set(source) - _EXPORTED_FIELDS)),
            )
            if gap
        ]
        if unbound and not binding:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=(
                        f"RAG source '{shown}' values not bound in this inventory: "
                        f"{'; '.join(unbound)}."
                    ),
                    recommendation=(
                        f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect changes "
                        "to these values."
                    ),
                )
            )
        properties: dict[str, Any] = {
            "collection_mode": "static-config",
            # URLs keep only their origin, plain paths are exported as written, and any
            # other locator, such as a connection string, only as a redaction marker.
            "source_credentials_omitted": True,
            "declared_controls": controls,
            "source_values_bound": bool(binding),
            "static_config_hash": structure_hash,
            "static_config_hash_profile": SOURCE_STRUCTURE_PROFILE,
            **binding,
        }
        if store_type is not None:
            properties["store_type"] = store_type
        if identities:
            properties["index_identities"] = identities
        if documents_hash is not None:
            properties["inline_documents_hash"] = documents_hash
        if strategy is not None and chunk_size is not None:
            properties["chunk_size"] = chunk_size
        component = RAGSourceComponent(
            bom_ref=bom_ref,
            name=name,
            corpus_type=corpus_type or store_type or "unknown",
            embedding_model_name=embedding,
            chunking_strategy=strategy or chunk_size,
            source_uris=[value for value, _ in exported],
            source_path=relative,
            trust_tier=TrustTier.UNKNOWN,
            risks=risks,
            properties=properties,
        )
        if documents is not None:
            # Set only when declared: a count observed at run time may enrich the record.
            component.document_count = len(documents)
        return component

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
                source_path=path.as_posix(),
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
