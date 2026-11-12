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
from nexus_symbiote.policy import read_sexagesimal_integers_as_text
from nexus_symbiote.scanners.base import (
    Scanner,
    ScanResult,
    SourceBudget,
    parse_python,
    source_collection_bytes,
)
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV
from nexus_symbiote.scanners.source_binding import (
    ORIGIN_PATHS,
    BindingError,
    beyond_origin,
    url_shape,
    value_binding,
)
from nexus_symbiote.utils.confined import ConfinedCollection, fold_name
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
_IDENTITY_FIELDS = ("index_name", "collection", "collection_name", "namespace")
_CONTROLS = ("sanitization", "content_filter")
# Fields read into the record. Any other field, such as vector_store, the members of
# embeddings other than model and those of a control object other than enabled, is
# digested by its names, flags and URL origins and shapes; its other values are bound
# only by the key.
_READ_FIELDS = frozenset(
    {
        "name",
        "type",
        "store_type",
        "embedding_model",
        "embeddings",
        "chunking_strategy",
        "chunk_size",
        "source_uris",
        "documents",
        *_IDENTITY_FIELDS,
        *_CONTROLS,
    }
)
_LIST_KEYS = ("sources", "knowledge_bases")
_FOLDED_CONFIG_NAMES = {fold_name(name): name for name in RAG_CONFIG_PATTERNS}
_MAX_ENTRIES = 1000
_MAX_DEPTH = 32
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


class _TooManyURLsError(_SourceError):
    """A configuration file declares more endpoint URLs than one file may describe."""


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


def _unread_control(value: Any) -> Any:
    """The part of a control declaration that ``_control`` does not read."""
    if isinstance(value, dict):
        return {k: v for k, v in value.items() if not (k == "enabled" and isinstance(v, bool))}
    return value


def _describe(value: Any, urls: list[str], depth: int = 0) -> tuple[Any, bool]:
    """A nested value as the unkeyed digest covers it, and whether it leaves values unbound.

    Names, booleans and nulls are kept, and URLs by their exported origin and their
    shape. ``urls`` collects the URLs of the whole file for the transport check, at most
    ``_MAX_ENTRIES``, since each may become a finding. Other text and numbers are kept
    only as their type, since the record does not export them.
    """
    if depth > _MAX_DEPTH:
        raise _SourceError("RAG configuration nested too deeply")
    if isinstance(value, dict | list) and len(value) > _MAX_ENTRIES:
        raise _SourceError("oversized RAG configuration value")
    if isinstance(value, dict):
        described: dict[str, Any] = {}
        unbound = False
        for key, item in value.items():
            name = redact_text(str(key))
            described[name], gap = _describe(item, urls, depth + 1)
            unbound |= gap or name != key
        return described, unbound
    if isinstance(value, list):
        items = [_describe(item, urls, depth + 1) for item in value]
        return [item for item, _ in items], any(gap for _, gap in items)
    if value is None or isinstance(value, bool):
        return value, False
    if isinstance(value, str) and _scheme(value) is not None:
        if len(value) > _MAX_URI:
            raise _SourceError(f"RAG configuration URL exceeds {_MAX_URI} characters")
        if len(urls) >= _MAX_ENTRIES:
            raise _TooManyURLsError(
                f"RAG configuration declares more than {_MAX_ENTRIES} endpoint URLs"
            )
        urls.append(value)
        exported, unbound = _exported_uri(value)
        return {"url": exported, "shape": url_shape(value.strip(), ORIGIN_PATHS)}, unbound
    return type(value).__name__, True


def _transport_risks(subject: str, urls: list[str], noun: str) -> list[RiskAssessment]:
    """One finding for each declared locator without a transport shown to be encrypted."""
    risks = []
    article = "an" if noun == "endpoint" else "a"
    for uri in urls:
        scheme = _scheme(uri)
        shown = neutralize(_exported_uri(uri)[0])
        if scheme in _CLEAR_TEXT_SCHEMES:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="data_integrity",
                    detail=f"{subject} declares an unencrypted {noun}: {shown}",
                    recommendation="Use authenticated encrypted transport for data connections.",
                )
            )
        elif scheme is not None and scheme not in _PROTECTED_SCHEMES:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="transport_security",
                    detail=(
                        f"{subject} declares {article} {noun} whose transport is not shown to "
                        f"be encrypted: {shown}"
                    ),
                    recommendation="Confirm that the connection is encrypted and authenticated.",
                )
            )
    return risks


def _unbound_risk(subject: str, unbound: list[str]) -> RiskAssessment:
    return RiskAssessment(
        severity=RiskSeverity.LOW,
        category="completeness",
        detail=f"{subject} values not bound in this inventory: {'; '.join(unbound)}.",
        recommendation=(
            f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect changes to these values."
        ),
    )


def _declares_rag(data: dict[str, Any]) -> bool:
    return bool({*_LIST_KEYS, *_SOURCE_FIELDS, "type"} & set(data))


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
                elif fold_name(path.name) in _FOLDED_CONFIG_NAMES:
                    self._config_variant(path, files, result)
                elif path.name in ENV_FILES and len(path.parts) == 1:
                    raw = files.read_bytes(path)
                    if raw is not None:
                        # Only ASCII key names are read; values are never decoded or kept.
                        content = raw.decode("utf-8", errors="replace")
                        result.surfaces_scanned.append(path.as_posix())
                        result.components.extend(self._scan_env(content, path))
                elif path.suffix == ".py":
                    python_sources.append(path)
            result.components.extend(self._scan_imports(files.root, python_sources, result))
        result.surfaces_scanned.append("rag: Python vector-store imports (heuristic)")
        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("rag (no RAG configuration found)")
        return result

    def _scan_imports(
        self, root: Path, sources: list[Path], result: ScanResult
    ) -> list[RAGSourceComponent]:
        """Name vector stores imported by Python source.

        The text read is bounded by the source budget, and running out of it is one
        named coverage gap. Files are read apart from the collection, whose failures are
        not kept: a file that is too large, not UTF-8 or not parsable by this interpreter
        declares no RAG configuration, so it never fails the collector or the default
        gates.
        """
        detected: dict[str, str] = {}
        budget = SourceBudget("rag vector-store imports", result)
        # The collection's own byte limit stays above the budget, which binds first.
        limit = source_collection_bytes()
        with ConfinedCollection(
            root, [], exclude_paths=self._exclude_paths, max_total_bytes=limit
        ) as heuristic:
            for path in sources:
                if budget.exhausted:
                    break
                raw = heuristic.read_bytes(path)
                if raw is None or not budget.admit(len(raw), path):
                    continue
                if not any(marker in raw for marker in _IMPORT_MARKERS):
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

    def _config_variant(self, path: Path, files: ConfinedCollection, result: ScanResult) -> None:
        """Record another spelling of a configuration name as a collection failure.

        Case-insensitive file systems open it in place of the configuration name. A data
        file spelled like a knowledge base is not a configuration, as for the exact name.
        """
        canonical = _FOLDED_CONFIG_NAMES[fold_name(path.name)]
        if canonical in _DATA_NAMES:
            data = self._read_config(path, files, result)
            if not (isinstance(data, dict) and _declares_rag(data)):
                return
        result.scan_failures.append(
            f"{path.as_posix()}: case variant of {path.with_name(canonical).as_posix()} is the "
            "active file on case-insensitive file systems and is not inventoried"
        )

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
            read_sexagesimal_integers_as_text(UniqueSafeLoader)
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
        declared = isinstance(data, dict) and _declares_rag(data)
        if path.name in _DATA_NAMES and not declared:
            return []
        result.surfaces_scanned.append(relative)
        if not isinstance(data, dict):
            result.scan_failures.append(f"{relative}: expected a RAG configuration object")
            return []
        # Every URL described in the file; the sources' own follow the shared fields' ones.
        urls: list[str] = []
        try:
            # Both list names are read, so neither can hide entries behind the other.
            if set(_LIST_KEYS) & set(data):
                sources = _named_list(data, "sources") + _named_list(data, "knowledge_bases")
                configuration = {k: v for k, v in data.items() if k not in _LIST_KEYS}
                if not sources and configuration:
                    # No source would carry these fields, so they are read as one.
                    sources, configuration = [configuration], {}
            else:
                sources, configuration = [data], {}
            described, configuration_unbound = _describe(configuration, urls)
            # Digested and bound once, so each source carries a fixed-size result.
            shared = (
                (
                    hash_canonical({"configuration": described}),
                    value_binding(SOURCE_VALUE_BINDING_PROFILE, {"configuration": configuration}),
                )
                if configuration
                else None
            )
        except (_SourceError, BindingError) as exc:
            result.scan_failures.append(f"{relative}: {exc}")
            return []
        except (TypeError, ValueError, RecursionError):
            result.scan_failures.append(f"{relative}: invalid RAG configuration field types")
            return []
        if len(sources) > _MAX_ENTRIES:
            result.scan_failures.append(f"{relative}: invalid or oversized RAG source list")
            return []
        configuration_urls = list(urls)
        # Computed once: every source of the file carries a copy.
        configuration_origins = sorted({_exported_uri(url)[0] for url in configuration_urls})
        components: list[RAGSourceComponent] = []
        target = files.link_target(path)
        for index, source in enumerate(sources):
            if not isinstance(source, dict):
                result.scan_failures.append(f"{relative}: RAG source must be an object")
                continue
            try:
                component = self._source(relative, index, source, shared, urls)
                if target is not None:
                    component.properties["symlink_target"] = target
                if configuration_origins:
                    component.properties["configuration_endpoint_origins"] = list(
                        configuration_origins
                    )
                components.append(component)
            except BindingError as exc:
                result.scan_failures.append(f"{relative}: {exc}")
            except _TooManyURLsError as exc:
                result.scan_failures.append(f"{relative}: {exc}")
                return []
            except _SourceError as exc:
                result.scan_failures.append(f"{relative}: {exc}")
            except (TypeError, ValueError, RecursionError):
                result.scan_failures.append(f"{relative}: invalid RAG source field types")
        if components:
            # Fields beside the source lists apply to every source; their findings are
            # recorded once, on the first source.
            subject = f"RAG configuration '{neutralize(relative)}'"
            first = components[0]
            first.risks.extend(_transport_risks(subject, configuration_urls, "endpoint"))
            if configuration_unbound and not first.properties["source_values_bound"]:
                first.risks.append(_unbound_risk(subject, ["fields beside the source lists"]))
        return components

    def _source(
        self,
        relative: str,
        index: int,
        source: dict[str, Any],
        shared: tuple[str, dict[str, str]] | None,
        file_urls: list[str],
    ) -> RAGSourceComponent:
        """One source's record.

        ``shared`` is the digest and binding of the fields beside the source lists, which
        apply to every source. ``file_urls`` collects the URLs described in the file.
        """
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
        first_url = len(file_urls)
        values, values_unbound = _describe(
            {
                "fields": {k: v for k, v in source.items() if k not in _READ_FIELDS},
                "embeddings": {k: v for k, v in (embeddings or {}).items() if k != "model"},
                "controls": {
                    control: _unread_control(source[control])
                    for control in _CONTROLS
                    if source.get(control) is not None and not isinstance(source[control], bool)
                },
            },
            file_urls,
        )
        urls = file_urls[first_url:]
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
                    "values": values,
                    "configuration": None if shared is None else shared[0],
                },
            }
        )
        configuration_binding = None if shared is None else shared[1].get("static_value_binding")
        binding = value_binding(
            SOURCE_VALUE_BINDING_PROFILE,
            {"configuration": configuration_binding, "source": source},
        )
        # One finding per locator, as each one is a separate connection.
        risks = _transport_risks(f"RAG source '{shown}'", locators, "URI")
        risks.extend(_transport_risks(f"RAG source '{shown}'", urls, "endpoint"))
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
        exported_identifiers = (corpus_type, store_type, embedding, strategy, chunk_size)
        redacted = (declared_name is not None and name != declared_name) or _REDACTED in (
            *exported_identifiers,
            *identities.values(),
        )
        unbound = [
            label
            for label, gap in (
                ("source URIs beyond their exported origins", any(gap for _, gap in exported)),
                ("values exported only as redaction markers", redacted),
                ("field values that the record does not export", values_unbound),
            )
            if gap
        ]
        if unbound and not binding:
            risks.append(_unbound_risk(f"RAG source '{shown}'", unbound))
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
        if urls:
            properties["endpoint_origins"] = sorted({_exported_uri(url)[0] for url in urls})
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
