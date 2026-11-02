"""``models-hosted`` collector: hosted model identifiers selected by configuration and code (``spec/collectors.md``).

Hosted models are chosen by strings scattered across an agent's repository: the agent manifest, coding-agent
settings, LLM gateway routes, ``.env`` files and literals in code. This collector finds them, attributes each
string to a provider and classifies it as a pinned snapshot, a floating alias or unknown with the rule table in
``symbiote.models_identity.hosted`` (``providers.yaml``). It never contacts a provider, so ``resolved_ref`` stays
``unknown`` until a live query fills it.

Safety rules: configuration is parsed (JSON/JSONC/YAML/TOML) and Python with ``ast`` (never imported or
executed); ``.env`` values are read only for model-selector keys and dropped when they look like a secret; base
URLs keep only their origin. A base URL set by repository configuration is recorded as an endpoint override:
it is how a cloned repository can redirect an agent's API traffic and keys (CVE-2025-59536, CVE-2026-21852).
"""

from __future__ import annotations

import ast
import re
import time
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from symbiote.collect._common import ReadOutcome, parse_structured, read_bounded
from symbiote.collect.base import BaseCollector, CollectContext, CollectionResult
from symbiote.model.common import Claim, Provenance, looks_like_secret
from symbiote.model.edges import Edge
from symbiote.model.entities import Model, Redaction
from symbiote.model.enums import AliasPinning, ClaimMethod, CollectorMode, EdgeType, ModelKind, Surface
from symbiote.model.ids import make_id
from symbiote.models_identity.hosted import (
    MAX_MODEL_REF,
    HostedRef,
    classify_model_ref,
    hosted_identity,
    load_providers,
    provider_for_endpoint,
)

__all__ = ["ModelsHostedCollector"]

Fmt = Literal["json", "jsonc", "toml", "yaml"]
Scope = Literal["project", "user"]

#: Python and JS/TS sources larger than this are skipped (recorded as truncated sources).
MAX_SOURCE_BYTES: Final = 1024 * 1024
#: At most this many code files are parsed per scan; the rest are reported as truncated coverage.
MAX_CODE_FILES: Final = 4000
#: Total bytes of code parsed per scan, and the share of the collector's time budget spent on code.
MAX_CODE_BYTES: Final = 64 * 1024 * 1024
CODE_TIME_SHARE: Final = 0.6

_MODEL_KWARGS: Final = frozenset(
    {
        "model",
        "model_id",
        "model_name",
        "modelId",
        "modelName",
        "deployment_name",
        "azure_deployment",
        "llm_model",
    }
)
_MODEL_NAME_RE: Final = re.compile(r"^(?:[A-Z0-9_]*_)?(?:MODEL|LLM)(?:_(?:NAME|ID|REF))?$")
_ENV_MODEL_KEY: Final = re.compile(
    r"^(?:[A-Z0-9_]*_)?MODEL(?:_(?:NAME|ID))?$|^[A-Z0-9_]*_DEPLOYMENT(?:_NAME)?$"
)
_ENV_LINE: Final = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]{0,127})\s*=(.*)$")
#: Longer .env lines are skipped: no model identifier is that long.
MAX_ENV_LINE: Final = 4096
_JS_MODEL: Final = re.compile(
    r"(?<![A-Za-z0-9_$])(?:model|modelId|modelName)\s*[:=]\s*[\"'`]([A-Za-z0-9~][A-Za-z0-9._:/@~*\[\]+-]{0,200})[\"'`]"
)
_TEST_PATH: Final = re.compile(r"(?:^|/)(?:tests?|__tests__|spec|fixtures?)/")
_CODE_SUFFIXES: Final = frozenset({".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"})
_ENV_NAMES: Final = re.compile(r"^\.env(?:\.[A-Za-z0-9_.-]+)?$")
_BASE_URL_ENV: Final = frozenset(
    {"ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE", "AZURE_OPENAI_ENDPOINT", "OLLAMA_HOST",
     "ANTHROPIC_BEDROCK_BASE_URL", "GOOGLE_GEMINI_BASE_URL", "LITELLM_BASE_URL"}
)  # fmt: skip
_IMPORT_HINTS: Final[Mapping[str, str]] = {
    "AzureOpenAI": "azure-openai",
    "AsyncAzureOpenAI": "azure-openai",
    "AzureChatOpenAI": "azure-openai",
    "AnthropicBedrock": "aws-bedrock",
    "AsyncAnthropicBedrock": "aws-bedrock",
    "AnthropicBedrockMantle": "aws-bedrock",
    "ChatBedrock": "aws-bedrock",
    "ChatBedrockConverse": "aws-bedrock",
    "AnthropicVertex": "google-vertex",
    "AsyncAnthropicVertex": "google-vertex",
    "ChatVertexAI": "google-vertex",
}
_MODULE_HINTS: Final[Mapping[str, str]] = {
    "anthropic": "anthropic",
    "claude_agent_sdk": "anthropic",
    "langchain_anthropic": "anthropic",
    "openai": "openai",
    "agents": "openai",
    "langchain_openai": "openai",
    "google.genai": "google-gemini",
    "google.generativeai": "google-gemini",
    "mistralai": "mistral",
    "cohere": "cohere",
    "xai_sdk": "xai",
    "ollama": "ollama",
    "huggingface_hub": "huggingface",
}


@dataclass(frozen=True, slots=True)
class _Spot:
    """Where a model string is selected in a structured config: a key path (``*`` = every list item/map value)."""

    path: tuple[str, ...]
    role: str
    provider_path: tuple[str, ...] | None = None
    endpoint_path: tuple[str, ...] | None = None
    provider_map: Mapping[str, str] | None = None


@dataclass(frozen=True, slots=True)
class _Source:
    name: str
    paths: tuple[str, ...]
    fmt: Fmt
    scope: Scope
    spots: tuple[_Spot, ...]
    context: str | None = None
    #: env-style map (key path) whose model-selector keys and base URLs are read like a ``.env`` file
    env_path: tuple[str, ...] | None = None
    gateway: str | None = None


_GOOSE_PROVIDERS: Final[Mapping[str, str]] = {
    "anthropic": "anthropic",
    "openai": "openai",
    "google": "google-gemini",
    "gcp_vertex_ai": "google-vertex",
    "aws_bedrock": "aws-bedrock",
    "azure_openai": "azure-openai",
    "ollama": "ollama",
    "openrouter": "openrouter",
    "xai": "xai",
}
_CONTINUE_PROVIDERS: Final[Mapping[str, str]] = {
    "anthropic": "anthropic",
    "openai": "openai",
    "gemini": "google-gemini",
    "vertexai": "google-vertex",
    "bedrock": "aws-bedrock",
    "azure": "azure-openai",
    "mistral": "mistral",
    "ollama": "ollama",
    "openrouter": "openrouter",
    "deepseek": "deepseek",
    "cohere": "cohere",
    "xAI": "xai",
    "huggingface-inference-api": "huggingface",
}
_MANIFEST_PROVIDERS: Final[Mapping[str, str]] = {
    "anthropic": "anthropic",
    "openai": "openai",
    "google": "google-gemini",
    "gemini": "google-gemini",
    "vertex": "google-vertex",
    "vertex-ai": "google-vertex",
    "bedrock": "aws-bedrock",
    "aws-bedrock": "aws-bedrock",
    "azure": "azure-openai",
    "azure-openai": "azure-openai",
    "mistral": "mistral",
    "cohere": "cohere",
    "xai": "xai",
    "deepseek": "deepseek",
    "openrouter": "openrouter",
    "ollama": "ollama",
    "huggingface": "huggingface",
}

SOURCES: Final[tuple[_Source, ...]] = (
    _Source(
        "agent-manifest",
        ("agent.yaml", "agent.yml", "symbiote.yaml", "symbiote.yml"),
        "yaml",
        "project",
        (
            _Spot(("models", "*", "requested_ref"), "agent-model", ("models", "*", "provider"), ("models", "*", "endpoint"), _MANIFEST_PROVIDERS),
            _Spot(("models", "*", "model"), "agent-model", ("models", "*", "provider"), ("models", "*", "endpoint"), _MANIFEST_PROVIDERS),
        ),
    ),
    _Source(
        "claude-code",
        (".claude/settings.json", ".claude/settings.local.json"),
        "json",
        "project",
        (_Spot(("model",), "client-default"),),
        context="claude-code",
        env_path=("env",),
    ),
    _Source("claude-code", ("~/.claude/settings.json",), "json", "user", (_Spot(("model",), "client-default"),), context="claude-code", env_path=("env",)),
    _Source(
        "codex",
        (".codex/config.toml", "~/.codex/config.toml"),
        "toml",
        "project",
        (
            _Spot(("model",), "client-default", ("model_provider",)),
            _Spot(("profiles", "*", "model"), "client-profile", ("profiles", "*", "model_provider")),
        ),
    ),
    _Source(
        "gemini-cli",
        (".gemini/settings.json", "~/.gemini/settings.json"),
        "jsonc",
        "project",
        (_Spot(("model", "name"), "client-default"), _Spot(("model",), "client-default")),
        context="gemini-cli",
    ),
    _Source(
        "opencode",
        ("opencode.json", "opencode.jsonc", "~/.config/opencode/opencode.json"),
        "jsonc",
        "project",
        (_Spot(("model",), "client-default"), _Spot(("small_model",), "client-small")),
    ),
    _Source(
        "goose",
        ("~/.config/goose/config.yaml",),
        "yaml",
        "user",
        (_Spot(("GOOSE_MODEL",), "client-default", ("GOOSE_PROVIDER",), None, _GOOSE_PROVIDERS),),
    ),
    _Source(
        "continue",
        (".continue/config.yaml", "~/.continue/config.yaml"),
        "yaml",
        "project",
        (_Spot(("models", "*", "model"), "client-model", ("models", "*", "provider"), ("models", "*", "apiBase"), _CONTINUE_PROVIDERS),),
    ),
    _Source(
        "aider",
        (".aider.conf.yml", "~/.aider.conf.yml"),
        "yaml",
        "project",
        (_Spot(("model",), "client-default"), _Spot(("weak-model",), "client-small"), _Spot(("editor-model",), "client-editor")),
    ),
    _Source(
        "zed",
        ("~/.config/zed/settings.json",),
        "jsonc",
        "user",
        (_Spot(("agent", "default_model", "model"), "client-default", ("agent", "default_model", "provider"), None, {"anthropic": "anthropic", "openai": "openai", "google": "google-gemini", "ollama": "ollama"}),),
    ),
    _Source(
        "litellm",
        ("litellm_config.yaml", "litellm.yaml", "litellm/config.yaml", "config/litellm.yaml", "proxy_config.yaml"),
        "yaml",
        "project",
        (_Spot(("model_list", "*", "litellm_params", "model"), "gateway-route", None, ("model_list", "*", "litellm_params", "api_base")),),
        gateway="litellm",
    ),
)  # fmt: skip


@dataclass(slots=True)
class _Found:
    ref: HostedRef
    locator: str
    source: str
    role: str
    scope: Scope
    endpoint: str | None = None
    endpoint_override: bool = False
    gateway_alias: str | None = None
    occurrences: int = 1
    extra_tags: set[str] = field(default_factory=set)


def _walk_spot(
    data: Any, path: tuple[str, ...], trail: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], Any]]:
    """Yield ``(concrete path, value)`` for a key path where ``*`` expands every list item or map value."""
    if not path:
        yield trail, data
        return
    head, rest = path[0], path[1:]
    if head == "*":
        if isinstance(data, list):
            for i, item in enumerate(data[:1000]):
                yield from _walk_spot(item, rest, (*trail, str(i)))
        elif isinstance(data, dict):
            for key in sorted(data, key=str)[:1000]:
                yield from _walk_spot(data[key], rest, (*trail, str(key)))
        return
    if isinstance(data, dict) and head in data:
        yield from _walk_spot(data[head], rest, (*trail, head))


def _resolve(data: Any, template: tuple[str, ...] | None, concrete: tuple[str, ...]) -> Any:
    """Value at ``template`` after substituting the ``*`` positions taken in ``concrete``."""
    if template is None:
        return None
    node = data
    for i, step in enumerate(template):
        key = concrete[i] if step == "*" and i < len(concrete) else step
        if isinstance(node, list) and key.isdigit() and int(key) < len(node):
            node = node[int(key)]
        elif isinstance(node, dict) and key in node:
            node = node[key]
        else:
            return None
    return node


def _pointer(path: Iterable[str]) -> str:
    return "#/" + "/".join(p.replace("~", "~0").replace("/", "~1") for p in path)


def _origin(url: str) -> str | None:
    """``scheme://host[:port]`` of a base URL; credentials, path and query are never kept."""
    text = url.strip()
    try:
        parts = urlsplit(text if "//" in text else f"https://{text}")
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if not host or parts.scheme not in ("http", "https"):
        return None
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "")


def _clean_value(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value.split(" #", 1)[0].strip()


class ModelsHostedCollector(BaseCollector):
    """Hosted model identifiers from manifests, client settings, gateway configs, ``.env`` files and code."""

    name = "models-hosted"
    version = "0.1.0"
    surfaces = (Surface.MODEL_GATEWAY, Surface.CODE)
    mode = CollectorMode.DECLARED

    def detect(self, ctx: CollectContext) -> bool:
        del ctx
        return True

    # ----------------------------------------------------------------------------------------------- sources

    def _paths(self, ctx: CollectContext, source: _Source) -> Iterator[tuple[Path, Scope]]:
        for raw in source.paths:
            if raw.startswith("~/"):
                if ctx.home is not None:
                    yield ctx.home / raw[2:], "user"
            else:
                yield ctx.root / raw, source.scope

    def _read(
        self, ctx: CollectContext, result: CollectionResult, path: Path, surface: Surface
    ) -> ReadOutcome | None:
        if not path.is_file() or path.is_symlink():
            return None
        outcome = ctx.read_config(path)  # confined beneath the scan root, home or user config dir
        display = ctx.display(path)
        if not outcome.ok or outcome.data is None:
            result.add_source(surface, "file", locator=display, ok=False, error_class=outcome.error_class)
            return None
        return outcome

    def _config_sources(
        self, ctx: CollectContext, result: CollectionResult, found: dict[tuple[str, str], _Found]
    ) -> None:
        checked = 0
        for source in SOURCES:
            for path, scope in self._paths(ctx, source):
                checked += 1
                outcome = self._read(ctx, result, path, Surface.MODEL_GATEWAY)
                if outcome is None or outcome.data is None:
                    continue
                display = ctx.display(path)
                try:
                    data = parse_structured(outcome.data, source.fmt)
                except (ValueError, TypeError, RecursionError):
                    result.add_source(
                        Surface.MODEL_GATEWAY,
                        source.name,
                        locator=display,
                        ok=False,
                        error_class="parse-error",
                    )
                    continue
                items = 0
                env_models, env_endpoint = self._env_block(ctx, result, data, source, display)
                for spot in source.spots:
                    for concrete, value in _walk_spot(data, spot.path):
                        if not isinstance(value, str):
                            continue
                        provider = _resolve(data, spot.provider_path, concrete)
                        if isinstance(provider, str) and spot.provider_map is not None:
                            provider = spot.provider_map.get(provider, provider)
                        endpoint = _resolve(data, spot.endpoint_path, concrete)
                        endpoint = endpoint if isinstance(endpoint, str) else env_endpoint
                        alias = None
                        if source.gateway == "litellm" and len(concrete) > 1:
                            name = _resolve(data, ("model_list", concrete[1], "model_name"), concrete)
                            alias = name if isinstance(name, str) else None
                        items += self._add(
                            ctx, result, found, value, locator=display + _pointer(concrete), source=source.name,
                            role=spot.role, scope=scope, provider=provider if isinstance(provider, str) else None, endpoint=endpoint,
                            context=source.context, gateway_alias=alias, gateway=source.gateway,
                        )  # fmt: skip
                for key, value in env_models:
                    items += self._add(
                        ctx, result, found, value, locator=display + _pointer((*(source.env_path or ()), key)),
                        source=source.name, role="client-env", scope=scope, endpoint=env_endpoint, context=source.context,
                        env_names=(key,),
                    )  # fmt: skip
                result.add_source(Surface.MODEL_GATEWAY, source.name, locator=display, ok=True, items=items)
        result.add_source(Surface.MODEL_GATEWAY, "locations-checked", ok=True, items=0, locator=str(checked))

    def _env_block(
        self, ctx: CollectContext, result: CollectionResult, data: Any, source: _Source, display: str
    ) -> tuple[list[tuple[str, str]], str | None]:
        """Model selectors and the base URL from a settings ``env`` map (values of other keys are never kept)."""
        if source.env_path is None:
            return [], None
        env = _resolve(data, source.env_path, ())
        if not isinstance(env, dict):
            return [], None
        models: list[tuple[str, str]] = []
        endpoint: str | None = None
        for key in sorted(env, key=str):
            value = env[key]
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            if key in _BASE_URL_ENV:
                endpoint = value
            elif _ENV_MODEL_KEY.match(key):
                if looks_like_secret(value):
                    self._redact(ctx, result, display)
                    continue
                models.append((key, value))
        return models, endpoint

    def _dotenv(
        self,
        ctx: CollectContext,
        result: CollectionResult,
        found: dict[tuple[str, str], _Found],
        files: list[Path],
    ) -> None:
        for path in files:
            outcome = self._read(ctx, result, path, Surface.MODEL_GATEWAY)
            if outcome is None or outcome.data is None:
                continue
            display = ctx.display(path)
            text = outcome.data.decode("utf-8", errors="replace")
            models: list[tuple[int, str, str]] = []
            endpoint: str | None = None
            for lineno, line in enumerate(text.splitlines()[:20000], start=1):
                if len(line) > MAX_ENV_LINE:
                    continue
                match = _ENV_LINE.match(line)
                if match is None or line.lstrip().startswith("#"):
                    continue
                key, raw = match.group(1), match.group(2)
                if key in _BASE_URL_ENV:
                    endpoint = _clean_value(raw)
                elif _ENV_MODEL_KEY.match(key):
                    value = _clean_value(raw)
                    if looks_like_secret(value):
                        self._redact(ctx, result, display)
                        continue
                    models.append((lineno, key, value))
            items = 0
            for lineno, key, value in models:
                items += self._add(
                    ctx, result, found, value, locator=f"{display}:{lineno}", source="dotenv", role="env",
                    scope="project", endpoint=endpoint, env_names=(key,),
                )  # fmt: skip
            result.add_source(Surface.MODEL_GATEWAY, "dotenv", locator=display, ok=True, items=items)

    def _python(self, path: Path, text: str) -> Iterator[tuple[int, str, tuple[str, ...], str | None]]:
        """``(line, string, provider hints, endpoint)`` for model literals in Python source (parsed, not run)."""
        tree = ast.parse(text, filename=path.name)
        hints: set[str] = set()
        endpoints: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                top = node.module
                if top in _MODULE_HINTS or top.split(".")[0] in _MODULE_HINTS:
                    hints.add(_MODULE_HINTS.get(top, _MODULE_HINTS.get(top.split(".")[0], "")))
                hints.update(_IMPORT_HINTS[a.name] for a in node.names if a.name in _IMPORT_HINTS)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    for candidate in (alias.name, alias.name.split(".")[0]):
                        if candidate in _MODULE_HINTS:
                            hints.add(_MODULE_HINTS[candidate])
            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg in ("base_url", "api_base", "azure_endpoint", "endpoint") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):  # fmt: skip
                        endpoints.add(kw.value.value)
        hints.discard("")
        if any(h in hints for h in ("azure-openai", "aws-bedrock", "google-vertex")):
            hints = {h for h in hints if h in ("azure-openai", "aws-bedrock", "google-vertex")}
        attributed = {p for p in (provider_for_endpoint(e) for e in endpoints) if p}
        endpoint = next(iter(endpoints)) if len(attributed) == 1 and len(endpoints) == 1 else None
        provider_hints = tuple(sorted(hints))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if (
                        kw.arg in _MODEL_KWARGS
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)
                    ):
                        yield kw.value.lineno, kw.value.value, provider_hints, endpoint
                func = node.func
                getenv = (isinstance(func, ast.Attribute) and func.attr in ("getenv", "get")) or (
                    isinstance(func, ast.Name) and func.id == "getenv"
                )
                if getenv and len(node.args) >= 2:
                    name, default = node.args[0], node.args[1]
                    if (
                        isinstance(name, ast.Constant)
                        and isinstance(name.value, str)
                        and _ENV_MODEL_KEY.match(name.value)
                        and isinstance(default, ast.Constant)
                        and isinstance(default.value, str)
                    ):
                        yield default.lineno, default.value, provider_hints, endpoint
            elif isinstance(node, ast.Assign | ast.AnnAssign):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
                    continue
                if any(isinstance(t, ast.Name) and _MODEL_NAME_RE.match(t.id) for t in targets):
                    yield value.lineno, value.value, provider_hints, endpoint
            elif isinstance(node, ast.Dict):
                for key, val in zip(node.keys, node.values, strict=True):
                    if isinstance(key, ast.Constant) and key.value in _MODEL_KWARGS and isinstance(val, ast.Constant) and isinstance(val.value, str):  # fmt: skip
                        yield val.lineno, val.value, provider_hints, endpoint

    def _code(
        self,
        ctx: CollectContext,
        result: CollectionResult,
        found: dict[tuple[str, str], _Found],
        files: list[Path],
    ) -> None:
        parsed = 0
        parsed_bytes = 0
        deadline = time.monotonic() + ctx.budget_seconds * CODE_TIME_SHARE
        for index, path in enumerate(files):
            display = ctx.display(path)
            if parsed >= MAX_CODE_FILES or parsed_bytes >= MAX_CODE_BYTES or time.monotonic() > deadline:
                remaining = len(files) - index
                result.add_source(
                    Surface.CODE,
                    "code-budget",
                    locator=display,
                    ok=False,
                    error_class="truncated",
                    items=remaining,
                )
                result.warnings.append(
                    f"code scan stopped at {display}: {remaining} file(s) not parsed (budget)"
                )
                break
            try:
                size = path.stat().st_size
            except OSError:
                result.add_source(Surface.CODE, "code", locator=display, ok=False, error_class="unreadable")
                continue
            if size > MAX_SOURCE_BYTES:
                result.add_source(Surface.CODE, "code", locator=display, ok=False, error_class="too-large")
                continue
            outcome = read_bounded(path, MAX_SOURCE_BYTES, root=ctx.root)
            if not outcome.ok or outcome.data is None:
                result.add_source(
                    Surface.CODE, "code", locator=display, ok=False, error_class=outcome.error_class
                )
                continue
            parsed += 1
            parsed_bytes += len(outcome.data)
            text = outcome.data.decode("utf-8", errors="replace")
            if path.suffix == ".py":
                try:
                    hits = list(self._python(path, text))
                except (SyntaxError, ValueError, RecursionError, MemoryError):
                    result.add_source(
                        Surface.CODE, "code", locator=display, ok=False, error_class="parse-error"
                    )
                    continue
                for line, value, hints, endpoint in hits:
                    self._add(
                        ctx, result, found, value, locator=f"{display}:{line}", source="code", role="code-literal",
                        scope="project", endpoint=endpoint, packages=hints, require_attribution=True,
                    )  # fmt: skip
            else:
                for match in _JS_MODEL.finditer(text):
                    line = text.count("\n", 0, match.start()) + 1
                    self._add(
                        ctx, result, found, match.group(1), locator=f"{display}:{line}", source="code",
                        role="code-literal", scope="project", require_attribution=True, shape_only=True,
                    )  # fmt: skip

    # ----------------------------------------------------------------------------------------------- results

    def _redact(self, ctx: CollectContext, result: CollectionResult, display: str) -> None:
        result.warnings.append(
            f"{display}: a model-selector value looks like a credential; it was not recorded"
        )
        result.redactions.append(
            Redaction(redaction_class="secret-value", count=1, applied_by=self.ref, applied_at=ctx.now)
        )

    def _add(
        self,
        ctx: CollectContext,
        result: CollectionResult,
        found: dict[tuple[str, str], _Found],
        value: str,
        *,
        locator: str,
        source: str,
        role: str,
        scope: Scope,
        provider: str | None = None,
        endpoint: str | None = None,
        context: str | None = None,
        env_names: Iterable[str] = (),
        packages: Iterable[str] = (),
        gateway_alias: str | None = None,
        gateway: str | None = None,
        require_attribution: bool = False,
        shape_only: bool = False,
    ) -> int:
        value = value.strip()
        if not value or len(value) > MAX_MODEL_REF or "${" in value or "{env:" in value:
            return 0
        if looks_like_secret(value):
            self._redact(ctx, result, locator.split("#", 1)[0])
            return 0
        explicit = provider
        known = explicit is not None and explicit in {p.id for p in load_providers()}
        ref = classify_model_ref(
            value,
            provider=explicit if known else None,
            endpoint=endpoint,
            context=context,
            env_names=() if shape_only else env_names,
            packages=() if shape_only else packages,
        )
        if explicit is not None and not known:
            # A provider the table does not know (an internal gateway, a proxy such as zed.dev): the declaration
            # wins; the identifier's shape still says whether the upstream name is a snapshot or an alias.
            shape = (
                f" (identifier shape of {ref.provider}; served through {explicit})" if ref.provider else ""
            )
            ref = HostedRef(
                ref.requested_ref, explicit, ref.base_ref, ref.alias_pinning if ref.provider else AliasPinning.UNKNOWN,
                (ref.reason if ref.provider else "provider is not in the rule table") + shape, ref.rule, "explicit",
            )  # fmt: skip
        if require_attribution and (
            ref.provider is None or (shape_only and ref.attribution not in ("shape", "litellm-prefix"))
        ):
            return 0
        key = (ref.provider or "unknown", ref.requested_ref)
        override = False
        origin: str | None = None
        if endpoint:
            origin = _origin(endpoint)
            official = provider_for_endpoint(endpoint)
            override = origin is not None and (official is None or official != ref.provider)
        existing = found.get(key)
        if existing is not None:
            existing.occurrences += 1
            if override and not existing.endpoint_override:
                existing.endpoint, existing.endpoint_override = origin, True
            return 1
        tags = {f"source:{source}", f"role:{role}", f"scope:{scope}"}
        if _TEST_PATH.search(locator.split("#", 1)[0]):
            tags.add("in-tests")
        if gateway:
            tags.add(f"gateway:{gateway}")
        found[key] = _Found(
            ref, locator, source, role, scope, origin, override, gateway_alias, extra_tags=tags
        )
        return 1

    def _emit(
        self, ctx: CollectContext, result: CollectionResult, found: dict[tuple[str, str], _Found]
    ) -> None:
        used: set[str] = set()
        for (provider, requested), item in sorted(found.items()):
            model_id = make_id("model", "hosted", provider, requested)
            if model_id in used:
                model_id = make_id("model", "hosted", provider, requested, collision_seed=requested)
            used.add(model_id)
            ref = item.ref
            tags = set(item.extra_tags) | {
                f"provider:{provider}",
                f"pinning:{ref.alias_pinning.value}",
                f"attributed-by:{ref.attribution}",
            }
            if ref.expected_resolution:
                tags.add(f"alias-resolves-to:{ref.expected_resolution.split(' ', 1)[0]}")
            if item.gateway_alias:
                tags.add(f"gateway-alias:{item.gateway_alias}")
            if item.endpoint_override:
                tags.add(f"endpoint-override:{item.scope}")
            if item.occurrences > 1:
                tags.add(f"occurrences:{item.occurrences}")
            identity = hosted_identity(
                ref, endpoint_origin=item.endpoint, locator=item.locator, collector=self.ref
            )
            model = Model(
                id=model_id,
                name=requested,
                description=ref.reason,
                provenance=Provenance(method=ClaimMethod.CONFIG, locator=item.locator, collector=self.ref, observed_at=ctx.now),
                tags=sorted(tags),
                model_kind=ModelKind.HOSTED,
                hosted=Claim.declared(identity, locator=item.locator, collector=self.ref, method=ClaimMethod.CONFIG, observed_at=ctx.now),
            )  # fmt: skip
            result.entities.append(model)
            result.edges.append(
                Edge.model_validate(
                    {
                        "type": EdgeType.USES_MODEL,
                        "from": ctx.agent_id,
                        "to": model_id,
                        "qualifiers": {"role": item.role, "source": item.source},
                        "declaredBy": item.locator.split("#", 1)[0],
                    }
                )
            )

    def collect(self, ctx: CollectContext) -> CollectionResult:
        result = self.new_result()
        found: dict[tuple[str, str], _Found] = {}
        self._config_sources(ctx, result, found)
        if ctx.home is None:
            result.add_source(Surface.MODEL_GATEWAY, "user-scope", ok=False, error_class="not-attempted")
        env_files: list[Path] = []
        code_files: list[Path] = []
        for path in ctx.walk():
            if _ENV_NAMES.match(path.name) and not path.name.endswith((".example", ".sample", ".template")):
                env_files.append(path)
            elif path.suffix in _CODE_SUFFIXES:
                code_files.append(path)
        self._dotenv(ctx, result, found, env_files)
        self._code(ctx, result, found, code_files)
        result.add_source(Surface.CODE, "code-files", ok=True, items=len(code_files))
        self._emit(ctx, result, found)
        if len(result.redactions) > 1:
            merged = sum(r.count for r in result.redactions)
            result.redactions = [
                Redaction(
                    redaction_class="secret-value", count=merged, applied_by=self.ref, applied_at=ctx.now
                )
            ]
        return result
