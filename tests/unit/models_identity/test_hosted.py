"""Hosted model identifiers: provider attribution, alias-versus-snapshot rules and ReDoS safety (providers.yaml)."""

from __future__ import annotations

import time
from typing import Any

import pytest

from symbiote.model.enums import AliasPinning, ValueState
from symbiote.models_identity.hosted import (
    MAX_MODEL_REF,
    classify_model_ref,
    hosted_identity,
    load_providers,
    provider_for_endpoint,
    provider_for_env,
    provider_for_package,
    split_litellm_prefix,
)

P, F, U = AliasPinning.PINNED, AliasPinning.FLOATING, AliasPinning.UNKNOWN

CASES: list[tuple[str, dict[str, Any], str | None, AliasPinning]] = [
    # Anthropic
    ("claude-sonnet-4-5-20250929", {}, "anthropic", P),
    ("claude-sonnet-4-5", {}, "anthropic", F),
    ("claude-opus-4-1", {}, "anthropic", F),
    ("claude-opus-4-6", {}, "anthropic", P),
    ("claude-opus-5-5", {}, "anthropic", P),
    ("claude-haiku-5-5", {}, "anthropic", P),
    ("claude-mythos-preview", {}, "anthropic", P),
    ("claude-3-5-sonnet-latest", {}, "anthropic", F),
    ("claude-opus-4-6[1m]", {}, "anthropic", P),
    ("claude-opus-4-6-fast", {}, "anthropic", P),
    ("claude-2.1", {}, "anthropic", U),
    ("opus", {"context": "claude-code"}, "anthropic", F),
    ("opusplan", {"context": "claude-code"}, "anthropic", F),
    ("opus", {}, None, U),
    # OpenAI
    ("gpt-4o", {}, "openai", F),
    ("gpt-4o-2024-08-06", {}, "openai", P),
    ("chatgpt-4o-latest", {}, "openai", F),
    ("o3", {}, "openai", F),
    ("o3-mini-2025-01-31", {}, "openai", P),
    ("gpt-4-0613", {}, "openai", P),
    ("ft:gpt-4o-mini-2024-07-18:my-org:custom_suffix:abc123", {}, "openai", P),
    ("text-embedding-3-large", {}, "openai", U),
    # Google Gemini API
    ("gemini-2.5-pro", {}, "google-gemini", P),
    ("gemini-2.0-flash", {}, "google-gemini", F),
    ("gemini-1.5-pro-002", {}, "google-gemini", P),
    ("models/gemini-2.0-flash-001", {}, "google-gemini", P),
    ("gemini-flash-latest", {}, "google-gemini", F),
    ("gemini-3-pro-preview", {}, "google-gemini", U),
    ("flash", {"context": "gemini-cli"}, "google-gemini", F),
    # Vertex
    ("publishers/google/models/gemini-2.5-pro", {}, "google-vertex", P),
    (
        "projects/p/locations/us-central1/publishers/google/models/gemini-2.0-flash-001",
        {},
        "google-vertex",
        P,
    ),
    ("claude-sonnet-4-5@20250929", {}, "google-vertex", P),
    ("claude-opus-4-6@default", {}, "google-vertex", F),
    ("publishers/anthropic/models/claude-opus-5-5", {}, "google-vertex", P),
    ("projects/p/locations/us-central1/endpoints/1234567890", {}, "google-vertex", F),
    ("projects/p/locations/us-central1/models/987654321@3", {}, "google-vertex", P),
    ("vertex_ai/gemini-2.5-pro", {}, "google-vertex", P),
    ("vertex_ai/gemini-2.0-flash", {}, "google-vertex", F),
    # Bedrock
    ("anthropic.claude-sonnet-4-5-20250929-v1:0", {}, "aws-bedrock", P),
    ("global.anthropic.claude-opus-5-5", {}, "aws-bedrock", P),
    ("us.anthropic.claude-3-5-sonnet-20240620-v1:0", {}, "aws-bedrock", P),
    ("meta.llama3-1-70b-instruct-v1:0", {}, "aws-bedrock", P),
    ("arn:aws:bedrock:us-east-1:123456789012:provisioned-model/abcdef123456", {}, "aws-bedrock", F),
    (
        "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/a1b2c3d4e5f6",
        {},
        "aws-bedrock",
        U,
    ),
    (
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20240620-v1:0",
        {},
        "aws-bedrock",
        P,
    ),
    ("bedrock/anthropic.claude-opus-4-6-v1", {}, "aws-bedrock", P),
    # Azure: the deployment decides the model
    ("gpt4o-prod", {"endpoint": "https://contoso.openai.azure.com"}, "azure-openai", U),
    ("gpt-4o", {"endpoint": "https://contoso.openai.azure.com/openai/deployments/gpt-4o"}, "azure-openai", U),
    ("model-router", {"provider": "azure-openai"}, "azure-openai", F),
    ("azure/my-deployment", {}, "azure-openai", U),
    # Mistral, Cohere, xAI, DeepSeek, Meta
    ("mistral-large-latest", {}, "mistral", F),
    ("mistral-large-2411", {}, "mistral", P),
    ("mistralai/Mistral-7B-Instruct-v0.3", {}, None, U),
    ("command-r-plus", {}, "cohere", F),
    ("command-a-03-2025", {}, "cohere", P),
    ("command-nightly", {}, "cohere", F),
    ("embed-v4.0", {}, "cohere", P),
    ("grok-4", {}, "xai", F),
    ("grok-4-0709", {}, "xai", P),
    ("grok-4-latest", {}, "xai", F),
    ("deepseek-chat", {}, "deepseek", F),
    ("deepseek-ai/DeepSeek-R1-0528", {}, None, U),
    ("Llama-4-Maverick-17B-128E-Instruct-FP8", {}, "meta-llama", U),
    # Routers and local runtimes
    ("openrouter/auto", {}, "openrouter", F),
    ("anthropic/claude-sonnet-4.5", {"endpoint": "https://openrouter.ai/api/v1"}, "openrouter", F),
    ("openai/gpt-4o-2024-08-06", {"endpoint": "https://openrouter.ai/api/v1"}, "openrouter", P),
    ("llama3.2", {"endpoint": "http://localhost:11434/v1"}, "ollama", F),
    ("llama3:70b", {"endpoint": "http://127.0.0.1:11434"}, "ollama", F),
    ("ollama/qwen3:30b-a3b-q4_K_M", {}, "ollama", F),
    ("llama3", {"packages": ["ollama"]}, "ollama", F),
    ("huggingface/meta-llama/Llama-3.1-8B-Instruct", {}, "huggingface", F),
    (
        "bigscience/bloom-560m@e985a63cdc139290c5f700ff1929f0b5942cced2",
        {"provider": "huggingface"},
        "huggingface",
        P,
    ),
    ("deepseek-ai/DeepSeek-R1-0528:fastest", {"provider": "huggingface"}, "huggingface", F),
    # LiteLLM prefixes reach the right table
    ("anthropic/claude-opus-4-6", {}, "anthropic", P),
    ("openai/gpt-4o", {}, "openai", F),
    ("gemini/gemini-2.5-flash", {}, "google-gemini", P),
    ("anthropic/*", {}, "anthropic", F),
]


@pytest.mark.parametrize(("ref", "kwargs", "provider", "pinning"), CASES, ids=[c[0] for c in CASES])
def test_classification(
    ref: str, kwargs: dict[str, Any], provider: str | None, pinning: AliasPinning
) -> None:
    out = classify_model_ref(ref, **kwargs)
    assert (out.provider, out.alias_pinning) == (provider, pinning), out
    assert out.requested_ref == ref
    if provider is None:
        assert out.attribution == "none" and out.rule is None


def test_known_alias_and_suffix_explanations() -> None:
    alias = classify_model_ref("claude-sonnet-4-5")
    assert alias.expected_resolution is not None and "claude-sonnet-4-5-20250929" in alias.expected_resolution
    assert classify_model_ref("claude-sonnet-4-5-20250929").expected_resolution is None
    routed = classify_model_ref("claude-opus-4-6[1m]")
    assert routed.base_ref == "claude-opus-4-6" and "routing suffix" in routed.reason
    prefixed = classify_model_ref("anthropic/claude-opus-4-6")
    assert prefixed.attribution == "litellm-prefix" and prefixed.base_ref == "claude-opus-4-6"


@pytest.mark.parametrize(
    "ref",
    ["", "   ", "a" * (MAX_MODEL_REF + 1), "gpt-4o; rm -rf /", "claude\nsonnet", "$(whoami)", "gpt-4o?x=1"],
)
def test_non_identifiers_are_unknown(ref: str) -> None:
    out = classify_model_ref(ref)
    assert out.alias_pinning is U and out.provider is None
    assert len(out.requested_ref) <= MAX_MODEL_REF


def test_weak_hints_need_agreement() -> None:
    assert classify_model_ref("my-deployment", env_names=["AZURE_OPENAI_ENDPOINT"]).provider == "azure-openai"
    both = classify_model_ref("my-deployment", env_names=["AZURE_OPENAI_ENDPOINT", "OPENAI_API_KEY"])
    assert both.provider is None and both.alias_pinning is U
    # the identifier's shape outranks hints
    assert classify_model_ref("claude-opus-4-6", packages=["openai"]).provider == "anthropic"


@pytest.mark.parametrize(
    ("endpoint", "provider"),
    [
        ("https://api.anthropic.com", "anthropic"),
        ("https://api.anthropic.com/v1/messages", "anthropic"),
        ("api.openai.com", "openai"),
        ("https://us-central1-aiplatform.googleapis.com/v1/projects/p", "google-vertex"),
        ("https://bedrock-runtime.us-east-1.amazonaws.com", "aws-bedrock"),
        ("https://contoso.services.ai.azure.com/models", "azure-openai"),
        ("http://[::1]:11434", "ollama"),
        ("https://abc.us-east-1.aws.endpoints.huggingface.cloud", "huggingface"),
        ("https://api.anthropic.com.evil.example", None),
        ("https://evil.example/api.anthropic.com", None),
        ("http://localhost:8080", None),
        ("not a url at all", None),
        ("https://[bad", None),
    ],
)
def test_endpoint_attribution(endpoint: str, provider: str | None) -> None:
    assert provider_for_endpoint(endpoint) == provider


def test_env_package_and_prefix_lookups() -> None:
    assert provider_for_env("ANTHROPIC_API_KEY") == "anthropic"
    assert provider_for_env("SOME_OTHER_KEY") is None
    assert provider_for_package("Anthropic") == "anthropic"
    assert provider_for_package("@anthropic-ai/claude-agent-sdk") == "anthropic"
    assert split_litellm_prefix("bedrock/anthropic.claude-opus-4-6-v1") == (
        "aws-bedrock",
        "anthropic.claude-opus-4-6-v1",
    )
    assert split_litellm_prefix("meta-llama/Llama-3.1-8B") == (None, "meta-llama/Llama-3.1-8B")
    assert split_litellm_prefix("anthropic/") == (None, "anthropic/")


def test_hosted_identity_never_claims_resolution() -> None:
    ident = hosted_identity(
        classify_model_ref("claude-sonnet-4-5"), endpoint_origin="https://api.anthropic.com"
    )
    assert ident.provider == "anthropic" and ident.alias_pinning is F
    assert ident.resolved_ref.state is ValueState.UNKNOWN and ident.resolved_ref.value is None
    assert hosted_identity(classify_model_ref("opus")).provider == "unknown"


def test_table_is_well_formed() -> None:
    providers = load_providers()
    ids = [p.id for p in providers]
    assert len(ids) == len(set(ids)) >= 14
    for p in providers:
        assert p.rules, p.id
        assert p.rules[-1].pattern.pattern == "^.+$" or p.id == "anthropic", f"{p.id} needs a terminal rule"
        for alias, (target, as_of) in p.known_aliases.items():
            assert classify_model_ref(alias, provider=p.id).alias_pinning is F, alias
            assert classify_model_ref(target, provider=p.id).alias_pinning is P, target
            assert as_of


PATHOLOGICAL = [
    "-" * 500,
    "a-" * 250,
    "a" * 500 + "!",
    "claude-" + "a-" * 240 + "!",
    "grok-0101" + "-a" * 240 + "!",
    "gpt-4" + "-a" * 250 + "!",
    "o3" + "-a" * 250 + "!",
    "x/" * 250,
    ":" * 500,
    "projects/" + "a/" * 240,
    "arn:aws:bedrock:" + "a:" * 240,
    "gemini-" + "a-" * 240 + "preview!",
    "anthropic." + "a." * 240 + "!",
    "a/" + "b-" * 240 + "!",
    "llama3:" + "a-" * 240 + "cloud!",
]


def test_rules_are_linear_on_hostile_input() -> None:
    patterns = []
    for p in load_providers():
        patterns += (
            [r.pattern for r in p.rules] + list(p.claims) + list(p.strip_suffixes) + list(p.host_patterns)
        )
        for ctx in p.context_rules.values():
            patterns += [r.pattern for r in ctx]
    for text in PATHOLOGICAL:
        for pattern in patterns:
            start = time.perf_counter()
            pattern.search(text)
            assert time.perf_counter() - start < 0.05, (pattern.pattern, text[:40])
        start = time.perf_counter()
        for provider in [None, *(p.id for p in load_providers())]:
            classify_model_ref(text, provider=provider)
        assert time.perf_counter() - start < 0.5, text[:40]
