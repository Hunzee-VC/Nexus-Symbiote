"""Hosted model identifiers: provider attribution and alias-versus-snapshot classification.

A hosted model is named by a string (``claude-sonnet-4-5``, ``gpt-4o-2024-08-06``,
``global.anthropic.claude-opus-5-5``, ``projects/p/locations/l/endpoints/123``). Whether that string pins the
weights the agent runs on decides ``HostedIdentity.alias_pinning`` and ``SYM-MODEL-001``. The rules live in
``providers.yaml`` (one ordered table per provider, sourced from the providers' SDK types and API specs) so they
can be updated without code changes.

Classification never contacts a provider: ``resolved_ref`` stays ``unknown`` until a live query fills it, and a
known alias mapping is reported only as ``expected_resolution``. Inputs come from untrusted repositories, so
identifiers are length-bounded and the table's patterns are kept free of nested ambiguous repetition (the test
suite times every pattern against pathological inputs).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any, Final, Literal
from urllib.parse import urlsplit

import yaml

from symbiote.model.common import Claim
from symbiote.model.entities import HostedIdentity
from symbiote.model.enums import AliasPinning, UnknownReason

__all__ = [
    "MAX_MODEL_REF",
    "HostedRef",
    "PinningRule",
    "ProviderSpec",
    "classify_model_ref",
    "hosted_identity",
    "load_providers",
    "provider_for_endpoint",
    "provider_for_env",
    "provider_for_package",
    "split_litellm_prefix",
]

#: Longest identifier the classifier accepts; longer strings are not model names and are reported unknown.
MAX_MODEL_REF: Final = 512

Attribution = Literal["explicit", "endpoint", "litellm-prefix", "shape", "context", "env", "package", "none"]

_CATCH_ALL: Final = "^.+$"
_REF_SHAPE: Final = re.compile(r"^[A-Za-z0-9~][A-Za-z0-9._:/@~*\[\]+-]*$")
_LOCAL_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"})  # noqa: S104


@dataclass(frozen=True, slots=True)
class PinningRule:
    pattern: re.Pattern[str]
    pinning: AliasPinning
    why: str


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    id: str
    name: str
    confidence: str
    hosts: frozenset[str]
    host_suffixes: tuple[str, ...]
    host_patterns: tuple[re.Pattern[str], ...]
    local_ports: frozenset[int]
    env: frozenset[str]
    sdks: frozenset[str]
    litellm_prefixes: frozenset[str]
    resolution: str
    strip_suffixes: tuple[re.Pattern[str], ...]
    claims: tuple[re.Pattern[str], ...]
    rules: tuple[PinningRule, ...]
    context_rules: Mapping[str, tuple[PinningRule, ...]]
    known_aliases: Mapping[str, tuple[str, str]]


@dataclass(frozen=True, slots=True)
class HostedRef:
    """The outcome of classifying one identifier."""

    requested_ref: str
    provider: str | None
    base_ref: str
    alias_pinning: AliasPinning
    reason: str
    rule: str | None
    attribution: Attribution
    expected_resolution: str | None = None


def _rules(raw: Iterable[Mapping[str, Any]]) -> tuple[PinningRule, ...]:
    return tuple(
        PinningRule(re.compile(str(r["pattern"])), AliasPinning(str(r["pinning"])), str(r.get("why", "")))
        for r in raw
    )


def _spec(raw: Mapping[str, Any]) -> ProviderSpec:
    aliases = raw.get("known_aliases") or {}
    return ProviderSpec(
        id=str(raw["id"]),
        name=str(raw.get("name", raw["id"])),
        confidence=str(raw.get("confidence", "low")),
        hosts=frozenset(str(h).lower() for h in raw.get("hosts") or ()),
        host_suffixes=tuple(str(h).lower() for h in raw.get("host_suffixes") or ()),
        host_patterns=tuple(re.compile(str(p)) for p in raw.get("host_patterns") or ()),
        local_ports=frozenset(int(p) for p in raw.get("local_ports") or ()),
        env=frozenset(str(e) for e in raw.get("env") or ()),
        sdks=frozenset(str(s).lower() for s in raw.get("sdks") or ()),
        litellm_prefixes=frozenset(str(p).lower() for p in raw.get("litellm_prefixes") or ()),
        resolution=str(raw.get("resolution", "")),
        strip_suffixes=tuple(re.compile(str(p)) for p in raw.get("strip_suffixes") or ()),
        claims=tuple(re.compile(str(p)) for p in raw.get("claims") or ()),
        rules=_rules(raw.get("rules") or ()),
        context_rules={str(k): _rules(v) for k, v in (raw.get("context_rules") or {}).items()},
        known_aliases={str(k): (str(v["resolves_to"]), str(v.get("as_of", ""))) for k, v in aliases.items()},
    )


@lru_cache(maxsize=1)
def load_providers() -> tuple[ProviderSpec, ...]:
    """The provider table shipped in ``providers.yaml``, in attribution order."""
    text = resources.files("symbiote.models_identity").joinpath("providers.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    return tuple(_spec(p) for p in data["providers"])


def _by_id() -> dict[str, ProviderSpec]:
    return {p.id: p for p in load_providers()}


def provider_for_endpoint(endpoint: str) -> str | None:
    """Provider id for a base URL or endpoint (``https://api.anthropic.com``, ``http://localhost:11434/v1``)."""
    try:
        parts = urlsplit(endpoint if "//" in endpoint else f"https://{endpoint}")
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return None
    if not host:
        return None
    local = host in _LOCAL_HOSTS
    if not local:
        try:
            local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = False
    for spec in load_providers():
        if host in spec.hosts or any(host.endswith(s) for s in spec.host_suffixes):
            return spec.id
        if any(p.search(host) for p in spec.host_patterns):
            return spec.id
        if local and port is not None and port in spec.local_ports:
            return spec.id
    return None


def provider_for_env(name: str) -> str | None:
    """Provider id an environment-variable *name* belongs to (values are never read here)."""
    for spec in load_providers():
        if name in spec.env:
            return spec.id
    return None


def provider_for_package(name: str) -> str | None:
    """Provider id for an SDK package name (PyPI or npm)."""
    lowered = name.lower()
    for spec in load_providers():
        if lowered in spec.sdks:
            return spec.id
    return None


def split_litellm_prefix(ref: str) -> tuple[str | None, str]:
    """``("anthropic", "claude-…")`` for a LiteLLM-style ``provider/model`` string, else ``(None, ref)``."""
    head, sep, rest = ref.partition("/")
    if not sep or not rest:
        return None, ref
    for spec in load_providers():
        if head.lower() in spec.litellm_prefixes:
            return spec.id, rest
    return None, ref


def _first_rule(rules: Iterable[PinningRule], ref: str) -> PinningRule | None:
    for rule in rules:
        if rule.pattern.search(ref):
            return rule
    return None


def _unknown(ref: str, why: str, provider: str | None = None, attribution: Attribution = "none") -> HostedRef:
    return HostedRef(ref, provider, ref, AliasPinning.UNKNOWN, why, None, attribution)


def _attribute(
    ref: str,
    *,
    provider: str | None,
    endpoint: str | None,
    context: str | None,
    env_names: Iterable[str],
    packages: Iterable[str],
) -> tuple[str | None, str, Attribution]:
    """Decide the provider and the identifier to classify: explicit > endpoint > LiteLLM prefix > shape > hints."""
    specs = _by_id()
    if provider is not None and provider in specs:
        return provider, ref, "explicit"
    if endpoint:
        by_host = provider_for_endpoint(endpoint)
        if by_host is not None:
            return by_host, ref, "endpoint"
    prefixed, rest = split_litellm_prefix(ref)
    if prefixed is not None:
        return prefixed, rest, "litellm-prefix"
    if context is not None:
        for spec in load_providers():
            if _first_rule(spec.context_rules.get(context, ()), ref) is not None:
                return spec.id, ref, "context"
    for spec in load_providers():
        if any(c.search(ref) for c in spec.claims):
            return spec.id, ref, "shape"
    hinted = {p for p in (provider_for_env(n) for n in env_names) if p is not None}
    if len(hinted) == 1:
        return hinted.pop(), ref, "env"
    sdk_hinted = {p for p in (provider_for_package(n) for n in packages) if p is not None}
    if len(sdk_hinted) == 1:
        return sdk_hinted.pop(), ref, "package"
    return None, ref, "none"


def classify_model_ref(
    ref: str,
    *,
    provider: str | None = None,
    endpoint: str | None = None,
    context: str | None = None,
    env_names: Iterable[str] = (),
    packages: Iterable[str] = (),
) -> HostedRef:
    """Attribute ``ref`` to a provider and classify it as a pinned snapshot, a floating alias or unknown.

    ``provider`` is an explicit provider id from ``providers.yaml``; ``endpoint`` a base URL from the same
    configuration; ``context`` a client whose own aliases apply (``claude-code``, ``gemini-cli``); ``env_names``
    and ``packages`` are weak hints used only when the identifier's shape does not decide the provider and the
    hints agree on exactly one provider.
    """
    raw = ref.strip()
    if not raw or len(raw) > MAX_MODEL_REF or not _REF_SHAPE.match(raw):
        return _unknown(
            raw[:MAX_MODEL_REF], "not a model identifier (empty, too long or unexpected characters)"
        )
    owner, target, attribution = _attribute(
        raw, provider=provider, endpoint=endpoint, context=context, env_names=env_names, packages=packages
    )
    if owner is None:
        return _unknown(
            raw, "the provider could not be attributed from the identifier, endpoint or configuration"
        )
    spec = _by_id()[owner]
    if target == "*":
        return HostedRef(
            raw,
            owner,
            target,
            AliasPinning.FLOATING,
            "wildcard route: forwards whatever model the client names",
            None,
            attribution,
        )
    base = target
    stripped = False
    for suffix in spec.strip_suffixes:
        shorter = suffix.sub("", base)
        if shorter != base and shorter:
            base, stripped = shorter, True
    rule = _first_rule(spec.context_rules.get(context, ()) if context else (), base) or _first_rule(
        spec.rules, base
    )
    if attribution == "litellm-prefix" and (rule is None or rule.pattern.pattern == _CATCH_ALL):
        # "openrouter/auto" is OpenRouter's own id, not LiteLLM routing to a model called "auto"
        whole = _first_rule(spec.rules, raw)
        if whole is not None and whole.pattern.pattern != _CATCH_ALL:
            base, rule = raw, whole
    if rule is None:
        return HostedRef(
            raw, owner, base, AliasPinning.UNKNOWN, f"no {spec.name} rule matches", None, attribution
        )
    why = rule.why + (" (routing suffix removed before classification)" if stripped else "")
    known = spec.known_aliases.get(base)
    expected = f"{known[0]} (as of {known[1]})" if known and rule.pinning is AliasPinning.FLOATING else None
    return HostedRef(raw, owner, base, rule.pinning, why, rule.pattern.pattern, attribution, expected)


def hosted_identity(
    ref: HostedRef,
    *,
    endpoint_origin: str | None = None,
    locator: str | None = None,
    collector: str | None = None,
) -> HostedIdentity:
    """The ``HostedIdentity`` for a classified identifier; ``resolved_ref`` stays unknown until queried live."""
    return HostedIdentity(
        provider=ref.provider or "unknown",
        endpoint_origin=endpoint_origin,
        requested_ref=ref.requested_ref,
        resolved_ref=Claim[str].unknown(UnknownReason.NOT_COLLECTED, locator=locator, collector=collector),
        alias_pinning=ref.alias_pinning,
    )
