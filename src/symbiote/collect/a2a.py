"""``a2a-cards`` collector: A2A Agent Cards found in the repository (``spec/collectors.md``).

Static only: cards are read from files named ``agent-card.json`` or ``agent.json`` anywhere under the root
(``ctx.walk()``, which also visits ``.well-known/``); nothing is fetched. Each card yields

* an external ``Agent`` carrying the card facts (``a2a_card``: digest, protocol versions, skills, security
  scheme names, signature status) and lint tags for its model-visible text, and
* a ``ToolServer(kind=a2a)`` for the card's preferred interface (transport, endpoint, authentication, trust
  zone, ``server/v1`` identity digest),

plus a ``delegatesTo`` edge from the scanned agent. A card under a ``.well-known/`` directory is the scanned
agent publishing *its own* card: both entities are tagged ``self-published-card`` and no delegation edge is
emitted.

Both card generations are understood: v0.2/v0.3 (``url``, ``preferredTransport``, ``additionalInterfaces``,
``protocolVersion``, ``supportsAuthenticatedExtendedCard``) and v1.0 (``supportedInterfaces[]`` with
``protocolBinding`` / ``protocolVersion``, ``capabilities.extendedAgentCard``, proto-JSON security schemes).
Unknown fields are ignored. The card digest is ``jsondoc/v1`` over the card minus ``signatures``
(``spec/digests.md`` section 3.7); JWS signatures are recorded as *present* (claimed) and never verified here.

Authentication is the weakest alternative a client may use: every declared scheme when ``security`` is
absent, otherwise each ``security`` requirement object (all schemes of one object are required together, and
an empty object permits anonymous access). ``securitySchemes: {}`` declares no authentication; a card that
omits ``securitySchemes`` leaves authentication ``unknown`` (I2).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from symbiote.collect._common import locator, url_facts
from symbiote.collect.base import BaseCollector, CollectContext, CollectionResult
from symbiote.digest import jsondoc_digest, server_identity_digest
from symbiote.digest.jcs import UndigestableError, parse_json_strict
from symbiote.digest.textflags import cross_tool_directives, hidden_code_points
from symbiote.model.common import (
    Claim,
    DigestResult,
    ExternalRef,
    Party,
    Provenance,
    looks_like_secret,
)
from symbiote.model.edges import Edge
from symbiote.model.entities import A2ACard, A2ASkill, Agent, Authentication, Redaction, ToolServer
from symbiote.model.enums import (
    AgentRole,
    AuthMode,
    ClaimMethod,
    CollectorMode,
    CoverageStatus,
    EdgeScope,
    EdgeType,
    PartyKind,
    Surface,
    TextFlag,
    ToolServerKind,
    Transport,
    TrustZone,
    UnknownReason,
)
from symbiote.model.ids import make_id

__all__ = [
    "CARD_FILENAMES",
    "A2ACardsCollector",
    "AuthFacts",
    "CardFacts",
    "CardInterface",
    "auth_facts",
    "card_interfaces",
    "looks_like_card",
    "parse_card",
]

#: File names an A2A Agent Card is published under (v0.3+ ``agent-card.json``; v0.2 ``agent.json``).
CARD_FILENAMES: Final = frozenset({"agent-card.json", "agent.json"})
#: Cards below a directory of this name are the scanned agent's own published card.
WELL_KNOWN_DIR: Final = ".well-known"
#: Media type used for the ``jsondoc/v1`` card digest.
CARD_MEDIA_TYPE: Final = "application/json"
MAX_DESCRIPTION_CHARS: Final = 1024
SELF_PUBLISHED_TAG: Final = "self-published-card"
#: Tag on an entity some of whose source text was withheld as credential-shaped (I6).
REDACTED_TAG: Final = "redacted:credential-shaped-token"

_SOURCE: Final = "a2a-card"
_MAX_TAG_TEXT: Final = 200
_MAX_JWS_HEADER_CHARS: Final = 8192

#: Keys whose presence marks a JSON object as an A2A Agent Card (any one suffices).
_CARD_MARKERS: Final = frozenset(
    {
        "url",
        "supportedInterfaces",
        "additionalInterfaces",
        "preferredTransport",
        "protocolVersion",
        "skills",
        "capabilities",
        "securitySchemes",
        "defaultInputModes",
        "defaultOutputModes",
    }
)

#: Protocol binding (normalised: upper case, no ``-``/``_``) -> transport. gRPC has no ``Transport`` member.
_BINDING_TRANSPORT: Final[dict[str, Transport]] = {
    "JSONRPC": Transport.STREAMABLE_HTTP,
    "HTTP+JSON": Transport.STREAMABLE_HTTP,
    "HTTP": Transport.STREAMABLE_HTTP,
}
#: Binding of a v0.2/v0.3 top-level ``url`` when ``preferredTransport`` is absent (A2A default).
_DEFAULT_BINDING: Final = "JSONRPC"

#: Security scheme kind (OpenAPI ``type`` or v1.0 proto-JSON member, normalised) -> authentication mode.
_SCHEME_MODES: Final[dict[str, AuthMode]] = {
    "oauth2": AuthMode.OAUTH2,
    "openidconnect": AuthMode.OAUTH2,
    "apikey": AuthMode.API_KEY,
    "http": AuthMode.API_KEY,
    "mutualtls": AuthMode.MTLS,
    "oauth2securityscheme": AuthMode.OAUTH2,
    "openidconnectsecurityscheme": AuthMode.OAUTH2,
    "apikeysecurityscheme": AuthMode.API_KEY,
    "httpauthsecurityscheme": AuthMode.API_KEY,
    "mtlssecurityscheme": AuthMode.MTLS,
}
_HTTP_SCHEME_KINDS: Final = frozenset({"http", "httpauthsecurityscheme"})
_API_KEY_KINDS: Final = frozenset({"apikey", "apikeysecurityscheme"})
#: HTTP authentication schemes that carry a bearer/basic credential (``api-key`` mode).
_HTTP_CREDENTIAL_SCHEMES: Final = frozenset({"bearer", "basic"})
#: Strength used to pick the weakest alternative; ``none`` is weaker than anything, unrecognised next.
_MODE_STRENGTH: Final[dict[AuthMode, int]] = {
    AuthMode.NONE: -1,
    AuthMode.OTHER: 0,
    AuthMode.API_KEY: 1,
    AuthMode.OBO_TOKEN: 2,
    AuthMode.OAUTH2: 2,
    AuthMode.MTLS: 3,
}
_OIDC_DISCOVERY_SUFFIX: Final = "/.well-known/openid-configuration"

#: ``capabilities`` flags (v0.3 and v1.0 names) and top-level flags -> Agent tag.
_CAPABILITY_TAGS: Final[tuple[tuple[str, str], ...]] = (
    ("streaming", "a2a-capability:streaming"),
    ("pushNotifications", "a2a-capability:push-notifications"),
    ("stateTransitionHistory", "a2a-capability:state-transition-history"),
    ("extendedAgentCard", "a2a-capability:extended-agent-card"),
)
_TOP_LEVEL_CAPABILITY_TAGS: Final[tuple[tuple[str, str], ...]] = (
    ("supportsAuthenticatedExtendedCard", "a2a-capability:extended-agent-card"),
)


# --------------------------------------------------------------------------------------------- pure parsing


@dataclass(frozen=True, slots=True)
class CardInterface:
    """One endpoint a card advertises, in the card's preference order."""

    url: str
    binding: str
    protocol_version: str | None
    pointer: tuple[str | int, ...]


@dataclass(frozen=True, slots=True)
class AuthFacts:
    """Authentication requirements derived from ``securitySchemes`` and ``security``."""

    mode: AuthMode | None
    unknown_reason: UnknownReason | None = None
    scheme_names: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    issuer: str | None = None
    header_names: tuple[str, ...] = ()


@dataclass(slots=True)
class _TextGuard:
    """Lints model-visible card text; credential-shaped strings are flagged and never recorded."""

    flags: set[TextFlag] = field(default_factory=set)
    withheld: int = 0

    def inspect(self, value: object) -> None:
        if not isinstance(value, str):
            return
        if hidden_code_points(value):
            self.flags.add(TextFlag.HIDDEN_UNICODE)
        if cross_tool_directives(value):
            self.flags.add(TextFlag.CROSS_TOOL_DIRECTIVE)
        if looks_like_secret(value):
            self.flags.add(TextFlag.SECRET_SHAPED_TOKEN)

    def keep(self, value: object) -> str | None:
        """``value`` when it is a string safe to record; credential-shaped text is withheld and counted."""
        if not isinstance(value, str):
            return None
        self.inspect(value)
        if looks_like_secret(value):
            self.withheld += 1
            return None
        return value


@dataclass(slots=True)
class CardFacts:
    """Everything the collector records about one card (values already reduced to safe forms)."""

    name: str
    digest: DigestResult
    description: str | None = None
    version: str | None = None
    interfaces: list[CardInterface] = field(default_factory=list)
    protocol_versions: list[str] = field(default_factory=list)
    skills: list[A2ASkill] = field(default_factory=list)
    auth: AuthFacts = field(default_factory=lambda: AuthFacts(mode=None))
    provider_org: str | None = None
    provider_url: str | None = None
    documentation_url: str | None = None
    signatures_present: bool = False
    tags: list[str] = field(default_factory=list)
    text_flags: list[TextFlag] = field(default_factory=list)
    withheld: int = 0
    url_credentials_dropped: int = 0


def _norm(token: str) -> str:
    return token.strip().lower().replace("_", "").replace("-", "")


_MAX_SHORT_TEXT: Final = 128


def _binding(value: object, default: str = "") -> str:
    text = value.strip() if isinstance(value, str) and value.strip() else default
    if len(text) > _MAX_SHORT_TEXT or looks_like_secret(text):
        text = "UNRECOGNIZED"  # never echo an oversized or credential-shaped value into the BOM
    return text.upper().replace("-", "").replace("_", "")


def _str_or_none(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _short(value: object) -> str | None:
    """A version-like field: kept only when short and not credential-shaped."""
    text = _str_or_none(value)
    if text is None or len(text) > _MAX_SHORT_TEXT or looks_like_secret(text):
        return None
    return text


def looks_like_card(data: object) -> bool:
    """True when ``data`` is a JSON object carrying at least one A2A Agent Card field."""
    return isinstance(data, Mapping) and any(key in data for key in _CARD_MARKERS)


def card_interfaces(card: Mapping[str, Any]) -> list[CardInterface]:
    """Advertised interfaces in preference order, de-duplicated on ``(url, binding)``.

    v1.0 ``supportedInterfaces[]`` (first entry preferred) come first; then the v0.2/v0.3 top-level ``url``
    with ``preferredTransport`` (default JSON-RPC) and ``additionalInterfaces[]``.
    """
    found: list[CardInterface] = []
    top_version = _short(card.get("protocolVersion"))
    supported = card.get("supportedInterfaces")
    if isinstance(supported, list):
        for i, entry in enumerate(supported):
            if isinstance(entry, Mapping) and _str_or_none(entry.get("url")):
                found.append(
                    CardInterface(
                        url=str(entry["url"]).strip(),
                        binding=_binding(entry.get("protocolBinding", entry.get("transport"))),
                        protocol_version=_short(entry.get("protocolVersion")) or top_version,
                        pointer=("supportedInterfaces", i, "url"),
                    )
                )
    url = _str_or_none(card.get("url"))
    if url:
        found.append(
            CardInterface(
                url=url,
                binding=_binding(card.get("preferredTransport"), _DEFAULT_BINDING),
                protocol_version=top_version,
                pointer=("url",),
            )
        )
    additional = card.get("additionalInterfaces")
    if isinstance(additional, list):
        for i, entry in enumerate(additional):
            if isinstance(entry, Mapping) and _str_or_none(entry.get("url")):
                found.append(
                    CardInterface(
                        url=str(entry["url"]).strip(),
                        binding=_binding(entry.get("transport", entry.get("protocolBinding"))),
                        protocol_version=top_version,
                        pointer=("additionalInterfaces", i, "url"),
                    )
                )
    unique: dict[tuple[str, str], CardInterface] = {}
    for iface in found:
        unique.setdefault((iface.url, iface.binding), iface)
    return list(unique.values())


def _scheme_parts(scheme: object) -> tuple[str, Mapping[str, Any]] | None:
    """``(normalised kind, body)`` of a security scheme in either card generation's JSON shape."""
    if not isinstance(scheme, Mapping):
        return None
    kind = scheme.get("type")
    if isinstance(kind, str):
        return _norm(kind), scheme
    for key, body in scheme.items():
        if isinstance(key, str) and _norm(key) in _SCHEME_MODES:
            return _norm(key), body if isinstance(body, Mapping) else {}
    return None


def _scheme_mode(kind: str, body: Mapping[str, Any]) -> AuthMode:
    mode = _SCHEME_MODES.get(kind, AuthMode.OTHER)
    if (
        kind in _HTTP_SCHEME_KINDS
        and str(body.get("scheme", "")).strip().lower() not in _HTTP_CREDENTIAL_SCHEMES
    ):
        return AuthMode.OTHER
    return mode


def _api_key_header(kind: str, body: Mapping[str, Any]) -> str | None:
    if kind not in _API_KEY_KINDS:
        return None
    where = body.get("in", body.get("location"))
    name = body.get("name")
    if str(where).lower() != "header" or not isinstance(name, str) or not name.strip():
        return None
    name = name.strip()
    return None if "=" in name or looks_like_secret(name) else name


def _oidc_issuer(body: Mapping[str, Any]) -> str | None:
    url = _str_or_none(body.get("openIdConnectUrl"))
    if url is None:
        return None
    display = url_facts(url).display
    return display.removesuffix(_OIDC_DISCOVERY_SUFFIX) or None


def _scope_list(value: object) -> list[str]:
    if isinstance(value, Mapping):  # v1.0 proto-JSON StringList: {"list": [...]}
        value = value.get("list")
    if not isinstance(value, list):
        return []
    return [s for s in value if isinstance(s, str) and s and not looks_like_secret(s)]


def _requirements(card: Mapping[str, Any]) -> list[dict[str, list[str]]]:
    raw = card.get("security")
    if raw is None:
        raw = card.get("securityRequirements")
    if not isinstance(raw, list):
        return []
    out: list[dict[str, list[str]]] = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            continue
        inner = entry.get("schemes")
        # v1.0 proto-JSON SecurityRequirement wraps the map: {"schemes": {"<name>": {"list": [...]}}}
        req = inner if set(entry) == {"schemes"} and isinstance(inner, Mapping) else entry
        out.append({str(name): _scope_list(scopes) for name, scopes in req.items()})
    return out


def _weakest_mode(modes: Mapping[str, AuthMode], requirements: list[dict[str, list[str]]]) -> AuthMode:
    """Mode of the weakest alternative; within one alternative every scheme is required (strongest counts)."""
    alternatives = [
        [modes.get(name, AuthMode.OTHER) for name in req] if req else [AuthMode.NONE] for req in requirements
    ]
    if not alternatives:
        alternatives = [[mode] for mode in modes.values()]

    def strength(alternative: list[AuthMode]) -> int:
        return max(_MODE_STRENGTH[m] for m in alternative)

    weakest = min(alternatives, key=strength)
    return max(weakest, key=_MODE_STRENGTH.__getitem__)


def auth_facts(card: Mapping[str, Any]) -> AuthFacts:
    """Authentication derived from ``securitySchemes``/``security`` (``unknown`` when the card is silent)."""
    schemes = card.get("securitySchemes")
    if schemes is None:
        return AuthFacts(mode=None, unknown_reason=UnknownReason.NOT_COLLECTED)
    if not isinstance(schemes, Mapping):
        return AuthFacts(mode=None, unknown_reason=UnknownReason.UNSUPPORTED_SOURCE)
    if not schemes:
        return AuthFacts(mode=AuthMode.NONE)
    modes: dict[str, AuthMode] = {}
    headers: set[str] = set()
    issuer: str | None = None
    for name, scheme in schemes.items():
        parts = _scheme_parts(scheme)
        if parts is None:
            modes[str(name)] = AuthMode.OTHER
            continue
        kind, body = parts
        modes[str(name)] = _scheme_mode(kind, body)
        header = _api_key_header(kind, body)
        if header:
            headers.add(header)
        issuer = issuer or _oidc_issuer(body)
    requirements = _requirements(card)
    return AuthFacts(
        mode=_weakest_mode(modes, requirements),
        scheme_names=tuple(sorted(n for n in modes if not looks_like_secret(n))),
        scopes=tuple(sorted({s for req in requirements for scopes in req.values() for s in scopes})),
        issuer=issuer,
        header_names=tuple(sorted(headers)),
    )


def _b64url_json(segment: str) -> object:
    if len(segment) > _MAX_JWS_HEADER_CHARS:
        return None
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        return json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):  # binascii.Error and UnicodeDecodeError are ValueErrors
        return None


def _tag_text(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip() or looks_like_secret(value):
        return None
    return value.strip()[:_MAX_TAG_TEXT]


def _signature_tags(signatures: list[Any]) -> list[str]:
    """``alg``/``kid``/``jku`` from each JWS *protected* header (unprotected headers are not integrity-bound)."""
    tags: list[str] = []
    for sig in signatures:
        protected = sig.get("protected") if isinstance(sig, Mapping) else None
        header = _b64url_json(protected) if isinstance(protected, str) else None
        if not isinstance(header, Mapping):
            continue
        for key in ("alg", "kid"):
            text = _tag_text(header.get(key))
            if text:
                tags.append(f"jws-{key}:{text}")
        jku = _str_or_none(header.get("jku"))
        if jku:
            tags.append(f"jws-jku:{url_facts(jku).display}")
    return tags


def _capability_tags(card: Mapping[str, Any]) -> list[str]:
    tags: list[str] = [tag for key, tag in _TOP_LEVEL_CAPABILITY_TAGS if card.get(key) is True]
    caps = card.get("capabilities")
    if not isinstance(caps, Mapping):
        return tags
    tags.extend(tag for key, tag in _CAPABILITY_TAGS if caps.get(key) is True)
    extensions = caps.get("extensions")
    for ext in extensions if isinstance(extensions, list) else []:
        raw_uri = ext.get("uri") if isinstance(ext, Mapping) else None
        uri = (
            url_facts(raw_uri).display
            if isinstance(raw_uri, str) and "://" in raw_uri
            else _tag_text(raw_uri)
        )
        if uri:
            tags.append(f"a2a-extension:{uri}")
            if ext.get("required") is True:
                tags.append(f"a2a-extension-required:{uri}")
    return tags


def _skills(card: Mapping[str, Any], guard: _TextGuard) -> list[A2ASkill]:
    skills: list[A2ASkill] = []
    raw = card.get("skills")
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, Mapping):
            continue
        guard.inspect(entry.get("description"))
        examples = entry.get("examples")
        for example in examples if isinstance(examples, list) else []:
            guard.inspect(example)
        skill_id = guard.keep(entry.get("id"))
        if not skill_id:
            continue
        tags_raw = entry.get("tags")
        tags = [t for t in (guard.keep(x) for x in (tags_raw if isinstance(tags_raw, list) else [])) if t]
        skills.append(A2ASkill(id=skill_id, name=guard.keep(entry.get("name")), tags=tags))
    return skills


def _display(url: str, facts: CardFacts) -> str:
    """Credential-free display form of a card URL; anything dropped is counted for the redaction record."""
    f = url_facts(url)
    facts.url_credentials_dropped += int(f.had_userinfo or f.secret_in_query or f.secret_in_path)
    return f.display


def parse_card(card: Mapping[str, Any], name: str) -> CardFacts:
    """Reduce a parsed card to the facts the collector records (pure; ``name`` is already validated)."""
    guard = _TextGuard()
    guard.inspect(name)
    description = guard.keep(card.get("description"))
    facts = CardFacts(
        name=name,
        digest=jsondoc_digest(CARD_MEDIA_TYPE, {k: v for k, v in card.items() if k != "signatures"}),
        description=description[:MAX_DESCRIPTION_CHARS] if description else None,
        version=_short(guard.keep(card.get("version"))),
        interfaces=card_interfaces(card),
        auth=auth_facts(card),
    )
    facts.protocol_versions = sorted(
        {v for v in [_short(card.get("protocolVersion"))] if v}
        | {i.protocol_version for i in facts.interfaces if i.protocol_version}
    )
    facts.skills = _skills(card, guard)
    provider = card.get("provider")
    if isinstance(provider, Mapping):
        facts.provider_org = _str_or_none(guard.keep(provider.get("organization")))
        provider_url = _str_or_none(provider.get("url"))
        facts.provider_url = _display(provider_url, facts) if provider_url else None
    docs_url = _str_or_none(card.get("documentationUrl"))
    facts.documentation_url = _display(docs_url, facts) if docs_url else None
    signatures = card.get("signatures")
    facts.signatures_present = isinstance(signatures, list) and bool(signatures)
    facts.tags = _capability_tags(card) + (
        _signature_tags(signatures) if isinstance(signatures, list) else []
    )
    for iface in facts.interfaces:
        f = url_facts(iface.url)
        facts.url_credentials_dropped += int(f.had_userinfo or f.secret_in_query or f.secret_in_path)
    facts.text_flags = sorted(guard.flags, key=lambda flag: flag.value)
    facts.withheld = guard.withheld
    return facts


# --------------------------------------------------------------------------------------------- collector


@dataclass(slots=True)
class _Run:
    """Per-run state: minted ids, cards already emitted (by name and digest), redactions per entity."""

    used_ids: set[str] = field(default_factory=set)
    seen: dict[tuple[str, str], str] = field(default_factory=dict)
    redacted: dict[str, int] = field(default_factory=dict)
    parties: set[str] = field(default_factory=set)


class A2ACardsCollector(BaseCollector):
    """Declared A2A peers (and the agent's own published card) from Agent Card files in the repository."""

    name = "a2a-cards"
    version = "0.1.0"
    surfaces = (Surface.TOOLS,)
    mode = CollectorMode.DECLARED

    def detect(self, ctx: CollectContext) -> bool:
        del ctx
        return True  # "no cards in this repository" is itself a recorded fact (queried, 0 items)

    def collect(self, ctx: CollectContext) -> CollectionResult:
        result = self.new_result()
        run = _Run()
        walked = 0
        for path in ctx.walk():
            walked += 1
            if path.name in CARD_FILENAMES:
                self._collect_card(ctx, result, path, run)
        result.add_source(Surface.TOOLS, "a2a-cards:repo-walk", locator=".", ok=True, items=0)
        if walked >= ctx.max_files:
            result.set_status(Surface.TOOLS, CoverageStatus.TRUNCATED, truncated_at=walked)
            result.warnings.append(
                f"repository walk stopped at {walked} files; later agent cards not examined"
            )
        if run.redacted:
            result.redactions.append(
                Redaction(
                    redaction_class="credential-shaped-token",
                    count=sum(run.redacted.values()),
                    applied_by=self.ref,
                    applied_at=ctx.now,
                    ids=sorted(run.redacted),
                )
            )
        return result

    def _collect_card(self, ctx: CollectContext, result: CollectionResult, path: Path, run: _Run) -> None:
        """Read, validate and emit one card; every outcome becomes a coverage source record."""
        display = ctx.display(path)
        outcome = ctx.read_config(path)  # confined beneath the scan root (or home with user scope)
        if not outcome.ok or outcome.data is None:
            result.add_source(
                Surface.TOOLS, _SOURCE, locator=display, ok=False, error_class=outcome.error_class
            )
            return
        try:
            card = parse_json_strict(outcome.data.decode("utf-8-sig"))
        except (ValueError, RecursionError) as exc:  # invalid UTF-8/JSON, duplicate keys, NaN, nesting
            result.add_source(Surface.TOOLS, _SOURCE, locator=display, ok=False, error_class="parse-error")
            result.warnings.append(f"{display}: not valid JSON ({type(exc).__name__})")
            return
        if not looks_like_card(card):
            # ``agent.json`` is a generic name: an unrelated file is examined and holds no card
            ok = path.name != "agent-card.json"
            result.add_source(
                Surface.TOOLS, _SOURCE, locator=display, ok=ok, error_class=None if ok else "invalid-card"
            )
            result.warnings.append(f"{display}: not an A2A Agent Card; skipped")
            return
        name = _str_or_none(card.get("name"))
        if name is None or looks_like_secret(name):
            result.add_source(Surface.TOOLS, _SOURCE, locator=display, ok=False, error_class="invalid-card")
            result.warnings.append(f"{display}: agent card has no usable 'name'; skipped")
            return
        marks = (len(result.entities), len(result.edges), len(result.evidence), len(result.parties))
        try:
            facts = parse_card(card, name)
            digest_key = facts.digest.value or display
            if (name, digest_key) in run.seen:
                result.add_source(Surface.TOOLS, _SOURCE, locator=display, ok=True, items=0)
                result.warnings.append(
                    f"{display}: identical copy of the card at {run.seen[(name, digest_key)]}"
                )
                return
            try:
                parents = path.relative_to(ctx.root).parts[:-1]
            except ValueError:  # pragma: no cover - walk() only yields paths below the root
                parents = path.parts[:-1]
            self._emit(ctx, result, display, facts, self_published=WELL_KNOWN_DIR in parents, run=run)
        except (ValueError, TypeError, RecursionError, UndigestableError) as exc:
            # One hostile card (an out-of-range port, an unbalanced IPv6 bracket) must not fail the collector:
            # roll back its partial output and record it; the message is withheld because it may echo the card.
            del result.entities[marks[0] :], result.edges[marks[1] :], result.evidence[marks[2] :]
            del result.parties[marks[3] :]
            result.add_source(Surface.TOOLS, _SOURCE, locator=display, ok=False, error_class="invalid-card")
            result.warnings.append(f"{display}: agent card rejected ({type(exc).__name__})")
            return
        run.seen[(name, digest_key)] = display
        result.add_source(Surface.TOOLS, _SOURCE, locator=display, ok=True, items=1)

    @staticmethod
    def _mint(kind: str, name: str, display: str, used_ids: set[str]) -> str:
        minted = make_id(kind, f"a2a-{name}")
        if minted in used_ids:
            minted = make_id(kind, f"a2a-{name}", collision_seed=display)
        used_ids.add(minted)
        return minted

    def _emit(
        self,
        ctx: CollectContext,
        result: CollectionResult,
        display: str,
        facts: CardFacts,
        *,
        self_published: bool,
        run: _Run,
    ) -> None:
        agent_id = self._mint("agent", facts.name, display, run.used_ids)
        server_id = self._mint("server", facts.name, display, run.used_ids)
        prov = Provenance(
            method=ClaimMethod.MANIFEST, locator=display, collector=self.ref, observed_at=ctx.now
        )
        common_tags = [SELF_PUBLISHED_TAG] if self_published else []
        if facts.withheld:
            run.redacted[agent_id] = facts.withheld
        if facts.url_credentials_dropped:
            run.redacted[server_id] = facts.url_credentials_dropped

        owner_ref: str | None = None
        if facts.provider_org:
            owner_ref = make_id("party", facts.provider_org)
        if owner_ref is not None and facts.provider_org and owner_ref not in run.parties:
            run.parties.add(owner_ref)
            result.parties.append(
                Party(
                    id=owner_ref,
                    party_kind=PartyKind.ORGANIZATION,
                    name=facts.provider_org,
                    urls=[facts.provider_url] if facts.provider_url else [],
                )
            )
        primary = facts.interfaces[0] if facts.interfaces else None
        card_url = url_facts(primary.url).display if primary else None
        if primary is None:
            result.warnings.append(
                f"{display}: card advertises no interface URL; transport and endpoint unknown"
            )
        if facts.url_credentials_dropped:
            result.warnings.append(f"{display}: credential material in an interface URL was dropped")
        agent_tags = [
            *common_tags,
            *facts.tags,
            *(f"text-flag:{flag.value}" for flag in facts.text_flags),
            *([REDACTED_TAG] if facts.withheld else []),
        ]
        a2a_card: A2ACard | None = None
        if facts.digest.ok and facts.digest.value is not None:
            a2a_card = A2ACard(
                url=card_url,
                digest=facts.digest.value,
                version=facts.version,
                protocol_versions=facts.protocol_versions,
                skills=facts.skills,
                security_schemes=list(facts.auth.scheme_names),
                signature_status="present" if facts.signatures_present else "none",
            )
        else:  # fail closed (ADR-0004): no made-up digest; the card facts stay unrecorded
            agent_tags.append("a2a-card:undigestable")
            result.warnings.append(f"{display}: card is not canonicalizable ({facts.digest.reason})")
        result.entities.append(
            Agent(
                id=agent_id,
                name=facts.name,
                description=facts.description,
                provenance=prov,
                tags=agent_tags,
                external_refs=[ExternalRef(type="documentation", url=facts.documentation_url)]
                if facts.documentation_url
                else [],
                version=facts.version or "unknown",
                role=AgentRole.EXTERNAL_AGENT,
                owner_ref=owner_ref,
                a2a_card=a2a_card,
            )
        )
        result.entities.append(self._server(ctx, server_id, display, facts, prov=prov, tags=common_tags))
        if not self_published:
            result.edges.append(
                Edge.model_validate(
                    {
                        "type": EdgeType.DELEGATES_TO,
                        "from": ctx.agent_id,
                        "to": agent_id,
                        "scope": EdgeScope.RUNTIME,
                        "qualifiers": {"protocol": "a2a"},
                        "declaredBy": display,
                    }
                )
            )

    def _server(
        self,
        ctx: CollectContext,
        server_id: str,
        display: str,
        facts: CardFacts,
        *,
        prov: Provenance,
        tags: list[str],
    ) -> ToolServer:
        primary = facts.interfaces[0] if facts.interfaces else None
        tags = list(tags)
        if primary is None:  # no endpoint to classify: transport and boundary stay unknown (I2)
            return ToolServer(
                id=server_id,
                name=facts.name,
                provenance=prov,
                tags=tags,
                server_kind=ToolServerKind.A2A,
                transport=Claim.unknown(UnknownReason.NOT_COLLECTED, locator=display, collector=self.ref),
                authentication=self._authentication(facts, display),
                trust_zone=TrustZone.UNKNOWN,
                crosses_trust_boundary=Claim.unknown(
                    UnknownReason.NOT_COLLECTED, locator=display, collector=self.ref
                ),
            )
        loc = locator(display, *primary.pointer)
        facts_url = url_facts(primary.url)
        transport = _BINDING_TRANSPORT.get(primary.binding)
        tags.append(f"a2a-binding:{primary.binding or 'unspecified'}")
        if facts.url_credentials_dropped:
            tags.append(REDACTED_TAG)
        tags.extend(
            f"a2a-interface:{iface.binding or 'unspecified'}:{url_facts(iface.url).display}"
            for iface in facts.interfaces[1:]
        )
        identity = server_identity_digest(
            kind=ToolServerKind.A2A.value,
            transport=transport.value if transport else (primary.binding.lower() or "unspecified"),
            endpoint=facts_url.display,
        )
        crosses: Claim[bool] = (
            self._declared(facts_url.crosses_trust_boundary, loc, ctx)
            if facts_url.host
            else Claim.unknown(UnknownReason.UNSUPPORTED_SOURCE, locator=loc, collector=self.ref)
        )
        return ToolServer(
            id=server_id,
            name=facts.name,
            provenance=prov,
            tags=tags,
            server_kind=ToolServerKind.A2A,
            digest=identity.value if identity.ok else None,
            transport=self._declared(transport, loc, ctx)
            if transport
            else Claim.unknown(UnknownReason.UNSUPPORTED_SOURCE, locator=loc, collector=self.ref),
            endpoint=self._declared(facts_url.display, loc, ctx),
            protocol_version=self._declared(primary.protocol_version, loc, ctx)
            if primary.protocol_version
            else None,
            header_names=list(facts.auth.header_names),
            authentication=self._authentication(facts, display),
            trust_zone=facts_url.trust_zone,
            crosses_trust_boundary=crosses,
        )

    def _declared(self, value: Any, loc: str, ctx: CollectContext) -> Claim[Any]:
        """A fact the card's publisher asserts (``declared``, read from the card manifest)."""
        return Claim.declared(
            value, locator=loc, collector=self.ref, method=ClaimMethod.MANIFEST, observed_at=ctx.now
        )

    def _authentication(self, facts: CardFacts, display: str) -> Claim[Authentication]:
        auth = facts.auth
        loc = locator(display, "securitySchemes")
        if auth.mode is None:
            return Claim.unknown(
                auth.unknown_reason or UnknownReason.NOT_COLLECTED, locator=loc, collector=self.ref
            )
        return Claim.declared(
            Authentication(mode=auth.mode, issuer=auth.issuer, scopes_requested=list(auth.scopes)),
            locator=loc,
            collector=self.ref,
            method=ClaimMethod.MANIFEST,
        )
