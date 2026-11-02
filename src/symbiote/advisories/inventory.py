"""The dependency inventory of an AgentBOM (``spec/monitoring.md`` §3).

Reads, without any network access, every third-party dependency an agent's BOM records:

* MCP server packages (``ToolServer.package``: npm, PyPI, OCI and others) — a floating launcher reference
  (``npx -y pkg``, ``pkg@latest``, ``uvx pkg``, an unpinned image tag) has ``version=None``;
* remote MCP servers (``ToolServer.endpoint`` without a package) and tool plugins (non-MCP servers that name a
  package);
* A2A peers (``ToolServer(kind=a2a)``, and sub-agents that publish an A2A card) with the card digest as version;
* skills (dirmanifest digest);
* software components imported from SBOMs that carry a package URL;
* hosted models (``Model.hosted``: the requested identifier; a floating alias has ``version=None``) and local
  models whose weights carry a ``pkg:huggingface`` URL.

Each reference keeps the entity ids that use it and the locators (``<file>#<json-pointer>``) where it is
declared, so an update can be proposed in the right place. References are de-duplicated by
``(ecosystem, name, version)``.

Package types symbiote has no registry advisor for (NuGet, Go, ...) are recorded with ecosystem
``mcp-registry`` when they back an MCP server (the MCP Registry is the one source that lists them); software
components of such types are not inventoried.
"""

from __future__ import annotations

from typing import Final

from packageurl import PackageURL

from symbiote.advisories.types import DependencyKind, DependencyRef, Ecosystem
from symbiote.model.document import AgentBOM
from symbiote.model.entities import Model, PackageRef, ToolServer
from symbiote.model.enums import AliasPinning, ModelKind, ToolServerKind

__all__ = ["dependencies_from_bom", "hosted_model_purl", "parse_purl"]

_PURL_ECOSYSTEM: Final[dict[str, Ecosystem]] = {
    "npm": "npm",
    "pypi": "pypi",
    "oci": "oci",
    "docker": "oci",
    "huggingface": "huggingface",
}

#: When two declarations merge, the more specific kind wins.
_KIND_RANK: Final = {
    DependencyKind.MCP_SERVER_PACKAGE: 0,
    DependencyKind.MCP_SERVER_REMOTE: 1,
    DependencyKind.A2A_PEER: 2,
    DependencyKind.TOOL_PLUGIN: 3,
    DependencyKind.SKILL: 4,
    DependencyKind.HOSTED_MODEL: 5,
    DependencyKind.LOCAL_MODEL: 6,
    DependencyKind.SOFTWARE_COMPONENT: 7,
}


def parse_purl(purl: str) -> PackageURL | None:
    try:
        return PackageURL.from_string(purl)
    except ValueError:
        return None


def _purl_name(p: PackageURL) -> str:
    """Registry name of a package URL (``@scope/name`` for npm, the repository for OCI)."""
    if p.type in ("oci", "docker"):
        repo = (p.qualifiers or {}).get("repository_url") if isinstance(p.qualifiers, dict) else None
        if isinstance(repo, str) and repo:
            return repo
    if p.namespace:
        return f"{p.namespace}/{p.name}"
    return str(p.name)


def hosted_model_purl(provider: str, ref: str) -> str:
    """``pkg:generic/<ref>?provider=<id>``: carries the provider attribution alongside the identifier."""
    return PackageURL(type="generic", name=ref, qualifiers={"provider": provider}).to_string()


def _locators(*values: str | None) -> tuple[str, ...]:
    return tuple(dict.fromkeys(v for v in values if v))


class _Builder:
    def __init__(self) -> None:
        self._refs: dict[tuple[str, str, str | None], DependencyRef] = {}

    def add(self, ref: DependencyRef) -> None:
        key = (ref.ecosystem, ref.name, ref.version)
        prev = self._refs.get(key)
        if prev is None:
            self._refs[key] = DependencyRef(
                kind=ref.kind,
                ecosystem=ref.ecosystem,
                name=ref.name,
                version=ref.version,
                subjects=tuple(sorted(set(ref.subjects))),
                locators=tuple(sorted(set(ref.locators))),
                purl=ref.purl,
            )
            return
        kind = prev.kind if _KIND_RANK[prev.kind] <= _KIND_RANK[ref.kind] else ref.kind
        self._refs[key] = DependencyRef(
            kind=kind,
            ecosystem=prev.ecosystem,
            name=prev.name,
            version=prev.version,
            subjects=tuple(sorted({*prev.subjects, *ref.subjects})),
            locators=tuple(sorted({*prev.locators, *ref.locators})),
            purl=prev.purl or ref.purl,
        )

    def result(self) -> list[DependencyRef]:
        return sorted(self._refs.values(), key=lambda r: (r.ecosystem, r.name, r.version or "", r.kind.value))


def _package_ref(server: ToolServer, pkg: PackageRef, locators: tuple[str, ...]) -> DependencyRef | None:
    if not pkg.purl:
        return None
    p = parse_purl(pkg.purl)
    if p is None:
        return None
    ecosystem: Ecosystem = _PURL_ECOSYSTEM.get(p.type, "mcp-registry")
    kind = (
        DependencyKind.MCP_SERVER_PACKAGE
        if server.server_kind is ToolServerKind.MCP
        else DependencyKind.TOOL_PLUGIN
    )
    version = None if pkg.floating else (p.version or pkg.digest)
    return DependencyRef(
        kind=kind,
        ecosystem=ecosystem,
        name=_purl_name(p),
        version=version,
        subjects=(server.id,),
        locators=locators,
        purl=pkg.purl,
    )


def _servers(bom: AgentBOM, out: _Builder) -> None:
    for server in bom.tool_servers:
        prov = server.provenance.locator
        pkg_claim = server.package
        pkg = pkg_claim.value if pkg_claim is not None else None
        if pkg is not None and pkg_claim is not None:
            ref = _package_ref(server, pkg, _locators(pkg_claim.locator, prov))
            if ref is not None:
                out.add(ref)
                continue
        endpoint_claim = server.endpoint
        endpoint = endpoint_claim.value if endpoint_claim is not None else None
        toolset = server.toolset_digest.value if server.toolset_digest is not None else None
        if server.server_kind is ToolServerKind.A2A:
            out.add(
                DependencyRef(
                    kind=DependencyKind.A2A_PEER,
                    ecosystem="a2a",
                    name=endpoint or server.name or server.id,
                    version=server.digest or toolset,
                    subjects=(server.id,),
                    locators=_locators(endpoint_claim.locator if endpoint_claim else None, prov),
                )
            )
        elif endpoint:
            kind = (
                DependencyKind.MCP_SERVER_REMOTE
                if server.server_kind is ToolServerKind.MCP
                else DependencyKind.TOOL_PLUGIN
            )
            out.add(
                DependencyRef(
                    kind=kind,
                    ecosystem="mcp-registry",
                    name=endpoint,
                    version=toolset or server.digest,
                    subjects=(server.id,),
                    locators=_locators(endpoint_claim.locator if endpoint_claim else None, prov),
                )
            )


def _peers(bom: AgentBOM, out: _Builder) -> None:
    for agent in bom.agents:
        if agent.id == bom.subject or agent.a2a_card is None:
            continue
        card = agent.a2a_card
        out.add(
            DependencyRef(
                kind=DependencyKind.A2A_PEER,
                ecosystem="a2a",
                name=card.url or agent.name or agent.id,
                version=card.digest,
                subjects=(agent.id,),
                locators=_locators(agent.provenance.locator),
            )
        )


def _skills(bom: AgentBOM, out: _Builder) -> None:
    for skill in bom.skills:
        out.add(
            DependencyRef(
                kind=DependencyKind.SKILL,
                ecosystem="skill",
                name=skill.name or skill.frontmatter.name or skill.path,
                version=skill.digest,
                subjects=(skill.id,),
                locators=_locators(skill.provenance.locator, skill.path),
            )
        )


def _software(bom: AgentBOM, out: _Builder) -> None:
    for comp in bom.software:
        if not comp.purl:
            continue
        p = parse_purl(comp.purl)
        if p is None or p.type not in _PURL_ECOSYSTEM:
            continue
        out.add(
            DependencyRef(
                kind=DependencyKind.SOFTWARE_COMPONENT,
                ecosystem=_PURL_ECOSYSTEM[p.type],
                name=_purl_name(p),
                version=p.version or comp.version,
                subjects=(comp.id,),
                locators=_locators(comp.provenance.locator),
                purl=comp.purl,
            )
        )


def _model_locators(model: Model, *claims: str | None) -> tuple[str, ...]:
    return _locators(*claims, model.provenance.locator)


def _models(bom: AgentBOM, out: _Builder) -> None:
    for model in bom.models:
        hosted_claim = model.hosted
        hosted = hosted_claim.value if hosted_claim is not None else None
        if hosted is not None and hosted_claim is not None:
            ref = hosted.requested_ref
            out.add(
                DependencyRef(
                    kind=DependencyKind.HOSTED_MODEL,
                    ecosystem="hosted-model",
                    name=ref,
                    version=None if hosted.alias_pinning is AliasPinning.FLOATING else ref,
                    subjects=(model.id,),
                    locators=_model_locators(model, hosted_claim.locator),
                    purl=hosted_model_purl(hosted.provider, ref),
                )
            )
            continue
        weights_claim = model.weights
        weights = weights_claim.value if weights_claim is not None else None
        if weights is None or weights_claim is None or not weights.purl:
            continue
        p = parse_purl(weights.purl)
        if p is None or p.type != "huggingface":
            continue
        out.add(
            DependencyRef(
                kind=DependencyKind.LOCAL_MODEL
                if model.model_kind is not ModelKind.HOSTED
                else DependencyKind.HOSTED_MODEL,
                ecosystem="huggingface",
                name=_purl_name(p),
                version=p.version,
                subjects=(model.id,),
                locators=_model_locators(model, weights_claim.locator),
                purl=weights.purl,
            )
        )


def dependencies_from_bom(bom: AgentBOM) -> list[DependencyRef]:
    """Every third-party dependency recorded in ``bom``, de-duplicated and in a deterministic order."""
    out = _Builder()
    _servers(bom, out)
    _peers(bom, out)
    _skills(bom, out)
    _software(bom, out)
    _models(bom, out)
    return out.result()
