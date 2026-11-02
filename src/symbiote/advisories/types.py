"""Shared types for agent dependency intelligence (``spec/monitoring.md`` §3).

An agent's third-party dependencies are the packages behind its MCP servers, its A2A peers, skills, tools and
plugins, and its models. :class:`DependencyRef` names one; an advisor turns it into :class:`DependencyIntel`:
what versions exist, which advisories apply, and which supply-chain *signals* (fresh release inside the
cooldown, provenance downgrade, new install script, publisher change, deprecation, retirement) were seen.

Everything here is data. Lookups never execute or download package contents, and a lookup that could not be
made is ``coverage="unreachable"`` (or ``"not-attempted"``) — never an empty, clean answer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Literal

__all__ = [
    "Advisory",
    "Coverage",
    "DependencyIntel",
    "DependencyKind",
    "DependencyRef",
    "Ecosystem",
    "ReleaseInfo",
    "Signal",
    "SignalKind",
]

Ecosystem = Literal["npm", "pypi", "oci", "mcp-registry", "huggingface", "hosted-model", "a2a", "skill"]
Coverage = Literal["queried", "partial", "unreachable", "not-attempted"]


class DependencyKind(StrEnum):
    MCP_SERVER_PACKAGE = "mcp-server-package"
    MCP_SERVER_REMOTE = "mcp-server-remote"
    A2A_PEER = "a2a-peer"
    SKILL = "skill"
    TOOL_PLUGIN = "tool-plugin"
    SOFTWARE_COMPONENT = "software-component"
    HOSTED_MODEL = "hosted-model"
    LOCAL_MODEL = "local-model"


class SignalKind(StrEnum):
    VULNERABLE = "vulnerable"  # a published advisory affects the current version
    MALICIOUS = "malicious"  # the current version is a known malicious release (OSV MAL-*, registry takedown)
    NEWER_VERSION = "newer-version"  # an update exists (outside the cooldown and clean)
    FRESH_RELEASE = "fresh-release"  # the newest release is younger than the cooldown: do not adopt yet
    PROVENANCE_DOWNGRADE = "provenance-downgrade"  # earlier releases had build provenance, this one does not
    INSTALL_SCRIPT_ADDED = "install-script-added"  # a lifecycle script (postinstall...) appeared
    PUBLISHER_CHANGED = "publisher-changed"  # a different account published this release
    DEPRECATED = "deprecated"  # registry deprecation or MCP Registry status deprecated/deleted
    YANKED = "yanked"  # PyPI yank / npm unpublish of the pinned version
    FLOATING = "floating"  # the reference resolves to "latest" at every start
    RETIRING_MODEL = "retiring-model"  # a hosted model snapshot or alias has an announced retirement date
    DEFINITION_DRIFT = (
        "definition-drift"  # served tool definitions or a peer card changed since the last cycle
    )


@dataclass(frozen=True, slots=True)
class DependencyRef:
    """One third-party dependency of an agent, as recorded in its AgentBOM."""

    kind: DependencyKind
    ecosystem: Ecosystem
    name: str
    #: The exact version or digest in use; ``None`` when the reference floats (``npx -y pkg``, ``pkg@latest``).
    version: str | None
    #: Entity ids in the AgentBOM that use this dependency (servers, peers, skills, models).
    subjects: tuple[str, ...] = ()
    #: Where the reference is declared (``.mcp.json#/mcpServers/github/args/1``) so an update can be proposed.
    locators: tuple[str, ...] = ()
    purl: str | None = None


@dataclass(frozen=True, slots=True)
class ReleaseInfo:
    version: str
    published_at: datetime | None = None
    #: Build provenance (npm SLSA attestation / PyPI PEP 740 attestation): True, False, or None when unknown.
    has_provenance: bool | None = None
    has_install_script: bool | None = None
    publisher: str | None = None
    deprecated: str | None = None
    yanked: bool = False


@dataclass(frozen=True, slots=True)
class Advisory:
    id: str
    summary: str
    severity: Literal["critical", "high", "medium", "low", "unknown"] = "unknown"
    malicious: bool = False
    #: Versions that fix it (empty when no fix exists or the advisory does not say).
    fixed_in: tuple[str, ...] = ()
    url: str | None = None
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Signal:
    kind: SignalKind
    severity: Literal["critical", "high", "medium", "low", "info"]
    detail: str
    #: Advisory or release the signal is about, when there is one.
    reference: str | None = None


@dataclass(slots=True)
class DependencyIntel:
    """What an advisor learned about one dependency at ``checked_at``."""

    ref: DependencyRef
    checked_at: datetime
    coverage: Coverage
    current: ReleaseInfo | None = None
    latest: ReleaseInfo | None = None
    #: The newest release that passes the update policy (cooldown, provenance, no advisories), if any.
    recommended: ReleaseInfo | None = None
    releases: list[ReleaseInfo] = field(default_factory=list)
    advisories: list[Advisory] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
