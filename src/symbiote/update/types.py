"""Shared types for agent dependency updates (``spec/monitoring.md`` §4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from symbiote.advisories.types import DependencyRef, Signal

__all__ = ["FileEdit", "UpdateKind", "UpdatePolicy", "UpdateProposal"]

UpdateKind = Literal["pin", "security", "version", "replace", "retire-model"]


@dataclass(frozen=True, slots=True)
class UpdatePolicy:
    """How conservative updates are. The defaults favour safety over freshness."""

    #: Releases younger than this are never proposed (fresh-release window used by recent npm worms).
    cooldown_days: int = 7
    #: Security fixes may be adopted sooner, but never inside this window.
    security_cooldown_days: int = 2
    #: Refuse a release without build provenance when an earlier release of the same package had it.
    require_provenance_continuity: bool = True
    #: Refuse a release that adds an install (lifecycle) script the current version does not have.
    block_new_install_scripts: bool = True
    #: Propose pinning floating references even when no newer version exists.
    pin_floating: bool = True
    #: Allow major-version updates (otherwise only within the current major).
    allow_major: bool = False


@dataclass(frozen=True, slots=True)
class FileEdit:
    """A minimal textual edit to one configuration file (formatting and comments are preserved)."""

    path: str
    locator: str
    before: str
    after: str


@dataclass(slots=True)
class UpdateProposal:
    """One proposed change, with the evidence a reviewer needs to accept it."""

    kind: UpdateKind
    dependency: DependencyRef
    current: str
    proposed: str
    title: str
    rationale: str
    signals: list[Signal] = field(default_factory=list)
    edits: list[FileEdit] = field(default_factory=list)
    #: Checks a reviewer should still do by hand (for example, diff the served tool definitions after upgrade).
    review_notes: list[str] = field(default_factory=list)
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
