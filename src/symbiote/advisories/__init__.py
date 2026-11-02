"""Agent dependency intelligence (``spec/monitoring.md`` §3).

:func:`dependencies_from_bom` reads an AgentBOM's third-party dependencies (MCP server packages and endpoints,
A2A peers, skills, software components, hosted and local models); :func:`check_dependencies` asks the advisors
(npm registry, PyPI, OSV, MCP Registry, the shipped hosted-model retirement table) about each one through a
bounded, cached :class:`HttpClient`, and reports versions, advisories, supply-chain signals and coverage.
"""

from __future__ import annotations

from symbiote.advisories.engine import check_dependencies, check_dependency
from symbiote.advisories.http import (
    HttpClient,
    HttpError,
    HttpStatusError,
    MalformedResponse,
    NotFound,
    ResponseTooLarge,
    Unreachable,
)
from symbiote.advisories.inventory import dependencies_from_bom
from symbiote.advisories.npm import InvalidPackageName
from symbiote.advisories.retirements import Retirement, find_retirement, load_retirements
from symbiote.advisories.types import (
    Advisory,
    Coverage,
    DependencyIntel,
    DependencyKind,
    DependencyRef,
    Ecosystem,
    ReleaseInfo,
    Signal,
    SignalKind,
)

__all__ = [
    "Advisory",
    "Coverage",
    "DependencyIntel",
    "DependencyKind",
    "DependencyRef",
    "Ecosystem",
    "HttpClient",
    "HttpError",
    "HttpStatusError",
    "InvalidPackageName",
    "MalformedResponse",
    "NotFound",
    "ReleaseInfo",
    "ResponseTooLarge",
    "Retirement",
    "Signal",
    "SignalKind",
    "Unreachable",
    "check_dependencies",
    "check_dependency",
    "dependencies_from_bom",
    "find_retirement",
    "load_retirements",
]
